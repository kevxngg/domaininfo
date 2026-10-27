import contextlib
import io
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import domaininfo as app
import report as legacy_report
import traceroute as legacy_trace


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404 if self.path == '/missing' else 200)
        self.send_header('Content-Security-Policy', "default-src 'self'")
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(b'<title>Local &amp; test</title><script>alert(1)</script>')

    def log_message(self, *args):
        pass


class DomainInfoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def args(self, *extra):
        return app.parser().parse_args(['127.0.0.1', '--timeout', '0.5', *extra])

    def test_normalize_targets(self):
        for value, expected in [
            ('HTTPS://Example.COM:443/path', 'example.com'),
            ('https://[::1]:443/', '::1'), ('::1', '::1'),
            ('Example.COM.', 'example.com'), ('münich.de', 'xn--mnich-kva.de'),
            ('127.0.0.1', '127.0.0.1'), ('localhost', 'localhost')]:
            with self.subTest(value=value):
                self.assertEqual(app.normalize_target(value), expected)

    def test_reject_invalid_targets(self):
        for value in ('', '-oops', '127.0.0.999', 'a;id', 'https://a:99999',
                      'ftp://example.com', 'https://user:secret@example.com',
                      'a b.com', 'example.com\nhello', 'https://a:bad',
                      '-bad.com', 'bad-.com', 'a' * 64 + '.com'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                app.normalize_target(value)

    def test_invalid_numeric_options(self):
        for option, value in [('--threads', '0'), ('--threads', '65'),
                              ('--timeout', 'nan'), ('--timeout', 'inf'),
                              ('--timeout', '-1'), ('--ports', '0,80'),
                              ('--ports', '80,no'), ('--web-port', '65536')]:
            with self.subTest(option=option, value=value):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    self.args(option, value)

    def test_local_dns(self):
        self.assertIn('127.0.0.1', app.resolve('localhost'))

    def test_http_headers_and_title(self):
        result = app.http_info('127.0.0.1', self.args('--scheme', 'http', '--web-port', str(self.port)))
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['title'], 'Local & test')
        self.assertEqual(result['missing_headers'], ['referrer-policy'])

    def test_http_error_is_inspectable(self):
        meta, _ = app.fetch(f'http://127.0.0.1:{self.port}/missing', .5)
        self.assertEqual(meta['status'], 404)

    def test_bounded_response(self):
        meta, body = app.fetch(f'http://127.0.0.1:{self.port}/', .5, limit=10)
        self.assertTrue(meta['truncated'])
        self.assertEqual(len(body), 10)

    def test_tcp_open_and_closed(self):
        # A bound but non-listening socket reserves a known closed port.
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            closed = reserved.getsockname()[1]
            data = app.ports_info('127.0.0.1', self.args('--ports', f'{self.port},{closed}'))
        states = {item['port']: item['state'] for item in data['results']}
        self.assertEqual(states[self.port], 'open')
        self.assertEqual(states[closed], 'closed_or_filtered')

    def test_tls_verification_error_remains_error(self):
        args = self.args('-m', 'web', '-s', 'dns', '-s', 'http', '-q')
        with patch.object(app.ssl, 'create_default_context', side_effect=ssl.SSLError('certificate failed')):
            result = app.scan('localhost', args)
        self.assertEqual(result['modules']['tls']['status'], 'error')

    def test_tls_verified_metadata(self):
        cert = {'notAfter': 'Jan 1 00:00:00 2030 GMT'}
        with patch.object(app.socket, 'create_connection') as raw, patch.object(app.ssl, 'create_default_context') as context:
            conn = context.return_value.wrap_socket.return_value.__enter__.return_value
            conn.getpeercert.return_value = cert
            conn.version.return_value = 'TLSv1.3'
            conn.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
            result = app.tls_info('localhost', self.args())
            self.assertTrue(result['verified'])
            context.return_value.wrap_socket.assert_called_once_with(raw.return_value.__enter__.return_value, server_hostname='localhost')

    def test_rdap_failure_not_success(self):
        with patch.object(app, 'fetch', return_value=({'status': 429}, b'{}')):
            with self.assertRaisesRegex(ValueError, '429'):
                app.rdap_info('example.com', self.args())

    def test_rdap_ip_route(self):
        with patch.object(app, 'fetch', return_value=({'status': 200, 'truncated': False}, b'{"handle":"test"}')) as fetch:
            self.assertEqual(app.rdap_info('::1', self.args())['handle'], 'test')
            self.assertIn('/ip/%3A%3A1', fetch.call_args.args[0])

    def test_trace_unavailable(self):
        with patch.object(app.shutil, 'which', return_value=None):
            self.assertEqual(app.trace_info('localhost', self.args())['status'], 'unavailable')

    def test_trace_failure_is_error(self):
        with patch.object(app.shutil, 'which', return_value='traceroute'), patch.object(app.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'denied')):
            with self.assertRaisesRegex(RuntimeError, 'denied'):
                app.trace_info('localhost', self.args())

    def test_no_fake_tcp_hops(self):
        with patch.object(legacy_trace.socket, 'gethostbyname', return_value='127.0.0.1'), patch.object(legacy_trace.socket, 'socket', side_effect=PermissionError), contextlib.redirect_stdout(io.StringIO()) as output:
            legacy_trace.traceroute('localhost')
        self.assertIn('Sin permisos RAW', output.getvalue())
        self.assertNotIn('REACHED', output.getvalue())

    def test_report_escape_and_unique_names(self):
        report = {'meta': {'target': 'example.com'}, 'data': '<script>alert(1)</script>'}
        with tempfile.TemporaryDirectory() as directory:
            first = app.save_report(report, Path(directory), ['json', 'html', 'txt'])
            second = app.save_report(report, Path(directory), ['json'])
            self.assertNotEqual(first[0], second[0])
            self.assertEqual(json.loads(Path(first[0]).read_text(encoding='utf-8')), report)
            page = Path(first[1]).read_text(encoding='utf-8')
            self.assertNotIn('<script>', page)
            self.assertIn('&lt;script&gt;', page)

    def test_cli_quiet_json_and_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = subprocess.run([sys.executable, 'domaininfo.py', 'localhost', '-s', 'rdap', '-q', '-o', directory], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stderr, '')
            self.assertEqual(json.loads(proc.stdout)['modules']['dns']['status'], 'ok')
            self.assertEqual(len(list(Path(directory).iterdir())), 3)

    def test_batch_bom_crlf_duplicates_and_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            batch = root / 'batch.txt'
            batch.write_bytes(b'\xef\xbb\xbf# test\r\nlocalhost\r\nlocalhost\r\n-invalid\r\n')
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                result = app.main(['-f', str(batch), '-s', 'rdap', '-q', '-o', str(root / 'out')])
            self.assertEqual(result, 1)
            self.assertEqual(len(out.getvalue().splitlines()), 1)

    def test_output_failure_returns_error(self):
        with patch.object(app, 'save_report', side_effect=PermissionError('denied')):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(app.main(['localhost', '-s', 'rdap', '-q']), 1)

    def test_doctor_offline(self):
        with patch.object(app.socket, 'getaddrinfo', side_effect=AssertionError('network')):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(app.main(['--doctor']), 0)
            self.assertIn('python', json.loads(out.getvalue()))

    @unittest.skipIf(sys.platform == 'win32', 'El instalador Bash se prueba en Unix')
    def test_termux_launcher_path_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix='domaininfo space ') as directory:
            env = dict(os.environ, TERMUX_VERSION='test', PREFIX=directory)
            proc = subprocess.run(['bash', 'install.sh'], env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            launcher = Path(directory) / 'bin' / 'domaininfo'
            result = subprocess.run([str(launcher), '--doctor'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('python', json.loads(result.stdout))

    def test_legacy_html_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'report.txt'
            log.write_text('Reporte: <script>x</script>\nDominio : <img src=x>\n', encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()):
                legacy_report.generate_html(str(log), str(root / 'report.html'))
            result = (root / 'report.html').read_text(encoding='utf-8')
            self.assertNotIn('<script>', result)
            self.assertNotIn('<img src=x>', result)


if __name__ == '__main__':
    unittest.main()
