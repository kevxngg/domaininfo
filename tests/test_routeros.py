import contextlib
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import domaininfo as app
import routeros


class RouterOSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'<title>MikroTik RouterOS v7.24.2</title>')
        else:
            self.send_response(302)
            self.send_header('Location', 'http://off-target.invalid/')
            self.end_headers()

    def log_message(self, *args):
        pass


class RouterOSTests(unittest.TestCase):
    def args(self, *extra):
        return app.parser().parse_args(['-m', 'mikrotik', *extra])

    def test_version_parser(self):
        self.assertEqual(routeros.parse_version('RouterOS v7.25 (stable)').numbers, (7, 25, 0))
        self.assertEqual(routeros.parse_version('7.23.8 (long-term)').text, '7.23.8')
        self.assertEqual(routeros.parse_version('7.26beta3').stage, 'beta')
        self.assertEqual(routeros.parse_version('7.25rc1').stage, 'rc')
        for invalid in ('7', '7.25.1.2', '7.25garbage', 'v7.25;ls', '7.25beta', ''):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                routeros.parse_version(invalid)

    def test_banner_ignores_protocol_versions(self):
        self.assertEqual(routeros.extract_versions('SSH-2.0-ROSSSH HTTP/1.1 nginx/1.25'), [])
        self.assertEqual(routeros.extract_versions('SSH-2.0-RouterOS_7.25'), [])
        self.assertEqual(routeros.extract_versions('SSH-2.0-MikroTik RouterOS 7.24.2'), ['7.24.2'])
        self.assertEqual(routeros.extract_versions('<title>RouterOS v7.25</title>'), ['7.25'])
        self.assertEqual(routeros.extract_versions('RouterOS 7.25bad'), [])

    def test_stable_and_lts_boundaries(self):
        all_ids = {entry['id'] for entry in routeros.ADVISORIES}
        cert_only = {'CVE-2026-67278'}
        common = {'CVE-2026-67277', 'CVE-2026-67279', 'CVE-2026-86060'}
        cases = {
            '6.49.20': common, '6.49.21': set(), '6.49.23': set(),
            '7.8': common | cert_only,
            '7.9': all_ids - {'CVE-2026-67281'},
            '7.19.6': all_ids - {'CVE-2026-67281'},
            '7.20': all_ids, '7.23.3': all_ids,
            '7.23.4': cert_only, '7.23.5': cert_only, '7.23.6': set(), '7.23.8': set(),
            '7.24': all_ids, '7.24.1': all_ids, '7.24.2': cert_only,
            '7.24.3': set(), '7.24.5': set(), '7.25': set(),
        }
        for version, expected in cases.items():
            with self.subTest(version=version):
                result = routeros.assess(version)
                affected = {item['id'] for item in result['advisories']
                            if item['status'] == 'potentially_affected'}
                self.assertEqual(affected, expected)
                self.assertFalse(any(item['confirmed'] for item in result['advisories']))

    def test_prereleases_and_unsupported_major_need_review(self):
        for version in ('7.25beta3', '7.25rc1', '5.26', '8.1'):
            with self.subTest(version=version):
                states = {entry['status'] for entry in routeros.assess(version)['advisories']}
                self.assertEqual(states, {'manual_review'})

    def test_no_version_does_not_turn_ports_into_cves(self):
        result = routeros.assess(open_ports=(22, 8291))
        self.assertEqual({entry['status'] for entry in result['advisories']}, {'unknown_version'})
        self.assertFalse(any(entry['confirmed'] for entry in result['advisories']))

    def test_closed_ports_do_not_clear_version_advisories(self):
        result = routeros.assess('7.24.2', open_ports=())
        item = next(entry for entry in result['advisories'] if entry['id'] == 'CVE-2026-67278')
        self.assertEqual(item['status'], 'potentially_affected')
        self.assertEqual(item['exposure'], 'not_established')

    def test_six_snapshot_advisories_not_universal_safe_claim(self):
        result = routeros.assess('7.25')
        self.assertEqual(len(result['advisories']), 6)
        self.assertEqual(result['release_snapshot']['comparison']['stable'], 'matches_snapshot')
        self.assertEqual(result['catalog_reviewed'], '2026-10-26')

    def test_offline_does_not_resolve_or_connect(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(app, 'ports_info', side_effect=AssertionError('probe')), \
                 patch.object(app.socket, 'getaddrinfo', side_effect=AssertionError('DNS')), \
                 patch.object(routeros, 'fetch_web', side_effect=AssertionError('HTTP')), \
                 contextlib.redirect_stdout(io.StringIO()) as output, \
                 contextlib.redirect_stderr(io.StringIO()):
                code = app.main(['-m', 'mikrotik', '--offline', '--routeros-version', '7.24.2',
                                 '-q', '-o', directory])
            self.assertEqual(code, 0)
            data = json.loads(output.getvalue())['modules']['mikrotik']['data']
            self.assertTrue(data['offline'])
            self.assertEqual(data['version_source'], 'user_supplied')
            self.assertEqual(len(list(Path(directory).iterdir())), 3)

    def test_cli_rejects_ambiguous_or_invalid_offline_usage(self):
        for args in (['--offline'], ['-m', 'mikrotik', '--offline'],
                     ['--routeros-version', '7.25'],
                     ['-m', 'mikrotik', '--offline', '--routeros-version', 'bad'],
                     ['-m', 'mikrotik', '--offline', '--routeros-version', '7.25', 'localhost']):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                app.main(args)

    def test_disagreeing_versions_require_review(self):
        args = self.args('--routeros-version', '7.25')
        ports = lambda *unused: {'results': [{'port': 80, 'state': 'open'}]}
        with patch.object(routeros, 'fetch_web', return_value={
                'port': 80, 'versions': ['7.24.2'], 'routeros_marker': True}):
            result = routeros.audit('localhost', args, ports)
        self.assertTrue(result['version_conflict'])
        self.assertEqual({entry['status'] for entry in result['advisories']}, {'manual_review'})

    def test_conflicting_public_banners_do_not_pick_one(self):
        ports = lambda *unused: {'results': [{'port': p, 'state': 'open'} for p in (80, 8080)]}
        with patch.object(routeros, 'fetch_web', side_effect=[
            {'versions': ['7.25'], 'routeros_marker': True},
            {'versions': ['7.24.2'], 'routeros_marker': True}]):
            result = routeros.audit('localhost', self.args(), ports)
        self.assertIsNone(result['version'])
        self.assertTrue(result['version_conflict'])

    def test_tls_failure_does_not_fabricate_version(self):
        ports = lambda *unused: {'results': [{'port': 443, 'state': 'open'}]}
        with patch.object(routeros, 'fetch_web', side_effect=OSError('certificate failed')):
            result = routeros.audit('localhost', self.args(), ports)
        self.assertEqual(result['identity'], 'unconfirmed')
        self.assertIsNone(result['version'])
        self.assertIn('certificate failed', result['evidence'][0]['error'])

    def test_local_web_detection_and_json_report(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), RouterOSHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = str(server.server_address[1])
            with tempfile.TemporaryDirectory() as directory:
                proc = subprocess.run([sys.executable, 'domaininfo.py', '-m', 'mikrotik', '127.0.0.1',
                    '--ports', port, '--web-port', port, '--scheme', 'http', '-q', '-o', directory],
                    capture_output=True, text=True, timeout=15)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)['modules']['mikrotik']['data']
            self.assertEqual(data['version'], '7.24.2')
            self.assertEqual(data['version_source'], 'public_banner')
            affected = [item['id'] for item in data['advisories'] if item['status'] == 'potentially_affected']
            self.assertEqual(affected, ['CVE-2026-67278'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_web_redirects_not_followed(self):
        from email.message import Message
        from urllib import error
        headers = Message()
        headers['Location'] = 'http://off-target.invalid/'
        response = error.HTTPError('http://localhost/', 302, 'Found', headers, io.BytesIO(b''))
        with patch.object(routeros.request, 'build_opener') as build:
            build.return_value.open.side_effect = response
            result = routeros.fetch_web('localhost', 80, .5)
        self.assertEqual(result['status'], 302)
        self.assertEqual(result['versions'], [])
        self.assertIsNone(routeros.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://off-target.invalid'))


if __name__ == '__main__':
    unittest.main()
