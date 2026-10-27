import io
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import domaininfo as core
from terminal_ui import InteractiveApp, Plan, safe_text, logo_lines


class UITests(unittest.TestCase):
    def ui(self, answers, directory):
        iterator = iter(answers)
        output = io.StringIO()
        args = core.parser().parse_args(['-o', str(directory)])
        ui = InteractiveApp(core, args, input_fn=lambda: next(iterator), output=output)
        return ui, output

    def test_offline_wizard_retries_and_returns_home(self):
        with tempfile.TemporaryDirectory() as directory:
            ui, out = self.ui(['5', '2', 'bad', '7.24.2', '1', '0', '0'], directory)
            with patch.object(core, 'resolve', side_effect=AssertionError('network')):
                self.assertEqual(ui.run(), 0)
            self.assertEqual(len(list(Path(directory).glob('*.json'))), 1)
            text = out.getvalue()
            self.assertIn('CVE-2026-67278', text)
            self.assertIn('7.24.2', text)
            self.assertIn('Versión RouterOS inválida', text)
            self.assertIn('Hasta luego, Kevin', text)
            self.assertNotIn('"modules":', text)
            self.assertNotIn('\x1b', text)

    def test_network_port_wizard_with_real_local_socket(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen()
            port = str(server.getsockname()[1])
            ui, out = self.ui(['3', 'bad target', '127.0.0.1', '3', '5', port, '0', '1', '0', '0'], directory)
            self.assertEqual(ui.run(), 0)
            data = ui.history[0]['report']['modules']['ports']['data']
            self.assertEqual(data['results'][0]['state'], 'open')
            self.assertIn('Puertos TCP accesibles: ' + port, out.getvalue())

    def test_batch_omits_invalid_and_duplicates_and_skips_rdap(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'batch.txt'
            path.write_bytes(b'\xef\xbb\xbf# comment\r\n127.0.0.1\r\n127.0.0.2\r\n127.0.0.1\r\n-bad\r\n')
            ui, out = self.ui(['6', str(path), '1', '3', '7', '2', '0', '0', '1', '', '0'], directory)
            with patch.object(core, 'fetch', side_effect=AssertionError('RDAP must be skipped')):
                self.assertEqual(ui.run(), 0)
            self.assertEqual(len(ui.history), 2)
            self.assertEqual(len(list(Path(directory).glob('*.json'))), 2)
            self.assertIn('2 líneas inválidas', out.getvalue())

    def test_back_at_target_does_not_start_scan(self):
        ui, _ = self.ui(['2', '0', '0'], Path('logs'))
        with patch.object(core, 'scan', side_effect=AssertionError('scan')):
            self.assertEqual(ui.run(), 0)

    def test_bad_menu_option_retries(self):
        ui, out = self.ui(['garbage', '0'], Path('logs'))
        self.assertEqual(ui.run(), 0)
        self.assertIn('Opción no válida', out.getvalue())

    def test_eof_closes_without_traceback(self):
        ui, out = self.ui([], Path('logs'))
        ui.read = lambda: (_ for _ in ()).throw(EOFError())
        self.assertEqual(ui.run(), 0)
        self.assertIn('Sesión cerrada', out.getvalue())

    def test_ctrl_c_returns_home(self):
        ui, out = self.ui([], Path('logs'))
        calls = iter([KeyboardInterrupt(), '0'])

        def read():
            value = next(calls)
            if isinstance(value, BaseException):
                raise value
            return value
        ui.read = read
        self.assertEqual(ui.run(), 0)
        self.assertIn('Acción cancelada', out.getvalue())

    def test_preferences_validate_and_are_copied_per_scan(self):
        ui, _ = self.ui(['1', 'nan', '2.5', '2', '65', '8', '0'], Path('logs'))
        ui.preferences(ui.defaults)
        self.assertEqual(ui.defaults.timeout, 2.5)
        self.assertEqual(ui.defaults.threads, 8)
        first = ui.fresh_args('web')
        first.skip.append('tls')
        self.assertNotIn('tls', ui.fresh_args('web').skip)

    def test_url_protocol_port_and_automatic_tls_skip(self):
        ui, _ = self.ui(['http://localhost:8080/path', 'https://localhost:8443'], Path('logs'))
        args = ui.fresh_args('web')
        self.assertEqual(ui.target(args), 'localhost')
        self.assertEqual(args.web_port, 8080)
        self.assertIn('tls', args.skip)
        ui.target(args)
        self.assertEqual(args.web_port, 8443)
        self.assertNotIn('tls', args.skip)

    def test_empty_batch_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / 'empty.txt'
            good = Path(directory) / 'good.txt'
            empty.write_text('# comment\n-bad\n', encoding='utf-8')
            good.write_text('localhost\n', encoding='utf-8')
            ui, out = self.ui([str(empty), str(good)], directory)
            self.assertEqual(ui.load_batch()[1], ['localhost'])
            self.assertIn('no contiene objetivos válidos', out.getvalue())

    def test_report_history_deduplicates_and_ignores_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            report = {'meta': {'tool': 'DomainInfo', 'target': 'localhost', 'mode': 'quick'},
                      'modules': {'dns': {'status': 'ok', 'data': {'addresses': ['127.0.0.1']}}}}
            paths = core.save_report(report, Path(directory), ['json', 'html'])
            (Path(directory) / 'domaininfo_invalid.json').write_text('{bad', encoding='utf-8')
            ui, _ = self.ui([], directory)
            ui.history.append({'report': report, 'paths': paths})
            self.assertEqual(len(ui.stored_reports()), 1)
            ui.history.clear()
            self.assertEqual(len(ui.stored_reports()), 1)

    def test_viewer_opens_html_only_when_selected(self):
        ui, _ = self.ui(['2', '', '0'], Path('logs'))
        entry = {'report': {'meta': {'target': 'localhost'}, 'modules': {}},
                 'paths': [str(Path('logs') / 'report.html')]}
        with patch('terminal_ui.webbrowser.open', return_value=True) as opened:
            ui.viewer(entry)
            opened.assert_called_once_with(Path(entry['paths'][0]).resolve().as_uri())

    def test_remote_ansi_and_controls_are_removed(self):
        self.assertEqual(safe_text('\x1b[31mhello\x1b[0m\x00\r'), 'hello  ')
        ui, output = self.ui([], Path('logs'))
        ui.summary({'modules': {'http': {'status': 'ok', 'data': {
            'title': '\x1b[2Jbad title\x00', 'status': 200, 'missing_headers': []}}}})
        self.assertNotIn('\x1b', output.getvalue())
        self.assertNotIn('\x00', output.getvalue())

    def test_narrow_mobile_terminal_wraps_content(self):
        ui, output = self.ui(['0'], Path('logs'))
        with patch('terminal_ui.shutil.get_terminal_size', return_value=shutil.os.terminal_size((38, 24))):
            ui.run()
        self.assertTrue(all(len(line) <= 38 for line in output.getvalue().splitlines()))

    def test_progress_callback_includes_skips(self):
        args = core.parser().parse_args(['localhost', '-s', 'rdap', '-q'])
        events = []
        core.scan('localhost', args, on_progress=lambda *event: events.append(event))
        self.assertEqual(events, [('dns', 'running', 1, 2), ('dns', 'ok', 1, 2), ('rdap', 'skipped', 2, 2)])

    def test_interactive_cli_accepts_piped_navigation(self):
        result = subprocess.run([sys.executable, 'domaininfo.py', '--interactive'], input='0\n',
                                text=True, capture_output=True, encoding='utf-8', timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CENTRO DE CONTROL', result.stdout)

    def test_main_automatic_tty_entry(self):
        with patch.object(core.sys.stdin, 'isatty', return_value=True), \
             patch('terminal_ui.InteractiveApp') as ui:
            ui.return_value.run.return_value = 0
            self.assertEqual(core.main([]), 0)
            ui.assert_called_once()

    def test_cancelling_target_edit_preserves_review(self):
        ui, _ = self.ui(['2', '0', '0'], Path('logs'))
        args = ui.fresh_args('quick')
        plan = Plan(args, ['localhost'])
        from terminal_ui import Back
        with self.assertRaises(Back):
            ui.review(plan)
        self.assertEqual(plan.targets, ['localhost'])

    def test_windows_classic_menu_explains_available_route(self):
        ui, output = self.ui([''], Path('logs'))
        with patch('terminal_ui.os.name', 'nt'), patch('terminal_ui.subprocess.run') as run:
            ui.classic()
            run.assert_not_called()
        self.assertIn('WSL', output.getvalue())

    def test_save_error_keeps_result_in_session(self):
        with tempfile.TemporaryDirectory() as directory:
            ui, output = self.ui(['0'], directory)
            args = ui.fresh_args('mikrotik')
            args.offline = True
            args.routeros_version = '7.25'
            with patch.object(core, 'save_report', side_effect=PermissionError('denied')):
                ui.execute(Plan(args, ['routeros-offline']))
            self.assertEqual(len(ui.history), 1)
            self.assertEqual(ui.history[0]['paths'], [])
            self.assertIn('No se pudieron guardar', output.getvalue())

    def test_ascii_logo_fits_desktop_and_mobile(self):
        for available in (28, 34, 36, 60, 76, 86):
            with self.subTest(available=available):
                art = logo_lines(available)
                self.assertTrue(all(row.isascii() and len(row) <= available for row in art))
                self.assertGreaterEqual(len(art), 3)

    def test_home_panels_fit_at_common_widths(self):
        for width in (32, 38, 60, 78, 80, 90):
            with self.subTest(width=width):
                ui, output = self.ui(['0'], Path('logs'))
                with patch('terminal_ui.shutil.get_terminal_size', return_value=shutil.os.terminal_size((width, 24))):
                    ui.run()
                self.assertTrue(all(len(line) <= width for line in output.getvalue().splitlines()))
                self.assertIn('MikroTik', output.getvalue())

    def test_return_shortcut_preserves_preferences(self):
        ui, output = self.ui(['1', '2.5', 'r'], Path('logs'))
        ui.preferences(ui.defaults)
        self.assertEqual(ui.defaults.timeout, 2.5)
        self.assertIn('[0 / r] Regresar', output.getvalue())

    def test_mikrotik_return_goes_to_its_submenu(self):
        ui, output = self.ui(['5', '2', 'r', '0', '0'], Path('logs'))
        with patch.object(core, 'scan', side_effect=AssertionError('scan')):
            self.assertEqual(ui.run(), 0)
        self.assertEqual(output.getvalue().count('[2]  Revisar solo una versión'), 2)

    def test_return_at_home_does_not_exit(self):
        ui, output = self.ui(['r', '0'], Path('logs'))
        self.assertEqual(ui.run(), 0)
        self.assertIn('Ya estás en el menú principal', output.getvalue())


if __name__ == '__main__':
    unittest.main()
