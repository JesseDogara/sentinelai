import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import app
from _test_support import csrf_post
from network_scanner import normalize_domain, normalize_ip, query_dns, scan_domain, scan_ip


def dns_output(status='NOERROR', records='', flags='qr rd ra'):
    return subprocess.CompletedProcess([], 0, f';; ->>HEADER<<- opcode: QUERY, status: {status}, id: 1\n;; flags: {flags}; QUERY: 1, ANSWER: 1\n' + records, '')


class NetworkTests(unittest.TestCase):
    def setUp(self):
        # Parser tests mock the process output; use this source file as a portable
        # existing path so the runtime dependency check does not make fixtures OS-specific.
        dig_path = patch('network_scanner.DIG_PATH', Path(__file__))
        dig_path.start()
        self.addCleanup(dig_path.stop)

    def test_domain_validation(self):
        self.assertEqual(normalize_domain(' Example.COM. '), 'example.com')
        self.assertEqual(normalize_domain('bücher.example'), 'xn--bcher-kva.example')
        for target in ('', 'localhost', 'https://example.com', 'example.com:443', '1.2.3.4',
                       '::1', 'x;touch.example', '*.example.com', '-x.example', 'x..com',
                       'x.com\nIN TXT', 'a' * 64 + '.com', 'x.com/path', '999.1.2.3', 'x.com..'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                normalize_domain(target)

    def test_ip_validation_and_no_network_default(self):
        with patch('network_scanner.subprocess.run') as run:
            for target, version in [('127.0.0.1', 'IPv4'), ('2001:db8::1', 'IPv6'), ('::ffff:192.0.2.1', 'IPv6')]:
                result = scan_ip(target)
                self.assertEqual(result['summary']['IP version'], version)
                self.assertIsNone(result['score'])
                self.assertEqual(result['dns_queries'], [])
            run.assert_not_called()
        for target in ('', 'http://127.0.0.1', '192.168.0.0/24', 'fe80::1%en0', '[::1]', '1.2.3.999', '127.0.0.1:80'):
            with self.assertRaises(ValueError): normalize_ip(target)

    def test_dns_parser_and_fixed_command(self):
        answer = dns_output(records='example.com.\t120\tIN\tTXT\t"hello world" "second part"\n')
        with patch('network_scanner.subprocess.run', return_value=answer) as run:
            result = query_dns('example.com', 'TXT')
            self.assertEqual(result['records'][0]['value'], '"hello world" "second part"')
            args, kwargs = run.call_args
            self.assertIn('example.com.', args[0])
            self.assertIn('+notrace', args[0])
            self.assertNotIn('-r', args[0])
            self.assertIn('+tries=1', args[0])
            self.assertFalse(kwargs.get('shell', False))
            self.assertEqual(kwargs['timeout'], 3)

    def test_dns_failure_states(self):
        for status, expected in [('NOERROR', 'No records returned'), ('NXDOMAIN', 'NXDOMAIN'), ('SERVFAIL', 'SERVFAIL'), ('REFUSED', 'REFUSED')]:
            with patch('network_scanner.subprocess.run', return_value=dns_output(status)):
                self.assertEqual(query_dns('example.com', 'A')['status'], expected)
        with patch('network_scanner.subprocess.run', side_effect=subprocess.TimeoutExpired('dig', 3)):
            self.assertEqual(query_dns('example.com', 'A')['status'], 'Timeout')
        with patch('network_scanner.subprocess.run', return_value=dns_output(flags='qr tc rd ra')):
            self.assertIn('Truncated', query_dns('example.com', 'A')['status'])
        with patch('network_scanner.subprocess.run', return_value=subprocess.CompletedProcess([], 9, '', '')):
            self.assertEqual(query_dns('example.com', 'A')['status'], 'Resolver unavailable')
        with patch('network_scanner.DIG_PATH', Path('/definitely-not-installed/dig')):
            with self.assertRaisesRegex(ValueError, 'not found'): query_dns('example.com', 'A')

    def test_domain_bounds_and_reverse_dns(self):
        with patch('network_scanner.subprocess.run', return_value=dns_output()) as run:
            self.assertEqual(len(scan_domain('example.com')['dns_queries']), 7)
            self.assertEqual(run.call_count, 7)
        with patch('network_scanner.subprocess.run', return_value=dns_output('NXDOMAIN')) as run:
            result = scan_domain('missing.example')
            self.assertEqual(run.call_count, 1)
            self.assertEqual(result['dns_queries'][-1]['status'], 'Skipped after NXDOMAIN')
        with patch('network_scanner.time.monotonic', side_effect=[0, 16, 16, 16, 16, 16, 16, 16]), patch('network_scanner.subprocess.run') as run:
            self.assertIn('time limit', scan_domain('example.com')['dns_queries'][0]['status'])
            run.assert_not_called()
        with patch('network_scanner.subprocess.run', return_value=dns_output(records='1.0.0.127.in-addr.arpa. 60 IN PTR localhost.')) as run:
            result = scan_ip('127.0.0.1', reverse_dns=True)
            self.assertEqual(result['dns_queries'][0]['records'][0]['value'], 'localhost.')
            self.assertEqual(run.call_count, 1)
            self.assertIn('1.0.0.127.in-addr.arpa.', run.call_args[0][0])

    def test_history_rendering_and_error_handling(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'DB_PATH', Path(directory) / 'scans.db'):
            app.init_db()
            client = app.app.test_client()
            with patch('network_scanner.subprocess.run', return_value=dns_output(records='example.com. 60 IN TXT "<script>alert(1)</script>"')):
                for scan_type, target in [('domain', 'example.com'), ('ip', '::1')]:
                    response = csrf_post(client, '/scan', data={'scan_type':scan_type, 'target':target}, follow_redirects=True)
                    self.assertEqual(response.status_code, 200)
                    self.assertNotIn(b'HTTP status', response.data)
                    self.assertIn(b'observations', response.data)
                    saved = app.get_history()[0]
                    detail = client.get('/scans/' + str(saved['id']))
                    self.assertEqual(detail.status_code, 200)
                    self.assertEqual(json.loads(saved['result_json'])['target'], target)
                    self.assertEqual(saved['scan_type'], scan_type)
                    if scan_type == 'domain':
                        self.assertIn(b'&lt;script&gt;', detail.data)
                        self.assertNotIn(b'<script>alert', detail.data)
            before = len(app.get_history())
            response = csrf_post(client, '/scan', data={'scan_type':'domain', 'target':'https://example.com'})
            self.assertEqual(response.status_code, 400)
            self.assertIn(b'Enter a domain name only', response.data)
            self.assertEqual(len(app.get_history()), before)
            dashboard = client.get('/').data
            for label in (b'Website', b'API', b'Domain', b'IP Address'):
                self.assertIn(label, dashboard)


if __name__ == '__main__': unittest.main()
