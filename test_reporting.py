import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import app
from reporting import markdown_report


class ReportingTests(unittest.TestCase):
    def test_redirect_refresh_export_and_history_filters(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'DB_PATH', Path(directory)/'scans.db'):
            app.init_db()
            client = app.app.test_client()
            response = client.post('/scan', data={'scan_type':'ip', 'target':'::1'})
            self.assertEqual(response.status_code, 303)
            self.assertEqual(response.location, '/scans/1')
            for _ in range(2): self.assertEqual(client.get(response.location).status_code, 200)
            self.assertEqual(len(app.get_history()), 1)
            raw = client.get('/scans/1/export/json')
            self.assertEqual(raw.status_code, 200)
            result = json.loads(raw.data)
            self.assertEqual(result['scanner_version'], '0.3.0')
            self.assertIn('+00:00', result['scanned_at'])
            self.assertGreaterEqual(result['duration_ms'], 0)
            self.assertIn('attachment;', raw.headers['Content-Disposition'])
            report = client.get('/scans/1/export/md')
            self.assertIn(b'## Recorded evidence', report.data)
            self.assertIn(b'certify security', report.data)
            self.assertEqual(client.get('/scans/999/export/md').status_code, 404)
            self.assertEqual(client.get('/scans/1/export/html').status_code, 404)
            self.assertIn(b'No matching assessments', client.get('/?type=api').data)
            self.assertEqual(len(app.get_history(scan_type='ip', query='::1')), 1)
            self.assertEqual(len(app.get_history(query="' OR 1=1 --")), 0)
            self.assertEqual(client.get('/?type=invalid').status_code, 400)

    def test_markdown_untrusted_data_stays_quoted(self):
        result={'target':'<img src=x onerror=alert(1)>', 'scan_type':'domain', 'findings':[],
                'evidence':'```\n<script>alert(1)</script>\n```'}
        report = markdown_report(result, 1)
        self.assertIn('\\<img', report)
        self.assertIn('````json', report)
        self.assertTrue(report.endswith('````\n'))

if __name__ == '__main__': unittest.main()
