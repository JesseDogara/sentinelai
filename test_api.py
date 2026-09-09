from contextlib import closing
import json
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
import app
from _test_support import csrf_post
from api_scanner import scan_api, normalize_api_target

class Handler(BaseHTTPRequestHandler):
    seen = []
    def do_GET(self):
        self.seen.append((self.path, self.headers.get('Authorization')))
        code = int(self.path.split('?')[0].strip('/') or 200)
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('X-RateLimit-Remaining', '5')
        self.send_header('WWW-Authenticate', 'Bearer')
        if code == 302: self.send_header('Location', '/200')
        self.end_headers()
    def log_message(self, *args): pass

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = 'http://127.0.0.1:%s' % cls.server.server_port
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
    def test_observations(self):
        for code in (200, 401, 403, 302, 429, 500):
            before = len(Handler.seen)
            result = scan_api(self.base + '/' + str(code) + '?token=secret')
            self.assertEqual(result['status_code'], code)
            self.assertEqual(len(Handler.seen), before + 1)
            self.assertIsNone(Handler.seen[-1][1])
            self.assertNotIn('secret', json.dumps(result))
            self.assertIsNone(result['score'])
            self.assertEqual(result['content_type'], 'application/json')
            self.assertEqual(result['header_groups']['CORS response headers']['Access-Control-Allow-Origin'], '*')
    def test_invalid_urls(self):
        for url in ('', 'ftp://example.com', 'https://u:p@example.com', 'http://x:bad', 'http://', 'http://x/a b'):
            with self.assertRaises(ValueError): normalize_api_target(url)
    def test_failure(self):
        import requests
        with patch('requests.Session.get', side_effect=requests.Timeout('secret')):
            with self.assertRaisesRegex(ValueError, 'No result was saved'):
                scan_api(self.base)
    def test_history_migration_and_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(app, 'DB_PATH', Path(directory) / 'history.db'):
                with closing(sqlite3.connect(app.DB_PATH)) as conn, conn:
                    conn.execute('CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, scanned_at TEXT NOT NULL, score INTEGER NOT NULL, findings_json TEXT NOT NULL)')
                    conn.execute("INSERT INTO scans VALUES (1, 'old', 'yesterday', 80, '[]')")
                app.init_db(); app.init_db()
                client = app.app.test_client()
                self.assertEqual(app.get_history()[0]['scan_type'], 'website')
                for kind in ('website', 'api'):
                    response = csrf_post(client, '/scan', data={'target':self.base, 'scan_type':kind}, follow_redirects=True)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(app.get_history()[0]['scan_type'], kind)
                    self.assertEqual(client.get('/scans/' + str(app.get_history()[0]['id'])).status_code, 200)
                self.assertIn(b'Observations', client.get('/').data)
                self.assertEqual(csrf_post(client, '/scan', data={'target':self.base,'scan_type':'other'}).status_code, 302)
                self.assertEqual(len(app.get_history()), 3)

if __name__ == '__main__': unittest.main()
