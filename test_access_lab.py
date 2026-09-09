import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import app
from _test_support import csrf_post
from access_lab import (LabClient, MAX_REQUESTS, create_training_api, evaluate_access,
                        make_fixture, run_access_lab, running_lab, _RUN_LOCK)
from reporting import markdown_report


class AccessLabTests(unittest.TestCase):
    def test_fixture_authentication_and_ownership(self):
        fixture = make_fixture()
        client = create_training_api(fixture).test_client()
        for mode in ('broken', 'fixed'):
            url = f'/{mode}/records/record-a'
            self.assertEqual(client.get(url).status_code, 401)
            self.assertEqual(client.get(url, headers={'Authorization':'Bearer wrong'}).status_code, 401)
            a = client.get(url, headers={'Authorization':'Bearer ' + fixture.tokens['account-a']})
            self.assertEqual(a.json, fixture.records['record-a'])
            b = client.get(url, headers={'Authorization':'Bearer ' + fixture.tokens['account-b']})
            self.assertEqual(b.status_code, 200 if mode == 'broken' else 403)
        self.assertEqual(client.post('/broken/records/record-a').status_code, 405)
        self.assertEqual(client.get('/broken/records/missing').status_code, 404)

    def test_status_alone_and_bad_baselines_are_not_proof(self):
        fixture = make_fixture()
        a, b, anon = (200,fixture.records['record-a']), (200,fixture.records['record-b']), (401,{'error':'authentication_required'})
        cases = [(200,{'message':'login required'}), (200,{'id':'record-a'}),
                 (500,{'error':'server_error'}), (403,{'private_note':'unexpected'})]
        for cross in cases:
            result = evaluate_access(a,b,anon,cross,fixture.records)
            self.assertIn('Inconclusive',result['outcome'])
        result = evaluate_access((401,{}),b,anon,a,fixture.records)
        self.assertFalse(result['controls_valid'])
        self.assertIn('Inconclusive',result['outcome'])
        self.assertIn('Confirmed',evaluate_access(a,b,anon,a,fixture.records)['outcome'])
        self.assertIn('denied',evaluate_access(a,b,anon,(403,{'error':'access_denied'}),fixture.records)['outcome'])

    def test_scope_budget_and_session_settings(self):
        for origin in ('https://example.com', 'http://localhost:1234', 'http://127.0.0.1:1234/path',
                       'http://user@127.0.0.1:1234', 'http://127.0.0.1:1234?target=x'):
            with self.assertRaises(ValueError): LabClient(origin)
        client = LabClient('http://127.0.0.1:1234')
        try:
            self.assertFalse(client.session.trust_env)
            with patch.object(client.session,'get') as get:
                for path in ('https://example.com', '//example.com', '/fixed/records/record-a?x=1', '/fixed/../broken/records/record-a'):
                    with self.assertRaises(ValueError):client.get(path)
                client.sent = MAX_REQUESTS
                with self.assertRaises(ValueError):client.get('/fixed/records/record-a')
                get.assert_not_called()
        finally:client.close()

    def test_redirect_oversized_response_and_timeout(self):
        for status, chunks, message in ((302,[], 'redirects'), (200,[b'x'*16385], 'size')):
            client = LabClient('http://127.0.0.1:1234')
            try:
                with patch.object(client.session,'get') as get:
                    response = get.return_value.__enter__.return_value
                    response.status_code = status
                    response.iter_content.return_value = chunks
                    with self.assertRaisesRegex(ValueError,message): client.get('/fixed/records/record-a','test-token')
                    self.assertFalse(get.call_args.kwargs['allow_redirects'])
                    self.assertTrue(get.call_args.kwargs['stream'])
            finally:client.close()
        client = LabClient('http://127.0.0.1:1234')
        try:
            client.started -= 21
            with patch.object(client.session,'get') as get:
                with self.assertRaisesRegex(ValueError,'time budget'):client.get('/fixed/records/record-a')
                get.assert_not_called()
        finally:client.close()

    def test_server_cleanup_on_error(self):
        with self.assertRaisesRegex(RuntimeError,'test failure'):
            with running_lab() as (origin, fixture):
                port = int(origin.rsplit(':',1)[1])
                raise RuntimeError('test failure')
        self.assertEqual(fixture.tokens,{})
        self.assertEqual(fixture.records,{})
        with socket.socket() as probe:
            probe.settimeout(1)
            self.assertNotEqual(probe.connect_ex(('127.0.0.1',port)),0)

    def test_concurrent_runs_are_rejected(self):
        _RUN_LOCK.acquire()
        try:
            with self.assertRaisesRegex(ValueError,'already in progress'):run_access_lab()
        finally:_RUN_LOCK.release()

    def test_real_comparison_persistence_exports_and_redaction(self):
        fixture = make_fixture()
        sensitive = list(fixture.tokens.values()) + [r['private_note'] for r in fixture.records.values()]
        with tempfile.TemporaryDirectory() as directory, patch.object(app,'DB_PATH',Path(directory)/'scans.db'):
            app.init_db()
            client = app.app.test_client()
            with patch('access_lab.make_fixture',return_value=fixture):
                response = csrf_post(client,'/lab/run',data={'target':'https://not-a-target.invalid'},follow_redirects=True)
            self.assertEqual(response.status_code,200)
            self.assertEqual(len(app.get_history()),1)
            saved = app.get_history()[0]
            result = json.loads(saved['result_json'])
            broken, fixed = result['access_comparisons']
            self.assertTrue(broken['controls_valid'])
            self.assertTrue(broken['private_record_matched'])
            self.assertIn('Confirmed',broken['outcome'])
            self.assertTrue(fixed['controls_valid'])
            self.assertFalse(fixed['private_record_matched'])
            self.assertIn('denied',fixed['outcome'])
            self.assertEqual(fixed['cross_account_status'],403)
            self.assertEqual(result['summary']['Requests'],'8 of 8 allowed GET requests')
            self.assertNotIn('not-a-target.invalid',saved['result_json'])
            for extension in ('json','md'):
                report = client.get(f'/scans/{saved["id"]}/export/{extension}')
                self.assertEqual(report.status_code,200)
                for secret in sensitive:self.assertNotIn(secret,report.data.decode())
            for secret in sensitive:
                self.assertNotIn(secret,response.data.decode())
                self.assertNotIn(secret,saved['result_json'])
            client.get(f'/scans/{saved["id"]}')
            self.assertEqual(len(app.get_history()),1)
            self.assertEqual(client.get('/?type=access_lab').status_code,200)

    def test_csrf_origin_and_host_protection(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app,'DB_PATH',Path(directory)/'scans.db'):
            app.init_db()
            client = app.app.test_client()
            for path in ('/scan','/lab/run'):
                self.assertEqual(client.post(path,data={'scan_type':'ip','target':'::1'}).status_code,400)
            client.get('/lab')
            with client.session_transaction() as session:token=session['csrf_token']
            with patch('app.run_access_lab') as run:
                self.assertEqual(client.post('/lab/run',data={'csrf_token':'wrong'}).status_code,400)
                self.assertEqual(client.post('/lab/run',data={'csrf_token':'é'}).status_code,400)
                self.assertEqual(client.post('/lab/run',data={'csrf_token':token},headers={'Origin':'https://evil.invalid'}).status_code,403)
                self.assertEqual(client.post('/lab/run',data={'csrf_token':token,'extra':'x'*17000}).status_code,413)
                run.assert_not_called()
            self.assertEqual(client.get('/lab',headers={'Host':'evil.invalid'}).status_code,400)
            self.assertEqual(len(app.get_history()),0)

if __name__ == '__main__':unittest.main()
