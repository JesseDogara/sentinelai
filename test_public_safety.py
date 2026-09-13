from pathlib import Path
import os
import socket
import tempfile
import unittest
from unittest.mock import patch

import app
from _test_support import csrf_post
from target_safety import (bounded_observation, redact_query, validate_outbound_url,
                           validate_public_domain, validate_public_reverse_dns)


PUBLIC_ENV = {"SENTINELAI_PUBLIC_MODE": "1"}


class TargetSafetyTests(unittest.TestCase):
    def test_public_mode_blocks_local_special_and_nonstandard_destinations(self):
        with patch.dict(os.environ, PUBLIC_ENV, clear=False):
            for target in ("http://localhost", "http://127.0.0.1", "http://10.0.0.1",
                           "http://169.254.169.254", "https://example.com:8443"):
                with self.subTest(target=target), self.assertRaises(ValueError):
                    validate_outbound_url(target)
            with self.assertRaises(ValueError):
                validate_public_domain("service.internal")
            with self.assertRaises(ValueError):
                validate_public_reverse_dns(__import__("ipaddress").ip_address("::1"))

    def test_public_mode_rejects_private_dns_answers_and_accepts_global_answers(self):
        private_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 443))]
        global_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with patch.dict(os.environ, PUBLIC_ENV, clear=False):
            with patch("target_safety.socket.getaddrinfo", return_value=private_answer):
                with self.assertRaisesRegex(ValueError, "private"):
                    validate_outbound_url("https://example.com")
            with patch("target_safety.socket.getaddrinfo", return_value=global_answer):
                parsed = validate_outbound_url("https://example.com/path")
                self.assertEqual(parsed.hostname, "example.com")

    def test_query_and_fragment_are_not_persisted(self):
        redacted = redact_query("https://example.com/path?token=secret#fragment")
        self.assertEqual(redacted, "https://example.com/path?[redacted]")
        self.assertNotIn("secret", redacted)
        self.assertNotIn("fragment", redacted)
        self.assertTrue(bounded_observation("x" * 3000).endswith("[clipped]"))
        with self.assertRaisesRegex(ValueError, "2,048"):
            validate_outbound_url("https://example.com/" + "a" * 2048)


class PublicApplicationTests(unittest.TestCase):
    def setUp(self):
        app._RATE_BUCKETS.clear()

    def test_results_are_isolated_and_local_lab_is_disabled(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(app, "DB_PATH", Path(directory) / "public.db"), \
                patch.object(app, "PUBLIC_MODE", True):
            app.init_db()
            first = app.app.test_client()
            second = app.app.test_client()
            response = csrf_post(first, "/scan", data={"scan_type": "ip", "target": "203.0.113.8",
                                                         "authorized": "on"})
            self.assertEqual(response.status_code, 303)
            detail_path = response.headers["Location"]
            self.assertEqual(first.get(detail_path).status_code, 200)
            self.assertEqual(second.get(detail_path).status_code, 404)
            self.assertEqual(first.get(detail_path + "/export/json").status_code, 200)
            self.assertEqual(second.get(detail_path + "/export/json").status_code, 404)
            self.assertEqual(first.get("/lab").status_code, 404)

    def test_private_http_target_is_rejected_before_request(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(app, "DB_PATH", Path(directory) / "public.db"), \
                patch.object(app, "PUBLIC_MODE", True), \
                patch.dict(os.environ, PUBLIC_ENV, clear=False), \
                patch("requests.Session.get") as request_get:
            app.init_db()
            client = app.app.test_client()
            response = csrf_post(client, "/scan", data={"scan_type": "website",
                                                         "target": "http://127.0.0.1",
                                                         "authorized": "on"})
            self.assertEqual(response.status_code, 400)
            request_get.assert_not_called()

    def test_health_and_browser_security_headers(self):
        with patch.object(app, "PUBLIC_MODE", True):
            response = app.app.test_client().get("/healthz")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["status"], "ok")
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")
            self.assertIn("max-age=31536000", response.headers["Strict-Transport-Security"])
            self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
            portfolio = app.app.test_client().get("/project")
            self.assertEqual(portfolio.status_code, 200)
            self.assertIn(b"PORTFOLIO CASE STUDY", portfolio.data)

    def test_public_rate_limit_is_bounded(self):
        with patch.object(app, "PUBLIC_MODE", True):
            self.assertTrue(all(app.scan_rate_allowed("198.51.100.10")
                                for _ in range(app.RATE_LIMIT_COUNT)))
            self.assertFalse(app.scan_rate_allowed("198.51.100.10"))


if __name__ == "__main__":
    unittest.main()
