import unittest

from antiflag.headers import analyze_headers, headers_from_wsgi


class AnalyzeHeadersTests(unittest.TestCase):
    def test_no_headers_means_no_intermediary(self):
        findings = analyze_headers({})
        self.assertEqual(findings.hops, 0)
        self.assertFalse(findings.has_intermediary)

    def test_via_counts_hops(self):
        findings = analyze_headers({"Via": "1.1 squid:3128, 1.0 corp-gateway"})
        self.assertEqual(findings.hops, 2)
        self.assertTrue(findings.has_intermediary)

    def test_forwarded_for_counts_entries_and_finds_private_hop(self):
        findings = analyze_headers({"X-Forwarded-For": "203.0.113.7, 10.0.0.2"})
        self.assertEqual(findings.hops, 2)
        self.assertEqual(findings.forwarded_addresses, ("203.0.113.7", "10.0.0.2"))
        self.assertTrue(findings.has_private_hop)

    def test_header_names_are_case_insensitive(self):
        findings = analyze_headers({"x-forwarded-for": "203.0.113.7"})
        self.assertEqual(findings.hops, 1)

    def test_rfc7239_forwarded_header(self):
        value = 'for=192.0.2.60;proto=http, for="[2001:db8::1]:4711"'
        findings = analyze_headers({"Forwarded": value})
        self.assertEqual(findings.hops, 2)
        self.assertEqual(findings.forwarded_addresses, ("192.0.2.60", "2001:db8::1"))

    def test_port_is_stripped_from_forwarded_address(self):
        findings = analyze_headers({"X-Forwarded-For": "203.0.113.7:51234"})
        self.assertEqual(findings.forwarded_addresses, ("203.0.113.7",))

    def test_unknown_forwarded_node_is_not_treated_as_address(self):
        findings = analyze_headers({"X-Forwarded-For": "unknown"})
        self.assertEqual(findings.hops, 1)
        self.assertEqual(findings.forwarded_addresses, ())

    def test_weak_markers_count_as_intermediary(self):
        findings = analyze_headers({"X-Real-IP": "203.0.113.7"})
        self.assertEqual(findings.hops, 0)
        self.assertTrue(findings.has_intermediary)
        self.assertEqual(findings.weak_markers, ("x-real-ip",))


class WsgiTests(unittest.TestCase):
    def test_extracts_http_headers_from_environ(self):
        environ = {
            "REMOTE_ADDR": "203.0.113.7",
            "HTTP_X_FORWARDED_FOR": "198.51.100.9",
            "HTTP_USER_AGENT": "test",
            "CONTENT_TYPE": "text/plain",
        }
        self.assertEqual(
            headers_from_wsgi(environ),
            {"x-forwarded-for": "198.51.100.9", "user-agent": "test"},
        )


if __name__ == "__main__":
    unittest.main()
