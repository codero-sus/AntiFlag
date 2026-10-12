import unittest

from antiflag import (
    NetworkDB,
    NetworkInfo,
    NetworkKind,
    Verdict,
    assess,
    classify_org,
)


class ClassifyOrgTests(unittest.TestCase):
    def test_keyword_rules(self):
        cases = {
            "Mullvad VPN AB": NetworkKind.VPN,
            "Digital Ocean, LLC": NetworkKind.HOSTING,
            "Example State University": NetworkKind.INSTITUTION,
            "Comcast Cable Communications": NetworkKind.RESIDENTIAL,
            "Acme Widgets": NetworkKind.UNKNOWN,
            None: NetworkKind.UNKNOWN,
        }
        for org, expected in cases.items():
            with self.subTest(org=org):
                self.assertEqual(classify_org(org), expected)

    def test_hosting_keyword_requires_word_boundary(self):
        # Word boundaries stop "ghost" from matching hosting keywords such as "host".
        self.assertEqual(classify_org("Ghostwriter Ltd"), NetworkKind.UNKNOWN)


class AssessTests(unittest.TestCase):
    def test_plain_residential_connection_is_direct(self):
        result = assess("203.0.113.7", network=NetworkInfo(NetworkKind.RESIDENTIAL, "Cable ISP"))
        self.assertEqual(result.verdict, Verdict.DIRECT)
        self.assertEqual(result.proxy_hops, 0)

    def test_wifi_proxy_on_residential_network_is_proxy_not_vpn(self):
        # The core false positive: a transparent proxy on a home or café network.
        result = assess(
            "203.0.113.7",
            {"Via": "1.1 hotspot-proxy"},
            network=NetworkInfo(NetworkKind.RESIDENTIAL, "Cable ISP"),
        )
        self.assertEqual(result.verdict, Verdict.PROXY)
        self.assertNotEqual(result.verdict, Verdict.VPN)
        self.assertGreaterEqual(result.confidence, 0.8)
        self.assertEqual(result.proxy_hops, 1)

    def test_school_proxy_with_private_forwarded_address_is_proxy(self):
        result = assess(
            "192.0.2.10",
            {"X-Forwarded-For": "10.1.2.3"},
            network=NetworkInfo(NetworkKind.INSTITUTION, "Example State University"),
        )
        self.assertEqual(result.verdict, Verdict.PROXY)
        self.assertTrue(any("private" in reason for reason in result.reasons))

    def test_vpn_provider_exit_is_vpn_even_without_headers(self):
        result = assess("198.51.100.4", network=NetworkInfo(NetworkKind.VPN, "Mullvad"))
        self.assertEqual(result.verdict, Verdict.VPN)
        self.assertEqual(result.confidence, 0.9)

    def test_vpn_keyword_in_org_name_is_vpn_with_lower_confidence(self):
        result = assess("198.51.100.4", network=NetworkInfo(org="NordVPN S.A."))
        self.assertEqual(result.verdict, Verdict.VPN)
        self.assertEqual(result.confidence, 0.7)

    def test_hosting_without_headers_is_hosting_not_vpn(self):
        result = assess("198.19.5.5", network=NetworkInfo(NetworkKind.HOSTING, "Example Cloud"))
        self.assertEqual(result.verdict, Verdict.HOSTING)
        self.assertLess(result.confidence, 0.7)

    def test_hosting_with_forwarding_headers_is_hosting_with_higher_confidence(self):
        result = assess(
            "198.19.5.5",
            {"Via": "1.1 relay"},
            network=NetworkInfo(NetworkKind.HOSTING, "Example Cloud"),
        )
        self.assertEqual(result.verdict, Verdict.HOSTING)
        self.assertEqual(result.confidence, 0.8)

    def test_unknown_network_with_proxy_headers_is_lower_confidence(self):
        result = assess("100.100.100.100", {"Via": "1.1 unknown"})
        self.assertEqual(result.verdict, Verdict.PROXY)
        self.assertLess(result.confidence, 0.7)
        self.assertIn("could be a proxy or a VPN", " ".join(result.reasons))

    def test_no_information_is_direct_with_low_confidence(self):
        result = assess(None)
        self.assertEqual(result.verdict, Verdict.DIRECT)
        self.assertLess(result.confidence, 0.7)

    def test_lookup_database_is_used_when_no_explicit_network(self):
        db = NetworkDB(
            [
                ("198.51.100.0/24", NetworkInfo(NetworkKind.VPN, "Example VPN", 64500)),
                ("203.0.113.0/24", NetworkInfo(NetworkKind.RESIDENTIAL, "Example ISP", 64501)),
            ]
        )
        self.assertEqual(assess("198.51.100.8", lookup=db).verdict, Verdict.VPN)
        self.assertEqual(assess("203.0.113.8", lookup=db).verdict, Verdict.DIRECT)

    def test_to_dict_is_json_friendly(self):
        result = assess(
            "203.0.113.7", {"Via": "1.1 x"}, network=NetworkInfo(NetworkKind.RESIDENTIAL, "ISP")
        )
        data = result.to_dict()
        self.assertEqual(data["verdict"], "proxy")
        self.assertEqual(data["network"]["kind"], "residential")
        self.assertIsInstance(data["reasons"], list)


class NetworkDBTests(unittest.TestCase):
    def test_longest_prefix_wins(self):
        db = NetworkDB(
            [
                ("198.51.0.0/16", NetworkInfo(NetworkKind.HOSTING, "Wide")),
                ("198.51.100.0/24", NetworkInfo(NetworkKind.VPN, "Narrow")),
            ]
        )
        self.assertEqual(db.lookup("198.51.100.9").org, "Narrow")
        self.assertEqual(db.lookup("198.51.1.9").org, "Wide")
        self.assertIsNone(db.lookup("192.0.2.1"))

    def test_ipv4_mapped_ipv6_is_matched(self):
        db = NetworkDB([("198.51.100.0/24", NetworkInfo(NetworkKind.VPN, "Narrow"))])
        self.assertEqual(db.lookup("::ffff:198.51.100.9").org, "Narrow")

    def test_invalid_ip_returns_none(self):
        self.assertIsNone(NetworkDB().lookup("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
