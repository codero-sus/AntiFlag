import contextlib
import io
import json
import pathlib
import tempfile
import unittest

from antiflag.cli import main
from antiflag.network import NetworkDB

EXAMPLE_DB = pathlib.Path(__file__).resolve().parent.parent / "examples" / "networks.example.json"


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(argv)
    return code, out.getvalue()


class CliTests(unittest.TestCase):
    def test_json_output_with_example_database(self):
        code, output = run(
            [
                "check",
                "--ip",
                "203.0.113.7",
                "--header",
                "Via: 1.1 wifi-proxy",
                "--db",
                str(EXAMPLE_DB),
                "--json",
            ]
        )
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["verdict"], "proxy")
        self.assertEqual(data["network"]["org"], "Example Cable Broadband")

    def test_vpn_database_entry(self):
        _, output = run(["check", "--ip", "198.51.100.1", "--db", str(EXAMPLE_DB), "--json"])
        self.assertEqual(json.loads(output)["verdict"], "vpn")

    def test_text_output_contains_verdict(self):
        _, output = run(["check", "--ip", "198.19.1.1", "--db", str(EXAMPLE_DB)])
        self.assertIn("Verdict:     HOSTING", output)

    def test_org_flag_without_database(self):
        _, output = run(["check", "--org", "Mullvad VPN AB", "--json"])
        self.assertEqual(json.loads(output)["verdict"], "vpn")

    def test_org_name_only_is_less_certain_than_database(self):
        _, output = run(["check", "--org", "Mullvad VPN AB", "--json"])
        self.assertEqual(json.loads(output)["confidence"], 0.7)

    def test_malformed_header_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            run(["check", "--header", "no-colon-here"])
        self.assertEqual(ctx.exception.code, 2)

    def test_bad_database_reports_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write('{"networks": [{"cidr": "not-a-cidr"}]}')
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            run(["check", "--db", handle.name])

    def test_example_database_loads(self):
        self.assertEqual(len(NetworkDB.from_file(EXAMPLE_DB)), 4)


if __name__ == "__main__":
    unittest.main()
