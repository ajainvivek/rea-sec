import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rea-sec" / "scripts"))

import attack_map  # noqa: E402
import fetch_advisory  # noqa: E402
import phish_headers  # noqa: E402


def run(fn, argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = fn(argv)
    return code, buf.getvalue()


class AttackMapTests(unittest.TestCase):
    def test_example_renders(self):
        code, out = run(attack_map.main, [str(ROOT / "examples" / "log4shell-steps.json")])
        self.assertEqual(code, 0)
        self.assertIn("T1190", out)
        self.assertIn("Exploit Public-Facing Application", out)
        self.assertIn("flowchart LR", out)
        self.assertIn("S1 --> S2", out)

    def test_rejects_bad_technique(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump([{"technique": "TA0001", "detail": "x"}], f)
        with self.assertRaises(ValueError):
            attack_map.normalise(attack_map.load(f.name)[1])
        os.unlink(f.name)

    def test_warns_on_unsourced_confirmed(self):
        steps = attack_map.normalise([{"technique": "T1078", "detail": "x", "status": "CONFIRMED"}])
        self.assertIn("Warning", attack_map.md_table("t", steps))


    def test_branching_and_escaping(self):
        steps = attack_map.normalise([
            {"technique": "T1190", "detail": "a"},
            {"technique": "T1552", "detail": "b #1; [x]"},
            {"technique": "T1078", "detail": "c", "after": [1], "tactic": "Persistence"},
        ])
        out = attack_map.mermaid(steps)
        self.assertIn("S1 --> S2", out)
        self.assertIn("S1 --> S3", out)
        self.assertNotIn("S2 --> S3", out)
        self.assertNotIn("#", out.split("classDef")[0])
        self.assertIn("3. Persistence", out)

    def test_after_must_point_backwards(self):
        with self.assertRaises(ValueError):
            attack_map.normalise([{"technique": "T1190", "detail": "a", "after": [2]}])

    def test_karte_example_renders(self):
        code, out = run(attack_map.main, [str(ROOT / "examples" / "plaid-karte-steps.json")])
        self.assertEqual(code, 0)
        self.assertIn("S2 --> S6", out)


class PhishTests(unittest.TestCase):
    def setUp(self):
        self.r = phish_headers.analyse((ROOT / "tests" / "sample_phish.eml").read_bytes())

    def test_flags(self):
        flags = " ".join(self.r["flags"])
        self.assertIn("Reply-To domain", flags)
        self.assertIn("DMARC = fail", flags)
        self.assertIn("SPF = softfail", flags)
        self.assertIn("Risky attachment type: invoice.html", flags)
        self.assertIn("microsoft", flags)

    def test_urls_defanged_and_redirect_found(self):
        urls = self.r["urls"]
        self.assertTrue(all(u["url"].startswith("hxxp") for u in urls))
        redirect = [u for u in urls if u["redirects_to"]]
        self.assertTrue(redirect and "collect[.]example[.]net" in redirect[0]["redirects_to"][0])
        self.assertTrue(any("URL shortener" in u["flags"] for u in urls))

    def test_short_brand_no_false_positive(self):
        r = phish_headers.analyse_url("https://groups.example.com/tomato?banana=1")
        self.assertEqual(r["flags"], [])
        r = phish_headers.analyse_url("https://ups-tracking.example.net/")
        self.assertIn("brand 'ups' in non-brand domain", r["flags"])

    def test_ip_and_hash(self):
        self.assertIn("203.0.113.45", self.r["first_hop_ips"])
        self.assertEqual(len(self.r["attachments"][0]["sha256"]), 64)


class AdvisoryTests(unittest.TestCase):
    def test_parse_kev(self):
        data = {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10",
                                     "knownRansomwareCampaignUse": "Known"}]}
        self.assertEqual(fetch_advisory.parse_kev(data, "CVE-2021-44228")["date_added"], "2021-12-10")
        self.assertIsNone(fetch_advisory.parse_kev(data, "CVE-2000-0001"))

    def test_rejects_bad_id(self):
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()), open(os.devnull, "w") as dn:
                old, sys.stderr = sys.stderr, dn
                try:
                    fetch_advisory.main(["log4shell"])
                finally:
                    sys.stderr = old

    @unittest.skipIf(os.environ.get("REA_SEC_OFFLINE"), "offline")
    def test_live_log4shell(self):
        r = fetch_advisory.fetch("CVE-2021-44228")
        self.assertEqual(r["nvd"]["cvss"]["score"], 10.0)
        self.assertIn("CWE-917", r["nvd"]["cwes"])
        self.assertEqual(r["kev"]["date_added"], "2021-12-10")
        md = fetch_advisory.to_markdown(r)
        self.assertNotIn("packetstormsecurity", md)


if __name__ == "__main__":
    unittest.main()
