import unittest
from phishing_detector import analyze, registered_domain


class DetectorTests(unittest.TestCase):
    def test_legit_site_is_low_risk(self):
        self.assertEqual(analyze("https://www.github.com/anthropics").verdict, "Low risk")

    def test_brand_impersonation_flagged(self):
        r = analyze("http://paypal-secure-login.example.xyz/verify/account")
        self.assertEqual(r.verdict, "High risk")
        self.assertIn("brand_impersonation", [f.rule for f in r.findings])

    def test_ip_host(self):
        self.assertIn("ip_host", [f.rule for f in analyze("http://192.168.1.5/login").findings])

    def test_registered_domain(self):
        self.assertEqual(registered_domain("a.b.example.co.uk"), "example.co.uk")


if __name__ == "__main__":
    unittest.main()
