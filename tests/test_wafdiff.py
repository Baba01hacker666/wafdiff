import unittest
import argparse
from wafdiff.main import WafDiff

class TestWafDiff(unittest.TestCase):
    def test_init(self):
        args = argparse.Namespace(
            url="http://example.com",
            paths=["/api"],
            payloads=None,
            method="GET",
            threads=1,
            timeout=10,
            delay=0,
            insecure=True,
            proxy=None,
            user_agent=None,
            headers=None
        )
        wd = WafDiff(args)
        self.assertEqual(wd.base_url, "http://example.com")
        self.assertEqual(wd.paths, ["/api"])

if __name__ == '__main__':
    unittest.main()
