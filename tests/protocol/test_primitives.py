import unittest

from cr01_sc.primitives import run_acvp_readiness


class AcvpReadinessTests(unittest.TestCase):
    def test_known_answer_and_self_consistency_checks_pass(self):
        report = run_acvp_readiness()
        summary = report["summary"]

        self.assertEqual(summary["total_checks"], summary["passed_checks"])
        self.assertFalse(summary["official_acvp_run"])
        self.assertFalse(summary["official_fips_validation"])
        self.assertGreaterEqual(summary["known_answer_checks"], 7)
        self.assertEqual(summary["known_answer_checks"], summary["known_answer_passed"])


if __name__ == "__main__":
    unittest.main()
