"""Bookkeeping tests for the diagnostic, not cryptographic validation."""
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location("tls_compare",Path(__file__).resolve().parents[2] / "tools/benchmarks/tls.py")
assessment=importlib.util.module_from_spec(spec);spec.loader.exec_module(assessment)

class AssessmentTests(unittest.TestCase):
    def test_means_do_not_drop_slow_tail(self):
        result=assessment.stats([1,1,1,100])
        self.assertEqual(result["mean_ms"],25.75)
        self.assertEqual(result["p95_ms"],100)
        self.assertEqual(result["raw_ms"],[1,1,1,100])
    def test_fragment_count_and_truncation(self):
        frame=b"\x17\x03\x03\x00\x03abc"
        self.assertEqual(assessment.tls_fragments(frame*4),4)
        with self.assertRaises(AssertionError): assessment.tls_fragments(frame[:-1])
    def test_aggregate_uses_median_of_all_run_means(self):
        rows=[]
        for panel in ("in-process","binary-pipes"):
            for profile in assessment.PROFILES:
                for value in (1,4,100):
                    rows.append({"panel":panel,"profile":profile,"handshake":None if profile.startswith("aes-") else {"mean_ms":value,"wire_bytes":100},
                                 "records":[{"payload_bytes":size,"mean_ms":value,"encoded_bytes":size+22,"fragments":1} for size,_ in assessment.SIZES]})
        for row in assessment.aggregate(rows):
            self.assertTrue(all(x["median_mean_ms"]==4 and x["max_mean_ms"]==100 for x in row["records"]))
            if row["profile"].startswith("aes-"): self.assertIsNone(row["handshake"])

if __name__=="__main__": unittest.main()

