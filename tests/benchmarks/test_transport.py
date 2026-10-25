"""Benchmark bookkeeping tests, not performance/security thresholds."""
import unittest
from tools.benchmarks.transport import comparison, stats


class TransportBenchmarkTests(unittest.TestCase):
    def test_statistics_keep_observed_slow_tail(self):
        self.assertEqual(stats([1,1,1,100]),{"samples":4,"mean_ms":25.75,"p50_ms":1,"p95_ms":100})

    def test_comparison_uses_median_of_means_not_fastest_sample(self):
        runs=[]
        for kind,values in (("native-json-pipes",[3,6,900]),("native-binary-pipes",[1,2,500])):
            for value in values:
                runs.append({"kind":kind,"records":[{"payload_bytes":size,"mean_ms":value}
                             for size in (64,1024,65536,1048576)]})
        for row in comparison(runs):
            self.assertEqual(row["json_ms"],6)
            self.assertEqual(row["binary_ms"],2)
            self.assertEqual(row["json_over_binary_elapsed_ratio"],3)

    def test_slower_binary_result_is_not_hidden(self):
        runs=[{"kind":kind,"records":[{"payload_bytes":size,"mean_ms":value}
               for size in (64,1024,65536,1048576)]}
              for kind,value in (("native-json-pipes",1),("native-binary-pipes",2))]
        self.assertTrue(all(row["json_over_binary_elapsed_ratio"]==.5 for row in comparison(runs)))
