"""Measurement boundaries and fail-closed diagnostic instrumentation."""
from pathlib import Path
import unittest
from tools.benchmarks.lifecycle import FUNCTIONS, instrument_function, summarize

ROOT = Path(__file__).resolve().parents[2]


class LifecycleTests(unittest.TestCase):
    def test_all_profile_markers_match_current_sources_exactly_once(self):
        for name, functions in FUNCTIONS.items():
            original = (ROOT/'src/cpp'/name).read_text(encoding='utf-8')
            for marker, label in functions:
                with self.subTest(name=name, marker=marker):
                    changed = instrument_function(original, marker, label)
                    self.assertEqual(changed.count('lifecycle_profile::Scope'), 1)
                    self.assertNotIn('lifecycle_profile', original)

    def test_instrumentation_rejects_missing_or_ambiguous_markers(self):
        for source in ('void other() {}', 'void f() {} void f() {}'):
            with self.assertRaises(ValueError): instrument_function(source, 'void f(', 'fixed-label')

    def test_stage_aggregation_retains_slow_runs_and_does_not_combine_costs(self):
        runs=[]
        for value in (1, 4, 100):
            runs.append({'timing': {name: {'raw_ms': [value,value*2]} for name in
                ('identity_load','warm_up','fresh_handshake','running_1k','running_1m')},
                'pipes': {'cold_start_pair_ready_ms': value*10, 'ready_pair_first_handshake_ms': value*3}})
        result=summarize(runs)
        self.assertEqual(result['fresh_handshake']['median_mean_ms'],6)
        self.assertEqual(result['fresh_handshake']['run_means_ms'],[1.5,6,150])
        self.assertEqual(result['cold_start_pair_ready_ms']['median_ms'],40)
        self.assertEqual(result['ready_pair_first_handshake_ms']['median_ms'],12)

    def test_production_sources_do_not_include_diagnostic_profiler(self):
        for path in (ROOT/'src/cpp').glob('*'):
            if path.is_file(): self.assertNotIn('lifecycle_profile', path.read_text(encoding='utf-8'))
