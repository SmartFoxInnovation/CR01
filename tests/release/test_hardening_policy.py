"""Release boundary assertions, not operating-system or rollback validation."""
import hashlib
from pathlib import Path
import unittest

from tools.build_release import collect_release_paths,validation_input_hashes

ROOT=Path(__file__).resolve().parents[2]


class HardeningPolicyTests(unittest.TestCase):
    def test_noncommercial_notice_and_licence_remain_exact(self):
        for path,digest in {
            'LICENSE':'c0ea4a896d2c8c394b29f9427589996db826cd501c512279ff0ed3ef48fabbe5',
            'NOTICE':'a9546fe19ba83585d39a13dab785d18722667448ff40b329961d092f3e1cba8e',
        }.items():
            self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),digest)

    def test_secret_and_identity_sources_and_failure_tests_are_shipped_and_bound(self):
        paths=set(collect_release_paths());hashes=validation_input_hashes()
        for path in ('src/cpp/channel_v2_secret.hpp','src/cpp/channel_v2_identity.hpp',
                     'tests/native/cpp/hardening_tests.cpp','tests/native/test_hardening.py'):
            self.assertIn(path,paths)
            self.assertEqual(hashes[path],hashlib.sha256((ROOT/path).read_bytes()).hexdigest())
        self.assertIn('Bytes pin = read_peer_pin(', (ROOT/'src/cpp/main.cpp').read_text())

    def test_rollback_policy_is_a_restriction_not_a_detection_claim(self):
        document=(ROOT/'docs/PROTOCOL.md').read_text(encoding='utf-8')
        for text in ('Live VM snapshots','unsupported','outside the rollback boundary',
                     'not implemented VM rollback detection','Actual hypervisor restores were not tested',
                     'not process-wide','Synthetic failure tests'):
            self.assertIn(text,document)
        self.assertIn('rollback policy',(ROOT/'README.md').read_text())
