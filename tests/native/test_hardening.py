"""Owned-secret failure cleanup, private-file policy and absent production hooks."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from cr01_sc.native import generate_native_identity, native_environment, NativePeer, write_native_pin
from tools.native import COMPILER, compile_native, openssl_flags

ROOT=Path(__file__).resolve().parents[2]


@unittest.skipUnless(COMPILER.is_file(), "Native compiler/OpenSSL prefix not configured")
class NativeHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build=tempfile.TemporaryDirectory(prefix='cr01-hardening-')
        cls.exe=compile_native(Path(cls.build.name)/'engine.exe')
        cls.checks=Path(cls.build.name)/'hardening.exe'
        command=[str(COMPILER),'-std=c++20','-O3','-DNDEBUG','-Wall','-Wextra','-Wpedantic','-Werror',
                 str(ROOT/'tests/native/cpp/hardening_tests.cpp'),*openssl_flags(),'-o',str(cls.checks)]
        done=subprocess.run(command,env=native_environment(),capture_output=True,text=True,timeout=120)
        if done.returncode: raise AssertionError(done.stdout+done.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def test_move_only_locked_memory_cleanses_failures_and_releases(self):
        result=subprocess.run([str(self.checks),'memory'],env=native_environment(),capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        counts=json.loads(result.stdout)
        self.assertGreaterEqual(counts['total'],12)
        self.assertEqual(counts['total'],counts['passed'])
        self.native_hardening_result={'mode':'owned-memory','scope':'application-owned allocations only',**counts}

    def test_rng_keygen_encapsulation_and_sign_failures_close_pending_endpoints(self):
        with tempfile.TemporaryDirectory(prefix='cr01 rng identity failure ') as directory:
            result=subprocess.run([str(self.checks),'rng',str(Path(directory)/'must-not-exist.pem')],
                                  env=native_environment(),capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        counts=json.loads(result.stdout)
        self.assertGreaterEqual(counts['total'],30)
        self.assertEqual(counts['total'],counts['passed'])
        self.native_hardening_result={'mode':'synthetic-backend-failures','randomness_quality_tested':False,**counts}

    def test_coalesced_kdf_slots_match_separate_derivation_and_fail_closed(self):
        result=subprocess.run([str(self.checks),'kdf'],env=native_environment(),capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        counts=json.loads(result.stdout)
        self.assertGreaterEqual(counts['total'],250)
        self.assertEqual(counts['total'],counts['passed'])
        self.native_hardening_result={'mode':'coalesced-kdf-slots','protected_handshake_allocations':8,**counts}

    def test_production_memory_probe_and_no_fault_or_seed_options(self):
        result=subprocess.run([str(self.exe),'--memory-status'],env=native_environment(),capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads(result.stdout)
        self.assertEqual(report['status'],'locked-buffer-probe-passed')
        self.assertEqual(report['provider_memory'],'not covered')
        self.assertEqual(report['rollback_detection'],'not provided')
        if os.name!='nt':
            # A real OS lock-limit denial must not silently use unlocked memory.
            import sys
            code=('import os,resource,sys;resource.setrlimit(resource.RLIMIT_MEMLOCK,(0,0));'
                  'os.execv(sys.argv[1],[sys.argv[1],"--memory-status"])')
            denied=subprocess.run([sys.executable,'-c',code,str(self.exe)],env=native_environment(),
                                  capture_output=True,text=True,timeout=10)
            self.assertNotEqual(denied.returncode,0)
            self.assertEqual(json.loads(denied.stdout),{'status':'rejected'})
        for option in ('--rng-failure','--rng-seed','--memory-failure','--resume','--restore'):
            denied=subprocess.run([str(self.exe),option,'1'],env=native_environment(),capture_output=True,text=True,timeout=10)
            self.assertNotEqual(denied.returncode,0)
            self.assertEqual(json.loads(denied.stdout),{'status':'rejected'})

    def test_generated_identity_is_private_no_overwrite_and_hardlinks_reject(self):
        with tempfile.TemporaryDirectory(prefix='cr01 identity policy ') as directory:
            base=Path(directory);path=base/'private.pem'
            public=generate_native_identity(self.exe,path)
            before=path.read_bytes()
            with self.assertRaises(ValueError):generate_native_identity(self.exe,path)
            self.assertEqual(path.read_bytes(),before)
            other=generate_native_identity(self.exe,base/'other.pem')
            write_native_pin(self.exe,base/'pin.pub',other)
            with self.assertRaises(ValueError):write_native_pin(self.exe,base/'pin.pub',public)
            self.assertEqual((base/'pin.pub').read_bytes(),other)
            peer=NativePeer(self.exe,'initiator',path,base/'pin.pub')
            peer.close()
            self.assertEqual(len(public),1952)
            if os.name!='nt':
                self.assertEqual(path.stat().st_mode & 0o777,0o600)
                path.chmod(0o644)
                with self.assertRaises(ValueError):NativePeer(self.exe,'initiator',path,base/'pin.pub')
                path.chmod(0o600)
                os.symlink(path,base/'linked.pem')
                with self.assertRaises(ValueError):NativePeer(self.exe,'initiator',base/'linked.pem',base/'pin.pub')
                os.mkfifo(base/'pipe.pem',0o600)
                with self.assertRaises(ValueError):NativePeer(self.exe,'initiator',base/'pipe.pem',base/'pin.pub')
            else:
                # A broad allow ACE must be rejected, then remove just that added ACE.
                result=subprocess.run(['icacls',str(path),'/grant','*S-1-1-0:(R)'],capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr)
                try:
                    with self.assertRaises(ValueError):NativePeer(self.exe,'initiator',path,base/'pin.pub')
                finally:
                    result=subprocess.run(['icacls',str(path),'/remove:g','*S-1-1-0'],capture_output=True,text=True,timeout=15)
                    self.assertEqual(result.returncode,0,result.stderr)
            pin=base/'pin.pub'
            if os.name!='nt':
                pin.chmod(0o666)
                with self.assertRaises(ValueError):NativePeer(self.exe,'initiator',path,pin)
                pin.chmod(0o644)
            else:
                result=subprocess.run(['icacls',str(pin),'/grant','*S-1-1-0:(R)'],capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr)
                peer=NativePeer(self.exe,'initiator',path,pin);peer.close() # Public does not mean confidential.
                result=subprocess.run(['icacls',str(pin),'/grant','*S-1-1-0:(W)'],capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr)
                try:
                    with self.assertRaises(ValueError):NativePeer(self.exe,'initiator',path,pin)
                finally:
                    result=subprocess.run(['icacls',str(pin),'/remove:g','*S-1-1-0'],capture_output=True,text=True,timeout=15)
                    self.assertEqual(result.returncode,0,result.stderr)
            os.link(path,base/'alias.pem')
            with self.assertRaises(ValueError):NativePeer(self.exe,'initiator',path,base/'pin.pub')
