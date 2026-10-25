"""Actual C++ application ↔ Python endpoint interoperability, no private state IPC."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, ec

from cr01_sc.handshake import HandshakeEndpoint, DOMAIN, canonical, packed
from tools.native import COMPILER, compile_native
from cr01_sc.native import MAX_LINE, NativePeer, complete, generate_native_identity, native_environment, write_native_pin


@unittest.skipUnless(COMPILER.is_file(), "MSYS2 UCRT64 compiler unavailable")
class NativeV2Tests(unittest.TestCase):
    peer_transport = "json"
    @classmethod
    def setUpClass(cls):
        cls.build_temp = tempfile.TemporaryDirectory(prefix="cr01-native-v2-build-")
        cls.exe = compile_native(Path(cls.build_temp.name) / "channel.exe")
        cls.unit_exe = compile_native(Path(cls.build_temp.name) / "endpoint-tests.exe", unit=True)

    @classmethod
    def tearDownClass(cls):
        cls.build_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cr01-native-v2-")
        self.work = Path(self.temp.name)
        self.i_key, self.r_key = mldsa.MLDSA65PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()
        self.peers = []
        for name, key in (("i", self.i_key), ("r", self.r_key)):
            generate_native_identity(self.exe,self.work/(name+".pem")) # Establish private owner/ACL before fixture serialization.
            (self.work / (name + ".pem")).write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            if os.name != "nt":
                (self.work / (name + ".pem")).chmod(0o600)
            write_native_pin(self.exe,self.work/(name+".pub"),key.public_key().public_bytes_raw())

    def tearDown(self):
        for peer in self.peers:
            peer.close()
        self.temp.cleanup()

    def native(self, role, **kwargs):
        own, other = ("i", "r") if role == "initiator" else ("r", "i")
        peer = self.native_peer(self.exe, role, self.work / (own + ".pem"), self.work / (other + ".pub"), **kwargs)
        self.peers.append(peer)
        return peer

    def native_peer(self, *args, **kwargs):
        kwargs.setdefault("transport", self.peer_transport)
        return NativePeer(*args, **kwargs)

    def python(self, role, **kwargs):
        own, other = (self.i_key, self.r_key) if role == "initiator" else (self.r_key, self.i_key)
        return HandshakeEndpoint(role, own, other.public_key().public_bytes_raw(), application=kwargs.get("application", b"native-v2-test"), epoch=kwargs.get("epoch", 1))

    def test_both_language_directions_and_two_native_peers(self):
        for languages in (("python", "native"), ("native", "python"), ("native", "native")):
            with self.subTest(languages=languages):
                initiator = getattr(self, languages[0])("initiator")
                responder = getattr(self, languages[1])("responder")
                complete(initiator, responder)
                self.assertEqual(initiator.channel.session_id, responder.channel.session_id)
                frame = initiator.channel.send(b"native/Python full handshake", b"interop")
                self.assertEqual(responder.channel.receive(frame, expected_aad=b"interop"), b"native/Python full handshake")
                self.assertEqual(initiator.channel.receive(responder.channel.send(b"reply")), b"reply")

    def test_native_generated_identity_python_verifies(self):
        path = self.work / "fresh-native.pem"
        public = generate_native_identity(self.exe, path)
        self.assertEqual(len(public), 1952)
        # Public-wire interoperability, not a private-PEM format portability claim.
        responder = self.native_peer(self.exe, "responder", path, self.work / "i.pub")
        self.peers.append(responder)
        initiator = HandshakeEndpoint("initiator", self.i_key, public, application=b"native-v2-test", epoch=1)
        complete(initiator, responder)
        self.assertEqual(initiator.channel.receive(responder.channel.send(b"native generated identity")), b"native generated identity")
        original = path.read_bytes()
        with self.assertRaises(ValueError):
            generate_native_identity(self.exe, path)
        self.assertEqual(path.read_bytes(), original)
        with self.subTest(key_origin="native-generated-both"):
            second_path = self.work / "second-native.pem"
            second_public = generate_native_identity(self.exe, second_path)
            write_native_pin(self.exe,self.work/"first-native.pub",public)
            write_native_pin(self.exe,self.work/"second-native.pub",second_public)
            native_i = self.native_peer(self.exe, "initiator", second_path, self.work / "first-native.pub")
            native_r = self.native_peer(self.exe, "responder", path, self.work / "second-native.pub")
            self.peers.extend((native_i, native_r))
            complete(native_i, native_r)
            self.assertEqual(native_r.channel.receive(native_i.channel.send(b"all native keys and crypto")), b"all native keys and crypto")

    def test_reused_cipher_state_after_repeated_authentication_failures(self):
        for native_role in ("initiator", "responder"):
            with self.subTest(native_role=native_role):
                native = self.native(native_role)
                python = self.python("responder" if native_role == "initiator" else "initiator")
                complete(native, python) if native_role == "initiator" else complete(python, native)
                for index, size in enumerate((0,1,15,16,17,1024,16384,65536)*2):
                    data = (bytes(range(256)) * ((size+255)//256))[:size]
                    aad = b"" if index%2 else b"changing application AAD"
                    for sender, receiver in ((python.channel,native), (native,python.channel)):
                        frame = sender.send(data,aad)
                        for mutation in (frame[:-1]+bytes([frame[-1]^1]), frame[:-2]+bytes([frame[-2]^128])+frame[-1:]):
                            with self.assertRaises(ValueError): receiver.receive(mutation,expected_aad=aad)
                        with self.assertRaises(ValueError): receiver.receive(frame,expected_aad=aad+b"wrong")
                        self.assertEqual(receiver.receive(frame,expected_aad=aad),data)
                        with self.assertRaises(ValueError): receiver.receive(frame)

    def test_flight_codec_does_not_repair_noncanonical_or_nested_input(self):
        source=self.python("initiator").start()
        original=json.loads(source)
        changed=json.loads(source);changed["payload"]["nonce"]={"nested":"not a nonce"}
        changed["signature"]=self.i_key.sign(DOMAIN+packed(canonical(changed["payload"]))).hex()
        mutations=[b" "+source,source+b" ",source.replace(b'"version":2',b'"version":2.0'),
                   source.replace(b'"epoch":1',b'"epoch":01'),
                   source.replace(b'"nonce":',b'"nonce":"00","nonce":'),
                   source.replace(b'ML-KEM',b'\\u004dL-KEM'),canonical(changed),
                   json.dumps(original,sort_keys=False,indent=2).encode(),
                   source.replace(b'"payload":{',b'"payload":[')]
        for index,frame in enumerate(mutations):
            with self.subTest(mutation=index):
                peer=self.native("responder")
                with self.assertRaises(ValueError):peer.respond(frame)
                self.assertEqual(peer.command("status")["phase"],"closed")

    def test_flight_codec_maximum_application_and_epoch_interoperate(self):
        application=bytes(range(256))*4;epoch=(1<<64)-1
        for native_role in ("initiator","responder"):
            peer=self.native(native_role,application=application,epoch=epoch)
            other=self.python("responder" if native_role=="initiator" else "initiator",application=application,epoch=epoch)
            complete(peer,other) if native_role=="initiator" else complete(other,peer)
            self.assertEqual(other.channel.receive(peer.send(b"maximum policy binding")),b"maximum policy binding")

    @staticmethod
    def resign(frame, signer, field, value):
        message = json.loads(frame)
        message["payload"][field] = value
        message["signature"] = signer.sign(DOMAIN + packed(canonical(message["payload"]))).hex()
        return canonical(message)

    def test_signed_client_policy_role_and_shape_mutations_reject(self):
        changes = (("version", 1), ("version", True), ("epoch", True), ("epoch", 2),
                   ("suite", "weak"), ("application", "00"), ("initiator", "00" * 32),
                   ("responder", "00" * 32), ("kind", "responder_hello"), ("nonce", "00"), ("extension", 1))
        for field, value in changes:
            with self.subTest(field=field, value=value):
                initiator, responder = self.python("initiator"), self.native("responder")
                hello = initiator.start()
                with self.assertRaises(ValueError):
                    responder.respond(self.resign(hello, self.i_key, field, value))
                self.assertEqual(responder.command("status")["phase"], "closed")

    def test_signed_responder_policy_and_binding_mutations_reject(self):
        for field, value in (("hello_hash", "00" * 32), ("kem_public", "00"), ("nonce", "00"),
                             ("kind", "initiator_hello"), ("suite", "weak"), ("epoch", 2), ("responder", "00" * 32)):
            with self.subTest(field=field):
                initiator, responder = self.native("initiator"), self.python("responder")
                reply = responder.respond(initiator.start())
                with self.assertRaises(ValueError):
                    initiator.finish(self.resign(reply, self.r_key, field, value))
                self.assertEqual(initiator.command("status")["phase"], "closed")

    def test_signed_client_finish_mutations_reject(self):
        for field, value in (("hello_hash", "00" * 32), ("reply_hash", "00" * 32),
                             ("kem_ciphertext", "00" * 1088), ("kem_ciphertext", "00"),
                             ("finished", "00" * 32), ("kind", "responder_finished"), ("epoch", False)):
            with self.subTest(field=field):
                initiator, responder = self.python("initiator"), self.native("responder")
                finish = initiator.finish(responder.respond(initiator.start()))
                with self.assertRaises(ValueError):
                    responder.accept(self.resign(finish, self.i_key, field, value))
                with self.assertRaises(ValueError):
                    _ = responder.channel

    def test_untrusted_signatures_reject_in_both_roles(self):
        unknown = mldsa.MLDSA65PrivateKey.generate()
        for native_role in ("initiator", "responder"):
            with self.subTest(role=native_role):
                if native_role == "responder":
                    native, python = self.native("responder"), self.python("initiator")
                    frame = python.start()
                    operation = native.respond
                else:
                    native, python = self.native("initiator"), self.python("responder")
                    frame = python.respond(native.start())
                    operation = native.finish
                payload = json.loads(frame)
                payload["signature"] = unknown.sign(DOMAIN + packed(canonical(payload["payload"]))).hex()
                with self.assertRaises(ValueError):
                    operation(canonical(payload))

    def test_no_channel_before_confirmation_or_after_bad_finished(self):
        for native_role in ("initiator", "responder"):
            with self.subTest(role=native_role):
                i = self.native("initiator") if native_role == "initiator" else self.python("initiator")
                r = self.native("responder") if native_role == "responder" else self.python("responder")
                hello, reply = i.start(), None
                reply = r.respond(hello)
                finish = i.finish(reply)
                native = i if native_role == "initiator" else r
                with self.assertRaises(ValueError):
                    native.send(b"too early")
                self.assertIn(native.command("status")["phase"], ("await_confirm", "await_finish"))
                ack = r.accept(finish)
                if native_role == "initiator":
                    with self.assertRaises(ValueError):
                        i.confirm(ack + b" ")
                    with self.assertRaises(ValueError):
                        i.send(b"never confirmed")
                else:
                    i.confirm(ack)
                    self.assertEqual(i.channel.receive(r.channel.send(b"confirmed")), b"confirmed")

    def test_actual_native_restart_both_roles_rejects_old_records(self):
        for native_role in ("initiator", "responder"):
            with self.subTest(role=native_role):
                i = self.native("initiator") if native_role == "initiator" else self.python("initiator")
                r = self.native("responder") if native_role == "responder" else self.python("responder")
                complete(i, r)
                native, remote = (i, r) if native_role == "initiator" else (r, i)
                old_sid = native.channel.session_id
                old_record = remote.channel.send(b"old session")
                self.assertEqual(native.channel.receive(old_record), b"old session")
                identity_before = native.ready["public_key"]
                native.close()
                restarted = self.native(native_role)
                self.assertEqual(restarted.ready["public_key"], identity_before)
                with self.assertRaises(ValueError):
                    restarted.receive(old_record)
                other = self.python("responder" if native_role == "initiator" else "initiator")
                complete(restarted, other) if native_role == "initiator" else complete(other, restarted)
                self.assertNotEqual(restarted.channel.session_id, old_sid)
                with self.assertRaises(ValueError):
                    restarted.channel.receive(old_record)
                self.assertEqual(restarted.channel.receive(other.channel.send(b"fresh after restart")), b"fresh after restart")

    def test_old_handshake_transcript_cannot_reestablish_native_keys(self):
        i, r = self.native("initiator"), self.native("responder")
        hello, reply, finish, ack = complete(i, r)
        i.close(); r.close()
        new_r = self.native("responder")
        self.assertNotEqual(new_r.respond(hello), reply)
        with self.assertRaises(ValueError):
            new_r.accept(finish)
        new_i = self.native("initiator")
        self.assertNotEqual(new_i.start(), hello)
        with self.assertRaises(ValueError):
            new_i.finish(reply)

    def test_record_tamper_reflection_and_auth_failure_do_not_advance(self):
        for native_role in ("initiator", "responder"):
            with self.subTest(role=native_role):
                i = self.native("initiator") if native_role == "initiator" else self.python("initiator")
                r = self.native("responder") if native_role == "responder" else self.python("responder")
                complete(i, r)
                native, remote = (i, r) if native_role == "initiator" else (r, i)
                own = native.channel.send(b"own")
                with self.assertRaises(ValueError):
                    native.channel.receive(own)
                for position in (0, 4, 5, 24, 36, -1):
                    frame = remote.channel.send(b"good", b"aad")
                    bad = bytearray(frame); bad[position] ^= 1
                    with self.assertRaises(ValueError):
                        native.channel.receive(bytes(bad))
                    with self.assertRaises(ValueError):
                        native.channel.receive(frame, expected_aad=b"wrong")
                    self.assertEqual(native.channel.receive(frame, expected_aad=b"aad"), b"good")
                    with self.assertRaises(ValueError):
                        native.channel.receive(frame)

    def test_native_replay_window_and_payload_boundaries(self):
        i, r = self.python("initiator"), self.native("responder")
        complete(i, r)
        frames = [i.channel.send(str(index).encode()) for index in range(130)]
        for index in (2, 1):
            self.assertEqual(r.channel.receive(frames[index]), str(index).encode())
        for index in range(3, 130):
            r.channel.receive(frames[index])
        with self.assertRaises(ValueError):
            r.channel.receive(frames[0])
        for payload in (b"", bytes(range(256)), b"x" * (8 * 1024 * 1024)):
            frame = i.channel.send(payload, b"x" * 65536)
            self.assertEqual(r.channel.receive(frame), payload)
        with self.assertRaises(ValueError):
            r.channel.send(b"", b"x" * 65537)

    def test_strict_canonical_flights_and_no_state_import_commands(self):
        for mutation in (lambda x: b" " + x, lambda x: x + b"{}", lambda x: b"[]",
                         lambda x: x[:-1] + b',"signature":"00"}'):
            i, r = self.python("initiator"), self.native("responder")
            with self.assertRaises(ValueError):
                r.respond(mutation(i.start()))
        peer = self.native("initiator")
        for line in ('[]', '{"op":"start","op":"status"}', '{"op":"export_session"}',
                     '{"op":"resume","state":"00"}', '{"op":"set_sequence","sequence":1}',
                     '{"op":"respond","data":"0"}', '{"op":"start","extra":1}'):
            self.assertEqual(peer.raw(line), {"status": "rejected"})
        self.assertEqual(peer.command("status")["phase"], "new_i")
        self.assertTrue(peer.start())

    def test_truncated_command_at_eof_is_not_executed(self):
        peer = self.native("initiator")
        peer.process.stdin.write('{"op":"start"}')
        peer.process.stdin.close()
        self.assertEqual(peer._read(), {"status": "rejected"})
        self.assertNotEqual(peer.process.wait(timeout=10), 0)

    def test_oversize_command_fails_with_json_and_bounded_input(self):
        peer = self.native("initiator")
        try:
            peer.process.stdin.write("x" * (MAX_LINE + 1) + "\n")
            peer.process.stdin.flush()
        except BrokenPipeError:
            pass
        self.assertEqual(peer._read(), {"status": "rejected"})
        self.assertNotEqual(peer.process.wait(timeout=15), 0)

    def test_native_core_lifecycle_concurrency_pid_and_nonce_controls(self):
        done = subprocess.run([str(self.unit_exe)], capture_output=True, text=True,
                              env=native_environment(), timeout=30)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        result = json.loads(done.stdout)
        self.native_core_result = result
        self.assertGreaterEqual(result["total"], 20)
        self.assertEqual(result["passed"], result["total"])

    def test_reused_ciphertext_output_variable_sizes_no_stale_tail(self):
        for native_role in ("initiator", "responder"):
            with self.subTest(role=native_role):
                native=self.native(native_role)
                peer=self.python("responder" if native_role=="initiator" else "initiator")
                complete(native,peer) if native_role=="initiator" else complete(peer,native)
                for size in (1048577,16383,16384,16385,32767,32768,32769,1048575,1048576,0,1,17):
                    data=b"x"*size;frame=native.send(data,b"changing AAD")
                    self.assertEqual(len(frame),37+len(b"changing AAD")+size+16)
                    self.assertEqual(peer.channel.receive(frame),data)
                    incoming=peer.channel.send(data,b"peer AAD")
                    with self.assertRaises(ValueError):native.receive(incoming[:-1]+bytes([incoming[-1]^1]))
                    self.assertEqual(native.receive(incoming),data)

    def test_receive_rejection_never_contains_plaintext_or_commits_replay(self):
        from cr01_sc import binary as binary
        for role in ("initiator","responder"):
            native=self.native(role);peer=self.python("responder" if role=="initiator" else "initiator")
            complete(native,peer) if role=="initiator" else complete(peer,native)
            for size in (0,1,17,16385,1048577):
                data=bytes(range(251))*(size//251)+bytes(range(size%251))
                frame=peer.channel.send(data,b"authenticated binding")
                for rejected in (frame[:-1]+bytes([frame[-1]^1]),frame[:-1],frame+b"extra",frame[:37]+bytes([frame[37]^1])+frame[38:]):
                    raw=b"".join(binary.request("receive",rejected)) if self.peer_transport=="binary" else json.dumps({"op":"receive","data":rejected.hex()})
                    self.assertEqual(native.raw(raw),{"status":"rejected"})
                self.assertEqual(native.receive(frame,expected_aad=b"authenticated binding"),data)
                with self.assertRaises(ValueError):native.receive(frame)

    def test_identity_and_pin_file_type_and_size_boundaries(self):
        key=self.i_key
        public_only=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        wrong=ec.generate_private_key(ec.SECP256R1()).private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        for label,value in (("empty",b""),("oversize",b"x"*65537),("public-only",public_only),("wrong-key",wrong)):
            path=self.work/(label+".pem");path.write_bytes(value)
            with self.subTest(identity=label),self.assertRaises(ValueError):
                self.peers.append(self.native_peer(self.exe,"initiator",path,self.work/"r.pub"))
        for identity,pin in ((self.work,self.work/"r.pub"),(self.work/"i.pem",self.work)):
            with self.subTest(directory=True),self.assertRaises(ValueError):
                self.peers.append(self.native_peer(self.exe,"initiator",identity,pin))
        bad_pin=self.work/"oversize.pub";bad_pin.write_bytes(b"x"*4097)
        with self.assertRaises(ValueError):
            self.peers.append(self.native_peer(self.exe,"initiator",self.work/"i.pem",bad_pin))
        if os.name == "nt":
            # A writer already holding a compatible shared handle must still
            # prevent our checked read. After it closes, normal loading works.
            import ctypes
            from ctypes import wintypes
            library=ctypes.WinDLL("kernel32",use_last_error=True)
            create=library.CreateFileW
            create.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
            create.restype=wintypes.HANDLE
            library.CloseHandle.argtypes=[wintypes.HANDLE]
            library.CloseHandle.restype=wintypes.BOOL
            for name in ("i.pem","r.pub"):
                handle=create(str(self.work/name),0x40000000,7,None,3,0x80,None)
                self.assertNotEqual(handle,ctypes.c_void_p(-1).value)
                try:
                    with self.subTest(open_writer=name),self.assertRaises(ValueError):
                        self.native("initiator")
                finally:
                    self.assertTrue(library.CloseHandle(handle))
            self.native("initiator")

    def test_invalid_native_configuration_never_defaults_to_trust(self):
        for kwargs in ({"epoch": 0}, {"epoch": 1 << 64}, {"application": b""}):
            with self.subTest(config=kwargs), self.assertRaises(ValueError):
                self.native("initiator", **kwargs)
        (self.work / "r.pub").write_bytes(self.i_key.public_key().public_bytes_raw())
        with self.assertRaises(ValueError):
            self.native("initiator")
        (self.work / "r.pub").write_bytes(self.r_key.public_key().public_bytes_raw())
        encrypted = self.i_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.BestAvailableEncryption(b"public-test-password"))
        plain = self.i_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        for label, encoded in (("encrypted", encrypted), ("multiple-keys", plain + plain), ("trailing", plain + b"garbage")):
            with self.subTest(identity_file=label):
                (self.work / "i.pem").write_bytes(encoded)
                with self.assertRaises(ValueError):
                    self.native("initiator")
