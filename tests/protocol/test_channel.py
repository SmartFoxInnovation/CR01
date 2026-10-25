"""V2 authentication, key separation, record and real-process restart regressions."""
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import multiprocessing
import os
import pickle
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import mldsa

from cr01_sc import channel as record
from cr01_sc.handshake import HandshakeEndpoint, DOMAIN, canonical, packed, HANDSHAKE_SECONDS
from cr01_sc.demo import run_channel_demo


def responder_worker(connection):
    # Public test identity survives actual worker restarts. Never exchanged over IPC.
    key = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes(range(32)))
    connection.send(key.public_key().public_bytes_raw())
    endpoint = HandshakeEndpoint("responder", key, connection.recv(), application=b"test", epoch=1)
    while True:
        name, value = connection.recv()
        if name == "stop":
            endpoint.close()
            return
        try:
            operations = {"hello": endpoint.respond, "finish": endpoint.accept,
                          "record": lambda frame: endpoint.channel.receive(frame)}
            connection.send((True, operations[name](value)))
        except ValueError:
            connection.send((False, b"rejected"))


class ChannelV2Tests(unittest.TestCase):
    def setUp(self):
        self.i_key = mldsa.MLDSA65PrivateKey.generate()
        self.r_key = mldsa.MLDSA65PrivateKey.generate()
        self.endpoints = []

    def tearDown(self):
        for endpoint in self.endpoints:
            endpoint.close()

    def pair(self, *, application=b"test", epoch=1):
        i = HandshakeEndpoint("initiator", self.i_key, self.r_key.public_key().public_bytes_raw(), application=application, epoch=epoch)
        r = HandshakeEndpoint("responder", self.r_key, self.i_key.public_key().public_bytes_raw(), application=application, epoch=epoch)
        self.endpoints.extend((i, r))
        return i, r

    def complete(self, i, r):
        hello = i.start()
        reply = r.respond(hello)
        finish = i.finish(reply)
        ack = r.accept(finish)
        i.confirm(ack)
        return hello, reply, finish, ack

    def resign(self, frame, key, field, value):
        envelope = json.loads(frame)
        envelope["payload"][field] = value
        envelope["signature"] = key.sign(DOMAIN + packed(canonical(envelope["payload"]))).hex()
        return canonical(envelope)

    def test_no_toy_core_dependency_and_default_demo_passes(self):
        with patch.dict(sys.modules, {"cr01_rsa": None, "cr01_rsa.secret_context": None}):
            result = run_channel_demo()
        self.assertEqual(result["summary"]["status"], "ready")
        self.assertFalse(result["summary"]["toy_core_used"])
        self.assertTrue(all(result["attacks"].values()))
        text = json.dumps(result).lower()
        for secret in ('"private_key"', '"shared_secret"', '"context_secret"', '"confirmation_mac"'):
            self.assertNotIn(secret, text)

    def test_no_channel_before_peer_confirmation(self):
        i, r = self.pair()
        hello = i.start()
        reply = r.respond(hello)
        finish = i.finish(reply)
        for endpoint in (i, r):
            with self.assertRaises(ValueError):
                _ = endpoint.channel
        ack = r.accept(finish)
        with self.assertRaises(ValueError):
            _ = i.channel
        i.confirm(ack)
        self.assertEqual(r.channel.receive(i.channel.send(b"")), b"")

    def test_identity_pins_must_be_distinct_and_policy_explicit(self):
        public = self.i_key.public_key().public_bytes_raw()
        for kwargs in ({"peer_public": public, "application": b"test", "epoch": 1},
                       {"peer_public": b"x", "application": b"test", "epoch": 1},
                       {"peer_public": self.r_key.public_key().public_bytes_raw(), "application": b"", "epoch": 1},
                       {"peer_public": self.r_key.public_key().public_bytes_raw(), "application": b"test", "epoch": True}):
            with self.assertRaises(ValueError):
                HandshakeEndpoint("initiator", self.i_key, **kwargs)

    def test_signed_wrong_identity_role_suite_application_epoch_reject(self):
        for name, value in (("initiator", "00" * 32), ("responder", "00" * 32),
                            ("kind", "responder_hello"), ("suite", "weak"), ("version", 1),
                            ("version", True), ("epoch", 2), ("application", b"other".hex()),
                            ("nonce", "00"), ("extension", 1)):
            with self.subTest(field=name):
                i, r = self.pair()
                frame = self.resign(i.start(), self.i_key, name, value)
                with self.assertRaises(ValueError):
                    r.respond(frame)
                with self.assertRaises(ValueError):
                    _ = r.channel

    def test_untrusted_signer_and_corrupt_signature_reject(self):
        i, r = self.pair()
        frame = json.loads(i.start())
        frame["signature"] = self.r_key.sign(DOMAIN + packed(canonical(frame["payload"]))).hex()
        with self.assertRaises(ValueError):
            r.respond(canonical(frame))

    def test_reply_bound_to_hello_before_encapsulation(self):
        i, r = self.pair()
        reply = r.respond(i.start())
        bad = self.resign(reply, self.r_key, "hello_hash", "00" * 32)
        with self.assertRaises(ValueError):
            i.finish(bad)

    def test_signed_ciphertext_and_finished_tampering_reject(self):
        for field, value in (("kem_ciphertext", "00" * 1088), ("finished", "00" * 32),
                             ("reply_hash", "00" * 32), ("hello_hash", "00" * 32)):
            with self.subTest(field=field):
                i, r = self.pair()
                finish = i.finish(r.respond(i.start()))
                with self.assertRaises(ValueError):
                    r.accept(self.resign(finish, self.i_key, field, value))
                with self.assertRaises(ValueError):
                    _ = r.channel

    def test_wrong_responder_finished_aborts_no_key_release(self):
        i, r = self.pair()
        ack = r.accept(i.finish(r.respond(i.start())))
        with self.assertRaises(ValueError):
            i.confirm(ack[:-1] + b" ")
        with self.assertRaises(ValueError):
            _ = i.channel
        with self.assertRaises(ValueError):
            i.confirm(ack)

    def test_old_hello_and_finish_cannot_reestablish_old_keys(self):
        i, r = self.pair()
        hello, reply, finish, ack = self.complete(i, r)
        old = i.channel.send(b"old")
        new_i, new_r = self.pair()
        fresh_reply = new_r.respond(hello)
        self.assertNotEqual(reply, fresh_reply)
        with self.assertRaises(ValueError):
            new_r.accept(finish)
        with self.assertRaises(ValueError):
            new_i.confirm(ack)
        other_i, other_r = self.pair()
        self.complete(other_i, other_r)
        self.assertNotEqual(i.channel.session_id, other_i.channel.session_id)
        with self.assertRaises(ValueError):
            other_r.channel.receive(old)

    def test_strict_flight_shape_size_duplicate_and_trailing_reject(self):
        for transform in (lambda x: b" " + x, lambda x: x + b"{}", lambda x: b"[]",
                          lambda x: x[:-1] + b',"signature":"00"}', lambda x: b"x" * 32769):
            i, r = self.pair()
            with self.assertRaises(ValueError):
                r.respond(transform(i.start()))

    def test_handshake_replay_phase_and_expiry_fail_closed(self):
        i, r = self.pair()
        hello = i.start()
        with self.assertRaises(ValueError):
            i.start()
        with patch("cr01_sc.handshake.time.monotonic", return_value=r._born + 120):
            with self.assertRaises(ValueError):
                r.respond(hello)

    def test_records_bidirectional_reflection_replay_and_out_of_order(self):
        i, r = self.pair()
        self.complete(i, r)
        frames = [i.channel.send(str(n).encode()) for n in range(3)]
        for n in (2, 0, 1):
            self.assertEqual(r.channel.receive(frames[n]), str(n).encode())
        with self.assertRaises(ValueError):
            r.channel.receive(frames[0])
        with self.assertRaises(ValueError):
            i.channel.receive(frames[0])
        self.assertEqual(i.channel.receive(r.channel.send(b"reply")), b"reply")

    def test_record_tampering_does_not_advance_window(self):
        for position in (0, 4, 5, 24, record.HEADER.size - 1, -1):
            i, r = self.pair()
            self.complete(i, r)
            frame = i.channel.send(b"real", b"aad")
            pos = position % len(frame)
            bad = frame[:pos] + bytes([frame[pos] ^ 1]) + frame[pos + 1:]
            with self.assertRaises(ValueError):
                r.channel.receive(bad)
            self.assertEqual(r.channel.receive(frame, expected_aad=b"aad"), b"real")

    def test_old_window_records_reject_and_state_stays_bounded(self):
        i, r = self.pair()
        self.complete(i, r)
        frames = [i.channel.send(b"x") for _ in range(200)]
        for frame in frames[1:]:
            r.channel.receive(frame)
        with self.assertRaises(ValueError):
            r.channel.receive(frames[0])
        self.assertLessEqual(r.channel._seen.bit_length(), record.WINDOW)

    def test_record_invalid_bounds_versions_lengths_aad_and_types(self):
        i, r = self.pair()
        self.complete(i, r)
        frame = i.channel.send(b"data", b"bound")
        for bad in (b"", frame + b"x", frame[:-1], "text"):
            with self.assertRaises(ValueError):
                r.channel.receive(bad)
        with self.assertRaises(ValueError):
            r.channel.receive(frame, expected_aad=b"wrong")
        self.assertEqual(r.channel.receive(frame, expected_aad=b"bound"), b"data")
        for payload, aad in (("text", b""), (b"", "text"), (b"", b"x" * 65537)):
            with self.assertRaises(ValueError):
                i.channel.send(payload, aad)

    def test_encryption_failure_burns_nonce(self):
        i, r = self.pair()
        self.complete(i, r)
        with patch("cr01_sc.channel.AESGCM", side_effect=RuntimeError("backend failed")):
            with self.assertRaises(RuntimeError):
                i.channel.send(b"failed")
        frame = i.channel.send(b"next")
        self.assertEqual(record.HEADER.unpack_from(frame)[3], 2)
        self.assertEqual(r.channel.receive(frame), b"next")

    def test_concurrent_send_sequences_unique_and_receive_exactly_once(self):
        i, r = self.pair()
        self.complete(i, r)
        channel = i.channel
        with ThreadPoolExecutor(max_workers=8) as pool:
            frames = list(pool.map(lambda _: i.channel.send(b"x"), range(32)))
        self.assertEqual(len({record.HEADER.unpack_from(frame)[3] for frame in frames}), 32)
        incoming = r.channel
        def attempt(_):
            try:
                incoming.receive(frames[0])
                return True
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(16))), 1)

    def test_age_message_cap_clock_rollback_and_closed_fail(self):
        for mode in ("age", "counter", "rollback", "close"):
            i, r = self.pair()
            self.complete(i, r)
            channel = i.channel
            if mode == "counter":
                channel._next = record.MAX_MESSAGES + 1
            if mode == "close":
                channel.close()
            clock = channel._born + record.MAX_AGE if mode == "age" else (channel._born - 1 if mode == "rollback" else channel._born)
            with patch("cr01_sc.channel.time.monotonic", return_value=clock):
                with self.assertRaises(ValueError):
                    channel.send(b"blocked")

    def test_cannot_restore_copy_pickle_or_use_inherited_process_state(self):
        i, r = self.pair()
        self.complete(i, r)
        channel = i.channel
        for obj in (i, channel):
            for operation in (pickle.dumps, copy.copy, copy.deepcopy):
                with self.assertRaises(TypeError):
                    operation(obj)
        with self.assertRaises(ValueError):
            record.RecordChannel(None, b"x" * 16, b"x" * 32, b"y" * 32, 0)
        with patch("os.getpid", return_value=os.getpid() + 1):
            with self.assertRaises(ValueError):
                channel.send(b"fork")

    def test_exact_float_deadline_rejects_without_subtraction_rounding(self):
        born = float.fromhex("0x1.ffffffffffffdp+12")
        for kind,limit in (("handshake",HANDSHAKE_SECONDS),("record",record.MAX_AGE)):
            deadline = born + limit
            # The old subtraction-based check could see an age just below limit.
            self.assertLess(deadline-born,limit)
            for expired in (False,True):
                with self.subTest(kind=kind,at_deadline=expired):
                    i,r=self.pair()
                    if kind=="record": self.complete(i,r)
                    target=i.channel if kind=="record" else i
                    target._born=target._last_clock=born
                    action=(lambda: target.send(b"boundary")) if kind=="record" else target.start
                    now=deadline if expired else math.nextafter(deadline,-math.inf)
                    with patch("cr01_sc.channel.time.monotonic",return_value=now):
                        if expired:
                            with self.assertRaises(ValueError): action()
                        else: self.assertTrue(action())

    def test_real_peer_process_restart_requires_new_handshake(self):
        ctx = multiprocessing.get_context("spawn")
        workers = []
        def start_worker():
            parent, child = ctx.Pipe()
            worker = ctx.Process(target=responder_worker, args=(child,))
            worker.start()
            workers.append((worker, parent))
            child.close()
            self.assertTrue(parent.poll(20), "worker startup timed out")
            public = parent.recv()
            parent.send(self.i_key.public_key().public_bytes_raw())
            return parent, public
        def request(conn, name, value):
            conn.send((name, value))
            self.assertTrue(conn.poll(20), "peer operation timed out")
            return conn.recv()
        try:
            conn, public = start_worker()
            i = HandshakeEndpoint("initiator", self.i_key, public, application=b"test", epoch=1)
            self.endpoints.append(i)
            hello = i.start()
            okay, reply = request(conn, "hello", hello)
            self.assertTrue(okay)
            finish = i.finish(reply)
            okay, ack = request(conn, "finish", finish)
            self.assertTrue(okay)
            i.confirm(ack)
            old_record = i.channel.send(b"before actual restart")
            self.assertEqual(request(conn, "record", old_record), (True, b"before actual restart"))
            workers[0][0].terminate()
            workers[0][0].join(10)
            fresh, same_public = start_worker()
            self.assertEqual(public, same_public)
            self.assertFalse(request(fresh, "record", old_record)[0])
            new_i = HandshakeEndpoint("initiator", self.i_key, public, application=b"test", epoch=1)
            self.endpoints.append(new_i)
            okay, reply2 = request(fresh, "hello", new_i.start())
            self.assertTrue(okay)
            okay, ack2 = request(fresh, "finish", new_i.finish(reply2))
            self.assertTrue(okay)
            new_i.confirm(ack2)
            self.assertNotEqual(i.channel.session_id, new_i.channel.session_id)
            self.assertFalse(request(fresh, "record", old_record)[0])
            self.assertEqual(request(fresh, "record", new_i.channel.send(b"after restart")), (True, b"after restart"))
        finally:
            for worker, connection in workers:
                if worker.is_alive():
                    worker.terminate()
                worker.join(10)
                connection.close()
