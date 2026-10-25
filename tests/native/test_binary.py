"""Same endpoint-security regressions through CRB1, plus framing boundaries."""
import io
import random
import unittest

from tests.native import test_endpoint as base
from cr01_sc import binary as binary
from cr01_sc.native import complete


class BinaryV2Tests(base.NativeV2Tests):
    peer_transport = "binary"

    def test_strict_canonical_flights_and_no_state_import_commands(self):
        for mutation in (lambda x: b" " + x, lambda x: x + b"{}", lambda x: b"[]",
                         lambda x: x[:-1] + b',"signature":"00"}'):
            i, r = self.python("initiator"), self.native("responder")
            with self.assertRaises(ValueError): r.respond(mutation(i.start()))
            self.assertEqual(r.command("status")["phase"], "closed")
        for op in (0, 10, 11, 255):
            with self.subTest(unknown_operation=op):
                peer = self.native("initiator")
                self.assertEqual(peer.raw(binary.HEADER.pack(b"CRB1",op,0,0,0,0,0)), {"status":"rejected"})
                self.assertNotEqual(peer.process.wait(timeout=10),0)

    def test_truncated_command_at_eof_is_not_executed(self):
        packet = b"".join(binary.request("respond", b"short"))
        for cut in (1,8,15,16,20):
            with self.subTest(cut=cut):
                peer = self.native("responder")
                peer.process.stdin.write(packet[:cut]); peer.process.stdin.close()
                self.assertEqual(peer._read(), {"status":"rejected"})
                self.assertNotEqual(peer.process.wait(timeout=10),0)

    def test_oversize_command_fails_with_json_and_bounded_input(self):
        # Header-only invalid requests must fail without waiting for any body.
        for op,flags,phase,reserved,size,aux in (
            (1,0,0,0,1,0),(8,0,0,0,0,1),(9,0,0,0,1,0),
            (2,0,0,0,32769,0),(3,0,0,0,0,1),(4,0,0,0,0xffffffff,0),
            (6,0,0,0,binary.MAX_PAYLOAD+1,0),(6,0,0,0,0,binary.MAX_AAD+1),
            (7,0,0,0,binary.MAX_RECORD+1,0),(7,1,0,0,0,binary.MAX_AAD+1),
            (7,0,0,0,0,1),(7,2,0,0,0,0),(1,1,0,0,0,0),
            (8,0,1,0,0,0),(8,0,0,1,0,0)):
            with self.subTest(header=(op,flags,phase,reserved,size,aux)):
                peer=self.native("initiator")
                header=binary.HEADER.pack(b"CRB1",op,flags,phase,reserved,size,aux)
                self.assertEqual(peer.raw(header),{"status":"rejected"})
                self.assertNotEqual(peer.process.wait(timeout=10),0)

    def test_fragmented_and_coalesced_frames(self):
        peer=self.native("initiator")
        packet=b"".join(binary.request("status"))
        for byte in packet:
            peer.process.stdin.write(bytes([byte])); peer.process.stdin.flush()
        self.assertEqual(peer._read()["phase"],"new_i")
        peer.process.stdin.write(packet*3); peer.process.stdin.flush()
        for _ in range(3): self.assertEqual(peer._read()["phase"],"new_i")
        # Body fragmentation too: no delimiter/newline is part of this transport.
        r=self.native("responder"); i=self.python("initiator"); hello=i.start()
        header,data,aux=binary.request("respond",hello)
        peer_parts=(header[:3],header[3:],data[:7],data[7:111],data[111:],aux)
        for part in peer_parts:
            r.process.stdin.write(part); r.process.stdin.flush()
        reply=r._read()["data"]
        finish=i.finish(reply); ack=r.accept(finish); i.confirm(ack)
        self.assertEqual(r.receive(i.channel.send(b"fragmented handshake")),b"fragmented handshake")

    def test_binary_bytes_and_empty_expected_aad(self):
        i,r=self.python("initiator"),self.native("responder"); complete(i,r)
        data=bytes(range(256))*100  # Includes NUL, CR/LF, Ctrl-Z and non-ASCII.
        frame=i.channel.send(data,b"not empty")
        with self.assertRaises(ValueError): r.receive(frame,expected_aad=b"")
        self.assertEqual(r.receive(frame),data)
        self.assertEqual(r.receive(i.channel.send(data),expected_aad=b""),data)
        self.assertEqual(i.channel.receive(r.send(data,b"\x00\r\n\x1a"),expected_aad=b"\x00\r\n\x1a"),data)

    def test_mixed_json_binary_native_peers(self):
        for first,second in (("json","binary"),("binary","json")):
            with self.subTest(initiator_transport=first,responder_transport=second):
                i,r=self.native("initiator",transport=first),self.native("responder",transport=second)
                complete(i,r)
                self.assertEqual(r.receive(i.send(b"mixed",b"aad"),expected_aad=b"aad"),b"mixed")
                self.assertEqual(i.receive(r.send(b"reply")),b"reply")

    def test_native_maximum_send_and_receive(self):
        i,r=self.native("initiator"),self.native("responder"); complete(i,r)
        data=b"\x00\r\n\x1a"*(binary.MAX_PAYLOAD//4); aad=b"a"*binary.MAX_AAD
        for sender,receiver in ((i,r),(r,i)):
            frame=sender.send(data,aad)
            self.assertEqual(receiver.receive(frame,expected_aad=aad),data)

    def test_invalid_magic_and_deterministic_reserved_mutations(self):
        rng=random.Random(15001)
        for index in range(17):
            peer=self.native("initiator")
            header=bytearray(binary.HEADER.pack(b"CRB1",8,0,0,0,0,0))
            if index==0: header[0]^=1
            else: header[rng.choice((5,6,7))]=rng.randrange(2,256)
            self.assertEqual(peer.raw(bytes(header)),{"status":"rejected"})
            self.assertNotEqual(peer.process.wait(timeout=10),0)

    def test_clean_eof_closes_without_extra_response(self):
        peer=self.native("initiator")
        peer.process.stdin.close()
        self.assertIsNone(peer._responses.get(timeout=20))
        self.assertEqual(peer.process.wait(timeout=10),0)

    def test_partial_live_frame_timeout_closes_driver_and_child(self):
        peer=self.native("initiator")
        peer.process.stdin.write(b"CRB"); peer.process.stdin.flush()
        peer.response_timeout=.05
        with self.assertRaisesRegex(RuntimeError,"timed out"): peer._read()
        self.assertIsNotNone(peer.process.poll())


class BinaryCodecTests(unittest.TestCase):
    def test_request_exact_bytes_and_explicit_empty_expected_aad(self):
        absent=b"".join(binary.request("receive",b"abc"))
        empty=b"".join(binary.request("receive",b"abc",expected_aad=True))
        self.assertEqual(absent,b"CRB1\x07\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00abc")
        self.assertNotEqual(absent,empty)
        self.assertEqual(binary.HEADER.unpack(empty[:16])[2],1)

    def test_response_rejects_bad_headers_before_body_read(self):
        for header in (binary.HEADER.pack(b"bad!",8,0,1,0,0,0),
                       binary.HEADER.pack(b"CRB1",8,0,1,0,binary.MAX_RECORD+1,0),
                       binary.HEADER.pack(b"CRB1",0,2,1,0,1953,0),
                       binary.HEADER.pack(b"CRB1",255,1,1,0,0,0),
                       binary.HEADER.pack(b"CRB1",8,0,6,0,0,0),
                       b"CRB1",binary.HEADER.pack(b"CRB1",1,0,3,0,1,0)):
            with self.subTest(header=header),self.assertRaises(ValueError):
                binary.read_response(io.BytesIO(header))
        self.assertEqual(binary.read_response(io.BytesIO(binary.REJECTION)),{"status":"rejected"})
        self.assertIsNone(binary.read_response(io.BytesIO(b"")))

    def test_partial_writes_complete_without_dropping_bytes(self):
        class Partial(io.BytesIO):
            def write(self,value): return super().write(value[:3])
        stream=Partial(); binary.write_all(stream,(b"abcdef",b"ghijk",b""))
        self.assertEqual(stream.getvalue(),b"abcdefghijk")

    def test_request_limits_and_no_unknown_controls(self):
        for op in ("resume","export_session","set_sequence"):
            with self.assertRaises(ValueError): binary.request(op)
        for args,kwargs in ((("start",b"x"),{}),(("respond",b"x"*32769),{}),
                            (("send",b"",b"x"*65537),{}),(("receive",b"",b"aad"),{}),
                            (("status",),{"expected_aad":True})):
            with self.assertRaises(ValueError): binary.request(*args,**kwargs)
