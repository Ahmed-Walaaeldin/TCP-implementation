"""
tests.py — test cases for the RUDP transport and the HTTP layer.

Run with:
    python tests.py            # full suite
    python tests.py -v         # verbose
    python -m unittest tests   # same thing via unittest

Covers:
    * Internet checksum correctness and invariants
    * Packet encode/decode round-trip
    * Checksum verification catches corrupted packets
    * HTTP request/response build and parse
    * Full end-to-end GET and POST over loopback
    * GET of missing file returns 404
    * Reliable transfer under simulated packet loss
    * Reliable transfer under simulated packet corruption
    * Deliberately bad checksum triggers retransmission
"""

from __future__ import annotations

import os
import random
import socket
import struct
import tempfile
import threading
import time
import unittest

import rudp
from rudp import (
    RUDPSocket,
    internet_checksum,
    make_packet,
    parse_packet,
    FLAG_SYN, FLAG_ACK, FLAG_FIN,
    HEADER_LEN,
    HEADER_FMT,
)
from http_message import HTTPRequest, HTTPResponse, Headers
from http_server import HTTPServer
from http_client import http_get, http_post


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def free_port() -> int:
    """Grab a free UDP port from the OS."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run_server(**kwargs) -> tuple[HTTPServer, threading.Thread, int]:
    port = free_port()
    server = HTTPServer(host="127.0.0.1", port=port, **kwargs)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    # Give accept() time to start listening on the UDP socket.
    time.sleep(0.15)
    return server, t, port


# ---------------------------------------------------------------------------
# Checksum tests
# ---------------------------------------------------------------------------

class ChecksumTests(unittest.TestCase):

    def test_empty(self):
        # Checksum of empty data: sum is 0, complement is 0xFFFF.
        self.assertEqual(internet_checksum(b""), 0xFFFF)

    def test_known_vector(self):
        # Classic RFC 1071 example: summing 0x0001, 0xF203, 0xF4F5, 0xF6F7
        data = struct.pack("!HHHH", 0x0001, 0xF203, 0xF4F5, 0xF6F7)
        # sum = 0x0001 + 0xF203 + 0xF4F5 + 0xF6F7 = 0x2DDF0 -> fold -> 0xDDF2
        # complement -> 0x220D
        self.assertEqual(internet_checksum(data), 0x220D)

    def test_odd_length_padding(self):
        # Odd-length data should pad logically with 0x00.
        self.assertEqual(internet_checksum(b"\x12\x34\x56"),
                         internet_checksum(b"\x12\x34\x56\x00"))

    def test_checksum_is_16_bit(self):
        for _ in range(200):
            data = os.urandom(random.randrange(0, 2048))
            c = internet_checksum(data)
            self.assertTrue(0 <= c <= 0xFFFF)

    def test_self_verifying_when_aligned(self):
        # Classic RFC 1071 property: if the checksum is placed at a
        # 16-bit-aligned position, summing data + stored-checksum gives
        # all-ones, so internet_checksum() of the whole thing returns 0.
        payload = b"Alexandria University Lab 4!"  # 28 bytes, even
        c = internet_checksum(payload)
        verified = internet_checksum(payload + struct.pack("!H", c))
        self.assertEqual(verified, 0x0000)

    def test_bit_sensitivity(self):
        # Any single-bit flip in the data must change the checksum.
        base = b"The quick brown fox jumps over the lazy dog."
        c0 = internet_checksum(base)
        for bit_pos in range(0, 8 * len(base), 17):  # sample every 17 bits
            flipped = bytearray(base)
            flipped[bit_pos // 8] ^= 1 << (bit_pos % 8)
            self.assertNotEqual(internet_checksum(bytes(flipped)), c0,
                                f"checksum unchanged after flipping bit {bit_pos}")


# ---------------------------------------------------------------------------
# Packet encode / decode tests
# ---------------------------------------------------------------------------

class PacketTests(unittest.TestCase):

    def test_roundtrip_syn(self):
        pkt = make_packet(seq=42, ack=0, flags=FLAG_SYN)
        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["seq"], 42)
        self.assertEqual(parsed["flags"], FLAG_SYN)
        self.assertEqual(parsed["payload"], b"")

    def test_roundtrip_data(self):
        body = b"the quick brown fox jumps over the lazy dog"
        pkt = make_packet(seq=100, ack=200, flags=0, payload=body)
        parsed = parse_packet(pkt)
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["seq"], 100)
        self.assertEqual(parsed["ack"], 200)
        self.assertEqual(parsed["payload"], body)

    def test_short_packet_returns_none(self):
        self.assertIsNone(parse_packet(b"abc"))
        self.assertIsNone(parse_packet(b""))

    def test_corrupted_header_detected(self):
        body = b"payload"
        pkt = bytearray(make_packet(seq=1, ack=1, flags=0, payload=body))
        # Flip a bit in the sequence number — checksum must fail.
        pkt[0] ^= 0x01
        parsed = parse_packet(bytes(pkt))
        self.assertIsNotNone(parsed)
        self.assertFalse(parsed["valid"])

    def test_corrupted_payload_detected(self):
        body = b"payload"
        pkt = bytearray(make_packet(seq=1, ack=1, flags=0, payload=body))
        # Flip a bit deep in the payload.
        pkt[HEADER_LEN + 2] ^= 0x80
        parsed = parse_packet(bytes(pkt))
        self.assertFalse(parsed["valid"])

    def test_truncated_payload_detected(self):
        body = b"payload"
        pkt = make_packet(seq=1, ack=1, flags=0, payload=body)
        parsed = parse_packet(pkt[:-3])  # strip last 3 bytes of payload
        self.assertIsNotNone(parsed)
        self.assertFalse(parsed["valid"])


# ---------------------------------------------------------------------------
# HTTP message tests
# ---------------------------------------------------------------------------

class HTTPMessageTests(unittest.TestCase):

    def test_request_roundtrip_get(self):
        req = HTTPRequest(method="GET", path="/index.html",
                          headers={"Host": "x:1", "User-Agent": "ut"})
        raw = req.to_bytes()
        parsed = HTTPRequest.from_bytes(raw)
        self.assertEqual(parsed.method, "GET")
        self.assertEqual(parsed.path, "/index.html")
        self.assertEqual(parsed.version, "HTTP/1.0")
        self.assertEqual(parsed.headers["host"], "x:1")     # case-insensitive
        self.assertEqual(parsed.body, b"")

    def test_request_roundtrip_post(self):
        body = b"key=value&foo=bar"
        req = HTTPRequest(method="POST", path="/submit",
                          headers={"Content-Type": "application/x-www-form-urlencoded"},
                          body=body)
        raw = req.to_bytes()
        parsed = HTTPRequest.from_bytes(raw)
        self.assertEqual(parsed.method, "POST")
        self.assertEqual(parsed.body, body)
        self.assertEqual(parsed.headers["Content-Length"], str(len(body)))

    def test_response_roundtrip(self):
        resp = HTTPResponse(status=200, body=b"<h1>ok</h1>")
        raw = resp.to_bytes()
        parsed = HTTPResponse.from_bytes(raw)
        self.assertEqual(parsed.status, 200)
        self.assertEqual(parsed.reason, "OK")
        self.assertEqual(parsed.body, b"<h1>ok</h1>")
        self.assertEqual(parsed.headers["Content-Length"], "11")

    def test_404_status(self):
        resp = HTTPResponse(status=404, body=b"x")
        self.assertIn(b"404 Not Found", resp.to_bytes())

    def test_headers_case_insensitive(self):
        h = Headers({"Content-Type": "text/html"})
        self.assertEqual(h["content-type"], "text/html")
        self.assertIn("CONTENT-TYPE", h)
        h["content-length"] = "5"
        # still only one logical entry
        self.assertEqual(len(h), 2)


# ---------------------------------------------------------------------------
# End-to-end integration tests
# ---------------------------------------------------------------------------

class HTTPEndToEndTests(unittest.TestCase):
    """Run a real server in a thread and exercise it with a real client
    over loopback UDP."""

    def setUp(self):
        # Fresh webroot per test so concurrent runs don't collide.
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        # Seed some content.
        with open(os.path.join(self.root, "index.html"), "wb") as f:
            f.write(b"<h1>hello from test</h1>")
        with open(os.path.join(self.root, "data.bin"), "wb") as f:
            f.write(bytes(range(256)) * 20)  # ~5 KB, forces several RUDP segments
        self.server, self.thread, self.port = run_server(webroot=self.root)

    def tearDown(self):
        # The daemon thread will die with the process; we also want to free
        # the port promptly for other tests.
        try:
            self.server._sock.destroy()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_get_200(self):
        r = http_get("127.0.0.1", self.port, "/index.html")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, b"<h1>hello from test</h1>")
        self.assertIn("content-length", r.headers)

    def test_get_404(self):
        r = http_get("127.0.0.1", self.port, "/does-not-exist")
        self.assertEqual(r.status, 404)
        self.assertIn(b"404", r.body)

    def test_get_multi_segment_file(self):
        r = http_get("127.0.0.1", self.port, "/data.bin")
        self.assertEqual(r.status, 200)
        self.assertEqual(len(r.body), 256 * 20)
        self.assertEqual(r.body, bytes(range(256)) * 20)

    def test_post_and_get_back(self):
        payload = b"This is some POST data.\n" * 100  # force segmentation
        r = http_post("127.0.0.1", self.port, "/uploads/u1.bin", payload,
                      content_type="application/octet-stream")
        self.assertEqual(r.status, 201)
        self.assertEqual(r.headers.get("Location"), "/uploads/u1.bin")

        # Round-trip via GET.
        r2 = http_get("127.0.0.1", self.port, "/uploads/u1.bin")
        self.assertEqual(r2.status, 200)
        self.assertEqual(r2.body, payload)


# ---------------------------------------------------------------------------
# Reliability under simulated loss / corruption
# ---------------------------------------------------------------------------

class ReliabilityTests(unittest.TestCase):
    """Validate that retransmission recovers from packet loss and that
    bad checksums cause the receiver to drop the packet, which in turn
    causes the sender to retransmit."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        # Use moderately large payload so there are lots of segments to
        # exercise the stop-and-wait loop.
        self.expected = b"Z" * 3000
        with open(os.path.join(self.root, "big.txt"), "wb") as f:
            f.write(self.expected)

    def tearDown(self):
        try:
            self._server_sock_destroy()
        except Exception:
            pass
        self.tmp.cleanup()

    def _server_sock_destroy(self):
        self.server._sock.destroy()

    def _run_with(self, loss: float, corrupt: float, seed: int):
        random.seed(seed)
        self.server, self.thread, port = run_server(
            webroot=self.root, loss_rate=loss, corrupt_rate=corrupt,
        )
        r = http_get("127.0.0.1", port, "/big.txt",
                     loss_rate=loss, corrupt_rate=corrupt)
        return r

    def test_20_percent_loss(self):
        r = self._run_with(loss=0.20, corrupt=0.0, seed=1)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, self.expected)

    def test_20_percent_corruption(self):
        r = self._run_with(loss=0.0, corrupt=0.20, seed=2)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, self.expected)

    def test_mixed_10_percent_each(self):
        r = self._run_with(loss=0.10, corrupt=0.10, seed=3)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, self.expected)


class ForcedBadChecksumTests(unittest.TestCase):
    """One deterministic tamper proves the checksum path actually
    triggers a retransmit, as the lab asks for."""

    def test_one_forced_bad_checksum_then_retransmit(self):
        # Server echo-style: receive a small GET, reply with a known body.
        tmp = tempfile.TemporaryDirectory()
        try:
            with open(os.path.join(tmp.name, "hi.txt"), "wb") as f:
                f.write(b"pong")
            server, thread, port = run_server(webroot=tmp.name)

            # Build a client that corrupts its very first DATA send.
            sock = RUDPSocket()
            try:
                sock.connect(("127.0.0.1", port))
                # Arm one deliberate bad checksum. The server must drop the
                # first DATA segment, the client times out, retransmits,
                # and the second attempt succeeds.
                sock.force_bad_checksum_next_send()
                req = HTTPRequest("GET", "/hi.txt", headers={"Host": f"127.0.0.1:{port}"})
                sock.send(req.to_bytes())
                # Read response
                from http_message import read_full_response
                resp = read_full_response(sock, expect_close=True)
            finally:
                sock.close()
                sock.destroy()

            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.body, b"pong")
            # And we should have recorded at least one retransmission.
            self.assertGreaterEqual(sock.stats["retransmissions"], 1)
        finally:
            try:
                server._sock.destroy()
            except Exception:
                pass
            tmp.cleanup()


if __name__ == "__main__":
    # unittest's default test runner. Exit code is non-zero on failure.
    unittest.main(verbosity=2)
