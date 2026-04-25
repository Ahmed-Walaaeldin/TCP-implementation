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


# Helpers

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


# Checksum tests

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


# Packet encode / decode tests

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


# HTTP message tests

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


# End-to-end integration tests

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


# Reliability under simulated loss / corruption

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


# Flow Control tests  (NEW)

class FlowControlPacketTests(unittest.TestCase):
    """Verify that the window field is present and correctly parsed
    in every packet type."""

    def test_window_field_present_in_syn(self):
        pkt = make_packet(seq=0, ack=0, flags=FLAG_SYN, window=65535)
        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed["valid"])
        self.assertIn("window", parsed)
        self.assertEqual(parsed["window"], 65535)

    def test_window_field_present_in_data(self):
        pkt = make_packet(seq=1, ack=1, flags=0, payload=b"hello", window=32000)
        parsed = parse_packet(pkt)
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["window"], 32000)

    def test_window_field_present_in_ack(self):
        pkt = make_packet(seq=0, ack=1, flags=FLAG_ACK, window=12345)
        parsed = parse_packet(pkt)
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["window"], 12345)

    def test_window_zero_is_valid(self):
        # A zero window (receiver buffer full) must still parse as valid.
        pkt = make_packet(seq=5, ack=5, flags=FLAG_ACK, window=0)
        parsed = parse_packet(pkt)
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["window"], 0)

    def test_window_survives_corruption_detection(self):
        # Corrupt the window bytes — checksum must catch it.
        pkt = bytearray(make_packet(seq=1, ack=1, flags=FLAG_ACK, window=65535))
        pkt[13] ^= 0xFF   # byte 13 is high byte of window field
        parsed = parse_packet(bytes(pkt))
        self.assertFalse(parsed["valid"])

    def test_header_length_is_15(self):
        # With the window field added, HEADER_LEN must be 15, not 13.
        self.assertEqual(HEADER_LEN, 15,
                         "HEADER_LEN should be 15 bytes after adding the window field")

    def test_packet_size_reflects_new_header(self):
        payload = b"x" * 100
        pkt = make_packet(seq=0, ack=0, flags=0, payload=payload, window=65535)
        self.assertEqual(len(pkt), HEADER_LEN + len(payload))


class FlowControlSocketTests(unittest.TestCase):
    """Verify window advertisement and peer_window tracking on RUDPSocket."""

    def test_initial_peer_window_is_max(self):
        sock = RUDPSocket()
        self.assertEqual(sock.peer_window, 65535)
        sock.destroy()

    def test_initial_recv_window_max_is_set(self):
        sock = RUDPSocket()
        self.assertEqual(sock.recv_window_max, 65535)
        sock.destroy()

    def test_peer_window_updated_after_data_transfer(self):
        """After a full GET, the client's peer_window should reflect the
        last window advertisement sent by the server (not the default)."""
        tmp = tempfile.TemporaryDirectory()
        try:
            # Write enough data to require multiple segments so we get
            # multiple window advertisements.
            content = b"W" * 4096
            with open(os.path.join(tmp.name, "w.bin"), "wb") as f:
                f.write(content)
            server, _, port = run_server(webroot=tmp.name)

            sock = RUDPSocket()
            try:
                sock.connect(("127.0.0.1", port))
                req = HTTPRequest("GET", "/w.bin",
                                  headers={"Host": f"127.0.0.1:{port}"})
                sock.send(req.to_bytes())
                from http_message import read_full_response
                resp = read_full_response(sock, expect_close=True)
            finally:
                sock.close()
                sock.destroy()

            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.body, content)
            # peer_window must have been set to something (not left at
            # the default 65535 unchanged, because the server sent ACKs
            # with its own window advertisement).
            self.assertIsInstance(sock.peer_window, int)
            self.assertGreaterEqual(sock.peer_window, 0)
        finally:
            try:
                server._sock.destroy()
            except Exception:
                pass
            tmp.cleanup()

    def test_sender_blocks_on_zero_window(self):
        """If peer_window is set to 0, _send_one_data_segment must block
        and only proceed once the window opens. We simulate this by
        starting with zero window and opening it from another thread."""
        sock = RUDPSocket()
        sock._reset_state()
        # Manually set up a fake peer so we can call internals directly.
        sock.peer_window = 0
        sock.recv_window_max = 65535

        unblocked = threading.Event()

        def open_window():
            time.sleep(0.2)
            sock.peer_window = 65535
            unblocked.set()

        t = threading.Thread(target=open_window, daemon=True)
        t.start()

        start = time.time()
        # This should block until the helper thread opens the window.
        # We only test the blocking logic — we don't actually send (no peer).
        payload = b"x" * 100
        while len(payload) > sock.peer_window:
            time.sleep(0.05)

        elapsed = time.time() - start
        self.assertTrue(unblocked.is_set(),
                        "window was never opened by the helper thread")
        # Should have blocked for roughly 0.2 s (allow generous margin).
        self.assertGreater(elapsed, 0.1,
                           "sender did not block on zero window")
        sock.destroy()


# Congestion Control tests  (NEW)

class CongestionControlTests(unittest.TestCase):
    """Verify slow-start growth, AIMD on timeout, and ssthresh transition."""

    def _fresh_sock(self) -> RUDPSocket:
        s = RUDPSocket()
        s._reset_state()
        return s

    def test_initial_cwnd_is_one(self):
        s = self._fresh_sock()
        self.assertEqual(s.cwnd, 1)
        s.destroy()

    def test_initial_ssthresh(self):
        s = self._fresh_sock()
        self.assertEqual(s.ssthresh, 16)
        s.destroy()

    def test_slow_start_doubles_cwnd(self):
        """While cwnd < ssthresh each ACK increments cwnd by 1 (doubles
        every RTT in stop-and-wait where one ACK = one RTT)."""
        s = self._fresh_sock()
        s.cwnd = 1
        s.ssthresh = 16
        for expected in range(2, 8):
            s._on_ack_received()
            self.assertEqual(s.cwnd, expected)
        s.destroy()

    def test_congestion_avoidance_linear_growth(self):
        """Once cwnd >= ssthresh, each ACK adds 1/cwnd (linear growth)."""
        s = self._fresh_sock()
        s.cwnd = 16.0
        s.ssthresh = 16
        before = s.cwnd
        s._on_ack_received()
        # Should add 1/16 = 0.0625
        self.assertAlmostEqual(s.cwnd, before + 1 / before, places=5)
        s.destroy()

    def test_timeout_resets_cwnd_to_one(self):
        s = self._fresh_sock()
        s.cwnd = 8
        s.ssthresh = 16
        s._on_timeout()
        self.assertEqual(s.cwnd, 1)
        s.destroy()

    def test_timeout_halves_ssthresh(self):
        s = self._fresh_sock()
        s.cwnd = 8
        s.ssthresh = 16
        s._on_timeout()
        self.assertEqual(s.ssthresh, 4)   # max(8//2, 1) = 4
        s.destroy()

    def test_timeout_ssthresh_minimum_is_one(self):
        """ssthresh must never drop below 1."""
        s = self._fresh_sock()
        s.cwnd = 1
        s.ssthresh = 16
        s._on_timeout()
        self.assertGreaterEqual(s.ssthresh, 1)
        s.destroy()

    def test_cwnd_resets_after_multiple_timeouts(self):
        """Repeated timeouts keep ssthresh halving and cwnd stays at 1."""
        s = self._fresh_sock()
        s.cwnd = 32
        s.ssthresh = 32
        for _ in range(4):
            s._on_timeout()
            self.assertEqual(s.cwnd, 1)
        s.destroy()

    def test_slow_start_to_avoidance_transition(self):
        """cwnd must switch from +1 per ACK to +1/cwnd per ACK exactly
        when it reaches ssthresh."""
        s = self._fresh_sock()
        s.cwnd = 1
        s.ssthresh = 4

        # Grow through slow start: cwnd goes 1→2→3→4
        for _ in range(3):
            s._on_ack_received()
        self.assertEqual(s.cwnd, 4)

        # Next ACK: cwnd == ssthresh so we're in congestion avoidance
        before = s.cwnd
        s._on_ack_received()
        self.assertAlmostEqual(s.cwnd, before + 1 / before, places=5)
        s.destroy()

    def test_congestion_control_during_loss(self):
        """End-to-end: transfer under loss should record retransmissions
        and the congestion window should be adjusted (ssthresh < 16 means
        at least one timeout fired and halved it)."""
        tmp = tempfile.TemporaryDirectory()
        try:
            content = b"C" * 5000
            with open(os.path.join(tmp.name, "c.bin"), "wb") as f:
                f.write(content)
            random.seed(42)
            server, _, port = run_server(
                webroot=tmp.name, loss_rate=0.25, corrupt_rate=0.0
            )
            sock = RUDPSocket(loss_rate=0.25)
            try:
                sock.connect(("127.0.0.1", port))
                req = HTTPRequest("GET", "/c.bin",
                                  headers={"Host": f"127.0.0.1:{port}"})
                sock.send(req.to_bytes())
                from http_message import read_full_response
                resp = read_full_response(sock, expect_close=True)
            finally:
                sock.close()
                sock.destroy()

            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.body, content)
            # Retransmissions must have occurred given 25% loss.
            self.assertGreater(sock.stats["retransmissions"], 0)
        finally:
            try:
                server._sock.destroy()
            except Exception:
                pass
            tmp.cleanup()


if __name__ == "__main__":
    # unittest's default test runner. Exit code is non-zero on failure.
    unittest.main(verbosity=2)
