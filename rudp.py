"""
Implements a TCP-like reliable stream abstraction on top of UDP:
    * 3-way handshake            (SYN / SYN-ACK / ACK)
    * Stop-and-Wait ARQ          (one outstanding packet at a time)
    * Internet checksum          (16-bit one's complement)
    * Timeout-based retransmission
    * Duplicate detection        (seq# based, receiver re-ACKs)
    * Connection teardown        (FIN / ACK)
    * Simulated packet loss and packet corruption for testing

The RUDPSocket class exposes a Berkeley-socket-like API:
    bind() / connect() / accept() / send() / recv() / close()

"""

from __future__ import annotations

import os
import random
import socket
import struct
import time
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Packet format
# ---------------------------------------------------------------------------
#
# Our packet carries a fixed 13-byte header followed by up to MAX_PAYLOAD
# payload bytes. All multi-byte fields are network byte order (big-endian).
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                      Sequence Number (32)                     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                   Acknowledgment Number (32)                  |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |  Flags (8)  |        Checksum (16)        |  Payload Len (16) |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                     Payload (variable)                        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Flags bits: SYN=0x01, ACK=0x02, FIN=0x04

FLAG_SYN = 0x01
FLAG_ACK = 0x02
FLAG_FIN = 0x04

HEADER_FMT = "!IIBHHH"  # seq, ack, flags, checksum, plen, window
HEADER_LEN = struct.calcsize(HEADER_FMT)  # recalculate

MAX_PAYLOAD = 1024                          # bytes per RUDP segment
MAX_PACKET = HEADER_LEN + MAX_PAYLOAD

DEFAULT_TIMEOUT = 1.0                       # seconds per retransmission timer
DEFAULT_MAX_RETRIES = 10                    # how many times we retransmit


# ---------------------------------------------------------------------------
# Checksum (Internet checksum, RFC 1071)
# ---------------------------------------------------------------------------

def internet_checksum(data: bytes) -> int:
    """
    Compute the 16-bit Internet checksum (RFC 1071) over `data`.

    Algorithm:
        1. Treat data as a sequence of 16-bit big-endian words. If the
           length is odd, logically append a zero byte.
        2. Sum the words using one's complement addition (any carry out
           of the 16-bit sum is wrapped back in).
        3. The checksum is the one's complement of the final sum.

    Properties we rely on:
        * If the sender places 0 in the checksum field, computes the sum
          over the whole packet, and writes the complement there, then
          the receiver who sums the entire packet (including the stored
          checksum) will get all-ones. Equivalently, we verify by
          recomputing with the field zeroed and comparing to the stored
          checksum.
    """
    if len(data) % 2 == 1:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) | data[i + 1]
        total += w
        # fold carry (one's complement wrap-around) as we go
        total = (total & 0xFFFF) + (total >> 16)
    # Fold one more time in case the last addition produced a carry
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# Packet build / parse

def make_packet(seq, ack, flags, payload=b"", window=65535):
    plen = len(payload)
    zero_hdr = struct.pack(HEADER_FMT, seq, ack, flags, 0, plen, window)
    chk = internet_checksum(zero_hdr + payload)
    real_hdr = struct.pack(HEADER_FMT, seq, ack, flags, chk, plen, window)
    return real_hdr + payload


def parse_packet(raw: bytes) -> Optional[dict]:
    """
    Parse a wire-format packet. Returns a dict with keys
        seq, ack, flags, checksum, payload, valid
    or None if the bytes are too short to even contain a header.

    `valid` is False if the checksum fails. The caller should drop
    invalid packets (simulating a real receiver that cannot trust
    corrupted bytes).
    """
    if len(raw) < HEADER_LEN:
        return None
    seq, ack, flags, chk, plen, window = struct.unpack(HEADER_FMT, raw[:HEADER_LEN])
    payload = raw[HEADER_LEN : HEADER_LEN + plen]
    if len(payload) != plen:
        # truncated payload — treat as corrupted
        return {
            "seq": seq, "ack": ack, "flags": flags,
            "checksum": chk, "payload": payload, "valid": False,
        }
    zero_hdr = struct.pack(HEADER_FMT, seq, ack, flags, 0, plen, window)
    expected = internet_checksum(zero_hdr + payload)
    return {
        "seq": seq, "ack": ack, "flags": flags,
        "checksum": chk, "payload": payload,
        "window": window, "valid": expected == chk,
    }

def flags_to_str(flags: int) -> str:
    """Pretty-print flag bits for logging, e.g. 'SYN|ACK'."""
    names = []
    if flags & FLAG_SYN:
        names.append("SYN")
    if flags & FLAG_ACK:
        names.append("ACK")
    if flags & FLAG_FIN:
        names.append("FIN")
    if not names:
        names.append("DATA")
    return "|".join(names)


# ---------------------------------------------------------------------------
# RUDPSocket — the reliable transport class
# ---------------------------------------------------------------------------

class RUDPSocket:
    """
    A connection-oriented reliable socket implemented on top of UDP.

    Typical usage — server:
        s = RUDPSocket()
        s.bind(("0.0.0.0", 9000))
        s.accept()                 # blocks until 3-way handshake done
        data = s.recv(4096)
        s.send(b"hello")
        s.close()
        s.destroy()

    Typical usage — client:
        c = RUDPSocket()
        c.connect(("127.0.0.1", 9000))
        c.send(b"hi")
        resp = b""
        while True:
            chunk = c.recv(4096)
            if not chunk: break
            resp += chunk
        c.close()
        c.destroy()

    Note: we use Stop-and-Wait ARQ — one outstanding unacknowledged
    packet at a time. Sequence numbers increment by one per packet
    (SYN/DATA/FIN each consume one number; pure ACKs do not).
    """

    # -------------------- construction / lifecycle --------------------

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        loss_rate: float = 0.0,
        corrupt_rate: float = 0.0,
        max_retries: int = DEFAULT_MAX_RETRIES,
        debug: bool = False,
    ):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.settimeout(timeout)
        self.timeout = timeout

        # simulation knobs
        self.loss_rate = loss_rate
        self.corrupt_rate = corrupt_rate
        self._force_bad_checksum_once = False  # one-shot tamper for tests

        self.max_retries = max_retries
        self.debug = debug

        # connection-level state — reset on each connection
        self._reset_state()

        # counters useful for tests / statistics
        self.stats = {
            "pkts_sent": 0,
            "pkts_recv": 0,
            "retransmissions": 0,
            "corrupt_drops": 0,
            "duplicates": 0,
            "simulated_losses": 0,
            "simulated_corruptions": 0,
        }

    def _reset_state(self) -> None:
        """Clear per-connection state (kept separate so a listening
        socket can serve multiple clients sequentially)."""
        self.peer_addr: Optional[Tuple[str, int]] = None
        self.send_seq: int = 0      # next seq number we will send
        self.recv_seq: int = 0      # next seq number we expect to receive
        self.recv_buffer: bytearray = bytearray()
        self.got_fin: bool = False
        self.closed: bool = False
        self.peer_window: int = 65535  # receiver's advertised window size
        self.cwnd = 1          # congestion window (in segments)
        self.ssthresh = 16     # slow start threshold
        self.recv_window_max: int = 65535  # max we will advertise to peer (for flow control)


    # -------------------- logging --------------------

    def _log(self, msg: str) -> None:
        if not self.debug:
            return
        me = ("?", "?")
        try:
            if self.udp.fileno() != -1:
                me = self.udp.getsockname()
        except OSError:
            # On Windows this can fail on an unbound UDP socket.
            pass
        print(f"[RUDP {me[0]}:{me[1]}] {msg}")

    # -------------------- simulation helpers --------------------
    #
    # The lab explicitly asks for "methods specially created" for
    # simulating packet loss and corruption. Those are below.

    def _simulate_loss(self) -> bool:
        """Return True if we should drop the packet we're about to send."""
        if self.loss_rate > 0 and random.random() < self.loss_rate:
            self.stats["simulated_losses"] += 1
            return True
        return False

    def _simulate_corruption(self, pkt: bytes) -> bytes:
        """Randomly flip a bit in `pkt` with probability corrupt_rate.
        Returns the (possibly mutated) packet."""
        if self.corrupt_rate > 0 and random.random() < self.corrupt_rate:
            ba = bytearray(pkt)
            if len(ba) > 0:
                idx = random.randrange(len(ba))
                ba[idx] ^= 1 << random.randrange(8)
                self.stats["simulated_corruptions"] += 1
                return bytes(ba)
        return pkt

    def force_bad_checksum_next_send(self) -> None:
        """Arm a one-shot: the very next outgoing packet will carry a
        deliberately wrong checksum. Useful for unit-testing the
        receiver's drop-and-timeout path."""
        self._force_bad_checksum_once = True

    def _send_raw(self, pkt: bytes, addr: Tuple[str, int]) -> None:
        """Transmit `pkt` through the underlying UDP socket, honouring
        the loss and corruption simulations."""
        # one-shot deliberately-bad checksum for tests
        if self._force_bad_checksum_once:
            self._force_bad_checksum_once = False
            if len(pkt) >= HEADER_LEN:
                # flip one bit in the checksum field (bytes 9..10)
                ba = bytearray(pkt)
                ba[9] ^= 0xFF
                pkt = bytes(ba)
                self._log("[SIM] Forcing bad checksum on next packet")

        if self._simulate_loss():
            self._log("[SIM] Dropping outgoing packet (simulated loss)")
            return

        pkt = self._simulate_corruption(pkt)

        try:
            self.udp.sendto(pkt, addr)
            self.stats["pkts_sent"] += 1
        except OSError as e:
            self._log(f"sendto failed: {e}")

    # -------------------- receive helpers --------------------

    def _recvfrom_with_timeout(self, timeout: float):
        """recvfrom that respects a specific timeout (may be < self.timeout
        when we're waiting for the tail of a retransmission window)."""
        self.udp.settimeout(max(0.001, timeout))
        try:
            return self.udp.recvfrom(MAX_PACKET)
        finally:
            self.udp.settimeout(self.timeout)

    def _is_from_peer(self, src) -> bool:
        """True if `src` is the currently-connected peer (or we don't
        have a peer yet)."""
        return self.peer_addr is None or src == self.peer_addr

    def _handle_incoming_data(self, pkt: dict) -> None:
        """Apply the stop-and-wait receiver logic to an incoming DATA
        packet. Either deliver in-order bytes and ACK, or re-ACK a
        duplicate, or silently discard an out-of-order packet."""
        seq = pkt["seq"]
        if seq == self.recv_seq:
            self.recv_buffer += pkt["payload"]
            self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
            
            free = max(0, self.recv_window_max - len(self.recv_buffer))  # add this constant e.g. 65535
            ack_pkt = make_packet(self.send_seq, self.recv_seq, FLAG_ACK, window=free)

            self._send_raw(ack_pkt, self.peer_addr)
        elif seq < self.recv_seq:
            # duplicate of a packet we already accepted: the peer's ACK
            # must have been lost or delayed. Re-ACK to unstick them.
            self.stats["duplicates"] += 1
            ack_pkt = make_packet(self.send_seq, self.recv_seq, FLAG_ACK)
            self._log(f"-> ACK ack={self.recv_seq} (duplicate seq={seq} re-ACKed)")
            self._send_raw(ack_pkt, self.peer_addr)
        else:
            # out-of-order ahead of what we expect — can't happen in
            # strict stop-and-wait but could happen with reordering. Drop.
            self._log(f"DROP data seq={seq} (expected {self.recv_seq})")

    # -------------------- bind / connect / accept --------------------

    def bind(self, addr: Tuple[str, int]) -> None:
        """Bind the underlying UDP socket to `addr`."""
        self.udp.bind(addr)

    def connect(self, addr: Tuple[str, int]) -> None:
        """Client side of the 3-way handshake:

            --> SYN (seq=X)
            <-- SYN-ACK (seq=Y, ack=X+1)
            --> ACK (seq=X+1, ack=Y+1)
        """
        self._reset_state()

        client_isn = random.randrange(0, 10_000)
        self.send_seq = client_isn
        syn = make_packet(self.send_seq, 0, FLAG_SYN)

        for attempt in range(1, self.max_retries + 1):
            self._log(f"-> SYN seq={self.send_seq} (attempt {attempt})")
            if attempt > 1:
                self.stats["retransmissions"] += 1
            self._send_raw(syn, addr)

            try:
                data, src = self.udp.recvfrom(MAX_PACKET)
            except socket.timeout:
                self._log("timeout waiting for SYN-ACK, retransmitting SYN")
                continue

            self.stats["pkts_recv"] += 1
            pkt = parse_packet(data)
            if pkt is None or not pkt["valid"]:
                self.stats["corrupt_drops"] += 1
                self._log("dropped corrupt datagram while awaiting SYN-ACK")
                continue

            if (
                pkt["flags"] == (FLAG_SYN | FLAG_ACK)
                and pkt["ack"] == (self.send_seq + 1) & 0xFFFFFFFF
            ):
                self._log(f"<- SYN-ACK seq={pkt['seq']} ack={pkt['ack']}")
                # SYN consumes one seq number
                self.send_seq = (self.send_seq + 1) & 0xFFFFFFFF
                self.recv_seq = (pkt["seq"] + 1) & 0xFFFFFFFF
                final_ack = make_packet(self.send_seq, self.recv_seq, FLAG_ACK)
                self.peer_addr = addr
                self._log(f"-> ACK seq={self.send_seq} ack={self.recv_seq} "
                          f"(handshake complete)")
                self._send_raw(final_ack, addr)
                return

            self._log(f"unexpected packet during handshake: "
                      f"flags={flags_to_str(pkt['flags'])} seq={pkt['seq']}")
        raise ConnectionError("3-way handshake failed (max retries reached)")

    def accept(self) -> None:
        """Server side of the 3-way handshake.

        Blocks until a SYN arrives from some peer, then completes the
        handshake with that peer. After this returns, self.peer_addr is
        bound and send/recv use that peer."""
        # (Re)listen in a loop: handle bad/duplicate SYNs gracefully.
        while True:
            # Wait indefinitely for the first SYN of a new connection.
            self.udp.settimeout(None)
            try:
                data, src = self.udp.recvfrom(MAX_PACKET)
            except OSError as e:
                self.udp.settimeout(self.timeout)
                raise ConnectionError(f"accept failed: {e}")
            self.udp.settimeout(self.timeout)
            self.stats["pkts_recv"] += 1

            pkt = parse_packet(data)
            if pkt is None or not pkt["valid"]:
                self.stats["corrupt_drops"] += 1
                self._log("dropped corrupt datagram while listening")
                continue
            if pkt["flags"] != FLAG_SYN:
                self._log(f"ignoring non-SYN while listening "
                          f"(flags={flags_to_str(pkt['flags'])})")
                continue

            self._log(f"<- SYN seq={pkt['seq']} from {src}")
            self._reset_state()
            self.peer_addr = src

            client_isn = pkt["seq"]
            server_isn = random.randrange(0, 10_000)
            self.recv_seq = (client_isn + 1) & 0xFFFFFFFF
            self.send_seq = server_isn

            if self._complete_server_handshake():
                return  # handshake done, control returns to caller

            # handshake failed for this peer — go back to listening
            self._reset_state()

    def _complete_server_handshake(self) -> bool:
        """Send SYN-ACK and wait for the final ACK, with retransmission.
        Returns True on success, False if we gave up."""
        synack = make_packet(self.send_seq, self.recv_seq, FLAG_SYN | FLAG_ACK)

        for attempt in range(1, self.max_retries + 1):
            self._log(f"-> SYN-ACK seq={self.send_seq} ack={self.recv_seq} "
                      f"(attempt {attempt})")
            if attempt > 1:
                self.stats["retransmissions"] += 1
            self._send_raw(synack, self.peer_addr)

            try:
                data, src = self.udp.recvfrom(MAX_PACKET)
            except socket.timeout:
                self._log("timeout waiting for final ACK, retransmitting SYN-ACK")
                continue

            self.stats["pkts_recv"] += 1
            if src != self.peer_addr:
                # some other peer is talking — ignore during handshake
                continue

            rp = parse_packet(data)
            if rp is None or not rp["valid"]:
                self.stats["corrupt_drops"] += 1
                self._log("dropped corrupt datagram while awaiting final ACK")
                continue

            # Client retransmitted its SYN (its RTT timer fired before our
            # SYN-ACK arrived). Resend SYN-ACK.
            if rp["flags"] == FLAG_SYN:
                continue

            # Final ACK — handshake complete.
            if rp["flags"] & FLAG_ACK and rp["ack"] == (self.send_seq + 1) & 0xFFFFFFFF:
                self._log(f"<- ACK seq={rp['seq']} ack={rp['ack']} "
                          f"(handshake complete)")
                self.send_seq = (self.send_seq + 1) & 0xFFFFFFFF
                return True

            # Piggyback case: the client's final ACK was lost but its
            # first DATA segment arrived. Treat that as implicit ACK.
            if rp["flags"] == 0 and rp["seq"] == self.recv_seq:
                self._log("<- early DATA (implicit ACK of SYN-ACK)")
                self.send_seq = (self.send_seq + 1) & 0xFFFFFFFF
                self._handle_incoming_data(rp)
                return True

        return False

    # -------------------- send / recv --------------------
    def _on_ack_received(self):
        """Call this every time a valid ACK comes in."""
        if self.cwnd < self.ssthresh:
            # slow start: exponential growth
            self.cwnd += 1
        else:
            # congestion avoidance: linear growth
            self.cwnd += 1 / self.cwnd

    def _on_timeout(self):
        """Call this every time a retransmission timeout fires."""
        self.ssthresh = max(self.cwnd // 2, 1)
        self.cwnd = 1  # back to slow start

    def send(self, data: bytes) -> int:
        """Reliably transmit `data`. Segments larger than MAX_PAYLOAD are
        split and sent one at a time under stop-and-wait."""
        if self.peer_addr is None:
            raise ConnectionError("send() called before connect()/accept()")
        if self.closed:
            raise ConnectionError("send() called on closed connection")

        total = 0
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + MAX_PAYLOAD]
            self._send_one_data_segment(chunk)
            offset += len(chunk)
            total += len(chunk)
        return total

    def _send_one_data_segment(self, payload: bytes) -> None:
        """Stop-and-wait: send one DATA packet, wait for matching ACK
        (retransmitting on timeout), then return."""
        # block if peer's window is too small for our chunk
        while len(payload) > self.peer_window:
            time.sleep(0.05)  # wait and retry
        pkt = make_packet(self.send_seq, self.recv_seq, 0, payload)

        for attempt in range(1, self.max_retries + 1):
            self._log(f"-> DATA seq={self.send_seq} len={len(payload)} "
                      f"(attempt {attempt})")
            if attempt > 1:
                self.stats["retransmissions"] += 1
            self._send_raw(pkt, self.peer_addr)

            deadline = time.time() + self.timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    self._on_timeout()
                    break  # timeout -> retransmit

                try:
                    data, src = self._recvfrom_with_timeout(remaining)
                except socket.timeout:
                    break

                self.stats["pkts_recv"] += 1
                if src != self.peer_addr:
                    continue
                rp = parse_packet(data)
                if rp is None or not rp["valid"]:
                    self.stats["corrupt_drops"] += 1
                    self._log("dropped corrupt datagram while awaiting ACK")
                    continue

                # ACK of this segment?
                if (rp["flags"] & FLAG_ACK
                        and rp["ack"] == (self.send_seq + 1) & 0xFFFFFFFF):
                    self._log(f"<- ACK ack={rp['ack']}")
                    self.send_seq = (self.send_seq + 1) & 0xFFFFFFFF
                    self.peer_window = rp["window"]
                    self._on_ack_received()
                    return

                # Peer is sending us data concurrently — buffer it.
                if rp["flags"] == 0:
                    self._handle_incoming_data(rp)
                    continue

                # Peer is closing while we are sending — buffer FIN, the
                # recv() side will drain it later.
                if rp["flags"] & FLAG_FIN:
                    if rp["seq"] == self.recv_seq:
                        self.got_fin = True
                        self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
                        ack_pkt = make_packet(self.send_seq, self.recv_seq,
                                              FLAG_ACK)
                        self._send_raw(ack_pkt, self.peer_addr)
                    continue

                # Stale ACK (e.g. ACK of a previous segment) — ignore.
                self._log(f"ignoring unexpected packet "
                          f"flags={flags_to_str(rp['flags'])} ack={rp['ack']}")

        raise ConnectionError(
            f"send failed: no ACK after {self.max_retries} retries"
        )

    def recv(self, nbytes: int = 4096) -> bytes:
        """Return up to `nbytes` bytes of received data. Blocks until
        data is available. Returns b'' once the peer's FIN has been
        consumed and the reassembly buffer is empty (EOF)."""
        if self.peer_addr is None:
            raise ConnectionError("recv() called before connect()/accept()")

        # Fast path: we already have buffered bytes.
        if self.recv_buffer:
            return self._drain_buffer(nbytes)

        # Otherwise loop until we have something (or we hit EOF).
        while not self.recv_buffer and not self.got_fin:
            try:
                data, src = self.udp.recvfrom(MAX_PACKET)
            except socket.timeout:
                # No data yet — keep waiting. (We don't abort on timeout
                # here, because a peer may legitimately stay silent
                # between segments.)
                continue

            self.stats["pkts_recv"] += 1
            if src != self.peer_addr:
                continue
            pkt = parse_packet(data)
            if pkt is None or not pkt["valid"]:
                self.stats["corrupt_drops"] += 1
                self._log("dropped corrupt datagram during recv")
                continue

            flags = pkt["flags"]

            # FIN from peer (in-order): ACK and mark EOF.
            if flags & FLAG_FIN:
                if pkt["seq"] == self.recv_seq:
                    self.got_fin = True
                    self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
                    ack_pkt = make_packet(self.send_seq, self.recv_seq,
                                          FLAG_ACK)
                    self._log(f"<- FIN seq={pkt['seq']}; -> ACK ack={self.recv_seq}")
                    self._send_raw(ack_pkt, self.peer_addr)
                else:
                    # Duplicate FIN — re-ACK current position.
                    ack_pkt = make_packet(self.send_seq, self.recv_seq,
                                          FLAG_ACK)
                    self._send_raw(ack_pkt, self.peer_addr)
                break

            # Pure ACK (e.g. a lingering ACK from the handshake) — ignore
            # in the recv path. We don't advance send_seq here.
            if flags == FLAG_ACK and len(pkt["payload"]) == 0:
                continue

            # DATA
            if flags == 0:
                self._handle_incoming_data(pkt)
                continue

            # Duplicate SYN (client's final ACK got lost and server re-sent
            # SYN-ACK… or the peer is out of sync). Ignore.
            self._log(f"ignored packet flags={flags_to_str(flags)} during recv")

        return self._drain_buffer(nbytes)

    def _drain_buffer(self, nbytes: int) -> bytes:
        if not self.recv_buffer:
            return b""
        take = min(nbytes, len(self.recv_buffer))
        out = bytes(self.recv_buffer[:take])
        del self.recv_buffer[:take]
        return out

    # -------------------- close --------------------

    def close(self) -> None:
        """Tear down the logical connection. Sends FIN and waits for ACK
        with retransmission. Leaves the underlying UDP socket open so a
        listening server can accept() again — call destroy() to release
        the UDP socket entirely."""
        if self.closed or self.peer_addr is None:
            self.closed = True
            return

        fin_pkt = make_packet(self.send_seq, self.recv_seq, FLAG_FIN)

        for attempt in range(1, self.max_retries + 1):
            self._log(f"-> FIN seq={self.send_seq} (attempt {attempt})")
            if attempt > 1:
                self.stats["retransmissions"] += 1
            self._send_raw(fin_pkt, self.peer_addr)

            deadline = time.time() + self.timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                try:
                    data, src = self._recvfrom_with_timeout(remaining)
                except socket.timeout:
                    break

                self.stats["pkts_recv"] += 1
                if src != self.peer_addr:
                    continue
                rp = parse_packet(data)
                if rp is None or not rp["valid"]:
                    self.stats["corrupt_drops"] += 1
                    continue

                if (rp["flags"] & FLAG_ACK
                        and rp["ack"] == (self.send_seq + 1) & 0xFFFFFFFF):
                    self._log(f"<- ACK of FIN ack={rp['ack']}")
                    self.send_seq = (self.send_seq + 1) & 0xFFFFFFFF
                    self.closed = True
                    return

                # Peer may be sending its own FIN concurrently (a
                # simultaneous close). Acknowledge it.
                if rp["flags"] & FLAG_FIN and rp["seq"] == self.recv_seq:
                    self.got_fin = True
                    self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
                    ack_pkt = make_packet(self.send_seq, self.recv_seq,
                                          FLAG_ACK)
                    self._send_raw(ack_pkt, self.peer_addr)
                    continue

        # Could not confirm FIN/ACK — we still mark closed so we don't
        # loop forever. A real TCP would go through TIME_WAIT; for a lab
        # this is an acceptable approximation.
        self._log("close: giving up without confirmed FIN/ACK")
        self.closed = True

    def destroy(self) -> None:
        """Release the underlying UDP socket. After this call the
        RUDPSocket is unusable."""
        try:
            self.udp.close()
        except Exception:
            pass

    # -------------------- context-manager sugar --------------------

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.close()
        finally:
            self.destroy()
