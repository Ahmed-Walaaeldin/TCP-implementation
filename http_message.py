"""
http_message.py — HTTP 1.0 request and response objects

Implements enough of RFC 1945 (HTTP/1.0) to support the lab:
    * Request line and status line parsing/building
    * Header folding into case-insensitive dictionaries
    * GET and POST methods
    * Status codes 200 OK and 404 Not Found (plus a few helpers)
    * Proper Content-Length, Content-Type, Server, Date, Host headers

All I/O is bytes; text headers are encoded as ISO-8859-1 (the legacy
HTTP encoding). Bodies may be arbitrary bytes.
"""

from __future__ import annotations

import email.utils
import time
from typing import Dict, Optional, Tuple

CRLF = b"\r\n"
HEADER_TERMINATOR = b"\r\n\r\n"


# ---------------------------------------------------------------------------
# Case-insensitive header dict
# ---------------------------------------------------------------------------

class Headers(dict):
    """
    A thin wrapper around dict that preserves the first-seen casing on
    output but compares keys case-insensitively — matching HTTP's rule
    that header names are case-insensitive.
    """

    def __init__(self, initial: Optional[Dict[str, str]] = None):
        super().__init__()
        self._keymap: Dict[str, str] = {}  # lower -> canonical
        if initial:
            for k, v in initial.items():
                self[k] = v

    def __setitem__(self, key: str, value: str) -> None:
        lk = key.lower()
        canonical = self._keymap.get(lk, key)
        self._keymap[lk] = canonical
        super().__setitem__(canonical, str(value))

    def __getitem__(self, key: str) -> str:
        lk = key.lower()
        return super().__getitem__(self._keymap[lk])

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        return key.lower() in self._keymap

    def get(self, key: str, default=None):
        lk = key.lower()
        if lk in self._keymap:
            return super().__getitem__(self._keymap[lk])
        return default

    def setdefault(self, key: str, default: str) -> str:
        if key not in self:
            self[key] = default
        return self[key]


# ---------------------------------------------------------------------------
# HTTP request
# ---------------------------------------------------------------------------

class HTTPRequest:
    """
    Represents an HTTP/1.0 request (possibly with a body for POST).

    Required fields on a well-formed request:
        method  — "GET" or "POST" (others rejected at server layer)
        path    — e.g. "/", "/index.html", "/submit?x=1"
        version — always "HTTP/1.0" for this lab
        headers — Headers(), case-insensitive
        body    — bytes (empty for GET)
    """

    def __init__(
        self,
        method: str = "GET",
        path: str = "/",
        version: str = "HTTP/1.0",
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
    ):
        self.method = method.upper()
        self.path = path
        self.version = version
        self.headers = Headers(headers or {})
        self.body = body if isinstance(body, (bytes, bytearray)) else str(body).encode()

    # -------- serialisation --------

    def to_bytes(self) -> bytes:
        # Make sure Content-Length matches the body; required for POST.
        if self.body:
            self.headers["Content-Length"] = str(len(self.body))
        else:
            # Strict HTTP/1.0 allows omitting Content-Length for bodyless
            # requests; we omit it to match browser behaviour for GET.
            if "Content-Length" in self.headers and not self.body:
                del self.headers[self.headers._keymap["content-length"]]
                del self.headers._keymap["content-length"]
        req_line = f"{self.method} {self.path} {self.version}".encode("iso-8859-1")
        lines = [req_line]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}".encode("iso-8859-1"))
        top = CRLF.join(lines) + HEADER_TERMINATOR
        return top + self.body

    # -------- parsing --------

    @classmethod
    def from_bytes(cls, raw: bytes) -> "HTTPRequest":
        """Parse a complete request. Raises ValueError if malformed or
        truncated (missing header terminator)."""
        idx = raw.find(HEADER_TERMINATOR)
        if idx == -1:
            raise ValueError("HTTP request has no header terminator (\\r\\n\\r\\n)")

        header_bytes = raw[:idx]
        body = raw[idx + len(HEADER_TERMINATOR):]

        lines = header_bytes.split(CRLF)
        if not lines:
            raise ValueError("empty HTTP request")

        request_line = lines[0].decode("iso-8859-1")
        parts = request_line.split(" ")
        if len(parts) != 3:
            raise ValueError(f"malformed request line: {request_line!r}")
        method, path, version = parts

        headers = Headers()
        for line in lines[1:]:
            if not line:
                continue
            text = line.decode("iso-8859-1")
            if ":" not in text:
                # Tolerate broken lines quietly rather than 500ing.
                continue
            name, _, value = text.partition(":")
            headers[name.strip()] = value.strip()

        return cls(method=method, path=path, version=version,
                   headers=dict(headers), body=body)

    # -------- diagnostics --------

    def __repr__(self) -> str:
        return (f"<HTTPRequest {self.method} {self.path} "
                f"headers={len(self.headers)} body={len(self.body)}B>")


# ---------------------------------------------------------------------------
# HTTP response
# ---------------------------------------------------------------------------

class HTTPResponse:
    """
    Represents an HTTP/1.0 response.

    Minimal required status codes for this lab: 200 OK, 404 Not Found.
    A handful of others are included because they fall out naturally
    (201 Created for POST, 400 Bad Request, 405 Method Not Allowed,
    500 Internal Server Error).
    """

    STATUS_MESSAGES = {
        200: "OK",
        201: "Created",
        204: "No Content",
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
    }

    def __init__(
        self,
        status: int = 200,
        version: str = "HTTP/1.0",
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
        reason: Optional[str] = None,
    ):
        self.status = status
        self.version = version
        self.headers = Headers(headers or {})
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.body = body
        self.reason = reason or self.STATUS_MESSAGES.get(status, "Unknown")

    # -------- defaults --------

    def _apply_default_headers(self) -> None:
        self.headers["Content-Length"] = str(len(self.body))
        if self.body and "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "text/html; charset=utf-8"
        self.headers.setdefault("Server", "RUDP-HTTP/1.0")
        self.headers.setdefault("Date", email.utils.formatdate(usegmt=True))
        # HTTP/1.0 default is non-persistent — state this explicitly.
        self.headers.setdefault("Connection", "close")

    # -------- serialisation --------

    def to_bytes(self) -> bytes:
        self._apply_default_headers()
        status_line = f"{self.version} {self.status} {self.reason}".encode("iso-8859-1")
        lines = [status_line]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}".encode("iso-8859-1"))
        top = CRLF.join(lines) + HEADER_TERMINATOR
        return top + self.body

    # -------- parsing --------

    @classmethod
    def from_bytes(cls, raw: bytes) -> "HTTPResponse":
        idx = raw.find(HEADER_TERMINATOR)
        if idx == -1:
            raise ValueError("HTTP response has no header terminator")
        header_bytes = raw[:idx]
        body = raw[idx + len(HEADER_TERMINATOR):]
        lines = header_bytes.split(CRLF)
        status_line = lines[0].decode("iso-8859-1")
        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            raise ValueError(f"malformed status line: {status_line!r}")
        version = parts[0]
        status = int(parts[1])
        reason = parts[2] if len(parts) >= 3 else ""
        headers = Headers()
        for line in lines[1:]:
            if not line:
                continue
            text = line.decode("iso-8859-1")
            if ":" not in text:
                continue
            name, _, value = text.partition(":")
            headers[name.strip()] = value.strip()
        return cls(status=status, version=version, headers=dict(headers),
                   body=body, reason=reason)

    def __repr__(self) -> str:
        return (f"<HTTPResponse {self.status} {self.reason} "
                f"body={len(self.body)}B>")


# ---------------------------------------------------------------------------
# Helpers for reading a full message from a reliable-stream socket
# ---------------------------------------------------------------------------

def read_full_request(conn) -> Optional[HTTPRequest]:
    """
    Read a complete HTTP request from a stream-like object (anything
    with a blocking recv(n) that returns b'' at EOF).

    Correctly handles messages that arrive across multiple segments,
    and uses the Content-Length header to bound the body for POST.

    Returns None if the connection closes before any bytes are read.
    Raises ValueError on malformed input.
    """
    buf = bytearray()
    # Read at least the header block.
    while HEADER_TERMINATOR not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            if not buf:
                return None
            raise ValueError("connection closed mid-headers")
        buf += chunk

    idx = buf.find(HEADER_TERMINATOR)
    header_end = idx + len(HEADER_TERMINATOR)

    # Peek at Content-Length.
    header_part = buf[:idx].decode("iso-8859-1")
    content_length = 0
    for line in header_part.split("\r\n")[1:]:
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        if k.strip().lower() == "content-length":
            try:
                content_length = int(v.strip())
            except ValueError:
                content_length = 0
            break

    body = bytes(buf[header_end:])
    while len(body) < content_length:
        chunk = conn.recv(4096)
        if not chunk:
            break  # connection ended early; we'll return what we have
        body += chunk

    return HTTPRequest.from_bytes(bytes(buf[:header_end]) + body)


def read_full_response(conn, expect_close: bool = True) -> HTTPResponse:
    """
    Read a complete HTTP response from a stream-like object.

    For HTTP/1.0, if Content-Length is given we stop there; otherwise we
    read until the peer closes (the historical HTTP/1.0 "end = EOF"
    framing rule).
    """
    buf = bytearray()
    while HEADER_TERMINATOR not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            raise ValueError("connection closed mid-headers")
        buf += chunk

    idx = buf.find(HEADER_TERMINATOR)
    header_end = idx + len(HEADER_TERMINATOR)
    header_part = buf[:idx].decode("iso-8859-1")

    content_length: Optional[int] = None
    for line in header_part.split("\r\n")[1:]:
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        if k.strip().lower() == "content-length":
            try:
                content_length = int(v.strip())
            except ValueError:
                pass
            break

    body = bytes(buf[header_end:])
    if content_length is not None:
        while len(body) < content_length:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body += chunk
    elif expect_close:
        # HTTP/1.0 end-of-body-is-EOF rule.
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body += chunk

    return HTTPResponse.from_bytes(bytes(buf[:header_end]) + body)
