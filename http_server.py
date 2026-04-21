"""
http_server.py — HTTP/1.0 server built on the RUDP transport

Supports GET (serve a file from a webroot directory) and POST (store a
file under webroot, which is handy for demoing request bodies).

The server is deliberately single-connection-at-a-time (no threading),
matching the Stop-and-Wait model where the whole transport is per-peer
anyway. The same RUDPSocket is re-used across client connections so the
UDP port stays bound.
"""

from __future__ import annotations

import argparse
import os
import sys

from rudp import RUDPSocket
from http_message import HTTPRequest, HTTPResponse, read_full_request


DEFAULT_INDEX = "index.html"


class HTTPServer:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9000,
        webroot: str = "./webroot",
        loss_rate: float = 0.0,
        corrupt_rate: float = 0.0,
        debug: bool = False,
    ):
        self.host = host
        self.port = port
        self.webroot = os.path.abspath(webroot)
        self.loss_rate = loss_rate
        self.corrupt_rate = corrupt_rate
        self.debug = debug
        os.makedirs(self.webroot, exist_ok=True)
        self._sock: RUDPSocket | None = None

    # ----------------------- main loop -----------------------

    def serve_forever(self) -> None:
        self._sock = RUDPSocket(
            loss_rate=self.loss_rate,
            corrupt_rate=self.corrupt_rate,
            debug=self.debug,
        )
        self._sock.bind((self.host, self.port))
        print(f"[HTTP] serving {self.webroot!r} at rudp://{self.host}:{self.port}  "
              f"(loss={self.loss_rate}, corrupt={self.corrupt_rate})")

        try:
            while True:
                try:
                    self._sock.accept()
                except (OSError, ConnectionError) as e:
                    # Socket was closed (e.g. on shutdown) or a broken
                    # handshake — stop if the fd is dead, otherwise keep going.
                    if self._sock.udp.fileno() == -1:
                        break
                    print(f"[HTTP] accept error: {e}", file=sys.stderr)
                    continue
                client = self._sock.peer_addr
                print(f"[HTTP] connection from {client}")
                try:
                    self._serve_one(self._sock)
                except Exception as e:
                    print(f"[HTTP] error serving {client}: {e}", file=sys.stderr)
                finally:
                    try:
                        self._sock.close()
                    except Exception:
                        pass
                    # reset connection-level state so the same UDP socket
                    # can accept the next connection
                    self._sock._reset_state()
        except KeyboardInterrupt:
            print("\n[HTTP] shutting down")
        finally:
            if self._sock is not None:
                self._sock.destroy()

    # ----------------------- per-connection handler -----------------------

    def _serve_one(self, conn: RUDPSocket) -> None:
        try:
            req = read_full_request(conn)
        except ValueError as e:
            resp = HTTPResponse(status=400, body=f"Bad Request: {e}".encode())
            conn.send(resp.to_bytes())
            return
        if req is None:
            return  # peer closed without sending anything

        print(f"[HTTP]   {req.method} {req.path}  "
              f"(body={len(req.body)}B, headers={len(req.headers)})")

        if req.method == "GET":
            resp = self._handle_get(req)
        elif req.method == "POST":
            resp = self._handle_post(req)
        else:
            resp = HTTPResponse(
                status=405,
                body=f"<h1>405 Method Not Allowed</h1><p>{req.method} is not supported."
                     f"</p>".encode(),
            )
            resp.headers["Allow"] = "GET, POST"

        print(f"[HTTP]   -> {resp.status} {resp.reason} ({len(resp.body)}B)")
        conn.send(resp.to_bytes())

    # ----------------------- GET -----------------------

    def _handle_get(self, req: HTTPRequest) -> HTTPResponse:
        # Drop query string for file mapping purposes.
        path = req.path.split("?", 1)[0]
        if path.endswith("/"):
            path = path + DEFAULT_INDEX
        rel = path.lstrip("/")

        # Resolve inside webroot and reject path-traversal attempts.
        full = os.path.normpath(os.path.join(self.webroot, rel))
        if not (full == self.webroot or full.startswith(self.webroot + os.sep)):
            return HTTPResponse(
                status=403,
                body=b"<h1>403 Forbidden</h1>",
            )

        if not os.path.isfile(full):
            return HTTPResponse(
                status=404,
                body=(f"<html><body><h1>404 Not Found</h1>"
                      f"<p>The resource <code>{path}</code> was not found."
                      f"</p></body></html>").encode(),
            )

        with open(full, "rb") as f:
            data = f.read()
        resp = HTTPResponse(status=200, body=data)
        resp.headers["Content-Type"] = _guess_content_type(full)
        return resp

    # ----------------------- POST -----------------------

    def _handle_post(self, req: HTTPRequest) -> HTTPResponse:
        rel = req.path.lstrip("/")
        if not rel:
            return HTTPResponse(
                status=400,
                body=b"<h1>400 Bad Request</h1><p>POST target path is required.</p>",
            )

        full = os.path.normpath(os.path.join(self.webroot, rel))
        if not (full == self.webroot or full.startswith(self.webroot + os.sep)):
            return HTTPResponse(status=403, body=b"<h1>403 Forbidden</h1>")

        os.makedirs(os.path.dirname(full) or self.webroot, exist_ok=True)
        with open(full, "wb") as f:
            f.write(req.body)

        body = (f"<html><body><h1>201 Created</h1>"
                f"<p>Stored {len(req.body)} bytes at <code>/{rel}</code></p>"
                f"</body></html>").encode()
        resp = HTTPResponse(status=201, body=body)
        resp.headers["Location"] = "/" + rel
        return resp


# ---------------------------------------------------------------------------
# Small MIME map (enough for typical lab uses)
# ---------------------------------------------------------------------------

_MIME = {
    ".html": "text/html; charset=utf-8",
    ".htm":  "text/html; charset=utf-8",
    ".txt":  "text/plain; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".js":   "application/javascript; charset=utf-8",
    ".json": "application/json",
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif":  "image/gif",
    ".pdf":  "application/pdf",
}


def _guess_content_type(path: str) -> str:
    _, ext = os.path.splitext(path.lower())
    return _MIME.get(ext, "application/octet-stream")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> None:
    p = argparse.ArgumentParser(
        description="HTTP/1.0 server over RUDP (reliable UDP)",
    )
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--webroot", default=os.path.join(os.path.dirname(__file__),
                                                     "webroot"))
    p.add_argument("--loss", type=float, default=0.0,
                   help="probability each outgoing packet is dropped (0..1)")
    p.add_argument("--corrupt", type=float, default=0.0,
                   help="probability each outgoing packet has a bit flipped")
    p.add_argument("--debug", action="store_true",
                   help="print RUDP protocol trace")
    args = p.parse_args(argv)

    HTTPServer(
        host=args.host,
        port=args.port,
        webroot=args.webroot,
        loss_rate=args.loss,
        corrupt_rate=args.corrupt,
        debug=args.debug,
    ).serve_forever()


if __name__ == "__main__":
    main()
