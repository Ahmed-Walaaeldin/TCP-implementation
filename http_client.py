"""
Usage (CLI):

    python http_client.py GET  http://127.0.0.1:9000/index.html
    python http_client.py POST http://127.0.0.1:9000/upload/hi.txt --body 'any text'
"""

from __future__ import annotations

import argparse
import sys
import urllib.parse
from typing import Dict, Optional

from rudp import RUDPSocket
from http_message import HTTPRequest, HTTPResponse, read_full_response


def _do_request(
    host: str,
    port: int,
    request: HTTPRequest,
    loss_rate: float = 0.0,
    corrupt_rate: float = 0.0,
    debug: bool = False,
) -> HTTPResponse:
    """Open an RUDP connection to (host, port), send one request, read
    the full response, and close. Returns the HTTPResponse."""
    # Default headers expected by most servers/browsers.
    request.headers.setdefault("Host", f"{host}:{port}")
    request.headers.setdefault("User-Agent", "RUDP-HTTP-Client/1.0")
    request.headers.setdefault("Accept", "*/*")

    sock = RUDPSocket(loss_rate=loss_rate, corrupt_rate=corrupt_rate, debug=debug)
    try:
        sock.connect((host, port))
        sock.send(request.to_bytes())
        resp = read_full_response(sock, expect_close=True)
        return resp
    finally:
        try:
            sock.close()
        finally:
            sock.destroy()


def http_get(
    host: str,
    port: int,
    path: str = "/",
    headers: Optional[Dict[str, str]] = None,
    loss_rate: float = 0.0,
    corrupt_rate: float = 0.0,
    debug: bool = False,
) -> HTTPResponse:
    req = HTTPRequest(method="GET", path=path, headers=headers or {})
    return _do_request(host, port, req, loss_rate, corrupt_rate, debug)


def http_post(
    host: str,
    port: int,
    path: str,
    body: bytes,
    headers: Optional[Dict[str, str]] = None,
    content_type: str = "application/octet-stream",
    loss_rate: float = 0.0,
    corrupt_rate: float = 0.0,
    debug: bool = False,
) -> HTTPResponse:
    hdrs = dict(headers or {})
    hdrs.setdefault("Content-Type", content_type)
    req = HTTPRequest(method="POST", path=path, headers=hdrs, body=body)
    return _do_request(host, port, req, loss_rate, corrupt_rate, debug)


# CLI

def _parse_url(url: str):
    u = urllib.parse.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 9000
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"
    return host, port, path


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="HTTP/1.0 client over RUDP")
    p.add_argument("method", choices=["GET", "POST"])
    p.add_argument("url",
                   help="e.g. http://127.0.0.1:9000/index.html")
    p.add_argument("--body", default=None,
                   help="request body for POST (literal string)")
    p.add_argument("--body-file", default=None,
                   help="request body for POST (read from file)")
    p.add_argument("--content-type", default="application/octet-stream")
    p.add_argument("--header", action="append", default=[],
                   help="additional header, e.g. --header 'X-Foo: bar'")
    p.add_argument("--loss", type=float, default=0.0)
    p.add_argument("--corrupt", type=float, default=0.0)
    p.add_argument("--debug", action="store_true")
    p.add_argument("--show-headers", action="store_true",
                   help="also print response headers")
    args = p.parse_args(argv)

    host, port, path = _parse_url(args.url)
    extra_headers: Dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            name, _, value = h.partition(":")
            extra_headers[name.strip()] = value.strip()

    if args.method == "GET":
        resp = http_get(host, port, path, headers=extra_headers,
                        loss_rate=args.loss, corrupt_rate=args.corrupt,
                        debug=args.debug)
    else:
        if args.body_file:
            with open(args.body_file, "rb") as f:
                body = f.read()
        elif args.body is not None:
            body = args.body.encode("utf-8")
        else:
            body = sys.stdin.buffer.read()
        resp = http_post(host, port, path, body, headers=extra_headers,
                         content_type=args.content_type,
                         loss_rate=args.loss, corrupt_rate=args.corrupt,
                         debug=args.debug)

    print(f"{resp.version} {resp.status} {resp.reason}")
    if args.show_headers:
        for k, v in resp.headers.items():
            print(f"{k}: {v}")
        print()
    try:
        sys.stdout.write(resp.body.decode("utf-8"))
    except UnicodeDecodeError:
        sys.stdout.buffer.write(resp.body)
    if not resp.body.endswith(b"\n"):
        print()


if __name__ == "__main__":
    main()
