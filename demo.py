"""
demo.py — one-shot demo that runs the HTTP server in a background
thread and exercises it with a few client requests, printing the full
protocol trace.

Run with:
    python demo.py                   # default (no loss, no corruption)
    python demo.py --loss 0.2        # drop 20% of outgoing packets
    python demo.py --corrupt 0.2     # corrupt 20% of outgoing packets
    python demo.py --loss 0.2 --corrupt 0.1 --debug
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time

from http_server import HTTPServer
from http_client import http_get, http_post


def run_server_in_thread(host, port, webroot, loss, corrupt, debug) -> threading.Thread:
    server = HTTPServer(host=host, port=port, webroot=webroot,
                        loss_rate=loss, corrupt_rate=corrupt, debug=debug)
    t = threading.Thread(target=server.serve_forever, daemon=True,
                         name="http-server")
    t.start()
    # Give the server a moment to bind before the first client connects.
    time.sleep(0.2)
    return t


def hr(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def main(argv=None) -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--loss", type=float, default=0.0)
    p.add_argument("--corrupt", type=float, default=0.0)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args(argv)

    webroot = os.path.join(os.path.dirname(__file__), "webroot")

    run_server_in_thread(args.host, args.port, webroot,
                         args.loss, args.corrupt, args.debug)

    # --- GET / ---
    hr("DEMO 1 — GET /")
    r = http_get(args.host, args.port, "/", loss_rate=args.loss,
                 corrupt_rate=args.corrupt, debug=args.debug)
    print(f"\nstatus: {r.status} {r.reason}")
    print(f"bytes : {len(r.body)}")
    print(f"first 80 bytes of body: {r.body[:80]!r}")

    # --- GET /hello.txt ---
    hr("DEMO 2 — GET /testing_get.txt")
    r = http_get(args.host, args.port, "/testing_get.txt", loss_rate=args.loss,
                 corrupt_rate=args.corrupt, debug=args.debug)
    print(f"\nstatus: {r.status} {r.reason}")
    print("body  :")
    print(r.body.decode())

    # --- GET /missing (404) ---
    hr("DEMO 3 — GET /missing  (expect 404)")
    r = http_get(args.host, args.port, "/missing", loss_rate=args.loss,
                 corrupt_rate=args.corrupt, debug=args.debug)
    print(f"\nstatus: {r.status} {r.reason}")

    # --- POST /uploads/note.txt ---
    hr("DEMO 4 — POST /uploads/note.txt")
    payload = ("Uploaded via our RUDP-HTTP client.\n"
               "Stop-and-wait at work.\n").encode()
    r = http_post(args.host, args.port, "/uploads/note.txt", payload,
                  content_type="text/plain; charset=utf-8",
                  loss_rate=args.loss, corrupt_rate=args.corrupt,
                  debug=args.debug)
    print(f"\nstatus: {r.status} {r.reason}")
    print(f"Location: {r.headers.get('Location', '-')}")

    # Verify round-trip
    hr("DEMO 5 — GET /uploads/note.txt  (verify POST)")
    r = http_get(args.host, args.port, "/uploads/note.txt", loss_rate=args.loss,
                 corrupt_rate=args.corrupt, debug=args.debug)
    print(f"\nstatus: {r.status} {r.reason}")
    print("body  :")
    print(r.body.decode())

    print("\nAll demo requests completed successfully.")


if __name__ == "__main__":
    main()
