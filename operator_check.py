#!/usr/bin/env python3
"""Operator check: does my TLS server negotiate the hybrid group when a
client defers the hybrid keyshare?

This is the single-script regression check for finding F-1 (flat server
group list ignores server preference; a client that defers the hybrid
keyshare silently falls back to classical X25519). Point it at any TLS 1.3
server and it tells you whether that server enforces the hybrid.

Usage:
    python3 operator_check.py --host example.com --port 443
    python3 operator_check.py --host 127.0.0.1 --port 8443 --openssl /path/to/openssl
    python3 operator_check.py --host example.com --port 443 --cafile /path/to/ca.crt

Requirements: an OpenSSL 3.5+ `s_client` (for the `*` keyshare-prefix
syntax and the hybrid groups). The server needs no special setup — the
script only connects as a client. If your server uses a private CA, pass
--cafile; without it the handshake still completes (verification is not
fatal by default) and the negotiated group is still reported.

Tests:
  A  Deferred keyshare: the client supports X25519MLKEM768 but predicts
     ONLY a classical X25519 keyshare (`*X25519:X25519MLKEM768`).
     PASS if the negotiated group is X25519MLKEM768 (the server sent a
     HelloRetryRequest and forced the hybrid up). FAIL if it is X25519
     (silent classical fallback — the F-1 misconfiguration).
  B  Control: the client predicts the hybrid keyshare
     (`*X25519MLKEM768:X25519`). PASS if the negotiated group is
     X25519MLKEM768 (the server supports the hybrid at all). If B fails
     while A fails, the server does not support the hybrid at all.

Exit code: 0 if every test passes, 1 otherwise. Every check prints its
own PASS/FAIL line, so the output is self-explanatory.
"""
import argparse
import re
import subprocess
import sys

HRR_RANDOM = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"


def run_client(openssl, host, port, groups, cafile, timeout=15):
    cmd = [openssl, "s_client", "-connect", "%s:%d" % (host, port),
           "-tls1_3", "-groups", groups, "-brief", "-msg"]
    if cafile:
        cmd += ["-CAfile", cafile]
    try:
        p = subprocess.run(cmd, input=b"", capture_output=True,
                           timeout=timeout)
        out = (p.stdout + p.stderr).decode("utf-8", "replace")
        return p.returncode, out
    except subprocess.TimeoutExpired as e:
        out = b"".join(x for x in [e.stdout, e.stderr] if x).decode(
            "utf-8", "replace")
        return "TIMEOUT", out + "\n[TIMEOUT after %.1fs]" % timeout


def negotiated_group(out):
    m = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", out)
    if m:
        return m.group(1)
    # Classical fallback: -brief prints "Peer Temp Key: X25519, ..." and
    # no "Negotiated TLS1.3 group" line.
    m = re.search(r"Peer Temp Key:\s*(X25519|secp256r1|secp384r1|X448)",
                  out)
    if m:
        return m.group(1)
    return None


def check(tag, got, want):
    ok = got == want
    print("%s: got=%r want=%r -> %s" % (tag, got, want,
                                        "PASS" if ok else "FAIL"))
    return ok


def main():
    ap = argparse.ArgumentParser(
        description="Check whether a TLS server enforces hybrid "
                    "X25519MLKEM768 when a client defers the hybrid keyshare.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--openssl", default="openssl",
                    help="path to an OpenSSL 3.5+ binary (default: openssl)")
    ap.add_argument("--cafile", default=None,
                    help="CA certificate for server verification (optional)")
    args = ap.parse_args()

    print("operator_check.py: %s:%d (openssl: %s)"
          % (args.host, args.port, args.openssl))
    ok = True

    # Test A: deferred hybrid keyshare.
    rc, out = run_client(args.openssl, args.host, args.port,
                         "*X25519:X25519MLKEM768", args.cafile)
    grp = negotiated_group(out)
    flat = "".join(out.split())
    hrr = HRR_RANDOM in flat
    ok &= check("A rc", rc, 0)
    ok &= check("A negotiated group (deferred keyshare)", grp,
                "X25519MLKEM768")
    ok &= check("A HRR seen", hrr, True)
    if grp == "X25519":
        print("A NOTE: server negotiated classical X25519 despite "
              "supporting the hybrid — flat-list misconfiguration (F-1).")

    # Test B: control — hybrid keyshare predicted.
    rc, out = run_client(args.openssl, args.host, args.port,
                         "*X25519MLKEM768:X25519", args.cafile)
    grp = negotiated_group(out)
    ok &= check("B rc", rc, 0)
    ok &= check("B negotiated group (hybrid keyshare predicted)", grp,
                "X25519MLKEM768")

    print("ALL PASS" if ok else "FAILURES PRESENT — see above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
