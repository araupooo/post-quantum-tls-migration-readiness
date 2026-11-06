# Configuration guide — enforcing hybrid X25519MLKEM768 on OpenSSL and wolfSSL

Copy-paste server settings for the F-1 remediation, the HelloRetryRequest
behaviour to expect, the misconfigurations to avoid, and a runnable test
for every claim. All commands were run against OpenSSL 3.5.9 and wolfSSL
5.9.4-stable (built from source); the exact outputs are in
`outputs/raw/`.

## 1. OpenSSL 3.5.9 — use the tuple syntax

### The setting

```
# Server: put the hybrid in its own, most-preferred tuple.
openssl s_server -accept 443 -cert server.crt -key server.key \
    -tls1_3 -groups "X25519MLKEM768/X25519" -CAfile ca.crt
```

The `/` separates **tuples** of comparable security. `X25519MLKEM768`
alone in the first tuple means "prefer the hybrid over everything in a
later tuple". The classical `X25519` in the second tuple remains available
as a fallback for clients that cannot do the hybrid at all. (OpenSSL 3.5+
syntax; see `SSL_CTX_set1_curves(3SSL)` — "Group tuples of comparable
security are defined by separating them from each other by a tuple
separator `/`.")

### What to expect

A client that supports the hybrid but predicts only a classical keyshare
gets a **HelloRetryRequest** instead of a silent classical fallback. The
HRR is an 88-byte ServerHello carrying the RFC 8446 magic random
`cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c` and a
key_share request for group `0x11ec`. The client then retries with a
hybrid keyshare and the negotiated group is `X25519MLKEM768`. Verified
live (R1 in `regression_hrr.py`, 9/9 PASS; raw log
`outputs/raw/hrr_R1_tuple_hrr_client.log`):

```
<<< TLS 1.3, Handshake [length 0058], ServerHello
    02 00 00 54 03 03 cf 21 ad 74 e5 9a 61 11 be 1d
    03 04 00 33 00 02 11 ec
```

### Runnable test for this claim

```
python3 operator_check.py --host <your server> --port 443
```

Expected output against a tuple-configured server (unedited output in
`outputs/raw/operator_check_tuple.log`):

```
A negotiated group (deferred keyshare): got='X25519MLKEM768' -> PASS
A HRR seen: got=True -> PASS
B negotiated group (hybrid keyshare predicted): got='X25519MLKEM768' -> PASS
ALL PASS
```

### Misconfigurations to avoid

| Misconfiguration | What happens | How to detect it |
|---|---|---|
| Flat list `-groups "X25519MLKEM768:X25519"` (colon, no `/`) | The server treats all groups as one comparable tuple and picks from the client's predicted keyshares — a client listing classical first, or deferring the hybrid keyshare, silently gets classical X25519 (F-1). | `operator_check.py` test A FAILS: negotiated `X25519`, no HRR (unedited output in `outputs/raw/operator_check_flat.log`). |
| `DEFAULT` keyword in the group list (e.g. `X25519MLKEM768:DEFAULT`) | CVE-2026-2673: the DEFAULT list loses its tuple structure and the server does not send an HRR even when a more-preferred group is mutually supported. Affects OpenSSL 3.5.0–3.5.5 and 3.6.0–3.6.1; fixed in 3.5.6/3.6.2. | Upgrade to 3.5.6+ (this build is 3.5.9) and avoid `DEFAULT` in the list; verify with `operator_check.py`. |
| No `-tls1_3` / allowing TLS 1.2 | Clients may negotiate TLS 1.2, which is classical-only (F-4). | Check the negotiated protocol in the client output (`Protocol version: TLSv1.2`). |
| Assuming "client supports hybrid" means "connection is hybrid" | A legacy server (e.g. OpenSSL 3.0.13) ignores the unknown group `0x11ec` and negotiates X25519 with no error (F-3). | Log the negotiated group server-side (`SSL_get_negotiated_group()`) and alert on classical groups. |
| Running `s_server` with stdin EOF in a detached environment | The server closes every connection before the handshake (F-6). | Hold stdin open (`stdin=subprocess.PIPE` in the harness, or `< <(sleep 60)` in a shell). |

## 2. wolfSSL 5.9.4 — hybrid via `--pqc`, with two caveats

### The setting

```
# Server: hybrid group, and -C high enough to serve more than one connection.
./build/examples/server/server -p 443 -v 4 -c server.crt -k server.key \
    -A ca.crt -d --pqc X25519MLKEM768 -C 100
```

(The example server takes a single `--pqc` value. It does not expose a
group list or a tuple syntax, so the OpenSSL-style preference test does
not apply to it — see the matrix.)

### Caveats (measured)

- **Standalone ML-KEM is not supported.** `--pqc ML_KEM_768` makes the
  server refuse to start: "invalid post-quantum KEM specified"
  (server.c:853). Use the hybrid group for interop (F-2).
- **One connection by default.** The example server serves exactly 1
  connection unless `-C <num>` is given (F-7). Set `-C 100` or higher.
- **Do not health-check it with a bare TCP connect.** A probe connection
  makes `SSL_accept` fail with `SOCKET_ERROR_E (-308)` and the server
  exits (F-7). Check readiness with `ss -ltn` instead.
- **Client exit behaviour.** The example client waits for the server's
  application reply after the handshake; use benchmark mode `-b 1` so it
  exits cleanly and prints `wolfSSL_connect avg took: X milliseconds`.

### Runnable test for this claim

The same `operator_check.py` works against a wolfSSL server (it only
needs an OpenSSL 3.5+ `s_client` on the operator's side):

```
python3 operator_check.py --host <your wolfSSL server> --port 443
```

Expected: test B passes (the server supports the hybrid). Test A depends
on the wolfSSL server's group handling, which the example server does not
expose as a list — treat test A against wolfSSL as informational, not as
a pass/fail on the tuple remediation (which is OpenSSL-specific).

## 3. Verifying the negotiated group (both stacks)

```
# One-off check with s_client (OpenSSL 3.5+):
openssl s_client -connect <host>:443 -tls1_3 -groups X25519MLKEM768 \
    -CAfile ca.crt -brief
# Look for: "Negotiated TLS1.3 group: X25519MLKEM768"

# Deferred-keyshare check (the F-1 test):
openssl s_client -connect <host>:443 -tls1_3 \
    -groups "*X25519:X25519MLKEM768" -CAfile ca.crt -brief -msg
# Correctly configured server: an 88-byte ServerHello (HRR) appears first,
# then the negotiated group is X25519MLKEM768.
# Misconfigured (flat-list) server: no HRR, "Peer Temp Key: X25519".
```

## 4. What "correct" looks like — the full check

Run `operator_check.py` against your server. Correct output is `ALL PASS`
(exit 0). If test A fails while test B passes, your server supports the
hybrid but does not enforce it — apply the tuple-syntax setting in §1
(OpenSSL) or check your stack's equivalent. If both fail, the server does
not support the hybrid at all — upgrade the TLS library (OpenSSL 3.5+,
wolfSSL with `WOLFSSL_MLKEM` + `WOLFSSL_PQC_HYBRIDS`, BoringSSL, or Go 1.24+).
