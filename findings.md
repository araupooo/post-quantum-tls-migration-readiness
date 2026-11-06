# Findings memo — Post-Quantum TLS Migration Readiness

Consolidated from the hybrid ML-KEM-768 TLS 1.3 assessment. Every finding
was measured on OpenSSL 3.5.9 and wolfSSL 5.9.4-stable (built from source)
or is labelled specification-derived. The full measured evidence is in
the assessment pack (results.json, raw logs, `regression_hrr.py` 9/9 PASS).

## F-1 (HIGH) — Flat server group list ignores server preference; deferred hybrid keyshare silently falls back to classical X25519

**Measured.** With a flat server list (`X25519:X25519MLKEM768`), the
negotiated group follows the client's order in both directions (D5: hybrid
wins; D5b: classical wins). A client that supports the hybrid but predicts
only a classical keyshare completes the handshake with classical X25519,
no error, no HelloRetryRequest (R2). **Remediation (measured):** use the
tuple syntax `X25519MLKEM768/X25519`; the server then sends an HRR (88-byte
ServerHello, RFC 8446 magic random, key_share request `0x11ec`) and the
client negotiates the hybrid (R1). **Relation to CVE-2026-2673:** same
downgrade class, but that CVE is specifically about the `DEFAULT` keyword
(affects 3.5.0–3.5.5 / 3.6.0–3.6.1, fixed in 3.5.6/3.6.2); this build is
3.5.9, so F-1 is the residual flat-list behaviour, not a CVE reproduction.
**Operator test:** `python3 operator_check.py --host <server> --port 443`
— test A must PASS.

## F-2 (MEDIUM) — wolfSSL 5.9.4 rejects standalone ML-KEM; OpenSSL 3.5.9 supports it

**Measured.** OpenSSL 3.5.9 negotiates standalone `MLKEM768` (rc=0, TLS 1.3).
wolfSSL 5.9.4's example server refuses to start with `--pqc ML_KEM_768`:
"invalid post-quantum KEM specified" (server.c:853). BoringSSL supports
standalone ML-KEM-1024 only (specification-derived, IETF writeup); Go has
no standalone ML-KEM TLS group (specification-derived). **Remediation:**
use hybrid groups (`X25519MLKEM768`) for interop; do not configure
standalone ML-KEM unless every peer is confirmed to support it.

## F-3 (MEDIUM) — Legacy (pre-PQ) servers silently fall back to classical X25519

**Measured.** An OpenSSL 3.5.9 client against a genuine system OpenSSL
3.0.13 server negotiates X25519, rc=0, TLS 1.3, no error. The legacy server
ignores the unknown group `0x11ec`. **Remediation:** log the negotiated
group for every connection (`SSL_get_negotiated_group()` / the s_client
"Negotiated TLS1.3 group" line) and alert when a connection that should be
hybrid negotiates a classical group. "Client supports hybrid" does not
imply "connection is hybrid".

## F-4 (LOW) — TLS 1.2 is classical-only

**Measured.** A TLS 1.2-only client negotiates TLS 1.2 +
ECDHE-ECDSA-AES256-GCM-SHA384 + X25519 (D4). ML-KEM groups are TLS 1.3 only
(RFC 10024). **Remediation:** enforce a TLS 1.3 minimum where
post-quantum protection is required.

## F-5 (LOW / informational) — Handshake latency is dominated by round trips

**Measured.** OpenSSL↔OpenSSL medians fit 2.5×RTT + ~10 ms at every
condition (baseline 8.7 ms; 25 ms one-way → 137.0 ms; 100 ms → 512.9 ms;
250 ms → 1254.9 ms; 100% success, no timeouts). The 1,216-byte client key
share adds no extra round trip on loopback. **Limitation:** MTU /
fragmentation effects on real networks were not measured.

## F-6 (LOW / environment) — OpenSSL s_server closes connections when stdin is EOF

**Measured (strace).** In a detached environment, `s_server` reads stdin
in its accept loop and treats EOF as "done", closing the connection before
any handshake. **Remediation:** hold stdin open (pipe). Affects test
harness automation, not TLS itself.

## F-7 (LOW / environment) — wolfSSL example server: 1 connection by default; dies on a bare TCP probe

**Measured.** The example server serves 1 connection by default (`-C`
raises it) and exits after a bare TCP probe's `SSL_accept` fails with
`SOCKET_ERROR_E (-308)`. **Remediation:** `-C 100`; check readiness with
`ss -ltn`, not a TCP connect. Affects the example server only, not the
wolfSSL library.

## Summary table

| ID | Severity | Finding | Remediation | Proof |
|----|----------|---------|-------------|-------|
| F-1 | HIGH | Flat-list server preference ignored; deferred keyshare → silent classical fallback | Tuple-syntax group list; server sends HRR | `regression_hrr.py` 9/9 PASS; `operator_check.py` (tuple ALL PASS, flat FAILS as expected) |
| F-2 | MEDIUM | wolfSSL rejects standalone ML-KEM; OpenSSL supports it | Use hybrid groups for interop | D6 |
| F-3 | MEDIUM | Legacy 3.0.13 server silently falls back to X25519 | Log + alert on negotiated group | D3 |
| F-4 | LOW | TLS 1.2 is classical-only | Enforce TLS 1.3 minimum | D4 |
| F-5 | LOW | Latency ≈ 2.5 RTT + ~10 ms | None (informational) | network trials |
| F-6 | LOW | s_server closes connections when stdin is EOF | Hold stdin open | strace |
| F-7 | LOW | wolfSSL example server: 1 connection by default; dies on bare TCP probe | `-C 100`; readiness via `ss -ltn` | smoke tests |
