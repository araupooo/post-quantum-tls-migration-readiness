# Claim-to-evidence index — Post-Quantum TLS Migration Readiness Pack

Labels: **[measured]** = reproduced by a script in this pack (or in the
cycle-5 pack it builds on) with the raw output saved; **[specification-
derived]** = follows from a cited primary source; **[unavailable]** =
could not be tested in this environment, stated honestly rather than
claimed.

## Measured claims

| # | Claim | Evidence |
|---|---|---|
| M-1 | OpenSSL 3.5.9 and wolfSSL 5.9.4-stable both negotiate hybrid X25519MLKEM768, both directions | cycle-5 `outputs/results.json` (network + interop); baselines 10/10 each |
| M-2 | Client key share 1,216 B, server key share 1,120 B (group 0x11EC) | `outputs/raw/clienthello_msg.log` (cycle-5 `-msg` transcript) |
| M-3 | Flat server list: negotiated group follows the client's order both ways (D5/D5b) | cycle-5 `outputs/raw/downgrade_D5*.log` |
| M-4 | Tuple server list sends an HRR to a deferred-keyshare client; the HRR carries the RFC 8446 magic random and a key_share request for 0x11ec; the client then negotiates the hybrid | R1, `outputs/raw/hrr_R1_tuple_hrr_client.log`; `regression_hrr.py` 9/9 PASS |
| M-5 | Flat server list with a deferred-keyshare client sends no HRR and completes with classical X25519 | R2, `outputs/raw/hrr_R2_flat_no_hrr_client.log` |
| M-6 | `operator_check.py` passes (ALL PASS, exit 0) against a tuple-configured server and fails test A (exit 1) against a flat-configured server, with test B passing in both cases | `outputs/raw/operator_check_tuple.log`, `outputs/raw/operator_check_flat.log` (fresh runs, 2026-11-06 ~04:10 WIB) |
| M-7 | OpenSSL 3.5.9 negotiates standalone MLKEM768; wolfSSL 5.9.4's example server refuses `--pqc ML_KEM_768` ("invalid post-quantum KEM specified") | cycle-5 D6, `outputs/raw/downgrade_D6_*.log`, `server_dg_D6_standalone_mlkem_wolfssl.log` |
| M-8 | Legacy OpenSSL 3.0.13 server negotiates X25519 with a hybrid client (rc=0, no error) | cycle-5 D3 (clean environment) |
| M-9 | TLS 1.2-only client negotiates TLS 1.2 + ECDHE-ECDSA-AES256-GCM-SHA384 + X25519 | cycle-5 D4 |
| M-10 | Handshake latency fits 2.5×RTT + ~10 ms (baselines 8.7/6.2 ms; 25 ms → 137.0 ms; 100 ms → 512.9 ms; 250 ms → 1254.9 ms; 100% success) | cycle-5 `outputs/results.json` |
| M-11 | `s_server` closes connections when stdin is EOF (strace: accept → read(0)=0 → DONE) | cycle-5 `outputs/raw/strace_server.log` |
| M-12 | wolfSSL example server serves 1 connection by default and exits after a bare TCP probe's `SSL_accept` fails with -308 | cycle-5 smoke tests, walkthrough.log |
| M-13 | Kernel packet-loss emulation (`tc netem`) is unavailable (no CAP_NET_ADMIN) | cycle-5 `outputs/probe_netem.log` |

## Specification-derived claims

| # | Claim | Primary source |
|---|---|---|
| S-1 | X25519MLKEM768 codepoint 0x11EC (4588); client key share 1,216 B, server share 1,120 B, shared secret 64 B | RFC 10024 (Aug 2026) |
| S-2 | ML-KEM-768 parameters: k=3, ek 1184, dk 2400, ct 1088, ss 32 | FIPS 203 (DOI 10.6028/NIST.FIPS.203) |
| S-3 | Flat group list: OpenSSL treats all groups as comparable in security and prioritises avoiding round trips over either party's preference; tuple syntax (`/`) + `SSL_CTX_set1_groups_list()` is the recommended fix | OpenSSL `SSL_CTX_set1_curves(3SSL)`, https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/ |
| S-4 | HRR random is the fixed value `cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c` | RFC 8446 §4.1.4 |
| S-5 | CVE-2026-2673: server using the `DEFAULT` keyword may negotiate a less-preferred group; affects 3.5.0–3.5.5 and 3.6.0–3.6.1, fixed in 3.5.6/3.6.2, CVSS 6.5 | OpenSSL Security Advisory 2026-03-13, https://openssl-library.org/news/secadv/20260313.txt |
| S-6 | BoringSSL: Kyber768 shipped since 2023 (`X25519Kyber768Draft00`), updated to standard `X25519MLKEM768`; Chrome 131+ negotiates it by default | postquantum.com RFC 10024 summary; systemshardening.com deployment guide |
| S-7 | BoringSSL standalone ML-KEM: ML-KEM-1024 only | IETF draft-ietf-tls-mlkem writeup (implementation list), https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/writeup/ |
| S-8 | Go 1.24+: X25519MLKEM768 on by default when `CurvePreferences` is nil; `GODEBUG=tlsmlkem=0` disables it (only when nil); explicit `CurvePreferences` is used verbatim as the server's preference order; Go 1.27 allows explicit hybrid enablement even with the GODEBUG set | Go 1.24 release notes; Go stdlib `crypto/tls` documentation for `Config.CurvePreferences` |
| S-9 | Go has no native ML-KEM TLS group (hybrid only) | cryptoramic.com lab check (Go 1.27); IETF writeup's standalone list omits Go |
| S-10 | TLS 1.2 is classical-only on every stack (ML-KEM groups are TLS 1.3 only) | RFC 10024 |
| S-11 | The default OpenSSL 3.5 TLS group list includes and prefers hybrid groups | OpenSSL 3.5 release notes |

## Unavailable claims (not tested, not asserted)

| # | Claim | Reason |
|---|---|---|
| U-1 | BoringSSL server group-preference enforcement behaviour | Not measured in this run; BoringSSL was not built or tested here. Do not assume it behaves like OpenSSL. |
| U-2 | wolfSSL group-preference enforcement (beyond the single `--pqc` value) | The example server takes one `--pqc` value, so preference ordering was not testable with it. |
| U-3 | Packet-loss / reordering behaviour of hybrid handshakes | No CAP_NET_ADMIN (`tc netem` fails); the userspace proxy emulates delay/jitter only. |
| U-4 | MTU / fragmentation effects of the larger ClientHello on real networks | No control over the path MTU; loopback only. |
| U-5 | Active network attacker stripping the hybrid group from the ClientHello | Honest misconfiguration tested, not active injection. (Specification-derived: the TLS 1.3 transcript is authenticated, RFC 8446 §4.1.3/§4.4.) |
| U-6 | Behaviour of other TLS stacks (NSS, Rustls, s2n-tls, GnuTLS, Bouncy Castle, Botan, AWS-LC) beyond the four in the matrix | Only OpenSSL and wolfSSL were built and tested; BoringSSL and Go are primary-sourced, not measured. |
| U-7 | Production-server behaviour (nginx, Apache, haproxy, Envoy, Caddy) with these group lists | Only the `s_server` CLI and the wolfSSL example server were tested; the tuple-syntax remediation is at the OpenSSL API level. |
