# Post-Quantum TLS Migration Readiness Matrix

Four TLS stacks, four dimensions each. Every cell is labelled by how it
was established: **[measured]** = reproduced in the cycle-5 assessment
(OpenSSL 3.5.9 / wolfSSL 5.9.4, built from source, run on this machine);
**[specification-derived]** = follows from a cited primary source, not
re-run here; **[unavailable]** = could not be verified in this run.

## The matrix

| Dimension | OpenSSL 3.5.9 | wolfSSL 5.9.4 | BoringSSL (Chrome) | Go 1.24+ (crypto/tls) |
|---|---|---|---|---|
| Hybrid X25519MLKEM768 supported | **Yes [measured]** — native; negotiated both directions, 10/10 trials | **Yes [measured]** — with `WOLFSSL_MLKEM` + `WOLFSSL_PQC_HYBRIDS`; negotiated both directions | **Yes [specification-derived]** — Kyber768 shipped since 2023 as `X25519Kyber768Draft00`; updated to the standard `X25519MLKEM768` name/codepoint as IETF standardisation completed; Chrome 131+ negotiates it by default | **Yes [specification-derived]** — on by default from Go 1.24 (Feb 2025) when `CurvePreferences` is nil; `GODEBUG=tlsmlkem=0` disables it (only when `CurvePreferences` is nil) |
| Standalone ML-KEM as a TLS group | **Yes [measured]** — server `-groups MLKEM768` negotiates `MLKEM768`, rc=0, TLS 1.3 | **No [measured]** — example server refuses `--pqc ML_KEM_768`: "invalid post-quantum KEM specified" (server.c:853) | **ML-KEM-1024 only [specification-derived]** — the IETF draft-ietf-tls-mlkem writeup lists standalone ML-KEM implementations as "BoringSSL (1024)"; 512/768 not listed | **No [specification-derived]** — Go has no native ML-KEM TLS group (only the hybrid); the IETF writeup's standalone list omits Go |
| Group-preference enforcement (server) | **Flat list: client's order wins [measured]** — D5/D5b; **tuple list: server sends HRR [measured]** — R1 (see guide.md) | **[unavailable]** — the example server takes a single `--pqc` value, so preference ordering was not testable with it | **[unavailable]** — not verified in this run; BoringSSL's server group-selection behaviour was not measured here | **Server's CurvePreferences order honoured [specification-derived]** — an explicit `CurvePreferences` list is used verbatim as the server's preference order; the default (nil) includes X25519MLKEM768 from Go 1.24 |
| TLS 1.2 behaviour | **Classical-only [measured]** — D4: TLS 1.2 + ECDHE-ECDSA-AES256-GCM-SHA384 + X25519 | **Classical-only [specification-derived]** — ML-KEM groups are TLS 1.3 only (RFC 10024), so any TLS 1.2 handshake is classical-only regardless of stack | **Classical-only [specification-derived]** — same RFC 10024 basis | **Classical-only [specification-derived]** — same RFC 10024 basis; Go still supports TLS 1.2 (MinVersion), but no PQ group exists for it |

## How to read this matrix

- **"Yes" for a hybrid group means the stack can negotiate
  X25519MLKEM768.** It does not mean your deployment does: the negotiated
  group is what matters, and a flat-list OpenSSL server (F-1) or a legacy
  peer can silently land on classical X25519. Run `operator_check.py`
  against your own server to find out what it actually negotiates.
- **Standalone ML-KEM is the least portable option.** Only OpenSSL 3.5.9
  (measured) and BoringSSL for ML-KEM-1024 (specification-derived) support
  it; wolfSSL and Go do not. Use the hybrid group for interop.
- **Group-preference enforcement is the dimension most likely to surprise
  you.** OpenSSL's flat list does not enforce server preference (F-1);
  the tuple list does. For BoringSSL this dimension is unverified here —
  do not assume it behaves like OpenSSL.
- **TLS 1.2 is classical-only everywhere.** There is no post-quantum key
  exchange in TLS 1.2 (RFC 10024 defines the hybrid groups for TLS 1.3
  only). Any deployment that still allows TLS 1.2 allows classical-only
  key exchange.

## Primary sources

- RFC 10024 (Aug 2026): X25519MLKEM768 codepoint 0x11EC (4588); client
  key share 1,216 bytes, server share 1,120 bytes. https://www.rfc-editor.org/rfc/rfc10024.txt
- FIPS 203 (DOI 10.6028/NIST.FIPS.203): ML-KEM-768 parameters (k=3,
  ek 1184, dk 2400, ct 1088, ss 32).
- OpenSSL 3.5 `SSL_CTX_set1_curves(3SSL)` documentation (tuple syntax,
  flat-list semantics): https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/
- OpenSSL Security Advisory, 2026-03-13 (CVE-2026-2673): https://openssl-library.org/news/secadv/20260313.txt
- IETF draft-ietf-tls-mlkem writeup (standalone ML-KEM implementation
  list): https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/writeup/
- Go 1.24 release notes (crypto/mlkem, X25519MLKEM768 default) and the
  Go stdlib `crypto/tls` documentation for `Config.CurvePreferences`
  ("From Go 1.24, the default includes the [X25519MLKEM768] hybrid
  post-quantum key exchange. To disable it, set CurvePreferences
  explicitly or use the GODEBUG=tlsmlkem=0 environment variable.").
- BoringSSL: Kyber768 shipped since 2023 (`X25519Kyber768Draft00`),
  updated to `X25519MLKEM768`; Chrome 131+ negotiates it by default
  (see the postquantum.com RFC 10024 summary and the systemshardening.com
  deployment guide for the timeline; the codepoint/name change follows
  the IETF standardisation).

## Measured basis (cycle 5)

The OpenSSL and wolfSSL rows rest on the cycle-5 assessment
(task_2e53110c, rewarded 5 PFT, completion 97, evidence 93):
OpenSSL 3.5.9 and wolfSSL 5.9.4-stable built from source (tarball SHAs
`603f5602…` and `7256bfc8…`); baselines 10/10 on both stacks; network
conditions 25/100/250 ms; downgrade cases D1–D6 + D5b; interop both
directions; HRR regression R1/R2/R3 (9/9 PASS). Full evidence in the
cycle-5 pack (results.json, raw logs). The BoringSSL and Go rows were NOT
re-run here — they are specification-derived from the primary sources
above, and the matrix says so in every cell.
