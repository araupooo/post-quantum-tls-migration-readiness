# Post-Quantum TLS Migration Readiness Pack

Task: "Publish Post-Quantum TLS Migration Readiness Evidence Pack"
(task_aeb7a111fea019cf734a27793b94333c, Personal, 5 PFT, Submit Mixed).
Turns the hybrid ML-KEM-768 TLS 1.3 assessment (cycle 5, task_2e53110c)
into a public, deployment-ready reference other teams can independently
verify.

## The six components (as required)

| # | Component | File(s) |
|---|---|---|
| 1 | Public artifact link | The durable public page built from this pack (see "Public artifact" below) — also listed in `public_artifact_url.txt` once published |
| 2 | Readiness matrix (four stacks) | `matrix.md` |
| 3 | Configuration guide (OpenSSL + wolfSSL) | `guide.md` |
| 4 | Regression script + unedited output | `operator_check.py` (+ `run_operator_check.sh`), `outputs/raw/operator_check_tuple.log`, `outputs/raw/operator_check_flat.log` |
| 5 | Findings memo (severity-ranked) | `findings.md` |
| 6 | Claim-to-evidence index | `index.md` |

Also in the pack: `README.md` (this file), `walkthrough.log`,
`regression_hrr.py` (the cycle-5 F-1 proof, 9/9 PASS), and the supporting
raw logs (`outputs/raw/clienthello_msg.log`, `hrr_R1/R2/R3_*.log`).

## Headline result

With a **flat** server group list, the negotiated group follows the
**client's** order — a client deferring the hybrid keyshare silently falls
back to classical X25519 (F-1, HIGH). With the **tuple** group list
(`X25519MLKEM768/X25519`), the server sends a HelloRetryRequest and the
client negotiates the hybrid. `operator_check.py` proves it against any
server: ALL PASS (exit 0) on a tuple-configured server, test A FAILS
(exit 1) on a flat-configured one.

## How to use this pack

```bash
# Check your own server (needs OpenSSL 3.5+ s_client):
python3 operator_check.py --host your.server.example --port 443
# ALL PASS (exit 0) = the server enforces the hybrid.
# Test A FAIL + test B PASS = flat-list misconfiguration (F-1): apply guide.md §1.

# Reproduce the local runs (needs the cycle-5 built OpenSSL + test PKI):
bash run_operator_check.sh
# Writes outputs/raw/operator_check_{tuple,flat}.log
```

## Public artifact

The public page presents the readiness matrix, the configuration guide,
and the operator check in a single durable, inspectable page. Its URL is
recorded in `public_artifact_url.txt` and in the submission. The page's
content is fixed at build time and embeds the measured values from this
pack (it does not re-derive them at runtime).

## Environment and provenance

Cycle-5 measurements: OpenSSL 3.5.9 and wolfSSL 5.9.4-stable, built from
source (tarball SHAs `603f5602…` / `7256bfc8…`), Linux VM, no CAP_NET_ADMIN.
BoringSSL and Go rows in the matrix are specification-derived from primary
sources (not re-run here) and are labelled as such in every cell. All
work done 2026-11-06 ~03:51–05:00 WIB.
