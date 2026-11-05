#!/bin/bash
# Run operator_check.py against a local OpenSSL 3.5.9 test server in both
# configurations (tuple list = remediated, flat list = F-1 misconfigured)
# and save the unedited outputs. Uses the cycle-5 built OpenSSL and test
# PKI (../task-2e53110c/). Usage: bash run_operator_check.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
C5="$HERE/../task-2e53110c"
OPENSSL="$C5/openssl-3.5.9-install/bin/openssl"
CERTS="$C5/outputs/certs"
export LD_LIBRARY_PATH="$C5/openssl-3.5.9-install/lib64"

run_one() {
    local tag="$1" groups="$2"
    local port=18443
    # stdin from a held-open pipe (sleep 60): s_server reads stdin in its
    # accept loop and treats EOF as "done", closing the connection before
    # the handshake (finding F-6). A held-open pipe makes the read block.
    "$OPENSSL" s_server -accept "$port" -cert "$CERTS/server.crt" \
        -key "$CERTS/server.key" -tls1_3 -groups "$groups" \
        -CAfile "$CERTS/ca.crt" < <(sleep 60) \
        > "$HERE/outputs/raw/operator_server_$tag.log" 2>&1 &
    local srv=$!
    sleep 1
    python3 "$HERE/operator_check.py" --host 127.0.0.1 --port "$port" \
        --openssl "$OPENSSL" --cafile "$CERTS/ca.crt" \
        > "$HERE/outputs/raw/operator_check_$tag.log" 2>&1
    echo "operator_check $tag: exit $?"
    kill "$srv" 2>/dev/null
    wait "$srv" 2>/dev/null
}

run_one tuple "X25519MLKEM768/X25519"
run_one flat "X25519MLKEM768:X25519"
echo "outputs in $HERE/outputs/raw/operator_check_{tuple,flat}.log"
