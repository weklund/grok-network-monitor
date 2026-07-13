#!/bin/bash
set -euo pipefail

# run-tests.sh - Run all 5 network monitoring tests sequentially
# Requires: mitmproxy installed, CA trusted, grok CLI available

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
CAPTURE_DIR="$REPO_ROOT/captures"
CANARY_DIR="$CAPTURE_DIR/canary-repo"
ADDONS_DIR="$REPO_ROOT/addons"
MARKERS_FILE="$CAPTURE_DIR/markers.txt"
FLOW_STATS_ADDON="$ADDONS_DIR/flow-stats.py"
RESULTS_BASE="$CAPTURE_DIR/results-$(date +%Y%m%d-%H%M%S)"
RESULTS_DIR="$RESULTS_BASE"
PROXY_PORT=8080
GROK_RUN=0

# Auto-detect grok binary
GROK_BIN=""
if [[ -x "$HOME/.grok/bin/grok" ]]; then
    GROK_BIN="$HOME/.grok/bin/grok"
elif command -v grok &>/dev/null; then
    GROK_BIN="$(which grok)"
else
    echo "[!] ERROR: grok binary not found"
    echo "    Checked: ~/.grok/bin/grok and PATH"
    exit 1
fi

for command in mitmdump git strings python3; do
    if ! command -v "$command" &>/dev/null; then
        echo "[!] ERROR: required command not found: $command"
        exit 1
    fi
done

if [[ ! -f "$HOME/.mitmproxy/mitmproxy-ca-cert.pem" ]]; then
    echo "[!] ERROR: mitmproxy CA certificate not found. Run ./setup.sh first."
    exit 1
fi

if lsof -nP -iTCP:"$PROXY_PORT" -sTCP:LISTEN &>/dev/null; then
    echo "[!] ERROR: port $PROXY_PORT is already in use. Stop the existing proxy and retry."
    exit 1
fi

while [[ -e "$RESULTS_DIR" ]]; do
    RESULTS_DIR="${RESULTS_BASE}-$(date +%Y%m%d-%H%M%S)-$RANDOM"
done
mkdir -p "$RESULTS_DIR"

echo "=== Grok Network Monitor - Test Suite ==="
echo ""
echo "  Grok binary:  $GROK_BIN"
echo "  Capture dir:  $RESULTS_DIR"
echo "  Proxy port:   $PROXY_PORT"
echo "  Markers file: $MARKERS_FILE"
echo ""

# Helper: start mitmproxy with an addon in the background
start_proxy() {
    local addon="$1"
    local flow_file="$2"
    local proxy_log="$3"
    shift 3
    mitmdump --listen-port "$PROXY_PORT" \
        --set flow_detail=0 \
        -s "$addon" \
        -w "$flow_file" \
        "$@" > "$proxy_log" 2>&1 &
    PROXY_PID=$!
    for _ in $(seq 1 20); do
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            echo "[!] ERROR: mitmproxy failed to start."
            sed -n '1,120p' "$proxy_log" >&2 || true
            exit 1
        fi
        sleep 0.1
    done
    echo "    Proxy started (PID: $PROXY_PID)"
}

# Helper: stop mitmproxy
stop_proxy() {
    if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
        unset PROXY_PID
        echo "    Proxy stopped"
    fi
}

# Helper: run grok through the proxy
run_grok_proxied() {
    local workdir="$1"
    shift
    local prompt="${*:-"List the files in this project and describe the architecture briefly."}"

    GROK_RUN=$((GROK_RUN + 1))
    local grok_log="$RESULTS_DIR/grok-${GROK_RUN}.log"
    pushd "$workdir" >/dev/null
    local rc=0
    if HTTPS_PROXY="http://127.0.0.1:$PROXY_PORT" \
        HTTP_PROXY="http://127.0.0.1:$PROXY_PORT" \
        SSL_CERT_FILE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem" \
        "$GROK_BIN" --single "$prompt" > "$grok_log" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    popd >/dev/null
    if [[ "$rc" -ne 0 ]]; then
        echo "    [!] Grok command failed; see $grok_log" >&2
        return "$rc"
    fi
    echo "    Grok output: $grok_log"
}

summarize_flow() {
    local flow_file="$1"
    local stats_file="$2"
    mitmdump -nr "$flow_file" -s "$FLOW_STATS_ADDON" \
        --set stats_output="$stats_file" \
        --set stats_markers_file="$MARKERS_FILE" \
        --quiet >/dev/null 2>&1
    [[ -s "$stats_file" ]]
}

json_value() {
    local stats_file="$1"
    local expression="$2"
    python3 -c "import json; data=json.load(open('$stats_file')); print($expression)"
}

# Cleanup on exit
trap 'stop_proxy; echo ""; echo "[*] Tests interrupted."' EXIT

# Ensure canary repo exists
if [[ ! -d "$CANARY_DIR" || ! -f "$MARKERS_FILE" ]]; then
    echo "[*] Canary fixture or marker file missing, creating it..."
    "$SCRIPT_DIR/make-canary.sh"
    echo ""
fi

# ============================================================
# TEST 1: Protobuf Trace Decode
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 1: Protobuf Trace Decode"
echo "  Goal: Capture OTEL traces and extract readable strings"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

FLOW_FILE="$RESULTS_DIR/test1-traces.flow"
TRACE_OUTPUT="$RESULTS_DIR/test1-trace-strings.txt"

start_proxy "$ADDONS_DIR/classify.py" "$FLOW_FILE" "$RESULTS_DIR/test1-proxy.log"

echo "    Running grok on canary repo..."
run_grok_proxied "$CANARY_DIR"

stop_proxy
summarize_flow "$FLOW_FILE" "$RESULTS_DIR/test1-stats.json"

# Extract strings from captured flow data
echo "    Extracting protobuf strings..."
if [[ -f "$FLOW_FILE" ]]; then
    strings "$FLOW_FILE" | grep -iE '(trace|span|resource|service|grok|otel)' | sort -u > "$TRACE_OUTPUT" 2>/dev/null || true
    TRACE_COUNT=$(wc -l < "$TRACE_OUTPUT" | tr -d ' ')
    echo "    [RESULT] Found $TRACE_COUNT trace-related strings"
    echo "    Output: $TRACE_OUTPUT"
else
    echo "    [RESULT] No flow file captured"
fi

echo ""

# ============================================================
# TEST 2: Server Flag Flip (disable_codebase_upload)
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 2: Server Flag Flip"
echo "  Goal: Rewrite disable_codebase_upload=false, observe behavior"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

FLOW_FILE="$RESULTS_DIR/test2-flagflip.flow"
FLAG_LOG="$RESULTS_DIR/test2-flag-observations.txt"

start_proxy "$ADDONS_DIR/flip-upload.py" "$FLOW_FILE" "$RESULTS_DIR/test2-proxy.log"

echo "    Running grok with upload flag flipped..."
run_grok_proxied "$CANARY_DIR"

stop_proxy
summarize_flow "$FLOW_FILE" "$RESULTS_DIR/test2-stats.json"

# Analyze the flip-upload addon output
if [[ -f "$FLOW_FILE" ]]; then
    grep -F '[FLIP]' "$RESULTS_DIR/test2-proxy.log" > "$FLAG_LOG" || true
    UPLOAD_COUNT=$(json_value "$RESULTS_DIR/test2-stats.json" "data['categories'].get('UPLOAD', 0)")
    echo "    [RESULT] $UPLOAD_COUNT upload-classified candidate request(s) observed after flag flip"
    echo "    Output: $FLAG_LOG"

    if [[ "$UPLOAD_COUNT" -gt 0 ]]; then
        echo "    [!] ALERT: Upload-classified candidates observed after flag flip. Inspect test2-stats.json before concluding an upload occurred."
    else
        echo "    [i] No upload attempts observed (server may have additional gates)"
    fi
else
    echo "    [RESULT] No flow file captured"
fi

echo ""

# ============================================================
# TEST 3: GROK_WORKSPACE_DATA_COLLECTION_DISABLED Comparison
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 3: GROK_WORKSPACE_DATA_COLLECTION_DISABLED Comparison"
echo "  Goal: Compare request counts with/without the env var"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run WITHOUT the env var
FLOW_FILE_A="$RESULTS_DIR/test3-without-envvar.flow"
start_proxy "$ADDONS_DIR/classify.py" "$FLOW_FILE_A" "$RESULTS_DIR/test3-without-envvar-proxy.log"
echo "    Running grok WITHOUT GROK_WORKSPACE_DATA_COLLECTION_DISABLED..."
run_grok_proxied "$CANARY_DIR"
stop_proxy

sleep 2

# Run WITH the env var
FLOW_FILE_B="$RESULTS_DIR/test3-with-envvar.flow"
start_proxy "$ADDONS_DIR/classify.py" "$FLOW_FILE_B" "$RESULTS_DIR/test3-with-envvar-proxy.log"
echo "    Running grok WITH GROK_WORKSPACE_DATA_COLLECTION_DISABLED=1..."
GROK_WORKSPACE_DATA_COLLECTION_DISABLED=1 run_grok_proxied "$CANARY_DIR"
stop_proxy

summarize_flow "$FLOW_FILE_A" "$RESULTS_DIR/test3-without-envvar-stats.json"
summarize_flow "$FLOW_FILE_B" "$RESULTS_DIR/test3-with-envvar-stats.json"
SIZE_A=$(json_value "$RESULTS_DIR/test3-without-envvar-stats.json" "data['request_bytes']")
SIZE_B=$(json_value "$RESULTS_DIR/test3-with-envvar-stats.json" "data['request_bytes']")
COUNT_A=$(json_value "$RESULTS_DIR/test3-without-envvar-stats.json" "data['request_count']")
COUNT_B=$(json_value "$RESULTS_DIR/test3-with-envvar-stats.json" "data['request_count']")

echo ""
echo "    [RESULT] Traffic comparison:"
echo "      Without env var: $COUNT_A requests, $SIZE_A request-body bytes"
echo "      With env var:    $COUNT_B requests, $SIZE_B request-body bytes"

if [[ "$SIZE_A" -gt 0 && "$SIZE_B" -gt 0 ]]; then
    RATIO=$(echo "scale=1; $SIZE_B * 100 / $SIZE_A" | bc 2>/dev/null || echo "?")
    echo "      Byte ratio: ${RATIO}% (network responses and capture metadata excluded)"
fi

echo "    Output: $RESULTS_DIR/test3-*.flow"
echo ""

# ============================================================
# TEST 4: Secret Detection in Outbound Traffic
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 4: Secret Detection in Outbound Request Bodies"
echo "  Goal: Run grok on canary repo, grep for marker strings"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

FLOW_FILE="$RESULTS_DIR/test4-secrets.flow"
SECRETS_FOUND="$RESULTS_DIR/test4-secrets-found.txt"

start_proxy "$ADDONS_DIR/capture-all.py" "$FLOW_FILE" "$RESULTS_DIR/test4-proxy.log" --set markers_file="$MARKERS_FILE"

echo "    Running grok on canary repo (asking about code)..."
run_grok_proxied "$CANARY_DIR" "Review the database.py file and suggest improvements for security."

stop_proxy

    echo "    Searching outbound request bodies for marker strings..."
    : > "$SECRETS_FOUND"

if [[ -f "$FLOW_FILE" ]]; then
    summarize_flow "$FLOW_FILE" "$RESULTS_DIR/test4-stats.json"
    python3 -c "import json; data=json.load(open('$RESULTS_DIR/test4-stats.json')); [print(hit['marker']) for hit in data['request_marker_hits']]" | sort -u | while IFS= read -r marker; do
        [[ -n "$marker" ]] && echo "    [!] FOUND IN REQUEST: $marker" | tee -a "$SECRETS_FOUND"
    done
    FOUND_COUNT=$(wc -l < "$SECRETS_FOUND" | tr -d ' ')
    echo ""
    echo "    [RESULT] $FOUND_COUNT marker strings detected in outbound request bodies"
    echo "    Output: $SECRETS_FOUND"
else
    echo "    [RESULT] No flow file captured"
fi

echo ""

# ============================================================
# TEST 5: Large Repo Egress Measurement
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 5: Large Repo Egress Measurement"
echo "  Goal: Generate 50+ file repo, measure total request-body bytes sent"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

LARGE_REPO="$CAPTURE_DIR/large-test-repo"
FLOW_FILE="$RESULTS_DIR/test5-large-repo.flow"

# Generate large repo
echo "    Generating 50-file test repository..."
rm -rf "$LARGE_REPO"
mkdir -p "$LARGE_REPO/src" "$LARGE_REPO/lib" "$LARGE_REPO/tests"
cd "$LARGE_REPO"
git init --quiet
git config user.name "Grok Network Monitor"
git config user.email "grok-network-monitor@example.invalid"

for i in $(seq 1 20); do
    cat > "src/module_${i}.py" << PYEOF
"""Module $i - Auto-generated for egress testing."""

class Service${i}:
    def __init__(self):
        self.name = "service_${i}"
        self.config = {"key": "value_${i}", "port": $((3000 + i))}

    def process(self, data):
        """Process incoming data for service $i."""
        return {"result": f"processed_{self.name}", "input": data}

    def validate(self, payload):
        """Validate payload structure."""
        required = ["id", "timestamp", "body"]
        return all(k in payload for k in required)
PYEOF
done

for i in $(seq 1 15); do
    cat > "lib/util_${i}.js" << JSEOF
// Utility module $i
export function helper${i}(input) {
  const processed = input.map(x => x * $i);
  return { result: processed, module: 'util_${i}' };
}

export function validate${i}(data) {
  if (!data || typeof data !== 'object') return false;
  return 'id' in data && 'value' in data;
}

export const CONFIG_${i} = {
  timeout: ${i}000,
  retries: $((i % 5)),
  endpoint: '/api/v${i}/data'
};
JSEOF
done

for i in $(seq 1 15); do
    cat > "tests/test_module_${i}.py" << TESTEOF
"""Tests for module $i."""
import pytest
from src.module_${i} import Service${i}

def test_init_${i}():
    svc = Service${i}()
    assert svc.name == "service_${i}"

def test_process_${i}():
    svc = Service${i}()
    result = svc.process({"test": True})
    assert "result" in result

def test_validate_${i}():
    svc = Service${i}()
    assert svc.validate({"id": 1, "timestamp": "now", "body": "data"})
    assert not svc.validate({"id": 1})
TESTEOF
done

# Add a README
cat > README.md << 'READMEEOF'
# Large Test Project

Auto-generated project with 50 files for egress measurement testing.
READMEEOF

git add -A
git commit --quiet -m "Initial commit - 50 file project"
cd "$REPO_ROOT"

# Measure local repo size
LOCAL_SIZE=$(du -sb "$LARGE_REPO" 2>/dev/null | cut -f1 || du -sk "$LARGE_REPO" | awk '{print $1 * 1024}')
echo "    Local repo size: $LOCAL_SIZE bytes"

start_proxy "$ADDONS_DIR/classify.py" "$FLOW_FILE" "$RESULTS_DIR/test5-proxy.log"

echo "    Running grok on large repo..."
run_grok_proxied "$LARGE_REPO" "Give me an overview of this project structure and what each module does."

stop_proxy

if [[ -f "$FLOW_FILE" ]]; then
    summarize_flow "$FLOW_FILE" "$RESULTS_DIR/test5-stats.json"
    EGRESS_SIZE=$(json_value "$RESULTS_DIR/test5-stats.json" "data['request_bytes']")
    REQUEST_COUNT=$(json_value "$RESULTS_DIR/test5-stats.json" "data['request_count']")
    echo ""
    echo "    [RESULT] Egress measurement:"
    echo "      Local repo size:    $LOCAL_SIZE bytes"
    echo "      Outbound request bodies: $EGRESS_SIZE bytes across $REQUEST_COUNT requests"
    if [[ "$LOCAL_SIZE" -gt 0 ]]; then
        RATIO=$(echo "scale=1; $EGRESS_SIZE * 100 / $LOCAL_SIZE" | bc 2>/dev/null || echo "?")
    echo "      Request-body/repo ratio: ${RATIO}%"
    fi
    echo "    Output: $FLOW_FILE"
else
    echo "    [RESULT] No flow file captured"
fi

echo ""

# ============================================================
# Summary
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST SUITE COMPLETE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Results directory: $RESULTS_DIR"
echo ""
echo "  Run the analysis script for a detailed summary:"
echo "    ./scripts/analyze.sh $RESULTS_DIR"
echo ""

# Remove trap
trap - EXIT
