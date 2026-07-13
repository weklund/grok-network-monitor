#!/bin/bash
set -euo pipefail

# analyze.sh - Post-capture analysis of grok network traffic
# Usage: ./scripts/analyze.sh [results-directory]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
CAPTURE_DIR="$REPO_ROOT/captures"
MARKERS_FILE="$CAPTURE_DIR/markers.txt"
FLOW_STATS_ADDON="$REPO_ROOT/addons/flow-stats.py"

# Use provided results dir or find the most recent one
if [[ -n "${1:-}" ]]; then
    RESULTS_DIR="$1"
else
    RESULTS_DIR=$(ls -dt "$CAPTURE_DIR"/results-* 2>/dev/null | head -1 || true)
    if [[ -z "$RESULTS_DIR" ]]; then
        echo "[!] No results directory found. Run tests first:"
        echo "    ./scripts/run-tests.sh"
        exit 1
    fi
fi

if [[ ! -d "$RESULTS_DIR" ]]; then
    echo "[!] Results directory not found: $RESULTS_DIR"
    exit 1
fi

echo "=== Grok Network Traffic Analysis ==="
echo ""
echo "  Results directory: $RESULTS_DIR"
echo "  Analysis time:     $(date)"
echo ""

if ! command -v mitmdump &>/dev/null; then
    echo "[!] mitmdump is required to analyze flow files. Run ./setup.sh first."
    exit 1
fi

STATS_DIR="$RESULTS_DIR/flow-stats"
mkdir -p "$STATS_DIR"

summarize_flow() {
    local flow_file="$1"
    local stats_name
    local stats_file
    stats_name="$(basename "${flow_file%.flow}")"
    stats_file="$STATS_DIR/$stats_name.json"
    mitmdump -nr "$flow_file" -s "$FLOW_STATS_ADDON" \
        --set stats_output="$stats_file" \
        --set stats_markers_file="$MARKERS_FILE" \
        --quiet >/dev/null 2>&1
    printf '%s\n' "$stats_file"
}

# ============================================================
# 1. Total bytes by host
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. TRAFFIC VOLUME BY HOST"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TOTAL_REQUEST_BYTES=0
TOTAL_REQUESTS=0
for flow_file in "$RESULTS_DIR"/*.flow; do
    [[ -f "$flow_file" ]] || continue
    summarize_flow "$flow_file" >/dev/null
done

for stats_file in "$STATS_DIR"/*.json; do
    [[ -f "$stats_file" ]] || continue
    REQUEST_BYTES=$(python3 -c "import json; print(json.load(open('$stats_file'))['request_bytes'])")
    REQUESTS=$(python3 -c "import json; print(json.load(open('$stats_file'))['request_count'])")
    TOTAL_REQUEST_BYTES=$((TOTAL_REQUEST_BYTES + REQUEST_BYTES))
    TOTAL_REQUESTS=$((TOTAL_REQUESTS + REQUESTS))
done

echo "  Outbound request bodies: $TOTAL_REQUEST_BYTES bytes across $TOTAL_REQUESTS requests"
echo "  (Responses and mitmproxy archive metadata are excluded.)"
echo ""

# Extract hostnames from decoded request metadata.
echo "  Hosts observed in requests:"
python3 -c "import glob,json; print('\\n'.join(sorted({host for path in glob.glob('$STATS_DIR/*.json') for host in json.load(open(path))['hosts']})))" | while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    echo "    - $host"
done

echo ""

# Per-file breakdown
echo "  Per-capture request-body breakdown:"
for flow_file in "$RESULTS_DIR"/*.flow; do
    [[ -f "$flow_file" ]] || continue
    BASENAME=$(basename "$flow_file")
    STATS_FILE="$STATS_DIR/${BASENAME%.flow}.json"
    REQUEST_BYTES=$(python3 -c "import json; print(json.load(open('$STATS_FILE'))['request_bytes'])")
    REQUESTS=$(python3 -c "import json; print(json.load(open('$STATS_FILE'))['request_count'])")
    printf "    %-40s %s bytes across %s requests\n" "$BASENAME" "$REQUEST_BYTES" "$REQUESTS"
done

echo ""

# ============================================================
# 2. Alert files found
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. ALERT FILES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

ALERT_COUNT=0
for alert_file in "$RESULTS_DIR"/*alert* "$RESULTS_DIR"/*found* "$RESULTS_DIR"/*observation*; do
    [[ -f "$alert_file" ]] || continue
    ALERT_COUNT=$((ALERT_COUNT + 1))
    BASENAME=$(basename "$alert_file")
    LINES=$(wc -l < "$alert_file" | tr -d ' ')
    echo "  [$BASENAME] - $LINES entries"
    # Show first few lines
    head -5 "$alert_file" | sed 's/^/    /'
    if [[ "$LINES" -gt 5 ]]; then
        echo "    ... ($((LINES - 5)) more)"
    fi
    echo ""
done

if [[ "$ALERT_COUNT" -eq 0 ]]; then
    echo "  No alert files found."
    echo ""
fi

# ============================================================
# 3. Secrets detected across all captures
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. SECRET MARKER DETECTION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [[ ! -f "$MARKERS_FILE" ]]; then
    echo "  [!] No markers file found at: $MARKERS_FILE"
    echo ""
else
    SECRETS_DETECTED=0
    SECRETS_TOTAL=0

    while IFS= read -r marker; do
        [[ "$marker" =~ ^#.*$ ]] && continue
        [[ -z "$marker" ]] && continue
        SECRETS_TOTAL=$((SECRETS_TOTAL + 1))

        FOUND_IN=$(python3 -c "import glob,json,os,sys; marker=sys.argv[1]; print(' '.join(os.path.basename(path).replace('.json','.flow') for path in glob.glob(sys.argv[2] + '/*.json') if any(hit['marker'] == marker for hit in json.load(open(path))['request_marker_hits'])))" "$marker" "$STATS_DIR")

        if [[ -n "$FOUND_IN" ]]; then
            SECRETS_DETECTED=$((SECRETS_DETECTED + 1))
            echo "  [!] DETECTED: $marker"
            echo "      Found in:$FOUND_IN"
        else
            echo "  [ ] Not found: $marker"
        fi
    done < "$MARKERS_FILE"

    echo ""
    echo "  Summary: $SECRETS_DETECTED / $SECRETS_TOTAL markers detected in outbound request bodies"

    if [[ "$SECRETS_DETECTED" -gt 0 ]]; then
        echo ""
        echo "  A requested canary marker was present in an outbound request body."
        echo "  Inspect the matching flow before generalizing the result beyond that run."
    fi
fi

echo ""

# ============================================================
# 4. Settings flags observed
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. SETTINGS FLAGS OBSERVED"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

FLAGS_FOUND=0
for flow_file in "$RESULTS_DIR"/*.flow; do
    [[ -f "$flow_file" ]] || continue

    # Search for known settings flags
    SETTINGS_STRINGS=$(strings "$flow_file" | grep -iE '(disable_codebase_upload|trace_upload_enabled|zero_data_retention|data_collection|upload_skipped)' 2>/dev/null || true)

    if [[ -n "$SETTINGS_STRINGS" ]]; then
        FLAGS_FOUND=$((FLAGS_FOUND + 1))
        echo "  In $(basename "$flow_file"):"
        echo "$SETTINGS_STRINGS" | sort -u | sed 's/^/    /'
        echo ""
    fi
done

if [[ "$FLAGS_FOUND" -eq 0 ]]; then
    echo "  No settings flags captured in flow data."
    echo "  (Settings are typically in JSON responses from /v1/settings endpoints)"
fi

echo ""

# ============================================================
# 5. Telemetry event summary
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. TELEMETRY INDICATORS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

for flow_file in "$RESULTS_DIR"/*.flow; do
    [[ -f "$flow_file" ]] || continue

    BASENAME=$(basename "$flow_file")
    STATS_FILE="$STATS_DIR/${BASENAME%.flow}.json"
    TELEMETRY=$(python3 -c "import json; print(json.load(open('$STATS_FILE'))['categories'].get('TELEMETRY', 0))")
    LLM_CALLS=$(python3 -c "import json; print(json.load(open('$STATS_FILE'))['categories'].get('LLM_CALL', 0))")

    if [[ "$TELEMETRY" -gt 0 || "$LLM_CALLS" -gt 0 ]]; then
        echo "  $BASENAME:"
        echo "    Telemetry-classified requests: $TELEMETRY"
        echo "    LLM-call-classified requests:  $LLM_CALLS"
    fi
done

echo ""

# ============================================================
# Final Summary
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ANALYSIS COMPLETE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Key findings:"
echo "    - Outbound request bodies: $TOTAL_REQUEST_BYTES bytes across $TOTAL_REQUESTS requests"
echo "    - Alert files generated: $ALERT_COUNT"
echo "    - Secret markers in traffic: ${SECRETS_DETECTED:-0} / ${SECRETS_TOTAL:-0}"
echo "    - Settings flags observed: $FLAGS_FOUND captures"
echo ""
echo "  For detailed inspection, examine individual flow files with:"
echo "    mitmproxy -r $RESULTS_DIR/<file>.flow"
echo ""
