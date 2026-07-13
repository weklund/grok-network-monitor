#!/bin/bash
set -euo pipefail

# analyze.sh - Post-capture analysis of grok network traffic
# Usage: ./scripts/analyze.sh [results-directory]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
CAPTURE_DIR="$REPO_ROOT/captures"
MARKERS_FILE="$CAPTURE_DIR/markers.txt"

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

# ============================================================
# 1. Total bytes by host
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. TRAFFIC VOLUME BY HOST"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TOTAL_BYTES=0
for flow_file in "$RESULTS_DIR"/*.flow; do
    [[ -f "$flow_file" ]] || continue
    SIZE=$(wc -c < "$flow_file" | tr -d ' ')
    TOTAL_BYTES=$((TOTAL_BYTES + SIZE))
done

echo "  Total captured traffic: $TOTAL_BYTES bytes ($(echo "scale=2; $TOTAL_BYTES / 1024" | bc 2>/dev/null || echo "?") KB)"
echo ""

# Extract hostnames from flow files
echo "  Hosts observed (extracted from flow data):"
for flow_file in "$RESULTS_DIR"/*.flow; do
    [[ -f "$flow_file" ]] || continue
    strings "$flow_file" | grep -oE '[a-zA-Z0-9.-]+\.(grok\.com|xai\.com|x\.ai|mixpanel\.com|amazonaws\.com)' | sort -u
done | sort -u | while read -r host; do
    echo "    - $host"
done

echo ""

# Per-file breakdown
echo "  Per-capture breakdown:"
for flow_file in "$RESULTS_DIR"/*.flow; do
    [[ -f "$flow_file" ]] || continue
    SIZE=$(wc -c < "$flow_file" | tr -d ' ')
    BASENAME=$(basename "$flow_file")
    printf "    %-40s %s bytes\n" "$BASENAME" "$SIZE"
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

        FOUND_IN=""
        for flow_file in "$RESULTS_DIR"/*.flow; do
            [[ -f "$flow_file" ]] || continue
            if strings "$flow_file" | grep -q "$marker" 2>/dev/null; then
                FOUND_IN="$FOUND_IN $(basename "$flow_file")"
            fi
        done

        if [[ -n "$FOUND_IN" ]]; then
            SECRETS_DETECTED=$((SECRETS_DETECTED + 1))
            echo "  [!] DETECTED: $marker"
            echo "      Found in:$FOUND_IN"
        else
            echo "  [ ] Not found: $marker"
        fi
    done < "$MARKERS_FILE"

    echo ""
    echo "  Summary: $SECRETS_DETECTED / $SECRETS_TOTAL markers detected in outbound traffic"

    if [[ "$SECRETS_DETECTED" -gt 0 ]]; then
        echo ""
        echo "  WARNING: Secrets from your working directory were transmitted to xAI servers."
        echo "  This is expected for files grok reads as LLM context, but confirms that"
        echo "  sensitive files should never be in a grok-accessible workspace."
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

    MIXPANEL=$(strings "$flow_file" | grep -ci "mixpanel" 2>/dev/null || echo "0")
    TELEMETRY=$(strings "$flow_file" | grep -ci "telemetry\|event\|track" 2>/dev/null || echo "0")

    if [[ "$MIXPANEL" -gt 0 || "$TELEMETRY" -gt 0 ]]; then
        echo "  $(basename "$flow_file"):"
        echo "    Mixpanel references: $MIXPANEL"
        echo "    Telemetry keywords:  $TELEMETRY"
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
echo "    - Total traffic captured: $TOTAL_BYTES bytes"
echo "    - Alert files generated: $ALERT_COUNT"
echo "    - Secret markers in traffic: ${SECRETS_DETECTED:-0} / ${SECRETS_TOTAL:-0}"
echo "    - Settings flags observed: $FLAGS_FOUND captures"
echo ""
echo "  For detailed inspection, examine individual flow files with:"
echo "    mitmproxy -r $RESULTS_DIR/<file>.flow"
echo ""
