#!/bin/bash
set -euo pipefail

# monitor.sh - Quick interactive network monitoring for Grok CLI
# Works without root privileges (uses lsof polling, not tcpdump)
#
# Modes:
#   ./monitor.sh live     - Live proxy view with classification
#   ./monitor.sh poll     - Background polling of grok connections
#   ./monitor.sh lsof     - One-shot connection listing
#   ./monitor.sh quick    - Quick capture (30 seconds)
#   (no args)             - Interactive menu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ADDONS_DIR="$SCRIPT_DIR/addons"
CAPTURE_DIR="$SCRIPT_DIR/captures"
PROXY_PORT="${GROK_MONITOR_PORT:-8080}"

# Auto-detect grok binary
GROK_BIN=""
if [[ -x "$HOME/.grok/bin/grok" ]]; then
    GROK_BIN="$HOME/.grok/bin/grok"
elif command -v grok &>/dev/null; then
    GROK_BIN="$(which grok)"
fi

# Find grok process
find_grok_pids() {
    pgrep -f "grok" 2>/dev/null || true
}

# ============================================================
# Mode: lsof - Show current grok network connections
# ============================================================
mode_lsof() {
    echo "=== Grok Network Connections (lsof) ==="
    echo ""

    local pids
    pids=$(find_grok_pids)

    if [[ -z "$pids" ]]; then
        echo "  No grok processes found running."
        echo ""
        echo "  Start grok in another terminal, then run this again."
        return
    fi

    echo "  Grok PIDs: $pids"
    echo ""

    for pid in $pids; do
        echo "  --- PID $pid ---"
        lsof -i -a -p "$pid" 2>/dev/null | grep -E "(ESTABLISHED|LISTEN|TCP|UDP)" || echo "    (no network connections)"
        echo ""
    done
}

# ============================================================
# Mode: poll - Background connection polling
# ============================================================
mode_poll() {
    local duration="${1:-60}"
    local interval="${2:-2}"

    echo "=== Grok Connection Polling ==="
    echo "  Duration: ${duration}s | Interval: ${interval}s"
    echo "  Press Ctrl+C to stop"
    echo ""
    echo "  Timestamp            | PID    | Connection"
    echo "  ---------------------|--------|------------------------------------------"

    local end_time=$((SECONDS + duration))
    local seen_connections=""

    while [[ $SECONDS -lt $end_time ]]; do
        local pids
        pids=$(find_grok_pids)

        if [[ -n "$pids" ]]; then
            for pid in $pids; do
                local connections
                connections=$(lsof -i -a -p "$pid" -Fn 2>/dev/null | grep "^n" | sed 's/^n//' || true)

                while IFS= read -r conn; do
                    [[ -z "$conn" ]] && continue
                    # Only show new connections
                    if [[ "$seen_connections" != *"$conn"* ]]; then
                        printf "  %-21s | %-6s | %s\n" "$(date +%H:%M:%S.%N | cut -c1-12)" "$pid" "$conn"
                        seen_connections="$seen_connections|$conn"
                    fi
                done <<< "$connections"
            done
        fi

        sleep "$interval"
    done

    echo ""
    echo "  Polling complete."
}

# ============================================================
# Mode: live - Start mitmproxy with live classification view
# ============================================================
mode_live() {
    echo "=== Live Traffic Classification ==="
    echo ""
    echo "  Starting mitmproxy on port $PROXY_PORT..."
    echo "  Configure grok to use the proxy:"
    echo ""
    echo "    export HTTPS_PROXY=http://127.0.0.1:$PROXY_PORT"
    echo "    export HTTP_PROXY=http://127.0.0.1:$PROXY_PORT"
    echo "    export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem"
    echo ""
    echo "  Press Ctrl+C to stop"
    echo ""

    mkdir -p "$CAPTURE_DIR"

    # Use mitmproxy (interactive) rather than mitmdump (headless)
    mitmproxy --listen-port "$PROXY_PORT" \
        -s "$ADDONS_DIR/classify.py" \
        -s "$ADDONS_DIR/dump-telemetry.py"
}

# ============================================================
# Mode: quick - Quick 30-second capture
# ============================================================
mode_quick() {
    local duration="${1:-30}"
    local flow_file="$CAPTURE_DIR/quick-$(date +%Y%m%d-%H%M%S).flow"

    echo "=== Quick Capture (${duration}s) ==="
    echo ""
    echo "  Output: $flow_file"
    echo "  Proxy:  http://127.0.0.1:$PROXY_PORT"
    echo ""
    echo "  Run grok with these env vars in another terminal:"
    echo "    HTTPS_PROXY=http://127.0.0.1:$PROXY_PORT \\"
    echo "    HTTP_PROXY=http://127.0.0.1:$PROXY_PORT \\"
    echo "    SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem \\"
    echo "    grok --message \"your prompt here\""
    echo ""
    echo "  Capturing for ${duration} seconds..."
    echo ""

    mkdir -p "$CAPTURE_DIR"

    # Run mitmdump with timeout
    timeout "$duration" mitmdump \
        --listen-port "$PROXY_PORT" \
        -s "$ADDONS_DIR/classify.py" \
        -w "$flow_file" 2>&1 || true

    echo ""
    echo "  Capture complete: $flow_file"

    if [[ -f "$flow_file" ]]; then
        local size
        size=$(wc -c < "$flow_file" | tr -d ' ')
        echo "  Size: $size bytes"
        echo ""
        echo "  Analyze with: mitmproxy -r $flow_file"
    fi
}

# ============================================================
# Interactive menu
# ============================================================
show_menu() {
    echo "=== Grok Network Monitor ==="
    echo ""

    if [[ -n "$GROK_BIN" ]]; then
        echo "  Grok binary: $GROK_BIN"
    else
        echo "  Grok binary: NOT FOUND"
    fi

    local pids
    pids=$(find_grok_pids)
    if [[ -n "$pids" ]]; then
        echo "  Grok running: YES (PIDs: $pids)"
    else
        echo "  Grok running: NO"
    fi
    echo ""
    echo "  Commands:"
    echo "    1) lsof   - Show current grok connections"
    echo "    2) poll   - Poll connections for 60 seconds"
    echo "    3) live   - Start mitmproxy with live view"
    echo "    4) quick  - Quick 30-second capture"
    echo "    5) quit   - Exit"
    echo ""
    read -rp "  Select [1-5]: " choice

    case "$choice" in
        1|lsof)  mode_lsof ;;
        2|poll)  mode_poll ;;
        3|live)  mode_live ;;
        4|quick) mode_quick ;;
        5|q|quit) exit 0 ;;
        *) echo "  Invalid choice."; show_menu ;;
    esac
}

# ============================================================
# Main
# ============================================================
case "${1:-menu}" in
    lsof)  mode_lsof ;;
    poll)  mode_poll "${2:-60}" "${3:-2}" ;;
    live)  mode_live ;;
    quick) mode_quick "${2:-30}" ;;
    menu|"")  show_menu ;;
    -h|--help)
        echo "Usage: $0 [lsof|poll|live|quick|menu]"
        echo ""
        echo "  lsof          One-shot connection listing"
        echo "  poll [s] [i]  Poll for s seconds at i interval"
        echo "  live          Start mitmproxy interactive view"
        echo "  quick [s]     Quick s-second capture (default 30)"
        echo "  menu          Interactive menu (default)"
        ;;
    *)
        echo "Unknown mode: $1"
        echo "Run '$0 --help' for usage"
        exit 1
        ;;
esac
