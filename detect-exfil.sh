#!/bin/bash
set -euo pipefail

# detect-exfil.sh - One-shot local artifact scan (no proxy needed)
#
# Scans the ~/.grok/ directory and system state for evidence of:
#   - Upload queue contents (pending or completed uploads)
#   - Session transcript sizes (how much data is cached locally)
#   - Projects/directories accessed by grok
#   - Telemetry configuration and opt-out state
#   - Current network connections from grok processes
#
# This script requires NO proxy setup - it examines local artifacts only.

GROK_DIR="${GROK_DIR:-$HOME/.grok}"

echo "=== Grok Exfiltration Artifact Scan ==="
echo ""
echo "  Scan time: $(date)"
echo "  Grok dir:  $GROK_DIR"
echo ""

if [[ ! -d "$GROK_DIR" ]]; then
    echo "[!] Grok directory not found: $GROK_DIR"
    echo "    Is grok installed? Expected at ~/.grok/"
    exit 1
fi

# ============================================================
# 1. Upload queue / staging area
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. UPLOAD QUEUE / STAGING"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Look for upload-related directories
UPLOAD_DIRS=("upload" "uploads" "queue" "staging" "bundles" "pending" "outbox")
FOUND_UPLOAD=0

for dir_name in "${UPLOAD_DIRS[@]}"; do
    matches=$(find "$GROK_DIR" -type d -iname "*${dir_name}*" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        FOUND_UPLOAD=1
        while IFS= read -r match; do
            file_count=$(find "$match" -type f 2>/dev/null | wc -l | tr -d ' ')
            dir_size=$(du -sh "$match" 2>/dev/null | cut -f1)
            echo "  [!] Found: $match"
            echo "      Files: $file_count | Size: $dir_size"
            if [[ "$file_count" -gt 0 ]]; then
                echo "      Contents:"
                find "$match" -type f -exec ls -lh {} \; 2>/dev/null | head -10 | sed 's/^/        /'
            fi
            echo ""
        done <<< "$matches"
    fi
done

# Look for git bundle files
BUNDLES=$(find "$GROK_DIR" -type f \( -name "*.bundle" -o -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" \) 2>/dev/null || true)
if [[ -n "$BUNDLES" ]]; then
    FOUND_UPLOAD=1
    echo "  [!] Git bundles / archives found:"
    while IFS= read -r bundle; do
        ls -lh "$bundle" | sed 's/^/      /'
    done <<< "$BUNDLES"
    echo ""
fi

if [[ "$FOUND_UPLOAD" -eq 0 ]]; then
    echo "  No upload queue or staging directories found."
    echo "  (Upload infrastructure may use temp dirs or in-memory buffers)"
fi
echo ""

# ============================================================
# 2. Session transcripts
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. SESSION TRANSCRIPTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Look for session/conversation data
SESSION_DIRS=$(find "$GROK_DIR" -type d \( -iname "*session*" -o -iname "*conversation*" -o -iname "*history*" -o -iname "*transcript*" -o -iname "*chat*" \) 2>/dev/null || true)

if [[ -n "$SESSION_DIRS" ]]; then
    while IFS= read -r dir; do
        file_count=$(find "$dir" -type f 2>/dev/null | wc -l | tr -d ' ')
        dir_size=$(du -sh "$dir" 2>/dev/null | cut -f1)
        echo "  Found: $dir"
        echo "    Files: $file_count | Total size: $dir_size"

        # Show largest files
        if [[ "$file_count" -gt 0 ]]; then
            echo "    Largest transcripts:"
            find "$dir" -type f -exec ls -lS {} \; 2>/dev/null | head -5 | awk '{print "      " $5 " " $NF}'
        fi
        echo ""
    done <<< "$SESSION_DIRS"
else
    # Fall back to looking for JSON/JSONL files that might be transcripts
    LARGE_JSON=$(find "$GROK_DIR" -type f \( -name "*.json" -o -name "*.jsonl" \) -size +10k 2>/dev/null | head -20 || true)
    if [[ -n "$LARGE_JSON" ]]; then
        echo "  Large JSON files (potential transcripts):"
        while IFS= read -r file; do
            size=$(ls -lh "$file" | awk '{print $5}')
            echo "    $size  $file"
        done <<< "$LARGE_JSON"
    else
        echo "  No session transcript directories found."
    fi
fi
echo ""

# ============================================================
# 3. Projects accessed
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. PROJECTS / WORKSPACES ACCESSED"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Look for project references in config/state files
PROJECT_FILES=$(find "$GROK_DIR" -type f \( -name "*project*" -o -name "*workspace*" -o -name "*recent*" -o -name "*state*" \) 2>/dev/null | head -20 || true)

if [[ -n "$PROJECT_FILES" ]]; then
    echo "  Project/workspace state files:"
    while IFS= read -r file; do
        echo "    $file"
        # Try to extract paths from the file
        if file "$file" | grep -q "text\|JSON"; then
            grep -oE '/[a-zA-Z0-9_./-]+' "$file" 2>/dev/null | grep -v "^/v1\|^/api" | sort -u | head -10 | sed 's/^/      path: /' || true
        fi
        echo ""
    done <<< "$PROJECT_FILES"
else
    echo "  No project state files found."
    echo ""
    # Try to find paths referenced anywhere in grok's data
    echo "  Searching for filesystem paths in grok data..."
    ALL_PATHS=$(find "$GROK_DIR" -type f -size -1M -exec grep -loh "$HOME/[a-zA-Z0-9_./ -]*" {} \; 2>/dev/null | sort -u | head -20 || true)
    if [[ -n "$ALL_PATHS" ]]; then
        echo "$ALL_PATHS" | sed 's/^/    /'
    else
        echo "    No filesystem paths found in grok data."
    fi
fi
echo ""

# ============================================================
# 4. Telemetry configuration
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. TELEMETRY CONFIGURATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Look for config files
CONFIG_FILES=$(find "$GROK_DIR" -type f \( -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" -o -name "config*" -o -name "settings*" \) 2>/dev/null | head -20 || true)

if [[ -n "$CONFIG_FILES" ]]; then
    echo "  Configuration files found:"
    while IFS= read -r file; do
        size=$(ls -lh "$file" 2>/dev/null | awk '{print $5}')
        echo "    [$size] $file"

        # Extract telemetry-related settings
        if file "$file" | grep -q "text\|JSON"; then
            TELEMETRY_LINES=$(grep -iE '(telemetry|analytics|tracking|mixpanel|opt.out|data.collection|upload|privacy|retention)' "$file" 2>/dev/null | head -5 || true)
            if [[ -n "$TELEMETRY_LINES" ]]; then
                echo "$TELEMETRY_LINES" | sed 's/^/          /'
            fi
        fi
    done <<< "$CONFIG_FILES"
else
    echo "  No configuration files found."
fi

echo ""

# Check environment variables
echo "  Relevant environment variables:"
env | grep -iE '(GROK|XAI)' 2>/dev/null | sed 's/^/    /' || echo "    (none set)"
echo ""

# ============================================================
# 5. Current network connections
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. CURRENT NETWORK CONNECTIONS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

GROK_PIDS=$(pgrep -f "grok" 2>/dev/null || true)

if [[ -n "$GROK_PIDS" ]]; then
    echo "  Active grok processes:"
    for pid in $GROK_PIDS; do
        CMDLINE=$(ps -p "$pid" -o args= 2>/dev/null || echo "unknown")
        echo "    PID $pid: $CMDLINE"
    done
    echo ""
    echo "  Network connections:"
    for pid in $GROK_PIDS; do
        lsof -i -a -p "$pid" 2>/dev/null | grep -v "^COMMAND" | sed 's/^/    /' || true
    done
    if ! lsof -i -a -p "$(echo "$GROK_PIDS" | head -1)" &>/dev/null; then
        echo "    (lsof requires the process to be running)"
    fi
else
    echo "  No grok processes currently running."
    echo ""
    echo "  Checking for recent connections to known grok hosts..."
    # Check DNS cache or recent connections if available
    if command -v nettop &>/dev/null; then
        echo "  (Use 'nettop' while grok is running for live connection data)"
    fi
fi

echo ""

# ============================================================
# 6. Upload decision history (CRITICAL CHECK)
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. UPLOAD DECISION HISTORY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

UNIFIED_LOG="$GROK_DIR/logs/unified.jsonl"

if [[ -f "$UNIFIED_LOG" ]]; then
    UPLOAD_DECISIONS=$(grep "trace.upload.decision" "$UNIFIED_LOG" 2>/dev/null || true)
    DECISION_COUNT=$(echo "$UPLOAD_DECISIONS" | grep -c "trace.upload.decision" 2>/dev/null || echo 0)

    if [[ "$DECISION_COUNT" -gt 0 ]]; then
        echo "  Found $DECISION_COUNT upload decision log entries."
        echo ""

        # Check for any successful uploads
        UPLOADS_ENABLED=$(echo "$UPLOAD_DECISIONS" | grep '"uploads_enabled":true' || true)
        if [[ -n "$UPLOADS_ENABLED" ]]; then
            echo "  ╔══════════════════════════════════════════════════╗"
            echo "  ║  ⚠️  WARNING: UPLOADS WERE ENABLED              ║"
            echo "  ║  Your repository data MAY have been uploaded.   ║"
            echo "  ╚══════════════════════════════════════════════════╝"
            echo ""
            echo "  Entries with uploads_enabled=true:"
            echo "$UPLOADS_ENABLED" | python3 -c "
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        ts = d.get('ts', '?')
        ctx = d.get('ctx', {})
        reason = ctx.get('upload_reason', '?')
        turn = ctx.get('turn_number', '?')
        sid = d.get('sid', '?')[:12]
        print(f'    {ts}  reason={reason}  turn={turn}  session={sid}...')
    except: pass
" 2>/dev/null
        else
            echo "  ✓ No uploads occurred during logged period."
            echo "    All decisions show uploads_enabled=false."
        fi

        echo ""
        echo "  Upload reasons breakdown:"
        echo "$UPLOAD_DECISIONS" | python3 -c "
import json, sys, collections
reasons = collections.Counter()
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        reason = d.get('ctx', {}).get('upload_reason', 'unknown')
        reasons[reason] += 1
    except: pass
for reason, count in reasons.most_common():
    print(f'    {reason}: {count}')
" 2>/dev/null

        echo ""
        echo "  Log date range:"
        FIRST_TS=$(echo "$UPLOAD_DECISIONS" | head -1 | python3 -c "import json,sys; print(json.loads(sys.stdin.read().strip()).get('ts','?'))" 2>/dev/null || echo "?")
        LAST_TS=$(echo "$UPLOAD_DECISIONS" | tail -1 | python3 -c "import json,sys; print(json.loads(sys.stdin.read().strip()).get('ts','?'))" 2>/dev/null || echo "?")
        echo "    First entry: $FIRST_TS"
        echo "    Last entry:  $LAST_TS"
        echo ""
        echo "  ⚠️  IMPORTANT: This only covers the log retention window."
        echo "     If you used grok before '$FIRST_TS',"
        echo "     earlier upload decisions may have been rotated out."
        echo "     Absence of evidence in truncated logs ≠ evidence of absence."
    else
        echo "  No upload decision entries found in logs."
        echo "  (The log may be empty, rotated, or from a version that doesn't log this)"
    fi
else
    echo "  Log file not found: $UNIFIED_LOG"
    echo "  Cannot check upload history."
fi
echo ""

# ============================================================
# 7. Disk usage summary
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7. DISK USAGE SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TOTAL_SIZE=$(du -sh "$GROK_DIR" 2>/dev/null | cut -f1)
echo "  Total ~/.grok size: $TOTAL_SIZE"
echo ""
echo "  Top-level breakdown:"
du -sh "$GROK_DIR"/* 2>/dev/null | sort -rh | head -15 | sed 's/^/    /'

echo ""
echo ""

# ============================================================
# Summary
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SCAN COMPLETE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  This scan examined local artifacts only (no network interception)."
echo "  For active traffic monitoring, use:"
echo "    ./monitor.sh live     # Interactive proxy view"
echo "    ./scripts/run-tests.sh  # Full test suite"
echo ""
