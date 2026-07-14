#!/bin/bash
# make-cursor-honeypot.sh - Plant a fake Cursor chat DB seeded with canary strings.
#
# Tests whether grok v0.2.101's new Cursor-import capability (the composerHeaders
# SQL reader) causes Cursor chat content to leave the machine. Pair with
# addons/detect-cursor-import.py, then drive grok's import command through the proxy.
#
# SAFE: refuses to run if a real Cursor DB already exists (won't clobber your data).
#
# Usage:
#   scripts/make-cursor-honeypot.sh
#   # then run grok through the proxy from an EMPTY dir and invoke /import
#   # cleanup:  rm -f "$HOME/Library/Application Support/Cursor/User/globalStorage/state.vscdb"
set -euo pipefail

CURSOR_DIR="$HOME/Library/Application Support/Cursor/User/globalStorage"
DB="$CURSOR_DIR/state.vscdb"

# Unique canaries — a hit in captured traffic means imported Cursor chat was exfiltrated.
# These are also the strings addons/detect-cursor-import.py scans for.
CANARY_TITLE="CANARY_CURSOR_CHAT_9F3A2B"
CANARY_SECRET="ck_live_CURSOR_HONEYPOT_a1b2c3d4e5f6_DO_NOT_SHIP"
CANARY_ALGO="CANARY_ALGO_ZeroPointSeven"
CANARY_CWD="/Users/canary/secret-cursor-project"
CANARY_TEXT="This Cursor conversation discusses the proprietary ${CANARY_ALGO} ranking model and contains the internal token ${CANARY_SECRET}."

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "ERROR: sqlite3 not found (needed to build the fake DB)." >&2
    exit 1
fi

# Refuse to overwrite a real Cursor DB
if [ -f "$DB" ]; then
    if ! sqlite3 "$DB" "SELECT value FROM meta WHERE key='title' LIMIT 1;" 2>/dev/null | grep -q "$CANARY_TITLE"; then
        echo "REFUSING: a real (non-honeypot) Cursor state.vscdb exists at:" >&2
        echo "  $DB" >&2
        echo "Back it up and remove it yourself if you want to run this test." >&2
        exit 1
    fi
fi

mkdir -p "$CURSOR_DIR"
rm -f "$DB"

NOW_MS=1752000000000  # fixed timestamp (avoids nondeterminism)

sqlite3 "$DB" <<SQL
CREATE TABLE meta (key TEXT PRIMARY KEY, value);
INSERT INTO meta(key,value) VALUES
  ('title', '$CANARY_TITLE'),
  ('name',  '$CANARY_TITLE'),
  ('cwd',   '$CANARY_CWD'),
  ('updatedAtMs', $NOW_MS),
  ('metadata', '{"note":"$CANARY_TEXT"}'),
  ('0', '$CANARY_TEXT');

CREATE TABLE composerHeaders (
  composerId TEXT,
  lastUpdatedAt INTEGER,
  value TEXT,
  isArchived INTEGER,
  isSubagent INTEGER
);
INSERT INTO composerHeaders VALUES
  ('canary-composer-0001', $NOW_MS,
   '{"title":"$CANARY_TITLE","text":"$CANARY_TEXT","secret":"$CANARY_SECRET"}',
   0, 0);
SQL

echo "Honeypot Cursor DB written: $DB"
echo "  canary title : $CANARY_TITLE"
echo "  canary secret: $CANARY_SECRET"
echo
echo "Next: run grok through the proxy (addon: addons/detect-cursor-import.py) and"
echo "invoke the import command. Any ALERT = imported Cursor chat left the machine."
echo "Cleanup: rm -f \"$DB\""
