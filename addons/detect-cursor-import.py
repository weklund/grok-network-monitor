"""
detect-cursor-import.py - Detect exfiltration of imported Cursor chat content.

Tests grok v0.2.101's new Cursor-import capability. Scans every outbound request
body for the canary strings planted by scripts/make-cursor-honeypot.sh. A hit means
Cursor chat content (read from Cursor's state.vscdb via grok's composerHeaders SQL
reader) left the machine.

Also flags the original repo/.env honeypot secrets, so the same addon covers both
the Cursor-import test and a normal file-context exfil check.

IMPORTANT: drive grok from an EMPTY directory that contains none of these canary
strings. Otherwise grok reading this repo's own files will produce false positives
(the canaries are string literals here). The only clean signal is a canary that
could ONLY have come from the Cursor DB.

Usage:
    scripts/make-cursor-honeypot.sh
    mitmdump -s addons/detect-cursor-import.py
    # run grok through the proxy from an empty dir, invoke the import command
"""

import logging
from mitmproxy import http, ctx

# Canaries planted in the fake Cursor state.vscdb (see make-cursor-honeypot.sh).
# A hit here = imported Cursor chat content was transmitted.
CURSOR_CANARIES = [
    "CANARY_CURSOR_CHAT_9F3A2B",
    "ck_live_CURSOR_HONEYPOT_a1b2c3d4e5f6_DO_NOT_SHIP",
    "CANARY_ALGO_ZeroPointSeven",
    "/Users/canary/secret-cursor-project",
]

# Repo/.env honeypot secrets (normal file-context exfil check).
REPO_SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "sk_live_51HexampleFAKE",
    "SuperS3cret!Pass",
    "my-super-secret-jwt-signing-key",
    "Pr0d-DB-P@ss_2024!",
    "svc_FAKE_INTERNAL_KEY",
]

# Markers that reveal grok actually read Cursor's DB (vs. a canary leaking via some
# other file). Presence of these in a payload is strong evidence of a genuine import.
CURSOR_DB_FINGERPRINTS = [
    "composerHeaders",
    "canary-composer-0001",
    "state.vscdb",
    "globalStorage",
]


class CursorImportDetector:
    """Scans outbound traffic for exfiltrated Cursor-import canaries."""

    def __init__(self):
        self.requests_scanned = 0
        self.cursor_hits: list[dict] = []
        self.repo_hits: list[dict] = []

    def request(self, flow: http.HTTPFlow) -> None:
        content = flow.request.content
        if not content:
            return
        self.requests_scanned += 1
        body = content.decode("utf-8", errors="replace")

        cursor_found = [m for m in CURSOR_CANARIES if m in body]
        repo_found = [m for m in REPO_SECRETS if m in body]
        db_fp = [m for m in CURSOR_DB_FINGERPRINTS if m in body]

        if cursor_found:
            record = {
                "url": flow.request.pretty_url,
                "host": flow.request.pretty_host,
                "markers": cursor_found,
                "cursor_db_fingerprints": db_fp,
                "bytes": len(content),
            }
            self.cursor_hits.append(record)
            ctx.log.error(
                f"[!!! CURSOR-IMPORT EXFIL] {flow.request.pretty_host}"
                f"{flow.request.path} :: {cursor_found}"
                + (f" [DB-fingerprint: {db_fp}]" if db_fp else "")
            )

        if repo_found:
            record = {
                "url": flow.request.pretty_url,
                "host": flow.request.pretty_host,
                "markers": repo_found,
                "bytes": len(content),
            }
            self.repo_hits.append(record)
            ctx.log.warn(
                f"[! REPO-SECRET EXFIL] {flow.request.pretty_host}"
                f"{flow.request.path} :: {repo_found}"
            )

    def done(self):
        ctx.log.info("")
        ctx.log.info("=" * 60)
        ctx.log.info("CURSOR-IMPORT DETECTION SUMMARY")
        ctx.log.info("=" * 60)
        ctx.log.info(f"  Requests scanned:      {self.requests_scanned}")
        ctx.log.info(f"  Cursor-canary hits:    {len(self.cursor_hits)}")
        ctx.log.info(f"  Repo-secret hits:      {len(self.repo_hits)}")
        ctx.log.info("")
        if self.cursor_hits:
            ctx.log.error("  CURSOR IMPORT EXFILTRATION CONFIRMED:")
            for h in self.cursor_hits:
                fp = " [DB-fingerprint present]" if h["cursor_db_fingerprints"] else ""
                ctx.log.error(f"    {h['host']} <- {h['markers']}{fp}")
        else:
            ctx.log.info(
                "  No Cursor canaries observed. The Cursor reader did not "
                "transmit imported chat content in this session."
            )
        if self.repo_hits:
            ctx.log.warn("  Repo/.env secrets seen in outbound traffic:")
            for h in self.repo_hits:
                ctx.log.warn(f"    {h['host']} <- {h['markers']}")
        ctx.log.info("=" * 60)


addons = [CursorImportDetector()]
