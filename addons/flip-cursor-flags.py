"""
flip-cursor-flags.py - Rewrite /v1/settings to force-enable Cursor/Codex import flags.

Companion to flip-upload.py. Where that addon tests the codebase-upload gate, this one
tests the NEW v0.2.101 foreign-session import gates: it flips the cursor_*_enabled and
codex_sessions_enabled flags to True in the server settings response, to see whether the
dormant Cursor chat-DB reader activates when the server-side gate is removed.

Pair with scripts/make-cursor-honeypot.sh (plants a canary Cursor DB) and, ideally,
addons/detect-cursor-import.py running alongside to catch any exfiltrated canaries.

IMPORTANT: this is a research tool. As of v0.2.101 there is no /import-cursor command;
this tests whether server-flag manipulation is sufficient to wake the reader that ships
in the binary but is not wired to a user-facing command.

Usage:
    scripts/make-cursor-honeypot.sh
    mitmdump -s addons/flip-cursor-flags.py
    # drive grok through the proxy from an empty dir; try /import
"""

import json
from datetime import datetime
from mitmproxy import http, ctx

# Flags flipped to True in the settings response.
CURSOR_FLAGS = [
    "cursor_sessions_enabled",
    "cursor_rules_enabled",
    "cursor_agents_enabled",
    "cursor_skills_enabled",
    "cursor_mcps_enabled",
    "cursor_hooks_enabled",
    "codex_sessions_enabled",
]

# Canaries to watch for on the wire (mirror make-cursor-honeypot.sh).
CANARIES = [
    "CANARY_CURSOR_CHAT_9F3A2B",
    "ck_live_CURSOR_HONEYPOT_a1b2c3d4e5f6_DO_NOT_SHIP",
    "CANARY_ALGO_ZeroPointSeven",
    "/Users/canary/secret-cursor-project",
]


class CursorFlagFlipper:
    """Force-enables Cursor/Codex import flags in settings responses."""

    def __init__(self):
        self.settings_intercepted = 0
        self.flips: list[dict] = []
        self.canary_hits: list[dict] = []

    def response(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url.lower()
        if not any(x in url for x in ["/v1/settings", "/settings", "/config"]):
            return
        if "json" not in flow.response.headers.get("content-type", ""):
            return
        try:
            data = json.loads(flow.response.content.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        self.settings_intercepted += 1
        changed = {}
        for flag in CURSOR_FLAGS:
            original = self._find_and_set(data, flag, True)
            if original is not None:
                changed[flag] = {"from": original, "to": True}
                ctx.log.warn(f"[FLIP] {flag}: {original} -> True")

        if changed:
            new_body = json.dumps(data)
            flow.response.content = new_body.encode("utf-8")
            flow.response.headers["content-length"] = str(len(new_body))
            self.flips.append({
                "timestamp": datetime.now().isoformat(),
                "url": flow.request.pretty_url,
                "changed": changed,
            })
            ctx.log.warn(f"[FLIP] Settings rewritten ({len(changed)} cursor/codex flags -> True)")
        else:
            keys = list(data.keys()) if isinstance(data, dict) else "non-dict"
            ctx.log.info(f"[FLIP] No cursor/codex flags present. Keys: {keys}")

    def request(self, flow: http.HTTPFlow) -> None:
        content = flow.request.content
        if not content:
            return
        body = content.decode("utf-8", errors="replace")
        found = [m for m in CANARIES if m in body]
        if found:
            self.canary_hits.append({
                "url": flow.request.pretty_url,
                "markers": found,
            })
            ctx.log.error(
                f"[!!! CANARY] {flow.request.pretty_host}{flow.request.path} :: {found}"
            )

    def _find_and_set(self, data, key: str, value):
        """Recursively find `key` and set it to `value`. Return original if changed."""
        if isinstance(data, dict):
            if key in data and data[key] != value:
                original = data[key]
                data[key] = value
                return original
            for v in data.values():
                r = self._find_and_set(v, key, value)
                if r is not None:
                    return r
        elif isinstance(data, list):
            for item in data:
                r = self._find_and_set(item, key, value)
                if r is not None:
                    return r
        return None

    def done(self):
        ctx.log.info("")
        ctx.log.info("=" * 60)
        ctx.log.info("CURSOR FLAG FLIP SUMMARY")
        ctx.log.info("=" * 60)
        ctx.log.info(f"  Settings responses intercepted: {self.settings_intercepted}")
        ctx.log.info(f"  Flag flips applied:             {len(self.flips)}")
        ctx.log.info(f"  Canary hits after flip:         {len(self.canary_hits)}")
        ctx.log.info("")
        if self.canary_hits:
            ctx.log.error("  DORMANT READER WOKEN — Cursor canaries exfiltrated:")
            for h in self.canary_hits:
                ctx.log.error(f"    {h['url']} <- {h['markers']}")
        elif self.flips:
            ctx.log.info(
                "  Flags forced True, but no Cursor canaries left the machine."
            )
            ctx.log.info(
                "  The reader likely needs a user-facing command (absent in v0.2.101)"
            )
            ctx.log.info("  in addition to the server flag.")
        ctx.log.info("=" * 60)


addons = [CursorFlagFlipper()]
