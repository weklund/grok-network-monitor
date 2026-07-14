# Findings: Grok Build v0.2.101 (Delta from v0.2.99)

> **Tested on Grok Build v0.2.101** (`grok-0.2.101-macos-aarch64`), 2026-07-14, after an
> auto-update from v0.2.99. This document records **only what changed** relative to
> [FINDINGS.md](FINDINGS.md) (v0.2.99). Everything not listed here is unchanged.

## Method note

Two binaries were compared directly (`grok-0.2.99` and `grok-0.2.101`, both retained
locally). Analysis used `strings` on the Mach-O arm64 binaries, per-binary marker
counts, slash-command registry enumeration, and live HTTPS capture via mitmproxy.

**No decompilation was performed.** Claims below are tagged by evidence type so the
distinction between "a string exists in the binary" and "this code path runs" stays
explicit:

- **[BIN]** — literal string present/absent in the binary (proves existence, not execution)
- **[CNT]** — per-binary marker-count diff (reliable for "added between versions")
- **[REG]** — slash-command registry enumeration (compile-time, install-independent)
- **[RUN]** — observed over the wire via mitmproxy (highest confidence — actual behavior)
- **[INF]** — inference/interpretation, explicitly not proven

---

## Comparison matrix

| # | Finding | v0.2.99 | v0.2.101 | Evidence |
|---|---------|---------|----------|----------|
| 1 | Cursor chat-DB reader (`composerHeaders` SQL against Cursor's `state.vscdb`) | absent | **present** | [CNT] 0→1 |
| 2 | `/import-cursor` slash command | n/a | **not registered** (only `/import`, `/import-claude`, `/import-map`) | [REG] |
| 3 | Cursor reader reachable by a shipped command? | n/a | **no — dormant** | [RUN]+[REG] |
| 4 | `cursor_*_enabled` server flags + `codex_sessions_enabled` | absent | **present** (parallel to existing `claude_*_enabled`) | [BIN] |
| 5 | Generalized "foreign sessions" backend (Cursor + Codex slots) | — | **present** | [BIN] |
| 6 | Codebase-upload infra (S3/GCS multipart, `disable_codebase_upload`, bucket `grok-code-session-traces`) | present | **unchanged** | [CNT] equal |
| 7 | Mixpanel + grok.com dual telemetry | present | **present, persists** | [RUN] |
| 8 | `GROK_WORKSPACE_DATA_COLLECTION_DISABLED` env var | present, no effect | **unchanged in binary** | [BIN] |
| 9 | Binary string count | 89,072 | 89,196 (+124 net) | [CNT] |
| 10 | Changelog entry for the update | — | **none** (bundled `CHANGELOG.md` stops at 0.2.99) | [BIN] |

---

## The one genuinely new capability: Cursor session import (dormant)

v0.2.101 adds machinery to read **Cursor's** local chat database. The binary contains
this literal SQL (absent in v0.2.99) [CNT]:

```sql
SELECT composerId, lastUpdatedAt, value FROM composerHeaders
  WHERE COALESCE(isArchived,0)=0 AND COALESCE(isSubagent,0)=0
        AND lastUpdatedAt BETWEEN ?1 AND ?2 ...
SELECT key, value FROM meta WHERE key IN ('metadata','title','name','cwd',...)
```

It reads from `~/Library/Application Support/Cursor/User/globalStorage/state.vscdb`
and a new server-flag family gates it: `cursor_sessions_enabled`, `cursor_rules_enabled`,
`cursor_agents_enabled`, `cursor_skills_enabled`, `cursor_mcps_enabled`,
`cursor_hooks_enabled`, plus `codex_sessions_enabled` — mirroring the existing
`claude_*_enabled` flags. This sits on a generalized "foreign sessions" backend with
Cursor and Codex slots [BIN].

### But it is not reachable in v0.2.101

- The only import commands compiled into the binary are `/import`, `/import-claude`,
  and `/import-map`. **There is no `/import-cursor` command** [REG]. Its absence is *not*
  because Cursor is uninstalled — the command string simply does not exist in the binary.
- **Runtime test [RUN]:** a fake Cursor `state.vscdb` was planted with unique canary
  strings (schema matching grok's exact SQL), then `/import-claude` was driven from an
  empty directory so the *only* way a canary could reach the network was a genuine Cursor
  read. Result: **`canary_hits: 0`** — no canary, no `state.vscdb` / `composerHeaders` /
  `globalStorage` reference in any captured payload. The Cursor reader did not fire.

**Conclusion:** the Cursor-import capability is built and flag-defined but **staged, not
shipped** — present ahead of its user-facing front door. This is the same pattern as the
codebase-upload feature documented in v0.2.99 (capability live, gated server-side).

Reproduce with `scripts/make-cursor-honeypot.sh` + `addons/detect-cursor-import.py`.

---

## Runtime telemetry (observed, v0.2.101)

Two short driven sessions, 144 requests total. The dual-tracking pattern from v0.2.99
persists; counts are observed [RUN]:

| Destination | Path | This capture (2 short sessions) |
|-------------|------|--------------------------------|
| grok.com | `/_data/v1/events` | 47 |
| api.mixpanel.com | `/track` | 45 |
| api.mixpanel.com | `/engage` | 6 |
| cli-chat-proxy | `/v1/responses` (LLM) | 8 |
| cli-chat-proxy | `/v1/traces` (OTLP) | 7 |
| cli-chat-proxy | `/v1/settings` | 8 |

---

## Upload-decision gate shift (runtime/account state, not a code change)

`~/.grok/logs/unified.jsonl` shows the upload-gate reason changed since v0.2.99:

| Field | v0.2.99 report | v0.2.101 (live) |
|-------|----------------|-----------------|
| `upload_reason` | `feature_off` (natural) | **`zdr_team`** (natural, every turn) |
| `data_collection_disabled` | `false` | **`true`** |
| `uploads_enabled: true` ever | never | never (0 across current log) |

**[INF]** The first gate now in play is the account's ZDR team status (`zdr_team`), not
the server feature flag (`feature_off`). For a non-ZDR user in this state, the weaker
safeguard would be the one standing — the exact fragility the v0.2.99 report warned about.

---

## Not tested

1. **Waking the dormant reader** — forcing `cursor_sessions_enabled: true` via a
   settings rewrite to see if the reader activates. `addons/flip-cursor-flags.py` is
   provided for this; it was not run for this document.
2. **Kill-switch re-test** — `GROK_WORKSPACE_DATA_COLLECTION_DISABLED` behavior at
   runtime was not re-measured this round.
3. **Non-ZDR / free-tier account, non-macOS** — all observations are SuperGrok + ZDR on
   macOS arm64.
4. **Control-flow / dead-code determination** — not attempted; would require actual
   disassembly. All reachability claims here are behavioral ([RUN]), not from reading code.

---

*Last updated: 2026-07-14*
