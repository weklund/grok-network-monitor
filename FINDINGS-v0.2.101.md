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

The **How we know** column says in plain words what kind of evidence backs each row,
so the table stands on its own. The short tag in parentheses (`[CNT]`, `[RUN]`, …) maps
to the confidence legend under the table.

| # | Finding | v0.2.99 | v0.2.101 | How we know |
|---|---------|---------|----------|-------------|
| 1 | Cursor chat-DB reader (`composerHeaders` SQL against Cursor's `state.vscdb`) | absent | **present** | The SQL string count went 0 → 1 between the two binaries — added this version (count diff, [CNT]) |
| 2 | `/import-cursor` slash command | n/a | **not registered** (only `/import`, `/import-claude`, `/import-map`) | Enumerated the compiled-in command registry; the string isn't there (registry, [REG]) |
| 3 | Cursor reader reachable by a shipped command? | n/a | **no — dormant** | No command triggers it (registry) *and* it never fired in a live proxied session (observed traffic, [RUN]+[REG]) |
| 4 | `cursor_*_enabled` server flags + `codex_sessions_enabled` | absent | **present** (parallel to existing `claude_*_enabled`) | The flag strings exist in the binary (present in binary, [BIN]) |
| 5 | Generalized "foreign sessions" backend (Cursor + Codex slots) | — | **present** | Backend/slot strings exist in the binary (present in binary, [BIN]) |
| 6 | Codebase-upload infra (top-level: `serialize_repo_changes`, tar/GCS/storage-proxy, `disable_codebase_upload`, bucket `grok-code-session-traces`) | present | **core path persists, bundle-upload layer stripped** — see §"Upload path changes" below | Raw-byte count diff across both binaries (count diff, [CNT]) |
| 7 | Mixpanel + grok.com dual telemetry | present | **present, persists** | Watched both fire over the wire this version (observed traffic, [RUN]) |
| 8 | `GROK_WORKSPACE_DATA_COLLECTION_DISABLED` env var | present, no effect | **unchanged in binary** | The string is still present; its runtime effect was not re-measured (present in binary, [BIN]) |
| 9 | Binary size / string volume | 129,124,976 B; 364,177 lines | 128,899,824 B (−225 KB); 365,348 lines (`strings -a \| wc -l`) | Byte size + total `strings -a` line count per binary (count diff, [CNT]) |
| 10 | Changelog entry for the update | — | **none** (bundled `CHANGELOG.md` stops at 0.2.99) | The bundled changelog file has no 0.2.101 entry (present in binary, [BIN]) |

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

## Upload path changes: bundle-upload layer stripped, core spine intact

An earlier draft of this document called the codebase-upload infrastructure
"unchanged." That was wrong — it came from a tokenized string diff that masked the
change. A **raw-byte** count (`grep -a -F` over the whole Mach-O, not `strings`, to rule
out tokenization artifacts) shows a specific implementation layer was **removed** in
v0.2.101, while the high-level upload spine remains.

**Removed entirely in v0.2.101** (raw-byte occurrences → 0) [CNT]:

| Marker | v0.2.99 | v0.2.101 |
|--------|:---:|:---:|
| `upload_coordinator` / `repo_state.upload_coordinator` | 3 | **0** |
| `git bundle create` / `bundle_create_failed` / `bundle_upload_failed` / `bundle too large` | 1 each | **0** |
| `flush_base_tree_batch` / `batch_upload` / `check_exists` / `Base tree upload complete` (base-tree dedup+batch layer) | 2–5 | **0** |
| `S3 storage client` | 1 | **0** |
| `repo_changes/mod.rs` / `upload_blocked` / `probe blocked` | 1–2 | **0** |

**Still present in v0.2.101** (unchanged) [BIN]:

- `serialize_repo_changes` (top-level entry point), `Wrote repo changes archive`
- `multipart upload`, `storage proxy`, `GCS URL`, `Failed to upload to gs://`
- `disable_codebase_upload` (×4), `first-parent history`, `public base`, `serialize_repo_changes_with_dedup`

The binary also shrank ~225 KB (129,124,976 → 128,899,824 bytes).

**[INF]** This reads as a **partial teardown / refactor, not a removal of the
capability.** The "collect repo changes → build archive → upload via GCS/storage-proxy"
spine and the server kill-switch flag both survive; what's gone is the git-*bundle*
upload *coordinator* and the base-tree dedup/batch machinery. Two readings fit the strings
equally well: (a) the bundle strategy was retired in favor of the tar+GCS path that
remains, or (b) genuine slimming. **`strings` alone cannot distinguish these, and no
decompilation was performed** — so intent is unknown. What is byte-verified is only that
these specific symbols are present in 0.2.99 and absent in 0.2.101.

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
