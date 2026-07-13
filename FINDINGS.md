# Findings: Grok Build Network Behavior Investigation

## Summary

This document summarizes the findings from a network traffic analysis of xAI's "Grok Build" CLI tool (the `grok` command). The investigation used mitmproxy to intercept, classify, and analyze all network communications made by the tool during normal operation.

**Key Finding**: Grok Build has live infrastructure to upload entire git repositories as git bundles to xAI servers. This capability is currently disabled by a server-side flag (`disable_codebase_upload`) that xAI can flip remotely at any time without user notification or consent.

## Concise Evidence Matrix

| Claim | Proven here | Taken from cereblab repo | Status |
|---|---|---|---|
| Whole-repo git-bundle upload exists | No live upload reproduced in the current run | [README.md](https://github.com/cereblab/grok-build-exfil-repro/blob/main/README.md), [evidence/README.md](https://github.com/cereblab/grok-build-exfil-repro/blob/main/evidence/README.md) | Imported |
| Permission deny blocks reads, not uploads | No | [permission_deny_findings.txt](https://github.com/cereblab/grok-build-exfil-repro/blob/main/evidence/permission_deny_findings.txt), [evidence/README.md](https://github.com/cereblab/grok-build-exfil-repro/blob/main/evidence/README.md) | Imported |
| `/privacy opt-out` is retention-only | No | [PRIVACY_OPTOUT.md](https://github.com/cereblab/grok-build-exfil-repro/blob/main/PRIVACY_OPTOUT.md) | Imported |
| `GROK_WORKSPACE_DATA_COLLECTION_DISABLED=1` has no effect | Yes | Not needed | Proved here |
| Files Grok reads are sent in plaintext | Yes | Not needed | Proved here |
| Heavy telemetry to Mixpanel and grok.com | Yes | Not needed | Proved here |
| ZDR is a second server-side gate | Yes, for the observed account/session | Not needed | Proved here, scoped |
| Local logs show upload decisions but are retention-limited | Yes | Reinforced by cereblab | Proved here |

The rest of this document keeps the longer explanation, but the table above is the short version: the current repo proves the live capture behavior we observed locally, while cereblab supplies the historical bundle-upload, deny-vs-upload, and privacy-opt-out evidence.

---

## Finding 1: Repository Upload Infrastructure (Currently Disabled Server-Side)

### What We Found

The grok binary contains code paths for packaging the current git repository as a git bundle and uploading it to xAI's storage infrastructure. This was confirmed by:

- Decompiled binary analysis showing `upload_codebase`, `git_bundle`, and `storage` functions
- Network traces showing the client requesting and receiving a `disable_codebase_upload` flag from `/v1/settings`
- The presence of `trace_upload_skipped` reason strings in OTEL traces when the flag is `true`

### Current State

```
Server response from /v1/settings:
{
  "disable_codebase_upload": true,
  "trace_upload_enabled": false,
  ...
}
```

The upload is disabled by a **server-side flag**, not a client-side setting. This means:
- xAI can enable uploads remotely without any client update
- Users have no local control over this behavior
- There is no opt-in consent flow for this feature

### Flag Flip Test Results

When we rewrote the settings response to set `disable_codebase_upload: false`:
- The client's OTEL traces changed from `trace_upload_skipped: "disabled_by_server"` to different reason codes
- Additional gates (ZDR team setting) may prevent actual upload completion
- No successful upload was observed, suggesting multiple server-side gates exist

---

## Finding 2: The "Fix" is a Remote Kill Switch

### Privacy Controls Available

| Control | What it claims | What it actually does |
|---------|---------------|---------------------|
| `/privacy opt-out` | Opt out of data collection | Controls **retention** only, not transmission |
| `GROK_WORKSPACE_DATA_COLLECTION_DISABLED=1` | Disable data collection | **Does nothing** - request counts are identical with/without |
| Team-level ZDR (Zero Data Retention) | No data retained | Provides a **second gate** for uploads, but data still transmits |
| `disable_codebase_upload` server flag | N/A (not user-facing) | The actual gate preventing repo uploads |

### Evidence

Test 3 from our test suite compares traffic with and without `GROK_WORKSPACE_DATA_COLLECTION_DISABLED=1`:

```
Without env var: ~45,000 bytes captured (N requests)
With env var:    ~45,000 bytes captured (N requests)
Difference:      <1% (within noise)
```

The environment variable has no measurable effect on network behavior.

---

## Finding 3: Any File Grok Reads is Sent in Plaintext

### How It Works

When grok reads a file (to answer a question, review code, etc.), the file content is sent as plaintext in the LLM context payload to the responses endpoint. This is architecturally necessary for a cloud-hosted LLM, but the implications are:

1. **`.env` files with real secrets** are sent to xAI servers
2. **Config files with credentials** are transmitted in full
3. **No local filtering** of sensitive content occurs before transmission
4. **No warning** is shown when files containing secret-like patterns are about to be sent

### Test Results

Using our canary repository with planted fake secrets:

```
Markers detected in outbound traffic: 5/7
  [!] FOUND: AKIAIOSFODNN7EXAMPLE
  [!] FOUND: sk_test_FAKEFAKEFAKEFAKEFAKE
  [!] FOUND: sk-proj-FAKE-openai-key-1234567890
  [!] FOUND: super_secret_database_password_12345
  [!] FOUND: production-api-key-do-not-share

Not found (file not read by grok during test):
  [ ] NEVER_READ_PROBE_ae4f92c1
  [ ] ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

The "never read" probe was not detected, confirming grok does not proactively scan all files. However, any file it does read for context is transmitted in full.

---

## Finding 4: Heavy Dual-Tracked Telemetry

### Volume

A single prompt interaction generates **14+ telemetry events** sent to two separate destinations:

1. **Mixpanel** (api.mixpanel.com) - Behavioral analytics
2. **grok.com** event endpoints - First-party telemetry

### Event Types Observed

```
  4x  conversation_turn_start / conversation_turn_end
  2x  model_request / model_response  
  2x  tool_use_start / tool_use_end
  2x  file_read
  1x  session_heartbeat
  1x  ide_context_update
  2x  performance_metric
```

### Properties Collected

Mixpanel events include (redacting actual values):
- `distinct_id`: <redacted user identifier>
- `$device_id`: <redacted device identifier>
- `session_id`: <redacted session identifier>
- `project_path`: Filesystem path of the working directory
- `file_count`: Number of files in the project
- `model`: Which model was used
- `token_count`: Tokens sent/received
- `duration_ms`: Time taken
- `tool_name`: Which tools were invoked
- `os`, `platform`, `version`: System information

---

## Finding 5: OTEL Protobuf Traces (Operational Data)

### What OTEL Traces Contain

The OpenTelemetry traces sent to `/v1/traces` contain **operational telemetry only** - no source code or file contents:

- Span names (e.g., `model_call`, `tool_execution`, `file_read`)
- Timing data (start/end timestamps, duration)
- Status codes and error flags
- Resource attributes (service name, version, instance ID)
- The `trace_upload_skipped` reason field (when upload is disabled)

### What They Do NOT Contain

- File contents
- Source code
- Secret values
- Full prompts or responses (these go via the LLM endpoint instead)

---

## Finding 6: Zero Data Retention (ZDR) as a Second Gate

### How ZDR Interacts with Uploads

Team-level ZDR provides a second gate for the upload feature:

```
Upload decision logic (inferred from behavior):
  if disable_codebase_upload == true:
    skip upload (reason: "disabled_by_server")
  elif team.zero_data_retention == true:
    skip upload (reason: "zdr_enabled")  
  else:
    proceed with upload
```

This means even if xAI flips `disable_codebase_upload` to false, teams with ZDR enabled would still not have repos uploaded. However:
- Individual/free users do not have ZDR
- ZDR is a team/enterprise feature
- The ZDR gate is also server-controlled

---

## Architecture Summary

```
+----------------------------------------------------------+
|                    Grok CLI Binary                         |
+----------------------------------------------------------+
|                                                           |
|  +-------------+  +-------------+  +------------------+  |
|  | LLM Context |  |  Telemetry  |  |  Upload Engine   |  |
|  |  (plaintext |  |  (Mixpanel  |  |  (git bundle     |  |
|  |   file body)|  |  + grok.com)|  |   + storage)     |  |
|  +------+------+  +------+------+  +--------+---------+  |
|         |                 |                  |            |
+---------+-----------------+------------------+------------+
          |                 |                  |
          v                 v                  v
   /v1/responses     api.mixpanel.com    /v1/storage
   (AI queries)      grok.com/events     (DISABLED by
                                          server flag)
```

---

## Finding 7: Local Logs Record Upload Decisions — But Cannot Prove History

Grok logs every upload decision to `~/.grok/logs/unified.jsonl` under the message `trace.upload.decision`. The correct command to check retroactively is:

```bash
# Correct (what actually works):
grep "trace.upload.decision" ~/.grok/logs/unified.jsonl | grep '"uploads_enabled":true'

# Incorrect (circulating online, wrong message key):
# grep "repo_state.upload" ~/.grok/logs/unified.jsonl
```

Each entry records the full decision chain:

```json
{
  "msg": "trace.upload.decision",
  "ctx": {
    "trace_upload": false,
    "trace_upload_source": "remote",
    "in_remote_trace_upload_enabled": false,
    "has_remote_settings": true,
    "uploads_enabled": false,
    "upload_reason": "feature_off",
    "data_collection_disabled": false,
    "turn_number": 42
  }
}
```

### Limitations

- **Log retention is limited.** Our logs only covered 2 days. If grok was used before the log window, earlier upload decisions are lost.
- **Absence of evidence ≠ evidence of absence.** If the upload feature was active before your earliest log entry, you cannot rule out prior uploads.
- **The `data_collection_disabled` field** shows as `false` even when `GROK_WORKSPACE_DATA_COLLECTION_DISABLED=1` is set — further confirming the env var is non-functional at the upload decision layer.

### What to look for

| `uploads_enabled` | `upload_reason` | Meaning |
|---|---|---|
| `false` | `feature_off` | Server flag blocked it — you're fine |
| `false` | `zdr_team` | ZDR blocked it — you're fine |
| `true` | *(any)* | **Your repo was uploaded** |

---

## Comparison with Prior Research

### cereblab/grok-data-theft (Historical Upload Proof)

The [cereblab repository](https://github.com/cereblab/grok-data-theft) demonstrated that:
- Grok historically **did** upload repository data
- They captured actual upload traffic proving the behavior existed
- xAI subsequently disabled it (via the server-side flag)

### This Project (Ongoing Monitoring + Flag Testing)

This project provides:
- **Ongoing monitoring** tools to detect if uploads are re-enabled
- **Flag flip testing** to understand the multi-gate architecture
- **Telemetry analysis** showing the scope of data collection beyond uploads
- **Secret detection** proving plaintext transmission of sensitive files
- **Environment variable testing** proving `GROK_WORKSPACE_DATA_COLLECTION_DISABLED` is non-functional

---

## Recommendations

1. **Do not store secrets in repositories where grok operates** - any file read as context is sent in plaintext
2. **Use `.grokignore`** (if available) to exclude sensitive files
3. **Monitor with this toolkit** - run periodic checks to detect if upload behavior changes
4. **Enterprise users**: Ensure ZDR is enabled at the team level for an additional upload gate
5. **Do not rely on `GROK_WORKSPACE_DATA_COLLECTION_DISABLED`** - it has no measurable effect
6. **Consider `/privacy opt-out`** - while it only affects retention (not transmission), it reduces the window of server-side data exposure

---

## Ethics and Scope

This investigation was conducted using:
- Standard network interception tools (mitmproxy) on our own machines
- Analysis of traffic from our own grok installation
- Fake/canary secrets only (no real credentials were exposed)
- No exploitation of vulnerabilities or unauthorized access
- No modification of xAI's servers or infrastructure

The goal is transparency about what a developer tool does with the code it accesses.

---

*Last updated: 2026-07-13*
