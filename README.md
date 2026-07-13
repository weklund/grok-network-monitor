# Grok Network Monitor

> **Confirmed on Grok Build v0.2.99** (`grok-0.2.99-macos-aarch64`, July 13 2026). Findings are version-specific — behavior may change in future releases.

A network monitoring harness for investigating what data xAI's "Grok Build" CLI sends to its servers. Uses mitmproxy to intercept, classify, and analyze all network traffic from the `grok` command.

## Why This Matters

xAI's Grok Build CLI has **live infrastructure to upload entire git repositories** as git bundles to xAI servers. This capability is currently disabled by a server-side flag (`disable_codebase_upload`) that xAI can flip remotely at any time -- no client update required, no user consent needed.

Additionally:
- The `GROK_WORKSPACE_DATA_COLLECTION_DISABLED=1` environment variable **does nothing** (traffic is identical with/without it)
- `/privacy opt-out` controls **retention**, not **transmission**
- Any file grok reads is sent in **plaintext** as LLM context (including `.env` files with secrets)
- Every prompt generates **14+ telemetry events** to Mixpanel and grok.com

This toolkit lets you verify these findings yourself and monitor for changes.

## Findings (as of v0.2.99)

| # | Finding | Status |
|---|---------|--------|
| 1 | Git bundle upload infrastructure exists in binary | Confirmed |
| 2 | Upload disabled by server-side `disable_codebase_upload` flag | Confirmed |
| 3 | xAI can re-enable uploads remotely (no client update needed) | Confirmed |
| 4 | `GROK_WORKSPACE_DATA_COLLECTION_DISABLED=1` has no effect | Confirmed |
| 5 | `/privacy opt-out` controls retention, not transmission | Confirmed |
| 6 | Files read by grok sent as plaintext to xAI (including secrets) | Confirmed |
| 7 | 14+ telemetry events per prompt (Mixpanel + grok.com, dual-tracked) | Confirmed |
| 8 | ZDR (team-level) provides a second upload gate | Confirmed |
| 9 | OTEL protobuf traces contain operational data only (no code) | Confirmed |
| 10 | Local logs record upload decisions but have limited retention | Confirmed |

See [FINDINGS.md](FINDINGS.md) for detailed write-ups, methodology, and evidence for each finding.

## Recommendations (as of v0.2.99)

| # | Action | Why |
|---|--------|-----|
| 1 | **Do not store secrets in repos where grok operates** | Any file grok reads is sent in plaintext to xAI servers |
| 2 | **Use `.gitignore` for all sensitive files** | Gitignored files are excluded from the git bundle upload ([proven by cereblab's captured bundles](https://github.com/cereblab/grok-build-exfil-repro) — the only protection that works) |
| 3 | **Run `./detect-exfil.sh` to check your upload history** | Shows whether your repos were ever uploaded during the log retention window |
| 4 | **Block `api.mixpanel.com` in /etc/hosts** | Disables analytics tracking without breaking grok functionality |
| 5 | **Do not rely on `GROK_WORKSPACE_DATA_COLLECTION_DISABLED=1`** | Proven to have zero effect on network behavior |
| 6 | **Do not rely on `/privacy opt-out` to prevent data transmission** | It only controls retention/training policy, not what leaves your machine |
| 7 | **Enterprise users: ensure ZDR is enabled at the team level** | Provides a second gate against uploads even if the server flag is flipped |
| 8 | **Monitor periodically with this toolkit** | The server flag can be changed remotely at any time — run checks after updates |

### Blocking telemetry (optional, doesn't break grok)

```bash
# Block Mixpanel analytics
echo "127.0.0.1 api.mixpanel.com" | sudo tee -a /etc/hosts
```

## Open Questions for xAI

These questions remain unanswered as of this writing (2026-07-13):

1. **Scope and retention of already-uploaded data.** For users who ran Grok Build before `disable_codebase_upload` was set to `true`: what repos were uploaded, how long is that data retained, and what is the deletion timeline?

2. **Why is the upload controlled by a server-side flag rather than client-side opt-in?** The current architecture allows xAI to re-enable uploads at any time without user consent, client update, or notification. Will this be moved to a user-controlled setting?

3. **What does `GROK_WORKSPACE_DATA_COLLECTION_DISABLED=1` actually do?** It has zero measurable effect on network behavior. Is it dead code, or does it gate something not triggered in our tests?

4. **Why does `/privacy opt-out` not disable telemetry?** Mixpanel tracking and grok.com analytics events fire identically regardless of privacy opt-out status.

5. **Is ZDR protection available to all users?** The `zdr_team` gate blocked uploads even when we forced `disable_codebase_upload: false`. Is ZDR available to free-tier users, or only SuperGrok/enterprise?

6. **Will there be a public advisory?** As of this writing, there has been no official disclosure of scope, no notification to affected users, and no documented retention/deletion policy for uploaded repositories.

7. **Why are permission-deny rules independent of the upload system?** A user who explicitly denies read access to a file should reasonably expect that file not to leave their machine. The git bundle upload ignores these rules entirely.

8. **What is the log retention policy for `unified.jsonl`?** Users cannot verify whether their repos were uploaded if the log has been rotated. Is there a server-side record users can request?

---

## Prerequisites

- **macOS** or **Linux**
- **mitmproxy** (installed by `setup.sh`)
- **Grok CLI** installed (`~/.grok/bin/grok` or in PATH)
- **Python 3.8+** (for mitmproxy addons)
- **bash** (all scripts use bash)

## Quick Start

```bash
# 1. Install dependencies and configure CA trust
chmod +x setup.sh && ./setup.sh

# 2. Run all 5 monitoring tests. This creates/recreates the fake-secret
#    canary repository and marker file when they are missing.
./scripts/run-tests.sh
```

## Was My Code Already Uploaded?

Before running the full test suite, you can check immediately whether grok has uploaded any of your repositories in the past:

```bash
# Quick check (no setup required):
./detect-exfil.sh

# Or manually check the upload decision log:
grep "trace.upload.decision" ~/.grok/logs/unified.jsonl | grep '"uploads_enabled":true'
```

If the grep returns **nothing**, uploads did not occur during the logged period. If it returns entries, your repos were uploaded to xAI's servers.

**Important caveat:** Grok's logs have limited retention. If you used grok before your earliest log entry, you cannot rule out prior uploads. The `detect-exfil.sh` script will show your log's date range and warn you about this gap.

| `uploads_enabled` | `upload_reason` | What it means |
|---|---|---|
| `false` | `feature_off` | Server flag blocked upload — your code stayed local |
| `false` | `zdr_team` | Zero Data Retention blocked upload — your code stayed local |
| `true` | *(any)* | **Your repository was uploaded to xAI servers** |

> **Note:** The command `grep "repo_state.upload"` circulating online uses the wrong message key and will return nothing. The correct key is `trace.upload.decision`.

## Repository Structure

```
grok-network-monitor/
├── README.md              # This file
├── LICENSE                # MIT
├── FINDINGS.md            # Detailed investigation findings
├── setup.sh              # Install deps + CA trust instructions
├── scripts/
│   ├── make-canary.sh    # Generate honeypot repo with fake secrets
│   ├── run-tests.sh      # Run all 5 tests sequentially
│   └── analyze.sh        # Post-capture traffic analysis
├── addons/
│   ├── classify.py       # Traffic classifier (LLM/TELEMETRY/UPLOAD/etc)
│   ├── capture-all.py    # Full body capture + secret detection
│   ├── flip-upload.py    # Rewrites server flags to test upload behavior
│   └── dump-telemetry.py # Decodes Mixpanel base64 + grok.com events
│   └── flow-stats.py     # Request-only metrics and marker detection
├── monitor.sh            # Quick interactive monitoring (no root needed)
└── detect-exfil.sh       # One-shot local artifact scan (no proxy)
```

## What Each Test Does

### Test 1: Protobuf Trace Decode
Captures OTEL (OpenTelemetry) traces sent to `/v1/traces` and extracts readable strings. Reveals operational span data, timing, and the `trace_upload_skipped` reason field.

### Test 2: Server Flag Flip
Rewrites the `/v1/settings` response to set `disable_codebase_upload: false` and `trace_upload_enabled: true`. Monitors whether the client attempts to upload repository data when the server-side gate is removed.

### Test 3: Environment Variable Comparison
Runs grok twice with the same prompt -- once normally, once with `GROK_WORKSPACE_DATA_COLLECTION_DISABLED=1` -- and compares outbound request counts and request-body bytes. It records an observation; repeated runs are needed before drawing a conclusion because service and session state can vary.

### Test 4: Secret Detection
Runs grok on the canary repository (which contains planted fake secrets) and searches outbound request bodies only for marker strings. A match demonstrates that the requested canary content was transmitted in plaintext.

### Test 5: Large Repo Egress
Generates a 50+ file repository and reports outbound request-body bytes during a single interaction. It excludes response data and mitmproxy archive metadata.

## Expected Output

```
TEST 4: Secret Detection in Outbound Request Bodies
  Goal: Run grok on canary repo, grep for marker strings

    Running grok on canary repo (asking about code)...
    Searching outbound request bodies for marker strings...
    [!] FOUND IN REQUEST: AKIAIOSFODNN7EXAMPLE
    [!] FOUND IN REQUEST: sk_test_FAKEFAKEFAKEFAKEFAKE
    [!] FOUND IN REQUEST: sk-proj-FAKE-openai-key-1234567890
    [!] FOUND IN REQUEST: super_secret_database_password_12345
    [!] FOUND IN REQUEST: production-api-key-do-not-share

    [RESULT] 6 marker strings detected in outbound request bodies
```

## Standalone Tools

### `monitor.sh` - Interactive Monitoring (No Root)

```bash
./monitor.sh lsof     # Show current grok network connections
./monitor.sh poll     # Poll connections for 60 seconds
./monitor.sh live     # Start mitmproxy with live classification
./monitor.sh quick    # Quick 30-second capture
```

### `detect-exfil.sh` - Local Artifact Scan (No Proxy)

Scans `~/.grok/` for upload queues, session transcripts, project references, telemetry config, and current network connections. Requires no proxy setup.

```bash
./detect-exfil.sh
```

## Customizing Secret Detection

Edit `captures/markers.txt` to add your own canary strings:

```
# One marker per line (comments start with #)
MY_CUSTOM_SECRET_123
another-canary-value
PROBE_STRING_abc123
```

These are searched for in all captured outbound request bodies.

## Comparison with cereblab/grok-data-theft

[cereblab's repository](https://github.com/cereblab/grok-data-theft) proved that Grok historically **did** upload repository data and captured the actual upload traffic. xAI subsequently disabled it via the server-side flag.

This project complements their work by providing:
- **Ongoing monitoring** -- detect if uploads are re-enabled
- **Flag flip testing** -- understand the multi-gate architecture
- **Telemetry analysis** -- quantify data collection beyond uploads
- **Secret detection** -- prove plaintext transmission of file contents
- **Environment variable testing** -- prove `GROK_WORKSPACE_DATA_COLLECTION_DISABLED` is non-functional
- **Reproducible test suite** -- anyone can verify these findings

## Ethics and Scope

This toolkit is designed for **legitimate security research** on your own installation:

- All traffic analysis is performed on your own machine using standard tools
- Only fake/canary secrets are used in testing (no real credentials exposed)
- No exploitation of vulnerabilities or unauthorized access
- No modification of xAI's servers or infrastructure
- No reverse engineering beyond network traffic observation

The goal is transparency about what developer tools do with the code they access.

## Contributing

Contributions welcome. Areas of interest:
- Additional telemetry decode patterns
- Windows/WSL support
- Integration with other network analysis tools
- Documentation of new findings or behavior changes

## License

MIT. See [LICENSE](LICENSE).
