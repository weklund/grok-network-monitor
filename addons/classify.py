"""
classify.py - mitmproxy addon that classifies Grok network traffic

Categories:
  LLM_CALL    - Requests to the responses/completions endpoint (actual AI queries)
  TELEMETRY   - Mixpanel events and grok.com analytics
  TRACES      - OpenTelemetry protobuf traces to /v1/traces
  UPLOAD      - Any codebase upload attempts (/v1/storage, octet-stream, tar/gzip)
  SESSION     - Session signals, turn deltas, heartbeats
  OTHER       - Unclassified traffic

Alerts on large code payloads (>50KB) that might indicate bulk data transfer.
"""

import logging
from mitmproxy import http, ctx

# Threshold for "large payload" alert (bytes)
LARGE_PAYLOAD_THRESHOLD = 50 * 1024  # 50KB


class GrokTrafficClassifier:
    """Classifies and logs all Grok CLI network requests."""

    def __init__(self):
        self.counts = {
            "LLM_CALL": 0,
            "TELEMETRY": 0,
            "TRACES": 0,
            "UPLOAD": 0,
            "SESSION": 0,
            "OTHER": 0,
        }
        self.total_bytes_out = 0
        self.alerts = []

    def classify_request(self, flow: http.HTTPFlow) -> str:
        """Determine the category of a request based on URL and headers."""
        url = flow.request.pretty_url.lower()
        content_type = flow.request.headers.get("content-type", "").lower()
        method = flow.request.method

        # UPLOAD: Binary uploads, storage endpoints, git bundles
        if any(
            x in url
            for x in ["/v1/storage", "/upload", "/bundle", "/codebase"]
        ):
            return "UPLOAD"
        if any(
            x in content_type
            for x in ["octet-stream", "tar", "gzip", "x-git"]
        ):
            return "UPLOAD"

        # TRACES: OpenTelemetry protobuf traces
        if "/v1/traces" in url or "/v1/logs" in url:
            return "TRACES"
        if "application/x-protobuf" in content_type:
            return "TRACES"

        # TELEMETRY: Mixpanel and analytics endpoints
        if "mixpanel" in url:
            return "TELEMETRY"
        if any(
            x in url
            for x in ["/track", "/engage", "/events", "/telemetry", "/analytics"]
        ):
            return "TELEMETRY"

        # LLM_CALL: AI model responses endpoint
        if any(
            x in url
            for x in ["/v1/responses", "/v1/completions", "/v1/chat", "/api/rpc/AnthropicHomepage"]
        ):
            return "LLM_CALL"

        # SESSION: Signals, deltas, session management
        if any(
            x in url
            for x in ["/signals", "/turn-delta", "/heartbeat", "/session", "/v1/settings"]
        ):
            return "SESSION"

        return "OTHER"

    def request(self, flow: http.HTTPFlow) -> None:
        """Called for each request passing through the proxy."""
        category = self.classify_request(flow)
        self.counts[category] += 1

        # Calculate payload size
        payload_size = len(flow.request.content) if flow.request.content else 0
        self.total_bytes_out += payload_size

        # Format log line
        url_short = flow.request.pretty_url
        if len(url_short) > 80:
            url_short = url_short[:77] + "..."

        log_line = (
            f"[{category:10}] {flow.request.method:4} "
            f"{url_short} ({payload_size:,} bytes)"
        )

        # Alert on large payloads
        if payload_size > LARGE_PAYLOAD_THRESHOLD:
            alert_msg = (
                f"LARGE PAYLOAD ALERT: {payload_size:,} bytes to "
                f"{flow.request.pretty_host}{flow.request.path}"
            )
            self.alerts.append(alert_msg)
            ctx.log.warn(f"[!!!] {alert_msg}")
            log_line += " [LARGE PAYLOAD!]"

        # Alert on any upload category
        if category == "UPLOAD":
            alert_msg = (
                f"UPLOAD DETECTED: {flow.request.method} "
                f"{flow.request.pretty_host}{flow.request.path} "
                f"({payload_size:,} bytes)"
            )
            self.alerts.append(alert_msg)
            ctx.log.warn(f"[!!!] {alert_msg}")

        ctx.log.info(log_line)

    def done(self):
        """Called when mitmproxy shuts down. Print summary."""
        ctx.log.info("")
        ctx.log.info("=" * 60)
        ctx.log.info("TRAFFIC CLASSIFICATION SUMMARY")
        ctx.log.info("=" * 60)
        ctx.log.info(f"  Total outbound bytes: {self.total_bytes_out:,}")
        ctx.log.info("")
        for category, count in sorted(self.counts.items()):
            if count > 0:
                ctx.log.info(f"  {category:12}: {count} requests")
        ctx.log.info("")
        if self.alerts:
            ctx.log.info(f"  ALERTS ({len(self.alerts)}):")
            for alert in self.alerts:
                ctx.log.info(f"    - {alert}")
        else:
            ctx.log.info("  No alerts triggered.")
        ctx.log.info("=" * 60)


addons = [GrokTrafficClassifier()]
