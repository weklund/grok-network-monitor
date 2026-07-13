"""
capture-all.py - Full body capture with configurable secret detection

This addon captures complete request/response bodies and searches for
user-defined marker strings (secrets, canary values) in outbound traffic.

Markers are loaded from a markers.txt file (one string per line).
Lines starting with # are treated as comments.

Usage:
    mitmdump -s addons/capture-all.py --set markers_file=captures/markers.txt

If markers_file is not set, it defaults to ./captures/markers.txt relative
to the current working directory.
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional
from mitmproxy import http, ctx


class FullBodyCapture:
    """Captures all traffic and detects secrets in outbound payloads."""

    def __init__(self):
        self.markers: list[str] = []
        self.detections: list[dict] = []
        self.request_count = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.capture_log: list[dict] = []

    def load(self, loader):
        """Register addon options."""
        loader.add_option(
            name="markers_file",
            typespec=str,
            default="captures/markers.txt",
            help="Path to markers file (one secret per line)",
        )

    def configure(self, updates):
        """Load markers when configuration changes."""
        markers_path = ctx.options.markers_file
        self._load_markers(markers_path)

    def _load_markers(self, path: str) -> None:
        """Load marker strings from file."""
        self.markers = []

        if not os.path.isfile(path):
            ctx.log.warn(f"[capture-all] Markers file not found: {path}")
            ctx.log.warn("[capture-all] Secret detection disabled")
            return

        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                self.markers.append(line)

        ctx.log.info(
            f"[capture-all] Loaded {len(self.markers)} markers from {path}"
        )

    def _check_for_markers(
        self, content: bytes, flow: http.HTTPFlow, direction: str
    ) -> None:
        """Search content for marker strings."""
        if not self.markers or not content:
            return

        # Decode content for string matching
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            text = str(content)

        for marker in self.markers:
            if marker in text:
                detection = {
                    "timestamp": datetime.now().isoformat(),
                    "direction": direction,
                    "marker": marker,
                    "host": flow.request.pretty_host,
                    "path": flow.request.path,
                    "method": flow.request.method,
                    "content_length": len(content),
                }
                self.detections.append(detection)

                # Log prominently
                ctx.log.warn(
                    f"[!!!] SECRET DETECTED in {direction}: "
                    f"'{marker[:30]}...' -> "
                    f"{flow.request.pretty_host}{flow.request.path}"
                )

    def request(self, flow: http.HTTPFlow) -> None:
        """Capture and analyze outbound requests."""
        self.request_count += 1
        content = flow.request.content or b""
        payload_size = len(content)
        self.total_bytes_sent += payload_size

        # Log the request
        entry = {
            "timestamp": datetime.now().isoformat(),
            "direction": "REQUEST",
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "path": flow.request.path,
            "content_type": flow.request.headers.get("content-type", ""),
            "content_length": payload_size,
            "headers": dict(flow.request.headers),
        }
        self.capture_log.append(entry)

        ctx.log.info(
            f"[REQ #{self.request_count:3}] {flow.request.method:4} "
            f"{flow.request.pretty_url} ({payload_size:,} bytes)"
        )

        # Check outbound content for secrets
        self._check_for_markers(content, flow, "REQUEST")

    def response(self, flow: http.HTTPFlow) -> None:
        """Capture inbound responses."""
        content = flow.response.content or b""
        payload_size = len(content)
        self.total_bytes_received += payload_size

        entry = {
            "timestamp": datetime.now().isoformat(),
            "direction": "RESPONSE",
            "status": flow.response.status_code,
            "url": flow.request.pretty_url,
            "content_type": flow.response.headers.get("content-type", ""),
            "content_length": payload_size,
        }
        self.capture_log.append(entry)

        # Also check responses (for reflected secrets)
        self._check_for_markers(content, flow, "RESPONSE")

    def done(self):
        """Print summary when proxy shuts down."""
        ctx.log.info("")
        ctx.log.info("=" * 60)
        ctx.log.info("CAPTURE SUMMARY")
        ctx.log.info("=" * 60)
        ctx.log.info(f"  Total requests:      {self.request_count}")
        ctx.log.info(f"  Total bytes sent:    {self.total_bytes_sent:,}")
        ctx.log.info(f"  Total bytes received:{self.total_bytes_received:,}")
        ctx.log.info(f"  Markers loaded:      {len(self.markers)}")
        ctx.log.info(f"  Secrets detected:    {len(self.detections)}")
        ctx.log.info("")

        if self.detections:
            ctx.log.warn("  SECRET DETECTIONS:")
            for det in self.detections:
                ctx.log.warn(
                    f"    [{det['direction']}] '{det['marker'][:40]}' "
                    f"-> {det['host']}{det['path']}"
                )
        ctx.log.info("=" * 60)


addons = [FullBodyCapture()]
