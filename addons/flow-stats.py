"""Write request-only mitmproxy flow statistics for the test runner.

Use with ``mitmdump -nr capture.flow -s addons/flow-stats.py``.  Flow archive
size is not a network-volume metric: it includes responses and mitmproxy
metadata.  This addon records only request bodies and marker hits in requests.
"""

import json
import os
from collections import Counter

from mitmproxy import ctx, http


UPLOAD_PATH_PARTS = ("/v1/storage", "/upload", "/bundle", "/codebase")
UPLOAD_CONTENT_TYPES = ("octet-stream", "tar", "gzip", "x-git", "x-bundle")


class FlowStats:
    def __init__(self):
        self.categories = Counter()
        self.hosts = Counter()
        self.markers = []
        self.marker_hits = []
        self.upload_candidates = []
        self.request_count = 0
        self.request_bytes = 0

    def load(self, loader):
        loader.add_option("stats_output", str, "", "Write JSON statistics to this path")
        loader.add_option("stats_markers_file", str, "", "Optional marker file")

    def configure(self, updates):
        markers_file = ctx.options.stats_markers_file
        self.markers = []
        if markers_file and os.path.isfile(markers_file):
            with open(markers_file, encoding="utf-8") as handle:
                self.markers = [
                    line.strip()
                    for line in handle
                    if line.strip() and not line.lstrip().startswith("#")
                ]

    @staticmethod
    def classify(flow: http.HTTPFlow) -> str:
        url = flow.request.pretty_url.lower()
        content_type = flow.request.headers.get("content-type", "").lower()
        method = flow.request.method.upper()
        if method in ("POST", "PUT", "PATCH") and any(
            part in url for part in UPLOAD_PATH_PARTS
        ):
            return "UPLOAD"
        if method in ("POST", "PUT", "PATCH") and any(
            part in content_type for part in UPLOAD_CONTENT_TYPES
        ):
            return "UPLOAD"
        if "/v1/traces" in url or "/v1/logs" in url or "application/x-protobuf" in content_type:
            return "TRACES"
        if "mixpanel" in flow.request.pretty_host.lower() or any(part in url for part in ("/event", "/track", "/telemetry", "/analytics")):
            return "TELEMETRY"
        if "/v1/responses" in url or "/completions" in url or "/chat" in url:
            return "LLM_CALL"
        return "OTHER"

    def request(self, flow: http.HTTPFlow) -> None:
        content = flow.request.content or b""
        self.request_count += 1
        self.request_bytes += len(content)
        category = self.classify(flow)
        self.categories[category] += 1
        self.hosts[flow.request.pretty_host] += 1
        if category == "UPLOAD":
            self.upload_candidates.append(
                {
                    "host": flow.request.pretty_host,
                    "method": flow.request.method,
                    "path": flow.request.path,
                    "content_type": flow.request.headers.get("content-type", ""),
                    "body_bytes": len(content),
                }
            )
        if not self.markers or not content:
            return

        text = content.decode("utf-8", errors="replace")
        for marker in self.markers:
            if marker in text:
                self.marker_hits.append(
                    {
                        "marker": marker,
                        "host": flow.request.pretty_host,
                        "method": flow.request.method,
                        "path": flow.request.path,
                    }
                )

    def done(self):
        output = ctx.options.stats_output
        if not output:
            return
        report = {
            "request_count": self.request_count,
            "request_bytes": self.request_bytes,
            "categories": dict(sorted(self.categories.items())),
            "hosts": dict(sorted(self.hosts.items())),
            "request_marker_hits": self.marker_hits,
            "upload_candidates": self.upload_candidates,
        }
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")


addons = [FlowStats()]
