"""
flip-upload.py - Rewrites /v1/settings responses to enable codebase upload

This addon intercepts the settings response from xAI's server and flips
the `disable_codebase_upload` flag to False (enabling uploads) and
`trace_upload_enabled` to True. This tests whether the client will
attempt to upload repository data when the server-side gate is removed.

IMPORTANT: This is a research tool. The upload infrastructure exists in
the grok binary but is currently disabled server-side. This addon tests
what happens when that gate is removed.

What it does:
  1. Intercepts responses from settings/config endpoints
  2. Rewrites disable_codebase_upload: true -> false
  3. Rewrites trace_upload_enabled: false -> true (if present)
  4. Logs all original vs modified values
  5. Monitors for any subsequent upload attempts (binary payloads,
     /v1/storage requests, git bundle content)

Usage:
    mitmdump -s addons/flip-upload.py
"""

import json
import logging
from datetime import datetime
from mitmproxy import http, ctx


class UploadFlagFlipper:
    """Rewrites server settings to test upload behavior."""

    def __init__(self):
        self.settings_intercepted = 0
        self.flags_flipped: list[dict] = []
        self.upload_attempts: list[dict] = []
        self.binary_payloads: list[dict] = []

    def response(self, flow: http.HTTPFlow) -> None:
        """Intercept and modify settings responses."""
        url = flow.request.pretty_url.lower()

        # Only intercept settings/config endpoints
        is_settings = any(
            x in url for x in ["/v1/settings", "/settings", "/config"]
        )

        if not is_settings:
            # Monitor for upload attempts in requests instead
            self._monitor_uploads(flow)
            return

        content_type = flow.response.headers.get("content-type", "")
        if "json" not in content_type:
            return

        # Try to parse and modify the response
        try:
            body = flow.response.content.decode("utf-8")
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        self.settings_intercepted += 1
        modified = False
        flip_record = {
            "timestamp": datetime.now().isoformat(),
            "url": flow.request.pretty_url,
            "original_values": {},
            "new_values": {},
        }

        # Flip disable_codebase_upload
        original_disable = self._find_and_flip(
            data, "disable_codebase_upload", target_value=False
        )
        if original_disable is not None:
            flip_record["original_values"]["disable_codebase_upload"] = original_disable
            flip_record["new_values"]["disable_codebase_upload"] = False
            modified = True
            ctx.log.warn(
                f"[FLIP] disable_codebase_upload: {original_disable} -> False"
            )

        # Flip trace_upload_enabled
        original_trace = self._find_and_flip(
            data, "trace_upload_enabled", target_value=True
        )
        if original_trace is not None:
            flip_record["original_values"]["trace_upload_enabled"] = original_trace
            flip_record["new_values"]["trace_upload_enabled"] = True
            modified = True
            ctx.log.warn(
                f"[FLIP] trace_upload_enabled: {original_trace} -> True"
            )

        # Also look for and flip any upload-related flags
        for key in ["enable_codebase_upload", "allow_upload", "upload_enabled"]:
            original = self._find_and_flip(data, key, target_value=True)
            if original is not None:
                flip_record["original_values"][key] = original
                flip_record["new_values"][key] = True
                modified = True
                ctx.log.warn(f"[FLIP] {key}: {original} -> True")

        if modified:
            # Write modified response back
            new_body = json.dumps(data)
            flow.response.content = new_body.encode("utf-8")
            flow.response.headers["content-length"] = str(len(new_body))
            self.flags_flipped.append(flip_record)
            ctx.log.warn(
                f"[FLIP] Settings response rewritten "
                f"({len(flip_record['original_values'])} flags modified)"
            )
        else:
            ctx.log.info(
                f"[FLIP] Settings response inspected but no upload flags found"
            )
            ctx.log.info(f"       Keys present: {list(data.keys()) if isinstance(data, dict) else 'non-dict'}")

    def _find_and_flip(self, data, key: str, target_value) -> object:
        """
        Recursively search for a key in nested dict and set it to target_value.
        Returns the original value if found and changed, None otherwise.
        """
        if isinstance(data, dict):
            if key in data:
                original = data[key]
                if original != target_value:
                    data[key] = target_value
                    return original
            # Search nested dicts
            for v in data.values():
                result = self._find_and_flip(v, key, target_value)
                if result is not None:
                    return result
        elif isinstance(data, list):
            for item in data:
                result = self._find_and_flip(item, key, target_value)
                if result is not None:
                    return result
        return None

    def _monitor_uploads(self, flow: http.HTTPFlow) -> None:
        """Monitor for any upload attempts after flag flip."""
        url = flow.request.pretty_url.lower()
        content_type = flow.request.headers.get("content-type", "").lower()
        method = flow.request.method
        payload_size = len(flow.request.content) if flow.request.content else 0

        # Check for upload-indicating URLs
        is_upload_url = any(
            x in url for x in ["/v1/storage", "/upload", "/bundle", "/codebase"]
        )

        # Check for binary content types
        is_binary = any(
            x in content_type
            for x in ["octet-stream", "tar", "gzip", "x-git", "x-bundle"]
        )

        # Check for large POST/PUT payloads (potential bulk upload)
        is_large_post = (
            method in ("POST", "PUT") and payload_size > 100 * 1024
        )  # >100KB

        if is_upload_url:
            record = {
                "timestamp": datetime.now().isoformat(),
                "type": "UPLOAD_URL",
                "method": method,
                "url": flow.request.pretty_url,
                "content_type": content_type,
                "payload_size": payload_size,
            }
            self.upload_attempts.append(record)
            ctx.log.error(
                f"[!!!] UPLOAD ATTEMPT DETECTED: {method} {flow.request.pretty_url} "
                f"({payload_size:,} bytes)"
            )

        if is_binary:
            record = {
                "timestamp": datetime.now().isoformat(),
                "type": "BINARY_PAYLOAD",
                "method": method,
                "url": flow.request.pretty_url,
                "content_type": content_type,
                "payload_size": payload_size,
            }
            self.binary_payloads.append(record)
            ctx.log.error(
                f"[!!!] BINARY PAYLOAD: {method} {flow.request.pretty_url} "
                f"Content-Type: {content_type} ({payload_size:,} bytes)"
            )

        if is_large_post and not is_upload_url:
            ctx.log.warn(
                f"[!] Large {method}: {flow.request.pretty_url} "
                f"({payload_size:,} bytes) - potential bulk transfer"
            )

    def done(self):
        """Print summary on shutdown."""
        ctx.log.info("")
        ctx.log.info("=" * 60)
        ctx.log.info("UPLOAD FLAG FLIP SUMMARY")
        ctx.log.info("=" * 60)
        ctx.log.info(f"  Settings responses intercepted: {self.settings_intercepted}")
        ctx.log.info(f"  Flags flipped: {len(self.flags_flipped)}")
        ctx.log.info(f"  Upload attempts detected: {len(self.upload_attempts)}")
        ctx.log.info(f"  Binary payloads detected: {len(self.binary_payloads)}")
        ctx.log.info("")

        if self.flags_flipped:
            ctx.log.info("  Modifications made:")
            for flip in self.flags_flipped:
                for key, orig in flip["original_values"].items():
                    new = flip["new_values"][key]
                    ctx.log.info(f"    {key}: {orig} -> {new}")
            ctx.log.info("")

        if self.upload_attempts:
            ctx.log.error("  UPLOAD ATTEMPTS:")
            for attempt in self.upload_attempts:
                ctx.log.error(
                    f"    [{attempt['type']}] {attempt['method']} "
                    f"{attempt['url']} ({attempt['payload_size']:,} bytes)"
                )
        elif self.flags_flipped:
            ctx.log.info(
                "  No upload attempts observed after flag flip."
            )
            ctx.log.info(
                "  (Client may require additional triggers or the upload"
            )
            ctx.log.info(
                "   path may need a ZDR=false gate as well)"
            )

        ctx.log.info("=" * 60)


addons = [UploadFlagFlipper()]
