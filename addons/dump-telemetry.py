"""
dump-telemetry.py - Decode and display Grok telemetry payloads

Grok sends telemetry to two destinations:
  1. Mixpanel (api.mixpanel.com) - Base64 encoded JSON payloads
  2. grok.com event endpoints - JSON event bodies

This addon decodes both formats and displays the telemetry events
in human-readable form, revealing what behavioral data is collected.

Typical events observed (14+ per prompt):
  - ide_editor_open, ide_editor_close
  - conversation_turn_start, conversation_turn_end
  - tool_use_start, tool_use_end
  - file_read, file_write
  - model_request, model_response
  - session_start, session_end
  - error events

Usage:
    mitmdump -s addons/dump-telemetry.py
"""

import base64
import json
import urllib.parse
from datetime import datetime
from mitmproxy import http, ctx


class TelemetryDecoder:
    """Decodes and logs telemetry from Mixpanel and grok.com events."""

    def __init__(self):
        self.events: list[dict] = []
        self.mixpanel_count = 0
        self.grok_event_count = 0
        self.event_types: dict[str, int] = {}
        self.properties_seen: set = set()

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept and decode telemetry requests."""
        host = flow.request.pretty_host.lower()
        url = flow.request.pretty_url.lower()

        if "mixpanel" in host:
            self._decode_mixpanel(flow)
        elif "grok.com" in host and any(
            x in url for x in ["/event", "/track", "/telemetry", "/analytics"]
        ):
            self._decode_grok_events(flow)
        elif "grok.com" in host and flow.request.method == "POST":
            # Try to decode any POST to grok.com as potential telemetry
            self._try_decode_json_body(flow, source="grok.com")

    def _decode_mixpanel(self, flow: http.HTTPFlow) -> None:
        """Decode Mixpanel base64 payloads."""
        content = flow.request.content
        if not content:
            return

        # Mixpanel sends data as base64-encoded JSON in the 'data' parameter
        # Either as a query param (GET) or form body (POST)
        data_param = None

        # Check query parameters
        params = dict(urllib.parse.parse_qsl(flow.request.url.split("?", 1)[-1] if "?" in flow.request.url else ""))
        if "data" in params:
            data_param = params["data"]

        # Check form body
        if not data_param:
            try:
                body = content.decode("utf-8")
                form_params = dict(urllib.parse.parse_qsl(body))
                if "data" in form_params:
                    data_param = form_params["data"]
            except (UnicodeDecodeError, ValueError):
                pass

        # Try direct base64 decode of the body
        if not data_param:
            try:
                data_param = content.decode("utf-8")
            except UnicodeDecodeError:
                return

        # Decode base64
        try:
            # Handle URL-safe base64 and padding
            padded = data_param + "=" * (4 - len(data_param) % 4)
            decoded = base64.b64decode(padded)
            events = json.loads(decoded)
        except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
            # Try standard JSON (some Mixpanel calls use plain JSON)
            try:
                events = json.loads(data_param)
            except (json.JSONDecodeError, ValueError):
                ctx.log.info(f"[MIXPANEL] Could not decode payload from {flow.request.path}")
                return

        # Normalize to list
        if isinstance(events, dict):
            events = [events]

        for event in events:
            if not isinstance(event, dict):
                continue

            self.mixpanel_count += 1
            event_name = event.get("event", event.get("name", "unknown"))
            properties = event.get("properties", event.get("$properties", {}))

            # Track event type frequency
            self.event_types[event_name] = self.event_types.get(event_name, 0) + 1

            # Track what properties are collected
            if isinstance(properties, dict):
                self.properties_seen.update(properties.keys())

            # Store for summary
            self.events.append({
                "timestamp": datetime.now().isoformat(),
                "source": "mixpanel",
                "event": event_name,
                "properties": properties,
            })

            # Log in real-time
            props_summary = ""
            if isinstance(properties, dict):
                # Show interesting properties, redact IDs
                safe_props = {
                    k: v for k, v in properties.items()
                    if k not in ("distinct_id", "token", "$device_id", "mp_lib")
                    and not k.startswith("$")
                }
                if safe_props:
                    props_summary = f" | {json.dumps(safe_props, default=str)[:100]}"

            ctx.log.info(
                f"[MIXPANEL] {event_name}{props_summary}"
            )

    def _decode_grok_events(self, flow: http.HTTPFlow) -> None:
        """Decode grok.com event endpoint payloads."""
        self._try_decode_json_body(flow, source="grok.com/events")

    def _try_decode_json_body(self, flow: http.HTTPFlow, source: str) -> None:
        """Try to decode a JSON body as telemetry."""
        content = flow.request.content
        if not content:
            return

        try:
            body = content.decode("utf-8")
            data = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return

        # Handle single event or batch
        events = []
        if isinstance(data, list):
            events = data
        elif isinstance(data, dict):
            # Could be a single event or a wrapper
            if "events" in data:
                events = data["events"] if isinstance(data["events"], list) else [data["events"]]
            elif "event" in data or "type" in data or "name" in data:
                events = [data]
            else:
                # Log the keys for inspection
                ctx.log.info(
                    f"[{source.upper()}] POST {flow.request.path} "
                    f"keys: {list(data.keys())[:10]}"
                )
                return

        for event in events:
            if not isinstance(event, dict):
                continue

            self.grok_event_count += 1
            event_name = (
                event.get("event")
                or event.get("type")
                or event.get("name")
                or event.get("action")
                or "unknown"
            )

            self.event_types[event_name] = self.event_types.get(event_name, 0) + 1

            self.events.append({
                "timestamp": datetime.now().isoformat(),
                "source": source,
                "event": event_name,
                "data": {
                    k: v for k, v in event.items()
                    if k not in ("token", "user_id", "device_id", "session_id")
                },
            })

            ctx.log.info(
                f"[{source.upper():15}] {event_name}"
            )

    def done(self):
        """Print telemetry summary."""
        ctx.log.info("")
        ctx.log.info("=" * 60)
        ctx.log.info("TELEMETRY DECODE SUMMARY")
        ctx.log.info("=" * 60)
        ctx.log.info(f"  Mixpanel events decoded:  {self.mixpanel_count}")
        ctx.log.info(f"  Grok.com events decoded:  {self.grok_event_count}")
        ctx.log.info(f"  Total events:             {len(self.events)}")
        ctx.log.info("")

        if self.event_types:
            ctx.log.info("  Event types (by frequency):")
            for event_name, count in sorted(
                self.event_types.items(), key=lambda x: -x[1]
            ):
                ctx.log.info(f"    {count:4}x  {event_name}")
            ctx.log.info("")

        if self.properties_seen:
            ctx.log.info("  Properties collected (Mixpanel):")
            for prop in sorted(self.properties_seen):
                # Redact anything that looks like an ID
                if any(x in prop.lower() for x in ["id", "token", "key"]):
                    ctx.log.info(f"    - {prop}: <redacted>")
                else:
                    ctx.log.info(f"    - {prop}")
            ctx.log.info("")

        ctx.log.info(
            f"  Events per prompt (estimated): "
            f"{len(self.events)} total across session"
        )
        ctx.log.info("=" * 60)


addons = [TelemetryDecoder()]
