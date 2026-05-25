"""
mitmproxy addon — Logs and documents all authr3.dreamtonics.com API traffic.

Captures every request/response and writes them to:
  - dreamtonics_api.log  : human-readable pretty-printed log
  - dreamtonics_api.json : machine-readable list of all captured calls

Usage:
    mitmweb -s dreamtonics_logger.py
  or:
    mitmdump -s dreamtonics_logger.py

Tip: run alongside audiologie_spoof.py:
    mitmweb -s dreamtonics_logger.py -s audiologie_spoof.py
"""

import json
import os
import textwrap
from datetime import datetime, timezone

from mitmproxy import http

TARGET_HOSTS = {
    "authr3.dreamtonics.com",
    "account.dreamtonics.com",
}
LOG_FILE = os.path.join(os.path.dirname(__file__), "dreamtonics_api.log")
JSON_FILE = os.path.join(os.path.dirname(__file__), "dreamtonics_api.json")

# In-memory list of all captured calls this session
_captured: list[dict] = []


def _decode_body(flow_message) -> str | None:
    """Decode a request/response body, return as string or None.
    Uses .content (mitmproxy auto-decompresses gzip/br/zstd for us)."""
    try:
        raw = flow_message.content  # already decompressed by mitmproxy
    except Exception:
        raw = flow_message.raw_content
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return f"<binary {len(raw)} bytes>"
    # Pretty-print JSON bodies
    ct = flow_message.headers.get("content-type", "")
    if "application/json" in ct:
        try:
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except Exception:
            pass
    return text


def _summarise_path(path: str, query: dict) -> str:
    """Return a short human label for a path."""
    base = path.rstrip("/")
    if query:
        qs = " | ".join(f"{k}={v}" for k, v in query.items())
        return f"{base}  [{qs}]"
    return base


def _write_log(entry: dict) -> None:
    ts        = entry["timestamp"]
    method    = entry["method"]
    path      = entry["path"]
    query     = entry["query"]
    req_body  = entry["request_body"]
    status    = entry["status"]
    resp_body = entry["response_body"]
    elapsed   = entry["elapsed_ms"]

    sep = "─" * 72
    label = _summarise_path(path, query)

    lines = [
        "",
        sep,
        f"  {method}  {label}",
        f"  {ts}   {status}   {elapsed} ms",
        sep,
    ]

    if req_body:
        lines.append("── REQUEST BODY ──")
        lines.extend(textwrap.indent(req_body, "  ").splitlines())

    if resp_body:
        lines.append("── RESPONSE BODY ──")
        # Truncate very large bodies in the log (full copy goes to JSON)
        if len(resp_body) > 8000:
            preview = resp_body[:8000]
            lines.extend(textwrap.indent(preview, "  ").splitlines())
            lines.append(f"  ... (truncated, {len(resp_body)} chars total — see JSON log)")
        else:
            lines.extend(textwrap.indent(resp_body, "  ").splitlines())

    lines.append("")

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _write_json() -> None:
    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(_captured, f, indent=2, ensure_ascii=False)


class DreamtonicsLogger:
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.request.pretty_host not in TARGET_HOSTS:
            return

        ts      = datetime.now(timezone.utc).isoformat()
        method  = flow.request.method
        path    = flow.request.path.split("?")[0]
        query   = dict(flow.request.query)
        status  = flow.response.status_code if flow.response else None
        elapsed = round(flow.response.timestamp_end - flow.request.timestamp_start, 3) * 1000 if flow.response else None

        req_body  = _decode_body(flow.request)
        resp_body = _decode_body(flow.response) if flow.response else None

        # Parse JSON bodies for structured storage
        def try_parse(s):
            if s:
                try:
                    return json.loads(s)
                except Exception:
                    pass
            return s

        entry = {
            "timestamp":     ts,
            "method":        method,
            "path":          path,
            "query":         query,
            "status":        status,
            "elapsed_ms":    elapsed,
            "request_body":  req_body,
            "response_body": resp_body,
            # Parsed versions for easy programmatic use
            "request_json":  try_parse(req_body),
            "response_json": try_parse(resp_body),
        }

        _captured.append(entry)
        _write_log(entry)
        _write_json()

        print(f"[dreamtonics] {method:6s} {status}  {path}  ({elapsed:.0f} ms)")


addons = [DreamtonicsLogger()]