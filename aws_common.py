#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Common helpers for LazyAWS modules:
- get_session(profile, region)
- get_traced_client(session, service, api_trace, profile, region)
- run_check(analyze_fn, args) -> prints table, saves RawData JSON (one-per-target)
- push_trace(trace, service, operation, cli_request, response)  # лишаю для сумісності
- легкий рендер таблиць з автопереносом
"""

from __future__ import annotations

import os
import re
import json
import textwrap
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Callable

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# ------------------------------ UI constants ------------------------------

RESET = "\033[0m"
OK   = "\033[32m✓\033[0m"   # green
WARN = "\033[33m!\033[0m"   # yellow
BAD  = "\033[31m✗\033[0m"   # red
NA   = "\033[90m—\033[0m"   # gray

ANSI_RE = re.compile(r"\x1B\[[0-9;]*[mK]")

RAW_DIR = Path("RawData")
RAW_DIR.mkdir(exist_ok=True)

# ------------------------------ Helpers ------------------------------

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def strip_ansi(s: str) -> str:
    if not isinstance(s, str):
        return s
    return ANSI_RE.sub("", s)

def sanitize_target(val: Optional[str]) -> str:
    if not val:
        return "none"
    s = str(val)
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", s)
    s = s.strip("-._")
    return s or "none"

def safe_json_dumps(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2, default=str)
    except Exception:
        return json.dumps(str(obj), ensure_ascii=False, indent=2)

def get_session(profile: Optional[str] = None, region: Optional[str] = None):
    """Return a boto3.Session honoring the profile."""
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)

# ---------- CLI helpers for tracing ----------

_CAMEL_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")

def camel_to_kebab(s: str) -> str:
    # "InstanceIds" -> "instance-ids"; "MaxItems" -> "max-items"
    if not s:
        return ""
    # якщо є підкреслення — це вже snake_case
    if "_" in s:
        return s.replace("_", "-").lower()
    parts = _CAMEL_BOUNDARY.split(s)
    return "-".join(p.lower() for p in parts if p)

def _format_cli_args(kwargs: Dict[str, Any]) -> str:
    parts = []
    for k, v in (kwargs or {}).items():
        flag = "--" + camel_to_kebab(k)
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            sv = " ".join(str(x) for x in v)
            parts.append(f"{flag} {sv}")
        elif isinstance(v, (dict,)):
            parts.append(f"{flag} '{json.dumps(v, ensure_ascii=False)}'")
        else:
            parts.append(f"{flag} {v}")
    return " ".join(parts)

def push_trace(trace_list: list, service: str, operation: str, request_cli: str, response: Any):
    """
    Append CLI-like request/response to a shared trace list.
    - response may be dict/list/str; we stringify safely.
    """
    try:
        if not isinstance(response, str):
            resp_str = json.dumps(response, ensure_ascii=False, indent=2, default=str)
        else:
            resp_str = response
    except Exception:
        resp_str = str(response)

    trace_list.append({
        "service": service,
        "operation": operation,
        "api": f"{service}:{operation}",
        "cli_request": request_cli,
        "cli_response": resp_str,
    })

class _TracedClientProxy:
    """
    Wraps a boto3 client; any method call is logged as CLI-like into api_trace.
    """
    def __init__(self, client, service: str, api_trace: list, profile: Optional[str], region: Optional[str]):
        self._client = client
        self._service = service
        self._trace = api_trace
        self._profile = profile or "default"
        self._region = region

    def __getattr__(self, name: str) -> Callable[..., Any]:
        orig = getattr(self._client, name)
        if not callable(orig):
            return orig

        # boto method name is snake_case of API, e.g., describe_instances -> DescribeInstances
        op_api = "".join([p.capitalize() for p in name.split("_")])
        op_cli = name.replace("_", "-")

        def wrapper(*args, **kwargs):
            # args (positional) рідко використовуються; намагаємось логувати kwargs
            cli_args = _format_cli_args(kwargs)
            region_part = f" --region {self._region}" if self._region else ""
            cmd = f"aws {self._service} {op_cli} {cli_args}{region_part} --profile {self._profile}".strip()
            try:
                resp = orig(*args, **kwargs)
                push_trace(self._trace, self._service, op_api, cmd, resp)
                return resp
            except Exception as e:
                push_trace(self._trace, self._service, op_api, cmd, f"ERROR: {e}")
                raise
        return wrapper

def get_traced_client(session, service: str, api_trace: list, profile: Optional[str] = None, region: Optional[str] = None):
    client = session.client(service, region_name=region) if region else session.client(service)
    return _TracedClientProxy(client, service, api_trace, profile, region)

# ------------------------------ ASCII table ------------------------------

def _term_width(default: int = 120) -> int:
    try:
        return shutil.get_terminal_size(fallback=(default, 24)).columns
    except Exception:
        return default

def _wrap(text: str, width: int) -> List[str]:
    if text is None:
        text = ""
    lines = []
    for para in str(text).splitlines() or [""]:
        wrapped = textwrap.wrap(para, width=width, break_long_words=False, replace_whitespace=False) or [""]
        lines.extend(wrapped)
    return lines

def _render_table(rows: List[Dict[str, str]]) -> str:
    if not rows:
        return ""

    total = _term_width()
    status_w  = 6
    remain = max(total - (status_w + 2*3 + 4*2 + 5), 70)
    check_w = max(int(remain * 0.38), 34)
    details_w = max(int(remain * 0.31), 18)
    reco_w = max(remain - check_w - details_w, 18)

    header = ["Check", "Status", "Details", "Recommendation"]

    lines_out: List[str] = []
    sep = "+" + "-"*(check_w+2) + "+" + "-"*(status_w+2) + "+" + "-"*(details_w+2) + "+" + "-"*(reco_w+2) + "+"

    def fmt_row(c: str, s: str, d: str, r: str) -> List[str]:
        cw = _wrap(c, check_w)
        dw = _wrap(d, details_w)
        rw = _wrap(r, reco_w)
        sw = _wrap(s, status_w)
        max_h = max(len(cw), len(dw), len(rw), len(sw))
        out = []
        for i in range(max_h):
            ci = cw[i] if i < len(cw) else ""
            si = sw[i] if i < len(sw) else ""
            di = dw[i] if i < len(dw) else ""
            ri = rw[i] if i < len(rw) else ""
            out.append(f"| {ci:<{check_w}} | {si:<{status_w}} | {di:<{details_w}} | {ri:<{reco_w}} |")
        return out

    lines_out.append(sep)
    lines_out.extend(fmt_row(*header))
    lines_out.append(sep)

    for r in rows:
        lines_out.extend(fmt_row(r.get("Check",""), r.get("Status",""), r.get("Details",""), r.get("Recommendation","")))
        lines_out.append(sep)

    return "\n".join(lines_out)

# ------------------------------ run_check ------------------------------

def _status_plain(f: Dict[str, Any]) -> str:
    if "StatusPlain" in f and isinstance(f["StatusPlain"], str):
        return f["StatusPlain"].upper()
    icon = strip_ansi(f.get("Status", ""))
    icon_map = { "✓": "OK", "!": "WARN", "✗": "BAD", "—": "NA", "-": "NA" }
    for ch, val in icon_map.items():
        if ch in icon:
            return val
    return "OK"

def _header_meta(meta: Dict[str, Any]) -> str:
    svc = meta.get("Service", "Unknown")
    tgt = meta.get("Target", "(none)")
    region = meta.get("Region", "—")
    profile = meta.get("Profile", "default")
    when = meta.get("TimeUTC") or iso_now()
    return (f"# AWS Security Review\n"
            f"Service: {svc} | Target: {tgt} | Region: {region} | Profile: {profile} | Time(UTC): {when}\n")

def _save_record(service: str, target: str, record: Dict[str, Any]) -> Path:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    safe_service = sanitize_target(service).lower()
    safe_target  = sanitize_target(target)
    if safe_service == "report":
        fname = f"{safe_service}_excel.json"
    elif safe_service == "iam" and safe_target in ("none","—",""):
        fname = f"{safe_service}_account.json"
    else:
        fname = f"{safe_service}_{safe_target}.json"
    out = RAW_DIR / fname
    out.write_text(safe_json_dumps(record), encoding="utf-8")
    return out

def run_check(fn, args):
    meta, findings, aux = fn(args)

    if not isinstance(findings, list):
        findings = []

    rows: List[Dict[str, str]] = []
    for f in findings:
        rows.append({
            "Check": f.get("Check",""),
            "Status": f.get("Status", OK),
            "Details": f.get("Details",""),
            "Recommendation": f.get("Recommendation",""),
        })

    print(_header_meta(meta))
    table = _render_table(rows)
    if table:
        print(table)

    api_trace = []
    if isinstance(aux, dict):
        api_trace = aux.get("api_trace") or []

    failed = []
    for f in findings:
        sp = _status_plain(f)
        ff = dict(f)
        ff["StatusPlain"] = sp
        if sp in ("WARN","BAD"):
            failed.append(ff)

    record = {
        "meta": meta,
        "findings": findings,
        "failed_findings": failed,
        "api_trace": api_trace,  # flattened
    }

    service = str(meta.get("Service","unknown"))
    target  = str(meta.get("Target","none"))
    out = _save_record(service, target, record)
    print(f"\nSaved run artifacts to: {out.resolve()}")
    return out
