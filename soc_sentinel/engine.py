from __future__ import annotations

import csv
import io
import json
import random
import re
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

DOC_IPS = ["192.0.2.10", "198.51.100.24", "203.0.113.10", "203.0.113.77"]
USERS = ["alex", "j.smith", "svc_backup", "maria", "admin"]
AUTH_FAIL = {"failed", "failure", "fail", "denied", "rejected", "invalid"}
AUTH_SUCCESS = {"success", "successful", "accepted", "logged_in", "login_success"}

def utc_iso(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="seconds")

def severity_rank(value: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(str(value).upper(), 9)

def normalize_records(records: list[dict[str, Any]], source: str = "uploaded") -> list[dict[str, Any]]:
    out = []
    for raw in records:
        if not isinstance(raw, dict):
            continue
        low = {str(k).strip().lower().replace("-", "_").replace(" ", "_"): v for k, v in raw.items()}
        timestamp = next((low[k] for k in ("timestamp", "time", "datetime", "@timestamp", "event_time") if low.get(k)), None)
        if timestamp is None:
            timestamp = utc_iso()
        timestamp = str(timestamp)
        event_type = str(next((low[k] for k in ("event_type", "event", "action", "event_action", "type") if low.get(k)), "unknown")).lower()
        outcome = str(next((low[k] for k in ("outcome", "status", "result", "auth_result", "http_status") if low.get(k) is not None), "")).lower()
        if outcome.isdigit():
            code = int(outcome)
            outcome = "failure" if code in (401, 403) else ("success" if 200 <= code < 400 else "unknown")
        if any(word in event_type for word in ("fail", "denied", "reject")) or outcome in AUTH_FAIL:
            outcome = "failure"
        elif any(word in event_type for word in ("success", "accepted", "login")) and not outcome:
            outcome = "success"
        ip = next((low[k] for k in ("source_ip", "src_ip", "src", "client_ip", "remote_addr", "ip", "source") if low.get(k)), "unknown")
        user = next((low[k] for k in ("username", "user", "account", "user_name") if low.get(k)), "unknown")
        path = next((low[k] for k in ("path", "url", "uri", "request") if low.get(k)), "")
        try:
            status_code = int(low.get("http_status", low.get("status_code", 0)) or 0)
        except (ValueError, TypeError):
            status_code = 0
        out.append({
            "event_id": str(low.get("event_id") or low.get("id") or uuid.uuid4()),
            "timestamp": timestamp,
            "source": source,
            "event_type": event_type,
            "outcome": outcome or "unknown",
            "source_ip": str(ip),
            "username": str(user),
            "path": str(path),
            "http_status": status_code,
            "message": str(low.get("message", low.get("raw", ""))),
            "is_synthetic": bool(low.get("is_synthetic", False)),
            "raw_json": json.dumps(raw, ensure_ascii=False, default=str),
        })
    return out

def parse_uploaded_file(raw: bytes, filename: str, source_kind: str = "Auto-detect"):
    text = raw.decode("utf-8-sig", errors="replace")
    warnings: list[str] = []
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    records: list[dict[str, Any]] = []
    if suffix in ("jsonl", "ndjson"):
        for i, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    records.append(item)
                else:
                    warnings.append(f"Line {i}: JSON value is not an object.")
            except json.JSONDecodeError as exc:
                warnings.append(f"Line {i}: invalid JSON ({exc.msg}).")
    elif suffix == "json" or source_kind == "Normalized JSON/CSV events":
        try:
            obj = json.loads(text)
            if isinstance(obj, list):
                records = [x for x in obj if isinstance(x, dict)]
            elif isinstance(obj, dict):
                records = obj.get("events", [obj]) if isinstance(obj.get("events", [obj]), list) else [obj]
        except json.JSONDecodeError:
            warnings.append("File did not parse as JSON; trying CSV or web-log parser.")
    if not records and suffix == "csv":
        try:
            records = list(csv.DictReader(io.StringIO(text)))
        except csv.Error as exc:
            warnings.append(f"CSV parser warning: {exc}")
    if not records:
        # Common/combined Apache/Nginx log parser.
        pattern = re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)')
        for line_no, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            match = pattern.match(line.strip())
            if match:
                item = match.groupdict()
                parts = item["request"].split()
                records.append({
                    "timestamp": item["time"], "source_ip": item["ip"],
                    "event_type": "web_request", "http_status": int(item["status"]),
                    "method": parts[0] if parts else "", "path": parts[1] if len(parts) > 1 else "",
                    "message": line,
                })
            elif suffix not in ("log", "txt"):
                warnings.append(f"Line {line_no}: not recognized by common web-log parser.")
            else:
                # Keep unparsed authentication text as a record; custom analyzer can
                # still be used by the project separately, and warnings are explicit.
                records.append({"timestamp": "", "event_type": "raw_log_line", "message": line})
    if not records:
        warnings.append("No records could be parsed.")
    return records, warnings

def detect_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts = []
    # Parse ISO-like timestamps; unknown timestamps use input order's current time.
    def dt_for(event, index):
        value = str(event.get("timestamp", ""))
        try:
            value = value.replace("Z", "+00:00")
            dt = datetime.fromisoformat(value)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return datetime.now(timezone.utc) + timedelta(seconds=index)
    ordered = sorted(enumerate(events), key=lambda pair: dt_for(pair[1], pair[0]))
    by_ip_failures = defaultdict(list)
    for idx, event in ordered:
        outcome = str(event.get("outcome", "")).lower()
        etype = str(event.get("event_type", "")).lower()
        if outcome == "failure" or any(word in etype for word in ("failed", "failure", "denied", "reject")):
            by_ip_failures[event.get("source_ip", "unknown")].append((dt_for(event, idx), event))
    emitted = set()
    for idx, event in ordered:
        ip = str(event.get("source_ip", "unknown"))
        now = dt_for(event, idx)
        outcome = str(event.get("outcome", "")).lower()
        etype = str(event.get("event_type", "")).lower()
        failures_10m = [(dt, e) for dt, e in by_ip_failures[ip] if timedelta(0) <= now - dt <= timedelta(minutes=10)]
        if len(failures_10m) >= 5:
            key = ("AUTH-001", ip, "failure-burst")
            if key not in emitted:
                emitted.add(key)
                alerts.append({
                    "id": str(uuid.uuid4()), "created_at": utc_iso(), "rule_id": "AUTH-001",
                    "title": "Repeated authentication failures", "severity": "MEDIUM",
                    "source_ip": ip, "event_count": len(failures_10m),
                    "evidence": [e.get("message") or e.get("raw_json", "") for _, e in failures_10m[-10:]],
                    "recommendation": "Validate user activity and correlate identity-provider, VPN, MFA, and endpoint logs.",
                    "status": "New", "is_synthetic": bool(event.get("is_synthetic")),
                })
        if outcome == "success" or "success" in etype or "accepted" in etype:
            previous = [(dt, e) for dt, e in by_ip_failures[ip] if timedelta(0) <= now - dt <= timedelta(minutes=30)]
            if len(previous) >= 5:
                key = ("AUTH-002", ip, "post-failure-success")
                if key not in emitted:
                    emitted.add(key)
                    alerts.append({
                        "id": str(uuid.uuid4()), "created_at": utc_iso(), "rule_id": "AUTH-002",
                        "title": "Successful login after repeated failures", "severity": "HIGH",
                        "source_ip": ip, "event_count": len(previous) + 1,
                        "evidence": [e.get("message") or e.get("raw_json", "") for _, e in previous[-10:]] + [event.get("message", "")],
                        "recommendation": "Verify the account owner, MFA result, session, and source context before considering containment.",
                        "status": "New", "is_synthetic": bool(event.get("is_synthetic")),
                    })
    # Web log detections are computed across the imported batch.
    web_by_ip = defaultdict(list)
    for event in events:
        if event.get("event_type") == "web_request" or event.get("http_status"):
            web_by_ip[str(event.get("source_ip", "unknown"))].append(event)
    for ip, rows in web_by_ip.items():
        if len(rows) >= 30:
            alerts.append({
                "id": str(uuid.uuid4()), "created_at": utc_iso(), "rule_id": "WEB-001",
                "title": "Elevated web request volume", "severity": "MEDIUM",
                "source_ip": ip, "event_count": len(rows),
                "evidence": [r.get("message", "") for r in rows[:10]],
                "recommendation": "Check expected clients, CDN/WAF telemetry, paths, and request rate before action.",
                "status": "New", "is_synthetic": any(r.get("is_synthetic") for r in rows),
            })
        denied = [r for r in rows if int(r.get("http_status", 0) or 0) in (401, 403)]
        if len(denied) >= 10:
            alerts.append({
                "id": str(uuid.uuid4()), "created_at": utc_iso(), "rule_id": "WEB-002",
                "title": "Repeated HTTP 401/403 responses", "severity": "MEDIUM",
                "source_ip": ip, "event_count": len(denied),
                "evidence": [r.get("message", "") for r in denied[:10]],
                "recommendation": "Correlate with authentication logs and check for expected failed sessions.",
                "status": "New", "is_synthetic": any(r.get("is_synthetic") for r in denied),
            })
    server_errors = [e for e in events if 500 <= int(e.get("http_status", 0) or 0) <= 599]
    if len(server_errors) >= 20:
        alerts.append({
            "id": str(uuid.uuid4()), "created_at": utc_iso(), "rule_id": "WEB-003",
            "title": "HTTP server error spike", "severity": "MEDIUM",
            "source_ip": "multiple", "event_count": len(server_errors),
            "evidence": [e.get("message", "") for e in server_errors[:10]],
            "recommendation": "Check application health, deployment history, and server logs.",
            "status": "New", "is_synthetic": any(e.get("is_synthetic") for e in server_errors),
        })
    return alerts

def make_demo_scenario(scenario: str, count: int = 80, seed: int = 2026) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    base = datetime.now(timezone.utc) - timedelta(minutes=15)
    records = []
    attack_ip = DOC_IPS[2]
    for i in range(count):
        ts = base + timedelta(seconds=i * 5)
        if scenario == "Credential guessing → successful login" and i < min(8, count):
            outcome, etype, ip = "failure", "authentication_failure", attack_ip
            user = "admin"
        elif scenario == "Credential guessing → successful login" and i == min(8, count - 1):
            outcome, etype, ip, user = "success", "authentication_success", attack_ip, "admin"
        elif scenario == "Web request spike" or (scenario == "Mixed SOC shift" and i % 3 == 0):
            outcome, etype, ip, user = "unknown", "web_request", DOC_IPS[1], "unknown"
        elif scenario == "Mixed SOC shift" and 20 <= i < 29:
            outcome, etype, ip, user = "failure", "authentication_failure", DOC_IPS[3], rng.choice(USERS)
        else:
            outcome, etype, ip, user = ("success" if rng.random() > .08 else "failure"), "authentication_success", DOC_IPS[0], rng.choice(USERS)
        status = 0
        path = ""
        message = f"{ts.isoformat()} {etype} user={user} src={ip} outcome={outcome}"
        if etype == "web_request":
            status = 401 if i % 7 == 0 else (500 if i % 29 == 0 else 200)
            path = rng.choice(["/", "/login", "/api/session", "/assets/app.js", "/admin"])
            message = f'{ip} [{ts.isoformat()}] "GET {path} HTTP/1.1" {status} 1234'
        records.append({
            "event_id": f"SIM-{seed}-{i:05d}", "timestamp": ts.isoformat(),
            "event_type": etype, "outcome": outcome, "source_ip": ip,
            "username": user, "path": path, "http_status": status,
            "message": message, "is_synthetic": True,
        })
    return records

def seed_demo_events(seed: int = 2026) -> list[dict[str, Any]]:
    return normalize_records(make_demo_scenario("Mixed SOC shift", 80, seed), source="synthetic-simulation")
