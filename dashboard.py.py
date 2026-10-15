"""
SOC Sentinel Pro — local defensive monitoring dashboard.

Features:
- Live refresh of local, authorized log files
- Re-runs the existing authentication analyzer without modifying it
- Alert filtering, incident review, evidence, and downloads
- Basic web access-log triage for YOUR OWN sites (Apache/Nginx combined/common logs)
- Safe response center: records and exports proposed/approved actions; does not change firewall,
  accounts, or remote systems automatically.

Run from the project root:
    python -m pip install streamlit pandas
    python -m streamlit run dashboard.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st
try:
    from streamlit_autorefresh import st_autorefresh
except ImportError:
    st_autorefresh = None

BASE_DIR = Path(__file__).resolve().parent
REPORT_PATH = BASE_DIR / "reports" / "alerts.json"
AUTH_LOG_PATH = BASE_DIR / "data" / "authentication.log"
ANALYZER_PATH = BASE_DIR / "src" / "analyzer.py"
ACTIONS_PATH = BASE_DIR / "reports" / "response_actions.json"

st.set_page_config(
    page_title="SOC Sentinel Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Helpers ----------

def read_json(path: Path, default: Any = None) -> Any:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def read_text_tail(path: Path, max_lines: int = 3000) -> tuple[str, str | None]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        return "\n".join(text.splitlines()[-max_lines:]), None
    except OSError as exc:
        return "", str(exc)


def normalize_alerts(report: Any) -> list[dict[str, Any]]:
    if isinstance(report, list):
        raw = report
    elif isinstance(report, dict):
        raw = report.get("alerts", [])
    else:
        raw = []
    return [item for item in raw if isinstance(item, dict)]


def severity_of(alert: dict[str, Any]) -> str:
    return str(alert.get("severity", alert.get("priority", "UNKNOWN"))).upper()


def alert_title(alert: dict[str, Any], index: int = 0) -> str:
    return str(
        alert.get("title")
        or alert.get("name")
        or alert.get("rule_name")
        or alert.get("rule_id")
        or alert.get("id")
        or f"Alert {index + 1}"
    )


def alert_ip(alert: dict[str, Any]) -> str:
    for key in ("source_ip", "src_ip", "ip", "source", "src", "client_ip"):
        value = alert.get(key)
        if value:
            return str(value)
    evidence = alert.get("evidence")
    if isinstance(evidence, dict):
        for key in ("source_ip", "src_ip", "ip", "source"):
            if evidence.get(key):
                return str(evidence[key])
    return "Unknown"


def safe_project_path(relative_path: str) -> Path:
    """Resolve a log path but refuse paths outside this project directory."""
    candidate = (BASE_DIR / relative_path).resolve()
    root = BASE_DIR.resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError("For safety, choose a log file located inside the project folder.")
    return candidate


def load_actions() -> list[dict[str, Any]]:
    value = read_json(ACTIONS_PATH, [])
    return value if isinstance(value, list) else []


def save_actions(actions: list[dict[str, Any]]) -> None:
    ACTIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    ACTIONS_PATH.write_text(json.dumps(actions, indent=2), encoding="utf-8")


def parse_web_access_log(text: str) -> tuple[pd.DataFrame, int]:
    """
    Best-effort parser for common/combined Apache and Nginx access logs.
    Only analyzes the local log file supplied by the user.
    """
    # Example: 192.0.2.10 - - [10/Oct/2026:13:55:36 +0000] "GET /login HTTP/1.1" 401 232
    pattern = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    )
    rows: list[dict[str, Any]] = []
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        match = pattern.match(line.strip())
        if not match:
            skipped += 1
            continue
        item = match.groupdict()
        parts = item["request"].split()
        rows.append({
            "Source IP": item["ip"],
            "Timestamp": item["time"],
            "Method": parts[0] if len(parts) > 0 else "Unknown",
            "Path": parts[1] if len(parts) > 1 else "Unknown",
            "HTTP Status": int(item["status"]),
            "Bytes": item["size"],
        })
    return pd.DataFrame(rows), skipped


def make_web_findings(df: pd.DataFrame) -> list[dict[str, Any]]:
    if df.empty:
        return []
    findings: list[dict[str, Any]] = []
    counts = df.groupby("Source IP").size().sort_values(ascending=False)
    for ip, count in counts.items():
        if count >= 100:
            findings.append({
                "severity": "HIGH",
                "title": "High request volume from one source",
                "source_ip": str(ip),
                "count": int(count),
                "recommendation": "Validate expected traffic and correlate with WAF, CDN, and application logs before taking action.",
            })
        elif count >= 30:
            findings.append({
                "severity": "MEDIUM",
                "title": "Elevated request volume from one source",
                "source_ip": str(ip),
                "count": int(count),
                "recommendation": "Review request paths, rate limits, and surrounding time window.",
            })
    auth_failures = df[df["HTTP Status"].isin([401, 403])]
    for ip, count in auth_failures.groupby("Source IP").size().items():
        if count >= 10:
            findings.append({
                "severity": "HIGH" if count >= 25 else "MEDIUM",
                "title": "Repeated HTTP 401/403 responses",
                "source_ip": str(ip),
                "count": int(count),
                "recommendation": "Check authentication events and confirm whether this activity is expected.",
            })
    server_errors = int(df["HTTP Status"].between(500, 599).sum())
    if server_errors >= 20:
        findings.append({
            "severity": "MEDIUM",
            "title": "Elevated HTTP 5xx responses",
            "source_ip": "Multiple / server-side",
            "count": server_errors,
            "recommendation": "Investigate application health and correlate with deployment and server logs.",
        })
    return findings


# ---------- Header and sidebar ----------

st.title("🛡️ SOC Sentinel Pro")
st.caption("Defensive monitoring and incident triage • Local logs only • Training / lab use")

with st.sidebar:
    st.header("Monitoring")
    source_mode = st.radio(
        "Log source",
        ["Authentication log", "My website access log"],
        help="Website mode reads an Apache/Nginx access log file that you own or are authorized to monitor.",
    )
    default_path = "data/authentication.log" if source_mode == "Authentication log" else "data/access.log"
    log_relative_path = st.text_input(
        "Log path (relative to project folder)",
        value=default_path,
        help="Example: data/authentication.log or data/access.log. Keep the file inside this project folder.",
    )
    refresh_seconds = st.selectbox("Refresh interval", [5, 10, 15, 30, 60], index=1)
    st.caption("Auto-refresh re-reads the selected local log. It cannot see traffic from unrelated public websites.")
    refresh_now = st.button("↻ Refresh now", use_container_width=True)
    st.divider()
    st.header("Response safety")
    st.info(
        "Response actions are recorded as a case/playbook. This dashboard does not silently block IPs, "
        "disable accounts, or modify remote systems."
    )

if refresh_now:
    st.rerun()

# Trigger a full app rerun so the selected local log is re-read on each interval.
if st_autorefresh is not None:
    st_autorefresh(interval=int(refresh_seconds) * 1000, key="soc_sentinel_live_refresh")
else:
    st.info("For timed live refresh, install streamlit-autorefresh. The Refresh now button still works.")

try:
    selected_log_path = safe_project_path(log_relative_path)
    log_text, log_error = read_text_tail(selected_log_path)
except ValueError as exc:
    selected_log_path = None
    log_text, log_error = "", str(exc)

if source_mode == "Authentication log":
    # Run the existing analyzer on refresh, preserving its source code and tests.
    if selected_log_path and selected_log_path.exists() and ANALYZER_PATH.exists():
        try:
            REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                [
                    sys.executable, str(ANALYZER_PATH),
                    "--input", str(selected_log_path),
                    "--output", str(REPORT_PATH),
                ],
                cwd=str(BASE_DIR),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                st.warning("Analyzer returned an error. The last available report is shown below.")
                if result.stderr:
                    st.code(result.stderr[-3000:])
        except (OSError, subprocess.TimeoutExpired) as exc:
            st.warning(f"Could not run analyzer: {exc}")
    report = read_json(REPORT_PATH, [])
    alerts = normalize_alerts(report)
    web_df = pd.DataFrame()
    findings: list[dict[str, Any]] = []
else:
    if log_error:
        st.error(log_error)
    elif not selected_log_path or not selected_log_path.exists():
        st.warning(f"Access log not found: `{log_relative_path}`. Add your own authorized Apache/Nginx access log there, or change the path above.")
    web_df, skipped_lines = parse_web_access_log(log_text)
    findings = make_web_findings(web_df)
    alerts = findings
    report = {"source": str(log_relative_path), "parsed_requests": len(web_df), "findings": findings}
    if skipped_lines:
        st.caption(f"Skipped {skipped_lines} lines that did not match the common/combined Apache/Nginx format.")

# ---------- Live status ----------
st.caption(
    f"Local-file polling interval: {refresh_seconds}s • Last page update: "
    f"{datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}"
)

# ---------- Summary metrics ----------

sev_counts = Counter(severity_of(a) for a in alerts)
if source_mode == "Authentication log":
    total_events = len(log_text.splitlines())
else:
    total_events = len(web_df)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Events / requests read", total_events)
m2.metric("Alerts / findings", len(alerts))
m3.metric("High severity", sev_counts.get("HIGH", 0))
m4.metric("Medium severity", sev_counts.get("MEDIUM", 0))

if source_mode == "Authentication log":
    st.caption(f"Input: `{log_relative_path}` • Output report: `reports/alerts.json`")
else:
    st.caption(f"Input: `{log_relative_path}` • Parser: common/combined Apache/Nginx access logs")

tab_overview, tab_alerts, tab_logs, tab_response = st.tabs(
    ["Overview", "Alerts & investigations", "Live log view", "Response center"]
)

with tab_overview:
    left, right = st.columns([1, 1])
    with left:
        st.subheader("Findings by severity")
        if alerts:
            sev_df = pd.DataFrame(
                [{"Severity": k, "Count": v} for k, v in sorted(sev_counts.items())]
            ).set_index("Severity")
            st.bar_chart(sev_df)
        else:
            st.success("No findings were generated from the current input.")
    with right:
        st.subheader("Top source IPs")
        if source_mode == "Authentication log":
            ip_counts = Counter(alert_ip(a) for a in alerts)
            ip_df = pd.DataFrame(
                [{"Source IP": ip, "Alerts": count} for ip, count in ip_counts.most_common(10)]
            )
        elif not web_df.empty:
            ip_df = (
                web_df.groupby("Source IP").size().sort_values(ascending=False).head(10)
                .rename("Requests").reset_index()
            )
        else:
            ip_df = pd.DataFrame()
        if not ip_df.empty:
            st.dataframe(ip_df, use_container_width=True, hide_index=True)
        else:
            st.info("No source-IP data is available yet.")

    st.subheader("Quick analyst checklist")
    st.markdown(
        "- Confirm the source IP and time window.\n"
        "- Check whether the activity matches an approved test, scanner, health check, or known user.\n"
        "- Correlate identity, VPN, endpoint, WAF/CDN, and application logs where available.\n"
        "- Preserve evidence and document your confidence before containment."
    )

with tab_alerts:
    st.subheader("Alert queue")
    if alerts:
        available_severities = sorted({severity_of(a) for a in alerts})
        chosen_severities = st.multiselect(
            "Severity filter", available_severities, default=available_severities
        )
        query = st.text_input("Search alerts (title, IP, rule, evidence)")
        filtered = []
        for idx, alert in enumerate(alerts):
            haystack = json.dumps(alert, ensure_ascii=False).lower()
            if severity_of(alert) in chosen_severities and query.lower() in haystack:
                filtered.append((idx, alert))
        if filtered:
            rows = []
            for idx, alert in filtered:
                rows.append({
                    "Severity": severity_of(alert),
                    "Alert": alert_title(alert, idx),
                    "Source IP": alert_ip(alert),
                    "Rule ID": alert.get("rule_id", alert.get("id", "")),
                    "Recommendation": alert.get("recommendation", alert.get("recommended_action", "")),
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            for idx, alert in filtered:
                with st.expander(f"{severity_of(alert)} · {alert_title(alert, idx)} · {alert_ip(alert)}"):
                    st.json(alert)
                    if st.button("Create response case", key=f"case_{source_mode}_{idx}"):
                        actions = load_actions()
                        actions.append({
                            "case_id": f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{len(actions)+1}",
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            "status": "Open",
                            "source": source_mode,
                            "alert_title": alert_title(alert, idx),
                            "severity": severity_of(alert),
                            "source_ip": alert_ip(alert),
                            "action": "Case opened for analyst review; no system changes performed.",
                        })
                        save_actions(actions)
                        st.success("Response case saved. Open Response center to review it.")
        else:
            st.info("No alerts match the selected filters.")
    else:
        st.success("The alert queue is empty for the current log source.")

with tab_logs:
    st.subheader("Recent log lines")
    if log_error:
        st.error(log_error)
    elif log_text.strip():
        st.code("\n".join(log_text.splitlines()[-200:]), language="text")
    else:
        st.info("No log content available. Add or select a local log file.")
    if source_mode == "My website access log" and not web_df.empty:
        st.subheader("Parsed HTTP requests")
        status_filter = st.multiselect(
            "HTTP status filter",
            sorted(web_df["HTTP Status"].unique().tolist()),
            default=sorted(web_df["HTTP Status"].unique().tolist()),
        )
        filtered_df = web_df[web_df["HTTP Status"].isin(status_filter)]
        st.dataframe(filtered_df.tail(500), use_container_width=True, hide_index=True)
        st.subheader("HTTP status counts")
        st.bar_chart(web_df["HTTP Status"].value_counts().sort_index())

with tab_response:
    st.subheader("Safe response center")
    st.warning(
        "This version does not execute firewall rules or changes on other systems. "
        "It supports auditable case tracking and response planning. Validate findings before any real containment."
    )
    with st.form("response_form"):
        case_title = st.text_input("Incident / case title", value="Suspicious authentication activity")
        case_severity = st.selectbox("Severity", ["HIGH", "MEDIUM", "LOW", "INFO"])
        case_ip = st.text_input("Source IP (optional)")
        response_plan = st.selectbox(
            "Response playbook",
            [
                "Investigate and preserve evidence",
                "Verify identity / MFA and review sign-in history",
                "Review WAF/CDN rate limits and application logs",
                "Prepare containment recommendation for human approval",
                "Close as expected activity with rationale",
            ],
        )
        notes = st.text_area("Analyst notes / justification")
        acknowledged = st.checkbox(
            "I confirm this is a system/log source I own or am authorized to investigate."
        )
        submitted = st.form_submit_button("Save response plan")
    if submitted:
        if not acknowledged:
            st.error("Confirm authorization before saving a response plan.")
        elif not case_title.strip():
            st.error("Enter a case title.")
        else:
            actions = load_actions()
            actions.append({
                "case_id": f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{len(actions)+1}",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "Planned — human review required",
                "source": source_mode,
                "alert_title": case_title.strip(),
                "severity": case_severity,
                "source_ip": case_ip.strip() or "Not specified",
                "playbook": response_plan,
                "notes": notes.strip(),
                "action": "Plan recorded only; no firewall/account/remote-system changes performed.",
            })
            save_actions(actions)
            st.success("Response plan saved to reports/response_actions.json.")

    actions = load_actions()
    st.subheader("Response case history")
    if actions:
        st.dataframe(pd.json_normalize(actions), use_container_width=True, hide_index=True)
        st.download_button(
            "Download response history",
            data=json.dumps(actions, indent=2),
            file_name="response_actions.json",
            mime="application/json",
        )
        if st.button("Clear response history"):
            ACTIONS_PATH.unlink(missing_ok=True)
            st.rerun()
    else:
        st.info("No response cases saved yet.")

# ---------- Downloads and footer ----------
st.divider()
col_a, col_b = st.columns(2)
with col_a:
    st.download_button(
        "Download current findings (JSON)",
        data=json.dumps(alerts, indent=2, ensure_ascii=False),
        file_name="soc_sentinel_findings.json",
        mime="application/json",
        use_container_width=True,
    )
with col_b:
    st.download_button(
        "Download current log sample (TXT)",
        data=log_text,
        file_name="soc_sentinel_log_sample.txt",
        mime="text/plain",
        use_container_width=True,
    )

st.caption(
    "Scope: local files and authorized environments only. "
    "This dashboard is a starter lab, not a replacement for a production SIEM/SOAR or incident-response process."
)
