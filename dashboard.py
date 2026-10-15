from __future__ import annotations

import json
import sqlite3
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from soc_sentinel.engine import (
    normalize_records, detect_events, make_demo_scenario, parse_uploaded_file,
    seed_demo_events, severity_rank,
)
from soc_sentinel.store import (
    init_db, insert_events, fetch_events, fetch_alerts, create_incident,
    fetch_incidents, update_incident, record_response, fetch_responses,
    clear_demo_data, event_count,
)

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "reports" / "soc_sentinel.db"
UPLOAD_DIR = ROOT / "reports" / "uploads"
init_db(DB_PATH)

st.set_page_config(page_title="SOC Sentinel | Security Operations", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container {padding-top: 1.3rem; padding-bottom: 2rem; max-width: 1600px;}
[data-testid="stMetric"] {background: rgba(120,130,145,.08); border: 1px solid rgba(120,130,145,.2); padding: 12px 16px; border-radius: 12px;}
.small-muted {color: #8b949e; font-size: .85rem;}
</style>
""", unsafe_allow_html=True)

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def fmt_time(value):
    if not value:
        return "—"
    return str(value).replace("T", " ")[:19]

with st.sidebar:
    st.title("🛡️ SOC Sentinel")
    st.caption("Blue Team lab • Local-first")
    workspace = st.radio("Workspace", [
        "Operations overview", "Live simulation", "Log ingestion",
        "Event explorer", "Detection engineering", "Incident & response",
    ])
    st.divider()
    st.markdown("**Data mode**")
    st.caption("Synthetic lab data and uploaded/authorized logs are stored locally in SQLite.")
    if st.button("Refresh view", use_container_width=True):
        st.rerun()
    st.divider()
    st.caption("Containment actions are simulated or recorded for approval. No automatic firewall or account changes.")

all_events = fetch_events(DB_PATH, limit=10000)
events_df = pd.DataFrame(all_events)
alerts = fetch_alerts(DB_PATH, limit=5000)
alerts_df = pd.DataFrame(alerts)
incidents = fetch_incidents(DB_PATH, limit=1000)

st.title("SOC Sentinel")
st.caption("Security information and event management simulation · Detection, triage, case management")

# Global metrics
if events_df.empty:
    total_events = 0
    first_seen = "—"
else:
    total_events = len(events_df)
    first_seen = fmt_time(events_df["timestamp"].min())
high_alerts = sum(1 for a in alerts if a.get("severity") == "HIGH")
medium_alerts = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
open_cases = sum(1 for c in incidents if c.get("status") not in ("Closed", "Resolved"))
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Events ingested", f"{total_events:,}")
c2.metric("Alerts", f"{len(alerts):,}")
c3.metric("High severity", f"{high_alerts:,}")
c4.metric("Open cases", f"{open_cases:,}")
c5.metric("Data freshness", fmt_time(events_df["timestamp"].max()) if not events_df.empty else "No data")

if workspace == "Operations overview":
    left, right = st.columns([1.4, 1])
    with left:
        st.subheader("Alert severity")
        if alerts_df.empty:
            st.info("No alerts yet. Open Live simulation and click **Load demo scenario**, or ingest a log.")
        else:
            sev = alerts_df.groupby("severity", dropna=False).size().reset_index(name="alerts")
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sev["sort"] = sev["severity"].map(order).fillna(9)
            sev = sev.sort_values("sort")
            st.plotly_chart(px.bar(sev, x="severity", y="alerts", color="severity",
                                   title="Generated detections", text_auto=True), use_container_width=True)
    with right:
        st.subheader("Top source IPs")
        if not alerts_df.empty and "source_ip" in alerts_df:
            ips = alerts_df[alerts_df["source_ip"].notna()].groupby("source_ip").size().sort_values(ascending=False).head(8).reset_index(name="alerts")
            if not ips.empty:
                st.plotly_chart(px.bar(ips, x="alerts", y="source_ip", orientation="h", title="Alert volume by source"), use_container_width=True)
            else:
                st.info("No source IPs extracted.")
        else:
            st.info("Alert source data appears here after analysis.")
    st.subheader("Latest alerts")
    if alerts:
        latest = sorted(alerts, key=lambda x: x.get("created_at", ""), reverse=True)[:12]
        st.dataframe(pd.DataFrame([{
            "Time": fmt_time(a.get("created_at")),
            "Severity": a.get("severity"),
            "Detection": a.get("title"),
            "Source IP": a.get("source_ip"),
            "Status": a.get("status", "New"),
            "Rule": a.get("rule_id"),
        } for a in latest]), use_container_width=True, hide_index=True)
    st.subheader("SOC workflow")
    st.markdown("**Ingest → Normalize → Detect → Triage → Document → Simulate response.** "
                "The application labels generated/demo events so they are not mistaken for production telemetry.")

elif workspace == "Live simulation":
    st.subheader("Live threat simulation")
    st.write("A deterministic training scenario generates synthetic authentication and web events. This is a simulation, not live internet traffic.")
    a, b, c = st.columns(3)
    with a:
        scenario = st.selectbox("Scenario", ["Credential guessing → successful login", "Web request spike", "Mixed SOC shift"])
    with b:
        count = st.slider("Events to generate", 20, 300, 80, step=20)
    with c:
        seed = st.number_input("Scenario seed", min_value=1, max_value=999999, value=2026)
    if st.button("Load demo scenario", type="primary", use_container_width=True):
        generated = make_demo_scenario(scenario, int(count), int(seed))
        inserted = insert_events(DB_PATH, generated, source="synthetic-simulation")
        normalized = normalize_records(generated, source="synthetic-simulation")
        detections = detect_events(normalized)
        # persist alerts through the store's event-to-alert insert helper
        insert_events(DB_PATH, [], source="synthetic-simulation")
        from soc_sentinel.store import insert_alerts
        insert_alerts(DB_PATH, detections)
        st.success(f"Added {inserted} synthetic events and evaluated detection rules.")
        st.rerun()
    st.warning("Simulation events use documentation IP ranges and fictional identities. They do not represent real attacks.")
    if not events_df.empty:
        st.subheader("Recent event stream")
        st.dataframe(events_df.sort_values("timestamp", ascending=False).head(100), use_container_width=True, hide_index=True)
    if st.button("Clear demo events and alerts"):
        clear_demo_data(DB_PATH)
        st.success("Synthetic simulation records cleared.")
        st.rerun()

elif workspace == "Log ingestion":
    st.subheader("Log ingestion pipeline")
    st.markdown("Upload an authorized authentication/web log or structured JSON/CSV export. Files are parsed and normalized before detection.")
    uploaded = st.file_uploader("Choose a log file", type=["log", "txt", "csv", "json", "jsonl", "ndjson"])
    source_kind = st.selectbox("Log type", ["Auto-detect", "Authentication events", "Apache/Nginx access log", "Normalized JSON/CSV events"])
    run_detection = st.checkbox("Run built-in detection rules after validation", value=True)
    if uploaded:
        raw = uploaded.getvalue()
        max_bytes = 20 * 1024 * 1024
        if len(raw) > max_bytes:
            st.error("File exceeds the 20 MB demo upload limit. Split it into smaller files.")
        else:
            try:
                records, warnings = parse_uploaded_file(raw, uploaded.name, source_kind)
                st.metric("Parsed events", len(records))
                if warnings:
                    with st.expander(f"Validation notes ({len(warnings)})"):
                        for warning in warnings[:100]:
                            st.write(f"• {warning}")
                if records:
                    st.subheader("Preview normalized records")
                    st.dataframe(pd.DataFrame(records).head(50), use_container_width=True, hide_index=True)
                    confirm = st.checkbox("I am authorized to analyze this log source.")
                    if st.button("Ingest and analyze", type="primary", disabled=not confirm):
                        normalized = normalize_records(records, source=uploaded.name)
                        inserted = insert_events(DB_PATH, normalized, source=uploaded.name)
                        if run_detection:
                            detections = detect_events(normalized)
                            from soc_sentinel.store import insert_alerts
                            insert_alerts(DB_PATH, detections)
                        else:
                            detections = []
                        st.success(f"Ingested {inserted} events. Generated {len(detections)} alerts.")
                        st.download_button("Download normalized JSON", data=json.dumps(normalized, indent=2), file_name="normalized_events.json", mime="application/json")
                        if detections:
                            st.download_button("Download detections JSON", data=json.dumps(detections, indent=2), file_name="detections.json", mime="application/json")
                        st.rerun()
                else:
                    st.error("No usable records found. Check file format and selected log type.")
            except Exception as exc:
                st.error(f"Could not parse file: {exc}")
    st.info("Supported starter formats: JSON Lines/NDJSON, JSON arrays/objects, CSV, and common Apache/Nginx access logs. Parsing is best-effort; review validation notes.")

elif workspace == "Event explorer":
    st.subheader("Event explorer")
    events = fetch_events(DB_PATH, limit=20000)
    if not events:
        st.info("No events yet. Load a simulation or ingest a log.")
    else:
        df = pd.DataFrame(events)
        f1, f2, f3 = st.columns(3)
        with f1:
            sources = sorted(df["source"].dropna().unique().tolist()) if "source" in df else []
            chosen_sources = st.multiselect("Source", sources, default=sources)
        with f2:
            event_types = sorted(df["event_type"].dropna().unique().tolist()) if "event_type" in df else []
            chosen_types = st.multiselect("Event type", event_types, default=event_types)
        with f3:
            search = st.text_input("Search fields")
        filtered = df.copy()
        if chosen_sources and "source" in filtered:
            filtered = filtered[filtered["source"].isin(chosen_sources)]
        if chosen_types and "event_type" in filtered:
            filtered = filtered[filtered["event_type"].isin(chosen_types)]
        if search:
            mask = filtered.astype(str).apply(lambda col: col.str.contains(search, case=False, na=False)).any(axis=1)
            filtered = filtered[mask]
        st.caption(f"{len(filtered):,} matching events")
        st.dataframe(filtered, use_container_width=True, hide_index=True)
        st.download_button("Export filtered events CSV", data=filtered.to_csv(index=False), file_name="events.csv", mime="text/csv")

elif workspace == "Detection engineering":
    st.subheader("Detection engineering")
    st.write("Built-in starter rules are transparent heuristics. Tune thresholds against your own labeled lab data before using them operationally.")
    rules = [
        {"Rule ID":"AUTH-001", "Detection":"Repeated failed logins", "Logic":"5+ failures from one IP in a 10-minute window", "Severity":"MEDIUM"},
        {"Rule ID":"AUTH-002", "Detection":"Success after failure burst", "Logic":"Successful login after 5+ failures from same IP within 30 minutes", "Severity":"HIGH"},
        {"Rule ID":"WEB-001", "Detection":"High request volume", "Logic":"30+ requests from one IP in the imported batch", "Severity":"MEDIUM"},
        {"Rule ID":"WEB-002", "Detection":"Repeated 401/403", "Logic":"10+ unauthorized/forbidden responses from one IP", "Severity":"MEDIUM"},
        {"Rule ID":"WEB-003", "Detection":"Server error spike", "Logic":"20+ HTTP 5xx responses in imported batch", "Severity":"MEDIUM"},
    ]
    st.dataframe(pd.DataFrame(rules), use_container_width=True, hide_index=True)
    st.markdown("**Roadmap:** externalize rules as YAML, add Sigma-compatible mappings, unit tests per rule, false-positive tracking, and MITRE ATT&CK technique references.")
    st.caption("This starter does not claim full Sigma rule-engine compatibility.")

elif workspace == "Incident & response":
    st.subheader("Incident management")
    st.write("Promote alerts into cases, assign an owner, document evidence, and record response plans. Real containment is deliberately not executed by this lab.")
    current_alerts = fetch_alerts(DB_PATH, limit=1000)
    if current_alerts:
        options = {f"{a.get('severity')} · {a.get('title')} · {a.get('source_ip')} · {a.get('id')}": a for a in current_alerts}
        with st.form("create_incident"):
            selected = st.selectbox("Alert to promote", list(options.keys()))
            owner = st.text_input("Analyst / owner", value="SOC Analyst")
            priority = st.selectbox("Case priority", ["P1", "P2", "P3", "P4"], index=1)
            notes = st.text_area("Initial notes")
            submitted = st.form_submit_button("Create incident")
        if submitted:
            alert = options[selected]
            create_incident(DB_PATH, alert, owner, priority, notes)
            st.success("Incident created.")
            st.rerun()
    else:
        st.info("No alerts available to promote. Run a simulation or ingest logs.")
    cases = fetch_incidents(DB_PATH, limit=1000)
    st.subheader("Case queue")
    if cases:
        st.dataframe(pd.DataFrame(cases), use_container_width=True, hide_index=True)
        ids = [c["id"] for c in cases]
        selected_id = st.selectbox("Select case ID", ids)
        case = next(c for c in cases if c["id"] == selected_id)
        with st.form("update_case"):
            new_status = st.selectbox("Status", ["New", "Investigating", "Containment proposed", "Resolved", "Closed"], index=["New", "Investigating", "Containment proposed", "Resolved", "Closed"].index(case["status"]) if case["status"] in ["New", "Investigating", "Containment proposed", "Resolved", "Closed"] else 0)
            new_owner = st.text_input("Owner", value=case.get("owner") or "")
            update_notes = st.text_area("Investigation notes", value=case.get("notes") or "")
            save_case = st.form_submit_button("Save case updates")
        if save_case:
            update_incident(DB_PATH, selected_id, new_status, new_owner, update_notes)
            st.success("Case updated.")
            st.rerun()
        st.markdown("**Response playbook (simulation / approval record only)**")
        action = st.selectbox("Proposed action", [
            "Collect and preserve evidence",
            "Verify identity and MFA events",
            "Review firewall/WAF logs",
            "Recommend IP block for human approval",
            "Recommend account lock for human approval",
            "Close as benign with documented rationale",
        ])
        rationale = st.text_area("Why is this action appropriate?")
        approved = st.checkbox("I reviewed the evidence and authorize recording this response plan.")
        if st.button("Record response plan", disabled=not approved or not rationale.strip()):
            record_response(DB_PATH, selected_id, action, rationale, actor="Local analyst", mode="SIMULATED / NOT EXECUTED")
            st.success("Response plan recorded. No system changes were made.")
        responses = fetch_responses(DB_PATH, incident_id=selected_id)
        if responses:
            st.subheader("Audit trail")
            st.dataframe(pd.DataFrame(responses), use_container_width=True, hide_index=True)
    else:
        st.info("No incidents created yet.")

st.divider()
st.caption("SOC Sentinel Lab · Synthetic scenarios are not real threat intelligence. Validate detections and follow your organization's response process.")
