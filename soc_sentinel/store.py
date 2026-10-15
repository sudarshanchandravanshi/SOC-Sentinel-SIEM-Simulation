from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

def connect(db_path):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path):
    with connect(db_path) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, timestamp TEXT, source TEXT, event_type TEXT,
          outcome TEXT, source_ip TEXT, username TEXT, path TEXT, http_status INTEGER,
          message TEXT, is_synthetic INTEGER, raw_json TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
          id TEXT PRIMARY KEY, created_at TEXT, rule_id TEXT, title TEXT, severity TEXT,
          source_ip TEXT, event_count INTEGER, evidence_json TEXT, recommendation TEXT,
          status TEXT, is_synthetic INTEGER
        );
        CREATE TABLE IF NOT EXISTS incidents (
          id TEXT PRIMARY KEY, created_at TEXT, alert_id TEXT, title TEXT, severity TEXT,
          source_ip TEXT, priority TEXT, status TEXT, owner TEXT, notes TEXT
        );
        CREATE TABLE IF NOT EXISTS responses (
          id TEXT PRIMARY KEY, created_at TEXT, incident_id TEXT, action TEXT,
          rationale TEXT, actor TEXT, mode TEXT
        );
        """)

def insert_events(db_path, events, source="uploaded"):
    count = 0
    with connect(db_path) as c:
        for e in events:
            eid = str(e.get("event_id") or uuid.uuid4())
            c.execute("""INSERT OR IGNORE INTO events
              (id,timestamp,source,event_type,outcome,source_ip,username,path,http_status,message,is_synthetic,raw_json)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
              (eid, e.get("timestamp"), e.get("source", source), e.get("event_type"), e.get("outcome"),
               e.get("source_ip"), e.get("username"), e.get("path"), int(e.get("http_status", 0) or 0),
               e.get("message"), int(bool(e.get("is_synthetic"))), e.get("raw_json") or json.dumps(e, default=str)))
            count += c.total_changes > 0
    return count

def insert_alerts(db_path, alerts):
    with connect(db_path) as c:
        for a in alerts:
            c.execute("""INSERT OR IGNORE INTO alerts
              (id,created_at,rule_id,title,severity,source_ip,event_count,evidence_json,recommendation,status,is_synthetic)
              VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
              (a.get("id") or str(uuid.uuid4()), a.get("created_at"), a.get("rule_id"), a.get("title"),
               a.get("severity"), a.get("source_ip"), int(a.get("event_count", 0)),
               json.dumps(a.get("evidence", [])), a.get("recommendation"), a.get("status", "New"),
               int(bool(a.get("is_synthetic")))))

def fetch_events(db_path, limit=10000):
    with connect(db_path) as c:
        rows = c.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (int(limit),)).fetchall()
    return [dict(r) for r in rows]

def fetch_alerts(db_path, limit=5000):
    with connect(db_path) as c:
        rows = c.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (int(limit),)).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["evidence"] = json.loads(item.pop("evidence_json") or "[]")
        item["status"] = item.get("status") or "New"
        out.append(item)
    return out

def create_incident(db_path, alert, owner, priority, notes):
    iid = "INC-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:5].upper()
    with connect(db_path) as c:
        c.execute("""INSERT INTO incidents (id,created_at,alert_id,title,severity,source_ip,priority,status,owner,notes)
        VALUES (?,?,?,?,?,?,?,?,?,?)""", (iid, datetime.now(timezone.utc).isoformat(), alert.get("id"),
        alert.get("title"), alert.get("severity"), alert.get("source_ip"), priority, "New", owner, notes))

def fetch_incidents(db_path, limit=1000):
    with connect(db_path) as c:
        rows = c.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (int(limit),)).fetchall()
    return [dict(r) for r in rows]

def update_incident(db_path, iid, status, owner, notes):
    with connect(db_path) as c:
        c.execute("UPDATE incidents SET status=?, owner=?, notes=? WHERE id=?", (status, owner, notes, iid))

def record_response(db_path, iid, action, rationale, actor, mode):
    with connect(db_path) as c:
        c.execute("""INSERT INTO responses (id,created_at,incident_id,action,rationale,actor,mode)
        VALUES (?,?,?,?,?,?,?)""", ("RESP-" + uuid.uuid4().hex[:10].upper(), datetime.now(timezone.utc).isoformat(),
        iid, action, rationale, actor, mode))

def fetch_responses(db_path, incident_id=None):
    with connect(db_path) as c:
        if incident_id:
            rows = c.execute("SELECT * FROM responses WHERE incident_id=? ORDER BY created_at DESC", (incident_id,)).fetchall()
        else:
            rows = c.execute("SELECT * FROM responses ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]

def clear_demo_data(db_path):
    with connect(db_path) as c:
        c.execute("DELETE FROM events WHERE is_synthetic=1")
        c.execute("DELETE FROM alerts WHERE is_synthetic=1")

def event_count(db_path):
    with connect(db_path) as c:
        return c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
