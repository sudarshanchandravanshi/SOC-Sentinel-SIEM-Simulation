#!/usr/bin/env python3
"""SOC Sentinel: defensive analyzer for synthetic authentication logs."""
import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_timestamp(value):
    return datetime.strptime(value, TIME_FORMAT)


def load_events(path):
    events = []
    with open(path, "r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"timestamp", "username", "source_ip", "event"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"Input must contain columns: {', '.join(sorted(required))}")
        for line_no, row in enumerate(reader, start=2):
            try:
                event = {
                    "timestamp": parse_timestamp(row["timestamp"]),
                    "username": row["username"].strip(),
                    "source_ip": row["source_ip"].strip(),
                    "event": row["event"].strip().lower(),
                }
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid data on line {line_no}: {exc}") from exc
            if event["event"] not in {"success", "failure"}:
                raise ValueError(f"Unsupported event on line {line_no}: {event['event']}")
            events.append(event)
    return sorted(events, key=lambda item: item["timestamp"])


def detect(events, threshold=5, window_minutes=10, success_window_minutes=30):
    by_ip = defaultdict(list)
    for event in events:
        by_ip[event["source_ip"]].append(event)

    alerts = []
    window = timedelta(minutes=window_minutes)
    success_window = timedelta(minutes=success_window_minutes)

    for source_ip, ip_events in by_ip.items():
        ip_events = sorted(ip_events, key=lambda item: item["timestamp"])
        failures = [e for e in ip_events if e["event"] == "failure"]
        bursts = []

        # Build non-duplicated failure bursts using a rolling window.
        index = 0
        while index < len(failures):
            start_event = failures[index]
            burst = [
                e for e in failures
                if start_event["timestamp"] <= e["timestamp"] <= start_event["timestamp"] + window
            ]
            if len(burst) >= threshold:
                bursts.append(burst)
                # Skip forward past the events included in this burst.
                last_time = burst[-1]["timestamp"]
                while index < len(failures) and failures[index]["timestamp"] <= last_time:
                    index += 1
            else:
                index += 1

        for burst in bursts:
            first_time = burst[0]["timestamp"]
            last_time = burst[-1]["timestamp"]
            users = sorted({e["username"] for e in burst})
            alerts.append({
                "alert_id": f"AUTH-FAIL-{len(alerts)+1:03d}",
                "rule": "Repeated authentication failures",
                "severity": "medium",
                "source_ip": source_ip,
                "first_seen": first_time.strftime(TIME_FORMAT),
                "last_seen": last_time.strftime(TIME_FORMAT),
                "failure_count": len(burst),
                "usernames": users,
                "evidence": "At least the configured threshold of failed logins occurred within the configured time window.",
                "recommended_triage": [
                    "Validate whether the source IP and login pattern are expected.",
                    "Review identity-provider, VPN, MFA, and endpoint logs for related activity.",
                    "Check whether any account was successfully accessed and assess scope.",
                    "Escalate through the organization's approved incident process if suspicious."
                ]
            })

            later_successes = [
                e for e in ip_events
                if e["event"] == "success"
                and last_time < e["timestamp"] <= last_time + success_window
            ]
            if later_successes:
                success = later_successes[0]
                alerts.append({
                    "alert_id": f"AUTH-SUCCESS-{len(alerts)+1:03d}",
                    "rule": "Successful login after repeated failures",
                    "severity": "high",
                    "source_ip": source_ip,
                    "first_seen": first_time.strftime(TIME_FORMAT),
                    "last_seen": success["timestamp"].strftime(TIME_FORMAT),
                    "failure_count": len(burst),
                    "usernames": sorted(set(users) | {success["username"]}),
                    "successful_username": success["username"],
                    "evidence": "A successful login followed a burst of authentication failures from the same source IP.",
                    "recommended_triage": [
                        "Prioritize validation of the successful login and account owner.",
                        "Review MFA results, device details, session activity, and sign-in context.",
                        "Determine whether the failures and success belong to the same legitimate user.",
                        "Follow the approved escalation and containment process if compromise is suspected."
                    ]
                })

    return sorted(alerts, key=lambda a: (a["first_seen"], a["alert_id"]))


def main():
    parser = argparse.ArgumentParser(description="Analyze synthetic authentication logs for SOC triage signals.")
    parser.add_argument("--input", required=True, help="Path to CSV authentication log")
    parser.add_argument("--output", default="reports/alerts.json", help="Path for JSON alert output")
    parser.add_argument("--threshold", type=int, default=5, help="Failed-login threshold (default: 5)")
    parser.add_argument("--window-minutes", type=int, default=10, help="Failure window in minutes (default: 10)")
    parser.add_argument("--success-window-minutes", type=int, default=30, help="Window after failures to check for success")
    args = parser.parse_args()

    if args.threshold < 2 or args.window_minutes < 1 or args.success_window_minutes < 1:
        parser.error("Threshold must be >= 2 and windows must be >= 1 minute.")

    events = load_events(args.input)
    alerts = detect(events, args.threshold, args.window_minutes, args.success_window_minutes)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    print(f"Events analyzed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    for alert in alerts:
        print(f"[{alert['severity'].upper()}] {alert['alert_id']} | {alert['rule']} | {alert['source_ip']}")
    print(f"JSON report written to: {output_path}")


if __name__ == "__main__":
    main()
