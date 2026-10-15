# SOC Sentinel — Security Monitoring & Incident Investigation Lab

**Portfolio project for entry-level SOC / Blue Team roles**

SOC Sentinel analyzes *synthetic authentication logs* to flag patterns that a Tier 1 SOC analyst may investigate:
- repeated failed logins from one source IP (possible brute-force activity)
- a successful login from an IP after repeated failures from that IP
- high-priority alerts with evidence and recommended triage steps

> All logs included here are fictional and generated for learning. This project does not access real systems, scan networks, or perform offensive actions.

## Skills demonstrated
Python, log parsing, detection logic, alert triage, incident documentation, JSON output, testing, and security recommendations.

## Requirements
- Python 3.9+
- No third-party packages required

## Run it
From this project folder:

```bash
python src/analyzer.py --input data/authentication.log --output reports/alerts.json
```

The script prints a summary and saves structured alerts to `reports/alerts.json`.

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Detection logic
1. **Repeated failed logins:** 5 or more failures from the same source IP within a rolling 10-minute window.
2. **Success after repeated failures:** a successful login from the same source IP within 30 minutes after a burst of at least 5 failures.
3. Events are grouped by source IP and sorted by timestamp. These are *triage signals*, not proof of compromise.

Thresholds are configurable using command-line flags.

## Suggested analyst workflow
1. Review the alert evidence and affected username(s).
2. Confirm whether the source IP and activity are expected.
3. Check related endpoint, VPN, MFA, and identity-provider logs if available.
4. Determine scope and whether the account had a successful login.
5. Escalate according to the organization's incident response process.
6. Record findings, confidence, impact, and recommended next steps.

## Example findings
- Multiple failed logins can result from a mistyped password, a stale service, or malicious guessing.
- A success after repeated failures raises concern but does not by itself prove an account was compromised.
- Never block an IP or disable an account based only on this toy detector without validating context and following approved procedures.

## Portfolio deliverables
- `src/analyzer.py` — detection script
- `data/authentication.log` — synthetic test data
- `reports/` — generated alert output and report template
- `tests/` — unit tests

## Next improvements
- Add Windows Event ID parsing or Linux SSH authentication log parsing.
- Ingest JSON/CSV exports from a lab SIEM.
- Add severity scoring and a dashboard.
- Compare detections against a documented detection rule and measure false positives.
- Include screenshots from your own run and a short incident timeline.

## Resume bullet (use only after running and understanding it)
**SOC Sentinel — Python Authentication Log Analyzer**
- Built a Python-based defensive log analysis tool to identify repeated authentication failures and successful logins following failure bursts in synthetic security logs.
- Generated structured JSON alerts with event evidence, severity, and recommended analyst triage steps; added unit tests for detection behavior.

Do not claim this project was deployed in a real SOC or detected real attacks.
