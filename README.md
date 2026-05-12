# Log_analyzer

# 🛡️ Security Log Analyzer — Mini SIEM

A Python-based security log analysis engine that reads system/login logs,
detects threats using a rule-based engine, and generates MITRE ATT&CK-mapped alerts.
Includes a Streamlit dashboard for visual SOC-style monitoring.

---

## 📁 Project Structure

```
log-analyzer/
├── logs/
│   └── sample_logs.txt       # Realistic log file with embedded attack patterns
├── analyzer.py               # Core detection engine (CLI entry point)
├── rules.py                  # Rule definitions, thresholds, MITRE mappings
├── utils.py                  # Log parser, formatters, export helpers
├── dashboard.py              # Streamlit visual dashboard
├── output/
│   ├── alerts.txt            # Plain-text alert report
│   └── alerts.csv            # CSV for SIEM import / analysis
└── README.md
```

---

## ⚡ Quickstart

### 1. Install dependencies
```bash
pip install streamlit pandas
```

### 2. Run CLI analyzer
```bash
python analyzer.py
# or with custom path:
python analyzer.py --log logs/sample_logs.txt --out output/
```

### 3. Launch dashboard
```bash
streamlit run dashboard.py
```

---

## 🔍 Detection Rules

| Rule | Description | Risk Level | MITRE ATT&CK |
|------|-------------|------------|--------------|
| `brute_force` | ≥3 failed logins from same IP | HIGH | T1110.001 |
| `credential_stuffing` | Same IP tries ≥4 different usernames | HIGH | T1110.004 |
| `off_hours_login` | Successful login between 12AM–5AM | MEDIUM | T1078 |
| `sensitive_file_access` | Access to /etc/shadow, id_rsa, etc. | MEDIUM | T1083 |
| `fail_then_succeed` | Failures followed by success (possible breach) | CRITICAL | T1078 |
| `port_scan` | PORT_SCAN event detected | HIGH | T1046 |
| `rapid_requests` | ≥8 login events within 10 seconds | HIGH | T1499 |
| `file_enum` | ≥3 sensitive files accessed by same actor | HIGH | T1083 |

---

## 📊 Features

- **Rule-based engine** — all thresholds configurable in `rules.py`
- **Risk levels** — CRITICAL / HIGH / MEDIUM / LOW
- **MITRE ATT&CK mapping** — every alert tagged with technique ID
- **Export** — `alerts.txt` (human-readable) + `alerts.csv` (machine-readable)
- **Streamlit dashboard** — bar charts, alert feed, top threat IPs, raw log viewer
- **CLI flags** — `--log`, `--out`, `--no-export`

---

## 📝 Log Format Supported

```
YYYY-MM-DD HH:MM:SS EVENT_TYPE STATUS user=X ip=X port=X protocol=X
YYYY-MM-DD HH:MM:SS FILE_ACCESS user=X ip=X file=X action=READ
YYYY-MM-DD HH:MM:SS PORT_SCAN ip=X ports_scanned=X duration=Xs
```

---

## 🚀 Extending the Project

- Add GeoIP lookup for external IPs
- Integrate with real syslog / auth.log files
- Add email/Slack alerting
- Export to JSON for ELK Stack ingestion
- Train an ML model on alert patterns

---

## 📸 Screenshots

### Dashboard Overview
<img width="1913" height="892" alt="Screenshot 2026-05-12 203846" src="https://github.com/user-attachments/assets/8e094e6b-99e4-4158-9824-1a92244a8814" />

### Alerts Feed
<img width="1917" height="882" alt="Screenshot 2026-05-12 204150" src="https://github.com/user-attachments/assets/b8ce141a-f108-49b8-b59d-4b390562e3ed" />

### Top Threat IPs
<img width="1919" height="878" alt="Screenshot 2026-05-12 204258" src="https://github.com/user-attachments/assets/72d43f2a-1d48-4611-b4d1-840222262453" />

### Alert Statistics
<img width="1919" height="882" alt="Screenshot 2026-05-12 204313" src="https://github.com/user-attachments/assets/9ea48c91-40d1-4ef0-bc7c-4889dc24deb4" />

<img width="1919" height="879" alt="Screenshot 2026-05-12 204334" src="https://github.com/user-attachments/assets/0eb9bd02-9f4f-47b8-be80-1c98f60968fa" />

<img width="1911" height="877" alt="Screenshot 2026-05-12 204351" src="https://github.com/user-attachments/assets/2be59a02-09dd-44bd-a50f-4470c34b823f" />

<img width="1914" height="879" alt="Screenshot 2026-05-12 204456" src="https://github.com/user-attachments/assets/c44d2987-e8c7-44a3-b2cb-ef90a2b5bc18" />

## 🚀 Live Demo
Try the interactive dashboard here:  
[Log Analyzer — Streamlit App]https://loganalyzer-kbikpftcy3zj8kpn4rbk6z.streamlit.app/

