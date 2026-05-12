# utils.py — Log Parsing & Helper Utilities

import re
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────
#  Log Line Parser
# ─────────────────────────────────────────────

# Matches: 2026-05-01 10:01:05 LOGIN FAILED user=admin ip=192.168.1.10 ...
LOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\s+(?P<event_type>\w+)"
    r"(?:\s+(?P<status>[A-Z_]+(?=\s|$)))?"   # optional all-caps status word
    r"(?:\s+user=(?P<user>\S+))?"
    r"(?:\s+ip=(?P<ip>[\d.]+))?"
    r"(?:\s+port=(?P<port>\d+))?"
    r"(?:\s+protocol=(?P<protocol>\S+))?"
    r"(?:\s+file=(?P<file>\S+))?"
    r"(?:\s+action=(?P<action>\S+))?"
    r"(?:\s+ports_scanned=(?P<ports_scanned>[^\s]+))?"
    r"(?:\s+duration=(?P<duration>\S+))?"
)


def parse_log_line(line: str) -> Optional[dict]:
    """
    Parse a single log line into a structured dict.
    Returns None for comments or blank lines.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    match = LOG_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()
    data["raw"] = line
    data["datetime"] = parse_timestamp(data["timestamp"])
    return data


def parse_timestamp(ts: str) -> Optional[datetime]:
    """Convert log timestamp string to datetime object."""
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


def load_logs(filepath: str) -> list[dict]:
    """
    Read a log file and return list of parsed log entries.
    Skips malformed or comment lines silently.
    """
    entries = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed:
                    entries.append(parsed)
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {filepath}")
    return entries


# ─────────────────────────────────────────────
#  IP & User Helpers
# ─────────────────────────────────────────────

def is_private_ip(ip: str) -> bool:
    """Check if an IP is RFC-1918 private."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10 or
            (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168)
        )
    except ValueError:
        return False


def is_external_ip(ip: str) -> bool:
    return ip is not None and not is_private_ip(ip)


def is_suspicious_hour(dt: datetime, suspicious_hours: list) -> bool:
    """Return True if login hour falls in suspicious time window."""
    if dt is None:
        return False
    return dt.hour in suspicious_hours


# ─────────────────────────────────────────────
#  Output Helpers
# ─────────────────────────────────────────────

RISK_COLOR = {
    "LOW":      "\033[33m",
    "MEDIUM":   "\033[38;5;208m",
    "HIGH":     "\033[31m",
    "CRITICAL": "\033[35m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def colorize(text: str, risk_level: str) -> str:
    color = RISK_COLOR.get(risk_level, "")
    return f"{BOLD}{color}{text}{RESET}"


def format_alert_console(alert) -> str:
    """Format an Alert object for console output."""
    from rules import get_mitre
    color = RISK_COLOR.get(alert.risk_level, "")
    mitre = get_mitre(alert.rule_name)
    lines = [
        f"{BOLD}{color}{'─'*60}{RESET}",
        f"{BOLD}{color}[{alert.risk_level}] {alert.message}{RESET}",
        f"  📅  Timestamp : {alert.timestamp}",
        f"  🌐  IP        : {alert.ip or 'N/A'}",
        f"  👤  User      : {alert.user or 'N/A'}",
        f"  📋  Rule      : {alert.rule_name}",
        f"  🎯  MITRE     : {mitre}",
    ]
    for k, v in alert.details.items():
        lines.append(f"  ℹ️   {k:<10}: {v}")
    return "\n".join(lines)


def format_alert_text(alert) -> str:
    """Plain-text version for writing to alerts.txt."""
    from rules import get_mitre
    mitre = get_mitre(alert.rule_name)
    lines = [
        f"{'─'*60}",
        f"[{alert.risk_level}] {alert.message}",
        f"  Timestamp : {alert.timestamp}",
        f"  IP        : {alert.ip or 'N/A'}",
        f"  User      : {alert.user or 'N/A'}",
        f"  Rule      : {alert.rule_name}",
        f"  MITRE     : {mitre}",
    ]
    for k, v in alert.details.items():
        lines.append(f"  {k:<10}: {v}")
    return "\n".join(lines)


def save_alerts_txt(alerts: list, filepath: str):
    """Write all alerts to a plain-text file."""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("  SECURITY LOG ANALYZER — ALERT REPORT\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Total Alerts: {len(alerts)}\n")
        f.write("=" * 60 + "\n\n")
        for alert in alerts:
            f.write(format_alert_text(alert) + "\n\n")


def save_alerts_csv(alerts: list, filepath: str):
    """Write all alerts to a CSV file."""
    import csv
    from rules import get_mitre

    if not alerts:
        return

    fieldnames = ["timestamp", "risk_level", "rule", "ip", "user", "message", "mitre"]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            writer.writerow({
                "timestamp":  alert.timestamp,
                "risk_level": alert.risk_level,
                "rule":       alert.rule_name,
                "ip":         alert.ip or "",
                "user":       alert.user or "",
                "message":    alert.message,
                "mitre":      get_mitre(alert.rule_name),
            })
