# analyzer.py — Core Security Log Analysis Engine
# Run:  python analyzer.py [--log logs/sample_logs.txt] [--out output/]

import os
import sys
import argparse
from collections import defaultdict
from datetime import timedelta

from rules import RULES, RiskLevel, Alert
from utils import (
    load_logs, is_suspicious_hour, format_alert_console,
    save_alerts_txt, save_alerts_csv, BOLD, RESET
)


# ─────────────────────────────────────────────
#  Detection Functions
# ─────────────────────────────────────────────

def detect_brute_force(logs: list) -> list[Alert]:
    """Rule: >= N failed logins from the same IP."""
    rule = RULES["brute_force"]
    if not rule["enabled"]:
        return []

    threshold = rule["failed_login_threshold"]
    failed_counts: dict[str, list] = defaultdict(list)

    for entry in logs:
        if entry["event_type"] == "LOGIN" and entry["status"] == "FAILED":
            ip = entry.get("ip") or "unknown"
            failed_counts[ip].append(entry)

    alerts = []
    for ip, entries in failed_counts.items():
        if len(entries) >= threshold:
            first = entries[0]
            alerts.append(Alert(
                rule_name  = "brute_force",
                risk_level = rule["risk_level"],
                message    = f"Brute force attack detected from {ip}",
                ip         = ip,
                user       = first.get("user", "multiple"),
                timestamp  = first["timestamp"],
                details    = {
                    "failed_count": len(entries),
                    "threshold":    threshold,
                },
            ))
    return alerts


def detect_credential_stuffing(logs: list) -> list[Alert]:
    """Rule: single IP trying >= N different usernames."""
    rule = RULES["credential_stuffing"]
    if not rule["enabled"]:
        return []

    threshold = rule["unique_user_threshold"]
    ip_users: dict[str, set] = defaultdict(set)

    for entry in logs:
        if entry["event_type"] == "LOGIN" and entry["status"] == "FAILED":
            ip   = entry.get("ip")   or "unknown"
            user = entry.get("user") or "unknown"
            ip_users[ip].add(user)

    alerts = []
    for ip, users in ip_users.items():
        if len(users) >= threshold:
            alerts.append(Alert(
                rule_name  = "credential_stuffing",
                risk_level = rule["risk_level"],
                message    = f"Credential stuffing suspected from {ip} ({len(users)} usernames tried)",
                ip         = ip,
                user       = ", ".join(sorted(users)),
                timestamp  = "various",
                details    = {
                    "unique_users":  len(users),
                    "usernames":     ", ".join(sorted(users)),
                    "threshold":     threshold,
                },
            ))
    return alerts


def detect_off_hours_login(logs: list) -> list[Alert]:
    """Rule: successful login during suspicious hours."""
    rule = RULES["off_hours_login"]
    if not rule["enabled"]:
        return []

    suspicious_hours = rule["suspicious_hours"]
    alerts = []

    for entry in logs:
        if entry["event_type"] == "LOGIN" and entry["status"] == "SUCCESS":
            dt = entry.get("datetime")
            if is_suspicious_hour(dt, suspicious_hours):
                alerts.append(Alert(
                    rule_name  = "off_hours_login",
                    risk_level = rule["risk_level"],
                    message    = f"Off-hours login at {entry['timestamp']} by {entry.get('user', 'unknown')}",
                    ip         = entry.get("ip", "unknown"),
                    user       = entry.get("user", "unknown"),
                    timestamp  = entry["timestamp"],
                    details    = {
                        "hour":       dt.hour if dt else "?",
                        "off_hours":  f"{min(suspicious_hours)}:00–{max(suspicious_hours)+1}:00",
                    },
                ))
    return alerts


def detect_sensitive_file_access(logs: list) -> list[Alert]:
    """Rule: access to any known-sensitive file path."""
    rule = RULES["sensitive_file_access"]
    if not rule["enabled"]:
        return []

    sensitive_paths = rule["sensitive_paths"]
    alerts = []

    for entry in logs:
        if entry["event_type"] == "FILE_ACCESS":
            filepath = entry.get("file") or ""
            hit = next((s for s in sensitive_paths if s in filepath), None)
            if hit:
                alerts.append(Alert(
                    rule_name  = "sensitive_file_access",
                    risk_level = rule["risk_level"],
                    message    = f"Sensitive file accessed: {filepath} by {entry.get('user', 'unknown')}",
                    ip         = entry.get("ip", "unknown"),
                    user       = entry.get("user", "unknown"),
                    timestamp  = entry["timestamp"],
                    details    = {
                        "file":        filepath,
                        "matched_rule": hit,
                        "action":      entry.get("action", "N/A"),
                    },
                ))
    return alerts


def detect_fail_then_succeed(logs: list) -> list[Alert]:
    """Rule: IP with multiple failures followed by a success (possible breach)."""
    rule = RULES["fail_then_succeed"]
    if not rule["enabled"]:
        return []

    min_failures = rule["min_failures_before"]
    window_secs  = rule["fail_window_seconds"]

    # Group failures by IP
    ip_failures: dict[str, list] = defaultdict(list)
    ip_successes: dict[str, list] = defaultdict(list)

    for entry in logs:
        if entry["event_type"] != "LOGIN":
            continue
        ip = entry.get("ip") or "unknown"
        if entry["status"] == "FAILED":
            ip_failures[ip].append(entry)
        elif entry["status"] == "SUCCESS":
            ip_successes[ip].append(entry)

    alerts = []
    for ip, successes in ip_successes.items():
        failures = ip_failures.get(ip, [])
        if len(failures) < min_failures:
            continue

        for success in successes:
            success_dt = success.get("datetime")
            if not success_dt:
                continue

            # Count failures within window before this success
            window_start = success_dt - timedelta(seconds=window_secs)
            recent_failures = [
                f for f in failures
                if f.get("datetime") and window_start <= f["datetime"] < success_dt
            ]

            if len(recent_failures) >= min_failures:
                alerts.append(Alert(
                    rule_name  = "fail_then_succeed",
                    risk_level = rule["risk_level"],
                    message    = (
                        f"POSSIBLE BREACH: {len(recent_failures)} failures then success "
                        f"from {ip} for user '{success.get('user', 'unknown')}'"
                    ),
                    ip         = ip,
                    user       = success.get("user", "unknown"),
                    timestamp  = success["timestamp"],
                    details    = {
                        "failures_before": len(recent_failures),
                        "window_seconds":  window_secs,
                    },
                ))
    return alerts


def detect_port_scan(logs: list) -> list[Alert]:
    """Rule: PORT_SCAN event in logs."""
    rule = RULES["port_scan"]
    if not rule["enabled"]:
        return []

    alerts = []
    for entry in logs:
        if entry["event_type"] == "PORT_SCAN":
            ip    = entry.get("ip", "unknown")
            ports = entry.get("ports_scanned", "unknown")
            alerts.append(Alert(
                rule_name  = "port_scan",
                risk_level = rule["risk_level"],
                message    = f"Port scan detected from {ip}",
                ip         = ip,
                user       = "N/A",
                timestamp  = entry["timestamp"],
                details    = {
                    "ports_scanned": ports,
                    "duration":      entry.get("duration", "N/A"),
                },
            ))
    return alerts


def detect_rapid_requests(logs: list) -> list[Alert]:
    """Rule: >= N LOGIN events from same IP within a short window (DoS-like)."""
    rule = RULES["rapid_requests"]
    if not rule["enabled"]:
        return []

    threshold = rule["count_threshold"]
    window    = rule["window_seconds"]

    # Collect all login events per IP (sorted by time)
    ip_events: dict[str, list] = defaultdict(list)
    for entry in logs:
        if entry["event_type"] == "LOGIN" and entry.get("datetime"):
            ip = entry.get("ip") or "unknown"
            ip_events[ip].append(entry)

    alerts = []
    alerted_ips = set()

    for ip, events in ip_events.items():
        events.sort(key=lambda e: e["datetime"])
        for i, event in enumerate(events):
            base_dt = event["datetime"]
            window_events = [
                e for e in events
                if 0 <= (e["datetime"] - base_dt).total_seconds() <= window
            ]
            if len(window_events) >= threshold and ip not in alerted_ips:
                alerted_ips.add(ip)
                alerts.append(Alert(
                    rule_name  = "rapid_requests",
                    risk_level = rule["risk_level"],
                    message    = f"Rapid login attempts (DoS-like) from {ip}: {len(window_events)} in {window}s",
                    ip         = ip,
                    user       = event.get("user", "unknown"),
                    timestamp  = event["timestamp"],
                    details    = {
                        "events_in_window": len(window_events),
                        "window_seconds":   window,
                    },
                ))
    return alerts


def detect_file_enumeration(logs: list) -> list[Alert]:
    """Rule: user/IP accessing >= N sensitive files (enumeration)."""
    rule_s    = RULES["sensitive_file_access"]
    rule_e    = RULES["file_enum"]
    if not rule_e["enabled"]:
        return []

    sensitive_paths = rule_s["sensitive_paths"]
    threshold       = rule_e["access_threshold"]

    # Track sensitive accesses per (ip, user)
    actor_hits: dict[tuple, list] = defaultdict(list)
    for entry in logs:
        if entry["event_type"] == "FILE_ACCESS":
            filepath = entry.get("file") or ""
            if any(s in filepath for s in sensitive_paths):
                key = (entry.get("ip", "?"), entry.get("user", "?"))
                actor_hits[key].append(entry)

    alerts = []
    for (ip, user), entries in actor_hits.items():
        if len(entries) >= threshold:
            files = [e.get("file", "?") for e in entries]
            alerts.append(Alert(
                rule_name  = "file_enum",
                risk_level = rule_e["risk_level"],
                message    = f"File enumeration by '{user}' from {ip}: {len(files)} sensitive files accessed",
                ip         = ip,
                user       = user,
                timestamp  = entries[0]["timestamp"],
                details    = {
                    "files_accessed": len(files),
                    "files":          " | ".join(files),
                },
            ))
    return alerts


# ─────────────────────────────────────────────
#  Main Analyzer
# ─────────────────────────────────────────────

class LogAnalyzer:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.logs:   list = []
        self.alerts: list[Alert] = []

    def load(self):
        self.logs = load_logs(self.log_path)
        print(f"{BOLD}[*] Loaded {len(self.logs)} log entries from '{self.log_path}'{RESET}")

    def analyze(self):
        detectors = [
            detect_brute_force,
            detect_credential_stuffing,
            detect_off_hours_login,
            detect_sensitive_file_access,
            detect_fail_then_succeed,
            detect_port_scan,
            detect_rapid_requests,
            detect_file_enumeration,
        ]

        print(f"{BOLD}[*] Running {len(detectors)} detection rules...{RESET}\n")

        for detector in detectors:
            found = detector(self.logs)
            self.alerts.extend(found)

        # Sort by risk level (highest first) then timestamp
        self.alerts.sort(key=lambda a: (-a.risk_score(), a.timestamp))

    def print_summary(self):
        counts = {r: 0 for r in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]}
        for alert in self.alerts:
            counts[alert.risk_level] = counts.get(alert.risk_level, 0) + 1

        print(f"\n{BOLD}{'═'*60}")
        print("  SECURITY ANALYSIS SUMMARY")
        print(f"{'═'*60}{RESET}")
        print(f"  Log File     : {self.log_path}")
        print(f"  Entries      : {len(self.logs)}")
        print(f"  Total Alerts : {len(self.alerts)}")
        print()
        for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            c = counts.get(level, 0)
            from utils import RISK_COLOR
            color = RISK_COLOR.get(level, "")
            print(f"  {BOLD}{color}{level:<10}{RESET}  {c} alert(s)")
        print(f"{BOLD}{'═'*60}{RESET}\n")

    def print_alerts(self):
        if not self.alerts:
            print("[✓] No threats detected.")
            return
        for alert in self.alerts:
            print(format_alert_console(alert))
            print()

    def export(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        txt_path = os.path.join(output_dir, "alerts.txt")
        csv_path = os.path.join(output_dir, "alerts.csv")

        save_alerts_txt(self.alerts, txt_path)
        save_alerts_csv(self.alerts, csv_path)

        print(f"\n{BOLD}[✓] Reports saved:{RESET}")
        print(f"    📄  {txt_path}")
        print(f"    📊  {csv_path}")

    def get_alerts_as_dicts(self) -> list[dict]:
        return [a.to_dict() for a in self.alerts]


# ─────────────────────────────────────────────
#  CLI Entry Point
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer — mini SIEM engine"
    )
    parser.add_argument(
        "--log",
        default="logs/sample_logs.txt",
        help="Path to the log file (default: logs/sample_logs.txt)",
    )
    parser.add_argument(
        "--out",
        default="output",
        help="Output directory for reports (default: output/)",
    )
    parser.add_argument(
        "--no-export",
        action="store_true",
        help="Skip exporting alerts to files",
    )
    args = parser.parse_args()

    engine = LogAnalyzer(args.log)
    engine.load()
    engine.analyze()
    engine.print_summary()
    engine.print_alerts()

    if not args.no_export:
        engine.export(args.out)


if __name__ == "__main__":
    main()
