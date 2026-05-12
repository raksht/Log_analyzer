# rules.py — Rule-Based Detection Engine
# Centralized configuration for all detection thresholds and logic

from dataclasses import dataclass, field
from typing import List


# ─────────────────────────────────────────────
#  Risk Level Constants
# ─────────────────────────────────────────────

class RiskLevel:
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"
    CRITICAL = "CRITICAL"

    SCORES = {
        LOW:      1,
        MEDIUM:   2,
        HIGH:     3,
        CRITICAL: 4,
    }

    COLORS = {
        LOW:      "\033[33m",    # Yellow
        MEDIUM:   "\033[38;5;208m",  # Orange
        HIGH:     "\033[31m",    # Red
        CRITICAL: "\033[35m",    # Magenta
    }

    RESET = "\033[0m"


# ─────────────────────────────────────────────
#  Alert Data Class
# ─────────────────────────────────────────────

@dataclass
class Alert:
    rule_name:   str
    risk_level:  str
    message:     str
    ip:          str
    user:        str
    timestamp:   str
    details:     dict = field(default_factory=dict)

    def risk_score(self) -> int:
        return RiskLevel.SCORES.get(self.risk_level, 0)

    def to_dict(self) -> dict:
        return {
            "timestamp":  self.timestamp,
            "rule":       self.rule_name,
            "risk_level": self.risk_level,
            "ip":         self.ip,
            "user":       self.user,
            "message":    self.message,
            **self.details,
        }


# ─────────────────────────────────────────────
#  Detection Rules
# ─────────────────────────────────────────────

RULES = {

    # --- Brute Force ---
    "brute_force": {
        "description":          "Repeated failed logins from a single IP",
        "failed_login_threshold": 3,       # trigger after N failures
        "risk_level":           RiskLevel.HIGH,
        "enabled":              True,
    },

    # --- Credential Stuffing ---
    "credential_stuffing": {
        "description":          "Single IP trying multiple different usernames",
        "unique_user_threshold": 4,        # N distinct usernames from same IP
        "risk_level":           RiskLevel.HIGH,
        "enabled":              True,
    },

    # --- Time Anomaly ---
    "off_hours_login": {
        "description":          "Successful login during off-hours",
        "suspicious_hours":     [0, 1, 2, 3, 4, 5],   # midnight – 5 AM
        "risk_level":           RiskLevel.MEDIUM,
        "enabled":              True,
    },

    # --- Sensitive File Access ---
    "sensitive_file_access": {
        "description":          "Access to system-critical or sensitive files",
        "sensitive_paths": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/root/",
            "/.ssh/",
            "/var/log/auth.log",
            "id_rsa",
            "config.php",
        ],
        "risk_level":           RiskLevel.MEDIUM,
        "enabled":              True,
    },

    # --- Fail-then-Succeed (Possible Breach) ---
    "fail_then_succeed": {
        "description":          "Multiple failures followed by a success (possible breach)",
        "fail_window_seconds":  120,       # look-back window
        "min_failures_before":  3,
        "risk_level":           RiskLevel.CRITICAL,
        "enabled":              True,
    },

    # --- Port Scan ---
    "port_scan": {
        "description":          "Port scanning activity detected",
        "risk_level":           RiskLevel.HIGH,
        "enabled":              True,
    },

    # --- Rapid Request (DoS-like) ---
    "rapid_requests": {
        "description":          "Abnormally high request rate from a single IP",
        "count_threshold":      8,         # N events within the time window
        "window_seconds":       10,
        "risk_level":           RiskLevel.HIGH,
        "enabled":              True,
    },

    # --- Multiple Sensitive File Accesses ---
    "file_enum": {
        "description":          "Accessing multiple sensitive files (possible enumeration)",
        "access_threshold":     3,
        "risk_level":           RiskLevel.HIGH,
        "enabled":              True,
    },
}


# ─────────────────────────────────────────────
#  Mitre ATT&CK Mappings
# ─────────────────────────────────────────────

MITRE_MAPPING = {
    "brute_force":          ("T1110.001", "Brute Force: Password Guessing"),
    "credential_stuffing":  ("T1110.004", "Brute Force: Credential Stuffing"),
    "off_hours_login":      ("T1078",     "Valid Accounts"),
    "sensitive_file_access":("T1083",     "File and Directory Discovery"),
    "fail_then_succeed":    ("T1078",     "Valid Accounts — Possible Compromise"),
    "port_scan":            ("T1046",     "Network Service Scanning"),
    "rapid_requests":       ("T1499",     "Endpoint Denial of Service"),
    "file_enum":            ("T1083",     "File and Directory Discovery"),
}


def get_mitre(rule_name: str) -> str:
    """Return formatted MITRE ATT&CK reference for a rule."""
    entry = MITRE_MAPPING.get(rule_name)
    if entry:
        return f"{entry[0]} — {entry[1]}"
    return "N/A"
