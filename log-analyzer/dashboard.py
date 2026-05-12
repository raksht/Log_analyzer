# dashboard.py — Streamlit SIEM Dashboard
# Run: streamlit run dashboard.py

import os
if not os.path.exists("Log_analyzer/blob/main/log-analyzer/logs/sample_logs.txt"):
    st.warning("Sample log file not found. couldnt Please upload a log file.")

import sys
import streamlit as st
import pandas as pd
from datetime import datetime

# ── ensure local imports work ──────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from analyzer import LogAnalyzer
from rules import RiskLevel

# ─────────────────────────────────────────────
#  Page Config
# ─────────────────────────────────────────────

st.set_page_config(
    page_title="Security Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
#  Custom CSS — Dark terminal aesthetic
# ─────────────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');

/* ── Base ── */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #0a0e1a !important;
    color: #c8d8e8 !important;
    font-family: 'Share Tech Mono', monospace !important;
}

[data-testid="stSidebar"] {
    background: #0d1321 !important;
    border-right: 1px solid #1e3a5f;
}

/* ── Header ── */
.main-header {
    font-family: 'Orbitron', monospace;
    font-size: 2.2rem;
    font-weight: 900;
    color: #00d4ff;
    text-shadow: 0 0 20px rgba(0, 212, 255, 0.5);
    letter-spacing: 2px;
    margin-bottom: 0.2rem;
}
.sub-header {
    color: #5a8a9f;
    font-size: 0.85rem;
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 1.5rem;
}

/* ── Metric Cards ── */
.metric-card {
    background: #0d1321;
    border: 1px solid #1e3a5f;
    border-radius: 6px;
    padding: 1.2rem 1.5rem;
    text-align: center;
    position: relative;
    overflow: hidden;
}
.metric-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
}
.metric-card.critical::before { background: #ff00ff; }
.metric-card.high::before     { background: #ff3333; }
.metric-card.medium::before   { background: #ff8800; }
.metric-card.low::before      { background: #ffcc00; }
.metric-card.total::before    { background: #00d4ff; }

.metric-value {
    font-family: 'Orbitron', monospace;
    font-size: 2.5rem;
    font-weight: 700;
}
.metric-card.critical .metric-value { color: #ff00ff; text-shadow: 0 0 10px #ff00ff88; }
.metric-card.high     .metric-value { color: #ff3333; text-shadow: 0 0 10px #ff333388; }
.metric-card.medium   .metric-value { color: #ff8800; text-shadow: 0 0 10px #ff880088; }
.metric-card.low      .metric-value { color: #ffcc00; text-shadow: 0 0 10px #ffcc0088; }
.metric-card.total    .metric-value { color: #00d4ff; text-shadow: 0 0 10px #00d4ff88; }

.metric-label {
    font-size: 0.7rem;
    letter-spacing: 2px;
    color: #5a8a9f;
    text-transform: uppercase;
    margin-top: 0.3rem;
}

/* ── Alert rows ── */
.alert-row {
    background: #0d1321;
    border: 1px solid #1e3a5f;
    border-left: 4px solid #1e3a5f;
    border-radius: 4px;
    padding: 0.8rem 1rem;
    margin-bottom: 0.5rem;
    font-size: 0.88rem;
}
.alert-row.CRITICAL { border-left-color: #ff00ff; }
.alert-row.HIGH     { border-left-color: #ff3333; }
.alert-row.MEDIUM   { border-left-color: #ff8800; }
.alert-row.LOW      { border-left-color: #ffcc00; }

.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: bold;
    letter-spacing: 1px;
    margin-right: 8px;
}
.badge.CRITICAL { background: #ff00ff22; color: #ff00ff; border: 1px solid #ff00ff55; }
.badge.HIGH     { background: #ff333322; color: #ff3333; border: 1px solid #ff333355; }
.badge.MEDIUM   { background: #ff880022; color: #ff8800; border: 1px solid #ff880055; }
.badge.LOW      { background: #ffcc0022; color: #ffcc00; border: 1px solid #ffcc0055; }

/* ── Section headings ── */
.section-title {
    font-family: 'Orbitron', monospace;
    font-size: 0.9rem;
    color: #00d4ff;
    letter-spacing: 3px;
    text-transform: uppercase;
    border-bottom: 1px solid #1e3a5f;
    padding-bottom: 0.4rem;
    margin: 1.5rem 0 1rem 0;
}

/* ── Terminal log ── */
.log-box {
    background: #060a12;
    border: 1px solid #1e3a5f;
    border-radius: 4px;
    padding: 1rem;
    font-size: 0.78rem;
    max-height: 300px;
    overflow-y: auto;
    line-height: 1.6;
}
.log-line { color: #7a9fbf; }
.log-line.fail  { color: #ff6666; }
.log-line.ok    { color: #33ff99; }
.log-line.scan  { color: #ffaa00; }

/* ── Streamlit overrides ── */
[data-testid="stMetricValue"] { color: #00d4ff !important; }
.stButton > button {
    background: #0d1321 !important;
    color: #00d4ff !important;
    border: 1px solid #1e3a5f !important;
    font-family: 'Share Tech Mono', monospace !important;
}
.stButton > button:hover {
    border-color: #00d4ff !important;
    box-shadow: 0 0 8px #00d4ff44 !important;
}
[data-testid="stDataFrame"] { background: #0d1321 !important; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  Sidebar Controls
# ─────────────────────────────────────────────

with st.sidebar:
    st.markdown("### 🛡️ SIEM Controls")
    st.markdown("---")

    log_path = st.text_input(
        "Log File Path",
        value="logs/sample_logs.txt",
        help="Path to the log file to analyze"
    )

    st.markdown("#### Risk Level Filter")
    show_critical = st.checkbox("CRITICAL", value=True)
    show_high     = st.checkbox("HIGH",     value=True)
    show_medium   = st.checkbox("MEDIUM",   value=True)
    show_low      = st.checkbox("LOW",      value=True)

    st.markdown("---")
    run_btn = st.button("▶  RUN ANALYSIS", use_container_width=True)

    st.markdown("---")
    st.markdown("**Export**")
    export_btn = st.button("💾  Export Reports", use_container_width=True)

    st.markdown("---")
    st.caption("Security Log Analyzer v1.0")
    st.caption("MITRE ATT&CK mapped")


# ─────────────────────────────────────────────
#  Header
# ─────────────────────────────────────────────

st.markdown('<div class="main-header">🛡 SECURITY LOG ANALYZER</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">mini SIEM · threat detection · MITRE ATT&CK mapped</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  Session State
# ─────────────────────────────────────────────

if "alerts"    not in st.session_state: st.session_state.alerts    = []
if "logs"      not in st.session_state: st.session_state.logs      = []
if "analyzed"  not in st.session_state: st.session_state.analyzed  = False
if "engine"    not in st.session_state: st.session_state.engine    = None


# ─────────────────────────────────────────────
#  Run Analysis
# ─────────────────────────────────────────────

if run_btn:
    with st.spinner("Analyzing logs..."):
        try:
            engine = LogAnalyzer(log_path)
            engine.load()
            engine.analyze()
            st.session_state.alerts   = engine.alerts
            st.session_state.logs     = engine.logs
            st.session_state.analyzed = True
            st.session_state.engine   = engine
        except Exception as e:
            st.error(f"Error: {e}")

if export_btn and st.session_state.engine:
    st.session_state.engine.export("output")
    st.success("✅ Reports saved to output/alerts.txt and output/alerts.csv")


# ─────────────────────────────────────────────
#  Dashboard Content
# ─────────────────────────────────────────────

if not st.session_state.analyzed:
    st.info("👆 Set log path in sidebar and click **RUN ANALYSIS** to begin.")
    st.stop()

alerts = st.session_state.alerts
logs   = st.session_state.logs

# Filter alerts
shown_levels = []
if show_critical: shown_levels.append("CRITICAL")
if show_high:     shown_levels.append("HIGH")
if show_medium:   shown_levels.append("MEDIUM")
if show_low:      shown_levels.append("LOW")

filtered_alerts = [a for a in alerts if a.risk_level in shown_levels]

from rules import get_mitre


# ── KPI Cards ────────────────────────────────

def count_by_level(level):
    return sum(1 for a in alerts if a.risk_level == level)

cols = st.columns(5)

kpi_data = [
    ("total",    "TOTAL ALERTS",    len(alerts)),
    ("critical", "CRITICAL",        count_by_level("CRITICAL")),
    ("high",     "HIGH",            count_by_level("HIGH")),
    ("medium",   "MEDIUM",          count_by_level("MEDIUM")),
    ("low",      "LOW",             count_by_level("LOW")),
]

for col, (cls, label, val) in zip(cols, kpi_data):
    with col:
        st.markdown(f"""
        <div class="metric-card {cls}">
            <div class="metric-value">{val}</div>
            <div class="metric-label">{label}</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("")

# ── Charts Row ───────────────────────────────

col1, col2 = st.columns([1, 1])

with col1:
    st.markdown('<div class="section-title">Alerts by Risk Level</div>', unsafe_allow_html=True)
    level_counts = {
        "CRITICAL": count_by_level("CRITICAL"),
        "HIGH":     count_by_level("HIGH"),
        "MEDIUM":   count_by_level("MEDIUM"),
        "LOW":      count_by_level("LOW"),
    }
    df_levels = pd.DataFrame(
        list(level_counts.items()), columns=["Risk Level", "Count"]
    ).set_index("Risk Level")
    st.bar_chart(df_levels, color="#00d4ff", height=220)

with col2:
    st.markdown('<div class="section-title">Alerts by Detection Rule</div>', unsafe_allow_html=True)
    from collections import Counter
    rule_counts = Counter(a.rule_name for a in alerts)
    df_rules = pd.DataFrame(
        list(rule_counts.items()), columns=["Rule", "Count"]
    ).set_index("Rule")
    st.bar_chart(df_rules, color="#ff8800", height=220)

# ── Top Threat IPs ────────────────────────────

st.markdown('<div class="section-title">🌐 Top Threat IPs</div>', unsafe_allow_html=True)

ip_counts = Counter(a.ip for a in alerts if a.ip not in ("N/A", None, ""))
top_ips   = ip_counts.most_common(10)

if top_ips:
    df_ips = pd.DataFrame(top_ips, columns=["IP Address", "Alert Count"])
    df_ips["Risk"] = df_ips["IP Address"].apply(
        lambda ip: max(
            (a.risk_level for a in alerts if a.ip == ip),
            key=lambda r: RiskLevel.SCORES.get(r, 0),
            default="N/A"
        )
    )
    st.dataframe(df_ips, use_container_width=True, hide_index=True)

# ── Alert Feed ────────────────────────────────

st.markdown(f'<div class="section-title">🚨 Alert Feed ({len(filtered_alerts)} alerts)</div>', unsafe_allow_html=True)

if not filtered_alerts:
    st.success("No alerts for selected risk levels.")
else:
    for alert in filtered_alerts:
        mitre = get_mitre(alert.rule_name)
        badge = f'<span class="badge {alert.risk_level}">{alert.risk_level}</span>'
        st.markdown(f"""
        <div class="alert-row {alert.risk_level}">
            {badge}
            <strong>{alert.message}</strong><br>
            <small style="color:#5a8a9f">
                🕐 {alert.timestamp} &nbsp;|&nbsp;
                🌐 {alert.ip or 'N/A'} &nbsp;|&nbsp;
                👤 {alert.user or 'N/A'} &nbsp;|&nbsp;
                🎯 {mitre}
            </small>
        </div>
        """, unsafe_allow_html=True)

# ── Raw Log Viewer ────────────────────────────

with st.expander("📄 Raw Log Viewer"):
    st.markdown('<div class="section-title">System Logs</div>', unsafe_allow_html=True)
    lines = []
    for entry in logs:
        raw = entry.get("raw", "")
        css = ""
        if "FAILED" in raw:    css = "fail"
        elif "SUCCESS" in raw: css = "ok"
        elif "SCAN" in raw:    css = "scan"
        lines.append(f'<div class="log-line {css}">{raw}</div>')

    st.markdown(
        f'<div class="log-box">{"".join(lines)}</div>',
        unsafe_allow_html=True
    )

# ── Full Alert Table ──────────────────────────

with st.expander("📊 Full Alert Table (CSV Preview)"):
    if alerts:
        df_export = pd.DataFrame([a.to_dict() for a in filtered_alerts])
        st.dataframe(df_export, use_container_width=True)

        csv_data = df_export.to_csv(index=False)
        st.download_button(
            label     = "⬇ Download as CSV",
            data      = csv_data,
            file_name = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime      = "text/csv",
        )

# ── Footer ────────────────────────────────────

st.markdown("---")
st.markdown(
    '<div style="text-align:center; color:#2a4a6a; font-size:0.75rem; font-family:Share Tech Mono;">'
    'Security Log Analyzer · Built with Python + Streamlit · MITRE ATT&CK Mapped'
    '</div>',
    unsafe_allow_html=True
)
