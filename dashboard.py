"""
dashboard.py - shelLM Web Dashboard + Real-time Alerts
Run this alongside your honeypot to monitor activity
Visit http://localhost:5000 in your browser
"""

import os
import json
import glob
import datetime
import threading
import subprocess
from pathlib import Path
from flask import Flask, render_template_string, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

LOGS_DIR = Path("logs")
SESSIONS_DIR = Path("sessions")

# Track last seen events for alerts
last_seen_connections = set()
last_seen_commands = {}

# â”€â”€ Windows Desktop Notification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def windows_notify(title, message):
    """
    Safe notification function.
    Prevents WPARAM errors caused by win10toast.
    """
    try:
        print(f"[NOTIFICATION] {title}: {message}")

        from plyer import notification

        notification.notify(
            title=title,
            message=message,
            app_name="shelLM",
            timeout=5
        )
    except Exception as e:
        print(f"[NOTIFICATION FAILED] {e}")

# â”€â”€ Log Parsing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def get_all_sessions():
    sessions = []
    for f in sorted(SESSIONS_DIR.glob("*.json"), reverse=True)[:20]:
        try:
            with open(f, encoding="utf-8") as fp:
                data = json.load(fp)
                sessions.append(data)
        except Exception:
            pass
    return sessions

def get_recent_commands(limit=50):
    commands = []
    for f in sorted(LOGS_DIR.glob("*.log"), reverse=True)[:10]:
        if "_trace" in f.name:
            continue
        try:
            with open(f, encoding="utf-8", errors="ignore") as fp:
                content = fp.read()
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if line.startswith("$ "):
                    cmd = line[2:]
                    response = lines[i+1] if i+1 < len(lines) else ""
                    ts_line = lines[i-1] if i > 0 else ""
                    commands.append({
                        "command": cmd,
                        "response": response[:100],
                        "session": f.stem,
                        "timestamp": ts_line
                    })
        except Exception:
            pass
    return commands[-limit:]

def get_auth_attempts():
    attempts = []
    auth_log = LOGS_DIR / "auth_attempts.log"
    if auth_log.exists():
        with open(auth_log, encoding="utf-8", errors="ignore") as f:
            for line in f.readlines()[-20:]:
                attempts.append(line.strip())
    return attempts

def get_connections():
    conns = []
    conn_log = LOGS_DIR / "connections.log"
    if conn_log.exists():
        with open(conn_log, encoding="utf-8", errors="ignore") as f:
            for line in f.readlines()[-20:]:
                conns.append(line.strip())
    return conns

def get_stats():
    sessions = list(SESSIONS_DIR.glob("*.json"))
    logs = [f for f in LOGS_DIR.glob("*.log") if "_trace" not in f.name]
    trace_logs = list(LOGS_DIR.glob("*_trace.log"))
    total_commands = 0
    for f in logs:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            total_commands += content.count("\n$ ")
        except:
            pass
    return {
        "total_sessions": len(sessions),
        "total_logs": len(logs),
        "total_trace_logs": len(trace_logs),
        "total_commands": total_commands
    }

# â”€â”€ Alert Monitor Thread â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def monitor_alerts():
    global last_seen_connections, last_seen_commands
    while True:
        try:
            # Check new connections
            conn_log = LOGS_DIR / "connections.log"
            if conn_log.exists():
                with open(conn_log, encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                for line in lines:
                    if line.strip() and line.strip() not in last_seen_connections:
                        last_seen_connections.add(line.strip())
                        ip = "unknown"
                        if "from" in line:
                            ip = line.split("from")[1].split()[0]
                        windows_notify(
                            "shelLM - New Connection!",
                            f"Attacker connected from {ip}"
                        )
                        print(f"[ALERT] New connection from {ip}")

            # Check new auth attempts
            auth_log = LOGS_DIR / "auth_attempts.log"
            if auth_log.exists():
                with open(auth_log, encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                for line in lines:
                    if line.strip() and line.strip() not in last_seen_connections:
                        last_seen_connections.add(line.strip())
                        windows_notify(
                            "shelLM - Login Attempt!",
                            line.strip()[:80]
                        )

        except Exception as e:
            pass
        threading.Event().wait(3)  # check every 3 seconds

# â”€â”€ HTML Dashboard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>ShelLM Dashboard</title>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="5">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', monospace; }
        .header { background: #161b22; padding: 16px 24px; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 12px; }
        .header h1 { font-size: 18px; color: #39d353; }
        .header .dot { width: 10px; height: 10px; border-radius: 50%; background: #39d353; animation: blink 1s infinite; }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; padding: 20px 24px; }
        .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
        .stat-card .num { font-size: 32px; font-weight: bold; color: #39d353; }
        .stat-card .label { font-size: 12px; color: #8b949e; margin-top: 4px; }
        .section { padding: 0 24px 20px; }
        .section h2 { font-size: 14px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; padding-bottom: 6px; border-bottom: 1px solid #21262d; }
        .log-table { width: 100%; border-collapse: collapse; font-size: 12px; }
        .log-table th { background: #21262d; padding: 8px 10px; text-align: left; color: #8b949e; }
        .log-table td { padding: 7px 10px; border-bottom: 1px solid #21262d; vertical-align: top; }
        .log-table tr:hover td { background: #161b22; }
        .cmd { color: #39d353; font-family: monospace; }
        .resp { color: #8b949e; font-size: 11px; }
        .session-id { color: #58a6ff; font-size: 11px; }
        .alert-box { background: #1c2128; border: 1px solid #f85149; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; font-size: 12px; }
        .alert-box.green { border-color: #39d353; }
        .ts { color: #8b949e; font-size: 11px; }
        ..grid2 {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: 20px;
}

.grid2 > div {
    min-width: 0;
}

.log-table {
    width: 100%;
    table-layout: fixed;
    border-collapse: collapse;
    font-size: 12px;
}

.log-table th,
.log-table td {
    overflow-wrap: anywhere;
    word-break: break-word;
}
        .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; background: #1c2128; color: #39d353; border: 1px solid #39d353; margin-left: 8px; }
        .footer { text-align: center; padding: 16px; color: #484f58; font-size: 11px; border-top: 1px solid #21262d; }
        .no-data { color: #484f58; font-size: 12px; padding: 12px 0; }
    </style>
</head>
<body>
<div class="header">
    <div class="dot"></div>
    <h1>ShelLM Honeypot Dashboard</h1>
    <span style="margin-left:auto;font-size:12px;color:#8b949e;">Auto-refresh every 5s &nbsp;|&nbsp; {{ now }}</span>
</div>

<div class="stats">
    <div class="stat-card">
        <div class="num">{{ stats.total_sessions }}</div>
        <div class="label">Total Sessions</div>
    </div>
    <div class="stat-card">
        <div class="num">{{ stats.total_commands }}</div>
        <div class="label">Commands Run</div>
    </div>
    <div class="stat-card">
        <div class="num">{{ stats.total_logs }}</div>
        <div class="label">Log Files</div>
    </div>
    <div class="stat-card">
        <div class="num">{{ stats.total_trace_logs }}</div>
        <div class="label">Trace Logs</div>
    </div>
</div>

<div class="grid2" style="padding: 0 24px 20px;">
    <div>
        <div class="section" style="padding: 0;">
            <h2>Recent Commands</h2>
            {% if commands %}
            <table class="log-table">
                <tr><th>Command</th><th>Response</th><th>Session</th></tr>
                {% for cmd in commands[-15:]|reverse %}
                <tr>
                    <td class="cmd">$ {{ cmd.command }}</td>
                    <td class="resp">{{ cmd.response }}</td>
                    <td class="session-id">{{ cmd.session[-8:] }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}
            <div class="no-data">No commands yet â€” run the honeypot first!</div>
            {% endif %}
        </div>
    </div>
    <div>
        <div class="section" style="padding: 0; margin-bottom: 20px;">
            <h2>Login Attempts <span class="badge">ALERTS</span></h2>
            {% if auth_attempts %}
                {% for a in auth_attempts|reverse %}
                <div class="alert-box">{{ a }}</div>
                {% endfor %}
            {% else %}
            <div class="no-data">No login attempts logged yet.</div>
            {% endif %}
        </div>
        <div class="section" style="padding: 0;">
            <h2>Connections <span class="badge">LIVE</span></h2>
            {% if connections %}
                {% for c in connections|reverse %}
                <div class="alert-box green">{{ c }}</div>
                {% endfor %}
            {% else %}
            <div class="no-data">No connections logged yet.</div>
            {% endif %}
        </div>
    </div>
</div>

<div class="section">
    <h2>Sessions</h2>
    {% if sessions %}
    <table class="log-table">
        <tr><th>Session ID</th><th>Personality</th><th>Commands</th><th>Started</th><th>Ended</th></tr>
        {% for s in sessions %}
        <tr>
            <td class="session-id">{{ s.session_id }}</td>
            <td>{{ s.personality }}</td>
            <td>{{ s.total_commands }}</td>
            <td class="ts">{{ s.start_time }}</td>
            <td class="ts">{{ s.end_time }}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <div class="no-data">No sessions yet.</div>
    {% endif %}
</div>

<div class="footer">
    ShelLM Honeypot Dashboard &nbsp;|&nbsp; 
</div>
</body>
</html>
"""

# â”€â”€ Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/")
def index():
    return render_template_string(
        DASHBOARD_HTML,
        stats=get_stats(),
        commands=get_recent_commands(),
        sessions=get_all_sessions(),
        auth_attempts=get_auth_attempts(),
        connections=get_connections(),
        now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())

@app.route("/api/commands")
def api_commands():
    return jsonify(get_recent_commands())

if __name__ == "__main__":
    LOGS_DIR.mkdir(exist_ok=True)
    SESSIONS_DIR.mkdir(exist_ok=True)

    # Start alert monitor thread
    alert_thread = threading.Thread(target=monitor_alerts, daemon=True)
    alert_thread.start()
    print("[*] Alert monitor started")

    print("[*] shelLM Dashboard starting...")
    print("[*] Open your browser â†’ http://localhost:5000")
    print("[*] Windows notifications enabled")
    print("[*] Auto-refreshes every 5 seconds")
    print("[*] Press Ctrl+C to stop\n")

    app.run(host="0.0.0.0", port=5000, debug=False)


