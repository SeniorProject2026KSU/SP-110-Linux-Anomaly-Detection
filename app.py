from flask import Flask, request, jsonify, render_template_string, Response
import csv
import io
from datetime import datetime
import psycopg2
from config import DB_CONFIG, SERVER_HOST, SERVER_PORT, API_KEY
import parser
import db
import alerts
import analytics

app = Flask(__name__)

# Dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Behavior Monitor — SP-110</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg:       #080c10;
            --surface:  #0d1117;
            --panel:    #111820;
            --border:   #1e2d3d;
            --border2:  #243447;
            --text:     #c9d1d9;
            --muted:    #6e7681;
            --accent:   #00d4aa;
            --accent2:  #0ea5e9;
            --red:      #f85149;
            --orange:   #e3a03a;
            --yellow:   #d29922;
            --green:    #3fb950;
            --purple:   #bc8cff;
            --scan:     rgba(0,212,170,0.03);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: 'IBM Plex Sans', sans-serif;
            font-size: 14px;
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* Scanline texture */
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background: repeating-linear-gradient(
                0deg,
                transparent,
                transparent 2px,
                rgba(0,0,0,0.07) 2px,
                rgba(0,0,0,0.07) 4px
            );
            pointer-events: none;
            z-index: 9999;
        }

        /* Nav */
        nav {
            background: var(--surface);
            border-bottom: 1px solid var(--border);
            padding: 0 24px;
            height: 56px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .nav-left { display: flex; align-items: center; gap: 16px; }

        .brand {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 13px;
            font-weight: 600;
            color: var(--accent);
            letter-spacing: 0.08em;
            border: 1px solid var(--accent);
            padding: 3px 10px;
            border-radius: 3px;
        }

        .nav-title {
            font-size: 15px;
            font-weight: 500;
            color: var(--text);
            letter-spacing: 0.02em;
        }

        .nav-right { display: flex; align-items: center; gap: 16px; }

        .live-badge {
            display: flex; align-items: center; gap: 6px;
            font-family: 'IBM Plex Mono', monospace;
            font-size: 11px;
            color: var(--accent);
            letter-spacing: 0.05em;
        }

        .live-dot {
            width: 7px; height: 7px;
            border-radius: 50%;
            background: var(--accent);
            animation: pulse 1.8s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.7); }
        }

        .nav-time {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 11px;
            color: var(--muted);
        }

        .btn {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 11px;
            font-weight: 500;
            letter-spacing: 0.06em;
            padding: 6px 14px;
            border-radius: 4px;
            border: 1px solid var(--border2);
            background: var(--panel);
            color: var(--text);
            cursor: pointer;
            transition: all 0.15s;
            text-decoration: none;
            display: inline-flex; align-items: center; gap: 6px;
        }
        .btn:hover { border-color: var(--accent2); color: var(--accent2); }
        .btn-danger { border-color: #3d1a1a; color: var(--red); }
        .btn-danger:hover { border-color: var(--red); background: rgba(248,81,73,0.1); }
        .btn-export { border-color: #1a3a4d; color: var(--accent2); }
        .btn-export:hover { background: rgba(14,165,233,0.1); }

        /* Layout */
        .main { display: flex; height: calc(100vh - 56px); overflow: hidden; }

        .sidebar {
            width: 280px;
            min-width: 280px;
            background: var(--surface);
            border-right: 1px solid var(--border);
            overflow-y: auto;
            display: flex;
            flex-direction: column;
        }

        .content { flex: 1; overflow-y: auto; padding: 20px; }

        /* Sidebar sections */
        .sidebar-section {
            border-bottom: 1px solid var(--border);
            padding: 16px;
        }

        .sidebar-label {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.12em;
            color: var(--muted);
            text-transform: uppercase;
            margin-bottom: 12px;
        }

        /* KPI mini cards */
        .kpi-grid { display: flex; flex-direction: column; gap: 8px; }

        .kpi-card {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 10px 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .kpi-label { font-size: 11px; color: var(--muted); }
        .kpi-val {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 22px;
            font-weight: 600;
            line-height: 1;
        }

        /* Alert list in sidebar */
        .alert-list { display: flex; flex-direction: column; gap: 6px; }

        .alert-item {
            background: var(--panel);
            border: 1px solid var(--border);
            border-left: 3px solid var(--red);
            border-radius: 4px;
            padding: 8px 10px;
            font-size: 11px;
        }

        .alert-item.warn { border-left-color: var(--orange); }
        .alert-item.info { border-left-color: var(--accent2); }

        .alert-ip {
            font-family: 'IBM Plex Mono', monospace;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 2px;
        }

        .alert-meta { color: var(--muted); }

        /* Event type breakdown */
        .etype-list { display: flex; flex-direction: column; gap: 4px; }

        .etype-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 5px 8px;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.1s;
        }
        .etype-row:hover, .etype-row.active { background: var(--border); }

        .etype-name {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 11px;
            display: flex; align-items: center; gap: 8px;
        }

        .etype-dot { width: 6px; height: 6px; border-radius: 50%; }

        .etype-count {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 11px;
            color: var(--muted);
            background: var(--border);
            padding: 1px 7px;
            border-radius: 10px;
        }

        /* Search bar */
        .search-bar {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            display: flex;
            align-items: center;
            padding: 0 12px;
            gap: 10px;
            margin-bottom: 16px;
        }

        .search-bar:focus-within { border-color: var(--accent2); }

        .search-icon { color: var(--muted); font-size: 13px; }

        .search-input {
            flex: 1;
            background: none;
            border: none;
            outline: none;
            color: var(--text);
            font-family: 'IBM Plex Mono', monospace;
            font-size: 13px;
            padding: 10px 0;
        }

        .search-input::placeholder { color: var(--muted); }

        /* Filter chips */
        .filter-row {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-bottom: 16px;
            align-items: center;
        }

        .filter-label { font-size: 11px; color: var(--muted); margin-right: 4px; }

        .chip {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 10px;
            font-weight: 500;
            letter-spacing: 0.06em;
            padding: 4px 10px;
            border-radius: 3px;
            border: 1px solid var(--border2);
            background: var(--panel);
            color: var(--muted);
            cursor: pointer;
            transition: all 0.12s;
            text-transform: uppercase;
        }

        .chip:hover { border-color: var(--border2); color: var(--text); }
        .chip.active { background: rgba(0,212,170,0.12); border-color: var(--accent); color: var(--accent); }
        .chip.chip-red.active { background: rgba(248,81,73,0.12); border-color: var(--red); color: var(--red); }
        .chip.chip-orange.active { background: rgba(227,160,58,0.12); border-color: var(--orange); color: var(--orange); }
        .chip.chip-green.active { background: rgba(63,185,80,0.12); border-color: var(--green); color: var(--green); }
        .chip.chip-purple.active { background: rgba(188,140,255,0.12); border-color: var(--purple); color: var(--purple); }
        .chip.chip-blue.active { background: rgba(14,165,233,0.12); border-color: var(--accent2); color: var(--accent2); }

        /* Stats row */
        .stats-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px 18px;
            position: relative;
            overflow: hidden;
        }

        .stat-card::after {
            content: '';
            position: absolute;
            bottom: 0; left: 0; right: 0;
            height: 2px;
        }

        .stat-card.s-red::after { background: var(--red); }
        .stat-card.s-orange::after { background: var(--orange); }
        .stat-card.s-yellow::after { background: var(--yellow); }
        .stat-card.s-blue::after { background: var(--accent2); }

        .stat-lbl { font-size: 11px; color: var(--muted); margin-bottom: 6px; letter-spacing: 0.04em; }
        .stat-val {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 32px;
            font-weight: 600;
            line-height: 1;
        }
        .stat-val.c-red { color: var(--red); }
        .stat-val.c-orange { color: var(--orange); }
        .stat-val.c-yellow { color: var(--yellow); }
        .stat-val.c-blue { color: var(--accent2); }

        /* Chart panel */
        .chart-panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 20px;
        }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 14px;
        }

        .panel-title {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.08em;
            color: var(--muted);
            text-transform: uppercase;
        }

        /* Log table */
        .log-panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }

        .log-panel-header {
            padding: 14px 18px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .log-count {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 11px;
            color: var(--muted);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-family: 'IBM Plex Mono', monospace;
            font-size: 12px;
        }

        thead { position: sticky; top: 0; z-index: 10; }

        th {
            background: var(--panel);
            padding: 10px 14px;
            text-align: left;
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: var(--muted);
            border-bottom: 1px solid var(--border);
            cursor: pointer;
            user-select: none;
            white-space: nowrap;
        }

        th:hover { color: var(--text); }
        th.sort-asc::after { content: ' ↑'; color: var(--accent); }
        th.sort-desc::after { content: ' ↓'; color: var(--accent); }

        td {
            padding: 9px 14px;
            border-bottom: 1px solid rgba(30,45,61,0.6);
            vertical-align: middle;
            max-width: 0;
        }

        tr.log-row { cursor: pointer; transition: background 0.1s; }
        tr.log-row:hover td { background: rgba(255,255,255,0.02); }

        tr.r-red td { background: rgba(248,81,73,0.05); }
        tr.r-red:hover td { background: rgba(248,81,73,0.09); }
        tr.r-orange td { background: rgba(227,160,58,0.04); }
        tr.r-orange:hover td { background: rgba(227,160,58,0.08); }

        /* Column styles */
        .col-time { width: 150px; color: var(--muted); white-space: nowrap; }
        .col-type { width: 130px; }
        .col-host { width: 120px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .col-user { width: 100px; color: var(--accent2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .col-ip   { width: 120px; color: var(--accent); white-space: nowrap; }
        .col-msg  { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .col-sev  { width: 90px; text-align: center; }

        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.07em;
            text-transform: uppercase;
            white-space: nowrap;
        }

        .badge-AUTH    { background: rgba(248,81,73,0.15);  color: var(--red);    border: 1px solid rgba(248,81,73,0.3); }
        .badge-SUDO    { background: rgba(227,160,58,0.15); color: var(--orange); border: 1px solid rgba(227,160,58,0.3); }
        .badge-SUSPICIOUS_COMMAND { background: rgba(248,81,73,0.2); color: #ff6b6b; border: 1px solid rgba(248,81,73,0.4); }
        .badge-BASH_HISTORY { background: rgba(188,140,255,0.15); color: var(--purple); border: 1px solid rgba(188,140,255,0.3); }
        .badge-SYS     { background: rgba(110,118,129,0.15); color: var(--muted);  border: 1px solid rgba(110,118,129,0.3); }

        .sev-badge {
            display: inline-block;
            width: 64px;
            text-align: center;
            padding: 2px 0;
            border-radius: 2px;
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.06em;
        }

        .sev-red    { background: rgba(248,81,73,0.2); color: var(--red); }
        .sev-orange { background: rgba(227,160,58,0.2); color: var(--orange); }
        .sev-green  { background: rgba(63,185,80,0.1); color: var(--green); }

        /* Detail drawer */
        #detail-drawer {
            background: var(--surface);
            border: 1px solid var(--border);
            border-top: 2px solid var(--accent);
            border-radius: 8px 8px 0 0;
            position: fixed;
            bottom: 0; left: 280px; right: 0;
            max-height: 280px;
            overflow-y: auto;
            padding: 16px 24px;
            transform: translateY(100%);
            transition: transform 0.2s ease;
            z-index: 200;
        }

        #detail-drawer.open { transform: translateY(0); }

        .drawer-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 14px;
        }

        .drawer-title {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 12px;
            font-weight: 600;
            color: var(--accent);
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .drawer-close {
            background: none; border: none; color: var(--muted);
            cursor: pointer; font-size: 16px; line-height: 1;
        }
        .drawer-close:hover { color: var(--text); }

        .drawer-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 10px;
        }

        .drawer-field { }
        .drawer-key {
            font-size: 10px; letter-spacing: 0.08em;
            color: var(--muted); text-transform: uppercase; margin-bottom: 3px;
        }
        .drawer-val {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 12px; color: var(--text);
            word-break: break-all;
        }

        .drawer-raw {
            margin-top: 12px;
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 10px 14px;
            font-family: 'IBM Plex Mono', monospace;
            font-size: 11px;
            color: var(--muted);
            word-break: break-all;
            white-space: pre-wrap;
        }

        /* Pagination */
        .pagination {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 18px;
            border-top: 1px solid var(--border);
        }

        .page-info { font-size: 11px; color: var(--muted); font-family: 'IBM Plex Mono', monospace; }

        .page-btns { display: flex; gap: 6px; }

        .page-btn {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 11px;
            padding: 4px 12px;
            border: 1px solid var(--border2);
            background: var(--panel);
            color: var(--text);
            border-radius: 3px;
            cursor: pointer;
            transition: all 0.12s;
        }
        .page-btn:hover { border-color: var(--accent); color: var(--accent); }
        .page-btn:disabled { opacity: 0.3; cursor: not-allowed; }
        .page-btn.current { border-color: var(--accent); color: var(--accent); background: rgba(0,212,170,0.08); }

        /* Scrollbar */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #3a4d60; }

        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--muted);
        }
        .empty-state .icon { font-size: 36px; margin-bottom: 12px; }
        .empty-state p { font-family: 'IBM Plex Mono', monospace; font-size: 12px; }
    </style>
</head>
<body>

<!-- Nav -->
<nav>
    <div class="nav-left">
        <span class="brand">SP-110/G</span>
        <span class="nav-title">Linux Behavior Monitor</span>
    </div>
    <div class="nav-right">
        <div class="live-badge"><div class="live-dot"></div> LIVE</div>
        <span class="nav-time" id="lastUpdate" style="color:var(--accent);font-size:10px;opacity:0.7"></span>
        <span class="nav-time" id="clock">{{ now }}</span>
        <a href="/export/csv" class="btn btn-export">⬇ Export CSV</a>
        <button onclick="clearLogs()" class="btn btn-danger">✕ Clear Logs</button>
    </div>
</nav>

<div class="main">

    <!-- Sidebar -->
    <div class="sidebar">

        <!-- KPIs -->
        <div class="sidebar-section">
            <div class="sidebar-label">Metrics</div>
            <div class="kpi-grid">
                <div class="kpi-card">
                    <div>
                        <div class="kpi-label">Failed Logins (60s)</div>
                        <div class="kpi-val" style="color:var(--red)">{{ failed_logins }}</div>
                    </div>
                </div>
                <div class="kpi-card">
                    <div>
                        <div class="kpi-label">Brute Force IPs</div>
                        <div class="kpi-val" style="color:var(--orange)">{{ brute_total }}</div>
                    </div>
                </div>
                <div class="kpi-card">
                    <div>
                        <div class="kpi-label">Sudo Abuses</div>
                        <div class="kpi-val" style="color:var(--yellow)">{{ sudo_total }}</div>
                    </div>
                </div>
                <div class="kpi-card">
                    <div>
                        <div class="kpi-label">Unique Source IPs</div>
                        <div class="kpi-val" style="color:var(--accent2)">{{ unique_ips }}</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Event type filter -->
        <div class="sidebar-section">
            <div class="sidebar-label">Event Types</div>
            <div class="etype-list" id="etypeList">
                <div class="etype-row active" data-etype="all" onclick="setEtype('all', this)">
                    <span class="etype-name"><span class="etype-dot" style="background:var(--muted)"></span> All Events</span>
                    <span class="etype-count">{{ total_logs }}</span>
                </div>
                {% for et in event_types %}
                <div class="etype-row" data-etype="{{ et.name }}" onclick="setEtype('{{ et.name }}', this)">
                    <span class="etype-name">
                        <span class="etype-dot" style="background:{{ et.color }}"></span>
                        {{ et.name }}
                    </span>
                    <span class="etype-count">{{ et.count }}</span>
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- Top IPs (brute force alerts) -->
        <div class="sidebar-section">
            <div class="sidebar-label">Top Attacker IPs</div>
            <div class="alert-list" id="topIpList">
                {% for ip, count in top_ips %}
                <div class="alert-item {% if count > 50 %}{% elif count > 20 %}warn{% else %}info{% endif %}">
                    <div class="alert-ip">{{ ip }}</div>
                    <div class="alert-meta">{{ count }} failed attempt{% if count != 1 %}s{% endif %}</div>
                </div>
                {% else %}
                <div style="font-size:11px;color:var(--muted);text-align:center;padding:12px 0">No attackers detected</div>
                {% endfor %}
            </div>
        </div>

        <!-- Sudo abusers -->
        {% if sudo_users %}
        <div class="sidebar-section">
            <div class="sidebar-label">Sudo Abusers</div>
            <div class="alert-list">
                {% for user, count in sudo_users %}
                <div class="alert-item warn">
                    <div class="alert-ip">{{ user }}</div>
                    <div class="alert-meta">{{ count }} sudo event{% if count != 1 %}s{% endif %}</div>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

    </div>

    <!-- Main content -->
    <div class="content">

        <!-- Stats row -->
        <div class="stats-row">
            <div class="stat-card s-red">
                <div class="stat-lbl">Total Events</div>
                <div class="stat-val c-red">{{ total_logs }}</div>
            </div>
            <div class="stat-card s-orange">
                <div class="stat-lbl">Suspicious Commands</div>
                <div class="stat-val c-orange">{{ suspicious_count }}</div>
            </div>
            <div class="stat-card s-yellow">
                <div class="stat-lbl">Auth Events</div>
                <div class="stat-val c-yellow">{{ auth_count }}</div>
            </div>
            <div class="stat-card s-blue">
                <div class="stat-lbl">Hosts Seen</div>
                <div class="stat-val c-blue">{{ host_count }}</div>
            </div>
        </div>

        <!-- Search + filters -->
        <div class="search-bar">
            <span class="search-icon">⌕</span>
            <input
                type="text"
                class="search-input"
                id="searchInput"
                placeholder='Search logs... (e.g. "failed password" OR source IP)'
                oninput="filterTable()"
            >
            <span id="matchCount" style="font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted)"></span>
        </div>

        <div class="filter-row">
            <span class="filter-label">Severity:</span>
            <span class="chip active" data-sev="all" onclick="setSev('all',this)">All</span>
            <span class="chip chip-red" data-sev="red" onclick="setSev('red',this)">High</span>
            <span class="chip chip-orange" data-sev="orange" onclick="setSev('orange',this)">Medium</span>
            <span class="chip chip-green" data-sev="green" onclick="setSev('green',this)">Normal</span>
        </div>

        <!-- Log table -->
        <div class="log-panel">
            <div class="log-panel-header">
                <span class="panel-title">Event Log</span>
                <span class="log-count" id="tableCount">Showing {{ recent_logs|length }} events</span>
            </div>

            <div style="overflow-x:auto;">
            <table id="logTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)" class="col-time" data-col="0">Time</th>
                        <th onclick="sortTable(1)" data-col="1">Event Type</th>
                        <th onclick="sortTable(2)" data-col="2">Host</th>
                        <th onclick="sortTable(3)" data-col="3">User</th>
                        <th onclick="sortTable(4)" data-col="4">Source IP</th>
                        <th data-col="5">Message</th>
                        <th onclick="sortTable(6)" data-col="6">Severity</th>
                    </tr>
                </thead>
                <tbody id="logBody">
                    {% for log in recent_logs %}
                    <tr class="log-row r-{{ log.threat_level }}"
                        data-sev="{{ log.threat_level }}"
                        data-etype="{{ log.eventtype }}"
                        data-raw="{{ log.rawline|replace('"', '&quot;') }}"
                        data-time="{{ log.timestamp }}"
                        data-user="{{ log.username }}"
                        data-ip="{{ log.sourceip }}"
                        data-host="{{ log.hostname }}"
                        data-msg="{{ log.message|replace('"', '&quot;') }}"
                        onclick="showDetail(this)"
                    >
                        <td class="col-time">{{ log.timestamp }}</td>
                        <td class="col-type"><span class="badge badge-{{ log.eventtype }}">{{ log.eventtype }}</span></td>
                        <td class="col-host">{{ log.hostname }}</td>
                        <td class="col-user">{{ log.username }}</td>
                        <td class="col-ip">{{ log.sourceip }}</td>
                        <td class="col-msg">{{ log.message }}</td>
                        <td class="col-sev"><span class="sev-badge sev-{{ log.threat_level }}">{{ log.threat_label }}</span></td>
                    </tr>
                    {% else %}
                    <tr><td colspan="7">
                        <div class="empty-state">
                            <div class="icon">◎</div>
                            <p>No events found</p>
                        </div>
                    </td></tr>
                    {% endfor %}
                </tbody>
            </table>
            </div>

            <!-- Pagination -->
            <div class="pagination">
                <span class="page-info" id="pageInfo">Page 1</span>
                <div class="page-btns" id="pageBtns"></div>
            </div>
        </div>

    </div>
</div>

<!-- Detail drawer -->
<div id="detail-drawer">
    <div class="drawer-header">
        <span class="drawer-title">Event Detail</span>
        <button class="drawer-close" onclick="closeDetail()">✕</button>
    </div>
    <div class="drawer-grid" id="drawerGrid"></div>
    <div class="drawer-raw" id="drawerRaw"></div>
</div>

<script>
// State
let currentSev  = localStorage.getItem('sevFilter')   || 'all';
let currentEtype = localStorage.getItem('etypeFilter') || 'all';
let sortCol  = -1;
let sortDir  = 'desc';
let page     = 1;
const PAGE_SIZE = 50;

// Init
window.addEventListener('load', () => {
    restoreFilters();
    updateClock();
    setInterval(updateClock, 1000);
    filterTable();
    // Live data polling — no page reload
    pollStats();
    setInterval(pollStats, 5000);
});

function updateClock() {
    const now = new Date();
    document.getElementById('clock').textContent =
        now.toLocaleTimeString('en-US', {hour12: false});
}

// Live polling
let isPolling = false;

async function pollStats() {
    if (isPolling) return;
    isPolling = true;
    try {
        const res  = await fetch('/api/stats');
        const data = await res.json();

        // ── Update KPI sidebar cards ──
        const kpiVals = document.querySelectorAll('.kpi-val');
        if (kpiVals[0]) kpiVals[0].textContent = data.failed_logins;
        if (kpiVals[1]) kpiVals[1].textContent = data.brute_total;
        if (kpiVals[2]) kpiVals[2].textContent = data.sudo_total;
        if (kpiVals[3]) kpiVals[3].textContent = data.unique_ips;

        // ── Update top stat cards ──
        const statVals = document.querySelectorAll('.stat-val');
        if (statVals[0]) statVals[0].textContent = data.total_logs;
        if (statVals[1]) statVals[1].textContent = data.suspicious_count;
        if (statVals[2]) statVals[2].textContent = data.auth_count;
        if (statVals[3]) statVals[3].textContent = data.host_count;

        // ── Rebuild event type list ──
        const etypeList = document.getElementById('etypeList');
        const firstRow  = etypeList.querySelector('[data-etype="all"]');
        if (firstRow) firstRow.querySelector('.etype-count').textContent = data.total_logs;

        // Remove old dynamic rows, re-add
        etypeList.querySelectorAll('[data-etype]:not([data-etype="all"])').forEach(r => r.remove());
        (data.event_types || []).forEach(et => {
            const row = document.createElement('div');
            row.className = 'etype-row' + (currentEtype === et.name ? ' active' : '');
            row.dataset.etype = et.name;
            row.onclick = () => setEtype(et.name, row);
            row.innerHTML = `
                <span class="etype-name">
                    <span class="etype-dot" style="background:${et.color}"></span>
                    ${et.name}
                </span>
                <span class="etype-count">${et.count}</span>`;
            etypeList.appendChild(row);
        });

        // Rebuild top IPs
        const ipSection = document.getElementById('topIpList');
        if (ipSection) {
            ipSection.innerHTML = (data.top_ips || []).length === 0
                ? '<div style="font-size:11px;color:var(--muted);text-align:center;padding:12px 0">No attackers detected</div>'
                : (data.top_ips || []).map(([ip, count]) => `
                    <div class="alert-item ${count > 50 ? '' : count > 20 ? 'warn' : 'info'}">
                        <div class="alert-ip">${ip}</div>
                        <div class="alert-meta">${count} failed attempt${count !== 1 ? 's' : ''}</div>
                    </div>`).join('');
        }

        // Rebuild log table rows
        const tbody = document.getElementById('logBody');
        const existingIds = new Set(
            Array.from(tbody.querySelectorAll('tr.log-row')).map(r => r.dataset.logid)
        );

        let newCount = 0;
        const fragment = document.createDocumentFragment();

        (data.logs || []).forEach(log => {
            if (existingIds.has(String(log.logid))) return; // already shown
            newCount++;
            const tr = document.createElement('tr');
            tr.className = `log-row r-${log.threat_level}`;
            tr.dataset.sev    = log.threat_level;
            tr.dataset.etype  = log.eventtype;
            tr.dataset.logid  = log.logid;
            tr.dataset.time   = log.timestamp;
            tr.dataset.user   = log.username;
            tr.dataset.ip     = log.sourceip;
            tr.dataset.host   = log.hostname;
            tr.dataset.msg    = log.message;
            tr.dataset.raw    = log.rawline || '';
            tr.onclick = function(){ showDetail(this); };
            tr.innerHTML = `
                <td class="col-time">${log.timestamp}</td>
                <td class="col-type"><span class="badge badge-${log.eventtype}">${log.eventtype}</span></td>
                <td class="col-host">${log.hostname}</td>
                <td class="col-user">${log.username}</td>
                <td class="col-ip">${log.sourceip}</td>
                <td class="col-msg">${log.message}</td>
                <td class="col-sev"><span class="sev-badge sev-${log.threat_level}">${log.threat_label}</span></td>`;
            fragment.appendChild(tr);
        });

        if (newCount > 0) {
            // Prepend new rows at the top
            tbody.insertBefore(fragment, tbody.firstChild);
            // Keep table from growing unbounded — trim to 300
            const allRows = tbody.querySelectorAll('tr.log-row');
            if (allRows.length > 300) {
                for (let i = 300; i < allRows.length; i++) allRows[i].remove();
            }
            filterTable();
        }

        // Flash last-updated indicator
        const lu = document.getElementById('lastUpdate');
        if (lu) {
            lu.textContent = 'UPDATED ' + new Date().toLocaleTimeString('en-US', {hour12: false});
            lu.style.opacity = '1';
            setTimeout(() => { lu.style.opacity = '0.4'; }, 1500);
        }

    } catch (e) {
        console.warn('Poll failed:', e);
    } finally {
        isPolling = false;
    }
}

function restoreFilters() {
    // Restore severity chip
    document.querySelectorAll('[data-sev]').forEach(el => {
        el.classList.toggle('active', el.dataset.sev === currentSev);
    });

    // Restore etype row
    document.querySelectorAll('[data-etype]').forEach(el => {
        if (el.classList.contains('etype-row')) {
            el.classList.toggle('active', el.dataset.etype === currentEtype);
        }
    });
}

// Filters
function setSev(val, el) {
    currentSev = val;
    localStorage.setItem('sevFilter', val);
    document.querySelectorAll('.chip[data-sev]').forEach(c => c.classList.remove('active'));
    el.classList.add('active');
    page = 1;
    filterTable();
}

function setEtype(val, el) {
    currentEtype = val;
    localStorage.setItem('etypeFilter', val);
    document.querySelectorAll('.etype-row').forEach(r => r.classList.remove('active'));
    el.classList.add('active');
    page = 1;
    filterTable();
}

function filterTable() {
    const search  = document.getElementById('searchInput').value.toLowerCase().trim();
    const rows    = document.querySelectorAll('#logBody tr.log-row');
    let visible   = 0;
    let allRows   = [];

    rows.forEach(row => {
        const sevOk   = currentSev  === 'all' || row.dataset.sev   === currentSev;
        const etypeOk = currentEtype === 'all' || row.dataset.etype === currentEtype;
        const searchOk = !search || row.textContent.toLowerCase().includes(search);
        const show = sevOk && etypeOk && searchOk;
        row._visible = show;
        if (show) { visible++; allRows.push(row); }
    });

    // Update match count
    document.getElementById('matchCount').textContent =
        search ? `${visible} match${visible !== 1 ? 'es' : ''}` : '';

    // Paginate
    renderPage(allRows, page);
    renderPagination(allRows.length);

    document.getElementById('tableCount').textContent =
        `Showing ${Math.min(visible, PAGE_SIZE)} of ${visible} events`;
}

function renderPage(visibleRows, pg) {
    const start = (pg - 1) * PAGE_SIZE;
    const end   = start + PAGE_SIZE;
    const all = document.querySelectorAll('#logBody tr.log-row');
    const visSet = new Set(visibleRows.slice(start, end));
    all.forEach(row => {
        row.style.display = visSet.has(row) ? '' : 'none';
    });
}

function renderPagination(total) {
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const container = document.getElementById('pageBtns');
    container.innerHTML = '';

    document.getElementById('pageInfo').textContent =
        `Page ${page} of ${pages}  (${total} events)`;

    // Prev
    const prev = document.createElement('button');
    prev.className = 'page-btn';
    prev.textContent = '← Prev';
    prev.disabled = page <= 1;
    prev.onclick = () => { page--; filterTable(); };
    container.appendChild(prev);

    // Page numbers (show up to 5)
    const start = Math.max(1, page - 2);
    const end   = Math.min(pages, start + 4);
    for (let i = start; i <= end; i++) {
        const btn = document.createElement('button');
        btn.className = 'page-btn' + (i === page ? ' current' : '');
        btn.textContent = i;
        btn.onclick = (function(n){ return () => { page = n; filterTable(); }; })(i);
        container.appendChild(btn);
    }

    // Next
    const next = document.createElement('button');
    next.className = 'page-btn';
    next.textContent = 'Next →';
    next.disabled = page >= pages;
    next.onclick = () => { page++; filterTable(); };
    container.appendChild(next);
}

// Sort 
function sortTable(col) {
    const tbody = document.getElementById('logBody');
    const rows  = Array.from(tbody.querySelectorAll('tr.log-row'));

    if (sortCol === col) {
        sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    } else {
        sortCol = col;
        sortDir = 'asc';
    }

    rows.sort((a, b) => {
        const aVal = a.cells[col]?.textContent.trim() || '';
        const bVal = b.cells[col]?.textContent.trim() || '';
        const cmp  = aVal.localeCompare(bVal, undefined, {numeric: true});
        return sortDir === 'asc' ? cmp : -cmp;
    });

    rows.forEach(r => tbody.appendChild(r));

    // Update header indicators
    document.querySelectorAll('th[data-col]').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
    });
    const th = document.querySelector(`th[data-col="${col}"]`);
    if (th) th.classList.add(sortDir === 'asc' ? 'sort-asc' : 'sort-desc');

    page = 1;
    filterTable();
}

// Detail drawer
function showDetail(row) {
    const d = row.dataset;
    const fields = [
        ['Timestamp',   d.time   || '—'],
        ['Event Type',  d.etype  || '—'],
        ['Host',        d.host   || '—'],
        ['User',        d.user   || '—'],
        ['Source IP',   d.ip     || '—'],
        ['Severity',    row.dataset.sev || '—'],
    ];

    const grid = document.getElementById('drawerGrid');
    grid.innerHTML = fields.map(([k, v]) => `
        <div class="drawer-field">
            <div class="drawer-key">${k}</div>
            <div class="drawer-val">${v}</div>
        </div>
    `).join('');

    document.getElementById('drawerRaw').textContent = d.msg || '';
    document.getElementById('detail-drawer').classList.add('open');
}

function closeDetail() {
    document.getElementById('detail-drawer').classList.remove('open');
}

// Clear logs
function clearLogs() {
    if (!confirm('⚠ Delete ALL logs?\\n\\nThis cannot be undone.')) return;

    fetch('/clear-logs', { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            if (data.status === 'success') {
                window.location.reload();
            } else {
                alert('Error: ' + (data.message || 'Unknown error'));
            }
        })
        .catch(() => alert('Failed to connect to server.'));
}

// Close drawer on Escape
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeDetail();
});
</script>
</body>
</html>
"""


def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)


# Colour helpers
ETYPE_COLORS = {
    "AUTH":               "var(--red)",
    "SUDO":               "var(--orange)",
    "SUSPICIOUS_COMMAND": "#ff6b6b",
    "BASH_HISTORY":       "var(--purple)",
    "SYS":                "var(--muted)",
}


def classify(eventtype, success, message):
    lower = (message or "").lower()
    if success == 0 or "failed password" in lower or eventtype == "SUSPICIOUS_COMMAND":
        return "red", "HIGH"
    elif eventtype == "SUDO" or "sudo" in lower or eventtype == "BASH_HISTORY":
        return "orange", "MED"
    else:
        return "green", "NORMAL"


# Dashboard route 
@app.route("/")
def dashboard():
    try:
        failed      = analytics.failed_logins()
        brute_list  = alerts.brute_force()
        sudo_list   = alerts.sudo_abuse()
        top_list    = analytics.top_ips()

        brute_total = sum(c for _, c in brute_list) if brute_list else 0
        sudo_total  = sum(c for _, c in sudo_list)  if sudo_list  else 0

        conn = get_db_connection()
        cur  = conn.cursor()

        # Recent logs
        cur.execute("""
            SELECT
                COALESCE(EventTime, NOW()) AS log_time,
                Message, EventType, Success,
                UserName, SourceIp, RawLine, HostName
            FROM Logs
            ORDER BY logid DESC
            LIMIT 200
        """)

        recent_logs = []
        for row in cur.fetchall():
            ts        = str(row[0])[:19] if row[0] else "—"
            message   = str(row[1]) if row[1] else ""
            eventtype = row[2] if row[2] else "SYS"
            success   = row[3] if row[3] is not None else 1
            username  = row[4] or "—"
            sourceip  = row[5] or "—"
            rawline   = row[6] or ""
            hostname  = row[7] or "—"

            threat_level, threat_label = classify(eventtype, success, message)

            recent_logs.append({
                "timestamp":   ts,
                "message":     message,
                "eventtype":   eventtype,
                "threat_level": threat_level,
                "threat_label": threat_label,
                "username":    username,
                "sourceip":    sourceip,
                "rawline":     rawline,
                "hostname":    hostname,
            })

        # Aggregates
        cur.execute("SELECT COUNT(*) FROM Logs")
        total_logs = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(*) FROM Logs WHERE EventType='SUSPICIOUS_COMMAND'")
        suspicious_count = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(*) FROM Logs WHERE EventType='AUTH'")
        auth_count = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(DISTINCT HostName) FROM Logs")
        host_count = cur.fetchone()[0] or 0

        cur.execute("""
            SELECT EventType, COUNT(*)
            FROM Logs
            GROUP BY EventType
            ORDER BY COUNT(*) DESC
        """)

        event_types = [
            {"name": r[0] or "SYS", "count": r[1],
             "color": ETYPE_COLORS.get(r[0] or "SYS", "var(--muted)")}
            for r in cur.fetchall()
        ]

        cur.close()
        conn.close()

        unique_ips = len(set(ip for ip, _ in top_list)) if top_list else 0

    except Exception as e:
        print(f" Dashboard error: {e}")
        failed = brute_total = sudo_total = unique_ips = 0
        total_logs = suspicious_count = auth_count = host_count = 0
        recent_logs = []
        top_list    = []
        sudo_list   = []
        event_types = []

    return render_template_string(
        DASHBOARD_HTML,
        failed_logins    = failed,
        brute_total      = brute_total,
        sudo_total       = sudo_total,
        unique_ips       = unique_ips,
        total_logs       = total_logs,
        suspicious_count = suspicious_count,
        auth_count       = auth_count,
        host_count       = host_count,
        top_ips          = top_list[:8],
        sudo_users       = sudo_list[:5],
        event_types      = event_types,
        recent_logs      = recent_logs,
        now              = datetime.now().strftime("%H:%M:%S"),
    )



# Live stats API (polled by frontend every 5s) 
@app.route("/api/stats", methods=["GET"])
def api_stats():
    try:
        failed     = analytics.failed_logins()
        brute_list = alerts.brute_force()
        sudo_list  = alerts.sudo_abuse()
        top_list   = analytics.top_ips()

        brute_total = sum(c for _, c in brute_list) if brute_list else 0
        sudo_total  = sum(c for _, c in sudo_list)  if sudo_list  else 0
        unique_ips  = len(set(ip for ip, _ in top_list)) if top_list else 0

        conn = get_db_connection()
        cur  = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM Logs")
        total_logs = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(*) FROM Logs WHERE EventType='SUSPICIOUS_COMMAND'")
        suspicious_count = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(*) FROM Logs WHERE EventType='AUTH'")
        auth_count = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(DISTINCT HostName) FROM Logs")
        host_count = cur.fetchone()[0] or 0

        cur.execute("""
            SELECT EventType, COUNT(*)
            FROM Logs
            GROUP BY EventType
            ORDER BY COUNT(*) DESC
        """)
        event_types = [
            {"name": r[0] or "SYS", "count": r[1],
             "color": ETYPE_COLORS.get(r[0] or "SYS", "var(--muted)")}
            for r in cur.fetchall()
        ]

        # Latest 200 logs for incremental table updates
        cur.execute("""
            SELECT
                logid,
                COALESCE(EventTime, NOW()) AS log_time,
                Message, EventType, Success,
                UserName, SourceIp, RawLine, HostName
            FROM Logs
            ORDER BY logid DESC
            LIMIT 200
        """)

        logs = []
        for row in cur.fetchall():
            logid     = row[0]
            ts        = str(row[1])[:19] if row[1] else "—"
            message   = str(row[2]) if row[2] else ""
            eventtype = row[3] if row[3] else "SYS"
            success   = row[4] if row[4] is not None else 1
            username  = row[5] or "—"
            sourceip  = row[6] or "—"
            rawline   = row[7] or ""
            hostname  = row[8] or "—"
            threat_level, threat_label = classify(eventtype, success, message)
            logs.append({
                "logid":        logid,
                "timestamp":    ts,
                "message":      message,
                "eventtype":    eventtype,
                "threat_level": threat_level,
                "threat_label": threat_label,
                "username":     username,
                "sourceip":     sourceip,
                "rawline":      rawline,
                "hostname":     hostname,
            })

        cur.close()
        conn.close()

        return jsonify({
            "failed_logins":    failed,
            "brute_total":      brute_total,
            "sudo_total":       sudo_total,
            "unique_ips":       unique_ips,
            "total_logs":       total_logs,
            "suspicious_count": suspicious_count,
            "auth_count":       auth_count,
            "host_count":       host_count,
            "top_ips":          top_list[:8],
            "event_types":      event_types,
            "logs":             logs,
        })

    except Exception as e:
        print(f"[!] api/stats error: {e}")
        return jsonify({"error": str(e)}), 500


#  Clear logs 
@app.route("/clear-logs", methods=["POST"])
def clear_logs():
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("TRUNCATE TABLE Logs RESTART IDENTITY;")
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        print(f"[!] Clear logs error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


# Health
@app.route("/health", methods=["GET"])
def health():
    try:
        get_db_connection().close()
        return jsonify({"status": "ok", "db": "reachable"})
    except Exception as e:
        return jsonify({"status": "error", "db": str(e)}), 500


# Ingest 
@app.route("/ingest", methods=["POST"])
def ingest():
    data = request.json
    if not data or data.get("api_key") != API_KEY:
        return jsonify({"error": "Invalid API key"}), 401

    raw_line = data.get("message", "")
    event    = parser.parse(raw_line)

    if not event:
        event = {
            "EventTime": datetime.utcnow().isoformat(),
            "EventType": "SYS",
            "Success":   1,
            "UserName":  None,
            "SourceIp":  None,
            "Message":   raw_line[:700],
            "RawLine":   raw_line,
            "HostName":  data.get("host", "unknown"),
        }
    else:
        event["HostName"] = data.get("host", "unknown")

    try:
        db.insert(event)
        return jsonify({"status": "ok"})
    except Exception as e:
        print(f"[!] Ingest error: {e}")
        return jsonify({"error": str(e)}), 500


# Logs JSON
@app.route("/logs", methods=["GET"])
def get_logs():
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM Logs ORDER BY logid DESC LIMIT 200")
        rows    = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        cur.close()
        conn.close()
        return jsonify([dict(zip(columns, r)) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# CSV export
@app.route("/export/csv", methods=["GET"])
def export_csv():
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM Logs ORDER BY logid DESC LIMIT 1000")
        rows    = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        cur.close()
        conn.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(columns)
        writer.writerows(rows)

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition":
                     f"attachment; filename=behavior_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print(f"Linux Behavior Monitor running → http://{SERVER_HOST}:{SERVER_PORT}")
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False)
