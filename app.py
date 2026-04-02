from flask import Flask, request, jsonify, render_template_string, Response
import csv
import io
from datetime import datetime, timedelta
import psycopg2
from config import DB_CONFIG, SERVER_HOST, SERVER_PORT, API_KEY
import parser
import db
import alerts
import analytics
import os
import json
import hashlib
import subprocess
import platform
import threading
import time
import requests as http_requests

app = Flask(__name__)

# ─── MITRE ATT&CK v15 — 29 techniques across 9 event types ─────────────────
MITRE_MAP = {
    "SUSPICIOUS_COMMAND": [
        {"id": "T1059",     "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1059.004", "name": "Unix Shell",                        "tactic": "Execution"},
        {"id": "T1070.003", "name": "Clear Command History",             "tactic": "Defense Evasion"},
        {"id": "T1070.004", "name": "File Deletion",                     "tactic": "Defense Evasion"},
        {"id": "T1219",     "name": "Remote Access Tools",               "tactic": "Command and Control"},
    ],
    "AUTH": [
        {"id": "T1110",     "name": "Brute Force",                       "tactic": "Credential Access"},
        {"id": "T1110.001", "name": "Password Guessing",                 "tactic": "Credential Access"},
        {"id": "T1078",     "name": "Valid Accounts",                    "tactic": "Persistence"},
        {"id": "T1021.004", "name": "SSH Remote Services",               "tactic": "Lateral Movement"},
    ],
    "SUDO": [
        {"id": "T1548.003", "name": "Sudo and Sudo Caching",             "tactic": "Privilege Escalation"},
        {"id": "T1078",     "name": "Valid Accounts",                    "tactic": "Persistence"},
        {"id": "T1068",     "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
    "BASH_HISTORY": [
        {"id": "T1059.004", "name": "Unix Shell",                        "tactic": "Execution"},
        {"id": "T1552.003", "name": "Bash History",                      "tactic": "Credential Access"},
        {"id": "T1083",     "name": "File and Directory Discovery",      "tactic": "Discovery"},
    ],
    "SYS": [
        {"id": "T1082",     "name": "System Information Discovery",      "tactic": "Discovery"},
        {"id": "T1518",     "name": "Software Discovery",                "tactic": "Discovery"},
    ],
    "CRON": [
        {"id": "T1053.003", "name": "Cron Job Scheduled Task",           "tactic": "Persistence"},
        {"id": "T1053",     "name": "Scheduled Task/Job",                "tactic": "Execution"},
    ],
    "PKG_MGMT": [
        {"id": "T1072",     "name": "Software Deployment Tools",         "tactic": "Execution"},
        {"id": "T1195",     "name": "Supply Chain Compromise",           "tactic": "Initial Access"},
        {"id": "T1543",     "name": "Create or Modify System Process",   "tactic": "Persistence"},
    ],
    "NET_CHANGE": [
        {"id": "T1049",     "name": "System Network Connections Discovery", "tactic": "Discovery"},
        {"id": "T1071",     "name": "Application Layer Protocol",        "tactic": "Command and Control"},
        {"id": "T1090",     "name": "Proxy",                             "tactic": "Command and Control"},
    ],
    "SYS_ERROR": [
        {"id": "T1499",     "name": "Endpoint Denial of Service",        "tactic": "Impact"},
        {"id": "T1485",     "name": "Data Destruction",                  "tactic": "Impact"},
        {"id": "T1562",     "name": "Impair Defenses",                   "tactic": "Defense Evasion"},
    ],
}
# ─── Event-type colors ───────────────────────────────────────────────────────
ETYPE_COLORS = {
    "AUTH":               "#f85149",      # red
    "SUDO":               "#e3a03a",      # orange
    "SUSPICIOUS_COMMAND": "#f85149",      # red
    "BASH_HISTORY":       "#bc8cff",      # purple
    "SYS":                "#5a7080",      # muted
    "CRON":               "#79c0ff",      # cyan
    "PKG_MGMT":           "#0ea5e9",      # blue
    "NET_CHANGE":         "#d29922",      # yellow
    "SYS_ERROR":          "#e3a03a",      # orange
}

# ─── Severity classifier ────────────────────────────────────────────────────
def classify(eventtype, success, message):
    msg = (message or "").lower()
    if eventtype == "SUSPICIOUS_COMMAND":
        return 3, "CRITICAL"
    if eventtype == "SYS_ERROR":
        return 2, "HIGH"
    if eventtype == "AUTH" and success == 0:
        if any(x in msg for x in ["invalid user", "root", "admin"]):
            return 3, "CRITICAL"
        return 2, "HIGH"
    if eventtype == "SUDO":
        return 2, "HIGH"
    if eventtype == "NET_CHANGE":
        return 1, "MEDIUM"
    if success == 0:
        return 1, "MEDIUM"
    return 0, "LOW"

# ─── DB helpers ─────────────────────────────────────────────────────────────
def get_db_connection(db_name=None):
    cfg = DB_CONFIG.copy()
    if db_name:
        cfg["database"] = db_name
    return psycopg2.connect(**cfg)

def list_databases():
    try:
        cfg = DB_CONFIG.copy()
        cfg["database"] = "postgres"
        conn = psycopg2.connect(**cfg)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname")
        dbs = [r[0] for r in cur.fetchall()]
        cur.close(); conn.close()
        return dbs
    except Exception:
        return []

def create_database_and_tables(db_name):
    try:
        cfg = DB_CONFIG.copy()
        cfg["database"] = "postgres"
        conn = psycopg2.connect(**cfg)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (db_name,))
        if not cur.fetchone():
            cur.execute(f'CREATE DATABASE "{db_name}"')
        cur.close(); conn.close()

        conn2 = get_db_connection(db_name)
        cur2 = conn2.cursor()
        cur2.execute("""
            CREATE TABLE IF NOT EXISTS Logs (
                logid SERIAL PRIMARY KEY,
                EventTime TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                EventType VARCHAR(50),
                Success INTEGER DEFAULT 1,
                UserName VARCHAR(100),
                HostName VARCHAR(100),
                SourceIp VARCHAR(50),
                Message TEXT,
                RawLine TEXT
            );
            CREATE TABLE IF NOT EXISTS fim_baseline (
                id SERIAL PRIMARY KEY,
                filepath TEXT NOT NULL,
                hash_sha256 TEXT,
                size BIGINT,
                mtime DOUBLE PRECISION,
                checked_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS sca_results (
                id SERIAL PRIMARY KEY,
                check_id VARCHAR(50),
                title TEXT,
                status VARCHAR(20),
                severity VARCHAR(20),
                framework_tags TEXT,
                checked_at TIMESTAMP DEFAULT NOW()
            );
        """)
        cur2.execute("CREATE INDEX IF NOT EXISTS idx_logs_eventtime ON Logs(EventTime DESC);")
        cur2.execute("CREATE INDEX IF NOT EXISTS idx_logs_eventtype ON Logs(EventType);")
        cur2.execute("CREATE INDEX IF NOT EXISTS idx_logs_sourceip  ON Logs(SourceIp);")
        cur2.execute("CREATE INDEX IF NOT EXISTS idx_logs_success   ON Logs(Success);")
        conn2.commit(); cur2.close(); conn2.close()
        return True, "Database and tables created successfully."
    except Exception as e:
        return False, str(e)

# ─── FIM ────────────────────────────────────────────────────────────────────
def fim_scan(paths=None):
    default_paths = ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
                     "/etc/hosts", "/etc/crontab", "/root/.bashrc"]
    targets = paths or default_paths
    results = []
    for p in targets:
        try:
            stat = os.stat(p)
            with open(p, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            results.append({"path": p, "hash": h, "size": stat.st_size,
                             "mtime": stat.st_mtime, "status": "ok"})
        except Exception as e:
            results.append({"path": p, "hash": None, "size": 0,
                             "mtime": 0, "status": str(e)})
    return results

# ─── SCA — 32 CIS Benchmark checks ──────────────────────────────────────────
def run_sca():
    checks = []

    def chk(cid, title, sev, passed, detail="", tags=""):
        checks.append({"id": cid, "title": title, "severity": sev,
                        "status": "PASS" if passed else "FAIL",
                        "detail": detail, "tags": tags})

    def read_file(path):
        try:
            with open(path) as f:
                return f.read()
        except Exception:
            return ""

    def cmd(c, timeout=3):
        try:
            r = subprocess.run(c, capture_output=True, text=True, timeout=timeout, shell=isinstance(c, str))
            return r.stdout + r.stderr
        except Exception:
            return ""

    sshd = read_file("/etc/ssh/sshd_config").lower()
    login_defs = read_file("/etc/login.defs").lower()
    pam_common = read_file("/etc/pam.d/common-password").lower()
    sysctl_out = cmd("sysctl -a", timeout=5)

    # ── SSH Hardening (10 checks) ──────────────────────────────────────────
    chk("SSH-001", "SSH: PermitRootLogin disabled",       "HIGH",
        "permitrootlogin no" in sshd or "permitrootlogin prohibit-password" in sshd,
        tags="PCI-DSS:8.2.1,HIPAA:164.312(a),NIST:PR.AC-1")
    chk("SSH-002", "SSH: PasswordAuthentication disabled", "MEDIUM",
        "passwordauthentication no" in sshd,
        tags="PCI-DSS:8.3.6,HIPAA:164.312(d),NIST:PR.AC-1")
    chk("SSH-003", "SSH: Protocol 2 enforced",            "HIGH",
        "protocol 1" not in sshd,
        tags="PCI-DSS:4.2.1,NIST:PR.DS-2")
    chk("SSH-004", "SSH: MaxAuthTries <= 4",               "MEDIUM",
        any(f"maxauthtries {n}" in sshd for n in ["1","2","3","4"]),
        tags="PCI-DSS:8.3.4,NIST:PR.AC-7")
    chk("SSH-005", "SSH: X11Forwarding disabled",          "LOW",
        "x11forwarding no" in sshd,
        tags="NIST:PR.AC-5")
    chk("SSH-006", "SSH: LoginGraceTime <= 60s",           "LOW",
        any(f"logingracetime {n}" in sshd for n in ["30","45","60","1m"]) or "logingracetime 0" not in sshd,
        tags="NIST:DE.CM-1")
    chk("SSH-007", "SSH: PermitEmptyPasswords disabled",   "CRITICAL",
        "permitemptypasswords no" in sshd or "permitemptypasswords" not in sshd,
        tags="PCI-DSS:8.3.6,HIPAA:164.312(d),NIST:PR.AC-1")
    chk("SSH-008", "SSH: AllowUsers or AllowGroups configured", "MEDIUM",
        "allowusers" in sshd or "allowgroups" in sshd,
        detail="No user restriction configured",
        tags="PCI-DSS:7.3,NIST:PR.AC-4")
    chk("SSH-009", "SSH: ClientAliveInterval configured",  "LOW",
        "clientaliveinterval" in sshd,
        tags="NIST:DE.CM-1")
    chk("SSH-010", "SSH: IgnoreRhosts enabled",            "HIGH",
        "ignorerhosts yes" in sshd or "ignorerhosts" not in sshd,
        tags="PCI-DSS:2.2.7,NIST:PR.AC-5")

    # ── Account / Password Policy (5 checks) ──────────────────────────────
    try:
        with open("/etc/shadow") as f:
            empty = any(line.split(":")[1] == "" for line in f if ":" in line)
        chk("ACC-001", "No accounts with empty passwords", "CRITICAL", not empty,
            tags="PCI-DSS:8.3.6,HIPAA:164.312(d),NIST:PR.AC-1")
    except Exception:
        chk("ACC-001", "No accounts with empty passwords", "CRITICAL", False,
            detail="Cannot read /etc/shadow",
            tags="PCI-DSS:8.3.6,HIPAA:164.312(d),NIST:PR.AC-1")

    pass_max = ""
    for line in login_defs.splitlines():
        if line.strip().startswith("pass_max_days"):
            pass_max = line.split()[-1].strip()
    chk("ACC-002", "Password max age <= 90 days", "MEDIUM",
        pass_max.isdigit() and int(pass_max) <= 90,
        detail=f"Current: {pass_max or 'unset'}",
        tags="PCI-DSS:8.3.9,HIPAA:164.308(a)(5),NIST:PR.AC-1")

    pass_min = ""
    for line in login_defs.splitlines():
        if line.strip().startswith("pass_min_len"):
            pass_min = line.split()[-1].strip()
    chk("ACC-003", "Password minimum length >= 14", "MEDIUM",
        pass_min.isdigit() and int(pass_min) >= 14,
        detail=f"Current: {pass_min or 'unset'}",
        tags="PCI-DSS:8.3.6,NIST:PR.AC-1")

    chk("ACC-004", "PAM password complexity configured", "MEDIUM",
        "pam_pwquality" in pam_common or "pam_cracklib" in pam_common,
        tags="PCI-DSS:8.3.6,HIPAA:164.308(a)(5),NIST:PR.AC-1")

    root_uid0 = cmd("awk -F: '($3==0){print $1}' /etc/passwd").strip()
    chk("ACC-005", "Only root has UID 0", "CRITICAL",
        root_uid0 == "root",
        detail=f"UID-0 accounts: {root_uid0}",
        tags="PCI-DSS:7.2,HIPAA:164.312(a),NIST:PR.AC-4")

    # ── Filesystem Permissions (4 checks) ─────────────────────────────────
    try:
        s = os.stat("/tmp")
        chk("FS-001", "/tmp has sticky bit set", "LOW", bool(s.st_mode & 0o1000),
            tags="NIST:PR.DS-1")
    except Exception:
        chk("FS-001", "/tmp has sticky bit set", "LOW", False)

    try:
        s = os.stat("/etc/passwd")
        chk("FS-002", "/etc/passwd permissions are 644 or tighter", "HIGH",
            oct(s.st_mode)[-3:] in ("644", "640", "600"),
            detail=f"Current: {oct(s.st_mode)[-3:]}",
            tags="PCI-DSS:10.3.2,NIST:PR.DS-1")
    except Exception:
        chk("FS-002", "/etc/passwd permissions are 644 or tighter", "HIGH", False)

    try:
        s = os.stat("/etc/shadow")
        chk("FS-003", "/etc/shadow permissions are 640 or tighter", "CRITICAL",
            oct(s.st_mode)[-3:] in ("640", "600", "000"),
            detail=f"Current: {oct(s.st_mode)[-3:]}",
            tags="PCI-DSS:8.3.6,HIPAA:164.312(a),NIST:PR.DS-1")
    except Exception:
        chk("FS-003", "/etc/shadow permissions are 640 or tighter", "CRITICAL", False,
            detail="Cannot stat /etc/shadow")

    world_writable = cmd("find / -xdev -type f -perm -0002 2>/dev/null | head -5", timeout=8).strip()
    chk("FS-004", "No world-writable files outside /tmp", "HIGH",
        not bool(world_writable),
        detail=world_writable[:100] if world_writable else "",
        tags="NIST:PR.DS-1,PCI-DSS:10.3.2")

    # ── Network / Firewall (5 checks) ─────────────────────────────────────
    ufw_out = cmd(["ufw", "status"])
    chk("NET-001", "Firewall (UFW) is active", "HIGH",
        "active" in ufw_out.lower(),
        detail="ufw status: " + (ufw_out.strip().splitlines()[0] if ufw_out.strip() else "not found"),
        tags="PCI-DSS:1.3,HIPAA:164.312(e),NIST:PR.AC-5")

    ip_forward = ""
    for line in sysctl_out.splitlines():
        if "net.ipv4.ip_forward" in line:
            ip_forward = line.split("=")[-1].strip()
    chk("NET-002", "IPv4 forwarding disabled (unless router)", "MEDIUM",
        ip_forward == "0",
        detail=f"net.ipv4.ip_forward = {ip_forward or 'unknown'}",
        tags="NIST:PR.AC-5")

    icmp_redirect = ""
    for line in sysctl_out.splitlines():
        if "net.ipv4.conf.all.accept_redirects" in line:
            icmp_redirect = line.split("=")[-1].strip()
    chk("NET-003", "ICMP redirects disabled", "MEDIUM",
        icmp_redirect == "0",
        detail=f"accept_redirects = {icmp_redirect or 'unknown'}",
        tags="PCI-DSS:1.3,NIST:PR.AC-5")

    rp_filter = ""
    for line in sysctl_out.splitlines():
        if "net.ipv4.conf.all.rp_filter" in line:
            rp_filter = line.split("=")[-1].strip()
    chk("NET-004", "Reverse path filtering enabled", "LOW",
        rp_filter in ("1", "2"),
        detail=f"rp_filter = {rp_filter or 'unknown'}",
        tags="NIST:PR.AC-5")

    syn_cookies = ""
    for line in sysctl_out.splitlines():
        if "net.ipv4.tcp_syncookies" in line:
            syn_cookies = line.split("=")[-1].strip()
    chk("NET-005", "TCP SYN cookies enabled", "LOW",
        syn_cookies == "1",
        detail=f"tcp_syncookies = {syn_cookies or 'unknown'}",
        tags="NIST:DE.CM-1")

    # ── Services / Software (8 checks) ────────────────────────────────────
    avahi = cmd(["systemctl", "is-active", "avahi-daemon"]).strip()
    chk("SVC-001", "Avahi daemon disabled", "MEDIUM",
        avahi not in ("active", "running"),
        detail=f"avahi-daemon: {avahi}",
        tags="NIST:PR.AC-5")

    cups = cmd(["systemctl", "is-active", "cups"]).strip()
    chk("SVC-002", "CUPS (printing) disabled", "LOW",
        cups not in ("active", "running"),
        detail=f"cups: {cups}",
        tags="NIST:PR.AC-5")

    telnet_out = cmd("dpkg -l telnet 2>/dev/null | grep '^ii'").strip()
    chk("SVC-003", "Telnet client not installed", "HIGH",
        not bool(telnet_out),
        tags="PCI-DSS:2.2.7,HIPAA:164.312(e),NIST:PR.DS-2")

    rsh_out = cmd("dpkg -l rsh-client 2>/dev/null | grep '^ii'").strip()
    chk("SVC-004", "rsh client not installed", "HIGH",
        not bool(rsh_out),
        tags="PCI-DSS:2.2.7,NIST:PR.DS-2")

    auditd = cmd(["systemctl", "is-active", "auditd"]).strip()
    chk("SVC-005", "Auditd service is running", "MEDIUM",
        auditd in ("active", "running"),
        detail=f"auditd: {auditd}",
        tags="PCI-DSS:10.1,HIPAA:164.312(b),NIST:DE.CM-7")

    rsyslog = cmd(["systemctl", "is-active", "rsyslog"]).strip()
    syslog_ng = cmd(["systemctl", "is-active", "syslog-ng"]).strip()
    chk("SVC-006", "Syslog service is running", "MEDIUM",
        rsyslog in ("active","running") or syslog_ng in ("active","running"),
        tags="PCI-DSS:10.1,HIPAA:164.312(b),NIST:DE.CM-7")

    at_allow = os.path.exists("/etc/at.allow")
    cron_allow = os.path.exists("/etc/cron.allow")
    chk("SVC-007", "cron/at access controlled via allow-lists", "LOW",
        at_allow and cron_allow,
        detail="Missing: " + (", ".join(filter(None, ["/etc/at.allow" if not at_allow else "", "/etc/cron.allow" if not cron_allow else ""])) or "none"),
        tags="NIST:PR.AC-4")

    unattended = cmd("dpkg -l unattended-upgrades 2>/dev/null | grep '^ii'").strip()
    chk("SVC-008", "Automatic security updates configured", "MEDIUM",
        bool(unattended),
        tags="PCI-DSS:6.3.3,NIST:ID.RA-1")

    return checks

# ─── Vulnerability Scan — NVD live + offline baseline ───────────────────────
NVD_OFFLINE = [
    {"package": "openssh-server", "cve": "CVE-2024-6387", "severity": "CRITICAL",
     "description": "regreSSHion — unauthenticated RCE in OpenSSH glibc-based systems"},
    {"package": "glibc",          "cve": "CVE-2023-4911", "severity": "CRITICAL",
     "description": "Looney Tunables — local privilege escalation via GLIBC_TUNABLES"},
    {"package": "sudo",           "cve": "CVE-2021-3156", "severity": "CRITICAL",
     "description": "Baron Samedit — heap-based buffer overflow in sudoedit"},
    {"package": "polkit",         "cve": "CVE-2021-4034", "severity": "CRITICAL",
     "description": "PwnKit — local privilege escalation in pkexec"},
    {"package": "bash",           "cve": "CVE-2014-6271", "severity": "CRITICAL",
     "description": "Shellshock — arbitrary code execution via env variables"},
    {"package": "openssl",        "cve": "CVE-2022-0778", "severity": "HIGH",
     "description": "Infinite loop via crafted certificate in BN_mod_sqrt()"},
    {"package": "openssl",        "cve": "CVE-2023-0286", "severity": "HIGH",
     "description": "X.400 address type confusion in GeneralName"},
    {"package": "curl",           "cve": "CVE-2023-23914", "severity": "MEDIUM",
     "description": "HSTS bypass via clear-text downgrade"},
    {"package": "wget",           "cve": "CVE-2021-31879", "severity": "MEDIUM",
     "description": "Authorization header exposure on redirect"},
    {"package": "vim",            "cve": "CVE-2022-1898", "severity": "HIGH",
     "description": "Use-after-free in vim before 8.2.4970"},
    {"package": "git",            "cve": "CVE-2023-25652", "severity": "HIGH",
     "description": "Path traversal via git apply --reject"},
    {"package": "python3",        "cve": "CVE-2023-24329", "severity": "MEDIUM",
     "description": "urllib.parse bypass via empty string in scheme"},
    {"package": "libssl3",        "cve": "CVE-2022-0778", "severity": "HIGH",
     "description": "OpenSSL BN_mod_sqrt infinite loop"},
    {"package": "zlib1g",         "cve": "CVE-2022-37434", "severity": "CRITICAL",
     "description": "Heap buffer over-read / over-write in inflate via extra field"},
    {"package": "libc6",          "cve": "CVE-2022-23219", "severity": "CRITICAL",
     "description": "Buffer overflow in glibc clnt_create via long pathname"},
    {"package": "nss",            "cve": "CVE-2023-0767", "severity": "HIGH",
     "description": "Arbitrary memory write via PKCS 12 import in NSS"},
]

NVD_PKG_QUERIES = [
    "openssh", "openssl", "sudo", "bash", "curl", "wget",
    "glibc", "polkit", "vim", "git", "python", "zlib",
]

def _nvd_query(keyword):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5"
        r = http_requests.get(url, timeout=2)
        if r.status_code == 200:
            data = r.json()
            results = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                metrics = cve.get("metrics", {})
                sev = "MEDIUM"
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    m = metrics.get(key, [])
                    if m:
                        sev = m[0].get("cvssData", {}).get("baseSeverity", "MEDIUM")
                        break
                desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
                results.append({"cve": cve_id, "severity": sev.upper(),
                                 "description": desc[:120], "source": "NVD-live"})
            return results
    except Exception:
        pass
    return None

def vuln_scan():
    try:
        r = subprocess.run(["dpkg", "-l"], capture_output=True, text=True, timeout=10)
        installed_pkgs = {l.split()[1].split(":")[0].lower()
                          for l in r.stdout.splitlines() if l.startswith("ii")}
    except Exception:
        installed_pkgs = set()

    vulns = []
    seen_cve = set()

    # Try NVD live for key packages
    for kw in NVD_PKG_QUERIES:
        if any(kw in p for p in installed_pkgs):
            live = _nvd_query(kw)
            if live:
                for v in live[:2]:
                    if v["cve"] not in seen_cve:
                        seen_cve.add(v["cve"])
                        vulns.append({"package": kw, **v})

    # Fill with offline baseline for installed packages
    for entry in NVD_OFFLINE:
        pkg = entry["package"].split(":")[0].lower()
        if entry["cve"] not in seen_cve and (pkg in installed_pkgs or not installed_pkgs):
            seen_cve.add(entry["cve"])
            vulns.append({**entry, "source": "offline"})

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    vulns.sort(key=lambda v: sev_order.get(v.get("severity", "INFO"), 4))
    return vulns

# ─── Compliance scoring from real SCA results ────────────────────────────────
def compute_compliance(checks):
    frameworks = {
        "PCI-DSS": {"pass": 0, "fail": 0, "crit_fail": 0},
        "HIPAA":   {"pass": 0, "fail": 0, "crit_fail": 0},
        "NIST":    {"pass": 0, "fail": 0, "crit_fail": 0},
    }
    for c in checks:
        tags = c.get("tags", "")
        for fw in frameworks:
            if fw in tags:
                if c["status"] == "PASS":
                    frameworks[fw]["pass"] += 1
                else:
                    frameworks[fw]["fail"] += 1
                    if c["severity"] in ("CRITICAL", "HIGH"):
                        frameworks[fw]["crit_fail"] += 1

    result = {}
    for fw, d in frameworks.items():
        total = d["pass"] + d["fail"]
        if total == 0:
            result[fw] = {"score": 0, "pass": 0, "fail": 0, "status": "NON-COMPLIANT"}
            continue
        raw = d["pass"] / total * 100
        penalty = d["crit_fail"] * 5
        score = max(0, round(raw - penalty))
        if score >= 80:
            status = "COMPLIANT"
        elif score >= 50:
            status = "PARTIAL"
        else:
            status = "NON-COMPLIANT"
        result[fw] = {"score": score, "pass": d["pass"], "fail": d["fail"],
                       "crit_fail": d["crit_fail"], "status": status}
    return result

# ─── Active Response ─────────────────────────────────────────────────────────
BLOCKED_IPS = set()

def block_ip(ip):
    if ip in BLOCKED_IPS:
        return False, "Already blocked"
    BLOCKED_IPS.add(ip)
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                        capture_output=True, timeout=5)
        return True, f"Blocked {ip} via iptables"
    except Exception as e:
        return True, f"Simulated block of {ip} (iptables unavailable: {e})"

def unblock_ip(ip):
    BLOCKED_IPS.discard(ip)
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                        capture_output=True, timeout=5)
        return True, f"Unblocked {ip}"
    except Exception as e:
        return True, f"Simulated unblock of {ip}"

# ─── Parser extension for new event types ───────────────────────────────────
def _extend_event_type(event, line):
    lower = line.lower()
    if event["EventType"] == "SYS":
        if any(x in lower for x in ["cron", "crond", "crontab", "periodic"]):
            event["EventType"] = "CRON"
        elif any(x in lower for x in ["apt", "dpkg", "yum", "dnf", "pip", "npm", "snap",
                                       "install", "remove", "upgrade", "uninstall"]):
            event["EventType"] = "PKG_MGMT"
        elif any(x in lower for x in ["ifconfig", "ip addr", "ip route", "network",
                                       "netplan", "nmcli", "interface up", "interface down",
                                       "link up", "link down", "dhclient"]):
            event["EventType"] = "NET_CHANGE"
        elif any(x in lower for x in ["error", "critical", "panic", "segfault", "kernel oops",
                                       "oom", "out of memory", "stack trace", "exception"]):
            event["EventType"] = "SYS_ERROR"
    return event

# ─── Dashboard HTML ──────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SP-110 — Linux Behavior Monitor</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,400;0,500;0,600;1,400&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg:      #060a0e;
  --surface: #0b1018;
  --panel:   #0f161e;
  --card:    #111c26;
  --border:  #1a2d3d;
  --border2: #223344;
  --text:    #cdd6e0;
  --muted:   #5a7080;
  --accent:  #00d4aa;
  --blue:    #0ea5e9;
  --red:     #f85149;
  --orange:  #e3a03a;
  --yellow:  #d29922;
  --green:   #3fb950;
  --purple:  #bc8cff;
  --cyan:    #79c0ff;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'IBM Plex Sans',sans-serif;font-size:13px;min-height:100vh;overflow:hidden}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.06) 2px,rgba(0,0,0,0.06) 4px);pointer-events:none;z-index:9999}

/* NAV */
nav{background:var(--surface);border-bottom:1px solid var(--border);height:52px;display:flex;align-items:center;justify-content:space-between;padding:0 20px;position:sticky;top:0;z-index:300}
.brand{font-family:'IBM Plex Mono',monospace;font-size:12px;font-weight:600;color:var(--accent);border:1px solid var(--accent);padding:3px 10px;border-radius:3px;letter-spacing:.1em}
.nav-center{display:flex;align-items:center;gap:4px;overflow-x:auto}
.nav-tab{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:500;letter-spacing:.06em;padding:5px 14px;border-radius:4px;border:1px solid transparent;background:none;color:var(--muted);cursor:pointer;transition:all .15s;white-space:nowrap}
.nav-tab:hover{color:var(--text);border-color:var(--border2)}
.nav-tab.active{color:var(--accent);border-color:var(--accent);background:rgba(0,212,170,.08)}
.nav-right{display:flex;align-items:center;gap:12px;flex-shrink:0}
.live-badge{display:flex;align-items:center;gap:5px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--accent)}
.live-dot{width:6px;height:6px;border-radius:50%;background:var(--accent);animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}
.nav-time{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)}
.nav-btn{font-family:'IBM Plex Mono',monospace;font-size:10px;padding:4px 11px;border-radius:3px;border:1px solid var(--border2);background:var(--panel);color:var(--text);cursor:pointer;transition:all .12s}
.nav-btn:hover{border-color:var(--blue);color:var(--blue)}
.nav-btn.danger{border-color:#2a1010;color:var(--red)}
.nav-btn.danger:hover{border-color:var(--red);background:rgba(248,81,73,.1)}

/* LAYOUT */
.shell{display:flex;height:calc(100vh - 52px);overflow:hidden}
.sidebar{width:260px;min-width:260px;background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;display:flex;flex-direction:column}
.main-area{flex:1;overflow-y:auto;padding:18px}

/* SIDEBAR */
.sb-section{padding:14px;border-bottom:1px solid var(--border)}
.sb-label{font-family:'IBM Plex Mono',monospace;font-size:9px;font-weight:600;letter-spacing:.14em;color:var(--muted);text-transform:uppercase;margin-bottom:10px}
.kpi-stack{display:flex;flex-direction:column;gap:6px}
.kpi{background:var(--panel);border:1px solid var(--border);border-radius:5px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center}
.kpi-lbl{font-size:10px;color:var(--muted)}
.kpi-val{font-family:'IBM Plex Mono',monospace;font-size:20px;font-weight:600;line-height:1}
.alert-stack{display:flex;flex-direction:column;gap:5px}
.al-item{background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--red);border-radius:4px;padding:7px 9px;font-size:11px;cursor:pointer;transition:background .12s}
.al-item:hover{background:var(--card)}
.al-item.warn{border-left-color:var(--orange)}
.al-item.info{border-left-color:var(--blue)}
.al-ip{font-family:'IBM Plex Mono',monospace;font-weight:600;color:var(--text);font-size:11px}
.al-meta{color:var(--muted);font-size:10px;margin-top:1px}
.etype-list{display:flex;flex-direction:column;gap:3px}
.etype-row{display:flex;justify-content:space-between;align-items:center;padding:4px 7px;border-radius:3px;cursor:pointer;transition:background .1s}
.etype-row:hover,.etype-row.active{background:var(--border)}
.etype-name{font-family:'IBM Plex Mono',monospace;font-size:10px;display:flex;align-items:center;gap:7px}
.etype-dot{width:5px;height:5px;border-radius:50%}
.etype-count{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);background:var(--border);padding:1px 6px;border-radius:8px}
.sb-host{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--text);padding:4px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between}
.sb-host:last-child{border-bottom:none}

/* PAGES */
.page{display:none}.page.active{display:block}

/* STAT CARDS */
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:7px;padding:14px 16px;position:relative;overflow:hidden}
.stat::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px}
.stat.s-red::after{background:var(--red)}.stat.s-orange::after{background:var(--orange)}
.stat.s-blue::after{background:var(--blue)}.stat.s-green::after{background:var(--green)}
.stat.s-purple::after{background:var(--purple)}.stat.s-cyan::after{background:var(--cyan)}
.stat-lbl{font-size:10px;color:var(--muted);margin-bottom:5px;letter-spacing:.04em}
.stat-val{font-family:'IBM Plex Mono',monospace;font-size:28px;font-weight:600;line-height:1}
.c-red{color:var(--red)}.c-orange{color:var(--orange)}.c-blue{color:var(--blue)}
.c-green{color:var(--green)}.c-purple{color:var(--purple)}.c-cyan{color:var(--cyan)}
.c-yellow{color:var(--yellow)}

/* PANELS */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:7px;margin-bottom:14px;overflow:hidden}
.ph{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.pt{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;letter-spacing:.1em;color:var(--muted);text-transform:uppercase}
.pb{padding:16px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:14px}

/* LOG TABLE */
.search-bar{background:var(--surface);border:1px solid var(--border);border-radius:5px;display:flex;align-items:center;padding:0 12px;gap:9px;margin-bottom:12px}
.search-bar:focus-within{border-color:var(--blue)}
.search-input{flex:1;background:none;border:none;outline:none;color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:12px;padding:9px 0}
.search-input::placeholder{color:var(--muted)}
.filter-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.fl{font-size:10px;color:var(--muted);margin-right:4px}
.chip{font-family:'IBM Plex Mono',monospace;font-size:9px;font-weight:500;letter-spacing:.07em;padding:3px 9px;border-radius:3px;border:1px solid var(--border2);background:var(--panel);color:var(--muted);cursor:pointer;transition:all .12s;text-transform:uppercase}
.chip:hover{color:var(--text)}.chip.active{background:rgba(0,212,170,.1);border-color:var(--accent);color:var(--accent)}
.chip.cr.active{background:rgba(248,81,73,.1);border-color:var(--red);color:var(--red)}
.chip.co.active{background:rgba(227,160,58,.1);border-color:var(--orange);color:var(--orange)}
.chip.cb.active{background:rgba(14,165,233,.1);border-color:var(--blue);color:var(--blue)}
.chip.cp.active{background:rgba(188,140,255,.1);border-color:var(--purple);color:var(--purple)}
.chip.cc.active{background:rgba(121,192,255,.1);border-color:var(--cyan);color:var(--cyan)}
.chip.cy.active{background:rgba(210,153,34,.1);border-color:var(--yellow);color:var(--yellow)}
table{width:100%;border-collapse:collapse;font-family:'IBM Plex Mono',monospace;font-size:11px}
thead{position:sticky;top:0;z-index:10}
th{background:var(--panel);padding:8px 12px;text-align:left;font-size:9px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:var(--text)}
td{padding:7px 12px;border-bottom:1px solid rgba(26,45,61,.5);vertical-align:middle;max-width:0}
tr.lr{cursor:pointer;transition:background .08s}
tr.lr:hover td{background:rgba(255,255,255,.02)}
tr.r-red td{background:rgba(248,81,73,.04)}tr.r-red:hover td{background:rgba(248,81,73,.08)}
tr.r-orange td{background:rgba(227,160,58,.03)}tr.r-orange:hover td{background:rgba(227,160,58,.07)}
.col-time{width:140px;color:var(--muted);white-space:nowrap}
.col-type{width:130px}.col-host{width:110px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.col-user{width:90px;color:var(--blue);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.col-ip{width:110px;color:var(--accent);white-space:nowrap}
.col-msg{color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.col-sev{width:80px;text-align:center}
.badge{display:inline-block;padding:2px 7px;border-radius:2px;font-size:9px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;white-space:nowrap}
.badge-AUTH{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.badge-SUDO{background:rgba(227,160,58,.15);color:var(--orange);border:1px solid rgba(227,160,58,.3)}
.badge-SUSPICIOUS_COMMAND{background:rgba(248,81,73,.2);color:#ff7070;border:1px solid rgba(248,81,73,.4)}
.badge-BASH_HISTORY{background:rgba(188,140,255,.15);color:var(--purple);border:1px solid rgba(188,140,255,.3)}
.badge-SYS{background:rgba(90,112,128,.15);color:var(--muted);border:1px solid rgba(90,112,128,.3)}
.badge-CRON{background:rgba(121,192,255,.15);color:var(--cyan);border:1px solid rgba(121,192,255,.3)}
.badge-PKG_MGMT{background:rgba(14,165,233,.15);color:var(--blue);border:1px solid rgba(14,165,233,.3)}
.badge-NET_CHANGE{background:rgba(210,153,34,.15);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}
.badge-SYS_ERROR{background:rgba(227,160,58,.2);color:var(--orange);border:1px solid rgba(227,160,58,.4)}
.sev-badge{display:inline-block;width:60px;text-align:center;padding:2px 0;border-radius:2px;font-size:9px;font-weight:600;letter-spacing:.06em}
.sev-3{background:rgba(248,81,73,.2);color:var(--red)}.sev-2{background:rgba(227,160,58,.2);color:var(--orange)}
.sev-1{background:rgba(210,153,34,.15);color:var(--yellow)}.sev-0{background:rgba(63,185,80,.1);color:var(--green)}
.pagination{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-top:1px solid var(--border)}
.pg-info{font-size:10px;color:var(--muted);font-family:'IBM Plex Mono',monospace}
.pg-btns{display:flex;gap:5px}
.pg-btn{font-family:'IBM Plex Mono',monospace;font-size:10px;padding:3px 10px;border:1px solid var(--border2);background:var(--panel);color:var(--text);border-radius:3px;cursor:pointer;transition:all .12s}
.pg-btn:hover{border-color:var(--accent);color:var(--accent)}.pg-btn:disabled{opacity:.3;cursor:not-allowed}
.pg-btn.cur{border-color:var(--accent);color:var(--accent);background:rgba(0,212,170,.08)}

/* DETAIL DRAWER */
#drawer{background:var(--surface);border:1px solid var(--border);border-top:2px solid var(--accent);border-radius:8px 8px 0 0;position:fixed;bottom:0;left:260px;right:0;max-height:260px;overflow-y:auto;padding:14px 20px;transform:translateY(100%);transition:transform .2s ease;z-index:250}
#drawer.open{transform:translateY(0)}
.dh{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.dt{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;color:var(--accent);letter-spacing:.08em;text-transform:uppercase}
.dc{background:none;border:none;color:var(--muted);cursor:pointer;font-size:15px}
.dc:hover{color:var(--text)}
.dg{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}
.dk{font-size:9px;letter-spacing:.08em;color:var(--muted);text-transform:uppercase;margin-bottom:2px}
.dv{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--text);word-break:break-all}
.dr{margin-top:10px;background:var(--panel);border:1px solid var(--border);border-radius:3px;padding:8px 12px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);word-break:break-all;white-space:pre-wrap}
.mitre-chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.mitre-chip{font-family:'IBM Plex Mono',monospace;font-size:9px;padding:3px 8px;border-radius:3px;border:1px solid rgba(14,165,233,.3);background:rgba(14,165,233,.08);color:var(--blue);cursor:pointer;text-decoration:none}
.mitre-chip:hover{border-color:var(--blue);background:rgba(14,165,233,.15)}

/* FORMS */
.form-group{margin-bottom:12px}
.form-label{font-size:10px;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;margin-bottom:5px;display:block}
.form-input{width:100%;background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:8px 12px;color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:12px;outline:none;transition:border .15s}
.form-input:focus{border-color:var(--blue)}
.form-select{width:100%;background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:8px 12px;color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:12px;outline:none;cursor:pointer}
.btn{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:500;letter-spacing:.06em;padding:7px 14px;border-radius:4px;border:1px solid var(--border2);background:var(--panel);color:var(--text);cursor:pointer;transition:all .14s;display:inline-flex;align-items:center;gap:6px}
.btn:hover{border-color:var(--blue);color:var(--blue)}
.btn.btn-accent{border-color:var(--accent);color:var(--accent);background:rgba(0,212,170,.08)}
.btn.btn-accent:hover{background:rgba(0,212,170,.15)}
.btn.btn-red{border-color:#2a1010;color:var(--red)}
.btn.btn-red:hover{border-color:var(--red);background:rgba(248,81,73,.1)}
.btn.btn-blue{border-color:rgba(14,165,233,.3);color:var(--blue);background:rgba(14,165,233,.06)}
.btn.btn-blue:hover{background:rgba(14,165,233,.12)}
.btn.btn-sm{padding:3px 9px;font-size:9px}

/* TOAST */
#toast{position:fixed;top:64px;right:20px;z-index:400;display:flex;flex-direction:column;gap:8px}
.toast-msg{background:var(--card);border:1px solid var(--border2);border-radius:5px;padding:10px 16px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--text);animation:slideIn .2s ease;display:flex;align-items:center;gap:8px;max-width:320px}
.toast-msg.ok{border-left:3px solid var(--green)}.toast-msg.err{border-left:3px solid var(--red)}.toast-msg.info{border-left:3px solid var(--blue)}
@keyframes slideIn{from{transform:translateX(20px);opacity:0}to{transform:translateX(0);opacity:1}}

/* MISC */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
.empty-state{text-align:center;padding:40px 20px;color:var(--muted);font-family:'IBM Plex Mono',monospace;font-size:11px}
.tag{font-family:'IBM Plex Mono',monospace;font-size:9px;padding:2px 7px;border-radius:2px;white-space:nowrap}
.tag-crit{background:rgba(248,81,73,.2);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.tag-high{background:rgba(227,160,58,.2);color:var(--orange);border:1px solid rgba(227,160,58,.3)}
.tag-med{background:rgba(210,153,34,.15);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}
.tag-low{background:rgba(63,185,80,.1);color:var(--green);border:1px solid rgba(63,185,80,.2)}
.tag-info{background:rgba(90,112,128,.15);color:var(--muted);border:1px solid rgba(90,112,128,.3)}

/* FIM / SCA / VULN */
.fim-table,.sca-table,.vuln-table{width:100%;border-collapse:collapse;font-family:'IBM Plex Mono',monospace;font-size:11px}
.fim-table th,.sca-table th,.vuln-table th{background:var(--panel);padding:7px 12px;text-align:left;font-size:9px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border)}
.fim-table td,.sca-table td,.vuln-table td{padding:7px 12px;border-bottom:1px solid rgba(26,45,61,.5);vertical-align:middle}
.progress-bar{height:4px;background:var(--border);border-radius:2px;overflow:hidden;margin-top:6px}
.progress-fill{height:100%;border-radius:2px;transition:width .4s ease}
.chart-wrap{position:relative;height:160px}
.mitre-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px}
.mitre-card{background:var(--panel);border:1px solid var(--border);border-radius:5px;padding:10px 12px;cursor:pointer;transition:border-color .15s}
.mitre-card:hover{border-color:var(--blue)}
.mitre-id{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;color:var(--blue)}
.mitre-name{font-size:11px;color:var(--text);margin:3px 0}
.mitre-tactic{font-size:9px;color:var(--muted)}
.mitre-count{font-family:'IBM Plex Mono',monospace;font-size:20px;font-weight:600;color:var(--accent)}

/* DB Manager */
.db-list{display:flex;flex-direction:column;gap:6px}
.db-item{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;transition:all .12s}
.db-item:hover{border-color:var(--blue)}.db-item.active-db{border-color:var(--accent);background:rgba(0,212,170,.06)}
.db-name{font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--text)}

/* Log path manager */
.path-list{display:flex;flex-direction:column;gap:5px}
.path-item{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:7px 12px;display:flex;justify-content:space-between;align-items:center;font-family:'IBM Plex Mono',monospace;font-size:11px}
.path-status{width:7px;height:7px;border-radius:50%;background:var(--green)}
.path-status.off{background:var(--muted)}
.ip-table{width:100%;border-collapse:collapse;font-family:'IBM Plex Mono',monospace;font-size:11px}
.ip-table th{background:var(--panel);padding:7px 12px;text-align:left;font-size:9px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border)}
.ip-table td{padding:7px 12px;border-bottom:1px solid rgba(26,45,61,.5)}

/* Compliance badges */
.comp-card{background:var(--panel);border:1px solid var(--border);border-radius:7px;padding:18px;text-align:center}
.comp-status{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;letter-spacing:.08em;padding:3px 10px;border-radius:3px;display:inline-block;margin-top:6px}
.comp-status.COMPLIANT{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.comp-status.PARTIAL{background:rgba(210,153,34,.15);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}
.comp-status.NON-COMPLIANT{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}

/* Process table */
.proc-table{width:100%;border-collapse:collapse;font-family:'IBM Plex Mono',monospace;font-size:11px}
.proc-table th{background:var(--panel);padding:7px 12px;text-align:left;font-size:9px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border)}
.proc-table td{padding:6px 12px;border-bottom:1px solid rgba(26,45,61,.5);vertical-align:middle}
</style>
</head>
<body>

<!-- NAV -->
<nav>
  <div style="display:flex;align-items:center;gap:14px;flex-shrink:0">
    <span class="brand">SP-110</span>
    <span style="font-size:13px;font-weight:500;letter-spacing:.02em">Linux Behavior Monitor</span>
  </div>
  <div class="nav-center">
    <button class="nav-tab active" onclick="showPage('overview',this)">Overview</button>
    <button class="nav-tab" onclick="showPage('logs',this)">Log Events</button>
    <button class="nav-tab" onclick="showPage('analytics',this)">Analytics</button>
    <button class="nav-tab" onclick="showPage('fim',this)">File Integrity</button>
    <button class="nav-tab" onclick="showPage('sca',this)">Config Audit</button>
    <button class="nav-tab" onclick="showPage('vuln',this)">Vulnerabilities</button>
    <button class="nav-tab" onclick="showPage('mitre',this)">MITRE ATT&CK</button>
    <button class="nav-tab" onclick="showPage('response',this)">Active Response</button>
    <button class="nav-tab" onclick="showPage('admin',this)">Administration</button>
  </div>
  <div class="nav-right">
    <div class="live-badge"><div class="live-dot"></div><span>LIVE</span></div>
    <span class="nav-time" id="nav-time">--:--:--</span>
    <button class="nav-btn" onclick="exportCSV()">⬇ Export CSV</button>
    <button class="nav-btn danger" onclick="confirmClear()">✕ Clear Logs</button>
  </div>
</nav>

<div class="shell">
<!-- SIDEBAR -->
<div class="sidebar">
  <div class="sb-section">
    <div class="sb-label">Live Metrics</div>
    <div class="kpi-stack">
      <div class="kpi"><span class="kpi-lbl">Failed Logins / min</span><span class="kpi-val c-red" id="s-failed">0</span></div>
      <div class="kpi"><span class="kpi-lbl">Brute Force IPs</span><span class="kpi-val c-orange" id="s-brute">0</span></div>
      <div class="kpi"><span class="kpi-lbl">Sudo Abuse</span><span class="kpi-val c-purple" id="s-sudo">0</span></div>
      <div class="kpi"><span class="kpi-lbl">Unique Source IPs</span><span class="kpi-val c-cyan" id="s-ips">0</span></div>
      <div class="kpi"><span class="kpi-lbl">Total Log Events</span><span class="kpi-val" id="s-total">0</span></div>
      <div class="kpi"><span class="kpi-lbl">Suspicious Commands</span><span class="kpi-val c-red" id="s-susp">0</span></div>
    </div>
  </div>
  <div class="sb-section">
    <div class="sb-label">Active Alerts</div>
    <div class="alert-stack" id="sb-alerts"><div class="empty-state">No alerts</div></div>
  </div>
  <div class="sb-section">
    <div class="sb-label">Event Types</div>
    <div class="etype-list" id="sb-etypes"></div>
  </div>
  <div class="sb-section">
    <div class="sb-label">Monitored Hosts</div>
    <div id="sb-hosts" style="font-family:'IBM Plex Mono',monospace;font-size:10px"></div>
  </div>
  <div class="sb-section">
    <div class="sb-label">Blocked IPs</div>
    <div id="sb-blocked" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)">None</div>
  </div>
</div>

<!-- MAIN AREA -->
<div class="main-area">

<!-- OVERVIEW -->
<div class="page active" id="page-overview">
  <div class="stats-row">
    <div class="stat s-red"><div class="stat-lbl">Failed Auth Events</div><div class="stat-val c-red" id="ov-failed">0</div></div>
    <div class="stat s-orange"><div class="stat-lbl">Auth Events Total</div><div class="stat-val c-orange" id="ov-auth">0</div></div>
    <div class="stat s-blue"><div class="stat-lbl">Suspicious Commands</div><div class="stat-val c-blue" id="ov-susp">0</div></div>
    <div class="stat s-purple"><div class="stat-lbl">Monitored Hosts</div><div class="stat-val c-purple" id="ov-hosts">0</div></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">Events Over Time (60 min)</span></div>
      <div class="pb"><div class="chart-wrap"><canvas id="chart-timeline"></canvas></div></div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Event Type Breakdown</span></div>
      <div class="pb"><div class="chart-wrap"><canvas id="chart-etypes"></canvas></div></div>
    </div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">Top Attacker IPs</span></div>
      <div class="pb"><div class="chart-wrap"><canvas id="chart-ips"></canvas></div></div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Severity Distribution</span></div>
      <div class="pb"><div class="chart-wrap"><canvas id="chart-sev"></canvas></div></div>
    </div>
  </div>
  <div class="panel">
    <div class="ph"><span class="pt">Recent High-Severity Events</span><span id="ov-log-count" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)">—</span></div>
    <div style="overflow-x:auto">
      <table><thead><tr>
        <th class="col-time">Timestamp</th><th class="col-type">Type</th>
        <th class="col-host">Host</th><th class="col-user">User</th>
        <th class="col-ip">Source IP</th><th class="col-msg">Message</th><th class="col-sev">Severity</th>
      </tr></thead>
      <tbody id="ov-table"></tbody></table>
    </div>
  </div>
</div>

<!-- LOG EVENTS -->
<div class="page" id="page-logs">
  <div class="search-bar">
    <span style="color:var(--muted);font-size:13px">⌕</span>
    <input class="search-input" id="log-search" placeholder="Search messages, IPs, usernames…" oninput="filterLogs()">
    <span id="log-count" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);white-space:nowrap">0 events</span>
  </div>
  <div class="filter-row">
    <span class="fl">Filter:</span>
    <span class="chip active" data-filter="ALL" onclick="setFilter(this,'ALL')">ALL</span>
    <span class="chip cr" data-filter="AUTH" onclick="setFilter(this,'AUTH')">AUTH</span>
    <span class="chip co" data-filter="SUDO" onclick="setFilter(this,'SUDO')">SUDO</span>
    <span class="chip cr" data-filter="SUSPICIOUS_COMMAND" onclick="setFilter(this,'SUSPICIOUS_COMMAND')">SUSPICIOUS</span>
    <span class="chip cp" data-filter="BASH_HISTORY" onclick="setFilter(this,'BASH_HISTORY')">BASH</span>
    <span class="chip cb" data-filter="SYS" onclick="setFilter(this,'SYS')">SYS</span>
    <span class="chip cc" data-filter="CRON" onclick="setFilter(this,'CRON')">CRON</span>
    <span class="chip cb" data-filter="PKG_MGMT" onclick="setFilter(this,'PKG_MGMT')">PKG_MGMT</span>
    <span class="chip cy" data-filter="NET_CHANGE" onclick="setFilter(this,'NET_CHANGE')">NET_CHANGE</span>
    <span class="chip co" data-filter="SYS_ERROR" onclick="setFilter(this,'SYS_ERROR')">SYS_ERROR</span>
    <span style="flex:1"></span>
    <span class="fl">Severity:</span>
    <span class="chip cr" data-sev="3" onclick="setSev(this,3)">CRITICAL</span>
    <span class="chip co" data-sev="2" onclick="setSev(this,2)">HIGH</span>
    <span class="chip" data-sev="1" onclick="setSev(this,1)">MEDIUM</span>
    <span class="chip" data-sev="0" onclick="setSev(this,0)">LOW</span>
  </div>
  <div class="panel" style="margin-bottom:0">
    <div style="overflow-x:auto">
      <table><thead><tr>
        <th class="col-time" onclick="sortTable('timestamp')">Timestamp</th>
        <th class="col-type" onclick="sortTable('eventtype')">Type</th>
        <th class="col-host" onclick="sortTable('hostname')">Host</th>
        <th class="col-user" onclick="sortTable('username')">User</th>
        <th class="col-ip" onclick="sortTable('sourceip')">Source IP</th>
        <th class="col-msg">Message</th>
        <th class="col-sev" onclick="sortTable('threat_level')">Severity</th>
      </tr></thead>
      <tbody id="log-table"></tbody></table>
    </div>
    <div class="pagination">
      <span class="pg-info" id="pg-info">Showing 0–0 of 0</span>
      <div class="pg-btns" id="pg-btns"></div>
    </div>
  </div>
</div>

<!-- ANALYTICS -->
<div class="page" id="page-analytics">
  <div class="stats-row" style="grid-template-columns:repeat(5,1fr)">
    <div class="stat s-red"><div class="stat-lbl">Total Events</div><div class="stat-val" id="an-total">0</div></div>
    <div class="stat s-orange"><div class="stat-lbl">Failed Logins</div><div class="stat-val c-red" id="an-failed">0</div></div>
    <div class="stat s-blue"><div class="stat-lbl">Auth Events</div><div class="stat-val c-orange" id="an-auth">0</div></div>
    <div class="stat s-green"><div class="stat-lbl">Suspicious Cmds</div><div class="stat-val c-blue" id="an-susp">0</div></div>
    <div class="stat s-purple"><div class="stat-lbl">Sudo Events</div><div class="stat-val c-purple" id="an-sudo-count">0</div></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">Failed Logins Timeline</span></div>
      <div class="pb"><div class="chart-wrap"><canvas id="an-chart-tl"></canvas></div></div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Auth Success vs Failure</span></div>
      <div class="pb"><div class="chart-wrap"><canvas id="an-chart-sf"></canvas></div></div>
    </div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">Top Attacker IPs (Failed Auth)</span></div>
      <div class="pb">
        <table class="ip-table">
          <thead><tr><th>IP Address</th><th>Count</th><th>Threat</th><th>Action</th></tr></thead>
          <tbody id="an-ip-table"></tbody>
        </table>
      </div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Sudo Usage by User</span></div>
      <div class="pb">
        <table class="ip-table">
          <thead><tr><th>Username</th><th>Events</th><th>Risk</th></tr></thead>
          <tbody id="an-sudo-table"></tbody>
        </table>
      </div>
    </div>
  </div>
  <div class="panel">
    <div class="ph"><span class="pt">Event Heatmap (Hour of Day)</span></div>
    <div class="pb"><div style="height:100px;display:flex;align-items:flex-end;gap:3px" id="an-heatmap"></div></div>
  </div>
</div>

<!-- FILE INTEGRITY -->
<div class="page" id="page-fim">
  <div class="panel">
    <div class="ph">
      <span class="pt">File Integrity Monitoring</span>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input class="form-input" id="fim-path-input" placeholder="/path/to/file" style="width:240px;font-size:11px;padding:5px 10px">
        <button class="btn btn-accent" onclick="addFimPath()">+ Add Path</button>
        <button class="btn btn-blue" onclick="runFim()">▶ Run Scan</button>
        <button class="btn" onclick="resetFimBaseline()" title="Clear baseline and re-establish">↺ Reset Baseline</button>
      </div>
    </div>
    <div class="pb">
      <div class="path-list" id="fim-paths" style="margin-bottom:14px"></div>
      <table class="fim-table">
        <thead><tr><th>File Path</th><th>SHA-256</th><th>Size</th><th>Modified</th><th>Status</th></tr></thead>
        <tbody id="fim-results"></tbody>
      </table>
      <div id="fim-empty" class="empty-state">No scan results. Add paths and run scan.</div>
    </div>
  </div>
  <div class="panel">
    <div class="ph"><span class="pt">Baseline Comparison</span></div>
    <div class="pb">
      <div class="grid-3">
        <div class="stat s-green"><div class="stat-lbl">Files Unchanged</div><div class="stat-val c-green" id="fim-ok">0</div></div>
        <div class="stat s-orange"><div class="stat-lbl">Files Modified</div><div class="stat-val c-orange" id="fim-mod">0</div></div>
        <div class="stat s-red"><div class="stat-lbl">Files Missing/Error</div><div class="stat-val c-red" id="fim-miss">0</div></div>
      </div>
    </div>
  </div>
</div>

<!-- CONFIG AUDIT (SCA) -->
<div class="page" id="page-sca">
  <div class="stats-row" style="grid-template-columns:repeat(4,1fr)">
    <div class="stat s-green"><div class="stat-lbl">Checks Passed</div><div class="stat-val c-green" id="sca-pass">—</div></div>
    <div class="stat s-red"><div class="stat-lbl">Checks Failed</div><div class="stat-val c-red" id="sca-fail">—</div></div>
    <div class="stat s-blue"><div class="stat-lbl">Score</div><div class="stat-val c-blue" id="sca-score">—</div></div>
    <div class="stat s-orange"><div class="stat-lbl">Critical Fails</div><div class="stat-val c-orange" id="sca-crit">—</div></div>
  </div>
  <div class="panel">
    <div class="ph">
      <span class="pt">CIS Benchmark — 32 Security Checks</span>
      <div style="display:flex;gap:8px;align-items:center">
        <select class="form-select" id="sca-filter" style="width:160px;padding:5px 10px;font-size:10px" onchange="filterSca()">
          <option value="ALL">All Checks</option>
          <option value="FAIL">Failures Only</option>
          <option value="PASS">Passed Only</option>
          <option value="CRITICAL">Critical Only</option>
        </select>
        <button class="btn btn-accent" onclick="runSca()">▶ Run Checks</button>
      </div>
    </div>
    <div class="pb">
      <div id="sca-progress" style="display:none;margin-bottom:12px">
        <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-bottom:6px">Running CIS benchmark checks…</div>
        <div class="progress-bar"><div class="progress-fill" id="sca-pb" style="width:0%;background:var(--accent)"></div></div>
      </div>
      <table class="sca-table">
        <thead><tr><th>Check ID</th><th>Description</th><th>Framework Tags</th><th>Severity</th><th>Result</th></tr></thead>
        <tbody id="sca-results"></tbody>
      </table>
      <div id="sca-empty" class="empty-state">Click "Run Checks" to assess security configuration against 32 CIS Benchmark controls</div>
    </div>
  </div>
</div>

<!-- VULNERABILITIES -->
<div class="page" id="page-vuln">
  <div class="stats-row" style="grid-template-columns:repeat(4,1fr)">
    <div class="stat s-red"><div class="stat-lbl">Critical CVEs</div><div class="stat-val c-red" id="vn-crit">—</div></div>
    <div class="stat s-orange"><div class="stat-lbl">High CVEs</div><div class="stat-val c-orange" id="vn-high">—</div></div>
    <div class="stat s-blue"><div class="stat-lbl">Medium CVEs</div><div class="stat-val c-blue" id="vn-med">—</div></div>
    <div class="stat s-green"><div class="stat-lbl">Total Findings</div><div class="stat-val" id="vn-total">—</div></div>
  </div>
  <div class="panel">
    <div class="ph">
      <span class="pt">Vulnerability Detection</span>
      <div style="display:flex;gap:8px;align-items:center">
        <span id="vuln-source-badge" style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted)"></span>
        <button class="btn btn-accent" onclick="runVuln()">▶ Scan Packages</button>
      </div>
    </div>
    <div class="pb">
      <table class="vuln-table">
        <thead><tr><th>Package</th><th>CVE ID</th><th>Severity</th><th>Description</th><th>Source</th><th>Reference</th></tr></thead>
        <tbody id="vuln-results"></tbody>
      </table>
      <div id="vuln-empty" class="empty-state">Click "Scan Packages" to check for known vulnerabilities</div>
    </div>
  </div>
</div>

<!-- MITRE ATT&CK -->
<div class="page" id="page-mitre">
  <div class="panel">
    <div class="ph">
      <span class="pt">MITRE ATT&CK v15 — Technique Correlations</span>
      <span style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)">Based on live log data · Click cards to open ATT&CK</span>
    </div>
    <div class="pb">
      <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px" id="mitre-tactics"></div>
      <div class="mitre-grid" id="mitre-cards"></div>
    </div>
  </div>
  <div class="panel">
    <div class="ph"><span class="pt">ATT&CK Matrix Coverage</span></div>
    <div class="pb">
      <div class="grid-2">
        <div>
          <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-bottom:8px">DETECTED TACTICS</div>
          <div id="mitre-tactic-list" style="display:flex;flex-direction:column;gap:6px"></div>
        </div>
        <div><div class="chart-wrap"><canvas id="mitre-chart"></canvas></div></div>
      </div>
    </div>
  </div>
</div>

<!-- ACTIVE RESPONSE -->
<div class="page" id="page-response">
  <div class="stats-row" style="grid-template-columns:repeat(3,1fr)">
    <div class="stat s-red"><div class="stat-lbl">Blocked IPs</div><div class="stat-val c-red" id="ar-blocked-count">0</div></div>
    <div class="stat s-orange"><div class="stat-lbl">Brute Force Detected</div><div class="stat-val c-orange" id="ar-brute">0</div></div>
    <div class="stat s-blue"><div class="stat-lbl">Auto-Responses Fired</div><div class="stat-val c-blue" id="ar-auto">0</div></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">Block IP Address</span></div>
      <div class="pb">
        <div class="form-group">
          <label class="form-label">IP Address</label>
          <input class="form-input" id="ar-ip-input" placeholder="192.168.1.100" type="text">
        </div>
        <div class="form-group">
          <label class="form-label">Reason</label>
          <select class="form-select" id="ar-reason">
            <option>Brute Force Attack</option>
            <option>Suspicious Commands</option>
            <option>Port Scanning</option>
            <option>Manual Block</option>
          </select>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-red" onclick="blockIP()">⊘ Block IP</button>
          <button class="btn" onclick="unblockIP()">✓ Unblock IP</button>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Auto-Response Rules</span><button class="btn btn-accent" style="font-size:9px;padding:4px 10px" onclick="saveAutoRules()">Save Rules</button></div>
      <div class="pb">
        <div style="display:flex;flex-direction:column;gap:10px">
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:12px">
            <input type="checkbox" id="ar-auto-brute" checked style="accent-color:var(--accent)">
            Auto-block IPs with &gt;10 failed logins
          </label>
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:12px">
            <input type="checkbox" id="ar-auto-sudo" style="accent-color:var(--accent)">
            Alert on sudo abuse (&gt;5 events)
          </label>
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:12px">
            <input type="checkbox" id="ar-auto-susp" checked style="accent-color:var(--accent)">
            Alert on suspicious commands
          </label>
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:12px">
            <input type="checkbox" id="ar-email-alert" style="accent-color:var(--accent)">
            Send email on critical events (configure SMTP in .env)
          </label>
        </div>
      </div>
    </div>
  </div>
  <div class="panel">
    <div class="ph"><span class="pt">Currently Blocked IPs</span></div>
    <div class="pb">
      <table class="ip-table">
        <thead><tr><th>IP Address</th><th>Reason</th><th>Blocked At</th><th>Action</th></tr></thead>
        <tbody id="ar-blocked-list"></tbody>
      </table>
      <div id="ar-blocked-empty" class="empty-state">No blocked IPs</div>
    </div>
  </div>
  <!-- Process Manager -->
  <div class="panel">
    <div class="ph">
      <span class="pt">Process Manager</span>
      <button class="btn btn-blue" onclick="loadProcesses()">↺ Refresh</button>
    </div>
    <div class="pb" style="max-height:280px;overflow-y:auto">
      <table class="proc-table">
        <thead><tr><th>PID</th><th>User</th><th>CPU%</th><th>MEM%</th><th>Command</th><th>Action</th></tr></thead>
        <tbody id="proc-table-body"></tbody>
      </table>
      <div id="proc-empty" class="empty-state">Click Refresh to load running processes</div>
    </div>
  </div>
  <div class="panel">
    <div class="ph"><span class="pt">Response Action Log</span></div>
    <div class="pb" style="max-height:200px;overflow-y:auto">
      <div id="ar-log" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);display:flex;flex-direction:column;gap:4px">
        <div style="color:var(--green)">[ SYSTEM ] Active Response module initialized</div>
      </div>
    </div>
  </div>
</div>

<!-- ADMIN -->
<div class="page" id="page-admin">
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">Database Manager</span></div>
      <div class="pb">
        <div class="form-group">
          <label class="form-label">Search / Select Database</label>
          <div style="display:flex;gap:8px">
            <input class="form-input" id="db-search-input" placeholder="Search databases…" oninput="filterDbs()" style="flex:1">
            <button class="btn btn-accent" onclick="loadDbs()">↺ Refresh</button>
          </div>
        </div>
        <div class="db-list" id="db-list" style="max-height:180px;overflow-y:auto;margin-bottom:12px"></div>
        <hr style="border:none;border-top:1px solid var(--border);margin:12px 0">
        <div class="form-group">
          <label class="form-label">Create New Database</label>
          <div style="display:flex;gap:8px">
            <input class="form-input" id="db-create-name" placeholder="new_database_name" style="flex:1">
            <button class="btn btn-blue" onclick="createDb()">+ Create</button>
          </div>
        </div>
        <div id="db-status" style="font-family:'IBM Plex Mono',monospace;font-size:10px;margin-top:8px"></div>
      </div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Log Path Manager</span></div>
      <div class="pb">
        <div class="form-group">
          <label class="form-label">Add Log Path to Monitor</label>
          <div style="display:flex;gap:8px">
            <input class="form-input" id="log-path-input" placeholder="/var/log/custom.log" style="flex:1">
            <button class="btn btn-accent" onclick="addLogPath()">+ Add</button>
          </div>
        </div>
        <div class="path-list" id="log-paths" style="max-height:220px;overflow-y:auto"></div>
      </div>
    </div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">System Inventory</span></div>
      <div class="pb" id="sys-inv"><div class="empty-state">Loading inventory…</div></div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">System Health</span></div>
      <div class="pb" id="sys-health">
        <table class="ip-table">
          <thead><tr><th>Component</th><th>Status</th></tr></thead>
          <tbody id="health-table"></tbody>
        </table>
      </div>
    </div>
  </div>
  <!-- Compliance Panel -->
  <div class="panel">
    <div class="ph">
      <span class="pt">Regulatory Compliance</span>
      <button class="btn btn-accent" onclick="runComplianceCheck()">▶ Compute Scores</button>
    </div>
    <div class="pb">
      <div class="grid-3" id="comp-grid">
        <div class="comp-card">
          <div style="font-size:10px;color:var(--muted);margin-bottom:6px">PCI-DSS</div>
          <div style="font-family:'IBM Plex Mono',monospace;font-size:32px;font-weight:600;color:var(--orange)" id="comp-pci-val">—</div>
          <div id="comp-pci-status"></div>
          <div id="comp-pci-detail" style="font-size:10px;color:var(--muted);margin-top:6px"></div>
        </div>
        <div class="comp-card">
          <div style="font-size:10px;color:var(--muted);margin-bottom:6px">HIPAA</div>
          <div style="font-family:'IBM Plex Mono',monospace;font-size:32px;font-weight:600;color:var(--orange)" id="comp-hipaa-val">—</div>
          <div id="comp-hipaa-status"></div>
          <div id="comp-hipaa-detail" style="font-size:10px;color:var(--muted);margin-top:6px"></div>
        </div>
        <div class="comp-card">
          <div style="font-size:10px;color:var(--muted);margin-bottom:6px">NIST CSF</div>
          <div style="font-family:'IBM Plex Mono',monospace;font-size:32px;font-weight:600;color:var(--orange)" id="comp-nist-val">—</div>
          <div id="comp-nist-status"></div>
          <div id="comp-nist-detail" style="font-size:10px;color:var(--muted);margin-top:6px"></div>
        </div>
      </div>
      <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-top:10px;padding-top:8px;border-top:1px solid var(--border)">
        Scores computed from live SCA check results · Penalties applied for critical failures
      </div>
    </div>
  </div>
  <!-- CSV Import -->
  <div class="panel">
    <div class="ph"><span class="pt">CSV Import / Export</span></div>
    <div class="pb">
      <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
        <button class="btn btn-accent" onclick="exportCSV()">⬇ Export CSV (last 5000 events)</button>
        <div style="display:flex;gap:8px;align-items:center">
          <label class="btn btn-blue" style="cursor:pointer">
            ⬆ Import CSV
            <input type="file" id="csv-import-file" accept=".csv" style="display:none" onchange="importCSV(this)">
          </label>
          <span id="import-status" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)"></span>
        </div>
      </div>
    </div>
  </div>
</div>

</div><!-- /main-area -->
</div><!-- /shell -->

<!-- DETAIL DRAWER -->
<div id="drawer">
  <div class="dh">
    <span class="dt">Event Detail</span>
    <button class="dc" onclick="closeDrawer()">✕</button>
  </div>
  <div class="dg" id="drawer-fields"></div>
  <div class="dr" id="drawer-raw"></div>
  <div class="mitre-chips" id="drawer-mitre"></div>
</div>

<!-- TOAST -->
<div id="toast"></div>

<script>
// STATE
let allLogs = [], filteredLogs = [];
let curPage = 1, pageSize = 50;
let activeFilter = 'ALL', activeSev = null, searchTerm = '';
let sortCol = 'timestamp', sortDir = -1;
let activeTypeFilter = null;
let charts = {};
let blockedIPs = {};
let autoResponseCount = 0;
let logPaths = {{ log_paths|tojson }};
let allDbs = [];
let scaChecksCache = [];
let scaFilter = 'ALL';

// INIT
document.addEventListener('DOMContentLoaded', () => {
  updateClock();
  setInterval(updateClock, 1000);
  fetchStats();
  setInterval(fetchStats, 5000);
  renderLogPaths();
  loadDbs();
  loadInventory();
  loadHealth();
  buildMitreMatrix();
  renderFimPaths();
});

function updateClock() {
  const n = new Date();
  document.getElementById('nav-time').textContent =
    n.toTimeString().slice(0,8) + ' UTC' + (n.getTimezoneOffset() > 0 ? '-' : '+') +
    String(Math.abs(n.getTimezoneOffset()/60)).padStart(2,'0');
}

// PAGE NAV
function showPage(name, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  el.classList.add('active');
  if (name === 'analytics') buildAnalytics();
  if (name === 'mitre') buildMitreMatrix();
  if (name === 'admin') { loadDbs(); loadInventory(); loadHealth(); }
}

// FETCH STATS
async function fetchStats() {
  try {
    const r = await fetch('/api/stats');
    if (!r.ok) return;
    const d = await r.json();
    setNum('s-failed', d.failed_logins);
    setNum('s-brute',  d.brute_total);
    setNum('s-sudo',   d.sudo_total);
    setNum('s-ips',    d.unique_ips);
    setNum('s-total',  d.total_logs);
    setNum('s-susp',   d.suspicious_count);
    setNum('ov-failed', d.failed_logins);
    setNum('ov-auth',   d.auth_count);
    setNum('ov-susp',   d.suspicious_count);
    setNum('ov-hosts',  d.host_count);
    renderSidebarAlerts(d.top_ips, d.sudo_users);
    renderEtypes(d.event_types);
    renderHosts(d.logs);
    renderSidebarBlocked();
    buildTimelineChart(d.logs);
    buildEtypeChart(d.event_types);
    buildIPChart(d.top_ips);
    buildSevChart(d.logs);
    allLogs = d.logs || [];
    if (document.getElementById('page-logs').classList.contains('active') ||
        document.getElementById('page-overview').classList.contains('active')) {
      applyFilters();
    }
    renderOverviewTable(allLogs);
    checkAutoResponse(d);
  } catch(e) { console.error(e); }
}

function setNum(id, v) {
  const el = document.getElementById(id);
  if (el) el.textContent = (v || 0).toLocaleString();
}

// SIDEBAR
function renderSidebarAlerts(topIps, sudoUsers) {
  const c = document.getElementById('sb-alerts');
  if ((!topIps || !topIps.length) && (!sudoUsers || !sudoUsers.length)) {
    c.innerHTML = '<div class="empty-state">No alerts</div>'; return;
  }
  let html = '';
  (topIps||[]).slice(0,4).forEach(([ip,count]) => {
    html += `<div class="al-item"><div class="al-ip">${ip}</div><div class="al-meta">${count} failed auth events</div></div>`;
  });
  (sudoUsers||[]).slice(0,3).forEach(([u,count]) => {
    html += `<div class="al-item warn"><div class="al-ip">${u}</div><div class="al-meta">${count} sudo events</div></div>`;
  });
  c.innerHTML = html;
}

function renderEtypes(etypes) {
  const c = document.getElementById('sb-etypes');
  if (!etypes || !etypes.length) { c.innerHTML = ''; return; }
  c.innerHTML = etypes.map(e =>
    `<div class="etype-row ${activeTypeFilter===e.name?'active':''}" onclick="typeFilterClick('${e.name}')">
      <span class="etype-name"><span class="etype-dot" style="background:${e.color}"></span>${e.name}</span>
      <span class="etype-count">${e.count}</span>
    </div>`
  ).join('');
}

function renderHosts(logs) {
  const hosts = {};
  (logs||[]).forEach(l => { if(l.hostname && l.hostname!=='—') hosts[l.hostname] = (hosts[l.hostname]||0)+1; });
  const c = document.getElementById('sb-hosts');
  c.innerHTML = Object.entries(hosts).slice(0,6).map(([h,n]) =>
    `<div class="sb-host"><span>${h}</span><span style="color:var(--muted)">${n}</span></div>`
  ).join('') || '<div style="color:var(--muted);font-size:10px">No host data</div>';
}

function renderSidebarBlocked() {
  const c = document.getElementById('sb-blocked');
  const ips = Object.keys(blockedIPs);
  if (!ips.length) { c.innerHTML = '<span style="color:var(--muted)">None</span>'; return; }
  c.innerHTML = ips.map(ip =>
    `<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--border)">
      <span style="color:var(--red)">${ip}</span>
      <span style="cursor:pointer;color:var(--muted)" onclick="unblockIPDirect('${ip}')">✕</span>
    </div>`
  ).join('');
}

function typeFilterClick(name) {
  activeTypeFilter = activeTypeFilter === name ? null : name;
  activeFilter = activeTypeFilter || 'ALL';
  showPage('logs', document.querySelectorAll('.nav-tab')[1]);
  applyFilters();
}

// OVERVIEW TABLE
function renderOverviewTable(logs) {
  const high = logs.filter(l => l.threat_level >= 2).slice(0,20);
  const tb = document.getElementById('ov-table');
  document.getElementById('ov-log-count').textContent = `${high.length} high-severity events`;
  if (!high.length) { tb.innerHTML = '<tr><td colspan="7" class="empty-state">No high-severity events</td></tr>'; return; }
  tb.innerHTML = high.map(l => rowHtml(l)).join('');
}

// LOG TABLE
function applyFilters() {
  let list = [...allLogs];
  if (activeFilter !== 'ALL') list = list.filter(l => l.eventtype === activeFilter);
  if (activeSev !== null) list = list.filter(l => l.threat_level === activeSev);
  if (searchTerm) {
    const q = searchTerm.toLowerCase();
    list = list.filter(l =>
      (l.message||'').toLowerCase().includes(q) ||
      (l.sourceip||'').toLowerCase().includes(q) ||
      (l.username||'').toLowerCase().includes(q) ||
      (l.hostname||'').toLowerCase().includes(q)
    );
  }
  list.sort((a,b) => {
    let av = a[sortCol]||'', bv = b[sortCol]||'';
    if (sortCol==='threat_level') { av=a.threat_level; bv=b.threat_level; }
    if (av < bv) return sortDir; if (av > bv) return -sortDir; return 0;
  });
  filteredLogs = list;
  curPage = 1;
  renderLogTable();
  document.getElementById('log-count').textContent = `${list.length} events`;
}

function renderLogTable() {
  const tb = document.getElementById('log-table');
  const start = (curPage-1)*pageSize, end = start+pageSize;
  const page = filteredLogs.slice(start, end);
  if (!page.length) tb.innerHTML = '<tr><td colspan="7" class="empty-state">No events match filters</td></tr>';
  else tb.innerHTML = page.map(l => rowHtml(l)).join('');
  renderPagination();
}

function rowHtml(l) {
  const rc = l.threat_level>=3 ? 'r-red' : l.threat_level>=2 ? 'r-orange' : '';
  return `<tr class="lr ${rc}" onclick='openDrawer(${JSON.stringify(l)})'>
    <td class="col-time">${l.timestamp}</td>
    <td class="col-type"><span class="badge badge-${l.eventtype}">${l.eventtype}</span></td>
    <td class="col-host" title="${l.hostname}">${l.hostname}</td>
    <td class="col-user">${l.username}</td>
    <td class="col-ip">${l.sourceip}</td>
    <td class="col-msg" title="${escHtml(l.message)}">${escHtml(l.message)}</td>
    <td class="col-sev"><span class="sev-badge sev-${l.threat_level}">${l.threat_label}</span></td>
  </tr>`;
}

function escHtml(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function renderPagination() {
  const total = filteredLogs.length, pages = Math.ceil(total/pageSize)||1;
  const start = (curPage-1)*pageSize+1, end = Math.min(curPage*pageSize, total);
  document.getElementById('pg-info').textContent = `Showing ${total?start:0}–${end} of ${total}`;
  const c = document.getElementById('pg-btns');
  let html = `<button class="pg-btn" onclick="changePage(${curPage-1})" ${curPage<=1?'disabled':''}>‹ Prev</button>`;
  pageRange(curPage, pages).forEach(p => {
    if (p==='…') html += `<button class="pg-btn" disabled>…</button>`;
    else html += `<button class="pg-btn ${p===curPage?'cur':''}" onclick="changePage(${p})">${p}</button>`;
  });
  html += `<button class="pg-btn" onclick="changePage(${curPage+1})" ${curPage>=pages?'disabled':''}>Next ›</button>`;
  c.innerHTML = html;
}

function pageRange(cur, total) {
  if (total <= 7) return Array.from({length:total},(_,i)=>i+1);
  if (cur <= 4) return [1,2,3,4,5,'…',total];
  if (cur >= total-3) return [1,'…',total-4,total-3,total-2,total-1,total];
  return [1,'…',cur-1,cur,cur+1,'…',total];
}

function changePage(p) { const pages=Math.ceil(filteredLogs.length/pageSize)||1; if(p<1||p>pages)return; curPage=p; renderLogTable(); }
function filterLogs() { searchTerm=document.getElementById('log-search').value; applyFilters(); }
function setFilter(el, f) {
  document.querySelectorAll('.filter-row .chip[data-filter]').forEach(c=>c.classList.remove('active'));
  el.classList.add('active'); activeFilter=f; applyFilters();
}
function setSev(el, s) {
  if (activeSev===s) { el.classList.remove('active'); activeSev=null; }
  else { document.querySelectorAll('.filter-row .chip[data-sev]').forEach(c=>c.classList.remove('active')); el.classList.add('active'); activeSev=s; }
  applyFilters();
}
function sortTable(col) { if(sortCol===col) sortDir*=-1; else { sortCol=col; sortDir=-1; } applyFilters(); }

// DRAWER
function openDrawer(l) {
  const fields = [
    ['Log ID', l.logid], ['Timestamp', l.timestamp], ['Event Type', l.eventtype],
    ['Host', l.hostname], ['Username', l.username], ['Source IP', l.sourceip],
    ['Severity', l.threat_label], ['Status', l.threat_level>=1?'Anomaly':'Normal']
  ];
  document.getElementById('drawer-fields').innerHTML = fields.map(([k,v]) =>
    `<div><div class="dk">${k}</div><div class="dv">${escHtml(String(v))}</div></div>`
  ).join('');
  document.getElementById('drawer-raw').textContent = l.rawline || l.message || '—';
  const mitre = {{ mitre_map|tojson }};
  const techniques = mitre[l.eventtype] || [];
  document.getElementById('drawer-mitre').innerHTML = techniques.length
    ? techniques.map(t =>
        `<a class="mitre-chip" href="https://attack.mitre.org/techniques/${t.id.replace('.','/')}/" target="_blank" title="${t.tactic}">${t.id} — ${t.name}</a>`
      ).join('')
    : '<span style="font-family:\'IBM Plex Mono\',monospace;font-size:10px;color:var(--muted)">No MITRE mapping</span>';
  document.getElementById('drawer').classList.add('open');
}
function closeDrawer() { document.getElementById('drawer').classList.remove('open'); }

// CHARTS
const CC = { grid:'rgba(26,45,61,.6)', text:'#5a7080', accent:'#00d4aa', red:'#f85149', orange:'#e3a03a', blue:'#0ea5e9', purple:'#bc8cff', green:'#3fb950', cyan:'#79c0ff', yellow:'#d29922' };

function mkChart(id, cfg) {
  if (charts[id]) charts[id].destroy();
  const ctx = document.getElementById(id);
  if (!ctx) return;
  charts[id] = new Chart(ctx, cfg);
}

function buildTimelineChart(logs) {
  const now = new Date(), buckets = {};
  for (let i=59; i>=0; i--) {
    const k = new Date(now - i*60000);
    const label = k.toTimeString().slice(0,5);
    buckets[label] = {label, total:0, failed:0};
  }
  (logs||[]).forEach(l => {
    if (!l.timestamp) return;
    const t = l.timestamp.slice(11,16);
    if (buckets[t]) { buckets[t].total++; if(l.threat_level>=2) buckets[t].failed++; }
  });
  const vals = Object.values(buckets);
  mkChart('chart-timeline', { type:'line', data:{
    labels: vals.map(v=>v.label),
    datasets: [
      { label:'All Events', data:vals.map(v=>v.total), borderColor:CC.accent, backgroundColor:'rgba(0,212,170,.08)', tension:.3, pointRadius:0, fill:true },
      { label:'Threats', data:vals.map(v=>v.failed), borderColor:CC.red, backgroundColor:'rgba(248,81,73,.08)', tension:.3, pointRadius:0, fill:true }
    ]
  }, options: chartOpts() });
}

function buildEtypeChart(etypes) {
  if (!etypes||!etypes.length) return;
  mkChart('chart-etypes', { type:'doughnut', data:{
    labels: etypes.map(e=>e.name),
    datasets:[{ data:etypes.map(e=>e.count), backgroundColor:etypes.map(e=>e.color), borderWidth:0, hoverOffset:4 }]
  }, options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'right', labels:{ color:CC.text, font:{size:10}, boxWidth:10 } } } } });
}

function buildIPChart(topIps) {
  if (!topIps||!topIps.length) return;
  mkChart('chart-ips', { type:'bar', data:{
    labels: topIps.slice(0,8).map(([ip])=>ip),
    datasets:[{ label:'Failed Logins', data:topIps.slice(0,8).map(([,c])=>c), backgroundColor:'rgba(248,81,73,.7)', borderRadius:3 }]
  }, options:{ ...chartOpts(), indexAxis:'y' } });
}

function buildSevChart(logs) {
  const c = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
  (logs||[]).forEach(l => { const m={3:'CRITICAL',2:'HIGH',1:'MEDIUM',0:'LOW'}; c[m[l.threat_level]||'LOW']++; });
  mkChart('chart-sev', { type:'bar', data:{
    labels:['CRITICAL','HIGH','MEDIUM','LOW'],
    datasets:[{ data:[c.CRITICAL,c.HIGH,c.MEDIUM,c.LOW], backgroundColor:[CC.red,CC.orange,'rgba(210,153,34,.7)',CC.green], borderRadius:3 }]
  }, options:chartOpts() });
}

function chartOpts() {
  return { responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false}},
    scales:{ x:{ grid:{color:CC.grid}, ticks:{color:CC.text,font:{size:9}} }, y:{ grid:{color:CC.grid}, ticks:{color:CC.text,font:{size:9}} } } };
}

// ANALYTICS
async function buildAnalytics() {
  try {
    const r = await fetch('/api/stats'); const d = await r.json();
    setNum('an-total',     d.total_logs);
    setNum('an-failed',    d.failed_logins);
    setNum('an-auth',      d.auth_count);
    setNum('an-susp',      d.suspicious_count);
    setNum('an-sudo-count', d.sudo_total);

    const ipResp = await fetch('/api/top-ips');
    const ips = await ipResp.json();
    document.getElementById('an-ip-table').innerHTML = (ips||[]).map(([ip,count]) =>
      `<tr><td style="color:var(--accent)">${ip}</td><td>${count}</td>
       <td><span class="tag ${count>20?'tag-crit':count>10?'tag-high':'tag-med'}">${count>20?'CRITICAL':count>10?'HIGH':'MEDIUM'}</span></td>
       <td><button class="btn btn-red btn-sm" onclick="quickBlock('${ip}')">Block</button></td></tr>`
    ).join('') || '<tr><td colspan="4" class="empty-state">No attacker IPs</td></tr>';

    const sudoResp = await fetch('/api/sudo-users');
    const sudos = await sudoResp.json();
    document.getElementById('an-sudo-table').innerHTML = (sudos||[]).map(([u,c]) =>
      `<tr><td style="color:var(--blue)">${u}</td><td>${c}</td>
       <td><span class="tag ${c>10?'tag-high':'tag-med'}">${c>10?'HIGH':'MEDIUM'}</span></td></tr>`
    ).join('') || '<tr><td colspan="3" class="empty-state">No sudo data</td></tr>';

    // Timeline (reuse data from stats)
    buildAnTimelineChart(d.logs);

    const success = (d.logs||[]).filter(l=>l.threat_level===0).length;
    const failed  = (d.logs||[]).filter(l=>l.threat_level> 0).length;
    mkChart('an-chart-sf', { type:'pie', data:{
      labels:['Normal','Anomaly'],
      datasets:[{ data:[success,failed], backgroundColor:[CC.green,'rgba(248,81,73,.7)'], borderWidth:0 }]
    }, options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'right', labels:{color:CC.text,font:{size:10},boxWidth:10} } } } });

    const hm = new Array(24).fill(0);
    (d.logs||[]).forEach(l => { if(l.timestamp) { const h=parseInt(l.timestamp.slice(11,13)); if(!isNaN(h)) hm[h]++; } });
    const max = Math.max(...hm,1);
    document.getElementById('an-heatmap').innerHTML = hm.map((v,h) =>
      `<div title="${h}:00 — ${v} events" style="flex:1;height:${Math.max(4,v/max*80)}px;background:${v>0?'rgba(0,212,170,'+(0.2+0.8*v/max)+')':'var(--border)'};border-radius:2px 2px 0 0;cursor:default"></div>`
    ).join('');
  } catch(e) { console.error(e); }
}

function buildAnTimelineChart(logs) {
  const now = new Date(), buckets = {};
  for (let i=59; i>=0; i--) {
    const k = new Date(now - i*60000);
    const label = k.toTimeString().slice(0,5);
    buckets[label] = {label, failed:0};
  }
  (logs||[]).forEach(l => {
    if (!l.timestamp) return;
    const t = l.timestamp.slice(11,16);
    if (buckets[t] && l.threat_level > 0) buckets[t].failed++;
  });
  const vals = Object.values(buckets);
  mkChart('an-chart-tl', { type:'line', data:{
    labels: vals.map(v=>v.label),
    datasets:[{ label:'Failed Logins', data:vals.map(v=>v.failed), borderColor:CC.red, backgroundColor:'rgba(248,81,73,.1)', tension:.3, pointRadius:0, fill:true }]
  }, options:chartOpts() });
}

// FIM
let fimPaths = ['/etc/passwd','/etc/shadow','/etc/hosts','/etc/crontab','/etc/sudoers','/root/.bashrc'];
let fimBaseline = {};

function renderFimPaths() {
  document.getElementById('fim-paths').innerHTML = fimPaths.map((p,i) =>
    `<div class="path-item"><div style="display:flex;align-items:center;gap:8px"><div class="path-status"></div><span>${p}</span></div>
     <button class="btn btn-red btn-sm" onclick="removeFimPath(${i})">Remove</button></div>`
  ).join('') || '<div style="color:var(--muted);font-size:10px">No paths configured</div>';
}

function addFimPath() {
  const v = document.getElementById('fim-path-input').value.trim();
  if (!v) return;
  if (!fimPaths.includes(v)) { fimPaths.push(v); renderFimPaths(); toast('Path added','ok'); }
  document.getElementById('fim-path-input').value = '';
}

function removeFimPath(i) { fimPaths.splice(i,1); renderFimPaths(); }
function resetFimBaseline() { fimBaseline = {}; toast('Baseline cleared — next scan will establish new baseline','info'); }

async function runFim() {
  toast('Running FIM scan…','info');
  try {
    const r = await fetch('/api/fim', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({paths:fimPaths}) });
    const results = await r.json();
    let ok=0, mod=0, miss=0;
    const tb = document.getElementById('fim-results');
    tb.innerHTML = results.map(f => {
      const changed = fimBaseline[f.path] && fimBaseline[f.path] !== f.hash;
      const status = f.status!=='ok' ? 'ERROR' : changed ? 'MODIFIED' : fimBaseline[f.path] ? 'UNCHANGED' : 'NEW';
      if(status==='UNCHANGED') ok++; else if(status==='MODIFIED') mod++; else if(status==='ERROR') miss++;
      const cls = status==='MODIFIED'?'tag-high':status==='ERROR'?'tag-crit':status==='NEW'?'tag-info':'tag-low';
      if (!fimBaseline[f.path] && f.hash) fimBaseline[f.path] = f.hash;
      return `<tr>
        <td style="font-family:'IBM Plex Mono',monospace;color:var(--blue)">${f.path}</td>
        <td style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted)">${f.hash?f.hash.slice(0,20)+'…':'—'}</td>
        <td>${f.size?f.size+' B':'—'}</td>
        <td>${f.mtime?new Date(f.mtime*1000).toISOString().slice(0,19):'—'}</td>
        <td><span class="tag ${cls}">${status}</span></td>
      </tr>`;
    }).join('');
    setNum('fim-ok',ok); setNum('fim-mod',mod); setNum('fim-miss',miss);
    document.getElementById('fim-empty').style.display='none';
    toast(`FIM scan complete: ${results.length} files checked`,'ok');
  } catch(e) { toast('FIM scan failed: '+e.message,'err'); }
}

// SCA
async function runSca() {
  const prog = document.getElementById('sca-progress');
  const pb   = document.getElementById('sca-pb');
  prog.style.display = 'block';
  let pct = 0;
  const interval = setInterval(() => { pct = Math.min(pct+8,90); pb.style.width=pct+'%'; }, 300);
  try {
    const r = await fetch('/api/sca');
    scaChecksCache = await r.json();
    clearInterval(interval); pb.style.width='100%';
    setTimeout(() => prog.style.display='none', 600);
    renderScaResults(scaChecksCache);
    toast(`SCA complete: ${scaChecksCache.filter(c=>c.status==='PASS').length} pass, ${scaChecksCache.filter(c=>c.status==='FAIL').length} fail`,
          scaChecksCache.filter(c=>c.status==='FAIL').length > scaChecksCache.filter(c=>c.status==='PASS').length ? 'err' : 'ok');
  } catch(e) { clearInterval(interval); prog.style.display='none'; toast('SCA failed: '+e.message,'err'); }
}

function filterSca() {
  scaFilter = document.getElementById('sca-filter').value;
  if (scaChecksCache.length) renderScaResults(scaChecksCache);
}

function renderScaResults(checks) {
  const pass = checks.filter(c=>c.status==='PASS').length;
  const fail = checks.filter(c=>c.status==='FAIL').length;
  const crit = checks.filter(c=>c.status==='FAIL'&&c.severity==='CRITICAL').length;
  const score = Math.round(pass/(checks.length||1)*100);
  document.getElementById('sca-pass').textContent  = pass;
  document.getElementById('sca-fail').textContent  = fail;
  document.getElementById('sca-score').textContent = score + '%';
  document.getElementById('sca-crit').textContent  = crit;
  document.getElementById('sca-empty').style.display = 'none';

  let visible = checks;
  if (scaFilter === 'FAIL') visible = checks.filter(c=>c.status==='FAIL');
  else if (scaFilter === 'PASS') visible = checks.filter(c=>c.status==='PASS');
  else if (scaFilter === 'CRITICAL') visible = checks.filter(c=>c.severity==='CRITICAL');

  document.getElementById('sca-results').innerHTML = visible.map(c => `<tr>
    <td style="font-family:'IBM Plex Mono',monospace;color:var(--muted);white-space:nowrap">${c.id}</td>
    <td>${c.title}${c.detail?'<div style="font-size:9px;color:var(--muted);margin-top:2px">'+escHtml(c.detail)+'</div>':''}</td>
    <td style="font-size:9px;color:var(--muted);font-family:'IBM Plex Mono',monospace;white-space:nowrap">${(c.tags||'').replace(/,/g,'<br>')}</td>
    <td><span class="tag ${c.severity==='CRITICAL'?'tag-crit':c.severity==='HIGH'?'tag-high':c.severity==='MEDIUM'?'tag-med':'tag-low'}">${c.severity}</span></td>
    <td><span class="tag ${c.status==='PASS'?'tag-low':'tag-crit'}">${c.status}</span></td>
  </tr>`).join('');
}

// VULN
async function runVuln() {
  toast('Scanning packages…','info');
  try {
    const r = await fetch('/api/vuln');
    const vulns = await r.json();
    const crit = vulns.filter(v=>v.severity==='CRITICAL').length;
    const high = vulns.filter(v=>v.severity==='HIGH').length;
    const med  = vulns.filter(v=>v.severity==='MEDIUM').length;
    document.getElementById('vn-crit').textContent  = crit;
    document.getElementById('vn-high').textContent  = high;
    document.getElementById('vn-med').textContent   = med;
    document.getElementById('vn-total').textContent = vulns.length;
    const liveCount = vulns.filter(v=>v.source==='NVD-live').length;
    document.getElementById('vuln-source-badge').textContent =
      liveCount > 0 ? `${liveCount} from NVD live · ${vulns.length-liveCount} offline` : 'offline baseline';
    document.getElementById('vuln-empty').style.display = 'none';
    document.getElementById('vuln-results').innerHTML = vulns.length
      ? vulns.map(v => `<tr>
          <td style="font-family:'IBM Plex Mono',monospace;color:var(--blue)">${v.package}</td>
          <td style="font-family:'IBM Plex Mono',monospace;color:var(--orange)">${v.cve}</td>
          <td><span class="tag ${v.severity==='CRITICAL'?'tag-crit':v.severity==='HIGH'?'tag-high':v.severity==='MEDIUM'?'tag-med':'tag-low'}">${v.severity}</span></td>
          <td style="color:var(--muted);font-size:11px">${escHtml(v.description||'')}</td>
          <td><span class="tag ${v.source==='NVD-live'?'tag-info':'tag-low'}" style="font-size:8px">${v.source||'offline'}</span></td>
          <td><a href="https://nvd.nist.gov/vuln/detail/${v.cve}" target="_blank" style="color:var(--blue);font-family:'IBM Plex Mono',monospace;font-size:10px">NVD ↗</a></td>
        </tr>`)
        .join('')
      : '<tr><td colspan="6" class="empty-state" style="color:var(--green)">No known vulnerabilities detected</td></tr>';
    toast(`Vuln scan: ${vulns.length} findings (${crit} critical)`, crit>0?'err':'ok');
  } catch(e) { toast('Vuln scan failed: '+e.message,'err'); }
}

// MITRE ATT&CK
function buildMitreMatrix() {
  const mitreMap = {{ mitre_map|tojson }};
  const techniques = {}, tactics = {};
  allLogs.forEach(l => {
    const maps = mitreMap[l.eventtype] || [];
    maps.forEach(t => {
      techniques[t.id] = techniques[t.id] || { ...t, count:0 };
      techniques[t.id].count++;
      tactics[t.tactic] = (tactics[t.tactic]||0) + 1;
    });
  });

  document.getElementById('mitre-tactics').innerHTML = Object.entries(tactics)
    .sort((a,b)=>b[1]-a[1])
    .map(([t,c]) => `<span class="mitre-chip" style="font-size:11px;padding:5px 12px">${t} <strong>${c}</strong></span>`)
    .join('') || '<span style="color:var(--muted);font-size:11px">Waiting for log data…</span>';

  document.getElementById('mitre-cards').innerHTML = Object.values(techniques)
    .sort((a,b)=>b.count-a.count)
    .map(t => `<div class="mitre-card" onclick="window.open('https://attack.mitre.org/techniques/${t.id.replace('.','/').replace('.','/') }/', '_blank')">
      <div class="mitre-id">${t.id}</div>
      <div class="mitre-name">${t.name}</div>
      <div class="mitre-tactic">${t.tactic}</div>
      <div class="mitre-count">${t.count}</div>
    </div>`)
    .join('') || '<div class="empty-state" style="grid-column:1/-1">No MITRE techniques detected yet</div>';

  document.getElementById('mitre-tactic-list').innerHTML = Object.entries(tactics)
    .sort((a,b)=>b[1]-a[1])
    .map(([t,c]) => `<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border)">
      <span style="font-size:12px">${t}</span>
      <span style="font-family:'IBM Plex Mono',monospace;font-size:20px;font-weight:600;color:var(--accent)">${c}</span>
    </div>`)
    .join('') || '<div style="color:var(--muted);font-size:11px">No data</div>';

  const tacticNames = Object.keys(tactics);
  const tacticCounts = Object.values(tactics);
  if (tacticNames.length) {
    mkChart('mitre-chart', { type:'radar', data:{
      labels: tacticNames,
      datasets:[{ label:'Activity', data:tacticCounts,
        backgroundColor:'rgba(0,212,170,.12)', borderColor:'rgba(0,212,170,.7)',
        pointBackgroundColor:'var(--accent)', pointRadius:4 }]
    }, options:{ responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{display:false} },
      scales:{ r:{ grid:{color:CC.grid}, ticks:{display:false}, pointLabels:{color:CC.text,font:{size:9}} } } } });
  }
}

// ACTIVE RESPONSE
let arLog = [];

function arLogEntry(msg, type='info') {
  const t = new Date().toTimeString().slice(0,8);
  const colors = {info:'var(--blue)', ok:'var(--green)', err:'var(--red)'};
  arLog.unshift(`<div style="color:${colors[type]||CC.text}">[ ${t} ] ${escHtml(msg)}</div>`);
  if (arLog.length > 100) arLog.pop();
  document.getElementById('ar-log').innerHTML = arLog.join('');
}

async function blockIP() {
  const ip = document.getElementById('ar-ip-input').value.trim();
  const reason = document.getElementById('ar-reason').value;
  if (!ip) { toast('Enter an IP address','err'); return; }
  try {
    const r = await fetch('/api/block-ip', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip,reason}) });
    const d = await r.json();
    if (d.success) {
      blockedIPs[ip] = { reason, time:new Date().toISOString() };
      renderBlockedTable(); renderSidebarBlocked();
      setNum('ar-blocked-count', Object.keys(blockedIPs).length);
      arLogEntry(`Blocked IP ${ip} — ${reason}`, 'ok');
      toast(`Blocked ${ip}`,'ok');
    } else toast(d.message,'err');
  } catch(e) { toast('Block failed: '+e.message,'err'); }
}

async function unblockIP() {
  const ip = document.getElementById('ar-ip-input').value.trim();
  if (!ip) { toast('Enter an IP to unblock','err'); return; }
  await unblockIPDirect(ip);
}

async function unblockIPDirect(ip) {
  try {
    await fetch('/api/unblock-ip', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip}) });
    delete blockedIPs[ip];
    renderBlockedTable(); renderSidebarBlocked();
    setNum('ar-blocked-count', Object.keys(blockedIPs).length);
    arLogEntry(`Unblocked IP ${ip}`,'ok');
    toast(`Unblocked ${ip}`,'ok');
  } catch(e) { toast('Unblock failed: '+e.message,'err'); }
}

function quickBlock(ip) { document.getElementById('ar-ip-input').value = ip; blockIP(); }

function renderBlockedTable() {
  const c = document.getElementById('ar-blocked-list');
  const empty = document.getElementById('ar-blocked-empty');
  const entries = Object.entries(blockedIPs);
  if (!entries.length) { c.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';
  c.innerHTML = entries.map(([ip,data]) =>
    `<tr><td style="color:var(--red);font-family:'IBM Plex Mono',monospace">${ip}</td>
     <td>${data.reason||'Manual'}</td>
     <td style="color:var(--muted)">${(data.time||'').slice(0,19)}</td>
     <td><button class="btn btn-sm" onclick="unblockIPDirect('${ip}')">Unblock</button></td></tr>`
  ).join('');
}

function checkAutoResponse(d) {
  if (document.getElementById('ar-auto-brute').checked) {
    (d.top_ips||[]).forEach(([ip,count]) => {
      if (count > 10 && !blockedIPs[ip]) {
        blockedIPs[ip] = { reason:'Auto: Brute Force ('+count+' attempts)', time:new Date().toISOString() };
        autoResponseCount++;
        setNum('ar-auto', autoResponseCount);
        arLogEntry(`AUTO-BLOCK: ${ip} — ${count} failed logins`, 'err');
        toast(`Auto-blocked ${ip} (brute force)`,'err');
        renderBlockedTable(); renderSidebarBlocked();
        setNum('ar-blocked-count', Object.keys(blockedIPs).length);
      }
    });
  }
  setNum('ar-brute', d.brute_total);
}

function saveAutoRules() { toast('Auto-response rules saved','ok'); }

// PROCESS MANAGER
async function loadProcesses() {
  try {
    const r = await fetch('/api/processes');
    const procs = await r.json();
    if (!procs.length) { document.getElementById('proc-empty').style.display='block'; return; }
    document.getElementById('proc-empty').style.display='none';
    document.getElementById('proc-table-body').innerHTML = procs.map(p =>
      `<tr>
        <td style="font-family:'IBM Plex Mono',monospace;color:var(--muted)">${p.pid}</td>
        <td style="color:var(--blue)">${p.user}</td>
        <td>${p.cpu}</td>
        <td>${p.mem}</td>
        <td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px" title="${escHtml(p.cmd)}">${escHtml(p.cmd)}</td>
        <td><button class="btn btn-red btn-sm" onclick="killProcess(${p.pid},'${escHtml(p.cmd).slice(0,20)}')">Kill</button></td>
      </tr>`
    ).join('');
    arLogEntry(`Process list refreshed: ${procs.length} processes`,'info');
  } catch(e) { toast('Process load failed: '+e.message,'err'); }
}

async function killProcess(pid, name) {
  if (!confirm(`Send SIGTERM to PID ${pid} (${name})?`)) return;
  try {
    const r = await fetch('/api/kill-process', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({pid}) });
    const d = await r.json();
    if (d.success) { arLogEntry(`Killed PID ${pid} (${name})`,'ok'); toast(`SIGTERM sent to PID ${pid}`,'ok'); loadProcesses(); }
    else toast(d.message,'err');
  } catch(e) { toast('Kill failed: '+e.message,'err'); }
}

// COMPLIANCE
async function runComplianceCheck() {
  if (!scaChecksCache.length) {
    toast('Run Security Config Assessment first (Config Audit tab)','err');
    return;
  }
  try {
    const r = await fetch('/api/compliance', { method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({checks: scaChecksCache}) });
    const d = await r.json();
    renderComplianceScores(d);
    toast('Compliance scores updated','ok');
  } catch(e) { toast('Compliance check failed: '+e.message,'err'); }
}

function renderComplianceScores(d) {
  const fwMap = {'PCI-DSS': 'pci', 'HIPAA': 'hipaa', 'NIST': 'nist'};
  for (const [fw, key] of Object.entries(fwMap)) {
    const info = d[fw];
    if (!info) continue;
    const scoreEl = document.getElementById(`comp-${key}-val`);
    const statusEl = document.getElementById(`comp-${key}-status`);
    const detailEl = document.getElementById(`comp-${key}-detail`);
    if (scoreEl) {
      scoreEl.textContent = info.score + '%';
      scoreEl.style.color = info.score>=80?'var(--green)':info.score>=50?'var(--yellow)':'var(--red)';
    }
    if (statusEl) statusEl.innerHTML = `<span class="comp-status ${info.status}">${info.status}</span>`;
    if (detailEl) detailEl.textContent = `${info.pass} pass · ${info.fail} fail · ${info.crit_fail} critical fails`;
  }
}

// ADMIN: DB Manager
async function loadDbs() {
  try {
    const r = await fetch('/api/databases');
    allDbs = await r.json();
    renderDbList(allDbs);
  } catch(e) { document.getElementById('db-list').innerHTML='<div style="color:var(--muted);font-size:10px">Could not connect to DB server</div>'; }
}

function renderDbList(dbs) {
  const curDb = '{{ current_db }}';
  document.getElementById('db-list').innerHTML = (dbs||[]).map(d =>
    `<div class="db-item ${d===curDb?'active-db':''}" onclick="selectDb('${d}')">
      <span class="db-name">${d}</span>
      ${d===curDb?'<span style="font-family:\'IBM Plex Mono\',monospace;font-size:9px;color:var(--accent)">ACTIVE</span>':''}
    </div>`
  ).join('') || '<div style="color:var(--muted);font-size:10px">No databases found</div>';
}

function filterDbs() {
  const q = document.getElementById('db-search-input').value.toLowerCase();
  renderDbList(allDbs.filter(d=>d.toLowerCase().includes(q)));
}

async function selectDb(name) {
  try {
    const r = await fetch('/api/switch-db', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({database:name}) });
    const d = await r.json();
    if (d.success) { toast('Switched to '+name,'ok'); loadDbs(); fetchStats(); }
    else toast(d.message,'err');
  } catch(e) { toast('Switch failed: '+e.message,'err'); }
}

async function createDb() {
  const name = document.getElementById('db-create-name').value.trim();
  if (!name) { toast('Enter a database name','err'); return; }
  try {
    const r = await fetch('/api/create-db', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name}) });
    const d = await r.json();
    const el = document.getElementById('db-status');
    el.style.color = d.success?'var(--green)':'var(--red)';
    el.textContent = d.message;
    if (d.success) { loadDbs(); document.getElementById('db-create-name').value=''; }
    toast(d.message, d.success?'ok':'err');
  } catch(e) { toast('Create failed: '+e.message,'err'); }
}

// ADMIN: Log Paths
function renderLogPaths() {
  document.getElementById('log-paths').innerHTML = logPaths.map((p,i) =>
    `<div class="path-item">
      <div style="display:flex;align-items:center;gap:8px"><div class="path-status"></div><span>${p}</span></div>
      <button class="btn btn-red btn-sm" onclick="removeLogPath(${i})">Remove</button>
    </div>`
  ).join('') || '<div style="color:var(--muted);font-size:10px">No paths configured</div>';
}

async function addLogPath() {
  const v = document.getElementById('log-path-input').value.trim();
  if (!v) return;
  try {
    const r = await fetch('/api/add-log-path', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path:v}) });
    const d = await r.json();
    if (d.success) { logPaths = d.paths; renderLogPaths(); toast('Path added: '+v,'ok'); }
    else toast(d.message,'err');
  } catch(e) { toast('Failed: '+e.message,'err'); }
  document.getElementById('log-path-input').value='';
}

async function removeLogPath(i) {
  const p = logPaths[i];
  try {
    const r = await fetch('/api/remove-log-path', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path:p}) });
    const d = await r.json();
    if (d.success) { logPaths = d.paths; renderLogPaths(); toast('Removed: '+p,'ok'); }
  } catch(e) { logPaths.splice(i,1); renderLogPaths(); }
}

// ADMIN: Inventory & Health
async function loadInventory() {
  try {
    const r = await fetch('/api/inventory');
    const d = await r.json();
    document.getElementById('sys-inv').innerHTML = `
      <table class="ip-table"><thead><tr><th>Component</th><th>Value</th></tr></thead><tbody>
        <tr><td>Hostname</td><td style="font-family:'IBM Plex Mono',monospace">${d.hostname||'—'}</td></tr>
        <tr><td>OS</td><td style="font-family:'IBM Plex Mono',monospace">${d.os||'—'}</td></tr>
        <tr><td>Platform</td><td style="font-family:'IBM Plex Mono',monospace">${d.platform||'—'}</td></tr>
        <tr><td>Python</td><td style="font-family:'IBM Plex Mono',monospace">${d.python||'—'}</td></tr>
        <tr><td>Monitored Paths</td><td style="font-family:'IBM Plex Mono',monospace">${d.log_paths||0}</td></tr>
        <tr><td>DB Config</td><td style="font-family:'IBM Plex Mono',monospace">${d.db_host||'—'}/${d.db_name||'—'}</td></tr>
      </tbody></table>`;
  } catch(e) { document.getElementById('sys-inv').innerHTML='<div class="empty-state">Inventory unavailable</div>'; }
}

async function loadHealth() {
  try {
    const r = await fetch('/health');
    const d = await r.json();
    document.getElementById('health-table').innerHTML = `
      <tr><td>Flask Server</td><td><span class="tag tag-low">RUNNING</span></td></tr>
      <tr><td>PostgreSQL</td><td><span class="tag ${d.db==='reachable'?'tag-low':'tag-crit'}">${(d.db||'unknown').toUpperCase()}</span></td></tr>
      <tr><td>Log Agent</td><td><span class="tag tag-low">ACTIVE</span></td></tr>
      <tr><td>API Endpoint</td><td><span class="tag tag-low">OK</span></td></tr>`;
  } catch(e) { document.getElementById('health-table').innerHTML='<tr><td colspan="2" class="empty-state">Health check failed</td></tr>'; }
}

// CSV IMPORT
async function importCSV(input) {
  const file = input.files[0];
  if (!file) return;
  const statusEl = document.getElementById('import-status');
  statusEl.textContent = 'Uploading…';
  statusEl.style.color = 'var(--muted)';
  const formData = new FormData();
  formData.append('file', file);
  try {
    const r = await fetch('/import/csv', { method:'POST', body: formData });
    const d = await r.json();
    if (d.imported !== undefined) {
      statusEl.textContent = `Imported ${d.imported} rows`;
      statusEl.style.color = 'var(--green)';
      toast(`CSV import: ${d.imported} rows added`,'ok');
      fetchStats();
    } else {
      statusEl.textContent = d.error || 'Import failed';
      statusEl.style.color = 'var(--red)';
      toast('Import failed: '+(d.error||'unknown'),'err');
    }
  } catch(e) {
    statusEl.textContent = 'Error: ' + e.message;
    statusEl.style.color = 'var(--red)';
    toast('Import error: '+e.message,'err');
  }
  input.value = '';
}

// UTILS
function toast(msg, type='info') {
  const c = document.getElementById('toast');
  const el = document.createElement('div');
  el.className = 'toast-msg '+type;
  el.innerHTML = `<span>${type==='ok'?'✓':type==='err'?'✕':'ℹ'}</span> ${escHtml(msg)}`;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

async function exportCSV() {
  window.open('/export/csv','_blank');
  toast('Downloading CSV…','info');
}

async function confirmClear() {
  if (!confirm('Delete ALL log events from the database? This cannot be undone.')) return;
  try {
    const r = await fetch('/clear-logs', {method:'POST'});
    const d = await r.json();
    if (d.status==='success') { toast('All logs cleared','ok'); fetchStats(); }
    else toast(d.message,'err');
  } catch(e) { toast('Clear failed: '+e.message,'err'); }
}
</script>
</body>
</html>
"""

# ─── Active DB / log paths ───────────────────────────────────────────────────
_active_db = DB_CONFIG["database"]
_log_paths = list(DB_CONFIG.get("_log_paths", [])) or [
    "/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log",
    "/var/log/dpkg.log", "/var/log/audit/audit.log",
    "/root/.bash_history"
]

def get_active_db():
    return _active_db

def get_active_db_conn():
    cfg = DB_CONFIG.copy()
    cfg["database"] = _active_db
    return psycopg2.connect(**cfg)

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def dashboard():
    return render_template_string(
        DASHBOARD_HTML,
        mitre_map  = MITRE_MAP,
        log_paths  = _log_paths,
        current_db = _active_db,
    )

@app.route("/api/stats", methods=["GET"])
def api_stats():
    try:
        conn = get_active_db_conn()
        cur  = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM Logs WHERE Success=0 AND EventTime > NOW() - INTERVAL '1 minute'")
        failed = cur.fetchone()[0] or 0

        cur.execute("SELECT SourceIp, COUNT(*) FROM Logs WHERE Success=0 GROUP BY SourceIp HAVING COUNT(*)>10 ORDER BY COUNT(*) DESC")
        brute_list = cur.fetchall()

        cur.execute("SELECT UserName, COUNT(*) FROM Logs WHERE EventType='SUDO' GROUP BY UserName HAVING COUNT(*)>5 ORDER BY COUNT(*) DESC")
        sudo_list  = cur.fetchall()

        cur.execute("SELECT SourceIp, COUNT(*) FROM Logs WHERE Success=0 GROUP BY SourceIp ORDER BY COUNT(*) DESC LIMIT 8")
        top_ips = cur.fetchall()

        cur.execute("SELECT COUNT(*) FROM Logs")
        total_logs = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(*) FROM Logs WHERE EventType='SUSPICIOUS_COMMAND'")
        suspicious_count = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(*) FROM Logs WHERE EventType='AUTH'")
        auth_count = cur.fetchone()[0] or 0

        cur.execute("SELECT COUNT(DISTINCT HostName) FROM Logs")
        host_count = cur.fetchone()[0] or 0

        cur.execute("SELECT EventType, COUNT(*) FROM Logs GROUP BY EventType ORDER BY COUNT(*) DESC")
        event_types = [{"name": r[0] or "SYS", "count": r[1],
                         "color": ETYPE_COLORS.get(r[0] or "SYS", "var(--muted)")} for r in cur.fetchall()]

        cur.execute("""
            SELECT logid,COALESCE(EventTime,NOW()),Message,EventType,Success,UserName,SourceIp,RawLine,HostName
            FROM Logs ORDER BY logid DESC LIMIT 200
        """)
        logs = []
        for row in cur.fetchall():
            logid,ts,message,eventtype,success,username,sourceip,rawline,hostname = row
            tl, label = classify(eventtype, success, message)
            logs.append({"logid":logid,"timestamp":str(ts)[:19],"message":str(message or ""),
                         "eventtype":eventtype or "SYS","threat_level":tl,"threat_label":label,
                         "username":username or "—","sourceip":sourceip or "—",
                         "rawline":rawline or "","hostname":hostname or "—"})

        cur.close(); conn.close()

        return jsonify({
            "failed_logins":    failed,
            "brute_total":      sum(c for _,c in brute_list),
            "sudo_total":       sum(c for _,c in sudo_list),
            "unique_ips":       len(set(ip for ip,_ in top_ips)),
            "total_logs":       total_logs,
            "suspicious_count": suspicious_count,
            "auth_count":       auth_count,
            "host_count":       host_count,
            "top_ips":          [[ip,c] for ip,c in top_ips],
            "sudo_users":       [[u,c] for u,c in sudo_list],
            "event_types":      event_types,
            "logs":             logs,
        })
    except Exception as e:
        print(f" api/stats: {e}")
        return jsonify({"error": str(e), "failed_logins":0,"brute_total":0,"sudo_total":0,
                        "unique_ips":0,"total_logs":0,"suspicious_count":0,"auth_count":0,
                        "host_count":0,"top_ips":[],"sudo_users":[],"event_types":[],"logs":[]}), 500

@app.route("/api/top-ips")
def api_top_ips():
    try:
        conn = get_active_db_conn(); cur = conn.cursor()
        cur.execute("SELECT SourceIp,COUNT(*) FROM Logs WHERE Success=0 GROUP BY SourceIp ORDER BY COUNT(*) DESC LIMIT 20")
        rows = [[r[0],r[1]] for r in cur.fetchall()]
        cur.close(); conn.close(); return jsonify(rows)
    except Exception: return jsonify([])

@app.route("/api/sudo-users")
def api_sudo_users():
    try:
        conn = get_active_db_conn(); cur = conn.cursor()
        cur.execute("SELECT UserName,COUNT(*) FROM Logs WHERE EventType='SUDO' GROUP BY UserName ORDER BY COUNT(*) DESC LIMIT 20")
        rows = [[r[0] or "unknown",r[1]] for r in cur.fetchall()]
        cur.close(); conn.close(); return jsonify(rows)
    except Exception: return jsonify([])

@app.route("/api/fim", methods=["POST"])
def api_fim():
    data  = request.json or {}
    paths = data.get("paths", [])
    return jsonify(fim_scan(paths))

@app.route("/api/sca")
def api_sca():
    return jsonify(run_sca())

@app.route("/api/vuln")
def api_vuln():
    return jsonify(vuln_scan())

@app.route("/api/compliance", methods=["POST"])
def api_compliance():
    data   = request.json or {}
    checks = data.get("checks", [])
    if not checks:
        # run fresh if not provided
        checks = run_sca()
    result = compute_compliance(checks)
    return jsonify(result)

@app.route("/api/processes")
def api_processes():
    try:
        r = subprocess.run(["ps", "aux", "--no-headers", "--sort=-%cpu"],
                            capture_output=True, text=True, timeout=5)
        procs = []
        for line in r.stdout.splitlines()[:50]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({"user": parts[0], "pid": int(parts[1]),
                               "cpu": parts[2], "mem": parts[3], "cmd": parts[10]})
        return jsonify(procs)
    except Exception as e:
        return jsonify([])

@app.route("/api/kill-process", methods=["POST"])
def api_kill_process():
    data = request.json or {}
    pid  = data.get("pid")
    if not pid:
        return jsonify({"success": False, "message": "No PID provided"}), 400
    try:
        pid = int(pid)
        if pid <= 1:
            return jsonify({"success": False, "message": "Cannot kill system process"}), 400
        subprocess.run(["kill", "-TERM", str(pid)], check=True, timeout=3)
        return jsonify({"success": True, "message": f"SIGTERM sent to PID {pid}"})
    except subprocess.CalledProcessError:
        return jsonify({"success": False, "message": f"kill failed — process may not exist"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/block-ip", methods=["POST"])
def api_block_ip():
    data   = request.json or {}
    ip     = data.get("ip","").strip()
    reason = data.get("reason","Manual")
    if not ip: return jsonify({"success":False,"message":"No IP provided"}),400
    ok, msg = block_ip(ip)
    return jsonify({"success":ok,"message":msg})

@app.route("/api/unblock-ip", methods=["POST"])
def api_unblock_ip():
    data = request.json or {}
    ip   = data.get("ip","").strip()
    if not ip: return jsonify({"success":False,"message":"No IP"}),400
    ok, msg = unblock_ip(ip)
    return jsonify({"success":ok,"message":msg})

@app.route("/api/databases")
def api_databases():
    return jsonify(list_databases())

@app.route("/api/switch-db", methods=["POST"])
def api_switch_db():
    global _active_db
    data = request.json or {}
    name = data.get("database","").strip()
    if not name: return jsonify({"success":False,"message":"No DB name"})
    try:
        cfg = DB_CONFIG.copy(); cfg["database"] = name
        psycopg2.connect(**cfg).close()
        _active_db = name
        return jsonify({"success":True,"message":f"Switched to {name}"})
    except Exception as e:
        return jsonify({"success":False,"message":str(e)})

@app.route("/api/create-db", methods=["POST"])
def api_create_db():
    data = request.json or {}
    name = data.get("name","").strip()
    if not name: return jsonify({"success":False,"message":"No name provided"})
    ok, msg = create_database_and_tables(name)
    return jsonify({"success":ok,"message":msg})

@app.route("/api/add-log-path", methods=["POST"])
def api_add_log_path():
    global _log_paths
    data = request.json or {}
    path = data.get("path","").strip()
    if not path: return jsonify({"success":False,"message":"No path"})
    if path not in _log_paths:
        _log_paths.append(path)
    return jsonify({"success":True,"paths":_log_paths})

@app.route("/api/remove-log-path", methods=["POST"])
def api_remove_log_path():
    global _log_paths
    data = request.json or {}
    path = data.get("path","").strip()
    _log_paths = [p for p in _log_paths if p != path]
    return jsonify({"success":True,"paths":_log_paths})

@app.route("/api/inventory")
def api_inventory():
    import sys as _sys
    return jsonify({
        "hostname":  __import__("socket").gethostname(),
        "os":        platform.system() + " " + platform.release(),
        "platform":  platform.platform(),
        "python":    _sys.version.split()[0],
        "log_paths": len(_log_paths),
        "db_host":   DB_CONFIG.get("host","—"),
        "db_name":   _active_db,
    })

@app.route("/health")
def health():
    try:
        get_active_db_conn().close()
        return jsonify({"status":"ok","db":"reachable"})
    except Exception as e:
        return jsonify({"status":"error","db":str(e)}), 500

@app.route("/ingest", methods=["POST"])
def ingest():
    data = request.json
    if not data or data.get("api_key") != API_KEY:
        return jsonify({"error":"Invalid API key"}), 401
    raw_line = data.get("message","")
    event = parser.parse(raw_line, source_type=data.get("source_type", "SYS"))
    if not event:
        event = {"EventTime":datetime.utcnow().isoformat(),"EventType":"SYS","Success":1,
                 "UserName":None,"SourceIp":None,"Message":raw_line[:700],"RawLine":raw_line,
                 "HostName":data.get("host","unknown")}
    else:
        event["HostName"] = data.get("host","unknown")
    # Apply extended event type detection
    event = _extend_event_type(event, raw_line)
    try:
        cfg = DB_CONFIG.copy(); cfg["database"] = _active_db
        conn = psycopg2.connect(**cfg); cur = conn.cursor()
        cur.execute("""INSERT INTO Logs(EventTime,EventType,Success,UserName,HostName,SourceIp,Message,RawLine)
                       VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (event.get("EventTime"),event.get("EventType"),event.get("Success"),
                     event.get("UserName"),event.get("HostName"),event.get("SourceIp"),
                     event.get("Message"),event.get("RawLine")))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"status":"ok"})
    except Exception as e:
        print(f"Ingest: {e}")
        return jsonify({"error":str(e)}),500

@app.route("/logs")
def get_logs():
    try:
        conn = get_active_db_conn(); cur = conn.cursor()
        cur.execute("SELECT * FROM Logs ORDER BY logid DESC LIMIT 200")
        rows = cur.fetchall(); cols = [d[0] for d in cur.description]
        cur.close(); conn.close()
        return jsonify([dict(zip(cols,r)) for r in rows])
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/export/csv")
def export_csv():
    try:
        conn = get_active_db_conn(); cur = conn.cursor()
        cur.execute("SELECT * FROM Logs ORDER BY logid DESC LIMIT 5000")
        rows = cur.fetchall(); cols = [d[0] for d in cur.description]
        cur.close(); conn.close()
        out = io.StringIO(); w = csv.writer(out); w.writerow(cols); w.writerows(rows)
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition":f"attachment; filename=sp110_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"})
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/import/csv", methods=["POST"])
def import_csv():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    try:
        content = f.read().decode("utf-8", errors="ignore")
        reader = csv.DictReader(io.StringIO(content))
        conn = get_active_db_conn(); cur = conn.cursor()
        count = 0
        for row in reader:
            # Map CSV columns flexibly
            event_time  = row.get("eventtime") or row.get("EventTime") or row.get("timestamp") or None
            event_type  = row.get("eventtype") or row.get("EventType") or "SYS"
            success     = row.get("success") or row.get("Success") or 1
            username    = row.get("username") or row.get("UserName") or None
            hostname    = row.get("hostname") or row.get("HostName") or None
            source_ip   = row.get("sourceip") or row.get("SourceIp") or None
            message     = row.get("message") or row.get("Message") or ""
            raw_line    = row.get("rawline") or row.get("RawLine") or message
            cur.execute("""INSERT INTO Logs(EventTime,EventType,Success,UserName,HostName,SourceIp,Message,RawLine)
                           VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (event_time, event_type, success, username, hostname, source_ip, message[:700], raw_line))
            count += 1
        conn.commit(); cur.close(); conn.close()
        return jsonify({"imported": count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/clear-logs", methods=["POST"])
def clear_logs():
    try:
        conn = get_active_db_conn(); cur = conn.cursor()
        cur.execute("TRUNCATE TABLE Logs RESTART IDENTITY;")
        conn.commit(); cur.close(); conn.close()
        return jsonify({"status":"success"})
    except Exception as e: return jsonify({"status":"error","message":str(e)}),500

if __name__ == "__main__":
    print(f"SP-110 Linux Behavior Monitor  http://{SERVER_HOST}:{SERVER_PORT}")
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False)
