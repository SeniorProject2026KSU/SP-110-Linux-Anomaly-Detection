import os

SERVER_HOST = os.environ.get("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("SERVER_PORT", 5000))

SERVER_URL = os.environ.get(
    "SERVER_URL",
    f"http://{SERVER_HOST}:{SERVER_PORT}/ingest"
)

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "database": os.environ.get("DB_NAME", "activescan"),
    "user": os.environ.get("DB_USER", "postgres"),
    "password": os.environ.get("DB_PASSWORD", "password"),
}

TEXT_LOG_FILES = os.environ.get("LOG_FILES", "").split(",") if os.environ.get("LOG_FILES") else [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/dpkg.log",
    "/var/log/boot.log",
    "/var/log/audit/audit.log",
    "/root/.bash_history",
    "/home/kubuntu/.bash_history"
]

JOURNAL_UNITS = os.environ.get("JOURNAL_UNITS", "sshd,sudo,systemd,auth").split(",") if os.environ.get("JOURNAL_UNITS") else [
    "sshd", "sudo", "systemd", "user"   # "user" catches most user sessions
]

API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    print(". ")
    API_KEY = "API_KEY"