import os

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5000
SERVER_URL = f"http://localhost:{SERVER_PORT}/ingest"

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "database": os.environ.get("DB_NAME", "activescan"),
    "user": os.environ.get("DB_USER", "postgres"),
    "password": os.environ.get("DB_PASSWORD", "password"),
}

LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/dpkg.log",
    "/var/log/boot.log",
    "/var/log/audit/audit.log",
    "/root/.bash_history",
    "/home/kubuntu/.bash_history"
]

API_KEY = os.environ.get("SOC_API_KEY", "API_KEY")
if not API_KEY:
    raise RuntimeError("API_KEY environment variable is not set. Refusing to start.")
