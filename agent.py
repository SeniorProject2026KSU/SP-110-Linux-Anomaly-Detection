import time
import requests
import socket
import threading
from datetime import datetime, timezone
from config import LOG_FILES, API_KEY, SERVER_URL
import buffer

HOSTNAME = socket.gethostname()
RETRY_INTERVAL = 5


def follow(file):
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line


def flush_buffer():
    pending = buffer.load()
    if not pending:
        return

    sent = []
    for event in pending:
        try:
            response = requests.post(SERVER_URL, json=event, timeout=5)
            if response.status_code == 200:
                sent.append(event)
        except Exception:
            break

    if sent:
        remaining = [e for e in pending if e not in sent]
        buffer.clear()
        for e in remaining:
            buffer.save(e)
        print(f"Flushed {len(sent)} buffered event(s)")


def send_log(line):
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": HOSTNAME,
        "message": line.strip(),
        "api_key": API_KEY
    }
    try:
        flush_buffer()
        response = requests.post(SERVER_URL, json=data, timeout=5)
        if response.status_code != 200:
            print(f"Server returned {response.status_code} buffering event")
            buffer.save(data)
    except Exception as e:
        print(f"Failed to send log: {e} buffering event")
        buffer.save(data)


def monitor_file(path):

    while True:
        try:
            with open(path, "r") as f:
                print(f"Monitoring {path}")
                for line in follow(f):
                    if line.strip():
                        send_log(line)
        except FileNotFoundError:
            print(f"File not found: {path}  retrying in {RETRY_INTERVAL}s")
            time.sleep(RETRY_INTERVAL)
        except Exception as e:
            print(f"Error on {path}: {e}  retrying in {RETRY_INTERVAL}s")
            time.sleep(RETRY_INTERVAL)


def main():
    threads = []
    for path in LOG_FILES:
        t = threading.Thread(target=monitor_file, args=(path,), daemon=True)
        t.start()
        threads.append(t)

    print("Agent running log ingestion")
    while True:
        time.sleep(0.5)


if __name__ == "__main__":
    main()
