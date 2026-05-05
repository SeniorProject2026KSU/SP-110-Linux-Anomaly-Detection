import time
import requests
import socket
import threading
import subprocess
from datetime import datetime, timezone
from config import TEXT_LOG_FILES, JOURNAL_UNITS, API_KEY, SERVER_URL
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


def follow_journal(unit=None):
    
    cmd = ["journalctl", "-f", "--no-pager", "-o", "short"]
    if unit and unit != "all":
        cmd.extend(["-u", unit])
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        print(f"Monitoring journalctl for unit: {unit or 'all'}")
        
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                yield line
    except Exception as e:
        print(f"Journalctl error: {e}")
        time.sleep(RETRY_INTERVAL)


def send_log(line, source_type="SYS"):

    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": HOSTNAME,
        "message": line.strip(),
        "source_type": source_type,   
        "api_key": API_KEY
    }
    try:
        flush_buffer()
        response = requests.post(SERVER_URL, json=data, timeout=5)
        if response.status_code != 200:
            buffer.save(data)
    except Exception as e:
        print(f"Failed to send log: {e} — buffering")
        buffer.save(data)


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


def monitor_text_file(path):
  
    while True:
        try:
            with open(path, "r") as f:
                print(f"Monitoring text file: {path}")
                for line in follow(f):
                    if line.strip():
                        send_log(line, source_type="TEXT")
        except FileNotFoundError:
            print(f"File not found: {path} — retrying in {RETRY_INTERVAL}s")
            time.sleep(RETRY_INTERVAL)
        except Exception as e:
            print(f"Error on {path}: {e} — retrying")
            time.sleep(RETRY_INTERVAL)


def monitor_journal(unit):
  
    while True:
        try:
            for line in follow_journal(unit):
                if line.strip():
                    send_log(line, source_type="JOURNAL")
        except Exception as e:
            print(f"Journal monitor error for {unit}: {e} — retrying")
            time.sleep(RETRY_INTERVAL)


def main():
    threads = []

    for path in TEXT_LOG_FILES:
        if path.strip():
            t = threading.Thread(target=monitor_text_file, args=(path,), daemon=True)
            t.start()
            threads.append(t)

    for unit in JOURNAL_UNITS:
        if unit.strip():
            t = threading.Thread(target=monitor_journal, args=(unit,), daemon=True)
            t.start()
            threads.append(t)


    print(f"SP-110 Agent running on {HOSTNAME}  monitoring {len(TEXT_LOG_FILES)} text files and {len(JOURNAL_UNITS)} journal units")
    print("Press Ctrl+C to stop")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()