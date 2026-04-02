import subprocess
import time
import sys
import os
import signal

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def start_process(cmd, name):
    print(f"Starting {name}")
    try:
        return subprocess.Popen(cmd)
    except Exception as e:
        print(f"Failed to start {name}: {e}")
        sys.exit(1)


def check_postgres():
    print("Checking PostgreSQL connection")
    try:
        import psycopg2
        from config import DB_CONFIG
        psycopg2.connect(**DB_CONFIG).close()
        print("PostgreSQL is reachable.")
        return True
    except ImportError:
        print("psycopg2 not installed — run: pip install psycopg2-binary")
        sys.exit(1)
    except Exception as e:
        print(f"PostgreSQL connection failed: {e}")
        sys.exit(1)


def setup_database():
    print("\nRunning automated database setup...")
    try:
        result = subprocess.run(
            [sys.executable, os.path.join(BASE_DIR, "setup_db.py")],
            capture_output=True,
            text=True,
            check=True
        )
        print(result.stdout.strip())
        if "completed successfully" in result.stdout.lower():
            print("Database setup successful.")
            return True
        return False
    except subprocess.CalledProcessError as e:
        print("Database setup failed:")
        print(e.stdout)
        if e.stderr:
            print(e.stderr)
        return False
    except Exception as e:
        print(f"Unexpected error during DB setup: {e}")
        return False


def main():

    print("   Linux Behavior Monitor (SP-110) Launcher")

    check_postgres()
    if not setup_database():
        print("Continuing anyway")

    processes = []

    # Start Flask Server
    server = start_process([sys.executable, os.path.join(BASE_DIR, "app.py")], "Flask Server")
    processes.append(server)

    time.sleep(2)

    # Start Log Agent
    agent = start_process([sys.executable, os.path.join(BASE_DIR, "agent.py")], "Log Ingestion Agent")
    processes.append(agent)

    print("\nSystem is now running!")
    print("   Dashboard  http://localhost:5000")
    print("   Press CTRL+C to stop all processes\n")

    def shutdown(sig=None, frame=None):
        print("\nShutting down all processes...")
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()