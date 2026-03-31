
import psycopg2
import sys
from config import DB_CONFIG

def create_database():
    postgres_config = DB_CONFIG.copy()
    postgres_config['database'] = 'postgres'

    try:
        conn = psycopg2.connect(**postgres_config)
        conn.autocommit = True
        cur = conn.cursor()

        db_name = DB_CONFIG.get('database', 'activescan')

        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (db_name,))
        if not cur.fetchone():
            print(f"Creating database '{db_name}'...")
            cur.execute(f'CREATE DATABASE "{db_name}"')
            print(f"✓ Database '{db_name}' created successfully.")
        else:
            print(f"Database '{db_name}' already exists.")

        cur.close()
        conn.close()
        return True

    except psycopg2.Error as e:
        print(f"Error creating database: {e}")
        print("   Tip: Run with a user that has CREATEDB privilege (e.g., postgres)")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False


def create_tables():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        cur.execute("""
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
        """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_eventtime ON Logs(EventTime DESC);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_eventtype ON Logs(EventType);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_sourceip ON Logs(SourceIp);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_success ON Logs(Success);")

        conn.commit()
        print(" Logs table and indexes are ready.")

        cur.close()
        conn.close()
        return True

    except psycopg2.Error as e:
        print(f" Error creating table/indexes: {e}")
        return False
    except Exception as e:
        print(f" Unexpected error: {e}")
        return False


if __name__ == "__main__":
    print("=" * 65)
    print("   Linux Behavior Monitor (SP-110) - Database Setup")
    print("=" * 65)

    success = create_database() and create_tables()

    if success:
        print("\n Database setup completed successfully!")
        print(" You can now run: python Launcher.py if")
    else:
        print("\n Database setup encountered issues.")
        print("   Please check PostgreSQL is running and credentials are correct.")

    print("\nIf you get permission errors, try:")
    print("   sudo -u postgres python3 setup_db.py")