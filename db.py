import psycopg2
from config import DB_CONFIG

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def insert(event):
    conn = get_connection()
    try:
        with conn.cursor() as c:
            c.execute("""
                INSERT INTO Logs
                (EventTime, EventType, Success, UserName, HostName, SourceIp, Message, RawLine)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                event.get("EventTime"),
                event.get("EventType"),
                event.get("Success"),
                event.get("UserName"),
                event.get("HostName"),
                event.get("SourceIp"),
                event.get("Message"),
                event.get("RawLine")
            ))
            conn.commit()
    finally:
        conn.close()

def query(sql):
    conn = get_connection()
    try:
        with conn.cursor() as c:
            c.execute(sql)
            return c.fetchall()
    finally:
        conn.close()
