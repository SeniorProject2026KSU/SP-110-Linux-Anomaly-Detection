from db import query

def brute_force():
    return query("""
        SELECT SourceIp, COUNT(*)
        FROM Logs
        WHERE Success = 0
        GROUP BY SourceIp
        HAVING COUNT(*) > 10
    """)

def sudo_abuse():
    return query("""
        SELECT UserName, COUNT(*)
        FROM Logs
        WHERE EventType = 'SUDO'
        GROUP BY UserName
        HAVING COUNT(*) > 5
    """)
