from db import query

def failed_logins():
    return query("""
        SELECT COUNT(*) FROM Logs
        WHERE Success = 0
        AND EventTime > NOW() - INTERVAL '1 minute'
    """)[0][0]

def top_ips():
    return query("""
        SELECT SourceIp, COUNT(*)
        FROM Logs
        WHERE Success = 0
        GROUP BY SourceIp
        ORDER BY COUNT(*) DESC
        LIMIT 5
    """)
