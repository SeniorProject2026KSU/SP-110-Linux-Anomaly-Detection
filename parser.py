import re
from datetime import datetime, timezone


def parse(line):
    line = line.strip()
    if not line:
        return None

    lower = line.lower()

    # Skip auditd lines, make cleaner later
    if any(x in lower for x in ["type=proctitle", "type=path", "type=syscall",
                                "type=execve", "type=cwd", "msg=audit(", "key=\"exec_log\""]):
        return None   # Completely ignore these noisy lines


    # Lines from .bash_history
    is_history_line = (
        re.match(r'^\d{4}-\d{2}-\d{2}', line) or 
        not any(k in lower for k in ["failed password", "accepted password",
                                     "sudo:", "authentication failure"])
    )

    event = {
        "EventTime": datetime.now(timezone.utc).isoformat(),
        "EventType": "BASH_HISTORY" if is_history_line else "SYS",
        "Success": 1,
        "UserName": None,
        "SourceIp": None,
        "Message": line[:700],
        "RawLine": line
    }

    # Suspicious Command Detection
    suspicious_patterns = [
        r'\|[\s]*bash', r'\|[\s]*sh', r'curl\s+.*\|', r'wget.*\|',
        r'bash\s+-i', r'/dev/tcp', r'nc\s+-e', r'sh\s+-i',
        r'rm\s+-rf', r'history\s+-c', r'rm\s+.*\.bash_history',
        r'HISTSIZE=0', r'HISTFILESIZE=0', r'unset\s+HISTFILE',
        r'cat\s+/etc/(passwd|shadow|sudoers)', r'sudo\s+-l',
        r'base64\s+-d', r'find\s+/.*-perm', r':\(\)\{\s*:\|\s*:\&\s*\};:',
        r'crontab', r'chmod\s+\+x', r'echo\s+.*>>\s*~/.bashrc'
    ]

    is_suspicious = any(re.search(pattern, lower) for pattern in suspicious_patterns)

    if is_suspicious:
        event["Success"] = 0
        event["EventType"] = "SUSPICIOUS_COMMAND"

    # High priority system log overrides
    if "failed password" in lower or "authentication failure" in lower:
        event["EventType"] = "AUTH"
        event["Success"] = 0
    elif "accepted password" in lower or "accepted publickey" in lower:
        event["EventType"] = "AUTH"
        event["Success"] = 1
    elif "sudo" in lower:
        event["EventType"] = "SUDO"
        sudo_user = re.search(r'sudo:\s+(\w+)\s+:', line)
        if sudo_user:
            event["UserName"] = sudo_user.group(1)

    # Username extraction
    if event["UserName"] is None:
        user_match = re.search(r'(?:for\s+(?:invalid\s+user\s+)?|user\s+)([a-zA-Z0-9_\-\.]+)', line, re.IGNORECASE)
        if user_match:
            candidate = user_match.group(1)
            if candidate.lower() not in ("user", "invalid", "unknown", "from", "port"):
                event["UserName"] = candidate

    # Source IP
    ip_match = re.search(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})', line)
    if ip_match:
        event["SourceIp"] = ip_match.group(1)

    return event
