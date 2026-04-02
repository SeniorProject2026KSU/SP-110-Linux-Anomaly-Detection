import re
from datetime import datetime, timezone

def parse(line: str):
    if not line or not line.strip():
        return None

    original_line = line.strip()
    lower = original_line.lower()

    # Skip noisy auditd / systemd lines
    if any(x in lower for x in ["type=proctitle", "type=path", "type=syscall", "type=execve",
                                "type=cwd", "msg=audit(", "key=\"exec_log\"", "type=service_start"]):
        return None

    event = {
        "EventTime": datetime.now(timezone.utc).isoformat(),
        "EventType": "SYS",
        "Success": 1,
        "UserName": None,
        "SourceIp": None,
        "Message": original_line[:700],
        "RawLine": original_line
    }

    #  IP EXTRACTION
    ip_patterns = [
        r'from\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})',
        r'rhost=([0-9]{1,3}(?:\.[0-9]{1,3}){3})',
        r'addr=([0-9]{1,3}(?:\.[0-9]{1,3}){3})',
        r'\b(127\.0\.0\.1|::1)\b'
    ]
    for pattern in ip_patterns:
        match = re.search(pattern, lower)
        if match:
            captured = match.group(1) if match.lastindex and match.group(1) else match.group(0)
            event["SourceIp"] = "127.0.0.1" if captured in ("127.0.0.1", "::1") else captured
            break

    #  USERNAME EXTRACTION
    user_patterns = [
        r'Failed password for (?:invalid user )?([a-zA-Z0-9_\-\.]+)',
        r'Accepted (?:password|publickey) for ([a-zA-Z0-9_\-\.]+)',
        r'authentication failure.*user=([a-zA-Z0-9_\-\.]+)',
        r'sudo:\s+([a-zA-Z0-9_\-\.]+)\s*:',
        r'for user ([a-zA-Z0-9_\-\.]+)'
    ]
    for pattern in user_patterns:
        match = re.search(pattern, lower)
        if match:
            candidate = match.group(1)
            if candidate.lower() not in {"user", "invalid", "unknown", "from", "port", "ssh2", "tty"}:
                event["UserName"] = candidate
                break

    #EVENT TYPE & SUCCESS
    if "failed password" in lower or "authentication failure" in lower or "invalid user" in lower:
        event["EventType"] = "AUTH"
        event["Success"] = 0
    elif "accepted password" in lower or "accepted publickey" in lower:
        event["EventType"] = "AUTH"
        event["Success"] = 1
    elif "sudo:" in lower:
        event["EventType"] = "SUDO"
        if any(x in lower for x in ["sudo -l", "/etc/sudoers", "/etc/shadow"]):
            event["Success"] = 0
    elif any(p in lower for p in ["bash -i", "/dev/tcp", "nc -e", "rm -rf", "history -c",
                                  "unset histfile", "histsize=0", "cat /etc/shadow", ":(){ :|:& };:"]):
        event["EventType"] = "SUSPICIOUS_COMMAND"
        event["Success"] = 0
    elif re.match(r'^\d{4}-\d{2}-\d{2}', original_line) or "bash_cmd:" in lower:
        event["EventType"] = "BASH_HISTORY"

    return event
