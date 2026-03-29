# Notification Manager

Simple SMTP-based email notification module for sending anomaly alerts and custom messages.

---

## Overview

This package provides a NotificationManager class that sends emails using SMTP.

- Uses .env for configuration (credentials, host, port)
- Supports SSL (port 465) and STARTTLS (port 587)
- Designed to be initialized from a central main.py

---

## Setup

1. Install dependency

pip install python-dotenv

---

2. Create .env in project root

> Do not place this inside the package.

Example:
```

SMTP_HOST=smtp.example.com
SMTP_PORT=465
SMTP_USE_SSL=true

SMTP_USERNAME=your_email@example.com
SMTP_PASSWORD=your_password_here
```

---

## Usage

Example main.py

```python
from dotenv import load_dotenv
import os

from user_notification.notification_manager import NotificationManager

def build_config():
    return {
        "smtp_host": os.getenv("SMTP_HOST"),
        "smtp_port": int(os.getenv("SMTP_PORT", 465)),
        "use_ssl": os.getenv("SMTP_USE_SSL", "true").lower() == "true",
        "username": os.getenv("SMTP_USERNAME"),
        "password": os.getenv("SMTP_PASSWORD"),
    }

def main():
    load_dotenv()

    config = build_config()

    notifier = NotificationManager(config)
    notifier.set_user_email("recipient@example.com")
    notifier.set_user_name("User")
    notifier.set_user_device("Laptop")

    notifier.send_anomaly_notification(85)

if __name__ == "__main__":
    main()

```

---

## TLDR

- Store SMTP config in .env
- Load with load_dotenv()
- Pass config into NotificationManager
- Call send_anomaly_notification()