# SP-110 Linux Anomaly Detection

Senior Project workspace for a machine learning system that detects anomalous behavior on Linux systems and notifies users.

---

## Table of Contents
- [Overview](#overview)
- [Goals](#goals)
- [Current Features](#current-features)
- [Project Structure](#project-structure)
- [Setup](#setup)
- [Usage](#usage)
- [Environment Configuration](#environment-configuration)
- [Notification System](#notification-system)
- [Future Work](#future-work)
- [Contributors](#contributors)

---

## Overview

This project aims to detect abnormal activity on Linux systems by analyzing system logs and behavior patterns using machine learning techniques.

When anomalies are detected, the system can notify users via email.

---

## Goals

- Monitor Linux system activity
- Detect anomalous or suspicious behavior
- Provide real-time or near real-time alerts
- Build a modular and extensible system

---

## Current Features

- SMTP-based email notification system
- Configurable environment using `.env`
- Modular project structure
- Basic anomaly alert messaging

---

## Project Structure

```
project_root/
├── .env
├── src/
│ ├── main.py
│ ├── user_notification/
│ │ ├── init.py
│ │ └── notification_manager.py
│ └── (future modules)
```

---

## Setup

### 1. Clone the repository

```
git clone <repo-url>
cd SP-110-Linux-Anomaly-Detection
```

### 2. Install dependencies

```
pip install python-dotenv
```

---

## Usage

Run the main entry point:

```
python src/main.py
```

This will:
- Load environment variables
- Build configuration
- Initialize components
- Send a test notification (if configured)

---

## Environment Configuration

Create a `.env` file in the project root:

```
SMTP_HOST=smtp.example.com
SMTP_PORT=465
SMTP_USE_SSL=true

SMTP_USERNAME=your_email@example.com

SMTP_PASSWORD=your_password_here
```

Notes:
- Do not commit your `.env` file
- Add `.env` to `.gitignore`
- These values are required for the notification system

---

## Notification System

The `NotificationManager` handles sending emails.

### Example Usage

```python
notifier = NotificationManager(config)
notifier.set_user_email("recipient@example.com
")
notifier.set_user_name("User")
notifier.set_user_device("Laptop")

notifier.send_anomaly_notification(85)
```

### Features

- Severity-based alert headers
- Default and custom message support
- SMTP SSL and STARTTLS support
- Input validation and error handling

---

## Future Work

- Log collection from Linux systems
- Feature extraction and preprocessing
- Machine learning anomaly detection models
- Dashboard / visualization
- Multi-device monitoring
- Alert severity classification

---
