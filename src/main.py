# PURPOSE:
# Load .env
# Build config
# Create objects
# Wire everything together

# NOT:
# business logic
# heavy code

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

    # Change these values and run from root to test!
    notifier.set_user_email("CHANGEME@gmail.com")
    notifier.set_user_name("CHANGEME")
    notifier.set_user_device("Laptop")

    notifier.send_anomaly_notification(85)

if __name__ == "__main__":
    main()