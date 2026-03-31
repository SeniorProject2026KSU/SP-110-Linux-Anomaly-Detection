# PURPOSE:
# Load .env
# Build config
# Create objects
# Wire everything together

# NOT:
# business logic
# heavy code

import datetime
from dotenv import load_dotenv
import os

from mock_detection.mock_detector import MockDetector
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
    notifier.set_user_email("colinhaskins2021@gmail.com")
    notifier.set_user_name("Colin")
    notifier.set_user_device("Laptop")


    ####################
    # DEMO LOOP
    """
    Simulates scanning of system. sends email and ends at demo_threshold
    """
    ####################

    #knobs
    demo_threshold = 65
    time_per_scan = 3

    while True:
        severity = MockDetector.simulate_detection(time_per_scan)
        print(f"""
              

----
{datetime.datetime.now()}              
SCAN RESULT: ANOMOLY SCORE = {severity}%        
----              
""")
        if severity > demo_threshold:
            notifier.send_anomaly_notification(severity)
            break



if __name__ == "__main__":
    main()