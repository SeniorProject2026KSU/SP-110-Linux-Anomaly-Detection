#TODO:
# Implement emailing lib

class NotificationManager():
    def __init__(self):
        self.user_email = "default"
        self.user_device = "device"
        self.user_name = "user"
        
    def set_user_email(self, user):
        self.user_email = user

    def set_user_email(self, name):
        self.user_name = name

    def set_user_device(self, device):
        # User Device is the name that the user has chosen for the device
        self.user_device = device
    
    def send_anomaly_notification(self, severity, subject="ANOMALY has been detected on one or more of your devices", body="default"):
        # Sends notificaition to user of a detected anomaly
        header = f"[SEVERITY {severity}%] "
        if body == "default":
            body = f"Dear {self.user_name},\n\nAn anomaly of severity {severity} has been detected on device {self.user_device}. We recommend checking your device.\n\n Thank you for using our service,\nSP-110 Green Team"
        pass