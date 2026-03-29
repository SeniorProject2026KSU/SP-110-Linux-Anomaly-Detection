import smtplib
import ssl
from email.message import EmailMessage


class NotificationManager:
    def __init__(self, config):
        """
        Initialize the notification manager with SMTP configuration.

        Required config keys:
        - smtp_host
        - smtp_port
        - use_ssl
        - username
        - password
        """
        self._validate_config(config)

        self.smtp_host = config["smtp_host"]
        self.smtp_port = config["smtp_port"]
        self.use_ssl = config["use_ssl"]
        self.username = config["username"]
        self.password = config["password"]

        # User-specific values. These should be set before sending.
        self.user_email = None
        self.user_device = None
        self.user_name = None

    def set_user_email(self, email):
        """
        Set the email address that notifications will be sent to.
        """
        if not isinstance(email, str) or not email.strip():
            raise ValueError("user email must be a non-empty string")

        email = email.strip()

        # Very basic sanity check. Not full RFC validation, just enough to catch obvious mistakes.
        if "@" not in email or "." not in email.split("@")[-1]:
            raise ValueError("user email does not appear to be valid")

        self.user_email = email

    def set_user_name(self, name):
        """
        Set the user's display name for notification text.
        """
        if not isinstance(name, str) or not name.strip():
            raise ValueError("user name must be a non-empty string")

        self.user_name = name.strip()

    def set_user_device(self, device):
        """
        Set the user-facing device name used in notifications.
        Example: 'Laptop', 'Desktop', 'Home Server'
        """
        if not isinstance(device, str) or not device.strip():
            raise ValueError("user device must be a non-empty string")

        self.user_device = device.strip()

    def send_anomaly_notification(
        self,
        severity,
        subject="ANOMALY has been detected on one or more of your devices",
        body="default",
    ):
        """
        Send a standard anomaly notification.

        - severity: numeric or string severity value
        - subject: optional custom subject line
        - body: optional custom body; if set to 'default', a standard body is generated
        """
        self._validate_runtime_state()
        severity_text = self._validate_and_format_severity(severity)

        header = f"[SEVERITY {severity_text}] "

        if body == "default":
            body = (
                f"Dear {self.user_name},\n\n"
                f"An anomaly of severity {severity_text} has been detected on device "
                f"{self.user_device}.\n\n"
                f"We recommend checking your device and reviewing recent activity.\n\n"
                f"Thank you for using our service,\n"
                f"SP-110 Green Team"
            )
        else:
            self._validate_message_text(body, field_name="body")

        self._validate_message_text(subject, field_name="subject")
        final_subject = header + subject

        self._send_email(final_subject, body)

    def send_custom_notification(self, subject, body):
        """
        Send a custom notification with a standard greeting and footer.
        """
        self._validate_runtime_state()
        self._validate_message_text(subject, field_name="subject")
        self._validate_message_text(body, field_name="body")

        final_body = (
            f"Dear {self.user_name},\n\n"
            f"{body}\n\n"
            f"Thank you for using our service,\n"
            f"SP-110 Green Team"
        )

        self._send_email(subject, final_body)

    def _send_email(self, subject, body):
        """
        Internal helper that builds and sends the email message.
        """
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.username
        msg["To"] = self.user_email
        msg.set_content(body)

        context = ssl.create_default_context()

        try:
            if self.use_ssl:
                with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, context=context) as smtp:
                    smtp.login(self.username, self.password)
                    smtp.send_message(msg)
            else:
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=context)
                    smtp.ehlo()
                    smtp.login(self.username, self.password)
                    smtp.send_message(msg)

        except smtplib.SMTPAuthenticationError as e:
            raise RuntimeError(
                "SMTP authentication failed. Check SMTP username, password, and provider settings."
            ) from e
        except smtplib.SMTPException as e:
            raise RuntimeError(f"SMTP error occurred while sending email: {e}") from e
        except OSError as e:
            raise RuntimeError(f"Network/socket error occurred while sending email: {e}") from e

    def _validate_config(self, config):
        """
        Validate the config dictionary passed into the class at startup.
        """
        if not isinstance(config, dict):
            raise TypeError("config must be a dictionary")

        required_keys = ["smtp_host", "smtp_port", "use_ssl", "username", "password"]
        missing_keys = [key for key in required_keys if key not in config]

        if missing_keys:
            raise ValueError(f"missing required config keys: {missing_keys}")

        if not isinstance(config["smtp_host"], str) or not config["smtp_host"].strip():
            raise ValueError("smtp_host must be a non-empty string")

        if not isinstance(config["username"], str) or not config["username"].strip():
            raise ValueError("username must be a non-empty string")

        if not isinstance(config["password"], str) or not config["password"].strip():
            raise ValueError("password must be a non-empty string")

        if not isinstance(config["use_ssl"], bool):
            raise ValueError("use_ssl must be a bool")

        try:
            port = int(config["smtp_port"])
        except (TypeError, ValueError):
            raise ValueError("smtp_port must be an integer")

        if port <= 0 or port > 65535:
            raise ValueError("smtp_port must be between 1 and 65535")

    def _validate_runtime_state(self):
        """
        Ensure required user-facing values are set before trying to send.
        """
        if self.user_email is None:
            raise ValueError("user_email has not been set")
        if self.user_name is None:
            raise ValueError("user_name has not been set")
        if self.user_device is None:
            raise ValueError("user_device has not been set")

    def _validate_and_format_severity(self, severity):
        """
        Validate severity and return a clean display string.
        """
        if severity is None:
            raise ValueError("severity cannot be None")

        # Allow ints, floats, or strings
        if isinstance(severity, (int, float)):
            if severity < 0 or severity > 100:
                raise ValueError("severity must be between 0 and 100")
            # Avoid ugly .0 display for whole numbers
            if float(severity).is_integer():
                return f"{int(severity)}%"
            return f"{severity}%"

        if isinstance(severity, str):
            cleaned = severity.strip()
            if not cleaned:
                raise ValueError("severity string cannot be empty")
            return cleaned

        raise ValueError("severity must be an int, float, or string")

    def _validate_message_text(self, text, field_name="text"):
        """
        Basic check for subject/body strings.
        """
        if not isinstance(text, str):
            raise ValueError(f"{field_name} must be a string")
        if not text.strip():
            raise ValueError(f"{field_name} cannot be empty")