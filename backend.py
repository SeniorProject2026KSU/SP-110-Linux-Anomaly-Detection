# backend.py
import pandas as pd

# Placeholder functions

def get_uploaded_logs_count():
    return 0

def get_anomalies_count():
    return 0

def get_anomaly_severity_counts():
    # Return a dummy dict
    return {"Low": 0, "Medium": 0, "High": 0}

def get_recent_activity():
    # Return empty dataframe
    columns = ['timestamp', 'ip', 'event', 'status']
    return pd.DataFrame(columns=columns)

def get_uploaded_files():
    return []

def validate_file(file):
    # Always return True for skeleton
    return True

def get_detected_anomalies():
    columns = ['timestamp', 'ip', 'event', 'status', 'severity']
    return pd.DataFrame(columns=columns)

def get_ml_model_performance():
    return {"accuracy": 0, "precision": 0, "recall": 0}