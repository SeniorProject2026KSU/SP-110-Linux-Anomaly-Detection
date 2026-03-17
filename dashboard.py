import streamlit as st
import pandas as pd
from backend import *

# === Sidebar Navigation ===
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to:", [
    "Overview",
    "Log Management",
    "Anomaly Review",
    "Data Visualization",
    "Test Cases",
    "System Administration"
])

# Overview Page 
if page == "Overview":
    st.title("Overview")
    
    st.header("Total Uploaded Logs")
    st.metric("Uploaded Logs", get_uploaded_logs_count())
    
    st.header("Total Anomalies Detected")
    st.metric("Anomalies Detected", get_anomalies_count())
    
    st.header("Anomaly Count by Severity Level")
    st.bar_chart(pd.Series(get_anomaly_severity_counts()))
    
    st.header("Recent Activity Summary")
    st.dataframe(get_recent_activity())
    
    st.header("System Features Navigation")
    st.write("Navigation buttons can go here")  # placeholder
    
    st.header("Logout")
    if st.button("Logout"):
        st.write("Logged out!")  # placeholder

# Log Management Page 
elif page == "Log Management":
    st.title("Log Management Page")
    
    st.header("Upload Log Files")
    uploaded_file = st.file_uploader("Upload CSV, JSON, TXT")
    
    if uploaded_file:
        if validate_file(uploaded_file):
            st.success("File validated and uploaded!")
        else:
            st.error("Invalid file format")
    
    st.header("Delete Logs / View Uploaded Files")
    st.write(get_uploaded_files())  # placeholder

# Anomaly Review Page 
elif page == "Anomaly Review":
    st.title("Anomaly Review Page")
    st.dataframe(get_detected_anomalies())
    st.write("Filters: date range, severity, IP")
    st.write("Mark anomalies as reviewed or false positive")


# Data Visualization Page 
elif page == "Data Visualization":
    st.title("Data Visualization Page")
    st.write("Line graph: anomalies over time")
    st.write("Bar chart: event frequency")
    st.write("Top IPs by anomalies")
    st.write("Severity distribution")
    st.write("Export as CSV")

# Test Case Demonstration 
elif page == "Test Cases":
    st.title("Test Case Demonstration")
    st.write("Load normal/attack datasets")
    st.write("Run detection")
    st.write("Display results and false-positive rate")

# System Administration 
elif page == "System Administration":
    st.title("System Administration")
    st.write("Manage user accounts")
    st.write("View system logs")
    st.write("Backup/restore database")
    st.write("Configure system settings")