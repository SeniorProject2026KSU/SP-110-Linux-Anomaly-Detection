import streamlit as st
import pandas as pd
from backend import *

# Initialize storage (must be at top, outside pages)
if "logs_df" not in st.session_state:
    st.session_state.logs_df = None

if "test_df" not in st.session_state:
    st.session_state.test_df = None

if "detection_results" not in st.session_state:
    st.session_state.detection_results = None


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

    df = st.session_state.logs_df

    if df is not None:

        st.header("Total Uploaded Logs")
        st.metric("Uploaded Logs", len(df))

        st.header("Total Anomalies Detected")
        anomalies = df[df["success"] == 0]
        st.metric("Anomalies Detected", len(anomalies))

        st.header("Anomaly Count by Severity Level")

        # simple rule-based severity
        df["severity"] = df["success"].apply(
            lambda x: "High" if x == 0 else "Low"
        )

        st.bar_chart(df["severity"].value_counts())

        st.header("Recent Activity Summary")
        st.dataframe(df.head(20))

    else:
        st.warning("No data uploaded yet.")


# Log Management Page
elif page == "Log Management":
    st.title("Log Management Page")
    
    st.header("Upload Log Files")
    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])
    
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        
        # Save globally
        st.session_state.logs_df = df
        
        st.success("File uploaded successfully!")
        st.dataframe(df.head())

# Anomaly Review Page 
elif page == "Anomaly Review":
    st.title("Anomaly Review Page")

    df = st.session_state.logs_df

    if df is not None:
        anomalies = df[df["success"] == 0]
        st.dataframe(anomalies)
    else:
        st.warning("Upload data first.")


# Data Visualization Page 
elif page == "Data Visualization":
    st.title("Data Visualization Page")

    df = st.session_state.logs_df

    if df is not None:
        st.subheader("Events by Type")
        st.bar_chart(df["eventtype"].value_counts())

        st.subheader("Success vs Failure")
        st.bar_chart(df["success"].value_counts())

        st.subheader("Top Source IPs")
        st.bar_chart(df["sourceip"].value_counts().head(10))

    else:
        st.warning("Upload data first.")


# TEST CASES PAGE
elif page == "Test Cases":
    st.title("Test Case Demonstration")

    # Auto-load dataset 
    try:
        df = pd.read_csv("example.csv")
        st.session_state.test_df = df
        st.success("Example dataset loaded automatically")
    except Exception as e:
        st.error(f"Failed to load example.csv: {e}")
        st.stop()

    st.subheader("Dataset Preview")
    st.dataframe(df.head())

    # Run Detection
    if st.button("Run Detection"):

        df = df.copy()

        # Detection rule
        df["predicted_anomaly"] = df["success"].apply(
            lambda x: 1 if x == 0 else 0
        )

        st.session_state.detection_results = df
        st.success("Detection complete!")

    # Results 
    results = st.session_state.get("detection_results", None)

    if results is not None:
        st.subheader("Detection Results")
        st.dataframe(results)

        # Metrics
        total = len(results)
        actual_anomalies = (results["success"] == 0).sum()
        predicted_anomalies = results["predicted_anomaly"].sum()

        st.metric("Total Logs", total)
        st.metric("Actual Anomalies", actual_anomalies)
        st.metric("Predicted Anomalies", predicted_anomalies)

    st.subheader("Success vs Failure Distribution")
    st.bar_chart(results["success"].value_counts())

    st.subheader("Event Type Distribution")
    st.bar_chart(results["eventtype"].value_counts())

    st.subheader("Top Source IPs")
    st.bar_chart(results["sourceip"].value_counts().head(10))

    st.subheader("Predicted Anomalies vs Normal")
    st.bar_chart(results["predicted_anomaly"].value_counts())

    st.subheader("Anomalies by Event Type")

    anomaly_counts = results[results["predicted_anomaly"] == 1]["eventtype"].value_counts()

    st.bar_chart(anomaly_counts)

# System Administration 
elif page == "System Administration":

    #not done yet/this is placeholder
    st.title("System Administration")
    st.write("Manage user accounts")
    st.write("View system logs")
    st.write("Backup/restore database")
    st.write("Configure system settings")