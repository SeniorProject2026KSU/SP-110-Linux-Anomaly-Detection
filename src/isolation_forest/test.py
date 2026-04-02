"""
auth_log_iforest_demo.py

Purpose:
    A simple end-to-end proof of concept for Linux log anomaly detection
    using /var/log/auth.log and an Isolation Forest.

What this script does:
    1. Watches auth.log in real time
    2. Groups new log lines into fixed time windows
    3. Converts each window into simple numeric features
    4. Collects a short "normal behavior" baseline
    5. Trains an Isolation Forest on that baseline
    6. Monitors future windows and flags unusual behavior

Good for:
    - quick MVP testing
    - showing the full pipeline works
    - demonstrating how logs become ML input


How to test it:
    - Let it sit during baseline collection while the system is mostly idle
    - After training, generate unusual auth activity such as:
        * several sudo commands in a short burst
        * failed SSH logins (if SSH is enabled)
    - Watch the script print anomaly scores for each window

Example sudo burst test:
    sudo ls /root
    sudo journalctl -n 5 >/dev/null
    sudo ls /var/log >/dev/null
    sudo cat /etc/shadow >/dev/null 2>&1

Optional SSH failed-login test (if localhost SSH is enabled):
    ssh fakeuser@localhost

Important note:
    Isolation Forest in this script has a fixed learning phase first,
    then a monitoring phase after that. It does not keep retraining itself.
"""

import os
import re
import time
from datetime import datetime
from sklearn.ensemble import IsolationForest
import joblib

# -----------------------------
# Configuration
# -----------------------------

# Path to the Linux auth log.
# On Ubuntu/Kubuntu this is usually /var/log/auth.log
AUTH_LOG = "/var/log/auth.log"

# Number of seconds to group into one "behavior window".
# Shorter windows = faster feedback, but noisier data.
# Longer windows = more stable summaries, but slower demo.
WINDOW_SECONDS = 20

# Number of windows to collect before training.
# These windows should ideally represent mostly normal behavior.
BASELINE_WINDOWS = 8

# Where the trained model will be saved.
MODEL_PATH = "auth_iforest.joblib"

# Isolation Forest setting:
# contamination is the model's guess for roughly how much anomaly-like
# data might exist. Smaller = less sensitive. Larger = more sensitive.
CONTAMINATION = 0.10


# -----------------------------
# Regex patterns
# -----------------------------
# These are simple patterns to detect useful auth.log events.
# They are not perfect, but good enough for a proof of concept.

# Example failed SSH line:
# "Failed password for invalid user bob from 192.168.1.5 port 22 ssh2"
failed_ssh_re = re.compile(
    r"Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)

# Example accepted SSH line:
# "Accepted password for colin from 192.168.1.5 port 22 ssh2"
accepted_ssh_re = re.compile(
    r"Accepted \S+ for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)

# Sudo lines often include "sudo:"
sudo_re = re.compile(r"sudo:")

# A very loose user extractor used for some sudo-style lines
user_re = re.compile(r"for (\S+)")

# General IP extractor for "from x.x.x.x"
ip_re = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")


# -----------------------------
# tail_f
# -----------------------------
# This works similarly to "tail -f" in Linux.
# It opens the file, jumps to the end, and then waits for new lines.
#
# Why do this?
# Because for live monitoring, we want only NEW log activity, not
# the entire old log history every time.
def tail_f(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        # Seek to end so we start watching new events only.
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()

            # If no line is available yet, wait a bit and try again.
            if not line:
                time.sleep(0.2)
                continue

            yield line.strip()


# -----------------------------
# extract_features
# -----------------------------
# Converts raw log lines from a single time window into a numeric feature vector.
#
# This is the most important ML step conceptually:
# raw logs are NOT fed directly into Isolation Forest.
# Instead, we summarize behavior into counts and simple metrics.
#
# Current features:
#   0 = failed SSH count
#   1 = accepted SSH count
#   2 = sudo count
#   3 = unique IP count
#   4 = unique user count
#   5 = total auth-related lines seen
#   6 = current hour of day
#
# Why these?
# They are simple, easy to explain, and often useful for anomaly detection.
def extract_features(lines):
    failed_ssh_count = 0
    accepted_ssh_count = 0
    sudo_count = 0
    unique_ips = set()
    unique_users = set()

    for line in lines:
        # Count failed SSH logins
        failed_match = failed_ssh_re.search(line)
        if failed_match:
            failed_ssh_count += 1
            unique_users.add(failed_match.group(2))
            unique_ips.add(failed_match.group(3))

        # Count successful SSH logins
        accepted_match = accepted_ssh_re.search(line)
        if accepted_match:
            accepted_ssh_count += 1
            unique_users.add(accepted_match.group(1))
            unique_ips.add(accepted_match.group(2))

        # Count sudo events
        if sudo_re.search(line):
            sudo_count += 1
            maybe_user = user_re.search(line)
            if maybe_user:
                unique_users.add(maybe_user.group(1))

        # Catch any IP that appears in a "from x.x.x.x" format
        maybe_ip = ip_re.search(line)
        if maybe_ip:
            unique_ips.add(maybe_ip.group(1))

    total_auth_events = len(lines)
    hour_of_day = datetime.now().hour

    return [
        failed_ssh_count,
        accepted_ssh_count,
        sudo_count,
        len(unique_ips),
        len(unique_users),
        total_auth_events,
        hour_of_day,
    ]


# -----------------------------
# collect_window
# -----------------------------
# Collects all new log lines that arrive during one fixed time window.
#
# Example:
# If WINDOW_SECONDS = 20, this function gathers all auth.log activity
# that appears during those 20 seconds, then returns it as a list.
#
# That list is later converted into a single feature vector.
def collect_window(line_gen, seconds):
    start = time.time()
    lines = []

    while time.time() - start < seconds:
        try:
            line = next(line_gen)
            lines.append(line)
        except StopIteration:
            break

    return lines


# -----------------------------
# train_model
# -----------------------------
# Trains an Isolation Forest using baseline feature rows.
#
# baseline_rows should look like:
# [
#   [0, 0, 1, 0, 1, 2, 19],
#   [0, 0, 0, 0, 0, 0, 19],
#   [1, 0, 0, 1, 1, 1, 19],
#   ...
# ]
#
# Each inner list is one time window summarized as features.
def train_model(baseline_rows):
    model = IsolationForest(
        n_estimators=100,
        contamination=CONTAMINATION,
        random_state=42,
    )
    model.fit(baseline_rows)
    return model


# -----------------------------
# describe_features
# -----------------------------
# Turns the numeric feature vector into a labeled dictionary for cleaner output.
# This is purely for readability during the demo.
def describe_features(feats):
    return {
        "failed_ssh_count": feats[0],
        "accepted_ssh_count": feats[1],
        "sudo_count": feats[2],
        "unique_ip_count": feats[3],
        "unique_user_count": feats[4],
        "total_auth_events": feats[5],
        "hour_of_day": feats[6],
    }


# -----------------------------
# main
# -----------------------------
# High-level flow:
#   1. Watch auth.log
#   2. Collect baseline windows
#   3. Train model
#   4. Save model
#   5. Monitor forever and score live windows
def main():
    print("Starting auth.log Isolation Forest demo...")
    print(f"Watching: {AUTH_LOG}")
    print(f"Window size: {WINDOW_SECONDS} seconds")
    print(f"Baseline windows: {BASELINE_WINDOWS}")
    print()

    # Create a live line generator for auth.log
    gen = tail_f(AUTH_LOG)

    # -----------------------------
    # Phase 1: Baseline collection
    # -----------------------------
    # During this phase, the script is "learning" normal behavior.
    # It does not score anomalies yet.
    print("Phase 1: collecting baseline windows under normal behavior")
    baseline_rows = []

    for i in range(BASELINE_WINDOWS):
        lines = collect_window(gen, WINDOW_SECONDS)
        feats = extract_features(lines)
        baseline_rows.append(feats)

        print(f"Baseline window {i + 1}/{BASELINE_WINDOWS}")
        print(f"  raw lines collected: {len(lines)}")
        print(f"  features: {describe_features(feats)}")
        print()

    # -----------------------------
    # Phase 2: Train model
    # -----------------------------
    print("Training Isolation Forest on baseline data...")
    model = train_model(baseline_rows)
    joblib.dump(model, MODEL_PATH)

    print(f"Model trained and saved to: {MODEL_PATH}")
    print()
    print("Phase 2: live monitoring started")
    print("Now generate suspicious auth activity and watch the scores.")
    print("Press Ctrl+C to stop.")
    print()

    # -----------------------------
    # Phase 3: Live monitoring
    # -----------------------------
    # For each new window:
    #   - collect new auth.log lines
    #   - convert them into features
    #   - ask the model whether they look normal or anomalous
    while True:
        lines = collect_window(gen, WINDOW_SECONDS)
        feats = extract_features(lines)

        # predict:
        #   1  = normal
        #  -1  = anomaly
        pred = model.predict([feats])[0]

        # decision_function:
        # higher = more normal
        # lower  = more anomalous
        score = model.decision_function([feats])[0]

        status = "ANOMALY" if pred == -1 else "normal"

        print(f"[{datetime.now().isoformat()}]")
        print(f"  status: {status}")
        print(f"  score: {score:.4f}")
        print(f"  features: {describe_features(feats)}")
        print(f"  raw lines collected this window: {len(lines)}")
        print()

        # Tutorial note:
        # If you later want alerts, this is the place to add them.
        # Example:
        # if pred == -1:
        #     send_email_alert(status, score, feats)


if __name__ == "__main__":
    main()