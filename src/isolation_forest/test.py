# You end up with a matrix like this:

# [failed_ssh, accepted_ssh, sudo_count, unique_ips, total_events, hour]
# [0,          0,            1,          1,           3,            19]
# [0,          0,            0,          0,           1,            19]
# [2,          0,            0,          2,           2,            19]
# [0,          1,            0,          1,           1,            19]
# Each row = one time window
# Each column = one feature

"""

Purpose:
    A simple end-to-end proof of concept for Linux log anomaly detection
    using /var/log/auth.log and an Isolation Forest.

What this script does:
    1. Watches auth.log in near real time
    2. Groups new log lines into fixed time windows
    3. Converts each window into simple numeric features
    4. Collects a short "normal behavior" baseline
    5. Trains an Isolation Forest on that baseline
    6. Monitors future windows and flags unusual behavior
    7. Prints a verdict for every window, including a human-readable severity

How to test it:
    - Let it sit during baseline collection while the system is mostly idle
    - During baseline, do a small amount of normal activity:
        * 1-2 sudo commands
        * some normal terminal usage
    - After training, generate unusual auth activity such as:
        * several sudo commands in a short burst
        * failed SSH logins (if SSH is enabled)
    - Watch the script print the verdict, anomaly score, and severity


Important note about severity:
    Isolation Forest does NOT output a true probability or confidence 0-100%.
    This script creates a pseudo-severity value from the anomaly score so the
    output is easier for humans to understand in a demo.
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

AUTH_LOG = "/var/log/auth.log"
WINDOW_SECONDS = 20
BASELINE_WINDOWS = 8
MODEL_PATH = "auth_iforest.joblib"
CONTAMINATION = 0.10

USE_MANUAL_SCORE_THRESHOLD = False
MANUAL_SCORE_THRESHOLD = -0.10


# -----------------------------
# Regex patterns
# -----------------------------
failed_ssh_re = re.compile(
    r"Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)

accepted_ssh_re = re.compile(
    r"Accepted \S+ for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)

sudo_re = re.compile(r"sudo:")
user_re = re.compile(r"for (\S+)")
ip_re = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")


# -----------------------------
# open_log_at_end
# -----------------------------
# Opens the auth log and seeks to the end of the file.
# This means the script starts watching only NEW log entries.
def open_log_at_end(path):
    f = open(path, "r", encoding="utf-8", errors="ignore")
    f.seek(0, os.SEEK_END)
    return f


# -----------------------------
# extract_features
# -----------------------------
# Converts raw log lines from a single time window into a numeric feature vector.
#
# Current features:
#   0 = failed SSH count
#   1 = accepted SSH count
#   2 = sudo count
#   3 = unique IP count
#   4 = unique user count
#   5 = total auth-related lines seen
#   6 = current hour of day
def extract_features(lines):
    failed_ssh_count = 0
    accepted_ssh_count = 0
    sudo_count = 0
    unique_ips = set()
    unique_users = set()

    for line in lines:
        failed_match = failed_ssh_re.search(line)
        if failed_match:
            failed_ssh_count += 1
            unique_users.add(failed_match.group(2))
            unique_ips.add(failed_match.group(3))

        accepted_match = accepted_ssh_re.search(line)
        if accepted_match:
            accepted_ssh_count += 1
            unique_users.add(accepted_match.group(1))
            unique_ips.add(accepted_match.group(2))

        if sudo_re.search(line):
            sudo_count += 1
            maybe_user = user_re.search(line)
            if maybe_user:
                unique_users.add(maybe_user.group(1))

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
# Collects all new log lines that appear during one fixed time window.
#
# This version is time-based and does NOT block forever waiting for new lines.
# If no line is ready, it sleeps briefly and checks again.
def collect_window(log_file, seconds):
    start = time.time()
    lines = []

    while time.time() - start < seconds:
        line = log_file.readline()

        if line:
            lines.append(line.strip())
        else:
            time.sleep(0.2)

    return lines


# -----------------------------
# train_model
# -----------------------------
# Trains an Isolation Forest using baseline feature rows.
#
# Each inner list in baseline_rows is one time window summarized as features.
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
# compute_severity_percent
# -----------------------------
# Isolation Forest does not give a true probability/confidence.
# So this function maps the raw anomaly score into a human-readable
# 0-100 severity percentage for demo purposes.
def compute_severity_percent(score):
    raw = -score * 200.0
    clamped = max(0.0, min(100.0, raw))
    return int(round(clamped))


# -----------------------------
# severity_label
# -----------------------------
# Converts the pseudo-severity percent into a word label.
def severity_label(percent):
    if percent == 0:
        return "none"
    if percent < 25:
        return "low"
    if percent < 50:
        return "moderate"
    if percent < 75:
        return "high"
    return "critical"


# -----------------------------
# determine_verdict
# -----------------------------
# Uses the model's built-in prediction by default.
# Optionally, you can also enforce a manual score threshold.
def determine_verdict(pred, score):
    model_says_anomaly = (pred == -1)

    if USE_MANUAL_SCORE_THRESHOLD:
        manual_says_anomaly = (score < MANUAL_SCORE_THRESHOLD)
        is_anomaly = model_says_anomaly or manual_says_anomaly
    else:
        is_anomaly = model_says_anomaly

    verdict = "ANOMALY DETECTED" if is_anomaly else "NORMAL"
    return verdict, is_anomaly


# -----------------------------
# get_preset_baseline_rows
# -----------------------------
# Returns a fake but more varied "normal-ish" baseline dataset.
# This is useful for testing the ML flow when live data is too sparse.
#
# Feature order:
# [failed_ssh, accepted_ssh, sudo_count, unique_ip_count, unique_user_count, total_auth_events, hour_of_day]
def get_preset_baseline_rows():
    rows = []

    # Helper to add repeated rows
    def add(row, n):
        for _ in range(n):
            rows.append(row.copy())

    # -----------------------------
    # HEAVY IDLE BASELINE (VERY IMPORTANT)
    # -----------------------------
    for hour in range(0, 24):
        add([0, 0, 0, 0, 0, 0, hour], 6)

    # -----------------------------
    # LIGHT NORMAL ACTIVITY
    # -----------------------------
    for hour in range(0, 24):
        add([0, 0, 1, 0, 1, 1, hour], 4)
        add([0, 0, 2, 0, 1, 2, hour], 3)
        add([0, 0, 3, 0, 1, 3, hour], 2)

    # -----------------------------
    # MODERATE NORMAL ACTIVITY
    # -----------------------------
    for hour in range(8, 20):
        add([0, 0, 4, 0, 1, 4, hour], 2)
        add([0, 0, 5, 0, 1, 5, hour], 2)
        add([0, 0, 6, 0, 1, 6, hour], 1)

    # -----------------------------
    # SSH ACTIVITY MIX (NORMAL)
    # -----------------------------
    for hour in range(8, 20):
        add([0, 1, 0, 1, 1, 1, hour], 3)
        add([0, 1, 1, 1, 1, 2, hour], 2)
        add([1, 0, 0, 1, 1, 1, hour], 2)  # occasional failed login

    # -----------------------------
    # MIXED EVENTS (REALISTIC NORMAL)
    # -----------------------------
    for hour in range(9, 18):
        add([0, 1, 2, 1, 1, 3, hour], 2)
        add([1, 1, 1, 2, 2, 3, hour], 1)
        add([0, 1, 3, 1, 1, 4, hour], 1)

    # -----------------------------
    # SLIGHTLY BUSY BUT STILL NORMAL
    # -----------------------------
    for hour in range(10, 16):
        add([0, 0, 6, 0, 1, 6, hour], 1)
        add([0, 0, 7, 0, 1, 7, hour], 1)
        add([0, 1, 4, 1, 1, 5, hour], 1)

    # -----------------------------
    # RANDOMIZED SMALL VARIATION (IMPORTANT)
    # -----------------------------
    import random

    for _ in range(200):
        hour = random.randint(0, 23)

        sudo = random.choice([0, 1, 2, 3, 4])
        accepted = random.choice([0, 0, 1])
        failed = random.choice([0, 0, 0, 1])

        unique_users = 1 if (sudo + accepted + failed) > 0 else 0
        unique_ips = 1 if (accepted or failed) else 0
        total = sudo + accepted + failed

        rows.append([
            failed,
            accepted,
            sudo,
            unique_ips,
            unique_users,
            total,
            hour
        ])

    return rows


# -----------------------------
# print_feature_reference
# -----------------------------
# Shows the user what each index in the matrix means.
def print_feature_reference():
    print("Feature order used by the model:")
    print("  [0] failed_ssh_count")
    print("  [1] accepted_ssh_count")
    print("  [2] sudo_count")
    print("  [3] unique_ip_count")
    print("  [4] unique_user_count")
    print("  [5] total_auth_events")
    print("  [6] hour_of_day")
    print()


# -----------------------------
# choose_baseline_mode
# -----------------------------
# Small text UI shown at startup so the user can choose whether to:
#   1. Collect live training data from auth.log
#   2. Use a preset baseline matrix
def choose_baseline_mode():
    print("==============================================")
    print(" auth.log Isolation Forest Demo")
    print("==============================================")
    print()
    print("Choose how to build the baseline training data:")
    print("  1) Collect live auth.log baseline data")
    print("  2) Use preset baseline matrix for quick testing")
    print()

    while True:
        choice = input("Enter choice (1 or 2): ").strip()
        if choice in {"1", "2"}:
            return choice
        print("Invalid choice. Please enter 1 or 2.")
        print()


# -----------------------------
# collect_live_baseline_rows
# -----------------------------
# Uses real auth.log windows to build the baseline.
def collect_live_baseline_rows():
    print()
    print("Live baseline mode selected.")
    print(f"Watching: {AUTH_LOG}")
    print(f"Window size: {WINDOW_SECONDS} seconds")
    print(f"Baseline windows: {BASELINE_WINDOWS}")
    print()
    print("Recommendation: do a small amount of normal activity during baseline.")
    print("Example: 1-2 sudo commands, normal terminal usage, no obvious bursts.")
    print()

    log_file = open_log_at_end(AUTH_LOG)
    baseline_rows = []

    for i in range(BASELINE_WINDOWS):
        lines = collect_window(log_file, WINDOW_SECONDS)
        feats = extract_features(lines)
        baseline_rows.append(feats)

        print(f"Baseline window {i + 1}/{BASELINE_WINDOWS}")
        print(f"  raw lines collected: {len(lines)}")
        print(f"  features: {describe_features(feats)}")
        print()

    return baseline_rows


# -----------------------------
# use_preset_baseline_rows
# -----------------------------
# Loads the fake default dataset and prints it for transparency.
def use_preset_baseline_rows():
    print()
    print("Preset baseline mode selected.")
    print("Using a built-in baseline matrix with more varied normal-ish activity.")
    print("This is useful when live auth.log activity is too sparse for testing.")
    print()

    baseline_rows = get_preset_baseline_rows()
    print_feature_reference()
    print("Preset baseline rows:")
    for i, row in enumerate(baseline_rows, start=1):
        print(f"  row {i:02d}: {row}")
    print()

    return baseline_rows


# -----------------------------
# run_live_monitoring
# -----------------------------
# After training, this watches auth.log and prints the verdict for each window.
def run_live_monitoring(model):
    print("Live monitoring started.")
    print(f"Watching: {AUTH_LOG}")
    print(f"Window size: {WINDOW_SECONDS} seconds")
    print("Now generate suspicious auth activity and watch the verdict, score, and severity.")
    print("Press Ctrl+C to stop.")
    print()

    log_file = open_log_at_end(AUTH_LOG)

    while True:
        lines = collect_window(log_file, WINDOW_SECONDS)
        feats = extract_features(lines)

        pred = model.predict([feats])[0]
        score = model.decision_function([feats])[0]

        verdict, is_anomaly = determine_verdict(pred, score)
        severity_percent = compute_severity_percent(score)
        severity_text = severity_label(severity_percent)

        print(f"[{datetime.now().isoformat()}]")
        print(f"  verdict: {verdict}")
        print(f"  model_prediction: {pred}   (1 = normal, -1 = anomaly)")
        print(f"  anomaly_score: {score:.4f}")
        print(f"  severity: {severity_percent}% ({severity_text})")
        print(f"  features: {describe_features(feats)}")
        print(f"  raw lines collected this window: {len(lines)}")
        print()


# -----------------------------
# main
# -----------------------------
# High-level flow:
#   1. Show startup text UI
#   2. Collect or load baseline rows
#   3. Train model
#   4. Save model
#   5. Start live monitoring
def main():
    choice = choose_baseline_mode()

    if choice == "1":
        baseline_rows = collect_live_baseline_rows()
    else:
        baseline_rows = use_preset_baseline_rows()

    print("Training Isolation Forest on baseline data...")
    model = train_model(baseline_rows)
    joblib.dump(model, MODEL_PATH)

    print(f"Model trained and saved to: {MODEL_PATH}")
    print()

    run_live_monitoring(model)


if __name__ == "__main__":
    main()