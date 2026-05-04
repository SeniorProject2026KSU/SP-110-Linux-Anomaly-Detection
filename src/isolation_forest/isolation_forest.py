"""
Purpose:
    A simple end-to-end proof of concept for Linux log anomaly detection
    using /var/log/auth.log and an Isolation Forest.

Class usage:
    detector = IsolationForest()
    thread = detector.run()

Important:
    run() starts the detector in a background thread because live monitoring is blocking.
    If you run this file directly, the __main__ block keeps the program alive by joining
    the thread.
"""

import os
import random
import re
import threading
import time
from datetime import datetime


import joblib
from sklearn.ensemble import IsolationForest as SklearnIsolationForest


class IsolationForest:
    """
    Watches auth.log, trains an Isolation Forest baseline, then monitors future
    auth.log windows for anomalies.
    """

    def __init__(
        self,
        auth_log="/var/log/auth.log",
        window_seconds=20,
        baseline_windows=8,
        model_path="auth_iforest.joblib",
        contamination=0.10,
        use_manual_score_threshold=False,
        manual_score_threshold=-0.10,
        daemon=False,
    ):
        self.auth_log = auth_log
        self.window_seconds = window_seconds
        self.baseline_windows = baseline_windows
        self.model_path = model_path
        self.contamination = contamination
        self.use_manual_score_threshold = use_manual_score_threshold
        self.manual_score_threshold = manual_score_threshold
        self.daemon = daemon
        self.is_notification_enabled = False
        self.notif = None

        self.model = None
        self.thread = None
        self.stop_event = threading.Event()

        self.failed_ssh_re = re.compile(
            r"Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
        )
        self.accepted_ssh_re = re.compile(
            r"Accepted \S+ for (\S+) from (\d+\.\d+\.\d+\.\d+)"
        )
        self.sudo_re = re.compile(r"sudo:")
        self.user_re = re.compile(r"for (\S+)")
        self.ip_re = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")

    def add_notification_module(self, notif):
        self.notif = notif
        self.is_notification_enabled = True

    def run(self):
        """
        Starts the anomaly detector in a background thread.

        Returns:
            threading.Thread: the started thread, in case the caller wants to join it.
        """
        if self.thread and self.thread.is_alive():
            return self.thread

        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._run_blocking,
            name="IsolationForestLogMonitor",
            daemon=self.daemon,
        )
        self.thread.start()
        return self.thread

    def stop(self):
        """
        Requests the monitoring loop to stop.
        The thread exits after the current window finishes collecting.
        """
        self.stop_event.set()

    def _run_blocking(self):
        """
        Blocking flow:
            1. Show startup text UI
            2. Collect or load baseline rows
            3. Train model
            4. Save model
            5. Start live monitoring
        """
        choice = self.choose_baseline_mode()

        if choice == "1":
            baseline_rows = self.collect_live_baseline_rows()
        else:
            baseline_rows = self.use_preset_baseline_rows()

        print("Training Isolation Forest on baseline data...")
        self.model = self.train_model(baseline_rows)
        joblib.dump(self.model, self.model_path)

        print(f"Model trained and saved to: {self.model_path}")
        print()

        self.run_live_monitoring(self.model)

    def open_log_at_end(self, path):
        """
        Opens the auth log and seeks to the end of the file.
        This means monitoring starts with only new log entries.
        """
        f = open(path, "r", encoding="utf-8", errors="ignore")
        f.seek(0, os.SEEK_END)
        return f

    def extract_features(self, lines):
        """
        Converts raw log lines from a single time window into a numeric vector.

        Feature order:
            0 = failed SSH count
            1 = accepted SSH count
            2 = sudo count
            3 = unique IP count
            4 = unique user count
            5 = total auth-related lines seen
            6 = current hour of day
        """
        failed_ssh_count = 0
        accepted_ssh_count = 0
        sudo_count = 0
        unique_ips = set()
        unique_users = set()

        for line in lines:
            failed_match = self.failed_ssh_re.search(line)
            if failed_match:
                failed_ssh_count += 1
                unique_users.add(failed_match.group(2))
                unique_ips.add(failed_match.group(3))

            accepted_match = self.accepted_ssh_re.search(line)
            if accepted_match:
                accepted_ssh_count += 1
                unique_users.add(accepted_match.group(1))
                unique_ips.add(accepted_match.group(2))

            if self.sudo_re.search(line):
                sudo_count += 1
                maybe_user = self.user_re.search(line)
                if maybe_user:
                    unique_users.add(maybe_user.group(1))

            maybe_ip = self.ip_re.search(line)
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

    def collect_window(self, log_file, seconds):
        """
        Collects all new log lines that appear during one fixed time window.
        This is time-based and does not block forever waiting for new lines.
        """
        start = time.time()
        lines = []

        while time.time() - start < seconds and not self.stop_event.is_set():
            line = log_file.readline()

            if line:
                lines.append(line.strip())
            else:
                time.sleep(0.2)

        return lines

    def train_model(self, baseline_rows):
        """
        Trains an sklearn Isolation Forest using baseline feature rows.
        """
        model = SklearnIsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
        )
        model.fit(baseline_rows)
        return model

    def describe_features(self, feats):
        """
        Turns the numeric feature vector into a labeled dictionary for cleaner output.
        """
        return {
            "failed_ssh_count": feats[0],
            "accepted_ssh_count": feats[1],
            "sudo_count": feats[2],
            "unique_ip_count": feats[3],
            "unique_user_count": feats[4],
            "total_auth_events": feats[5],
            "hour_of_day": feats[6],
        }

    def compute_severity_percent(self, score):
        """
        Isolation Forest does not give a true probability/confidence.
        This maps the raw anomaly score into a 0-100 demo severity value.
        """
        raw = -score * 200.0
        clamped = max(0.0, min(100.0, raw))
        return int(round(clamped))

    def severity_label(self, percent):
        """
        Converts the pseudo-severity percent into a word label.
        """
        if percent == 0:
            return "none"
        if percent < 25:
            return "low"
        if percent < 50:
            return "moderate"
        if percent < 75:
            return "high"
        return "critical"

    def determine_verdict(self, pred, score):
        """
        Uses the model's built-in prediction by default.
        Optionally, also enforces a manual score threshold.
        """
        model_says_anomaly = pred == -1

        if self.use_manual_score_threshold:
            manual_says_anomaly = score < self.manual_score_threshold
            is_anomaly = model_says_anomaly or manual_says_anomaly
        else:
            is_anomaly = model_says_anomaly

        verdict = "ANOMALY DETECTED" if is_anomaly else "NORMAL"
        return verdict, is_anomaly

    def get_preset_baseline_rows(self):
        """
        Returns a fake but more varied normal-ish baseline dataset.

        Feature order:
        [failed_ssh, accepted_ssh, sudo_count, unique_ip_count,
         unique_user_count, total_auth_events, hour_of_day]
        """
        rows = []

        def add(row, n):
            for _ in range(n):
                rows.append(row.copy())

        for hour in range(0, 24):
            add([0, 0, 0, 0, 0, 0, hour], 6)

        for hour in range(0, 24):
            add([0, 0, 1, 0, 1, 1, hour], 4)
            add([0, 0, 2, 0, 1, 2, hour], 3)
            add([0, 0, 3, 0, 1, 3, hour], 2)

        for hour in range(8, 20):
            add([0, 0, 4, 0, 1, 4, hour], 2)
            add([0, 0, 5, 0, 1, 5, hour], 2)
            add([0, 0, 6, 0, 1, 6, hour], 1)

        for hour in range(8, 20):
            add([0, 1, 0, 1, 1, 1, hour], 3)
            add([0, 1, 1, 1, 1, 2, hour], 2)
            add([1, 0, 0, 1, 1, 1, hour], 2)

        for hour in range(9, 18):
            add([0, 1, 2, 1, 1, 3, hour], 2)
            add([1, 1, 1, 2, 2, 3, hour], 1)
            add([0, 1, 3, 1, 1, 4, hour], 1)

        for hour in range(10, 16):
            add([0, 0, 6, 0, 1, 6, hour], 1)
            add([0, 0, 7, 0, 1, 7, hour], 1)
            add([0, 1, 4, 1, 1, 5, hour], 1)

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
                hour,
            ])

        return rows

    def print_feature_reference(self):
        """
        Shows what each index in the feature matrix means.
        """
        print("Feature order used by the model:")
        print("  [0] failed_ssh_count")
        print("  [1] accepted_ssh_count")
        print("  [2] sudo_count")
        print("  [3] unique_ip_count")
        print("  [4] unique_user_count")
        print("  [5] total_auth_events")
        print("  [6] hour_of_day")
        print()

    def choose_baseline_mode(self):
        """
        Startup UI for choosing live baseline data or preset demo data.
        """
        print("==============================================")
        print(" auth.log Isolation Forest Demo")
        print("==============================================")
        print()
        print("Choose how to build the baseline training data:")
        print("  1) Collect live auth.log baseline data")
        print("  2) Use preset baseline matrix for demo")
        print()

        while not self.stop_event.is_set():
            choice = input("Enter choice (1 or 2): ").strip()
            if choice in {"1", "2"}:
                return choice
            print("Invalid choice. Please enter 1 or 2.")
            print()

        return "2"

    def collect_live_baseline_rows(self):
        """
        Uses real auth.log windows to build the baseline.
        """
        print()
        print("Live baseline mode selected.")
        print(f"Watching: {self.auth_log}")
        print(f"Window size: {self.window_seconds} seconds")
        print(f"Baseline windows: {self.baseline_windows}")
        print()
        print("Recommendation: do a small amount of normal activity during baseline.")
        print("Example: 1-2 sudo commands, normal terminal usage, no obvious bursts.")
        print()

        log_file = self.open_log_at_end(self.auth_log)
        baseline_rows = []

        try:
            for i in range(self.baseline_windows):
                if self.stop_event.is_set():
                    break

                lines = self.collect_window(log_file, self.window_seconds)
                feats = self.extract_features(lines)
                baseline_rows.append(feats)

                print(f"Baseline window {i + 1}/{self.baseline_windows}")
                print(f"  raw lines collected: {len(lines)}")
                print(f"  features: {self.describe_features(feats)}")
                print()
        finally:
            log_file.close()

        return baseline_rows

    def use_preset_baseline_rows(self):
        """
        Loads the fake default dataset and prints it for transparency.
        """
        print()
        print("Preset baseline mode selected.")
        print("Using a built-in baseline matrix with more varied normal-ish activity.")
        print("This is useful when live auth.log activity is too sparse for testing.")
        print()

        baseline_rows = self.get_preset_baseline_rows()
        self.print_feature_reference()
        print("Preset baseline rows:")
        for i, row in enumerate(baseline_rows, start=1):
            print(f"  row {i:02d}: {row}")
        print()

        return baseline_rows

    def run_live_monitoring(self, model):
        """
        After training, watches auth.log and prints the verdict for each window.
        """
        print("Live monitoring started.")
        print(f"Watching: {self.auth_log}")
        print(f"Window size: {self.window_seconds} seconds")
        print("Now generate suspicious auth activity and watch the verdict, score, and severity.")
        print("Call stop() or press Ctrl+C to stop if running directly.")
        print()

        log_file = self.open_log_at_end(self.auth_log)

        try:
            while not self.stop_event.is_set():
                lines = self.collect_window(log_file, self.window_seconds)
                feats = self.extract_features(lines)

                pred = model.predict([feats])[0]
                score = model.decision_function([feats])[0]

                verdict, is_anomaly = self.determine_verdict(pred, score)
                severity_percent = self.compute_severity_percent(score)
                severity_text = self.severity_label(severity_percent)

                print(f"[{datetime.now().isoformat()}]")
                print(f"  verdict: {verdict}")
                print(f"  model_prediction: {pred}   (1 = normal, -1 = anomaly)")
                print(f"  anomaly_score: {score:.4f}")
                print(f"  severity: {severity_percent}% ({severity_text})")
                print(f"  features: {self.describe_features(feats)}")
                print(f"  raw lines collected this window: {len(lines)}")
                print()

                if (severity_percent > 9 and self.is_notification_enabled == True):
                    self.notif.send_anomaly_notification(severity_percent)
        finally:
            log_file.close()


if __name__ == "__main__":
    detector = IsolationForest(daemon=False)
    monitor_thread = detector.run()

    try:
        monitor_thread.join()
    except KeyboardInterrupt:
        detector.stop()
        monitor_thread.join()
