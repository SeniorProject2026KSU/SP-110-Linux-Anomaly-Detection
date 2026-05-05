import json
import os

BUFFER_FILE = "buffer.json"

def save(event):
    data = []
    if os.path.exists(BUFFER_FILE):
        with open(BUFFER_FILE, "r") as f:
            data = json.load(f)

    data.append(event)

    with open(BUFFER_FILE, "w") as f:
        json.dump(data, f)

def load():
    if not os.path.exists(BUFFER_FILE):
        return []

    with open(BUFFER_FILE, "r") as f:
        return json.load(f)

def clear():
    if os.path.exists(BUFFER_FILE):
        os.remove(BUFFER_FILE)
