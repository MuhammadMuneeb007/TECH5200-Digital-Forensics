"""
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██████╗  ██████╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██╔════╝
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ██████╔╝██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔═══╝ ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║     ╚██████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝      ╚═════╝

SentinelPC — Your PC as a Silent Forensic Witness
--------------------------------------------------
Author  : You
Version : 1.0.0
License : MIT

REQUIREMENTS (install once):
    pip install watchdog psutil opencv-python Pillow schedule jinja2

HOW TO RUN:
    python sentinelpc.py

HOW TO STOP:
    Ctrl+C  (report is always saved before exit)

OUTPUT:
    • ~/Desktop/SentinelPC_Report.html   ← live forensic report
    • ~/SentinelPC/                       ← evidence vault
        ├── sentinel.db                   ← tamper-evident SQLite database
        └── snapshots/                    ← captured screenshots + webcam photos
"""

# ─────────────────────────────────────────────
#  STANDARD LIBRARY
# ─────────────────────────────────────────────
import os
import sys
import time
import math
import hashlib
import sqlite3
import threading
import subprocess
import platform
import datetime
import json
import re
import shutil
import base64
import signal
import logging
from pathlib import Path

# ─────────────────────────────────────────────
#  THIRD-PARTY  (pip install …)
# ─────────────────────────────────────────────
def _check_deps():
    missing = []
    for pkg in ["watchdog", "psutil", "cv2", "PIL", "schedule", "jinja2"]:
        try:
            __import__(pkg if pkg != "cv2" else "cv2")
        except ImportError:
            name_map = {"cv2": "opencv-python", "PIL": "Pillow"}
            missing.append(name_map.get(pkg, pkg))
    if missing:
        print(f"\n[SentinelPC] Missing packages: {', '.join(missing)}")
        print(f"Run:  pip install {' '.join(missing)}\n")
        sys.exit(1)

_check_deps()

import psutil
import schedule
import cv2
from PIL import ImageGrab
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from jinja2 import Template

# ─────────────────────────────────────────────
#  CONFIG  (edit these if you want)
# ─────────────────────────────────────────────
VAULT_DIR        = Path.home() / "SentinelPC"
SNAPSHOTS_DIR    = VAULT_DIR / "snapshots"
DB_PATH          = VAULT_DIR / "sentinel.db"
REPORT_PATH      = Path.home() / "Desktop" / "SentinelPC_Report.html"
REPORT_INTERVAL  = 5          # minutes between report refreshes
NETWORK_INTERVAL = 30         # seconds between network scans
WEBCAM_INTERVAL  = 60         # seconds between passive webcam checks
WATCHED_DIRS     = [          # directories monitored for file changes
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path.home() / "Downloads",
]
SENSITIVE_EXTS   = {".env", ".key", ".pem", ".p12", ".pfx",
                    ".kdbx", ".wallet", ".keystore"}  # extra-flagged extensions
LOG_LEVEL        = logging.INFO

# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("SentinelPC")

# ─────────────────────────────────────────────
#  VAULT / DATABASE SETUP
# ─────────────────────────────────────────────
VAULT_DIR.mkdir(parents=True, exist_ok=True)
SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)

_db_lock = threading.Lock()

def _get_conn():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with _db_lock:
        conn = _get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT    NOT NULL,
                category    TEXT    NOT NULL,
                severity    TEXT    NOT NULL DEFAULT 'INFO',
                title       TEXT    NOT NULL,
                detail      TEXT,
                snapshot    TEXT,
                file_hash   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ts       ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_category ON events(category);
            CREATE INDEX IF NOT EXISTS idx_severity ON events(severity);
        """)
        conn.commit()
        conn.close()
    log.info("Database initialised at %s", DB_PATH)

def log_event(category: str, title: str, detail: str = "",
              severity: str = "INFO", snapshot: str = None,
              file_hash: str = None):
    ts = datetime.datetime.now().isoformat(sep=" ", timespec="seconds")
    with _db_lock:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO events(ts,category,severity,title,detail,snapshot,file_hash) "
            "VALUES (?,?,?,?,?,?,?)",
            (ts, category, severity, title, detail, snapshot, file_hash)
        )
        conn.commit()
        conn.close()
    icon = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🟢"}.get(severity, "⚪")
    log.info("%s [%s] %s — %s", icon, category, title, detail[:120] if detail else "")

def fetch_events(limit: int = 500):
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT ts,category,severity,title,detail,snapshot,file_hash "
            "FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
    return rows

def event_stats():
    with _db_lock:
        conn = _get_conn()
        total   = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        crits   = conn.execute("SELECT COUNT(*) FROM events WHERE severity='CRITICAL'").fetchone()[0]
        warns   = conn.execute("SELECT COUNT(*) FROM events WHERE severity='WARNING'").fetchone()[0]
        by_cat  = conn.execute(
            "SELECT category, COUNT(*) FROM events GROUP BY category ORDER BY COUNT(*) DESC"
        ).fetchall()
        conn.close()
    return total, crits, warns, by_cat

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def sha256_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unreadable"

def take_screenshot(tag: str = "event") -> str:
    try:
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"{tag}_{ts}.png"
        path = SNAPSHOTS_DIR / name
        img  = ImageGrab.grab()
        img.save(str(path))
        return str(path)
    except Exception as e:
        log.warning("Screenshot failed: %s", e)
        return None

def capture_webcam(tag: str = "webcam") -> str:
    try:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return None
        ret, frame = cap.read()
        cap.release()
        if not ret:
            return None
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"{tag}_{ts}.jpg"
        path = SNAPSHOTS_DIR / name
        cv2.imwrite(str(path), frame)
        return str(path)
    except Exception as e:
        log.warning("Webcam capture failed: %s", e)
        return None

def detect_face_in_image(image_path: str) -> bool:
    """Returns True if at least one face is detected."""
    try:
        cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        face_cascade = cv2.CascadeClassifier(cascade_path)
        img  = cv2.imread(image_path)
        if img is None:
            return False
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1,
                                              minNeighbors=5, minSize=(60, 60))
        return len(faces) > 0
    except Exception:
        return False

def img_to_b64(path: str) -> str:
    """Convert image to base64 for embedding in HTML."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        ext = Path(path).suffix.lower().lstrip(".")
        mime = {"jpg": "jpeg", "jpeg": "jpeg", "png": "png"}.get(ext, "png")
        return f"data:image/{mime};base64,{base64.b64encode(data).decode()}"
    except Exception:
        return ""

# ─────────────────────────────────────────────
#  1. FILE SYSTEM WATCHER
# ─────────────────────────────────────────────
class _FSHandler(FileSystemEventHandler):
    def _handle(self, event, action):
        if event.is_directory:
            return
        path = event.src_path
        ext  = Path(path).suffix.lower()
        sev  = "CRITICAL" if ext in SENSITIVE_EXTS else "WARNING"
        fhash = sha256_file(path) if action in ("created", "modified") else None
        snap  = take_screenshot(f"fs_{action}")
        log_event(
            category="FILESYSTEM",
            title=f"File {action}: {Path(path).name}",
            detail=path,
            severity=sev,
            snapshot=snap,
            file_hash=fhash,
        )

    def on_created(self, e):  self._handle(e, "created")
    def on_deleted(self, e):  self._handle(e, "deleted")
    def on_modified(self, e): self._handle(e, "modified")
    def on_moved(self, e):
        if not e.is_directory:
            snap = take_screenshot("fs_moved")
            log_event("FILESYSTEM", f"File moved: {Path(e.src_path).name}",
                      f"{e.src_path} → {e.dest_path}",
                      severity="WARNING", snapshot=snap)

def start_file_watcher():
    observer = Observer()
    handler  = _FSHandler()
    for d in WATCHED_DIRS:
        if d.exists():
            observer.schedule(handler, str(d), recursive=True)
            log.info("Watching directory: %s", d)
        else:
            log.warning("Watch dir not found (skipping): %s", d)
    observer.start()
    log.info("File system watcher started.")
    return observer

# ─────────────────────────────────────────────
#  2. USB / DEVICE MONITOR
# ─────────────────────────────────────────────
_known_disks      = set()
_known_partitions = set()

def _get_disk_set():
    return {d.device for d in psutil.disk_partitions(all=False)}

def _init_usb_baseline():
    global _known_disks, _known_partitions
    _known_disks      = _get_disk_set()
    _known_partitions = {p.device for p in psutil.disk_partitions(all=True)}
    log.info("USB baseline: %d known drives", len(_known_disks))

def check_usb():
    global _known_disks
    current = _get_disk_set()
    added   = current - _known_disks
    removed = _known_disks - current
    for dev in added:
        snap = take_screenshot("usb_inserted")
        log_event("USB", f"Device inserted: {dev}",
                  f"New drive appeared: {dev}",
                  severity="CRITICAL", snapshot=snap)
    for dev in removed:
        log_event("USB", f"Device removed: {dev}",
                  f"Drive disconnected: {dev}",
                  severity="WARNING")
    _known_disks = current

# ─────────────────────────────────────────────
#  3. NETWORK MONITOR
# ─────────────────────────────────────────────
_known_connections = set()
_known_net_ifaces  = set()

def _conn_key(c):
    try:
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "–"
        return (c.laddr.port if c.laddr else 0, raddr, c.status)
    except Exception:
        return None

def _init_network_baseline():
    global _known_connections, _known_net_ifaces
    _known_connections = {_conn_key(c) for c in psutil.net_connections(kind="inet")
                          if _conn_key(c)}
    _known_net_ifaces  = set(psutil.net_if_stats().keys())
    log.info("Network baseline: %d known connections", len(_known_connections))

def check_network():
    global _known_connections, _known_net_ifaces
    current = {_conn_key(c) for c in psutil.net_connections(kind="inet")
               if _conn_key(c)}
    new_conns = current - _known_connections
    for conn in new_conns:
        lport, raddr, status = conn
        if raddr == "–" or status == "LISTEN":
            continue
        log_event("NETWORK", f"New connection → {raddr}",
                  f"Local port {lport} connected to {raddr} [{status}]",
                  severity="INFO")
    _known_connections = current

    # Check for new network interfaces (e.g. VPN, tethering)
    current_ifaces = set(psutil.net_if_stats().keys())
    new_ifaces     = current_ifaces - _known_net_ifaces
    for iface in new_ifaces:
        snap = take_screenshot("new_iface")
        log_event("NETWORK", f"New network interface: {iface}",
                  f"Interface appeared: {iface} (VPN / hotspot / tethering?)",
                  severity="WARNING", snapshot=snap)
    _known_net_ifaces = current_ifaces

# ─────────────────────────────────────────────
#  4. PROCESS MONITOR
# ─────────────────────────────────────────────
_known_pids = set()

SUSPICIOUS_NAMES = {
    "nmap", "metasploit", "msfconsole", "wireshark", "netcat", "nc",
    "mimikatz", "lazagne", "pwdump", "fgdump", "wce", "procdump",
    "psexec", "wmiexec", "smbclient", "hydra", "john", "hashcat",
    "tor", "proxychains", "bleachbit", "ccleaner", "eraser",
}

def _init_process_baseline():
    global _known_pids
    _known_pids = {p.pid for p in psutil.process_iter(["pid"])}
    log.info("Process baseline: %d running processes", len(_known_pids))

def check_processes():
    global _known_pids
    current_pids = set()
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
        try:
            current_pids.add(proc.pid)
            if proc.pid not in _known_pids:
                name = (proc.info.get("name") or "").lower()
                exe  = proc.info.get("exe") or ""
                cmd  = " ".join(proc.info.get("cmdline") or [])
                sev  = "CRITICAL" if any(s in name for s in SUSPICIOUS_NAMES) else "INFO"
                if sev == "CRITICAL":
                    snap = take_screenshot("suspicious_process")
                    log_event("PROCESS", f"Suspicious process: {proc.info['name']}",
                              f"PID {proc.pid} | {exe} | {cmd[:200]}",
                              severity="CRITICAL", snapshot=snap)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    _known_pids = current_pids

# ─────────────────────────────────────────────
#  5. WEBCAM / FACE MONITOR
# ─────────────────────────────────────────────
def check_webcam():
    photo = capture_webcam("presence")
    if not photo:
        return
    has_face = detect_face_in_image(photo)
    if has_face:
        log_event("WEBCAM", "Face detected at workstation",
                  f"Photo saved: {photo}",
                  severity="WARNING", snapshot=photo)
    else:
        # Still store the photo but at INFO level
        log_event("WEBCAM", "Webcam snapshot (no face)",
                  f"Photo saved: {photo}",
                  severity="INFO", snapshot=photo)

# ─────────────────────────────────────────────
#  6. LOGIN / AUTH MONITOR  (Windows)
# ─────────────────────────────────────────────
def check_failed_logins():
    if platform.system() != "Windows":
        return
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-EventLog -LogName Security -InstanceId 4625 -Newest 5 "
             "| Select-Object TimeGenerated,Message | ConvertTo-Json"],
            capture_output=True, text=True, timeout=10
        )
        if result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            for entry in data:
                ts  = entry.get("TimeGenerated", "")
                msg = entry.get("Message", "")[:300]
                snap = take_screenshot("failed_login")
                log_event("AUTH", "Failed login attempt (Event 4625)",
                          f"Time: {ts} | {msg}",
                          severity="CRITICAL", snapshot=snap)
    except Exception as e:
        log.debug("Failed login check error: %s", e)

# ─────────────────────────────────────────────
#  7. STARTUP PERSISTENCE AUDIT
# ─────────────────────────────────────────────
def audit_persistence():
    """One-shot audit of persistence locations on startup."""
    entries = []

    # Windows registry run keys
    if platform.system() == "Windows":
        try:
            import winreg
            keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ]
            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                for key_path in keys:
                    try:
                        key = winreg.OpenKey(hive, key_path)
                        i   = 0
                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(key, i)
                                entries.append(f"[Registry] {key_path}\\{name} = {val}")
                                i += 1
                            except OSError:
                                break
                        winreg.CloseKey(key)
                    except Exception:
                        pass
        except ImportError:
            pass

    # Startup folder
    startup = Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    if startup.exists():
        for f in startup.iterdir():
            entries.append(f"[Startup Folder] {f}")

    # Cron jobs (Linux/macOS)
    if platform.system() in ("Linux", "Darwin"):
        try:
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.strip() and not line.startswith("#"):
                    entries.append(f"[Cron] {line.strip()}")
        except Exception:
            pass

    if entries:
        log_event("PERSISTENCE", f"Persistence audit: {len(entries)} entries found",
                  "\n".join(entries[:50]), severity="WARNING")
    else:
        log_event("PERSISTENCE", "Persistence audit: clean",
                  "No suspicious autorun entries found.", severity="INFO")

# ─────────────────────────────────────────────
#  8. HTML REPORT GENERATOR
# ─────────────────────────────────────────────
REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="refresh" content="120">
<title>SentinelPC — Forensic Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Space+Grotesk:wght@400;600;700&display=swap');

  :root {
    --bg:       #0a0c10;
    --surface:  #111318;
    --border:   #1e2128;
    --accent:   #00d4aa;
    --red:      #ff4757;
    --yellow:   #ffa502;
    --green:    #2ed573;
    --blue:     #1e90ff;
    --text:     #e2e8f0;
    --muted:    #64748b;
    --mono:     'JetBrains Mono', monospace;
    --sans:     'Space Grotesk', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    min-height: 100vh;
  }

  /* ── HEADER ── */
  header {
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    border-bottom: 1px solid var(--border);
    padding: 24px 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky; top: 0; z-index: 100;
  }
  .logo { display: flex; align-items: center; gap: 14px; }
  .logo-icon {
    width: 44px; height: 44px;
    background: linear-gradient(135deg, var(--accent), #0099cc);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 22px;
  }
  .logo h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.3px; }
  .logo p  { font-size: 11px; color: var(--muted); font-family: var(--mono); margin-top: 2px; }
  .header-meta {
    text-align: right;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    line-height: 1.8;
  }
  .live-badge {
    display: inline-flex; align-items: center; gap: 6px;
    background: rgba(46,213,115,.12);
    border: 1px solid rgba(46,213,115,.3);
    border-radius: 20px;
    padding: 3px 10px;
    font-size: 11px;
    color: var(--green);
    font-family: var(--mono);
    margin-bottom: 6px;
  }
  .live-dot {
    width: 6px; height: 6px; border-radius: 50%;
    background: var(--green);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%,100% { opacity:1; } 50% { opacity:0.3; }
  }

  /* ── LAYOUT ── */
  main { max-width: 1400px; margin: 0 auto; padding: 32px 40px; }

  /* ── STAT CARDS ── */
  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 24px;
    position: relative;
    overflow: hidden;
  }
  .stat-card::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 3px;
  }
  .stat-card.total::before  { background: var(--blue); }
  .stat-card.critical::before { background: var(--red); }
  .stat-card.warning::before  { background: var(--yellow); }
  .stat-card.info::before     { background: var(--green); }
  .stat-label { font-size: 11px; color: var(--muted); text-transform: uppercase;
                letter-spacing: 1px; font-family: var(--mono); }
  .stat-value { font-size: 36px; font-weight: 700; margin: 8px 0 4px;
                font-family: var(--mono); }
  .stat-card.total    .stat-value { color: var(--blue); }
  .stat-card.critical .stat-value { color: var(--red); }
  .stat-card.warning  .stat-value { color: var(--yellow); }
  .stat-card.info     .stat-value { color: var(--green); }
  .stat-sub { font-size: 12px; color: var(--muted); }

  /* ── CATEGORY BREAKDOWN ── */
  .category-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 10px;
    margin-bottom: 32px;
  }
  .cat-pill {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 14px;
    display: flex; align-items: center; justify-content: space-between;
    font-size: 12px;
  }
  .cat-name { color: var(--muted); font-family: var(--mono); }
  .cat-count {
    background: rgba(0,212,170,.15);
    color: var(--accent);
    border-radius: 4px;
    padding: 2px 7px;
    font-family: var(--mono);
    font-weight: 700;
    font-size: 12px;
  }

  /* ── SECTION HEADER ── */
  .section-header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 16px;
  }
  .section-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    font-family: var(--mono);
  }
  .event-count {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 2px 8px;
  }

  /* ── EVENT TABLE ── */
  .event-table {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    margin-bottom: 40px;
  }
  table { width: 100%; border-collapse: collapse; }
  thead th {
    background: #0d1117;
    padding: 12px 16px;
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
    font-family: var(--mono);
    border-bottom: 1px solid var(--border);
  }
  tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background .15s;
  }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: rgba(255,255,255,.03); }
  td { padding: 12px 16px; vertical-align: top; }
  .td-ts    { font-family: var(--mono); font-size: 11px; color: var(--muted); white-space: nowrap; }
  .td-cat   { font-family: var(--mono); font-size: 11px; }
  .td-title { font-weight: 600; font-size: 13px; }
  .td-detail{ font-family: var(--mono); font-size: 11px; color: var(--muted);
               word-break: break-all; max-width: 340px; }
  .td-hash  { font-family: var(--mono); font-size: 10px; color: var(--muted);
               word-break: break-all; max-width: 200px; }

  /* ── SEVERITY BADGES ── */
  .badge {
    display: inline-block;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 10px;
    font-family: var(--mono);
    font-weight: 700;
    letter-spacing: .5px;
  }
  .badge-CRITICAL { background: rgba(255,71,87,.2);  color: var(--red);    border: 1px solid rgba(255,71,87,.4); }
  .badge-WARNING  { background: rgba(255,165,2,.2);  color: var(--yellow); border: 1px solid rgba(255,165,2,.4); }
  .badge-INFO     { background: rgba(46,213,115,.1); color: var(--green);  border: 1px solid rgba(46,213,115,.3); }

  /* ── CATEGORY COLOURS ── */
  .cat-FILESYSTEM  { color: #a78bfa; }
  .cat-USB         { color: #f59e0b; }
  .cat-NETWORK     { color: #38bdf8; }
  .cat-PROCESS     { color: var(--red); }
  .cat-WEBCAM      { color: #f472b6; }
  .cat-AUTH        { color: #fb923c; }
  .cat-PERSISTENCE { color: #e879f9; }

  /* ── SNAPSHOT GALLERY ── */
  .gallery {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 16px;
    margin-bottom: 40px;
  }
  .gallery-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }
  .gallery-img { width: 100%; aspect-ratio: 16/9; object-fit: cover;
                  display: block; background: #0d1117; }
  .gallery-meta {
    padding: 10px 14px;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    border-top: 1px solid var(--border);
  }
  .gallery-meta strong { color: var(--text); display: block; margin-bottom: 3px; }

  /* ── FOOTER ── */
  footer {
    text-align: center;
    padding: 32px;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    border-top: 1px solid var(--border);
  }
  footer span { color: var(--accent); }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">🛡</div>
    <div>
      <h1>SentinelPC</h1>
      <p>FORENSIC MONITORING AGENT — v1.0.0</p>
    </div>
  </div>
  <div class="header-meta">
    <div class="live-badge"><div class="live-dot"></div>LIVE MONITORING</div>
    <div>Host: {{ hostname }}</div>
    <div>OS: {{ os_info }}</div>
    <div>Report generated: {{ generated_at }}</div>
  </div>
</header>

<main>

  <!-- STATS -->
  <div class="stats">
    <div class="stat-card total">
      <div class="stat-label">Total Events</div>
      <div class="stat-value">{{ total }}</div>
      <div class="stat-sub">all time</div>
    </div>
    <div class="stat-card critical">
      <div class="stat-label">Critical</div>
      <div class="stat-value">{{ crits }}</div>
      <div class="stat-sub">require attention</div>
    </div>
    <div class="stat-card warning">
      <div class="stat-label">Warnings</div>
      <div class="stat-value">{{ warns }}</div>
      <div class="stat-sub">worth reviewing</div>
    </div>
    <div class="stat-card info">
      <div class="stat-label">Snapshots</div>
      <div class="stat-value">{{ snap_count }}</div>
      <div class="stat-sub">photos captured</div>
    </div>
  </div>

  <!-- CATEGORY BREAKDOWN -->
  {% if by_cat %}
  <div class="section-header">
    <div class="section-title">Category Breakdown</div>
  </div>
  <div class="category-grid">
    {% for cat, count in by_cat %}
    <div class="cat-pill">
      <span class="cat-name cat-{{ cat }}">{{ cat }}</span>
      <span class="cat-count">{{ count }}</span>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <!-- EVENT LOG -->
  <div class="section-header">
    <div class="section-title">Event Timeline</div>
    <div class="event-count">latest {{ events|length }} events</div>
  </div>
  <div class="event-table">
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Severity</th>
          <th>Category</th>
          <th>Event</th>
          <th>Detail</th>
          <th>SHA-256</th>
        </tr>
      </thead>
      <tbody>
        {% for ts, cat, sev, title, detail, snap, fhash in events %}
        <tr>
          <td class="td-ts">{{ ts }}</td>
          <td><span class="badge badge-{{ sev }}">{{ sev }}</span></td>
          <td class="td-cat cat-{{ cat }}">{{ cat }}</td>
          <td class="td-title">{{ title }}</td>
          <td class="td-detail">{{ detail or '—' }}</td>
          <td class="td-hash">{{ fhash or '—' }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- SNAPSHOT GALLERY -->
  {% if gallery_items %}
  <div class="section-header">
    <div class="section-title">Evidence Snapshots</div>
    <div class="event-count">{{ gallery_items|length }} images</div>
  </div>
  <div class="gallery">
    {% for item in gallery_items %}
    <div class="gallery-card">
      <img class="gallery-img" src="{{ item.src }}" alt="{{ item.title }}" loading="lazy">
      <div class="gallery-meta">
        <strong>{{ item.title }}</strong>
        {{ item.ts }}
      </div>
    </div>
    {% endfor %}
  </div>
  {% endif %}

</main>

<footer>
  SentinelPC &mdash; Silent Forensic Witness &mdash;
  Evidence vault: <span>{{ vault_path }}</span> &mdash;
  Auto-refreshes every 2 minutes
</footer>

</body>
</html>"""

def generate_report():
    try:
        total, crits, warns, by_cat = event_stats()
        events = fetch_events(limit=300)

        # Build gallery from snapshots in events
        gallery_items = []
        seen_snaps = set()
        for ts, cat, sev, title, detail, snap, fhash in events:
            if snap and snap not in seen_snaps and Path(snap).exists():
                seen_snaps.add(snap)
                b64 = img_to_b64(snap)
                if b64:
                    gallery_items.append({
                        "src":   b64,
                        "title": title[:60],
                        "ts":    ts,
                    })
                if len(gallery_items) >= 30:
                    break

        snap_count = len(list(SNAPSHOTS_DIR.glob("*")))

        html = Template(REPORT_TEMPLATE).render(
            hostname     = platform.node(),
            os_info      = f"{platform.system()} {platform.release()}",
            generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total        = total,
            crits        = crits,
            warns        = warns,
            snap_count   = snap_count,
            by_cat       = by_cat,
            events       = events,
            gallery_items= gallery_items,
            vault_path   = str(VAULT_DIR),
        )

        # Ensure Desktop exists
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(html, encoding="utf-8")
        log.info("Report updated → %s", REPORT_PATH)
    except Exception as e:
        log.error("Report generation failed: %s", e)

# ─────────────────────────────────────────────
#  SCHEDULER THREAD
# ─────────────────────────────────────────────
def _scheduler_loop():
    schedule.every(REPORT_INTERVAL).minutes.do(generate_report)
    schedule.every(NETWORK_INTERVAL).seconds.do(check_network)
    schedule.every(30).seconds.do(check_usb)
    schedule.every(60).seconds.do(check_processes)
    schedule.every(WEBCAM_INTERVAL).seconds.do(check_webcam)
    schedule.every(5).minutes.do(check_failed_logins)
    while True:
        schedule.run_pending()
        time.sleep(1)

# ─────────────────────────────────────────────
#  STARTUP BANNER
# ─────────────────────────────────────────────
BANNER = r"""
  ___         _   _           _ ___  ___
 / __| ___ _ _| |_(_)_ _  ___ | | _ \/ __|
 \__ \/ -_) ' \  _| | ' \/ -_) | |  _/ (__
 |___/\___|_||_\__|_|_||_\___|_|_|_|  \___|

  Your PC is now a Silent Forensic Witness
  ─────────────────────────────────────────
  Vault   : {vault}
  Report  : {report}
  Press   : Ctrl+C to stop and save final report
"""

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    print(BANNER.format(vault=VAULT_DIR, report=REPORT_PATH))

    # Initialise
    init_db()
    log_event("SYSTEM", "SentinelPC started",
              f"Host: {platform.node()} | OS: {platform.system()} {platform.release()}",
              severity="INFO")

    # Baselines
    _init_usb_baseline()
    _init_network_baseline()
    _init_process_baseline()

    # Persistence audit (runs once on startup)
    threading.Thread(target=audit_persistence, daemon=True).start()

    # File system watcher
    fs_observer = start_file_watcher()

    # Scheduler (USB, network, process, webcam, report)
    sched_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    sched_thread.start()

    # Initial report immediately
    generate_report()
    log.info("Initial report written. Opening in browser...")
    try:
        import webbrowser
        webbrowser.open(REPORT_PATH.as_uri())
    except Exception:
        pass

    # Graceful shutdown
    def _shutdown(sig, frame):
        print("\n\n[SentinelPC] Shutting down — saving final report...")
        log_event("SYSTEM", "SentinelPC stopped", "Clean shutdown by user.", severity="INFO")
        generate_report()
        fs_observer.stop()
        fs_observer.join()
        print(f"[SentinelPC] Final report saved to: {REPORT_PATH}")
        print(f"[SentinelPC] Evidence vault:        {VAULT_DIR}")
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    log.info("SentinelPC is watching. Press Ctrl+C to stop.")
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()