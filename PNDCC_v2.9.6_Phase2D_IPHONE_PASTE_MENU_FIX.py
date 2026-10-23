#!/usr/bin/env python3
"""
PNDCC v2.0
Personal Network & Device Command Center

Author: Saiful Quadir
Updated: 2026-10-07
Version: 2.6.1 Fine-Tuned Build
Copyright: © Saiful Quadir

Design rule: Simple is the best.

This version is built from the frozen PNDCC v1.7 baseline and
carries forward the safer v1.3 dashboard improvements without using
HTML .format() substitution for the full page. It also adds:
- stable dashboard rendering
- device history view
- latency / packet-loss history charts (CSS/SVG-free, simple HTML tables)
- actual FTP/FTPS service handshake monitoring
- optional FTP/FTPS login using environment variables or macOS Keychain
- persistent CSV history logging
- live iCloud account storage status from macOS System Settings
- /health, /history, /api/status and /api/history endpoints
- safer HTML escaping
- no external Python packages
"""

import csv
import base64
import html
import ipaddress
import json
import mimetypes
import tempfile
import io
import zipfile
import os
import platform
import re
import socket
import ssl
import subprocess
import time
import urllib.parse
from threading import Lock, Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from ftplib import FTP, FTP_TLS


class PNDCC_FTP_TLS(FTP_TLS):
    """FTPS client with explicit TLS session reuse for FileZilla Server.

    FileZilla Server can require the protected data connection to reuse the
    TLS session created on the control connection. Python ftplib normally
    creates the data TLS socket without passing that session, which can
    produce a 425 response after a successful login.
    """

    def ntransfercmd(self, cmd, rest=None):
        conn, size = super(FTP_TLS, self).ntransfercmd(cmd, rest)
        if self._prot_p:
            session = None
            try:
                session = self.sock.session
            except Exception:
                session = None
            kwargs = {"server_hostname": self.host}
            if session is not None:
                kwargs["session"] = session
            conn = self.context.wrap_socket(conn, **kwargs)
        return conn, size
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------
APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(APP_DIR)
# Prefer the normal PNDCC project config, but also accept config placed beside
# this Phase 2D file. This prevents a standalone download from refusing to run.
if os.path.isdir(os.path.join(PROJECT_DIR, "config")):
    BASE = PROJECT_DIR
elif os.path.isdir(os.path.join(APP_DIR, "config")):
    BASE = APP_DIR
else:
    BASE = PROJECT_DIR

CONFIG_CANDIDATES = [
    (os.path.join(BASE, "config", "devices.json"), os.path.join(BASE, "config", "settings.json")),
    (os.path.join(APP_DIR, "config", "devices.json"), os.path.join(APP_DIR, "config", "settings.json")),
]

DEVICE_CONFIG = SETTINGS_CONFIG = None
for _dc, _sc in CONFIG_CANDIDATES:
    if os.path.exists(_dc) and os.path.exists(_sc):
        DEVICE_CONFIG, SETTINGS_CONFIG = _dc, _sc
        break

if DEVICE_CONFIG and SETTINGS_CONFIG:
    with open(DEVICE_CONFIG, encoding="utf-8") as f:
        CFG = json.load(f)
    with open(SETTINGS_CONFIG, encoding="utf-8") as f:
        SET = json.load(f)
else:
    # Safe standalone defaults. Existing project config always wins when present.
    CFG = {"devices": [
        {"name":"MacBook Pro","ip":"192.168.2.205"},
        {"name":"Windows Laptop","ip":"192.168.2.162"},
        {"name":"iPad","ip":"192.168.2.161"},
        {"name":"iPhone","ip":"192.168.2.62"},
        {"name":"Android Tablet","ip":"192.168.2.208"},
        {"name":"OnePlus Nord CE 3 Lite 5G","ip":"192.168.2.19"}
    ]}
    SET = {"server":{"host":"127.0.0.1","port":8787},"history":{"csv_file":"data/history.csv"}}

HOST = SET.get("server", {}).get("host", "127.0.0.1")
HIST = os.path.join(BASE, SET.get("history", {}).get("csv_file", "data/history.csv"))

# New PNDCC history file. If the configured history path is relative, it is
# resolved under the project directory as in v1.2/v1.3.
DEVICE_HIST = HIST
FTP_HIST = os.path.join(os.path.dirname(HIST), "ftp_history.csv")
ALERT_HIST = os.path.join(os.path.dirname(HIST), "alerts_history.csv")
os.makedirs(os.path.dirname(HIST), exist_ok=True)

FIELDS = [
    "timestamp",
    "target_id",
    "name",
    "ip",
    "status",
    "latency_ms",
    "packet_loss_pct",
]

FTP_FIELDS = [
    "timestamp",
    "host",
    "port",
    "mode",
    "status",
    "latency_ms",
    "test",
]

ALERT_FIELDS = [
    "timestamp", "target_id", "name", "ip", "status", "latency_ms", "packet_loss_pct", "message"
]

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------
FTP_SETTINGS = SET.get("ftp", {}) if isinstance(SET.get("ftp", {}), dict) else {}
FTP_HOST = os.environ.get("PNDCC_FTP_HOST", str(FTP_SETTINGS.get("host", "")).strip()).strip()
try:
    FTP_PORT = int(os.environ.get("PNDCC_FTP_PORT", str(FTP_SETTINGS.get("port", 21))))
except ValueError:
    FTP_PORT = 21
FTP_MODE = os.environ.get("PNDCC_FTP_MODE", str(FTP_SETTINGS.get("mode", "ftp"))).strip().lower()
FTP_USER = os.environ.get("PNDCC_FTP_USER", str(FTP_SETTINGS.get("user", "")).strip()).strip()

def _ftp_password_from_keychain():
    """Read the FTP password for the configured user from macOS Keychain."""
    if platform.system() != "Darwin" or not FTP_USER:
        return ""
    try:
        # Match BOTH the Keychain service and the FileZilla account.
        # This avoids retrieving a password belonging to another FTP user.
        p = subprocess.run(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-a", FTP_USER,
                "-s", "PNDCC-FTP",
                "-w",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if p.returncode == 0:
            return (p.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def _ftp_login(client):
    """Log in using the configured FileZilla account and password."""
    if FTP_USER:
        if not FTP_PASSWORD:
            raise RuntimeError("FTP password not available from environment or Keychain")
        return client.login(FTP_USER, FTP_PASSWORD)
    return client.login()

# Password priority: environment variable first, then macOS Keychain.
# The password is never stored in this Python file.
FTP_PASSWORD = os.environ.get("PNDCC_FTP_PASSWORD", "") or _ftp_password_from_keychain()
try:
    FTP_TIMEOUT = float(os.environ.get("PNDCC_FTP_TIMEOUT", str(FTP_SETTINGS.get("timeout", 5))))
except ValueError:
    FTP_TIMEOUT = 5.0

# Supported values: ftp, ftps
if FTP_MODE not in {"ftp", "ftps"}:
    FTP_MODE = "ftp"


def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def esc(value):
    return html.escape(str(value if value is not None else ""))


def enabled_devices():
    return [
        d for d in CFG.get("devices", []) + CFG.get("infrastructure", [])
        if d.get("enabled")
    ]


def personal_devices():
    return [d for d in CFG.get("devices", []) if d.get("enabled")]

# ---------------------------------------------------------------------------
# Network monitoring
# ---------------------------------------------------------------------------

def ping(ip):
    c = str(SET.get("monitoring", {}).get("ping_count", 2))
    timeout_seconds = float(SET.get("monitoring", {}).get("ping_timeout_seconds", 1))
    t = max(1, int(timeout_seconds * 1000))

    if platform.system() != "Windows":
        cmd = ["ping", "-c", c, "-W", str(t), str(ip)]
    else:
        cmd = ["ping", "-n", c, "-w", str(t), str(ip)]

    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(10, int(timeout_seconds * 10)),
        )
        out = p.stdout + p.stderr

        m = (
            re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", out)
            or re.search(r"(\d+(?:\.\d+)?)%\s*loss", out)
        )
        loss = float(m.group(1)) if m else (0.0 if p.returncode == 0 else 100.0)

        vals = [
            float(x)
            for x in re.findall(r"time[=<] ?(\d+(?:\.\d+)?)\s*ms", out)
        ]
        latency = sum(vals) / len(vals) if vals else None
        return p.returncode == 0, latency, loss
    except Exception:
        return False, None, 100.0


def status(ok, lat, loss):
    thresholds = SET.get("thresholds", {})
    critical_loss = float(thresholds.get("critical_packet_loss_pct", 50))
    critical_latency = float(thresholds.get("critical_latency_ms", 250))
    warning_loss = float(thresholds.get("warning_packet_loss_pct", 10))
    warning_latency = float(thresholds.get("warning_latency_ms", 100))

    if not ok and loss >= 100:
        return "OFFLINE"
    if loss >= critical_loss or (lat is not None and lat >= critical_latency):
        return "CRITICAL"
    if loss >= warning_loss or (lat is not None and lat >= warning_latency):
        return "WARNING"
    return "ONLINE"


def check_all():
    rows = []
    stamp = now()

    for d in enabled_devices():
        ok, lat, loss = ping(d.get("ip", ""))
        rows.append({
            "timestamp": stamp,
            "target_id": d.get("id", "unknown"),
            "name": d.get("name", "Unnamed device"),
            "ip": d.get("ip", ""),
            "status": status(ok, lat, loss),
            "latency_ms": round(lat, 2) if lat is not None else "",
            "packet_loss_pct": round(loss, 2),
        })

    if rows:
        new = not os.path.exists(DEVICE_HIST)
        with open(DEVICE_HIST, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            if new:
                w.writeheader()
            w.writerows(rows)
    return rows


def latest():
    if not os.path.exists(DEVICE_HIST):
        return {}

    result = {}
    try:
        with open(DEVICE_HIST, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                target = row.get("target_id", "")
                if target:
                    result[target] = row
    except (OSError, csv.Error):
        return {}
    return result

# ---------------------------------------------------------------------------
# FTP / FTPS monitoring
# ---------------------------------------------------------------------------

def ftp_check():
    """Perform an actual FTP/FTPS service handshake.

    No credentials are required for the basic service test. If
    PNDCC_FTP_USER is set, login is attempted. For FTPS, AUTH TLS is
    negotiated before optional login and a protected data channel is used
    when the server accepts it.
    """
    if not FTP_HOST:
        return {
            "status": "NOT CONFIGURED",
            "latency_ms": "—",
            "test": "Set PNDCC_FTP_HOST",
            "mode": FTP_MODE.upper(),
        }

    started = time.perf_counter()
    client = None
    try:
        if FTP_MODE == "ftps":
            # Use the already-proven Phase 2D FileZilla FTPS client path.
            # FileZilla uses a self-signed LAN certificate, so monitoring
            # accepts that local certificate without changing Phase 2D.
            # Re-read Keychain credentials at monitor time so a running
            # background monitor never depends on an import-time password
            # lookup.
            monitor_tls_context = ssl._create_unverified_context()
            client = PNDCC_FTP_TLS(context=monitor_tls_context)
            client.connect(FTP_HOST, FTP_PORT, timeout=FTP_TIMEOUT)
            client.auth()
            password = os.environ.get("PNDCC_FTP_PASSWORD", "") or _ftp_password_from_keychain()
            if FTP_USER and not password:
                raise RuntimeError("FTP password not available from environment or Keychain")
            if FTP_USER:
                client.login(FTP_USER, password)
            else:
                client.login()
            client.prot_p()
        else:
            client = FTP()
            client.connect(FTP_HOST, FTP_PORT, timeout=FTP_TIMEOUT)
            if FTP_USER:
                _ftp_login(client)

        welcome = getattr(client, "welcome", "") or ""
        test = "FTP service handshake successful"

        if FTP_USER:
            test = "Service handshake + login successful"
        else:
            test = "Service handshake successful (login not configured)"

        if FTP_MODE == "ftps":
            # Verify the authenticated control channel without performing a
            # directory/data transfer. The proven Phase 2D data-channel
            # session-reuse logic remains available through PNDCC_FTP_TLS.
            client.pwd()
            test += "; TLS data protection enabled"

        latency = round((time.perf_counter() - started) * 1000, 2)
        return {
            "status": "ONLINE",
            "latency_ms": f"{latency} ms",
            "test": test,
            "mode": FTP_MODE.upper(),
            "welcome": welcome[:160],
        }
    except Exception as e:
        latency = round((time.perf_counter() - started) * 1000, 2)
        return {
            "status": "OFFLINE",
            "latency_ms": f"{latency} ms",
            "test": type(e).__name__,
            "mode": FTP_MODE.upper(),
        }
    finally:
        if client is not None:
            try:
                client.quit()
            except Exception:
                try:
                    client.close()
                except Exception:
                    pass


def log_ftp(result):
    if not FTP_HOST:
        return
    new = not os.path.exists(FTP_HIST)
    row = {
        "timestamp": now(),
        "host": FTP_HOST,
        "port": FTP_PORT,
        "mode": result.get("mode", FTP_MODE.upper()),
        "status": result.get("status", "UNKNOWN"),
        "latency_ms": result.get("latency_ms", ""),
        "test": result.get("test", ""),
    }
    try:
        with open(FTP_HIST, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FTP_FIELDS)
            if new:
                w.writeheader()
            w.writerow(row)
    except OSError:
        pass

# ---------------------------------------------------------------------------
# History helpers
# ---------------------------------------------------------------------------

def read_device_history(target_id=None, limit=30):
    rows = []
    if not os.path.exists(DEVICE_HIST):
        return rows
    try:
        with open(DEVICE_HIST, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if target_id and row.get("target_id") != target_id:
                    continue
                rows.append(row)
    except (OSError, csv.Error):
        return []
    return rows[-limit:]


def history_summary(target_id):
    rows = read_device_history(target_id, 200)
    if not rows:
        return {"samples": 0, "online": 0, "avg_latency": None, "avg_loss": None}

    online = sum(1 for r in rows if r.get("status") == "ONLINE")
    lats = []
    losses = []
    for r in rows:
        try:
            if r.get("latency_ms") not in (None, ""):
                lats.append(float(r["latency_ms"]))
        except ValueError:
            pass
        try:
            if r.get("packet_loss_pct") not in (None, ""):
                losses.append(float(r["packet_loss_pct"]))
        except ValueError:
            pass

    return {
        "samples": len(rows),
        "online": online,
        "avg_latency": round(sum(lats) / len(lats), 2) if lats else None,
        "avg_loss": round(sum(losses) / len(losses), 2) if losses else None,
    }


def log_alerts(results):
    """Persist actionable device events for later review."""
    events = [r for r in results if r.get("status") in {"WARNING", "CRITICAL", "OFFLINE"}]
    if not events:
        return
    new = not os.path.exists(ALERT_HIST)
    try:
        with open(ALERT_HIST, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=ALERT_FIELDS)
            if new:
                w.writeheader()
            for r in events:
                st = r.get("status", "UNKNOWN")
                lat = r.get("latency_ms", "")
                loss = r.get("packet_loss_pct", "")
                if st == "OFFLINE":
                    msg = "Device is offline or unreachable"
                elif st == "CRITICAL":
                    msg = "Critical latency or packet loss detected"
                else:
                    msg = "Elevated latency or packet loss detected"
                w.writerow({"timestamp": r.get("timestamp", now()), "target_id": r.get("target_id", ""),
                            "name": r.get("name", ""), "ip": r.get("ip", ""), "status": st,
                            "latency_ms": lat, "packet_loss_pct": loss, "message": msg})
    except OSError:
        pass


def recent_alerts(limit=40):
    if not os.path.exists(ALERT_HIST):
        return []
    try:
        with open(ALERT_HIST, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))[-limit:]
    except (OSError, csv.Error):
        return []


def health_summary(results):
    counts = {"ONLINE": 0, "WARNING": 0, "CRITICAL": 0, "OFFLINE": 0}
    for r in results:
        st = r.get("status")
        if st in counts:
            counts[st] += 1
    total = sum(counts.values())
    health = round((counts["ONLINE"] / total) * 100) if total else 0
    return {"counts": counts, "health_pct": health, "total": total}


def latency_chart(rows):
    points = []
    values = []
    for r in rows:
        try:
            v = float(r.get("latency_ms", ""))
            if v >= 0:
                values.append(v)
                points.append((r.get("timestamp", ""), v, r.get("status", "")))
        except (TypeError, ValueError):
            pass
    if not points:
        return "<div class='notice'>No latency data available yet.</div>"
    max_v = max(values) or 1.0
    bars = []
    for stamp, val, st in points[-24:]:
        width = max(2, min(100, (val / max_v) * 100))
        bars.append(f"<div class='chart-row'><span class='chart-time'>{esc(stamp[-8:])}</span><div class='chart-track'><span class='chart-bar {esc(st.replace(' ', '-'))}' style='width:{width:.1f}%'></span></div><span class='chart-value'>{val:.2f} ms</span></div>")
    return "<div class='chart'>" + "".join(bars) + "</div>"


def recent_ftp_history(limit=20):
    rows = []
    if not os.path.exists(FTP_HIST):
        return rows
    try:
        with open(FTP_HIST, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    except (OSError, csv.Error):
        return []
    return rows[-limit:]

# ---------------------------------------------------------------------------
# Storage and cloud monitoring — v1.7
# ---------------------------------------------------------------------------
# Simple rule: detect what is safely visible from the Mac. Do not copy cloud
# data locally and do not invent capacity/connection information.

STORAGE_CONFIG = SET.get("storage", {})
CLOUD_CONFIG = SET.get("cloud", {})
# Plan capacities are configuration defaults only; usage always comes from a
# live provider report. Values are decimal plan labels represented in GiB for
# consistent calculations, matching the existing byte conversion below.
CLOUD_PLAN_GB = {"icloud": 5.0, "google_drive": 15.0, "onedrive": 1024.0}
_ICLOUD_READ_DIAGNOSTIC = "Not checked"
# Store only the last successfully parsed iCloud quota and verification timestamp.
# No credentials, tokens, or file contents are stored. Expiry is 24 hours.
_ICLOUD_QUOTA_CACHE_PATH = os.path.join(APP_DIR, "pndcc_icloud_quota_cache.json")
_ICLOUD_QUOTA_CACHE_MAX_AGE_SECONDS = 24 * 60 * 60
_ICLOUD_QUOTA_CACHE_LOCK = Lock()
# Serialize all AppleScript accessibility reads. Dashboard rendering must not
# compete with the explicit Refresh iCloud request for System Events.
_ICLOUD_READ_LOCK = Lock()
CLOUD_PLAN_GB.update({
    str(k).lower(): float(v)
    for k, v in CLOUD_CONFIG.get("plan_gb", {}).items()
    if str(v).replace(".", "", 1).isdigit() and float(v) > 0
})


def _first_existing_path(paths):
    for path in paths:
        if path and os.path.exists(os.path.expanduser(path)):
            return os.path.expanduser(path)
    return ""


def local_storage_info(name, path):
    path = os.path.expanduser(path) if path else ""
    if not path or not os.path.exists(path):
        return {"name": name, "status": "NOT CONFIGURED", "path": path, "total_gb": None, "used_gb": None, "free_gb": None, "used_pct": None}
    try:
        total, used, free = __import__("shutil").disk_usage(path)
        return {"name": name, "status": "ONLINE", "path": path,
                "total_gb": round(total / 1024**3, 1),
                "used_gb": round(used / 1024**3, 1),
                "free_gb": round(free / 1024**3, 1),
                "used_pct": round((used / total) * 100, 1) if total else 0}
    except OSError:
        return {"name": name, "status": "ERROR", "path": path, "total_gb": None, "used_gb": None, "free_gb": None, "used_pct": None}




def windows_storage_status():
    """Read the read-only Windows storage report through FileZilla FTPS.

    The report is physically D:\\PNDCC\\storage_status.json and is
    exposed by FileZilla under /ADATA/PNDCC/storage_status.json.
    """
    if not FTP_HOST:
        return {}

    data = bytearray()
    client = None
    try:
        if FTP_MODE == "ftps":
            client = PNDCC_FTP_TLS()
            client.connect(FTP_HOST, FTP_PORT, timeout=FTP_TIMEOUT)
            client.auth()
            _ftp_login(client)
            client.prot_p()
        else:
            client = FTP()
            client.connect(FTP_HOST, FTP_PORT, timeout=FTP_TIMEOUT)
            _ftp_login(client)

        # FileZilla maps the Windows D: drive to /ADATA.
        remote_paths = (
            "ADATA/PNDCC/storage_status.json",
            "/ADATA/PNDCC/storage_status.json",
        )
        last_error = None
        for remote_path in remote_paths:
            try:
                data.clear()
                client.retrbinary(f"RETR {remote_path}", data.extend)
                break
            except Exception as e:
                last_error = e
        else:
            raise last_error

        payload = json.loads(bytes(data).decode("utf-8-sig"))
        if isinstance(payload, dict) and isinstance(payload.get("drives"), dict):
            return payload["drives"]
    except Exception:
        return {}
    finally:
        if client is not None:
            try:
                client.quit()
            except Exception:
                try:
                    client.close()
                except Exception:
                    pass
    return {}

def storage_items():
    home = os.path.expanduser("~")
    items = [local_storage_info("MacBook Pro", home)]

    remote = windows_storage_status()
    remote_map = {
        "windows": ("Windows Laptop", "C:"),
        "transcend": ("Transcend Backup #1", "F:"),
        "adata": ("ADATA Backup #2", "D:"),
    }

    for key, (label, drive) in remote_map.items():
        info = remote.get(key, {}) if isinstance(remote, dict) else {}
        if info.get("total_gb") is not None:
            items.append({
                "name": label,
                "status": "ONLINE",
                "path": drive,
                "total_gb": info.get("total_gb"),
                "used_gb": info.get("used_gb"),
                "free_gb": info.get("free_gb"),
                "used_pct": info.get("used_pct"),
                "detail": f"Windows drive {drive}",
            })
        else:
            windows_ip = next((d.get("ip") for d in CFG.get("devices", []) if d.get("id") == "windows_laptop"), "")
            windows_ok, _, _ = ping(windows_ip) if windows_ip else (False, None, 100.0)
            items.append({
                "name": label,
                "status": "HOST ONLINE" if windows_ok else "OFFLINE",
                "path": drive,
                "total_gb": None,
                "used_gb": None,
                "free_gb": None,
                "used_pct": None,
                "detail": "Windows reachable; storage report not available" if windows_ok else "Windows Laptop not reachable",
            })
    return items

def _quota_from_bytes(total_bytes, used_bytes=None, free_bytes=None):
    """Build verified quota metrics from provider-reported byte values."""
    try:
        total = float(total_bytes) if total_bytes is not None else None
    except (TypeError, ValueError):
        total = None
    try:
        used = float(used_bytes) if used_bytes is not None else None
    except (TypeError, ValueError):
        used = None
    try:
        free = float(free_bytes) if free_bytes is not None else None
    except (TypeError, ValueError):
        free = None

    if total is None:
        return None
    if free is not None and used is None:
        used = max(0.0, total - free)
    if used is not None and free is None:
        free = max(0.0, total - used)
    if used is None or free is None:
        return None

    return {
        "total_gb": round(total / 1024**3, 2),
        "used_gb": round(used / 1024**3, 2),
        "free_gb": round(free / 1024**3, 2),
        "used_pct": round((used / total) * 100, 1) if total else 0,
    }


def _read_icloud_system_settings_unlocked():
    # V5 uses value-only accessibility reads. Earlier trials queried five
    # attributes for every UI element and silently swallowed timeouts. The
    # original successful manual test used value-only reads.
    if platform.system() != "Darwin":
        return None

    script = r'''tell application "System Events"
    if exists process "System Settings" then
        set appName to "System Settings"
    else if exists process "System Preferences" then
        set appName to "System Preferences"
    else
        return "SETTINGS_PROCESS_NOT_FOUND"
    end if
    tell process appName
        set collected to ""
        repeat with w in windows
            try
                set collected to collected & linefeed & "WINDOW: " & (name of w as text)
            end try
            try
                set allElements to entire contents of w
                repeat with x in allElements
                    try
                        set t to value of x as text
                        if t is not "" then set collected to collected & linefeed & t
                    end try
                end repeat
            end try
        end repeat
        return collected
    end tell
end tell
'''

    def read_settings():
        try:
            p = subprocess.run(
                ["/usr/bin/osascript", "-e", script],
                capture_output=True,
                text=True,
                timeout=25,
            )
            return (p.stdout or "") + "\n" + (p.stderr or "")
        except subprocess.TimeoutExpired:
            return "ICLOUD_ACCESSIBILITY_READ_TIMEOUT"
        except OSError as exc:
            return "ICLOUD_ACCESSIBILITY_OSASCRIPT_ERROR: " + str(exc)
        except subprocess.SubprocessError as exc:
            return "ICLOUD_ACCESSIBILITY_SUBPROCESS_ERROR: " + str(exc)

    storage_pattern = re.compile(
        r"(?:iCloud\s+)?(?:Storage\s*(?:Full\s*:?\s*)?)?"
        r"([0-9]+(?:\.[0-9]+)?)\s*(GB|TB)\s+of\s+"
        r"([0-9]+(?:\.[0-9]+)?)\s*(GB|TB)(?:\s+Used)?",
        re.I,
    )
    compact_storage_pattern = re.compile(
        r"(?:iCloud\s+)?Storage\s*:?\s*"
        r"([0-9]+(?:\.[0-9]+)?)\s+of\s+"
        r"([0-9]+(?:\.[0-9]+)?)\s*(GB|TB)(?:\s+Used)?",
        re.I,
    )

    def has_storage_label(text):
        return bool(storage_pattern.search(text) or compact_storage_pattern.search(text))

    out = read_settings()
    if not has_storage_label(out):
        settings_urls = (
            "x-apple.systempreferences:com.apple.systempreferences.AppleIDSettings?iCloud",
            "x-apple.systempreferences:com.apple.AppleID-Settings.extension?iCloud",
        )
        for settings_url in settings_urls:
            try:
                subprocess.run(
                    ["/usr/bin/open", settings_url],
                    capture_output=True,
                    text=True,
                    timeout=8,
                )
            except (OSError, subprocess.SubprocessError):
                pass
            for _ in range(6):
                time.sleep(1.0)
                out = read_settings()
                if has_storage_label(out):
                    break
            if has_storage_label(out):
                break

    m = storage_pattern.search(out)
    compact_match = False
    if not m:
        m = compact_storage_pattern.search(out)
        compact_match = bool(m)
    if not m:
        global _ICLOUD_READ_DIAGNOSTIC
        window_match = re.search(r"WINDOW:\s*([^\r\n]+)", out, re.I)
        if "ICLOUD_ACCESSIBILITY_READ_TIMEOUT" in out:
            _ICLOUD_READ_DIAGNOSTIC = "AppleScript accessibility read timed out"
        elif "SETTINGS_PROCESS_NOT_FOUND" in out:
            _ICLOUD_READ_DIAGNOSTIC = "System Settings process not found"
        elif window_match:
            _ICLOUD_READ_DIAGNOSTIC = "No recognizable quota label; current window: " + window_match.group(1).strip()
        elif "ICLOUD_ACCESSIBILITY_OSASCRIPT_ERROR" in out:
            _ICLOUD_READ_DIAGNOSTIC = out.strip()[:180]
        else:
            _ICLOUD_READ_DIAGNOSTIC = "No iCloud storage text returned by System Events"
        return None

    if compact_match:
        used = float(m.group(1))
        total = float(m.group(2))
        used_unit = total_unit = m.group(3).upper()
    else:
        used = float(m.group(1))
        total = float(m.group(3))
        used_unit = m.group(2).upper()
        total_unit = m.group(4).upper()

    def to_gb(value, unit):
        return value * (1024.0 if unit == "TB" else 1.0)

    used_gb = to_gb(used, used_unit)
    total_gb = to_gb(total, total_unit)
    if total_gb <= 0 or used_gb < 0 or used_gb > total_gb:
        _ICLOUD_READ_DIAGNOSTIC = "Parsed quota values failed sanity checks"
        return None

    free_gb = max(0.0, total_gb - used_gb)
    pct = min(100.0, max(0.0, (used_gb / total_gb) * 100.0))
    saving_paused = bool(re.search(r"Saving\s+is\s+Paused|Saving\s+Paused", out, re.I))
    sync_limited = bool(re.search(
        r"Some\s+photos\s+aren['’]t\s+syncing|backups\s+are\s+paused|sync\s+limited",
        out,
        re.I,
    ))
    drive_gb = None
    drive_match = re.search(r"(?:^|\n)Drive\s+([0-9]+(?:\.[0-9]+)?)\s*(GB|TB)", out, re.I)
    if drive_match:
        drive_gb = to_gb(float(drive_match.group(1)), drive_match.group(2).upper())

    _ICLOUD_READ_DIAGNOSTIC = "Live iCloud storage label parsed successfully"
    return {
        "total_gb": round(total_gb, 2),
        "used_gb": round(used_gb, 2),
        "free_gb": round(free_gb, 2),
        "used_pct": round(pct, 1),
        "storage_full": free_gb <= 0.001,
        "saving_paused": saving_paused,
        "sync_limited": sync_limited,
        "drive_gb": round(drive_gb, 2) if drive_gb is not None else None,
        "source": "Live macOS System Settings · Apple Account > iCloud",
    }


def _read_icloud_system_settings():
    """Run one serialized iCloud accessibility read for an explicit refresh.

    Multiple page renders and browser tabs must not launch competing AppleScript
    traversals of System Settings. If another read is already active, fail fast
    with a useful diagnostic and allow the caller to show the verified cache.
    """
    global _ICLOUD_READ_DIAGNOSTIC
    if not _ICLOUD_READ_LOCK.acquire(blocking=False):
        _ICLOUD_READ_DIAGNOSTIC = (
            "Another iCloud accessibility read is already in progress; wait a moment and retry"
        )
        return None
    try:
        return _read_icloud_system_settings_unlocked()
    finally:
        _ICLOUD_READ_LOCK.release()


def _write_icloud_quota_cache(quota):
    """Persist only a successfully parsed live quota with an explicit timestamp."""
    if not isinstance(quota, dict):
        return False
    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
    record = {"verified_at": stamp, "quota": dict(quota)}
    try:
        with _ICLOUD_QUOTA_CACHE_LOCK:
            temp_path = _ICLOUD_QUOTA_CACHE_PATH + ".tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False)
                f.write("\n")
            try:
                os.chmod(temp_path, 0o600)
            except OSError:
                pass
            os.replace(temp_path, _ICLOUD_QUOTA_CACHE_PATH)
        quota["verified_at"] = stamp
        return True
    except (OSError, TypeError, ValueError):
        return False


def _read_icloud_quota_cache():
    """Read a recent, timestamped successful quota; never resurrect old hardcoded data."""
    global _ICLOUD_READ_DIAGNOSTIC
    try:
        with _ICLOUD_QUOTA_CACHE_LOCK:
            with open(_ICLOUD_QUOTA_CACHE_PATH, "r", encoding="utf-8") as f:
                record = json.load(f)
        stamp = str(record.get("verified_at", ""))
        verified_at = datetime.fromisoformat(stamp)
        now = datetime.now(verified_at.tzinfo) if verified_at.tzinfo else datetime.now()
        age = (now - verified_at).total_seconds()
        if age < 0 or age > _ICLOUD_QUOTA_CACHE_MAX_AGE_SECONDS:
            _ICLOUD_READ_DIAGNOSTIC = "No fresh verified iCloud quota cache (older than 24 hours)"
            return None
        quota = record.get("quota")
        if not isinstance(quota, dict):
            return None
        used = float(quota["used_gb"])
        total = float(quota["total_gb"])
        free = float(quota["free_gb"])
        if total <= 0 or used < 0 or free < 0 or abs((used + free) - total) > max(0.05, total * 0.02):
            return None
        result = dict(quota)
        result.update({
            "used_gb": round(used, 2),
            "total_gb": round(total, 2),
            "free_gb": round(free, 2),
            "used_pct": round(float(quota.get("used_pct", used / total * 100)), 1),
            "verified_at": stamp,
            "snapshot": True,
            "source": "Last verified macOS System Settings · Apple Account > iCloud",
        })
        try:
            local_stamp = verified_at.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        except Exception:
            local_stamp = stamp
        _ICLOUD_READ_DIAGNOSTIC = "Using last verified iCloud quota from " + local_stamp
        return result
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def _icloud_quota():
    """Read the verified cache for page rendering; live UI reads are button-driven.

    System Events is a macOS UI-automation surface, not a cloud API. Running a
    full accessibility traversal on every dashboard render can race with the
    Refresh iCloud endpoint and produce intermittent empty reads. Dashboard GETs
    therefore use the latest verified cache only; the explicit POST refresh is
    the sole routine that performs a new live accessibility read.
    """
    global _ICLOUD_READ_DIAGNOSTIC
    cached = _read_icloud_quota_cache()
    if cached:
        return cached
    _ICLOUD_READ_DIAGNOSTIC = (
        "No recent verified iCloud quota cache; click Refresh iCloud to obtain a live reading"
    )
    return None


def _rclone_path():
    return os.environ.get("PNDCC_RCLONE_BIN", "rclone").strip() or "rclone"


def _rclone_remotes():
    """Return configured rclone remote names, without exposing credentials."""
    try:
        p = subprocess.run(
            [_rclone_path(), "listremotes"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if p.returncode != 0:
            return []
        return [x.strip().rstrip(":") for x in (p.stdout or "").splitlines() if x.strip()]
    except (OSError, subprocess.SubprocessError):
        return []


def _find_rclone_remote(provider):
    configured = CLOUD_CONFIG.get("rclone_remotes", {})
    explicit = str(configured.get(provider, "")).strip().rstrip(":")
    remotes = _rclone_remotes()
    if explicit and explicit in remotes:
        return explicit
    low = [(r, r.lower()) for r in remotes]
    if provider == "google_drive":
        matches = [r for r, x in low if "google" in x or "drive" in x]
    elif provider == "onedrive":
        matches = [r for r, x in low if "onedrive" in x or "one_drive" in x or x == "one"]
    else:
        matches = []
    return matches[0] if len(matches) == 1 else ""


def _rclone_quota(remote):
    if not remote:
        return None
    try:
        p = subprocess.run(
            [_rclone_path(), "about", f"{remote}:", "--json"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if p.returncode != 0:
            return None
        data = json.loads(p.stdout or "{}")
        return _quota_from_bytes(data.get("total"), data.get("used"), data.get("free"))
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError):
        return None


GOOGLE_DRIVE_CREDENTIALS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "google_drive_credentials.json")
GOOGLE_DRIVE_TOKEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "google_drive_token.json")
GOOGLE_DRIVE_SCOPE = ["https://www.googleapis.com/auth/drive.metadata.readonly"]


def _google_drive_quota():
    """Fetch Google Drive storage quota using stdlib HTTP/OAuth (no pip modules)."""
    if not (os.path.exists(GOOGLE_DRIVE_CREDENTIALS) and os.path.exists(GOOGLE_DRIVE_TOKEN)):
        return None, "Google Drive API credentials/token not available"

    import urllib.error
    import urllib.request
    from datetime import datetime, timedelta, timezone

    try:
        with open(GOOGLE_DRIVE_TOKEN, "r", encoding="utf-8") as f:
            token_data = json.load(f)
        with open(GOOGLE_DRIVE_CREDENTIALS, "r", encoding="utf-8") as f:
            credential_data = json.load(f)
        if not isinstance(token_data, dict) or not isinstance(credential_data, dict):
            return None, "Google Drive authorization files are invalid"

        client = credential_data.get("installed") or credential_data.get("web") or credential_data
        client_id = token_data.get("client_id") or client.get("client_id")
        client_secret = token_data.get("client_secret") or client.get("client_secret")
        token_uri = token_data.get("token_uri") or client.get("token_uri") or "https://oauth2.googleapis.com/token"
        refresh_token = token_data.get("refresh_token")
        if not client_id or not client_secret:
            return None, "Google Drive OAuth client settings are incomplete"

        def token_expired(data):
            expiry = data.get("expiry")
            if not expiry:
                return not (data.get("token") or data.get("access_token"))
            try:
                dt = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt <= datetime.now(timezone.utc) + timedelta(seconds=60)
            except (TypeError, ValueError):
                # Unknown expiry format: test the token with the API before refresh.
                return False

        def refresh_access_token():
            if not refresh_token:
                return None, "Google Drive access token expired and no refresh token is available"
            form = urllib.parse.urlencode({
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }).encode("utf-8")
            req = urllib.request.Request(
                token_uri, data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=12) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                return None, f"Google OAuth refresh failed (HTTP {exc.code})"
            except (OSError, urllib.error.URLError, TimeoutError, ValueError):
                return None, "Google OAuth refresh failed (network or response error)"
            fresh = payload.get("access_token")
            if not fresh:
                return None, "Google OAuth refresh returned no access token"
            token_data["token"] = fresh
            token_data["access_token"] = fresh
            token_data["token_uri"] = token_uri
            token_data["client_id"] = client_id
            token_data["client_secret"] = client_secret
            if payload.get("refresh_token"):
                token_data["refresh_token"] = payload["refresh_token"]
            expires_in = int(payload.get("expires_in", 3600))
            token_data["expiry"] = (
                datetime.now(timezone.utc) + timedelta(seconds=max(60, expires_in))
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            # Atomic, owner-only save. Never log or display token contents.
            directory = os.path.dirname(os.path.abspath(GOOGLE_DRIVE_TOKEN))
            fd, temp_path = tempfile.mkstemp(prefix=".google_drive_token.", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(token_data, f, indent=2)
                    f.write("\n")
                os.chmod(temp_path, 0o600)
                os.replace(temp_path, GOOGLE_DRIVE_TOKEN)
            finally:
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except OSError:
                    pass
            return fresh, ""

        access_token = token_data.get("token") or token_data.get("access_token")
        if token_expired(token_data):
            access_token, err = refresh_access_token()
            if not access_token:
                return None, err

        def request_quota(bearer):
            req = urllib.request.Request(
                "https://www.googleapis.com/drive/v3/about?fields=storageQuota",
                headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))

        try:
            about = request_quota(access_token)
        except urllib.error.HTTPError as exc:
            if exc.code == 401 and refresh_token:
                access_token, err = refresh_access_token()
                if not access_token:
                    return None, err
                try:
                    about = request_quota(access_token)
                except urllib.error.HTTPError as retry_exc:
                    return None, f"Google Drive API request failed (HTTP {retry_exc.code})"
            else:
                return None, f"Google Drive API request failed (HTTP {exc.code})"
        except (OSError, urllib.error.URLError, TimeoutError, ValueError):
            return None, "Google Drive API request failed (network or response error)"

        quota = about.get("storageQuota", {}) if isinstance(about, dict) else {}
        result = _quota_from_bytes(quota.get("limit"), quota.get("usage"))
        if result:
            result["source"] = "Live Google Drive API · standard-library OAuth"
            return result, ""
        return None, "Google Drive API returned no usable storage quota"
    except (OSError, ValueError, TypeError, KeyError):
        return None, "Google Drive credentials/token could not be read"
    except Exception as exc:
        # Keep diagnostic useful without exposing any credential/token data.
        return None, f"Google Drive API request failed ({type(exc).__name__})"


# OneDrive account quota was verified in OneDrive Preferences: 23.4 GB used of 1 TB.
# Microsoft Graph live quota requires a separate app-registration/permission flow,
# which we intentionally do not add to this simple PNDCC setup. Never use the
# local Finder sync-folder size as OneDrive cloud quota.
ONEDRIVE_VERIFIED_TOTAL_GB = 1024.0
ONEDRIVE_VERIFIED_USED_GB = 23.4


def _onedrive_verified_quota():
    total = ONEDRIVE_VERIFIED_TOTAL_GB
    used = ONEDRIVE_VERIFIED_USED_GB
    free = max(0.0, total - used)
    return {
        "total_gb": total,
        "used_gb": used,
        "free_gb": round(free, 2),
        "used_pct": round((used / total) * 100, 1),
        "source": "Verified OneDrive Account · macOS OneDrive Preferences",
        "snapshot": True,
    }


def cloud_items():
    """Return cloud connectivity and account quota; never use local folder size as quota."""
    candidates = {
        "iCloud": ("www.icloud.com", 443, ["~/Library/Mobile Documents/com~apple~CloudDocs", "~/Library/CloudStorage/iCloud Drive"]),
        "Google Drive": ("drive.google.com", 443, ["~/Library/CloudStorage/GoogleDrive", "~/Google Drive"]),
        "OneDrive": ("onedrive.live.com", 443, ["~/Library/CloudStorage/OneDrive", "~/OneDrive"]),
    }
    configured = CLOUD_CONFIG.get("paths", {})
    result = []

    for name, (host, port, paths) in candidates.items():
        key = name.lower().replace(" ", "_")
        custom = configured.get(key, "")
        path = _first_existing_path([custom] + paths)
        try:
            with socket.create_connection((host, port), timeout=3):
                reachable = True
        except OSError:
            reachable = False

        if reachable and path:
            st, detail = "CONNECTED", "Cloud endpoint reachable · local sync location detected"
        elif reachable:
            st, detail = "ONLINE", "Cloud endpoint reachable · local sync location not detected"
        else:
            st, detail = "OFFLINE", "Cloud endpoint not reachable from PNDCC"

        quota = None
        quota_note = ""
        if name == "iCloud":
            quota = _icloud_quota()
            if quota:
                details = [quota.get("source", "System Settings")]
                if quota.get("saving_paused"):
                    details.append("Saving paused")
                if quota.get("sync_limited"):
                    details.append("Sync limited")
                if quota.get("drive_gb") is not None:
                    details.append(f"Drive {quota['drive_gb']:.2f} GB")
                quota_note = " · ".join(details)
                if quota.get("storage_full"):
                    st = "STORAGE FULL"
            else:
                quota_note = "Account quota unavailable; " + str(_ICLOUD_READ_DIAGNOSTIC) + "; no unverified storage values shown"
                if reachable:
                    st = "QUOTA UNAVAILABLE"
        elif name == "Google Drive":
            quota, quota_note = _google_drive_quota()
            if quota:
                quota_note = quota.get("source", "Live Google Drive API")
        elif name == "OneDrive":
            quota = _onedrive_verified_quota()
            quota_note = quota.get("source", "Verified OneDrive Account snapshot")

        result.append({
            "name": name,
            "status": st,
            "path": path,
            "detail": detail,
            "quota": quota,
            "quota_note": quota_note,
            "plan_gb": CLOUD_PLAN_GB.get(key),
        })
    return result


def status_pill_class(value):
    return str(value).upper().replace(" ", "-")


def _storage_progress_markup(pct, label, cloud=False):
    """Render a percentage bar without inventing a value when quota is unknown.

    Thresholds are consistent across local and cloud storage cards:
    green <70%, yellow 70–<90%, and red >=90% used.
    """
    label_text = esc(str(label or "Storage") + " storage usage")
    track_data = " data-cloud-usage-progress='1'" if cloud else ""
    fill_data = " data-cloud-usage-fill='1'" if cloud else ""
    caption_data = " data-cloud-usage-caption='1'" if cloud else ""
    valid = False
    try:
        numeric_pct = float(pct)
        valid = numeric_pct == numeric_pct and numeric_pct not in (float("inf"), float("-inf"))
    except (TypeError, ValueError, OverflowError):
        numeric_pct = 0.0

    if valid:
        shown_pct = min(100.0, max(0.0, numeric_pct))
        if numeric_pct >= 90:
            color = "red"
        elif numeric_pct >= 70:
            color = "yellow"
        else:
            color = "green"
        pct_text = f"{numeric_pct:.1f}% used"
        track_class = "storage-progress-track"
        fill_class = "storage-progress-fill is-" + color
        aria_value = f" aria-valuenow='{shown_pct:.1f}' aria-valuetext='{esc(pct_text)}'"
        width = f"{shown_pct:.1f}%"
    else:
        pct_text = "Usage unavailable"
        track_class = "storage-progress-track storage-progress-unavailable"
        fill_class = "storage-progress-fill is-unavailable"
        aria_value = " aria-valuetext='Usage unavailable; quota not verified'"
        width = "0%"

    return (
        "<div class='storage-progress-wrap'>"
        "<div class='storage-progress-meta'><span>Storage usage</span>"
        f"<strong{caption_data}>{esc(pct_text)}</strong></div>"
        f"<div class='{track_class}' role='progressbar' aria-label='{label_text}' "
        f"aria-valuemin='0' aria-valuemax='100'{aria_value}{track_data}>"
        f"<span class='{fill_class}' style='width:{width}'{fill_data}></span></div>"
        "</div>"
    )


def storage_card(item):
    st = item.get("status", "UNKNOWN")
    pct = item.get("used_pct")
    usage = f"{pct}% used" if pct is not None else "Capacity not available"
    detail = item.get("detail", "")
    if item.get("total_gb") is not None:
        detail = f"{item['used_gb']} GB used · {item['free_gb']} GB free · {item['total_gb']} GB total"
    elif item.get("path"):
        detail = esc(item["path"])
    progress = _storage_progress_markup(pct, item.get("name", "Storage"))
    return f"""<article class='card'><div class='device-top'><div><h3>{esc(item['name'])}</h3><div class='small'>{esc(detail)}</div></div><span class='pill {status_pill_class(st)}'>{esc(st)}</span></div><div class='metrics'><div><div class='metric-label'>USAGE</div><div class='metric-value'>{esc(usage)}</div></div><div><div class='metric-label'>LOCATION</div><div class='metric-value'>{esc(item.get('path') or 'Not configured')}</div></div></div>{progress}</article>"""


def cloud_card(item):
    """Render cloud quota; never substitute local sync size for account quota."""
    st = item.get("status", "UNKNOWN")
    quota = item.get("quota", {}) or {}
    total = quota.get("total_gb")
    used = quota.get("used_gb")
    free = quota.get("free_gb")
    pct = quota.get("used_pct")

    def quota_label(value):
        if value is None:
            return "Not available"
        return f"{value:.3f} GB" if value < 1 else f"{value:.2f} GB"

    values = {
        "USED": quota_label(used),
        "FREE": quota_label(free),
        "TOTAL": f"{total:g} GB" if isinstance(total, (int, float)) else "Not available",
        "USAGE": f"{pct:.1f}%" if pct is not None else "Not available",
        "STATUS": st,
    }

    if item.get("name") == "iCloud" and quota:
        if quota.get("storage_full"):
            values["STATUS"] = "STORAGE FULL"
        verified_at = quota.get("verified_at")
        if quota.get("snapshot"):
            values["SOURCE"] = "Last verified System Settings reading"
            if verified_at:
                try:
                    dt = datetime.fromisoformat(str(verified_at))
                    note_suffix = "Last verified: " + dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
                    # Normalize any timestamp already embedded in the note so
                    # repeated renders never duplicate the same verification time.
                    note_base = re.sub(
                        r"\s*[·|]?\s*Last verified:\s*[^·|]*",
                        "",
                        str(item.get("quota_note") or ""),
                        flags=re.I,
                    ).strip(" ·|")
                    item["quota_note"] = " · ".join(part for part in (note_base, note_suffix) if part)
                except Exception:
                    pass
        else:
            values["SOURCE"] = "Live System Settings"
        if quota.get("saving_paused"):
            values["SAVING"] = "PAUSED"
        if quota.get("sync_limited"):
            values["SYNC"] = "LIMITED"
    elif item.get("name") == "Google Drive" and quota:
        values["SOURCE"] = "Live Google Drive API"
    elif item.get("name") == "OneDrive" and quota:
        values["SOURCE"] = "Verified OneDrive Account snapshot"

    metrics = "".join(
        f"<div><div class='metric-label'>{label}</div><div class='metric-value' data-cloud-metric='{label}'>{esc(value)}</div></div>"
        for label, value in values.items()
    )
    note = esc(item.get("quota_note") or item.get("detail") or "")
    cloud_name = str(item.get("name", "Cloud storage"))
    status_class = status_pill_class(values['STATUS'])
    progress = _storage_progress_markup(pct, cloud_name, cloud=True)
    icloud_controls = ""
    if cloud_name == "iCloud":
        # Deliberately small, inline control: it refreshes only iCloud quota,
        # and never reloads the entire network dashboard.
        icloud_controls = r"""
        <style>
        .icloud-refresh-row{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-top:13px}
        .icloud-refresh-btn{border:1px solid var(--line);border-radius:8px;background:#f8fafc;color:var(--ink);padding:7px 10px;font-size:12px;font-weight:700;cursor:pointer}
        .icloud-refresh-btn:hover{border-color:var(--blue);color:var(--blue)}
        .icloud-refresh-btn:disabled{opacity:.6;cursor:wait}
        .icloud-refresh-message{margin-top:10px;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:#f8fafc;color:var(--ink);font-size:12px;line-height:1.5}
        .icloud-refresh-message.success{border-color:#a7e0be;background:#edf9f1}
        .icloud-refresh-message.warning{border-color:#f1d399;background:#fff8e8}
        </style>
        <div class="icloud-refresh-row">
          <button type="button" id="pndcc-icloud-refresh-button" class="icloud-refresh-btn">↻ Refresh iCloud</button>
          <span id="pndcc-icloud-refresh-indicator" class="small" aria-live="polite"></span>
        </div>
        <div id="pndcc-icloud-refresh-message" class="icloud-refresh-message" role="status" aria-live="polite" hidden></div>
        <script>
        (function(){
          const btn = document.getElementById('pndcc-icloud-refresh-button');
          const indicator = document.getElementById('pndcc-icloud-refresh-indicator');
          const box = document.getElementById('pndcc-icloud-refresh-message');
          const card = btn ? btn.closest('article.card') : null;
          if (!btn || !indicator || !box || !card || btn.dataset.bound === '1') return;
          btn.dataset.bound = '1';
          function metric(name){ return card.querySelector('[data-cloud-metric="' + name + '"]'); }
          function showMessage(kind, text){
            box.className = 'icloud-refresh-message ' + kind;
            box.textContent = text;
            box.hidden = false;
          }
          function formatGB(value){
            const n = Number(value);
            return Number.isFinite(n) ? (n < 1 ? n.toFixed(3) : n.toFixed(2)) + ' GB' : 'Not available';
          }
          btn.addEventListener('click', async function(){
            btn.disabled = true;
            indicator.textContent = 'Checking iCloud…';
            showMessage('', 'Attempting a fresh read from macOS System Settings. This may take a few seconds.');
            try {
              const response = await fetch('/api/cloud/icloud-refresh', {
                method: 'POST',
                headers: {'Accept': 'application/json'},
                credentials: 'same-origin',
                cache: 'no-store'
              });
              const data = await response.json();
              if (data.ok && data.quota) {
                const q = data.quota;
                const fields = {
                  'USED': formatGB(q.used_gb),
                  'FREE': formatGB(q.free_gb),
                  'TOTAL': Number.isFinite(Number(q.total_gb)) ? Number(q.total_gb).toString() + ' GB' : 'Not available',
                  'USAGE': Number.isFinite(Number(q.used_pct)) ? Number(q.used_pct).toFixed(1) + '%' : 'Not available',
                  'SOURCE': 'Live System Settings',
                  'STATUS': q.storage_full ? 'STORAGE FULL' : 'CONNECTED'
                };
                Object.keys(fields).forEach(function(k){ const el = metric(k); if (el) el.textContent = fields[k]; });
                const pct = (q.used_pct !== null && q.used_pct !== undefined) ? Number(q.used_pct) : NaN;
                const progress = card.querySelector('[data-cloud-usage-progress]');
                const fill = card.querySelector('[data-cloud-usage-fill]');
                const progressCaption = card.querySelector('[data-cloud-usage-caption]');
                if (Number.isFinite(pct) && pct >= 0) {
                  const shownPct = Math.min(100, pct);
                  const color = pct >= 90 ? 'red' : (pct >= 70 ? 'yellow' : 'green');
                  if (progress) {
                    progress.classList.remove('storage-progress-unavailable');
                    progress.setAttribute('aria-valuenow', shownPct.toFixed(1));
                    progress.setAttribute('aria-valuetext', pct.toFixed(1) + '% used');
                  }
                  if (fill) {
                    fill.className = 'storage-progress-fill is-' + color;
                    fill.style.width = shownPct.toFixed(1) + '%';
                  }
                  if (progressCaption) progressCaption.textContent = pct.toFixed(1) + '% used';
                } else {
                  if (progress) {
                    progress.classList.add('storage-progress-unavailable');
                    progress.removeAttribute('aria-valuenow');
                    progress.setAttribute('aria-valuetext', 'Usage unavailable; quota not verified');
                  }
                  if (fill) { fill.className = 'storage-progress-fill is-unavailable'; fill.style.width = '0%'; }
                  if (progressCaption) progressCaption.textContent = 'Usage unavailable';
                }
                const pill = card.querySelector('.pill');
                if (pill) { pill.textContent = fields.STATUS; pill.className = 'pill ' + fields.STATUS.replace(/ /g, '-'); }
                const note = card.querySelector('[data-cloud-note]');
                if (note) note.textContent = q.verified_at ? 'Live macOS System Settings · Apple Account > iCloud · Refreshed: ' + new Date(q.verified_at).toLocaleString() : 'Live macOS System Settings · Apple Account > iCloud';
                indicator.textContent = 'Live reading updated';
                showMessage('success', data.message || 'iCloud storage refreshed successfully.');
              } else {
                indicator.textContent = data.last_verified_at ? 'Showing last verified reading' : 'Fresh reading unavailable';
                const advice = data.advice || 'Open System Settings → Apple Account → iCloud, wait for the Storage line to appear, then try again.';
                const detail = data.diagnostic ? ' Details: ' + data.diagnostic : '';
                const stamp = data.last_verified_at ? ' Last verified: ' + data.last_verified_at + '.' : ' No recent verified reading is available.';
                showMessage('warning', (data.message || 'Could not refresh the live iCloud quota.') + stamp + ' What to check: ' + advice + detail);
              }
            } catch (err) {
              indicator.textContent = 'Refresh failed';
              showMessage('warning', 'PNDCC could not complete the refresh request. Keep System Settings → Apple Account → iCloud open and try again. If this repeats, note the time and share the Terminal/server log.');
            } finally {
              btn.disabled = false;
            }
          });
        })();
        </script>
        """
    return f"""<article class='card' data-cloud-name='{esc(cloud_name.lower())}'><div class='device-top'><div><h3>{esc(cloud_name)}</h3><div class='small' data-cloud-note>{note}</div></div><span class='pill {status_class}'>{esc(values['STATUS'])}</span></div><div class='metrics' style='grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:8px'>{metrics}</div>{progress}{icloud_controls}</article>"""


def storage_cloud_sections():
    storages = storage_items()
    clouds = cloud_items()
    return f"""
    <section class='section'><div class='section-head'><h2 class='section-title'>Storage</h2><span class='section-note'>Usage colors: green &lt;70% · yellow 70–89.9% · red ≥90%</span></div><div class='grid'>{''.join(storage_card(x) for x in storages)}</div></section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Cloud storage</h2><span class='section-note'>Usage colors: green &lt;70% · yellow 70–89.9% · red ≥90%</span></div><div class='grid'>{''.join(cloud_card(x) for x in clouds)}</div></section>
    """

# ---------------------------------------------------------------------------
# Dashboard rendering
# ---------------------------------------------------------------------------

CSS = r"""
:root{color-scheme:light;--bg:#f3f6fb;--panel:#fff;--ink:#172033;--muted:#667085;--line:#e6eaf1;--blue:#315ee8;--green:#16834a;--amber:#a15c00;--red:#b42318;--shadow:0 8px 26px rgba(16,24,40,.06)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{max-width:1240px;margin:0 auto;padding:28px 22px 36px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:22px}.brand{display:flex;align-items:center;gap:13px}.logo{width:46px;height:46px;border-radius:14px;display:grid;place-items:center;color:white;font-size:22px;font-weight:800;background:linear-gradient(135deg,#4777f5,#2546b8);text-decoration:none;cursor:pointer;flex:0 0 auto}h1{margin:0;font-size:24px;letter-spacing:-.5px}.subtitle{color:var(--muted);font-size:13px;margin-top:4px}.actions{display:flex;align-items:center;gap:10px}.refresh,.linkbtn{border:0;border-radius:10px;background:var(--blue);color:#fff;padding:10px 14px;font-size:13px;font-weight:700;cursor:pointer;text-decoration:none}.live{color:var(--green);font-size:12px;font-weight:700}.hero{background:linear-gradient(120deg,#172b59,#254da6);color:white;padding:22px;border-radius:18px;box-shadow:var(--shadow)}.hero-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap}.hero h2{margin:0;font-size:17px}.hero p{margin:6px 0 0;color:#d8e3ff;font-size:13px}.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}.kpi{padding:15px;background:rgba(255,255,255,.10);border:1px solid rgba(255,255,255,.12);border-radius:13px;min-width:0}.kpi-label{color:#d8e3ff;font-size:10px;letter-spacing:.09em;font-weight:700}.kpi-value{margin-top:8px;font-size:23px;font-weight:800;overflow-wrap:anywhere}.section{margin-top:25px}.section-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}.section-title{margin:0;font-size:14px;font-weight:800}.section-note{color:var(--muted);font-size:12px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:15px;padding:17px;box-shadow:var(--shadow);min-width:0}.device-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px}.card h3{margin:0;font-size:15px;overflow-wrap:anywhere}.small{color:var(--muted);font-size:12px;margin-top:5px;overflow-wrap:anywhere}.pill{display:inline-flex;align-items:center;border-radius:999px;padding:5px 9px;font-size:10px;font-weight:800;letter-spacing:.04em;white-space:nowrap;background:#eef2f6;color:#667085}.ONLINE,.CONNECTED{color:var(--green)}.WARNING{color:var(--amber)}.CRITICAL,.OFFLINE{color:var(--red)}.NOT-CONFIGURED,.NOT-CHECKED{color:var(--muted)}.pill.ONLINE,.pill.CONNECTED{background:#e8f7ee}.pill.WARNING{background:#fff3d6}.pill.CRITICAL,.pill.OFFLINE{background:#fdeceb}.metrics{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:16px;padding-top:13px;border-top:1px solid var(--line)}.metric-label{color:var(--muted);font-size:11px}.metric-value{margin-top:4px;font-size:14px;font-weight:700}.storage-progress-wrap{margin-top:14px}.storage-progress-meta{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:6px;color:var(--muted);font-size:11px}.storage-progress-meta strong{color:var(--ink);font-size:11px;font-weight:750}.storage-progress-track{height:10px;width:100%;border-radius:999px;background:#e8edf5;overflow:hidden}.storage-progress-fill{display:block;height:100%;border-radius:999px;transition:width .25s ease}.storage-progress-fill.is-green{background:#16a34a}.storage-progress-fill.is-yellow{background:#eab308}.storage-progress-fill.is-red{background:#dc2626}.storage-progress-fill.is-unavailable{background:#94a3b8}.storage-progress-unavailable{background:repeating-linear-gradient(135deg,#eef2f6,#eef2f6 6px,#e3e8ef 6px,#e3e8ef 12px)}.ftp-card{display:grid;grid-template-columns:1.3fr 1fr 1fr;gap:16px;align-items:center}.ftp-main{min-width:0}.ftp-status{font-size:16px;font-weight:800;margin-top:8px}.table-wrap{overflow:auto}.table{width:100%;border-collapse:collapse;font-size:12px}.table th,.table td{text-align:left;padding:9px;border-bottom:1px solid var(--line);white-space:nowrap}.table th{font-size:10px;letter-spacing:.06em;color:var(--muted)}.foot{color:var(--muted);font-size:11px;margin-top:24px;text-align:center}.nav{display:flex;gap:8px;flex-wrap:wrap}.nav a{color:var(--blue);text-decoration:none;font-size:12px;font-weight:700}.bar{height:8px;border-radius:99px;background:#e8edf5;overflow:hidden;margin-top:7px}.bar>span{display:block;height:100%;background:#315ee8}.chart{display:grid;gap:7px}.chart-row{display:grid;grid-template-columns:70px 1fr 70px;gap:8px;align-items:center;font-size:10px}.chart-time,.chart-value{color:var(--muted);white-space:nowrap}.chart-value{text-align:right}.chart-track{height:10px;background:#e8edf5;border-radius:99px;overflow:hidden}.chart-bar{display:block;height:100%;border-radius:99px;background:#315ee8}.chart-bar.WARNING{background:#a15c00}.chart-bar.CRITICAL,.chart-bar.OFFLINE{background:#b42318}.alert-list{display:grid;gap:8px}.alert-item{display:grid;grid-template-columns:105px 1fr auto;gap:10px;align-items:center;padding:10px;border:1px solid var(--line);border-radius:10px}.alert-item .message{font-size:12px}.alert-item .meta{color:var(--muted);font-size:11px}.notice{padding:12px;border-radius:10px;background:#f7f8fa;color:var(--muted);font-size:12px}.STORAGE-FULL{color:var(--red)}.pill.STORAGE-FULL{background:#fdeceb}.screenshot-controls{margin-top:25px}.screenshot-preview{margin-top:14px}.screenshot-image{display:block;width:100%;height:auto;border:1px solid var(--line);border-radius:12px;background:#fff}.screenshot-note{color:var(--muted);font-size:11px;margin-top:7px}.screenshot-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.screenshot-actions button,.screenshot-actions a{font:inherit;cursor:pointer;text-decoration:none}.screenshot-menu{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px;padding:10px;border:1px solid var(--line);border-radius:10px;background:#f8fafc}.screenshot-menu strong{font-size:11px;color:var(--muted);width:100%}.screenshot-menu button{border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--ink);padding:8px 10px;font-size:12px;cursor:pointer}.screenshot-status{color:var(--muted);font-size:11px;margin-top:8px;min-height:16px}.screenshot-choice{display:none;margin-top:12px;padding:14px;border:1px solid var(--line);border-radius:12px;background:#f8fafc}.screenshot-choice p{margin:0 0 10px;font-size:12px}.screenshot-choice-actions{display:flex;gap:8px;flex-wrap:wrap}.screenshot-choice-actions button{border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--ink);padding:9px 12px;font-size:12px;font-weight:700;cursor:pointer}.screenshot-choice-actions button.primary{background:var(--blue);border-color:var(--blue);color:#fff}@media(max-width:640px){.wrap{padding:18px 13px 28px}h1{font-size:20px}.hero{padding:17px}.kpi{padding:12px}.kpi-value{font-size:20px}.ftp-card{grid-template-columns:1fr 1fr}.ftp-main{grid-column:1/-1}}
"""


def device_card(d, r):
    s = str(r.get("status", "NOT CHECKED"))
    cls = s.replace(" ", "-")
    latency = r.get("latency_ms") or "—"
    loss = r.get("packet_loss_pct") or "—"
    return f"""
    <article class='card'>
      <div class='device-top'>
        <div><h3>{esc(d.get('name','Unnamed device'))}</h3><div class='small'>{esc(d.get('ip','—'))}</div></div>
        <span class='pill {esc(cls)}'>{esc(s)}</span>
      </div>
      <div class='metrics'>
        <div><div class='metric-label'>Latency</div><div class='metric-value'>{esc(latency)}{' ms' if latency != '—' and str(latency).find('ms') < 0 else ''}</div></div>
        <div><div class='metric-label'>Packet loss</div><div class='metric-value'>{esc(loss)}{'%' if loss != '—' and str(loss).find('%') < 0 else ''}</div></div>
      </div>
    </article>"""


PNDCC_SCREENSHOT_JS = r"""
<script>
(function () {
  var screenshotDataUrl = null;
  var screenshotBlob = null;
  var screenshotBaseName = null;

  function setStatus(message) {
    var status = document.getElementById('pndcc-screenshot-status');
    if (status) status.textContent = message || '';
  }

  function closeMenu(id) {
    var el = document.getElementById(id);
    if (el) el.style.display = 'none';
  }

  function cancelScreenshot() {
    var panel = document.getElementById('pndcc-screenshot-preview');
    var image = document.getElementById('pndcc-screenshot-image');
    if (panel) panel.style.display = 'none';
    if (image) image.removeAttribute('src');
    screenshotDataUrl = null;
    screenshotBlob = null;
    screenshotBaseName = null;
    closeMenu('pndcc-save-menu');
    closeMenu('pndcc-share-menu');
    setStatus('Screenshot cancelled.');
  }

  function downloadBlob(blob, filename) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function saveAs(format) {
    if (!screenshotDataUrl) return;
    closeMenu('pndcc-save-menu');
    var base = screenshotBaseName || 'PNDCC_Screenshot';
    if (format === 'pdf') {
      var win = window.open('', '_blank');
      if (!win) { setStatus('PDF preview was blocked. Allow pop-ups for PNDCC and try again.'); return; }
      win.document.write('<!doctype html><html><head><title>' + base + '</title><style>@page{margin:10mm}body{margin:0;text-align:center}img{max-width:100%;height:auto}</style></head><body><img src="' + screenshotDataUrl + '"></body></html>');
      win.document.close();
      win.focus();
      setTimeout(function () { win.print(); }, 350);
      setStatus('PDF print dialog opened. Choose Save as PDF.');
      return;
    }
    if (format === 'svg') {
      var svgText = document.getElementById('pndcc-svg-source');
      if (svgText && svgText.value) {
        var svgBlob = new Blob([svgText.value], {type: 'image/svg+xml;charset=utf-8'});
        downloadBlob(svgBlob, base + '.svg');
        setStatus('SVG saved.');
        return;
      }
      setStatus('SVG source is not available for this capture.');
      return;
    }
    var mime = 'image/png', ext = 'png', quality;
    if (format === 'jpeg') { mime = 'image/jpeg'; ext = 'jpg'; quality = 0.92; }
    if (format === 'webp') { mime = 'image/webp'; ext = 'webp'; quality = 0.92; }
    var img = new Image();
    img.onload = function () {
      var canvas = document.createElement('canvas');
      canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
      var ctx = canvas.getContext('2d');
      if (format === 'jpeg') { ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, canvas.width, canvas.height); }
      ctx.drawImage(img, 0, 0);
      canvas.toBlob(function (blob) {
        if (!blob) { setStatus('This format could not be created by the browser.'); return; }
        downloadBlob(blob, base + '.' + ext);
        setStatus(ext.toUpperCase() + ' saved.');
      }, mime, quality);
    };
    img.src = screenshotDataUrl;
  }

  async function systemShare() {
    if (!screenshotBlob || !screenshotBaseName) return;
    closeMenu('pndcc-share-menu');
    try {
      var file = new File([screenshotBlob], screenshotBaseName + '.png', {type: 'image/png'});
      if (navigator.share && (!navigator.canShare || navigator.canShare({files: [file]}))) {
        await navigator.share({title: 'PNDCC Screenshot', text: 'PNDCC current sheet screenshot', files: [file]});
        setStatus('Share / Send completed or handed to the browser.');
      } else {
        setStatus('Native Share is not available here. Choose a destination below or use Save & Send Later.');
      }
    } catch (e) {
      if (e && e.name === 'AbortError') setStatus('Share / Send cancelled.');
      else setStatus('Share / Send was not completed.');
    }
  }

  async function copyImage() {
    if (!screenshotBlob) return;
    try {
      if (navigator.clipboard && window.ClipboardItem) {
        await navigator.clipboard.write([new ClipboardItem({'image/png': screenshotBlob})]);
        closeMenu('pndcc-share-menu');
        setStatus('Screenshot copied to the clipboard. Paste it into the destination.');
        return;
      }
    } catch (e) {}
    setStatus('Copy Image is not available in this browser. Use System Share or Save & Send Later.');
  }

  function saveAndSendLater() {
    if (!screenshotBlob || !screenshotBaseName) return;
    downloadBlob(screenshotBlob, screenshotBaseName + '.png');
    closeMenu('pndcc-share-menu');
    setStatus('Screenshot PNG saved. You can send it from your preferred app.');
  }

  function openDestination(kind) {
    closeMenu('pndcc-share-menu');
    var subject = encodeURIComponent('PNDCC Screenshot');
    var body = encodeURIComponent('PNDCC Screenshot — the screenshot file has been created locally.');
    var url = '';
    if (kind === 'whatsapp') url = 'https://web.whatsapp.com/send?text=' + body;
    else if (kind === 'gmail') url = 'https://mail.google.com/mail/?view=cm&fs=1&tf=1&su=' + subject + '&body=' + body;
    else if (kind === 'yahoo') url = 'https://compose.mail.yahoo.com/?subject=' + subject + '&body=' + body;
    else if (kind === 'messages') url = 'sms:&body=' + body;
    else if (kind === 'email') url = 'mailto:?subject=' + subject + '&body=' + body;
    if (!url) return;
    // Web destinations cannot receive a local browser File object directly.
    // Create the real PNG first so it is ready for attachment, then open the destination.
    if (screenshotBlob && screenshotBaseName) {
      downloadBlob(screenshotBlob, screenshotBaseName + '.png');
    }
    window.open(url, '_blank');
    setStatus('Screenshot PNG created. The destination is open and the file is ready to attach.');
  }

  function capturePNDCCPage() {
    return captureDocument(window.document, 'PNDCC_Screenshot_' + new Date().toISOString().replace(/[:.]/g, '-'), function (blob, dataUrl, svg) {
      screenshotBlob = blob; screenshotDataUrl = dataUrl; screenshotBaseName = 'PNDCC_Screenshot_' + new Date().toISOString().replace(/[:.]/g, '-');
      var output = document.getElementById('pndcc-screenshot-image');
      var preview = document.getElementById('pndcc-screenshot-preview');
      if (output) output.src = dataUrl;
      if (preview) preview.style.display = '';
      var svgSource = document.getElementById('pndcc-svg-source');
      if (svgSource) svgSource.value = svg;
      setStatus('Screenshot ready. Choose Save, Share / Send, or Cancel.');
    });
  }

  function exportContextFor(doc) {
    var path = '';
    try { path = new URL(doc.location && doc.location.href ? doc.location.href : window.location.href).pathname; } catch (e) {}
    var titleNode = doc.querySelector('h1');
    var title = titleNode ? titleNode.textContent.trim() : (doc.title || path || 'PNDCC page');
    var map = {
      '/': ['Dashboard', 'Provides the main at-a-glance command-center view of your network, devices, services, storage, cloud status, alerts, and Network Pulse.', 'Use it to quickly understand what is online, what needs attention, and where to open the detailed monitoring or control pages.'],
      '/history': ['Device History', 'Shows historical device connectivity, latency, and packet-loss observations.', 'Use it to identify recurring instability, outages, or performance changes over time.'],
      '/ftp-history': ['FTP / FTPS History', 'Shows completed FTP/FTPS service checks, login status, TLS protection, and latency.', 'Use it to verify that the Windows FTP/FTPS service is consistently reachable and authenticated.'],
      '/alerts': ['Alert History', 'Shows recorded device and service alert events with timestamps and severity.', 'Use it to investigate when problems started and distinguish current issues from historical events.'],
      '/network-diagnostics': ['Network Diagnostics', 'Provides detailed network checks for the monitored devices and connectivity path.', 'Use it when the dashboard shows an offline, critical, or unusually slow device and you need more evidence.'],
      '/network-pulse': ['Network Pulse', 'Provides the latest Internet latency, packet loss, DNS, and overall network-health measurement.', 'Use it to separate a local device problem from a broader Internet or network problem.'],
      '/device-control': ['Device Control Center', 'Provides controlled Finder/Explorer-style access to local and remote files and folders.', 'Use it to browse, create, rename, copy, move, delete, upload, download, and paste files under the existing PNDCC safety controls.'],
      '/decision-engine': ['Decision / Action Engine', 'Summarizes completed monitoring evidence and produces controlled recommendations.', 'Use it to understand what PNDCC recommends before taking an action.'],
      '/diagnostic-explanation': ['Diagnostic & Explanation', 'Explains completed PNDCC observations and the evidence behind detected conditions.', 'Use it to understand why a condition was classified as normal, warning, critical, or offline.'],
      '/controlled-action': ['Controlled Action & Recovery', 'Shows controlled recovery actions and their recorded results.', 'Use it to review what PNDCC attempted, whether it succeeded, and what was recorded for later troubleshooting.'],
      '/settings': ['PNDCC Settings', 'Shows the persistent configuration used by PNDCC monitoring and service checks.', 'Use it to review or safely update configuration without changing the underlying monitoring engine.']
    };
    var item = map[path] || [title, 'Provides the information and controls available on this PNDCC page.', 'Use this page together with the Dashboard to understand status, investigate problems, and operate PNDCC safely.'];
    return {name:item[0], purpose:item[1], benefit:item[2], info:'Page: ' + title + (path ? ' · Route: ' + path : '')};
  }

  function addExportFooter(clone, doc) {
    var ctx = exportContextFor(doc);
    var foot = doc.createElement('div');
    foot.setAttribute('data-pndcc-export-footer', 'true');
    foot.style.cssText = 'margin-top:18px;padding:12px 14px;border-top:2px solid #d9e2f2;background:#f7f9fc;color:#344054;font:12px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;';
    foot.innerHTML = '<div style="font-weight:800;font-size:13px;margin-bottom:4px">About this page — ' + escapeHtml(ctx.name) + '</div>' +
      '<div><b>Purpose:</b> ' + escapeHtml(ctx.purpose) + '</div>' +
      '<div><b>Benefit:</b> ' + escapeHtml(ctx.benefit) + '</div>' +
      '<div><b>Contains:</b> ' + escapeHtml(ctx.info) + '</div>';
    var existing = clone.querySelector('.foot');
    if (existing && existing.parentNode) existing.parentNode.insertBefore(foot, existing);
    else clone.appendChild(foot);
    return ctx;
  }

  function captureDocument(doc, baseName, done) {
    var settled = false;
    function finish(blob, dataUrl, svg, errorMessage) {
      if (settled) return;
      settled = true;
      done(blob || null, dataUrl || null, svg || null, errorMessage || null);
    }
    var target = doc.querySelector('.wrap');
    if (!target) {
      setStatus('Screenshot target was not found.');
      finish(null, null, null, 'Screenshot target was not found.');
      return;
    }
    setStatus('Creating screenshot…');
    var clone = target.cloneNode(true);
    var cloneControls = clone.querySelector('.screenshot-controls');
    if (cloneControls) cloneControls.remove();
    addExportFooter(clone, doc);
    var rect = target.getBoundingClientRect();
    var width = Math.max(320, Math.ceil(rect.width));
    // Capture the complete target. Do not cap height at the viewport: that
    // crops the bottom of the dashboard before the user can review the image.
    // PDF/DOCX placement scales this complete image proportionally afterward.
    var height = Math.max(200, Math.ceil(target.scrollHeight));
    clone.style.width = width + 'px'; clone.style.maxWidth = 'none'; clone.style.margin = '0';
    var serialized = new XMLSerializer().serializeToString(clone);
    var styleText = '';
    doc.querySelectorAll('style').forEach(function (node) { styleText += node.textContent + '\n'; });
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' + width + '" height="' + height + '"><foreignObject x="0" y="0" width="100%" height="100%"><div xmlns="http://www.w3.org/1999/xhtml"><style>' + styleText + '</style>' + serialized + '</div></foreignObject></svg>';
    var img = new Image();
    img.onload = function () {
      try {
        var canvas = document.createElement('canvas'); canvas.width = width * 2; canvas.height = height * 2;
        var ctx = canvas.getContext('2d'); ctx.scale(2, 2); ctx.drawImage(img, 0, 0, width, height);
        canvas.toBlob(function (blob) {
          if (!blob) { var msg = 'Screenshot could not be created.'; setStatus(msg); finish(null, null, svg, msg); return; }
          finish(blob, canvas.toDataURL('image/png'), svg, null);
        }, 'image/png');
      } catch (e) { var msg = 'Screenshot could not be rendered in this browser.'; setStatus(msg); finish(null, null, svg, msg); }
    };
    img.onerror = function () { var msg = 'Screenshot could not be rendered in this browser.'; setStatus(msg); finish(null, null, svg, msg); };
    img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
  }

  function openScreenshotChoice() {
    var choice = document.getElementById('pndcc-screenshot-choice');
    var preview = document.getElementById('pndcc-screenshot-preview');
    if (preview) preview.style.display = 'none';
    if (choice) choice.style.display = 'block';
    setStatus('Choose Current Page or All PNDCC Pages.');
  }

  function openDocumentationChoice() {
    var choice = document.getElementById('pndcc-screenshot-choice');
    var docs = document.getElementById('pndcc-documentation-choice');
    var preview = document.getElementById('pndcc-screenshot-preview');
    if (preview) preview.style.display = 'none';
    if (choice) choice.style.display = 'none';
    if (docs) docs.style.display = 'block';
    setStatus('Choose PNDCC documentation sets to generate.');
  }

  function closeDocumentationChoice() {
    var docs = document.getElementById('pndcc-documentation-choice');
    if (docs) docs.style.display = 'none';
    var all = document.getElementById('pndcc-doc-all');
    if (all) all.checked = false;
    document.querySelectorAll('input[name="pndcc-doc-set"]').forEach(function(cb){ cb.checked = false; });
    setStatus('');
  }

  async function generateSelectedDocumentation(archiveMode) {
    var all = document.getElementById('pndcc-doc-all');
    var selected = Array.prototype.slice.call(document.querySelectorAll('input[name="pndcc-doc-set"]:checked')).map(function(cb){ return cb.value; });
    if (all && all.checked) selected = ['1','2','3'];
    selected = Array.from(new Set(selected));
    if (!selected.length) {
      setStatus('Please select documentation set 1, 2, 3, or Select all.');
      return;
    }

    setStatus(archiveMode ? 'Generating documentation ZIP and saving an archive copy…' : 'Generating selected PNDCC documentation ZIP…');
    try {
      // Reuse the screenshot created by the explicit Capture Screenshot action.
      // If the user did not capture one, attempt a fresh capture. Screenshot
      // failure is non-fatal: the server still creates text-only DOCX/PDF files.
      async function downloadDocumentation(imageDataUrl) {
        var endpoint = '/api/documentation/with-screenshot' + (archiveMode ? '?archive=1' : '');
        var response = await fetch(endpoint, {
          method: 'POST', credentials: 'same-origin', cache: 'no-store',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({docs:selected, screenshot:imageDataUrl || null})
        });
        if (!response.ok) throw new Error('HTTP ' + response.status);
        var blob = await response.blob();
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'PNDCC_Documentation_' + selected.join('_') + '_' + new Date().toISOString().slice(0,10) + '.zip';
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(function(){ URL.revokeObjectURL(url); }, 30000);
        setStatus(archiveMode ? 'Documentation generated, downloaded, and archived; screenshot included when available.' : 'Documentation ZIP generated; screenshot included when available, with text-only fallback.');
      }
      if (typeof screenshotDataUrl === 'string' && screenshotDataUrl.indexOf('data:image/png;base64,') === 0) {
        await downloadDocumentation(screenshotDataUrl);
      } else {
        var captureSettled = false;
        var captureFallback = setTimeout(function(){
          if (captureSettled) return;
          captureSettled = true;
          downloadDocumentation(null).catch(function(e){ console.error(e); setStatus('Documentation generation failed safely.'); });
        }, 12000);
        try {
          captureDocument(document, 'PNDCC_Documentation', function(blob, dataUrl) {
            if (captureSettled) return;
            captureSettled = true; clearTimeout(captureFallback);
            downloadDocumentation(dataUrl || null).catch(function(e){ console.error(e); setStatus('Documentation generation failed safely.'); });
          });
        } catch (captureError) {
          if (!captureSettled) {
            captureSettled = true; clearTimeout(captureFallback);
            await downloadDocumentation(null);
          }
        }
      }
    } catch (e) {
      console.error('PNDCC documentation generation failed:', e);
      setStatus('Documentation generation failed. No existing PNDCC configuration or data was changed.');
    }
  }

  function generateDocumentationForSending() {
    generateSelectedDocumentation(false);
  }

  function generateDocumentationForArchive() {
    generateSelectedDocumentation(true);
  }

  function generateAllPagesPdfOnly() {
    closeDocumentationChoice();
    captureAllPNDCCPages();
  }

  function closeScreenshotChoice() {
    var choice = document.getElementById('pndcc-screenshot-choice');
    if (choice) choice.style.display = 'none';
    setStatus('');
  }

  function finishAllPagesPdf(pages, report) {
    closeScreenshotChoice();
    var stamp = new Date();
    var dateText = stamp.toLocaleDateString();
    var timeText = stamp.toLocaleTimeString();
    var version = '2.6.3';
    var title = 'PNDCC — Personal Network & Device Command Center';
    if (!report || report.closed) { setStatus('PDF report window is unavailable. Please allow pop-ups for PNDCC and try again.'); return; }
    var pageCount = pages.length;

    var pageHtml = pages.map(function (p, i) {
      var ctx = p.context || {name:p.title, purpose:'Provides the information and controls available on this PNDCC page.', benefit:'Use this page with the Dashboard to understand status and investigate problems.', info:'Page: '+p.title};
      var content = p.html || ('<img src="' + (p.dataUrl || '') + '" alt="' + escapeHtml(p.title) + '">');
      return '<section class="report-page">' +
        '<div class="report-head"><h1>' + title + '</h1>' +
        '<div>Created by: Saiful Quadir · Version: ' + version + '</div>' +
        '<div>Created: ' + dateText + ' ' + timeText + '</div>' +
        '<div>Page ' + (i + 1) + ' of ' + pageCount + ' · ' + escapeHtml(p.title) + '</div></div>' +
        '<div class="page-capture">' + content + '</div>' +
        '<div class="report-context"><b>Purpose:</b> ' + escapeHtml(ctx.purpose) +
        '<br><b>Benefit:</b> ' + escapeHtml(ctx.benefit) +
        '<br><b>Contains:</b> ' + escapeHtml(ctx.info) + '</div>' +
        '<div class="report-foot">PNDCC · Saiful Quadir · Generated ' + dateText + ' ' + timeText + ' · Page ' + (i + 1) + ' of ' + pageCount + '</div>' +
        '</section>';
    }).join('');

    report.document.write('<!doctype html><html><head><meta charset="utf-8"><title>PNDCC All Pages</title>' +
      '<style>' +
      '@page{size:auto;margin:10mm}' +
      'body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033}' +
      '.report-page{page-break-after:always;min-height:260mm;box-sizing:border-box;padding:0}' +
      '.report-page:last-child{page-break-after:auto}' +
      '.report-head{border-bottom:1px solid #ddd;padding-bottom:8px;margin-bottom:12px;font-size:11px;line-height:1.55}' +
      '.report-head h1{font-size:17px;margin:0 0 3px}' +
      '.page-capture{width:100%;overflow:visible}' +
      '.page-capture .wrap{width:100%!important;max-width:none!important;margin:0!important}' +
      '.page-capture .screenshot-controls{display:none!important}' +
      '.report-context{font-size:10px;line-height:1.5;margin-top:10px;padding:8px 10px;border-top:1px solid #d9e2f2;background:#f7f9fc;color:#344054}' +
      '.report-foot{font-size:10px;color:#667085;margin-top:8px;border-top:1px solid #eee;padding-top:5px}' +
      '</style></head><body>' + pageHtml + '</body></html>');
    report.document.close();
    report.focus();

    // The All-Pages export deliberately avoids the fragile SVG/foreignObject
    // rasterization path. The server already gives us complete HTML pages, so
    // print the real page markup directly and let the browser paginate it.
    try {
      var doneMessage = report.document.getElementById('pndcc-progress-message');
      if (doneMessage) doneMessage.textContent = 'Opening print dialog…';
    } catch (e) {}
    setTimeout(function () {
      try {
        report.focus();
        report.print();
        setStatus('All ' + pageCount + ' PNDCC pages are ready. Choose Save as PDF in the print dialog.');
      } catch (e) {
        setStatus('PDF print could not be opened. The All-Pages report window is still available.');
      }
    }, 1200);
  }

  function escapeHtml(value) {
    return String(value || '').replace(/[&<>"']/g, function (c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; });
  }

  function updateAllPagesProgress(reportWindow, collected, discovered, currentTitle, phase) {
    try {
      if (!reportWindow || reportWindow.closed) return;
      var bar = reportWindow.document.getElementById('pndcc-progress-bar');
      var pct = reportWindow.document.getElementById('pndcc-progress-pct');
      var count = reportWindow.document.getElementById('pndcc-progress-count');
      var current = reportWindow.document.getElementById('pndcc-progress-current');
      var message = reportWindow.document.getElementById('pndcc-progress-message');
      var list = reportWindow.document.getElementById('pndcc-progress-list');
      var value = discovered > 0 ? Math.min(100, Math.round((collected / discovered) * 100)) : 0;
      if (phase === 'complete') value = 100;
      if (bar) bar.style.width = value + '%';
      if (pct) pct.textContent = value + '%';
      if (count) count.textContent = collected + ' of ' + discovered + ' page(s) collected';
      if (current) current.textContent = currentTitle ? 'Current: ' + currentTitle : 'Current: Preparing…';
      if (message) message.textContent = phase === 'complete' ? 'All pages collected. Preparing PDF…' : (phase === 'print' ? 'Opening print dialog…' : 'Collecting current PNDCC pages…');
      if (list && currentTitle) {
        var items = Array.prototype.slice.call(list.querySelectorAll('[data-page-name]'));
        var found = false;
        items.forEach(function(item) {
          if (item.getAttribute('data-page-name') === currentTitle) { item.innerHTML = '● ' + escapeHtml(currentTitle); item.style.fontWeight = '600'; found = true; }
        });
        if (!found) {
          var li = reportWindow.document.createElement('div');
          li.setAttribute('data-page-name', currentTitle);
          li.textContent = '● ' + currentTitle;
          li.style.fontWeight = '600';
          list.appendChild(li);
        }
      }
    } catch (e) {}
  }

  async function captureAllPNDCCPages() {
    closeScreenshotChoice();

    // IMPORTANT: open the report window immediately while this function still
    // has the user's click activation. Opening it after async fetch() calls can
    // cause Chrome to treat the popup as unsolicited and silently block it.
    var reportWindow = window.open('', '_blank');
    if (!reportWindow) {
      setStatus('PDF report was blocked. Allow pop-ups for PNDCC and try again.');
      return;
    }
    reportWindow.document.write('<!doctype html><html><head><meta charset="utf-8"><title>PNDCC All Pages — Preparing</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;padding:28px;color:#172033;background:#fff}.panel{max-width:760px;margin:30px auto}.bar{height:14px;background:#e7ecf3;border-radius:999px;overflow:hidden}.fill{height:100%;width:0;background:#2563eb;transition:width .25s ease}.pct{font-size:28px;font-weight:700;margin-top:12px}.muted{color:#667085}.current{margin-top:12px;font-weight:600}.message{margin-top:18px}.list{margin-top:18px;display:grid;gap:5px;font-size:13px;line-height:1.45}.hint{margin-top:18px;padding:10px 12px;background:#f7f9fc;border:1px solid #e1e7ef;border-radius:8px;font-size:12px;color:#667085}</style></head><body><main class="panel"><h2>PNDCC All Pages</h2><p class="muted">Preparing your complete PNDCC report</p><div class="bar"><div id="pndcc-progress-bar" class="fill"></div></div><div id="pndcc-progress-pct" class="pct">0%</div><div id="pndcc-progress-count" class="muted">0 pages collected</div><div id="pndcc-progress-current" class="current">Current: Starting…</div><div id="pndcc-progress-message" class="message">Collecting current PNDCC pages…</div><div id="pndcc-progress-list" class="list"></div><div class="hint">Please wait. PNDCC is collecting live pages before opening the PDF print dialog.</div></main></body></html>');
    reportWindow.document.close();
    setStatus('Discovering current PNDCC pages…');
    var startUrl = new URL('/', window.location.href).href;
    var queue = [startUrl], seen = new Set(), pages = [], failedPages = [];
    var excluded = /\/api\/|\/favicon|\.css(?:\?|$)|\.js(?:\?|$)|mailto:|javascript:/i;

    while (queue.length && seen.size < 100) {
      var url = queue.shift();
      var u = new URL(url, window.location.href);
      u.hash = '';
      if (u.origin !== window.location.origin || excluded.test(u.pathname) || seen.has(u.href)) continue;
      seen.add(u.href);

      updateAllPagesProgress(reportWindow, pages.length, Math.max(seen.size, pages.length + queue.length), u.pathname === '/' ? 'PNDCC' : u.pathname, 'collecting');
      setStatus('Collecting ' + (u.pathname === '/' ? 'PNDCC' : u.pathname) + '… ' + pages.length + ' page(s) collected.');

      try {
        // For the root dashboard, use the already-loaded live DOM instead of
        // fetching / again. This avoids the root request abort seen in Chrome
        // while preserving the same .wrap-based export path.
        var html;
        var isCurrentRoot = (u.pathname === '/' && window.location.pathname === '/' && u.origin === window.location.origin);
        if (isCurrentRoot) {
          html = '<!doctype html>' + document.documentElement.outerHTML;
        } else {
          // Apply the timeout to the ENTIRE page read, including response-body
          // consumption. Clearing the timer after fetch() headers arrive can
          // leave res.text() pending forever and freeze collection at e.g. 5/9.
          var controller = new AbortController();
          var fetchTimer = null;
          try {
            html = await Promise.race([
              (async function () {
                var res = await fetch(u.href, {credentials:'same-origin', cache:'no-store', signal:controller.signal});
                if (!res.ok) throw new Error('HTTP ' + res.status);
                if (!/text\/html/i.test(res.headers.get('content-type') || '')) throw new Error('Response was not HTML');
                return await res.text();
              })(),
              new Promise(function (_, reject) {
                fetchTimer = setTimeout(function () {
                  try { controller.abort(); } catch (e) {}
                  reject(new Error('Page timed out after 15 seconds; skipped so collection can continue'));
                }, 15000);
              })
            ]);
          } finally {
            if (fetchTimer !== null) clearTimeout(fetchTimer);
          }
        }
        var parsed = new DOMParser().parseFromString(html, 'text/html');
        var wrap = parsed.querySelector('.wrap');
        if (!wrap) throw new Error('Expected PNDCC page wrapper was not found');
        var title = (parsed.querySelector('h1') && parsed.querySelector('h1').textContent.trim()) || parsed.title || u.pathname;

        // IMPORTANT: All-Pages PDF no longer rasterizes this page through
        // SVG/foreignObject. Keep the actual PNDCC HTML and its inline styles.
        // This removes the browser-rendering deadlock seen on the dashboard.
        var clone = wrap.cloneNode(true);
        var cloneControls = clone.querySelector('.screenshot-controls');
        if (cloneControls) cloneControls.remove();
        addExportFooter(clone, parsed);
        clone.style.width = '100%';
        clone.style.maxWidth = 'none';
        clone.style.margin = '0';

        var styleText = '';
        parsed.querySelectorAll('style').forEach(function(node) {
          styleText += '<style>' + node.textContent + '</style>';
        });

        pages.push({
          url: u.href,
          title: title,
          html: styleText + clone.outerHTML,
          context: exportContextFor(parsed)
        });

        parsed.querySelectorAll('a[href]').forEach(function(a) {
          try {
            var next = new URL(a.getAttribute('href'), u.href);
            next.hash = '';
            if (next.origin === window.location.origin && !excluded.test(next.pathname) && !seen.has(next.href)) queue.push(next.href);
          } catch (e) {}
        });
      } catch (e) {
        failedPages.push({url: u.href, reason: String(e && e.message || e)});
        console.warn('PNDCC All Pages discovery failed:', u.href, e);
        updateAllPagesProgress(reportWindow, pages.length, Math.max(seen.size, pages.length + queue.length), u.pathname === '/' ? 'PNDCC' : u.pathname, 'collecting');
      }

      var discoveredCount = Math.max(seen.size, pages.length + queue.length);
      updateAllPagesProgress(reportWindow, pages.length, discoveredCount, title, 'collecting');
      setStatus('Preparing All PNDCC Pages… ' + pages.length + ' page(s) collected.');
    }

    var discoveryLimitReached = queue.length > 0 && seen.size >= 100;
    // Preserve the useful pages: one failed/slow route must not suppress the
    // entire PDF. The report window records skipped routes and still prints.
    if (failedPages.length || discoveryLimitReached) {
      var warningParts = [];
      if (failedPages.length) warningParts.push(failedPages.length + ' page(s) skipped after load/wrapper failure');
      if (discoveryLimitReached) warningParts.push('100-page safety limit reached; ' + queue.length + ' page(s) remain');
      var warningMessage = pages.length
        ? 'PARTIAL REPORT — ' + pages.length + ' page(s) collected; ' + warningParts.join('; ') + '. The PDF will still be generated.'
        : 'No PNDCC pages could be collected. Check the dashboard and retry.';
      if (reportWindow && !reportWindow.closed) {
        var warningStatus = reportWindow.document.getElementById('pndcc-progress-message');
        if (warningStatus) { warningStatus.textContent = warningMessage; warningStatus.style.color = pages.length ? '#9a6700' : '#b42318'; }
        var warningList = reportWindow.document.getElementById('pndcc-progress-list');
        if (warningList) {
          failedPages.forEach(function(item) {
            var li = reportWindow.document.createElement('div');
            li.textContent = 'SKIPPED: ' + new URL(item.url).pathname + ' — ' + item.reason;
            li.style.color = '#9a6700';
            warningList.appendChild(li);
          });
          if (discoveryLimitReached) {
            var cap = reportWindow.document.createElement('div');
            cap.textContent = 'LIMIT: ' + queue.length + ' additional page(s) were not processed.';
            cap.style.color = '#9a6700';
            warningList.appendChild(cap);
          }
        }
      }
      setStatus(warningMessage);
      if (!pages.length) return;
    }

    updateAllPagesProgress(reportWindow, pages.length, Math.max(pages.length, seen.size), '', 'complete');
    if (reportWindow && !reportWindow.closed) {
      var doneMessage = reportWindow.document.getElementById('pndcc-progress-message');
      if (doneMessage) doneMessage.textContent = failedPages.length || discoveryLimitReached
        ? 'Collected pages are ready. Some routes were skipped; preparing the available-pages PDF…'
        : 'All discovered PNDCC pages collected. Preparing PDF…';
    }

    if (!pages.length) {
      try { reportWindow.close(); } catch (e) {}
      setStatus('No PNDCC pages could be captured.');
      return;
    }

    finishAllPagesPdf(pages, reportWindow);
  }
  // Bind the main capture button directly after the screenshot module loads.
  // This avoids relying on an inline onclick handler and preserves all existing
  // screenshot functions/options.
  var captureButton = document.getElementById('pndcc-capture-button');
  if (captureButton) captureButton.addEventListener('click', openScreenshotChoice);

  window.capturePNDCCPage = capturePNDCCPage;
  window.openScreenshotChoice = openScreenshotChoice;
  window.openDocumentationChoice = openDocumentationChoice;
  window.closeDocumentationChoice = closeDocumentationChoice;
  // Removed stale export: generateDocumentationAndAllPages is not defined or used.
  // These three functions are called by inline onclick handlers in the
  // documentation selector. Explicitly expose them on window so the browser
  // can resolve the handlers reliably.
  window.generateDocumentationForSending = generateDocumentationForSending;
  window.generateDocumentationForArchive = generateDocumentationForArchive;
  window.generateAllPagesPdfOnly = generateAllPagesPdfOnly;
  window.closeScreenshotChoice = closeScreenshotChoice;
  window.captureAllPNDCCPages = captureAllPNDCCPages;
  window.savePNDCCScreenshot = saveAs;
  window.systemSharePNDCCScreenshot = systemShare;
  window.openPNDCCDestination = openDestination;
  window.copyPNDCCScreenshot = copyImage;
  window.saveAndSendLaterPNDCCScreenshot = saveAndSendLater;
  window.cancelPNDCCScreenshot = cancelScreenshot;
})();
</script>
"""


def page_shell(title, body):
    screenshot = """
    <section class='section screenshot-controls' aria-label='Screenshot controls'>
      <div class='section-head'><h2 class='section-title'>Screenshot</h2><span class='section-note'>Manual capture · no automatic screenshot</span></div>
      <div class='card'>
        <div class='small' style='margin-bottom:8px'>Screenshot controls ready · manual capture only</div>
        <button id='pndcc-capture-button' class='linkbtn' type='button'>📸 Capture Screenshot</button>
        <div id='pndcc-screenshot-status' class='screenshot-status'></div>
        <div id='pndcc-screenshot-choice' class='screenshot-choice'>
          <p><b>What would you like to capture?</b></p>
          <div class='screenshot-choice-actions'>
            <button class='primary' type='button' onclick='capturePNDCCPage()'>Current Page</button>
            <button type='button' onclick='openDocumentationChoice()'>All PNDCC Pages → PDF</button>
            <button type='button' onclick='closeScreenshotChoice()'>Cancel</button>
          </div>
        </div>
        <div id='pndcc-documentation-choice' class='screenshot-choice' style='display:none'>
          <p><b>PNDCC Documentation Set</b></p>
          <div class='small' style='margin-bottom:10px'>Select the documentation you want generated. Each selected set contains both DOCX and PDF.</div>
          <label style='display:block;margin:8px 0'><input type='checkbox' name='pndcc-doc-set' value='1'> <b>1.</b> PNDCC-01 — User Guide</label>
          <label style='display:block;margin:8px 0'><input type='checkbox' name='pndcc-doc-set' value='2'> <b>2.</b> PNDCC-02 — Technical Reference</label>
          <label style='display:block;margin:8px 0'><input type='checkbox' name='pndcc-doc-set' value='3'> <b>3.</b> PNDCC-03 — Admin &amp; Diagnostics Runbook</label>
          <label style='display:block;margin:12px 0;font-weight:600'><input type='checkbox' id='pndcc-doc-all'> Select all 3 documentation sets</label>
          <div class='screenshot-choice-actions'>
            <button class='primary' type='button' onclick='generateDocumentationForSending()'>Generate ZIP · Send / Store</button>
            <button type='button' onclick='generateDocumentationForArchive()'>Generate + Archive</button>
            <button type='button' onclick='generateAllPagesPdfOnly()'>All PNDCC Pages → PDF</button>
            <button type='button' onclick='closeDocumentationChoice()'>Cancel</button>
          </div>
          <div class='small' style='margin-top:10px;color:#667085'>Send / Store downloads one ZIP containing exactly the selected DOCX/PDF files. Generate + Archive also saves a dated copy locally under the PNDCC app archive.</div>
        </div>
        <div id='pndcc-screenshot-preview' class='screenshot-preview' style='display:none'>
          <img id='pndcc-screenshot-image' class='screenshot-image' alt='PNDCC screenshot preview'>
          <input id='pndcc-svg-source' type='hidden'>
          <div class='screenshot-actions'>
            <button class='linkbtn' type='button' onclick="document.getElementById('pndcc-save-menu').style.display='flex'">Save</button>
            <button class='linkbtn' type='button' onclick="document.getElementById('pndcc-share-menu').style.display='flex'">Share / Send</button>
            <button class='linkbtn' type='button' onclick='cancelPNDCCScreenshot()'>Cancel</button>
          </div>
          <div id='pndcc-save-menu' class='screenshot-menu' style='display:none'>
            <strong>Choose format</strong>
            <button onclick="savePNDCCScreenshot('png')">PNG</button>
            <button onclick="savePNDCCScreenshot('jpeg')">JPEG / JPG</button>
            <button onclick="savePNDCCScreenshot('webp')">WebP</button>
            <button onclick="savePNDCCScreenshot('svg')">SVG</button>
            <button onclick="savePNDCCScreenshot('pdf')">PDF</button>
            <button onclick="this.parentElement.style.display='none'">Back</button>
          </div>
          <div id='pndcc-share-menu' class='screenshot-menu' style='display:none'>
            <strong>Choose how to share / send</strong>
            <button onclick='systemSharePNDCCScreenshot()'>System Share</button>
            <button onclick='copyPNDCCScreenshot()'>Copy Image</button>
            <button onclick='saveAndSendLaterPNDCCScreenshot()'>Save &amp; Send Later</button>
            <button onclick="openPNDCCDestination('whatsapp')">WhatsApp</button>
            <button onclick="openPNDCCDestination('messages')">Messages</button>
            <button onclick="openPNDCCDestination('gmail')">Gmail</button>
            <button onclick="openPNDCCDestination('yahoo')">Yahoo Mail</button>
            <button onclick="openPNDCCDestination('email')">Mail</button>
            <button onclick="this.parentElement.style.display='none'">Cancel</button>
          </div>
          <div class='screenshot-note'>Screenshot is created locally. Save supports PNG, JPEG/JPG, WebP, SVG, and PDF (browser print → Save as PDF). Share / Send uses the native share system when available, plus direct destinations, Copy Image, and Save &amp; Send Later. Web destinations may require attaching the PNG that PNDCC creates automatically.</div>
        </div>
      </div>
    </section>
    """
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><meta http-equiv='refresh' content='30'><title>{esc(title)}</title><style>{CSS}</style></head><body><div class='wrap'><header class='topbar'><div class='brand'><a class='logo' href='/' aria-label='PNDCC Dashboard' title='Return to Dashboard'>N</a><div><h1>PNDCC</h1><div class='subtitle'>Personal Network &amp; Device Command Center · Version 2.6.3</div></div></div><div class='actions'><span class='live'>● LIVE MONITOR</span><button class='refresh' onclick='location.reload()'>↻ Refresh now</button></div></header>{body}{screenshot}<footer class='foot'>Local-only dashboard · 30-second refresh · persistent CSV history · © Saiful Quadir · PNDCC v2.6.3</footer></div>{PNDCC_SCREENSHOT_JS}</body></html>"""


def dashboard():
    results = check_all()
    log_alerts(results)
    x = {r["target_id"]: r for r in results}
    ftp = ftp_check()
    log_ftp(ftp)

    personal = personal_devices()
    # v1.6: headline uses the complete six-device personal inventory.
    # Offline/resting devices remain visible in the device section but are
    # not treated as missing from the inventory.
    online = sum(1 for d in personal if x.get(d.get("id"), {}).get("status") == "ONLINE")
    alerts = sum(1 for r in results if r.get("status") in {"WARNING", "CRITICAL", "OFFLINE"})
    hs = health_summary(results)
    recent = list(reversed(recent_alerts(5)))

    cards = []
    for d in personal:
        cards.append(device_card(d, x.get(d.get("id"), {"status": "NOT CHECKED", "latency_ms": "—", "packet_loss_pct": "—"})))

    rr = next((r for r in results if r.get("target_id") == "router"), None)
    router_status = rr.get("status", "NOT CHECKED") if rr else "NOT CHECKED"

    inet_ip = SET.get("internet_check_ip", "8.8.8.8")
    inet = ping(inet_ip)
    internet_status = status(*inet)

    ftpcls = ftp.get("status", "NOT CONFIGURED").replace(" ", "-")
    body = f"""
    <section class='hero'>
      <div class='hero-head'><div><h2>Network overview</h2><p>At-a-glance status of connected devices and services.</p></div><div class='small' style='color:#d8e3ff'>Auto-refresh: 30 seconds</div></div>
      <div class='kpis'>
        <div class='kpi'><div class='kpi-label'>ACTIVE DEVICES ONLINE</div><div class='kpi-value'>{online}/{len(personal)}</div></div>
        <div class='kpi'><div class='kpi-label'>ROUTER</div><div class='kpi-value {esc(router_status)}'>{esc(router_status)}</div></div>
        <div class='kpi'><div class='kpi-label'>INTERNET</div><div class='kpi-value {esc(internet_status)}'>{esc(internet_status)}</div></div>
        <div class='kpi'><div class='kpi-label'>FTP / FTPS</div><div class='kpi-value {esc(ftpcls)}'>{esc(ftp.get('status'))}</div></div>
        <div class='kpi'><div class='kpi-label'>ACTIVE ALERTS</div><div class='kpi-value'>{alerts}</div></div>
      </div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Network devices</h2><span class='section-note'>Latest ping result</span></div><div class='grid'>{''.join(cards) or '<div class="notice">No enabled personal devices found.</div>'}</div></section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Network health</h2><span class='section-note'>Current monitoring snapshot</span></div>
      <div class='card'><div class='metric-label'>ONLINE RATIO</div><div class='kpi-value'>{hs["health_pct"]}%</div><div class='bar'><span style='width:{hs["health_pct"]}%'></span></div><div class='small'>Online {hs["counts"]["ONLINE"]} · Warning {hs["counts"]["WARNING"]} · Critical {hs["counts"]["CRITICAL"]} · Offline {hs["counts"]["OFFLINE"]}</div></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Active alerts</h2><span class='section-note'>Latest recorded events</span></div>
      <div class='card'><div class='alert-list'>{''.join(f"<div class='alert-item'><span class='pill {esc(a.get('status',''))}'>{esc(a.get('status',''))}</span><div class='message'><b>{esc(a.get('name','Device'))}</b><div class='meta'>{esc(a.get('message',''))} · {esc(a.get('ip',''))}</div></div><span class='meta'>{esc(a.get('timestamp',''))}</span></div>" for a in recent) or '<div class="notice">No active alert events recorded.</div>'}</div><div class='nav' style='margin-top:12px'><a href='/alerts'>Open alert history →</a></div></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>FTP monitor</h2><span class='section-note'>Actual service handshake</span></div>
      <div class='card ftp-card'><div class='ftp-main'><h3>{esc(FTP_HOST or 'FTP host not configured')}</h3><div class='small'>Mode: {esc(ftp.get('mode', FTP_MODE.upper()))} · Port {esc(FTP_PORT)}</div><div class='ftp-status {esc(ftpcls)}'>{esc(ftp.get('status'))}</div></div><div><div class='metric-label'>Connection latency</div><div class='metric-value'>{esc(ftp.get('latency_ms'))}</div></div><div><div class='metric-label'>Test</div><div class='metric-value'>{esc(ftp.get('test'))}</div></div></div>
    </section>
    {storage_cloud_sections()}
    <section class='section'><div class='section-head'><h2 class='section-title'>Control Center</h2><span class='section-note'>Phase 2 · safe file access</span></div><div class='card'><div class='nav'><a href='/device-control'>Open Device Control →</a><a href='/network-diagnostics'>Open Network Diagnostics →</a><a href='/history'>Open device history →</a><a href='/ftp-history'>Open FTP history →</a><a href='/api/status'>JSON status →</a></div></div></section>
    """
    return page_shell("PNDCC v1.7", body)


def history_page():
    devices = personal_devices()
    selected = urllib.parse.parse_qs(urllib.parse.urlparse("/" + os.environ.get("PNDCC_DUMMY", "")).query).get("device", [""])[0]
    # The actual selection is supplied by the request handler through query
    # parsing; this fallback keeps the renderer simple.
    if not selected and devices:
        selected = devices[0].get("id", "")

    d = next((d for d in devices if d.get("id") == selected), None)
    rows = read_device_history(selected, 40) if selected else []
    summary = history_summary(selected) if selected else {"samples": 0, "online": 0, "avg_latency": None, "avg_loss": None}

    options = []
    for dev in devices:
        did = urllib.parse.quote(str(dev.get("id", "")), safe="")
        label = esc(dev.get("name", dev.get("id", "Device")))
        options.append(f"<a class='linkbtn' href='/history?device={did}'>{label}</a>")

    table_rows = []
    for r in reversed(rows):
        table_rows.append(f"<tr><td>{esc(r.get('timestamp'))}</td><td>{esc(r.get('status'))}</td><td>{esc(r.get('latency_ms') or '—')}</td><td>{esc(r.get('packet_loss_pct') or '—')}</td></tr>")

    selected_name = d.get("name", selected) if d else "Device history"
    body = f"""
    <section class='section'><div class='section-head'><h2 class='section-title'>Device history</h2><span class='section-note'>{esc(selected_name)}</span></div>
      <div class='card'><div class='nav'>{''.join(options)}</div></div>
    </section>
    <section class='section'><div class='grid'>
      <div class='card'><div class='metric-label'>SAMPLES</div><div class='kpi-value'>{summary['samples']}</div></div>
      <div class='card'><div class='metric-label'>ONLINE SAMPLES</div><div class='kpi-value'>{summary['online']}</div></div>
      <div class='card'><div class='metric-label'>AVERAGE LATENCY</div><div class='kpi-value'>{summary['avg_latency'] if summary['avg_latency'] is not None else '—'}{' ms' if summary['avg_latency'] is not None else ''}</div></div>
      <div class='card'><div class='metric-label'>AVERAGE PACKET LOSS</div><div class='kpi-value'>{summary['avg_loss'] if summary['avg_loss'] is not None else '—'}{'%' if summary['avg_loss'] is not None else ''}</div></div>
    </div></section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Latency trend</h2><span class='section-note'>Recent samples</span></div><div class='card'>{latency_chart(rows)}</div></section>
    <section class='section'><div class='card table-wrap'><table class='table'><thead><tr><th>TIME</th><th>STATUS</th><th>LATENCY MS</th><th>PACKET LOSS %</th></tr></thead><tbody>{''.join(table_rows) or '<tr><td colspan="4">No history recorded yet.</td></tr>'}</tbody></table></div></section>
    <section class='section'><div class='card'><div class='nav'><a href='/'>← Dashboard</a></div></div></section>
    """
    return page_shell("PNDCC Device History", body)


def alerts_page():
    rows = list(reversed(recent_alerts(100)))
    trs = []
    for r in rows:
        trs.append(f"<tr><td>{esc(r.get('timestamp'))}</td><td>{esc(r.get('name'))}</td><td>{esc(r.get('ip'))}</td><td>{esc(r.get('status'))}</td><td>{esc(r.get('latency_ms') or '—')}</td><td>{esc(r.get('packet_loss_pct') or '—')}</td><td>{esc(r.get('message'))}</td></tr>")
    body = f"""<section class='section'><div class='section-head'><h2 class='section-title'>Alert history</h2><span class='section-note'>Latest 100 events</span></div><div class='card table-wrap'><table class='table'><thead><tr><th>TIME</th><th>DEVICE</th><th>IP</th><th>STATUS</th><th>LATENCY</th><th>LOSS</th><th>EVENT</th></tr></thead><tbody>{''.join(trs) or '<tr><td colspan="7">No alert history recorded yet.</td></tr>'}</tbody></table></div></section><section class='section'><div class='card'><div class='nav'><a href='/'>← Dashboard</a></div></div></section>"""
    return page_shell("PNDCC Alert History", body)


def ftp_history_page():
    rows = recent_ftp_history(40)
    trs = []
    for r in reversed(rows):
        trs.append(f"<tr><td>{esc(r.get('timestamp'))}</td><td>{esc(r.get('host'))}</td><td>{esc(r.get('port'))}</td><td>{esc(r.get('mode'))}</td><td>{esc(r.get('status'))}</td><td>{esc(r.get('latency_ms'))}</td><td>{esc(r.get('test'))}</td></tr>")
    body = f"""
    <section class='section'><div class='section-head'><h2 class='section-title'>FTP / FTPS history</h2><span class='section-note'>Latest 40 checks</span></div>
      <div class='card table-wrap'><table class='table'><thead><tr><th>TIME</th><th>HOST</th><th>PORT</th><th>MODE</th><th>STATUS</th><th>LATENCY</th><th>TEST</th></tr></thead><tbody>{''.join(trs) or '<tr><td colspan="7">No FTP history recorded yet.</td></tr>'}</tbody></table></div>
    </section><section class='section'><div class='card'><div class='nav'><a href='/'>← Dashboard</a></div></div></section>
    """
    return page_shell("PNDCC FTP History", body)

# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/device-control":
            self._send_text(404, "PNDCC 404 - Not Found")
            return
        params = urllib.parse.parse_qs(parsed.query)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > PNDCC_UPLOAD_MAX_BYTES + 1024 * 1024:
                self._send_text(400, "Invalid request size")
                return
            body = self.rfile.read(length)
            ctype = self.headers.get("Content-Type", "")
            if ctype.lower().startswith("multipart/form-data"):
                filename, data = _parse_multipart_upload(body, ctype)
                form = urllib.parse.parse_qs(body.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")) if False else {}
                # The upload folder is supplied as a small hidden field.
                m = re.search(rb'name="path"\r\n\r\n([^\r\n]+)', body)
                remote_dir = m.group(1).decode("utf-8", "replace") if m else "/"
                remote_dir = _clean_remote_path(remote_dir)
                if len(data) > PNDCC_UPLOAD_MAX_BYTES:
                    raise ValueError("Upload exceeds the 100 MB Phase 2B limit")
                remote_path = _join_remote_path(remote_dir, filename)
                _ftp_upload_bytes(remote_path, data)
                body_html = _device_control_result_page(f"Upload successful: {filename} ({_format_bytes(len(data))})", remote_dir, True)
            else:
                form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
                action = form.get("action", [""])[0]
                remote_path = _clean_remote_path(form.get("path", ["/"])[0])
                if action == "mkdir":
                    name = form.get("name", [""])[0].strip()
                    if not name or "/" in name or "\\" in name:
                        raise ValueError("Folder name must be a single name")
                    target = _join_remote_path(remote_path, name)
                    _ftp_make_directory(target)
                    body_html = _device_control_result_page(f"Folder created: {target}", remote_path, True)
                elif action == "rename":
                    name = form.get("name", [""])[0].strip()
                    _ftp_rename(remote_path, name)
                    body_html = _device_control_result_page(f"Rename successful: {os.path.basename(remote_path)} → {name}", "/".join(remote_path.rstrip("/").split("/")[:-1]) or "/", True)
                elif action == "delete":
                    kind = form.get("kind", ["file"])[0]
                    _ftp_delete_item(remote_path, kind == "directory")
                    parent = "/".join(remote_path.rstrip("/").split("/")[:-1]) or "/"
                    body_html = _device_control_result_page(f"Deleted {kind}: {os.path.basename(remote_path)}", parent, True)
                elif action == "move":
                    destination_dir = form.get("destination", [""])[0]
                    _ftp_move_item(remote_path, destination_dir)
                    parent = "/".join(remote_path.rstrip("/").split("/")[:-1]) or "/"
                    body_html = _device_control_result_page(f"Moved: {os.path.basename(remote_path)} → {_clean_remote_path(destination_dir)}", parent, True)
                elif action == "copy":
                    destination_dir = form.get("destination", [""])[0]
                    new_name = form.get("name", [""])[0]
                    _ftp_copy_file(remote_path, destination_dir, new_name)
                    body_html = _device_control_result_page(f"Copied: {os.path.basename(remote_path)} → {_clean_remote_path(destination_dir)}", _clean_remote_path(destination_dir), True)
                else:
                    self._send_text(400, "Unsupported Phase 2C action")
                    return
            data_out = body_html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data_out)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data_out)
        except Exception as e:
            try:
                self._send_text(500, f"PNDCC Phase 2B error: {type(e).__name__}: {e}")
            except Exception:
                pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        try:
            if path == "/":
                body = dashboard()
            elif path == "/device-control":
                body = device_control_page(params.get("path", [""])[0])
            elif path == "/device-control-rename":
                body = device_control_rename_page(params.get("path", [""])[0])
            elif path == "/download":
                remote_path = params.get("path", [""])[0]
                if not remote_path:
                    self._send_text(400, "Missing file path")
                    return
                self._send_ftp_download(remote_path)
                return
            elif path == "/open-file":
                remote_path = params.get("path", [""])[0]
                if not remote_path:
                    self._send_text(400, "Missing file path")
                    return
                result = open_remote_file(remote_path)
                self._send_json(result)
                return
            elif path == "/network-diagnostics":
                body = network_diagnostics_page()
            elif path == "/history":
                # Render the requested device directly instead of relying on
                # global state.
                device_id = params.get("device", [""])[0]
                devices = personal_devices()
                if not device_id and devices:
                    device_id = devices[0].get("id", "")
                d = next((x for x in devices if x.get("id") == device_id), None)
                rows = read_device_history(device_id, 40) if device_id else []
                summary = history_summary(device_id) if device_id else {"samples":0,"online":0,"avg_latency":None,"avg_loss":None}
                options = [f"<a class='linkbtn' href='/history?device={urllib.parse.quote(str(x.get('id','')),safe='')}'>{esc(x.get('name','Device'))}</a>" for x in devices]
                trs = [f"<tr><td>{esc(r.get('timestamp'))}</td><td>{esc(r.get('status'))}</td><td>{esc(r.get('latency_ms') or '—')}</td><td>{esc(r.get('packet_loss_pct') or '—')}</td></tr>" for r in reversed(rows)]
                body_html = f"""
                <section class='section'><div class='section-head'><h2 class='section-title'>Device history</h2><span class='section-note'>{esc(d.get('name',device_id) if d else 'Select a device')}</span></div><div class='card'><div class='nav'>{''.join(options)}</div></div></section>
                <section class='section'><div class='grid'><div class='card'><div class='metric-label'>SAMPLES</div><div class='kpi-value'>{summary['samples']}</div></div><div class='card'><div class='metric-label'>ONLINE SAMPLES</div><div class='kpi-value'>{summary['online']}</div></div><div class='card'><div class='metric-label'>AVG LATENCY</div><div class='kpi-value'>{summary['avg_latency'] if summary['avg_latency'] is not None else '—'}{' ms' if summary['avg_latency'] is not None else ''}</div></div><div class='card'><div class='metric-label'>AVG PACKET LOSS</div><div class='kpi-value'>{summary['avg_loss'] if summary['avg_loss'] is not None else '—'}{'%' if summary['avg_loss'] is not None else ''}</div></div></div></section>
                <section class='section'><div class='card table-wrap'><table class='table'><thead><tr><th>TIME</th><th>STATUS</th><th>LATENCY MS</th><th>PACKET LOSS %</th></tr></thead><tbody>{''.join(trs) or '<tr><td colspan="4">No history recorded yet.</td></tr>'}</tbody></table></div></section>
                <section class='section'><div class='card'><div class='nav'><a href='/'>← Dashboard</a></div></div></section>"""
                body = page_shell("PNDCC Device History", body_html)
            elif path == "/ftp-history":
                body = ftp_history_page()
            elif path == "/alerts":
                body = alerts_page()
            elif path == "/health":
                self._send_text(200, "PNDCC OK")
                return
            elif path == "/api/network-diagnostics":
                self._send_json(_network_diagnostics())
                return
            elif path == "/api/status":
                rows = check_all()
                ftp = ftp_check()
                log_ftp(ftp)
                payload = {
                    "version": PNDCC_VERSION,
                    "timestamp": now(),
                    "devices": rows,
                    "ftp": ftp,
                    "storage": storage_items(),
                    "cloud": cloud_items(),
                }
                self._send_json(payload)
                return
            elif path == "/api/history":
                device_id = params.get("device", [""])[0]
                payload = {"device": device_id, "rows": read_device_history(device_id, 100)}
                self._send_json(payload)
                return
            else:
                self._send_text(404, "PNDCC 404 - Not Found")
                return

            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._send_text(500, f"PNDCC server error: {type(e).__name__}")

    def _send_text(self, code, text):
        data = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_ftp_download(self, remote_path):
        """Download one remote FTP/FTPS file to the browser safely."""
        remote_path = _clean_remote_path(remote_path)
        if remote_path == "/":
            self._send_text(400, "A directory cannot be downloaded as a file")
            return

        client = None
        temp_path = None
        try:
            name = os.path.basename(remote_path) or "download"
            fd, temp_path = tempfile.mkstemp(prefix="pndcc_", suffix=".download")
            os.close(fd)

            client = _ftp_client_for_control()
            with open(temp_path, "wb") as f:
                client.retrbinary("RETR " + remote_path, f.write)

            size = os.path.getsize(temp_path)
            content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", "attachment; filename=\"" + name.replace('"', '_') + "\"")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with open(temp_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 64)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except Exception as e:
            try:
                self._send_text(500, f"PNDCC download error: {type(e).__name__}")
            except Exception:
                pass
        finally:
            _close_ftp_client(client)
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    def _send_json(self, payload):
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass



# ---------------------------------------------------------------------------
# Phase 2 — Device Control Center (read-only first)
# ---------------------------------------------------------------------------
# This section is intentionally isolated from monitoring, storage, cloud,
# alerts, and diagnostics. Phase 2A provides safe FTP/FTPS browsing,
# downloading, and optional opening of a downloaded file on the Mac.
# No remote write, rename, move, or delete operations are enabled yet.


def _ftp_client_for_control():
    """Create and authenticate an FTP/FTPS client for Device Control."""
    if not FTP_HOST:
        raise RuntimeError("FTP host is not configured")

    if FTP_MODE == "ftps":
        # Phase 2A: FileZilla on the local LAN uses a self-signed
        # certificate. Accept it only for this read-only Device Control
        # connection. Existing FTP/FTPS monitoring is intentionally unchanged.
        control_tls_context = ssl._create_unverified_context()
        client = PNDCC_FTP_TLS(context=control_tls_context)
        client.connect(FTP_HOST, FTP_PORT, timeout=FTP_TIMEOUT)
        client.auth()
        client.prot_p()
    else:
        client = FTP()
        client.connect(FTP_HOST, FTP_PORT, timeout=FTP_TIMEOUT)

    _ftp_login(client)
    return client


def _close_ftp_client(client):
    if client is None:
        return
    try:
        client.quit()
    except Exception:
        try:
            client.close()
        except Exception:
            pass


def _clean_remote_path(path):
    """Normalize a browser path without allowing parent traversal."""
    path = urllib.parse.unquote(str(path or "")).replace("\\", "/")
    parts = []
    for part in path.split("/"):
        part = part.strip()
        if not part or part == ".":
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


def _join_remote_path(base, name):
    base = _clean_remote_path(base)
    name = str(name or "").replace("\\", "/").strip("/")
    return _clean_remote_path(base.rstrip("/") + "/" + name)


def _ftp_list_directory(remote_path):
    """Return simple directory entries using MLSD, with LIST fallback."""
    remote_path = _clean_remote_path(remote_path)
    client = None
    try:
        client = _ftp_client_for_control()
        client.cwd(remote_path)
        actual_path = client.pwd()
        entries = []

        try:
            for name, facts in client.mlsd():
                if name in {".", ".."}:
                    continue
                kind = facts.get("type", "file")
                if kind == "cdir":
                    continue
                entries.append({
                    "name": name,
                    "type": "directory" if kind == "dir" else "file",
                    "size": int(facts.get("size", 0) or 0),
                    "modified": facts.get("modify", ""),
                })
        except Exception:
            lines = []
            client.retrlines("LIST", lines.append)
            for line in lines:
                # Unix-style FileZilla listing fallback.
                m = re.match(r"^([d-])[^ ]*\s+\S+\s+\S+\s+(\d+)\s+(.{12})\s+(.+)$", line)
                if m:
                    entries.append({
                        "name": m.group(4).strip(),
                        "type": "directory" if m.group(1) == "d" else "file",
                        "size": int(m.group(2)),
                        "modified": m.group(3).strip(),
                    })

        entries.sort(key=lambda x: (x.get("type") != "directory", x.get("name", "").lower()))
        return {"ok": True, "path": actual_path, "entries": entries}
    finally:
        _close_ftp_client(client)


def _ftp_download_bytes(remote_path):
    """Read one remote file into memory for a controlled local download."""
    remote_path = _clean_remote_path(remote_path)
    if remote_path == "/":
        raise ValueError("A directory cannot be downloaded as a file")

    client = None
    chunks = []
    try:
        client = _ftp_client_for_control()
        client.retrbinary("RETR " + remote_path, chunks.append)
        return b"".join(chunks)
    finally:
        _close_ftp_client(client)


def open_remote_file(remote_path):
    """Download a remote file to a temporary Mac file and open it."""
    remote_path = _clean_remote_path(remote_path)
    name = os.path.basename(remote_path) or "remote_file"
    safe_name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)
    try:
        data = _ftp_download_bytes(remote_path)
        temp_dir = os.path.join("/tmp", "PNDCC_Device_Control")
        os.makedirs(temp_dir, exist_ok=True)
        local_path = os.path.join(temp_dir, safe_name)
        with open(local_path, "wb") as f:
            f.write(data)
        if platform.system() == "Darwin":
            subprocess.Popen(["/usr/bin/open", local_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"ok": True, "message": "File downloaded and opened on the Mac", "local_path": local_path, "bytes": len(data)}
    except Exception as e:
        return {"ok": False, "message": f"{type(e).__name__}: {e}"}


def _format_bytes(value):
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "—"
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return "—"



# ---------------------------------------------------------------------------
# Phase 2B — controlled remote write operations
# ---------------------------------------------------------------------------
# Phase 2B adds only Upload, Create Folder, and Rename. Delete/Move/Copy are
# intentionally not implemented yet. All operations use the same isolated
# Device Control FTPS client, including the local FileZilla certificate rule.

PNDCC_UPLOAD_MAX_BYTES = 100 * 1024 * 1024


def _ftp_upload_bytes(remote_path, data):
    """Upload one file to the remote FTP/FTPS server."""
    remote_path = _clean_remote_path(remote_path)
    if remote_path == "/":
        raise ValueError("A file path is required")
    name = os.path.basename(remote_path)
    if not name or name in {".", ".."}:
        raise ValueError("Invalid file name")
    client = None
    try:
        client = _ftp_client_for_control()
        client.storbinary("STOR " + remote_path, __import__("io").BytesIO(data))
    finally:
        _close_ftp_client(client)


def _ftp_make_directory(remote_path):
    """Create one remote directory."""
    remote_path = _clean_remote_path(remote_path)
    if remote_path == "/":
        raise ValueError("Cannot create the root directory")
    client = None
    try:
        client = _ftp_client_for_control()
        client.mkd(remote_path)
    finally:
        _close_ftp_client(client)


def _ftp_rename(remote_path, new_name):
    """Rename one remote file/folder within its current directory only."""
    remote_path = _clean_remote_path(remote_path)
    new_name = str(new_name or "").strip().replace("\\", "/")
    if remote_path == "/":
        raise ValueError("The root directory cannot be renamed")
    if not new_name or "/" in new_name or new_name in {".", ".."}:
        raise ValueError("New name must be a single file or folder name")
    parent = _clean_remote_path("/".join(remote_path.rstrip("/").split("/")[:-1]))
    destination = _join_remote_path(parent, new_name)
    if destination == remote_path:
        raise ValueError("The new name is the same as the current name")
    client = None
    try:
        client = _ftp_client_for_control()
        client.rename(remote_path, destination)
    finally:
        _close_ftp_client(client)


def _ftp_delete_item(remote_path, is_directory=False):
    """Delete a file or an empty directory only."""
    remote_path = _clean_remote_path(remote_path)
    if remote_path == "/":
        raise ValueError("The remote root cannot be deleted")
    client = None
    try:
        client = _ftp_client_for_control()
        if is_directory:
            client.rmd(remote_path)  # FTP RMD rejects non-empty folders
        else:
            client.delete(remote_path)
    finally:
        _close_ftp_client(client)


def _ftp_move_item(remote_path, destination_dir):
    """Move an item into an existing remote directory; never overwrite."""
    remote_path = _clean_remote_path(remote_path)
    destination_dir = _clean_remote_path(destination_dir)
    if remote_path == "/":
        raise ValueError("The remote root cannot be moved")
    name = os.path.basename(remote_path)
    destination = _join_remote_path(destination_dir, name)
    if destination == remote_path:
        raise ValueError("The item is already in that folder")
    client = None
    try:
        client = _ftp_client_for_control()
        client.cwd(destination_dir)
        names = client.nlst()
        if name in [os.path.basename(n.rstrip("/")) for n in names]:
            raise FileExistsError("An item with that name already exists in the destination")
        client.rename(remote_path, destination)
    finally:
        _close_ftp_client(client)


def _ftp_copy_file(remote_path, destination_dir, new_name=""):
    """Copy a remote file to an existing directory; folders are not recursive."""
    remote_path = _clean_remote_path(remote_path)
    destination_dir = _clean_remote_path(destination_dir)
    if remote_path == "/":
        raise ValueError("Select a file to copy")
    name = str(new_name or os.path.basename(remote_path)).strip().replace("\\", "/")
    if not name or "/" in name or name in {".", ".."}:
        raise ValueError("Copy name must be a single file name")
    destination = _join_remote_path(destination_dir, name)
    if destination == remote_path:
        raise ValueError("Source and destination are the same")
    client = None
    try:
        client = _ftp_client_for_control()
        client.cwd(destination_dir)
        names = client.nlst()
        if name in [os.path.basename(n.rstrip("/")) for n in names]:
            raise FileExistsError("A file with that name already exists in the destination")
        chunks = []
        client.retrbinary("RETR " + remote_path, chunks.append)
        data = b"".join(chunks)
        if len(data) > PNDCC_UPLOAD_MAX_BYTES:
            raise ValueError("Copy is limited to 100 MB")
        client.storbinary("STOR " + destination, __import__("io").BytesIO(data))
    finally:
        _close_ftp_client(client)


def _parse_multipart_upload(body, content_type):
    """Extract a single file field from a multipart/form-data request."""
    match = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', content_type or "", re.I)
    if not match:
        raise ValueError("Upload boundary is missing")
    boundary = (match.group(1) or match.group(2)).encode("utf-8")
    delimiter = b"--" + boundary
    parts = body.split(delimiter)
    for part in parts:
        if b"Content-Disposition:" not in part:
            continue
        header, sep, data = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        disposition = header.decode("utf-8", "replace")
        fm = re.search(r'filename="([^"]*)"', disposition, re.I)
        if not fm:
            continue
        filename = os.path.basename(fm.group(1).replace("\\", "/")).strip()
        if not filename:
            raise ValueError("Upload file name is missing")
        if data.endswith(b"\r\n"):
            data = data[:-2]
        return filename, data
    raise ValueError("No upload file was supplied")


def _device_control_result_page(message, remote_path="/", ok=True):
    safe_message = esc(message)
    title = "Phase 2B Complete" if ok else "Phase 2B Error"
    body = f"""
    <section class='hero'>
      <div class='hero-head'><div><h2>{title}</h2><p>Device Control Center · Phase 2B</p></div><div class='small' style='color:#d8e3ff'>Windows / FTP · {esc(FTP_HOST or 'Not configured')}</div></div>
    </section>
    <section class='section'><div class='card'>
      <div class='alert'>{safe_message}</div>
      <div class='nav' style='margin-top:14px'><a href='/device-control?path={urllib.parse.quote(_clean_remote_path(remote_path), safe='')}'>← Back to Device Control</a></div>
    </div></section>
    """
    body += """<script>
function renameRemote(path){
  const name = prompt("Enter the new name:");
  if (!name) return false;
  if (name.includes("/") || name.includes("\\")) { alert("Use a single file or folder name."); return false; }
  const form = document.createElement("form"); form.method="POST"; form.action="/device-control";
  [["action","rename"],["path",path],["name",name]].forEach(([k,v])=>{const i=document.createElement("input");i.type="hidden";i.name=k;i.value=v;form.appendChild(i);});
  document.body.appendChild(form); form.submit(); return false;
}
</script>"""
    return page_shell("PNDCC Device Control Center", body)


def device_control_rename_page(remote_path="/"):
    """Show a simple server-side rename form; no JavaScript required."""
    remote_path = _clean_remote_path(remote_path)
    if remote_path == "/":
        return _device_control_result_page("The root directory cannot be renamed.", "/", False)
    current_name = os.path.basename(remote_path)
    parent = _clean_remote_path("/".join(remote_path.rstrip("/").split("/")[:-1]))
    qparent = urllib.parse.quote(parent, safe="")
    body = f"""
    <section class='hero'>
      <div class='hero-head'><div><h2>Rename Remote Item</h2><p>Device Control Center · Phase 2B</p></div><div class='small' style='color:#d8e3ff'>Windows / FTP · {esc(FTP_HOST or 'Not configured')}</div></div>
    </section>
    <section class='section'><div class='card'>
      <div class='small'>Current name</div>
      <div style='font-size:20px;font-weight:600;margin:6px 0 18px'>{esc(current_name)}</div>
      <form method='POST' action='/device-control' onsubmit='return confirm("Rename this remote item?")'>
        <input type='hidden' name='action' value='rename'>
        <input type='hidden' name='path' value='{esc(remote_path)}'>
        <input name='name' value='{esc(current_name)}' maxlength='120' required style='min-width:280px;padding:8px'>
        <button class='linkbtn' type='submit'>Rename</button>
      </form>
      <div class='small' style='margin-top:14px'>Enter one file or folder name only. The item stays in its current folder.</div>
      <div class='nav' style='margin-top:14px'><a href='/device-control?path={qparent}'>← Cancel / Back</a></div>
    </div></section>
    """
    return page_shell("PNDCC Rename Remote Item", body)


def device_control_page(remote_path="/"):
    remote_path = _clean_remote_path(remote_path)
    try:
        listing = _ftp_list_directory(remote_path)
        entries = listing.get("entries", [])
        actual_path = listing.get("path", remote_path)
        error = ""
    except Exception as e:
        entries = []
        actual_path = remote_path
        error = f"{type(e).__name__}: {e}"

    rows = []
    if actual_path != "/":
        parent = _clean_remote_path("/".join(actual_path.rstrip("/").split("/")[:-1]))
        rows.append(f"<tr><td>📁</td><td><a href='/device-control?path={urllib.parse.quote(parent, safe='')}'>.. (Parent)</a></td><td>Directory</td><td>—</td></tr>")

    for item in entries:
        name = item.get("name", "")
        kind = item.get("type", "file")
        path = _join_remote_path(actual_path, name)
        qpath = urllib.parse.quote(path, safe="")
        rename_href = f"/device-control-rename?path={qpath}"
        if kind == "directory":
            actions = f"<a class='linkbtn' href='/device-control?path={qpath}'>Open</a> "
            actions += f"<a class='linkbtn' href='{rename_href}'>Rename</a> "
            actions += f"<form method='POST' action='/device-control' style='display:inline' onsubmit='return confirm(\"Delete this empty folder?\")'><input type='hidden' name='action' value='delete'><input type='hidden' name='kind' value='directory'><input type='hidden' name='path' value='{esc(path)}'><button class='linkbtn' type='submit'>Delete</button></form> "
            actions += f"<form method='POST' action='/device-control' style='display:inline-flex;gap:4px'><input type='hidden' name='action' value='move'><input type='hidden' name='path' value='{esc(path)}'><input name='destination' placeholder='Move to folder path' required style='width:130px'><button class='linkbtn' type='submit' onclick='return confirm(\"Move this folder?\")'>Move</button></form>"
            rows.append(f"<tr><td>📁</td><td><a href='/device-control?path={qpath}'>{esc(name)}</a></td><td>Directory</td><td>—</td><td>{actions}</td></tr>")
        else:
            actions = f"<a class='linkbtn' href='/download?path={qpath}'>Download</a> "
            actions += f"<a class='linkbtn' href='/open-file?path={qpath}' target='_blank'>Open on Mac</a> "
            actions += f"<a class='linkbtn' href='{rename_href}'>Rename</a> "
            actions += f"<form method='POST' action='/device-control' style='display:inline' onsubmit='return confirm(\"Permanently delete this file?\")'><input type='hidden' name='action' value='delete'><input type='hidden' name='kind' value='file'><input type='hidden' name='path' value='{esc(path)}'><button class='linkbtn' type='submit'>Delete</button></form> "
            actions += f"<form method='POST' action='/device-control' style='display:inline-flex;gap:4px'><input type='hidden' name='action' value='move'><input type='hidden' name='path' value='{esc(path)}'><input name='destination' placeholder='Move to folder path' required style='width:130px'><button class='linkbtn' type='submit' onclick='return confirm(\"Move this file?\")'>Move</button></form> "
            actions += f"<form method='POST' action='/device-control' style='display:inline-flex;gap:4px'><input type='hidden' name='action' value='copy'><input type='hidden' name='path' value='{esc(path)}'><input name='destination' placeholder='Copy to folder path' required style='width:130px'><button class='linkbtn' type='submit' onclick='return confirm(\"Copy this file?\")'>Copy</button></form>"
            rows.append(f"<tr><td>📄</td><td>{esc(name)}</td><td>File</td><td>{esc(_format_bytes(item.get('size')))}</td><td>{actions}</td></tr>")

    status = "ONLINE" if not error else "ERROR"
    body = f"""
    <section class='hero'>
      <div class='hero-head'><div><h2>Device Control Center</h2><p>Phase 2C · controlled file management from your Mac.</p></div><div class='small' style='color:#d8e3ff'>Windows / FTP · {esc(FTP_HOST or 'Not configured')}</div></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Phase 2C Controls</h2><span class='section-note'>Write operations</span></div>
      <div class='card'>
        <form method='POST' action='/device-control' enctype='multipart/form-data' style='margin-bottom:14px' onsubmit='return confirm("Upload this file to the remote folder?")'>
          <input type='hidden' name='action' value='upload'><input type='hidden' name='path' value='{esc(actual_path)}'>
          <input type='file' name='file' required> <button class='linkbtn' type='submit'>Upload File</button>
        </form>
        <form method='POST' action='/device-control' style='display:inline-flex;gap:8px;align-items:center;margin-right:16px' onsubmit='return confirm("Create this remote folder?")'>
          <input type='hidden' name='action' value='mkdir'><input type='hidden' name='path' value='{esc(actual_path)}'>
          <input name='name' placeholder='New folder name' required maxlength='120'> <button class='linkbtn' type='submit'>Create Folder</button>
        </form>
        <div class='small' style='margin-top:12px'>Phase 2C enables Upload, Create Folder, Rename, Delete, Move, and Copy with confirmations.</div>
      </div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Remote Files</h2><span class='section-note'>{esc(status)}</span></div>
      <div class='card'>
        <div class='small'>Location: <strong>{esc(actual_path)}</strong></div>
        {f"<div class='alert' style='margin-top:12px'>{esc(error)}</div>" if error else ""}
        <div class='table-wrap' style='margin-top:14px'><table class='table'><thead><tr><th></th><th>NAME</th><th>TYPE</th><th>SIZE</th><th>ACTIONS</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="5">No files or folders found.</td></tr>'}</tbody></table></div>
      </div>
    </section>
    <section class='section'><div class='card'><div class='small'>Phase 2C is controlled. Delete removes files or empty folders only; Move and Copy require a destination folder.</div><div class='nav' style='margin-top:12px'><a href='/'>← Dashboard</a><a href='/network-diagnostics'>Network Diagnostics</a></div></div></section>
    """
    return page_shell("PNDCC Device Control Center", body)


# ---------------------------------------------------------------------------
# Project metadata
# ---------------------------------------------------------------------------
PNDCC_VERSION = "2.0"
PNDCC_AUTHOR = "Saiful Quadir"
PNDCC_PROJECT = "Personal Network & Device Command Center"
PNDCC_UPDATED = "2026-10-04 Phase 2C Delete Move Copy"
PNDCC_COPYRIGHT = "© Saiful Quadir"


def pndcc_project_info():
    return {
        "project": PNDCC_PROJECT,
        "version": PNDCC_VERSION,
        "author": PNDCC_AUTHOR,
        "updated": PNDCC_UPDATED,
        "copyright": PNDCC_COPYRIGHT,
    }


# ---------------------------------------------------------------------------
# Network Diagnostics — simple Terminal-tested measurements
# ---------------------------------------------------------------------------
# This section is intentionally isolated. It does not change device, storage,
# FTP/FTPS, cloud, alert, or history monitoring. Diagnostics run only when
# the dedicated page/API is opened.

def _run_cmd(args, timeout=5):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "").strip(), (p.stderr or "").strip(), p.returncode
    except (OSError, subprocess.SubprocessError):
        return "", "", 1


def _first_match(text, pattern, default="—"):
    m = re.search(pattern, text, re.MULTILINE)
    return m.group(1).strip() if m else default


def _ping_target(host, count=5, timeout=8):
    out, _, rc = _run_cmd(["/sbin/ping", "-c", str(count), host], timeout=timeout)
    loss = _first_match(out, r"([0-9.]+)% packet loss")
    avg = _first_match(out, r"round-trip .*?= [0-9.]+/([0-9.]+)/[0-9.]+/[0-9.]+ ms")
    return {
        "host": host,
        "packet_loss_pct": None if loss == "—" else float(loss),
        "avg_latency_ms": None if avg == "—" else float(avg),
        "reachable": rc == 0 and loss != "100.0",
    }


def _network_diagnostics():
    """Collect a small, read-only network snapshot using macOS commands."""
    wifi_out, _, _ = _run_cmd(["/usr/sbin/networksetup", "-getinfo", "Wi-Fi"])
    airport_out, _, _ = _run_cmd(["/usr/sbin/system_profiler", "SPAirPortDataType"], timeout=8)
    route_out, _, _ = _run_cmd(["/sbin/route", "-n", "get", "default"])
    arp_out, _, _ = _run_cmd(["/usr/sbin/arp", "-a"])

    ip = _first_match(wifi_out, r"^IP address:\s*(.+)$")
    router = _first_match(wifi_out, r"^Router:\s*(.+)$")
    interface = _first_match(route_out, r"^\s*interface:\s*(.+)$")
    channel = _first_match(airport_out, r"^\s*Channel:\s*(.+)$")
    signal_noise = _first_match(airport_out, r"^\s*Signal / Noise:\s*(.+)$")
    tx_rate = _first_match(airport_out, r"^\s*Transmit Rate:\s*(.+)$")
    phy = _first_match(airport_out, r"^\s*PHY Mode:\s*(.+)$")

    router_test = _ping_target(router) if router != "—" else {"packet_loss_pct": None, "avg_latency_ms": None, "reachable": False}
    internet_test = _ping_target("1.1.1.1")

    dns_out, _, _ = _run_cmd(["/usr/bin/nslookup", "google.com"], timeout=5)
    dns_server = _first_match(dns_out, r"^Server:\s*(.+)$")
    dns_time = "—"
    start = time.monotonic()
    _, _, dns_rc = _run_cmd(["/usr/bin/nslookup", "google.com"], timeout=5)
    if dns_rc == 0:
        dns_time = f"{(time.monotonic() - start) * 1000:.1f} ms"

    arp_rows = []
    for line in arp_out.splitlines():
        m = re.search(r"\(([^)]+)\) at ([0-9a-f:]+|incomplete) on", line, re.I)
        if m:
            arp_rows.append({"ip": m.group(1), "mac": m.group(2)})

    # Simple local-device identification. This is display-only and does not
    # change the existing PNDCC device inventory or monitoring logic.
    device_names = {
        "192.168.2.1": "Router",
        "192.168.2.19": "OnePlus Nord CE 3 Lite 5G",
        "192.168.2.62": "iPhone (current IP)",
        "192.168.2.120": "RE315 Wi-Fi Extender",
        "192.168.2.161": "iPad",
        "192.168.2.162": "Windows Laptop",
        "192.168.2.205": "MacBook Pro",
        "192.168.2.208": "Android Tablet",
    }
    for row in arp_rows:
        row["name"] = device_names.get(row["ip"], "Unknown device")

    # Simple signal classification. The existing raw dBm value is preserved.
    signal_dbm = None
    signal_match = re.search(r"(-\d+)\s*dBm", signal_noise or "")
    if signal_match:
        signal_dbm = int(signal_match.group(1))
    if signal_dbm is None:
        signal_quality = "Unknown"
    elif signal_dbm >= -60:
        signal_quality = "Excellent"
    elif signal_dbm >= -67:
        signal_quality = "Good"
    elif signal_dbm >= -75:
        signal_quality = "Fair"
    else:
        signal_quality = "Weak"

    # Overall health is intentionally conservative: packet loss or a failed
    # router/internet test prevents a misleading GOOD result.
    router_ok = router_test.get("packet_loss_pct") == 0.0
    internet_ok = internet_test.get("packet_loss_pct") == 0.0
    dns_ok = dns_time != "—"
    if router_ok and internet_ok and dns_ok and signal_quality in ("Excellent", "Good", "Fair"):
        network_health = "GOOD" if signal_quality != "Weak" else "FAIR"
    elif router_test.get("packet_loss_pct") is not None or internet_test.get("packet_loss_pct") is not None:
        network_health = "FAIR"
    else:
        network_health = "UNKNOWN"

    return {
        "timestamp": now(),
        "wifi": {
            "status": "ONLINE" if ip != "—" and interface != "—" else "OFFLINE",
            "interface": interface,
            "ip": ip,
            "channel": channel,
            "signal_noise": signal_noise,
            "transmit_rate": tx_rate,
            "phy_mode": phy,
            "signal_quality": signal_quality,
        },
        "router": {
            "ip": router,
            "avg_latency_ms": router_test.get("avg_latency_ms"),
            "packet_loss_pct": router_test.get("packet_loss_pct"),
        },
        "internet": {
            "target": "1.1.1.1",
            "avg_latency_ms": internet_test.get("avg_latency_ms"),
            "packet_loss_pct": internet_test.get("packet_loss_pct"),
        },
        "dns": {"server": dns_server, "lookup_time": dns_time},
        "local_devices": arp_rows,
        "network_health": network_health,
    }


def network_diagnostics_page():
    d = _network_diagnostics()
    wifi = d["wifi"]
    router = d["router"]
    internet = d["internet"]
    dns = d["dns"]
    devices = d["local_devices"]
    network_health = d.get("network_health", "UNKNOWN")

    def val(x, suffix=""):
        if x is None or x == "—":
            return "—"
        if isinstance(x, float):
            return f"{x:.2f}{suffix}"
        return f"{x}{suffix}"

    rows = "".join(
        f"<tr><td>{esc(x['ip'])}</td><td>{esc(x.get('name', 'Unknown device'))}</td><td>{esc(x['mac'])}</td></tr>"
        for x in devices
    ) or '<tr><td colspan="2">No local ARP entries found.</td></tr>'

    body = f"""
    <section class='hero'>
      <div class='hero-head'><div><h2>Network Diagnostics</h2><p>Simple read-only Wi-Fi and network measurements from macOS.</p></div><div class='small' style='color:#d8e3ff'>{esc(d['timestamp'])}</div></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Wi-Fi</h2><span class='section-note'>Current connection</span></div>
      <div class='grid'>
        <article class='card'><div class='metric-label'>STATUS</div><div class='kpi-value {esc(wifi['status'])}'>{esc(wifi['status'])}</div><div class='small'>Interface {esc(wifi['interface'])} · IP {esc(wifi['ip'])}</div></article>
        <article class='card'><div class='metric-label'>NETWORK HEALTH</div><div class='metric-value'>{esc(network_health)}</div><div class='small'>Overall read-only assessment</div></article>
        <article class='card'><div class='metric-label'>CHANNEL</div><div class='metric-value'>{esc(wifi['channel'])}</div><div class='small'>PHY {esc(wifi['phy_mode'])}</div></article>
        <article class='card'><div class='metric-label'>SIGNAL / NOISE</div><div class='metric-value'>{esc(wifi['signal_noise'])}</div><div class='small'>Signal quality: {esc(wifi.get('signal_quality', 'Unknown'))}</div></article>
        <article class='card'><div class='metric-label'>TRANSMIT RATE</div><div class='metric-value'>{esc(wifi['transmit_rate'])} Mbps</div></article>
      </div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Network Performance</h2><span class='section-note'>5-packet measurements</span></div>
      <div class='grid'>
        <article class='card'><h3>Router · {esc(router['ip'])}</h3><div class='metric-label'>LATENCY</div><div class='metric-value'>{val(router['avg_latency_ms'], ' ms')}</div><div class='metric-label'>PACKET LOSS</div><div class='metric-value'>{val(router['packet_loss_pct'], '%')}</div></article>
        <article class='card'><h3>Internet · 1.1.1.1</h3><div class='metric-label'>LATENCY</div><div class='metric-value'>{val(internet['avg_latency_ms'], ' ms')}</div><div class='metric-label'>PACKET LOSS</div><div class='metric-value'>{val(internet['packet_loss_pct'], '%')}</div></article>
        <article class='card'><h3>DNS</h3><div class='metric-label'>SERVER</div><div class='metric-value'>{esc(dns['server'])}</div><div class='metric-label'>LOOKUP TIME</div><div class='metric-value'>{esc(dns['lookup_time'])}</div></article>
      </div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Local Network Devices</h2><span class='section-note'>{len(devices)} ARP entries</span></div>
      <div class='card table-wrap'><table class='table'><thead><tr><th>IP ADDRESS</th><th>DEVICE</th><th>MAC ADDRESS</th></tr></thead><tbody>{rows}</tbody></table></div>
    </section>
    <section class='section'><div class='card'><div class='small'>Diagnostics are read-only and run only when this page is opened. They do not modify network settings.</div><div class='nav' style='margin-top:12px'><a href='/'>← Dashboard</a></div></div></section>
    """
    return page_shell("PNDCC Network Diagnostics", body)




# ===========================================================================
# PNDCC v2.0 Phase 2D — Finder / File Explorer Device Control
# Author: Saiful Quadir
# Project: Personal Network & Device Command Center (PNDCC)
# Updated: 2026-10-04
# Version: 2.0 Phase 2D
# Copyright: © Saiful Quadir
# Design rule: Simple is the best.
# IMPORTANT: This section is layered on top of the working Phase 2C engine.
# ===========================================================================

PNDCC_2D_VERSION = "2.0 Phase 2D"
LOCAL_ROOT = os.path.realpath(os.path.expanduser("~"))
LOCAL_ROOT = os.path.realpath(LOCAL_ROOT)


def _local_path(rel="/"):
    """Resolve a path inside the Mac user's home directory only."""
    rel = urllib.parse.unquote(str(rel or "/")).replace("\\", "/")
    if rel in ("", "/", "."):
        return LOCAL_ROOT
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError("Parent traversal is not allowed")
    p = os.path.realpath(os.path.join(LOCAL_ROOT, *parts))
    if p != LOCAL_ROOT and not p.startswith(LOCAL_ROOT + os.sep):
        raise ValueError("Path is outside Mac Storage")
    return p


def _local_rel(path):
    p = os.path.realpath(path)
    if p == LOCAL_ROOT:
        return "/"
    if not p.startswith(LOCAL_ROOT + os.sep):
        raise ValueError("Path is outside Mac Storage")
    return "/" + os.path.relpath(p, LOCAL_ROOT).replace(os.sep, "/")


def _local_list(rel="/"):
    p = _local_path(rel)
    if not os.path.isdir(p):
        raise NotADirectoryError(rel)
    entries=[]
    for name in os.listdir(p):
        if name in (".", ".."):
            continue
        full=os.path.join(p,name)
        try:
            st=os.stat(full)
            isdir=os.path.isdir(full)
            entries.append({
                "name": name,
                "type": "directory" if isdir else "file",
                "size": 0 if isdir else st.st_size,
                "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
            })
        except OSError:
            pass
    entries.sort(key=lambda x:(x["type"]!="directory", x["name"].lower()))
    return {"ok":True,"path":_local_rel(p),"entries":entries}


def _local_unique_name(directory, name):
    candidate=os.path.join(directory,name)
    if not os.path.exists(candidate):
        return candidate
    stem,ext=os.path.splitext(name)
    n=2
    while True:
        candidate=os.path.join(directory,f"{stem} ({n}){ext}")
        if not os.path.exists(candidate):
            return candidate
        n+=1


def _local_copy(src_rel,dst_rel,keep_both=False):
    import shutil
    src=_local_path(src_rel); dst_dir=_local_path(dst_rel)
    if not os.path.exists(src) or not os.path.isdir(dst_dir):
        raise FileNotFoundError("Source or destination not found")
    dst=os.path.join(dst_dir,os.path.basename(src))
    if os.path.exists(dst):
        if not keep_both:
            if os.path.isdir(dst): shutil.rmtree(dst)
            else: os.remove(dst)
        else: dst=_local_unique_name(dst_dir,os.path.basename(src))
    if os.path.isdir(src): shutil.copytree(src,dst)
    else: shutil.copy2(src,dst)
    return _local_rel(dst)


def _local_move(src_rel,dst_rel,keep_both=False):
    import shutil
    src=_local_path(src_rel); dst_dir=_local_path(dst_rel)
    if not os.path.exists(src) or not os.path.isdir(dst_dir):
        raise FileNotFoundError("Source or destination not found")
    dst=os.path.join(dst_dir,os.path.basename(src))
    if os.path.exists(dst):
        if not keep_both:
            if os.path.isdir(dst): shutil.rmtree(dst)
            else: os.remove(dst)
        else: dst=_local_unique_name(dst_dir,os.path.basename(src))
    shutil.move(src,dst)
    return _local_rel(dst)


def _local_delete(rel,is_dir=False):
    import shutil
    p=_local_path(rel)
    if p==LOCAL_ROOT: raise ValueError("Mac Storage root cannot be deleted")
    if is_dir:
        os.rmdir(p)  # safe: only empty folders
    else:
        os.remove(p)


def _local_rename(rel,new_name):
    p=_local_path(rel)
    if p==LOCAL_ROOT: raise ValueError("Mac Storage root cannot be renamed")
    new_name=str(new_name or "").strip()
    if not new_name or "/" in new_name or "\\" in new_name or new_name in (".",".."):
        raise ValueError("Name must be a single file/folder name")
    dst=os.path.join(os.path.dirname(p),new_name)
    if os.path.exists(dst): raise FileExistsError(new_name)
    os.rename(p,dst)


def _remote_read_bytes(path):
    chunks=[]; c=None
    try:
        c=_ftp_client_for_control(); c.retrbinary("RETR "+_clean_remote_path(path),chunks.append)
        return b"".join(chunks)
    finally: _close_ftp_client(c)


def _remote_mkdirs(path):
    """Create a remote directory tree and verify every component.

    FileZilla may return 550 when MKD is attempted for an already-existing
    directory, so that case is harmless only when the directory can then be
    entered.  Previously every exception was swallowed, which could make a
    later STOR fail with a misleading 550 on folder paste.
    """
    path=_clean_remote_path(path)
    if path=="/": return
    c=None
    try:
        c=_ftp_client_for_control()
        built=""
        for part in path.strip("/").split("/"):
            if not part: continue
            built += "/"+part
            try:
                c.mkd(built)
            except Exception as mkd_error:
                try:
                    c.cwd(built)
                except Exception as cwd_error:
                    raise RuntimeError(
                        f"Cannot create/access remote directory '{built}'. "
                        f"FTP server returned: {mkd_error}"
                    ) from cwd_error
    finally:
        _close_ftp_client(c)


def _remote_exists(path):
    path=_clean_remote_path(path); parent="/".join(path.rstrip("/").split("/")[:-1]) or "/"; name=os.path.basename(path)
    c=None
    try:
        c=_ftp_client_for_control(); c.cwd(parent)
        try: return name in [os.path.basename(x.rstrip("/")) for x in c.nlst()]
        except Exception: return False
    finally: _close_ftp_client(c)


def _ftp_delete_tree(path):
    """Delete one remote file or folder without turning FileZilla 550 into an error.

    FileZilla commonly returns 550 when CWD/LIST is attempted on a file.
    Therefore determine file-vs-folder with CWD first; only recurse when CWD
    succeeds. This preserves the Phase 2D behavior while making REPLACE/Paste
    safe for existing remote files.
    """
    path = _clean_remote_path(path)
    if path == "/":
        raise ValueError("Remote root cannot be deleted")

    client = None
    is_dir = False
    try:
        client = _ftp_client_for_control()
        client.cwd(path)
        is_dir = True
    except Exception:
        is_dir = False
    finally:
        _close_ftp_client(client)

    if not is_dir:
        _ftp_delete_item(path, False)
        return

    listing = _ftp_list_directory(path)
    for item in listing.get("entries", []):
        child = _join_remote_path(path, item["name"])
        if item.get("type") == "directory":
            _ftp_delete_tree(child)
        else:
            _ftp_delete_item(child, False)
    _ftp_delete_item(path, True)


def _ftp_copy_item_recursive(src,dst_dir,keep_both=False):
    """Copy one remote file or a remote folder recursively.

    Important: FTP LIST/MLSD on a FILE commonly returns 550.  Therefore we
    must not use a directory listing as the file/folder test.
    """
    src = _clean_remote_path(src)
    dst_dir = _clean_remote_path(dst_dir)
    name = os.path.basename(src)
    if not name:
        raise ValueError("The remote root cannot be copied")

    target = _join_remote_path(dst_dir, name)
    if target == src:
        if keep_both:
            base, ext = os.path.splitext(name)
            n = 2
            while _remote_exists(_join_remote_path(dst_dir, f"{base} ({n}){ext}")):
                n += 1
            name = f"{base} ({n}){ext}"
            target = _join_remote_path(dst_dir, name)
        else:
            raise ValueError("Source and destination are the same item")

    if _remote_exists(target):
        if not keep_both:
            _ftp_delete_tree(target)
        else:
            base, ext = os.path.splitext(name)
            n = 2
            while _remote_exists(_join_remote_path(dst_dir, f"{base} ({n}){ext}")):
                n += 1
            name = f"{base} ({n}){ext}"
            target = _join_remote_path(dst_dir, name)

    # First try to determine whether the source is a directory by CWD.
    # CWD on a normal FTP file returns 550, which is expected here.
    c = None
    is_dir = False
    try:
        c = _ftp_client_for_control()
        c.cwd(src)
        is_dir = True
    except Exception:
        is_dir = False
    finally:
        _close_ftp_client(c)

    if not is_dir:
        data = _remote_read_bytes(src)
        if len(data) > PNDCC_UPLOAD_MAX_BYTES:
            raise ValueError("Copy is limited to 100 MB")
        c = None
        try:
            c = _ftp_client_for_control()
            c.storbinary("STOR " + target, __import__("io").BytesIO(data))
        finally:
            _close_ftp_client(c)
        return target

    _remote_mkdirs(target)
    listing = _ftp_list_directory(src)
    for item in listing.get("entries", []):
        child = _join_remote_path(src, item["name"])
        if item["type"] == "directory":
            _ftp_copy_item_recursive(child, target, False)
        else:
            data = _remote_read_bytes(child)
            if len(data) > PNDCC_UPLOAD_MAX_BYTES:
                raise ValueError("Copy is limited to 100 MB per file")
            c = None
            try:
                c = _ftp_client_for_control()
                c.storbinary("STOR " + _join_remote_path(target, item["name"]), __import__("io").BytesIO(data))
            finally:
                _close_ftp_client(c)
    return target


def _ftp_move_item_recursive(src,dst_dir,keep_both=False):
    src=_clean_remote_path(src); dst_dir=_clean_remote_path(dst_dir); name=os.path.basename(src)
    target=_join_remote_path(dst_dir,name)
    if _remote_exists(target):
        if not keep_both: _ftp_delete_tree(target)
        else:
            base,ext=os.path.splitext(name); n=2
            while _remote_exists(_join_remote_path(dst_dir,f"{base} ({n}){ext}")): n+=1
            target=_join_remote_path(dst_dir,f"{base} ({n}){ext}")
    c=None
    try:
        c=_ftp_client_for_control(); c.rename(src,target); return target
    except Exception:
        # FTP rename is the correct move for same-server folders/files.
        raise
    finally: _close_ftp_client(c)


def _download_to_local(remote_path, local_dir_rel, keep_both=False):
    import tempfile
    data=_remote_read_bytes(remote_path)
    d=_local_path(local_dir_rel); name=os.path.basename(_clean_remote_path(remote_path))
    target=os.path.join(d,name)
    if os.path.exists(target):
        if not keep_both: os.remove(target)
        else: target=_local_unique_name(d,name)
    if len(data)>PNDCC_UPLOAD_MAX_BYTES: raise ValueError("Transfer exceeds 100 MB limit")
    with open(target,"wb") as f: f.write(data)
    return _local_rel(target)


def _upload_from_local(local_rel, remote_dir, keep_both=False):
    p=_local_path(local_rel); name=os.path.basename(p); remote_dir=_clean_remote_path(remote_dir)
    target=_join_remote_path(remote_dir,name)
    if _remote_exists(target):
        if not keep_both: _ftp_delete_tree(target)
        else:
            base,ext=os.path.splitext(name); n=2
            while _remote_exists(_join_remote_path(remote_dir,f"{base} ({n}){ext}")): n+=1
            target=_join_remote_path(remote_dir,f"{base} ({n}){ext}")
    if os.path.isdir(p):
        _remote_mkdirs(target)
        for root,dirs,files in os.walk(p):
            rel=os.path.relpath(root,p)
            rdir=target if rel=="." else _join_remote_path(target,rel.replace(os.sep,"/"))
            _remote_mkdirs(rdir)
            for fn in files:
                fp=os.path.join(root,fn)
                with open(fp,"rb") as fh:
                    c=None
                    try:
                        c=_ftp_client_for_control(); c.storbinary("STOR "+_join_remote_path(rdir,fn),fh)
                    finally: _close_ftp_client(c)
    else:
        if os.path.getsize(p)>PNDCC_UPLOAD_MAX_BYTES: raise ValueError("Transfer exceeds 100 MB limit")
        with open(p,"rb") as fh:
            c=None
            try:
                c=_ftp_client_for_control(); c.storbinary("STOR "+target,fh)
            finally: _close_ftp_client(c)
    return target


def _open_local(rel):
    p=_local_path(rel)
    subprocess.Popen(["open",p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _format_modified(value):
    return value or "—"


def _device_control_page_2d(source="remote", path="/"):
    source="local" if source=="local" else "remote"
    path = _local_rel(_local_path(path)) if source=="local" else _clean_remote_path(path)
    try:
        listing=_local_list(path) if source=="local" else _ftp_list_directory(path)
        entries=listing.get("entries",[]); actual=listing.get("path",path); error=""
    except Exception as e:
        entries=[]; actual=path; error=f"{type(e).__name__}: {e}"
    data=[]
    for item in entries:
        name=item.get("name",""); kind=item.get("type","file")
        child=_join_remote_path(actual,name) if source=="remote" else _local_rel(os.path.join(_local_path(actual),name))
        data.append({"name":name,"type":kind,"size":item.get("size",0),"modified":_format_modified(item.get("modified","")),"path":child})
    payload=json.dumps(data).replace("</","<\\/")
    qpath=urllib.parse.quote(actual,safe="")
    parent="/" if actual=="/" else ( _clean_remote_path("/".join(actual.rstrip("/").split("/")[:-1])) if source=="remote" else _local_rel(os.path.dirname(_local_path(actual))) )
    qparent=urllib.parse.quote(parent,safe="")
    status="ONLINE" if not error else "ERROR"
    root_local=urllib.parse.quote("/",safe="")
    root_remote=urllib.parse.quote("/",safe="")
    test_folder=urllib.parse.quote("/PNDCC_Test",safe="")
    body=f"""
<style>
.fm2d{{display:grid;grid-template-columns:190px 1fr;min-height:600px;border:1px solid #d8dee8;border-radius:12px;overflow:hidden;background:#fff}}
.fm-side{{background:#f5f7fa;border-right:1px solid #d8dee8;padding:12px}}
.fm-side button{{display:block;width:100%;text-align:left;border:0;background:transparent;padding:9px 10px;border-radius:7px;cursor:pointer;font-size:14px}}
.fm-side button:hover,.fm-side button.active{{background:#e7edf7}}
.fm-side-toggle{{display:none}}
.fm-main{{min-width:0}}
.fm-toolbar{{display:flex;gap:6px;align-items:center;padding:10px;border-bottom:1px solid #d8dee8;flex-wrap:wrap}}
.fm-toolbar button,.fm-toolbar input{{height:32px;border:1px solid #cbd3df;border-radius:6px;background:white;padding:0 9px}}
.fm-toolbar input{{min-width:180px;flex:1}}
.fm-bread{{padding:8px 12px;border-bottom:1px solid #e4e8ee;font-size:13px;color:#56616f;white-space:nowrap;overflow:auto}}
.fm-list{{outline:none;min-height:390px}}
.fm-head,.fm-row{{display:grid;grid-template-columns:minmax(200px,1fr) 90px 100px 135px 44px;align-items:center}}
.fm-head{{font-size:12px;font-weight:700;color:#687384;border-bottom:1px solid #e4e8ee;padding:7px 10px}}
.fm-row{{padding:7px 10px;cursor:pointer;border-bottom:1px solid #f0f2f5;user-select:none;-webkit-user-select:none;-webkit-touch-callout:none;touch-action:manipulation}}
.fm-row:hover{{background:#f6f9fd}}
.fm-row.selected{{background:#cfe2ff}}
.fm-row .name{{display:flex;align-items:center;gap:8px;min-width:0}}.fm-check{{display:none;width:20px;height:20px;flex:0 0 20px;accent-color:#315ee8}}.fm-more{{width:36px;height:34px;border:1px solid #d5dce6;border-radius:8px;background:#fff;font-size:21px;line-height:1;cursor:pointer;touch-action:manipulation}}.fm-more:focus-visible,.fm-check:focus-visible{{outline:2px solid #315ee8;outline-offset:2px}}
.fm-row .name span:last-child{{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.fm-empty{{height:300px;padding:20px;color:#7a8492}}
.fm-status{{padding:8px 12px;border-top:1px solid #d8dee8;color:#596575;font-size:12px;display:flex;justify-content:space-between}}
.fm-menu{{position:fixed;z-index:99999;display:none;background:white;border:1px solid #cbd3df;box-shadow:0 8px 24px rgba(0,0,0,.18);border-radius:7px;padding:5px;min-width:190px}}
.fm-menu button{{display:block;width:100%;border:0;background:transparent;text-align:left;padding:8px 10px;border-radius:4px;cursor:pointer}}
.fm-menu button:hover{{background:#eef3f9}}
.fm-menu hr{{border:0;border-top:1px solid #e5e8ed;margin:4px 0}}.fm-menu button{{min-height:40px;touch-action:manipulation}}
.fm-note{{font-size:12px;color:#6b7480;margin-top:7px}}
@media(max-width:800px){{.fm2d{{grid-template-columns:1fr}}.fm-side{{display:none;border-right:0;border-bottom:1px solid #d8dee8}}.fm-side.fm-side-open{{display:block}}.fm-side-toggle{{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:8px 11px;border:1px solid #cbd3df;border-radius:7px;background:#fff;font-weight:600;touch-action:manipulation}}.fm-head,.fm-row{{grid-template-columns:minmax(150px,1fr) 65px 75px 95px 42px}}}}@media(max-width:640px){{.fm-toolbar{{gap:7px;padding:9px}}.fm-toolbar button,.fm-toolbar select{{min-height:40px;height:auto;padding:8px 10px;font-size:14px}}.fm-toolbar input{{min-width:100%;min-height:42px;flex:1 1 100%;font-size:16px}}.fm-toolbar select{{max-width:100%;flex:1 1 42%;min-width:0}}.fm-head{{display:none}}.fm-row{{grid-template-columns:minmax(0,1fr) 44px;padding:8px 8px;min-height:52px;gap:4px}}.fm-row>div:nth-child(2),.fm-row>div:nth-child(3),.fm-row>div:nth-child(4){{display:none}}.fm-check{{display:inline-block}}.fm-more{{min-height:40px;min-width:40px}}.fm-bread{{font-size:12px}}.fm-status{{gap:8px;flex-wrap:wrap}}.fm-note{{line-height:1.5}}}}
</style>
<section class='hero'><div class='hero-head'><div><h2>Device Control Center · Phase 2D</h2><p>Windows / FTP + Mac Storage · Finder / File Explorer style.</p></div><div class='small' style='color:#d8e3ff'>Windows / FTP · {esc(FTP_HOST or 'Not configured')} · {status}</div></div></section>
<section class='section'><div class='card' style='padding:0;overflow:hidden'>
<div class='fm2d'>
<aside id='fmSide' class='fm-side' aria-label='Locations and Favorites'>
<div class='small' style='font-weight:700;margin:4px 8px 8px'>LOCATIONS</div>
<button class='{ 'active' if source=='local' else '' }' onclick="go('local','/')">⌂ Mac Storage</button>
<button class='{ 'active' if source=='remote' and actual=='/' else '' }' onclick="go('remote','/')">▣ Windows FTP</button>
<button onclick="go('remote','/PNDCC_Test')">▣ PNDCC_Test</button>
<div class='small' style='font-weight:700;margin:18px 8px 8px'>FAVORITES</div>
<button onclick="go('local','/')">Home</button>
<button onclick="refreshFM()">↻ Refresh</button>
</aside>
<main class='fm-main'>
<div class='fm-toolbar'>
<button class='fm-side-toggle' type='button' aria-expanded='false' aria-controls='fmSide' onclick='toggleFMSidebar()'>☰ Locations / Favorites</button>
<button onclick='backFM()'>←</button><button onclick='forwardFM()'>→</button><button onclick='upFM()'>↑ Up</button><button onclick='refreshFM()'>↻</button>
<button onclick='newFolder()'>＋ New Folder</button><button onclick='uploadFile()'>↑ Upload</button>
<input id='searchBox' placeholder='Search this folder…' oninput='renderFilter()'>
<select id='typeFilter' onchange='renderFilter()' title='Filter by Type'><option value='all'>Type: All</option><option value='file'>Type: Files</option><option value='directory'>Type: Folders</option></select>
<select id='sizeFilter' onchange='renderFilter()' title='Filter by Size'><option value='all'>Size: All</option><option value='empty'>Size: Empty (0 B)</option><option value='small'>Size: &lt; 1 MB</option><option value='medium'>Size: 1–100 MB</option><option value='large'>Size: &gt; 100 MB</option></select>
<select id='modifiedFilter' onchange='renderFilter()' title='Filter by modification date'><option value='all'>Modified: Any date</option><option value='today'>Modified: Today</option><option value='7d'>Modified: Past 7 days</option><option value='30d'>Modified: Past 30 days</option><option value='older'>Modified: Over 30 days ago</option><option value='unknown'>Modified: Date unavailable</option></select>
<select id='sortBox' onchange='sortRows()' title='Sort by column'><option value='name'>Sort: Name</option><option value='type'>Sort: Type</option><option value='size'>Sort: Size</option><option value='modified'>Sort: Modified</option></select>
</div>
<div class='fm-bread'>Location: <strong>{esc(actual)}</strong></div>
<div id='fmList' class='fm-list' tabindex='0' onclick='focusList()' onkeydown='keyNav(event)' oncontextmenu='emptyMenu(event)'>
<div class='fm-head'><div class='fm-sort-head' role='button' tabindex='0' onclick="sortByHeader('name')">Name <span id='sort-ind-name'>↕</span></div><div class='fm-sort-head' role='button' tabindex='0' onclick="sortByHeader('type')">Type <span id='sort-ind-type'>↕</span></div><div class='fm-sort-head' role='button' tabindex='0' onclick="sortByHeader('size')">Size <span id='sort-ind-size'>↕</span></div><div class='fm-sort-head' role='button' tabindex='0' onclick="sortByHeader('modified')">Modified <span id='sort-ind-modified'>↕</span></div><div aria-hidden='true'></div></div>
<div id='rows'>{''.join(f"<div class='fm-row' data-index='{i}' data-name='{html.escape(x['name'],quote=True)}' data-type='{x['type']}' data-size='{x['size']}' data-modified='{html.escape(x['modified'],quote=True)}' data-path='{html.escape(x['path'],quote=True)}' onclick='rowClick(event,{i})' ondblclick='rowOpen({i})' oncontextmenu='rowMenu(event,{i})' onpointerdown='fmPointerDown(event,{i})' onpointermove='fmPointerMove(event)' onpointerup='fmPointerUp(event)' onpointercancel='fmPointerCancel()'><div class='name'><input class='fm-check' type='checkbox' aria-label='Select {html.escape(x['name'],quote=True)}' onclick='event.stopPropagation();toggleRowSelection({i},this.checked)' onpointerdown='event.stopPropagation()'><span>{'📁' if x['type']=='directory' else '📄'}</span><span>{esc(x['name'])}</span></div><div>{'Folder' if x['type']=='directory' else 'File'}</div><div>{esc(_format_bytes(x['size'])) if x['type']!='directory' else '—'}</div><div>{esc(x['modified'])}</div><div><button class='fm-more' type='button' aria-label='Actions for {html.escape(x['name'],quote=True)}' title='Actions' onclick='event.stopPropagation();rowMenu(event,{i})'>⋯</button></div></div>" for i,x in enumerate(data)) or "<div class='fm-empty'>No files or folders found.</div>"}</div>
</div>
<div class='fm-status'><span id='selStatus'>0 selected</span><span>{esc('Mac Storage' if source=='local' else 'Windows / FTP')} · {esc(FTP_HOST or '')} · {status}</span></div>
</main></div>
</div></section>
<div class='fm-note'>Keyboard: ↑/↓ select, Shift+↑/↓ range, Cmd/Ctrl-click multi-select, Cmd/Ctrl+A, C, X, V, F2 Rename, Delete, Enter Open, Esc closes menu. Right-click keeps all file/folder actions. Desktop: click to select, double-click to open, right-click for actions. iPhone: use Locations / Favorites to show the sidebar, tap ⋯ or long-press for file actions, and use checkboxes for multi-select. Modified filters use the file's modification date; unavailable dates have their own filter.</div>
<div id='ctx' class='fm-menu'></div>
<form id='uploadForm' method='POST' action='/device-control' enctype='multipart/form-data' style='display:none'><input name='action' value='upload'><input name='source' value='{esc(source)}'><input id='uploadPath' name='path' value='{esc(actual)}'><input id='uploadFileInput' type='file' name='file' onchange='document.getElementById("uploadForm").submit()'></form>
</section>
<script>
const FM={{source:{json.dumps(source)},path:{json.dumps(actual)},rows:{payload},history:[],histPos:-1,selected:[],anchor:-1,clipboard:null,sortKey:'name',sortDir:1}};
const CLIPBOARD_KEY='PNDCC_Phase2D_Clipboard_v1';
function loadClipboard(){{try{{const raw=localStorage.getItem(CLIPBOARD_KEY);if(raw)FM.clipboard=JSON.parse(raw)}}catch(e){{FM.clipboard=null}}}}
function saveClipboard(){{try{{if(FM.clipboard&&FM.clipboard.items&&FM.clipboard.items.length)localStorage.setItem(CLIPBOARD_KEY,JSON.stringify(FM.clipboard));else localStorage.removeItem(CLIPBOARD_KEY)}}catch(e){{}}}}
function qs(s){{return document.querySelector(s)}}
function rows(){{return [...document.querySelectorAll('.fm-row')]}}
function focusList(){{qs('#fmList').focus()}}
function escjs(s){{return String(s).replace(/'/g,"\\'")}}
function go(source,path){{location.href='/device-control?source='+encodeURIComponent(source)+'&path='+encodeURIComponent(path)}}
function refreshFM(){{location.reload()}}
function backFM(){{history.back()}}
function forwardFM(){{history.forward()}}
function upFM(){{if(FM.path==='/' )return;let p=FM.path.replace(/\\/$/,'').split('/');p.pop();go(FM.source,p.join('/')||'/')}}
function rowData(i){{const r=rows()[i];return r?{{name:r.dataset.name,type:r.dataset.type,size:+r.dataset.size,modified:r.dataset.modified,path:r.dataset.path,index:i}}:null}}
let fmLongPressTimer=null,fmPointerStart=null,fmLongPressTriggered=false,fmSuppressClick=false;
function updateSel(){{rows().forEach((r,i)=>{{r.classList.toggle('selected',FM.selected.includes(i));const c=r.querySelector('.fm-check');if(c)c.checked=FM.selected.includes(i)}});qs('#selStatus').textContent=FM.selected.length+' selected'}}
function toggleRowSelection(i,checked){{if(checked){{if(!FM.selected.includes(i))FM.selected.push(i);FM.anchor=i}}else{{FM.selected=FM.selected.filter(x=>x!==i);if(FM.anchor===i)FM.anchor=FM.selected.length?FM.selected[FM.selected.length-1]:-1}}updateSel()}}
function fmPointerDown(e,i){{if(e.pointerType!=='touch'||e.target.closest('button,input'))return;fmPointerCancel();fmLongPressTriggered=false;fmPointerStart={{x:e.clientX,y:e.clientY,i:i}};fmLongPressTimer=setTimeout(function(){{if(!fmPointerStart)return;fmLongPressTriggered=true;fmSuppressClick=true;if(!FM.selected.includes(i)){{FM.selected=[i];FM.anchor=i;updateSel()}}showMenuAt(fmPointerStart.x,fmPointerStart.y,menuFor(rowData(i))) }},550)}}
function fmPointerMove(e){{if(!fmPointerStart)return;if(Math.abs(e.clientX-fmPointerStart.x)>10||Math.abs(e.clientY-fmPointerStart.y)>10)fmPointerCancel()}}
function fmPointerUp(e){{if(fmLongPressTriggered){{e.preventDefault();fmSuppressClick=true}}if(fmLongPressTimer)clearTimeout(fmLongPressTimer);fmLongPressTimer=null;fmPointerStart=null}}
function fmPointerCancel(){{if(fmLongPressTimer)clearTimeout(fmLongPressTimer);fmLongPressTimer=null;fmPointerStart=null}}
function rowClick(e,i){{e.stopPropagation();if(fmSuppressClick){{fmSuppressClick=false;e.preventDefault();return}}focusList();if(e.shiftKey&&FM.anchor>=0){{let a=Math.min(FM.anchor,i),b=Math.max(FM.anchor,i);FM.selected=[...Array(b-a+1)].map((_,k)=>a+k)}}else if(e.metaKey||e.ctrlKey){{if(FM.selected.includes(i))FM.selected=FM.selected.filter(x=>x!==i);else FM.selected.push(i);FM.anchor=i}}else{{FM.selected=[i];FM.anchor=i}}updateSel()}}
function rowOpen(i){{const x=rowData(i);if(!x)return;if(x.type==='directory')go(FM.source,x.path);else openItem(x)}}
function openItem(x){{if(FM.source==='local')fetch('/device-control',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{action:'open_local',path:x.path}})}}).then(r=>r.json()).then(j=>{{if(!j.ok)alert(j.message)}});else window.open('/open-file?path='+encodeURIComponent(x.path),'_blank')}}
function downloadItem(x){{if(FM.source==='remote')location.href='/download?path='+encodeURIComponent(x.path);else location.href='/local-download?path='+encodeURIComponent(x.path)}}
function props(x){{alert('Name: '+x.name+'\\nType: '+(x.type==='directory'?'Folder':'File')+'\\nSize: '+(x.type==='directory'?'—':x.size+' bytes')+'\\nModified: '+x.modified+'\\nPath: '+x.path)}}
function showMenuAt(x,y,html){{const m=qs('#ctx');m.innerHTML=html;m.style.display='block';m.style.left=Math.max(8,Math.min(x,window.innerWidth-Math.min(220,window.innerWidth-16)-8))+'px';m.style.top=Math.max(8,Math.min(y,window.innerHeight-260))+'px'}}
function showMenu(e,html){{if(e&&e.preventDefault)e.preventDefault();showMenuAt(e&&Number.isFinite(e.clientX)?e.clientX:window.innerWidth/2,e&&Number.isFinite(e.clientY)?e.clientY:window.innerHeight/2,html)}}
function closeMenu(){{qs('#ctx').style.display='none'}}
function rowMenu(e,i){{const x=rowData(i);if(!FM.selected.includes(i)){{FM.selected=[i];FM.anchor=i;updateSel()}}showMenu(e,menuFor(x))}}
function menuFor(x){{let h='';if(x.type==='directory')h+=btn('Open',"rowOpen("+x.index+")");else h+=btn('Open',"rowOpen("+x.index+")")+btn('Download',"downloadItem(rowData("+x.index+"))")+(FM.source==='remote'?btn('Open on Mac',"window.open('/open-file?path='+encodeURIComponent(rowData("+x.index+").path),'_blank')"):btn('Open on Mac',"openItem(rowData("+x.index+"))"));h+=hr()+btn('Rename','renameSelected()')+btn('Copy','copySelected()')+btn('Move / Cut','cutSelected()')+btn('Delete','deleteSelected()')+btn('Properties','props(rowData('+x.index+'))');if(FM.clipboard&&FM.clipboard.items&&FM.clipboard.items.length)h+=btn('Paste','pasteSelected()');return h}}
function btn(t,c){{return '<button onclick="closeMenu();'+c+'">'+t+'</button>'}} function hr(){{return '<hr>'}}
function emptyMenu(e){{if(e.target.closest('.fm-row'))return;showMenu(e,btn('New Folder','newFolder()')+btn('Upload File','uploadFile()')+btn('Paste','pasteSelected()')+btn('Refresh','refreshFM()'))}}
function selectedData(){{return FM.selected.map(rowData).filter(Boolean)}}
function renameSelected(){{const a=selectedData()[0];if(!a)return;const n=prompt('Rename:',a.name);if(n&&n!==a.name)postAction({{action:'rename',source:FM.source,path:a.path,name:n}})}}
function newFolder(){{const n=prompt('New folder name:');if(n)postAction({{action:'mkdir',source:FM.source,path:FM.path,name:n}})}}
function deleteSelected(){{const a=selectedData();if(!a.length)return;if(confirm('Delete '+a.length+' selected item(s)?\\nFolders must be empty.'))postAction({{action:'delete_many',source:FM.source,items:a}})}}
function copySelected(){{const items=selectedData();if(!items.length)return alert('Select at least one item first.');FM.clipboard={{mode:'copy',source:FM.source,items:items}};saveClipboard();updateClipboard();alert('Copied '+FM.clipboard.items.length+' item(s). Navigate to a folder and Paste.')}}
function cutSelected(){{const items=selectedData();if(!items.length)return alert('Select at least one item first.');FM.clipboard={{mode:'move',source:FM.source,items:items}};saveClipboard();updateClipboard();alert('Cut '+FM.clipboard.items.length+' item(s). Navigate to a folder and Paste.')}}
function updateClipboard(){{}}
function pasteSelected(){{loadClipboard();if(!FM.clipboard||!FM.clipboard.items||!FM.clipboard.items.length)return alert('Nothing to paste.');const choice=prompt('Paste conflict handling: type REPLACE, KEEP BOTH, or CANCEL','REPLACE');if(choice===null||choice.trim().toLowerCase()==='cancel')return;const c=choice.trim().toLowerCase().replace(/[ \t]+/g,'_');if(!['replace','keep_both'].includes(c))return alert('Please type REPLACE, KEEP BOTH, or CANCEL.');postAction({{action:'paste',source:FM.clipboard.source,destination_source:FM.source,destination:FM.path,mode:FM.clipboard.mode,items:FM.clipboard.items,conflict:c}})}}
function postAction(obj){{fetch('/device-control',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(obj)}}).then(async r=>{{const t=await r.text();if(!r.ok)throw new Error(t);try{{const j=JSON.parse(t);if(j.message)alert(j.message)}}catch(_){{}}if(obj.action==='paste'&&FM.clipboard&&FM.clipboard.mode==='move'){{FM.clipboard=null;saveClipboard()}}location.reload()}}).catch(e=>alert('PNDCC: '+e.message))}}
function uploadFile(){{qs('#uploadFileInput').click()}}
function sortRows(){{sortByHeader(qs('#sortBox').value)}}
function sortByHeader(key){{if(FM.sortKey===key)FM.sortDir=-FM.sortDir;else{{FM.sortKey=key;FM.sortDir=1}};const box=qs('#rows');const rs=rows();rs.sort((a,b)=>{{let av=a.dataset[key],bv=b.dataset[key],n;if(key==='size')n=(+av)-(+bv);else if(key==='modified')n=modifiedTime(av)-modifiedTime(bv);else n=av.localeCompare(bv,undefined,{{numeric:true,sensitivity:'base'}});if(!Number.isFinite(n))n=0;return n*FM.sortDir}});rs.forEach((r,i)=>{{r.dataset.index=i;box.appendChild(r)}});FM.selected=[];FM.anchor=-1;updateSel();updateSortIndicators()}}
function updateSortIndicators(){{['name','type','size','modified'].forEach(function(k){{const el=qs('#sort-ind-'+k);if(el)el.textContent=(FM.sortKey===k?(FM.sortDir===1?'↑':'↓'):'↕')}})}}
function modifiedTime(v){{if(!v||v==='—')return NaN;v=String(v).trim();let m=v.match(/^([0-9]{{4}})([0-9]{{2}})([0-9]{{2}})(?:[ T]?([0-9]{{2}}):?([0-9]{{2}})?):?([0-9]{{2}})?$/);if(m){{const t=new Date(+m[1],+m[2]-1,+m[3],+(m[4]||0),+(m[5]||0),+(m[6]||0)).getTime();return Number.isNaN(t)?NaN:t}}let t=Date.parse(v);if(!Number.isNaN(t))return t;let ftp=v.match(/^([A-Za-z]{{3}})\\s+(\\d{{1,2}})\\s+(\\d{{4}}|\\d{{1,2}}:\\d{{2}})$/);if(ftp){{const months={{Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11}};const mo=months[ftp[1]];if(mo===undefined)return NaN;const now=new Date();let y=now.getFullYear(),hh=0,mm=0;if(ftp[3].includes(':')){{[hh,mm]=ftp[3].split(':').map(Number)}}else y=+ftp[3];return new Date(y,mo,+ftp[2],hh,mm).getTime()}}return NaN}}
function toggleFMSidebar(){{const side=qs('#fmSide');const button=qs('.fm-side-toggle');const open=!side.classList.contains('fm-side-open');side.classList.toggle('fm-side-open',open);button.setAttribute('aria-expanded',String(open))}}
function renderFilter(){{const q=qs('#searchBox').value.toLowerCase();const tf=qs('#typeFilter').value;const sf=qs('#sizeFilter').value;const mf=qs('#modifiedFilter').value;const now=Date.now();const day=86400000;rows().forEach(r=>{{const nameOk=r.dataset.name.toLowerCase().includes(q);const typeOk=tf==='all'||r.dataset.type===tf;const size=+r.dataset.size||0;const sizeOk=sf==='all'||(sf==='empty'&&size===0)||(sf==='small'&&size>0&&size<1024*1024)||(sf==='medium'&&size>=1024*1024&&size<=100*1024*1024)||(sf==='large'&&size>100*1024*1024);const mt=modifiedTime(r.dataset.modified);const age=Number.isFinite(mt)?now-mt:NaN;const modOk=mf==='all'||(mf==='today'&&age>=0&&age<day)||(mf==='7d'&&age>=0&&age<7*day)||(mf==='30d'&&age>=0&&age<30*day)||(mf==='older'&&Number.isFinite(age)&&age>=30*day)||(mf==='unknown'&&!Number.isFinite(mt));r.style.display=(nameOk&&typeOk&&sizeOk&&modOk)?'':'none'}})}}
function keyNav(e){{const visible=rows().filter(r=>r.style.display!=='none');if(['ArrowDown','ArrowUp'].includes(e.key)){{e.preventDefault();if(!visible.length)return;let cur=FM.selected.length?FM.selected[FM.selected.length-1]:0;let pos=visible.findIndex(r=>+r.dataset.index===cur);pos=pos<0?0:pos+(e.key==='ArrowDown'?1:-1);pos=Math.max(0,Math.min(visible.length-1,pos));let idx=+visible[pos].dataset.index;if(e.shiftKey&&FM.anchor>=0){{let a=Math.min(FM.anchor,idx),b=Math.max(FM.anchor,idx);FM.selected=[...Array(b-a+1)].map((_,k)=>a+k)}}else if(e.metaKey||e.ctrlKey){{FM.selected=[idx]}}else{{FM.selected=[idx];FM.anchor=idx}}updateSel();visible[pos].scrollIntoView({{block:'nearest'}});return}}if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='a'){{e.preventDefault();FM.selected=visible.map(r=>+r.dataset.index);updateSel()}}else if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='c'){{e.preventDefault();copySelected()}}else if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='x'){{e.preventDefault();cutSelected()}}else if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='v'){{e.preventDefault();pasteSelected()}}else if(e.key==='F2'){{e.preventDefault();renameSelected()}}else if(e.key==='Delete'){{e.preventDefault();deleteSelected()}}else if(e.key==='Enter'){{e.preventDefault();if(FM.selected.length)rowOpen(FM.selected[FM.selected.length-1])}}else if(e.key==='Escape')closeMenu()}}
document.addEventListener('click',e=>{{if(!e.target.closest('#ctx')&&!e.target.closest('.fm-row'))closeMenu()}});document.addEventListener('contextmenu',e=>{{if(e.target.closest('.fm-row'))e.preventDefault()}});document.addEventListener('keydown',e=>{{if(e.key==='Escape')closeMenu()}});window.addEventListener('blur',fmPointerCancel);loadClipboard();updateClipboard();updateSel();focusList();
</script>
"""
    return page_shell("PNDCC Device Control Center · Phase 2D", body)


def device_control_page(remote_path="/"):
    # Phase 2D unified Finder/Explorer page. The legacy Phase 2C engine remains above.
    return _device_control_page_2d("remote", remote_path)


def _json_response(handler, obj, status=200):
    raw=json.dumps(obj).encode("utf-8")
    handler.send_response(status); handler.send_header("Content-Type","application/json; charset=utf-8"); handler.send_header("Content-Length",str(len(raw))); handler.send_header("Cache-Control","no-store"); handler.end_headers(); handler.wfile.write(raw)


def _phase2d_post(self):
    parsed=urllib.parse.urlparse(self.path)
    if parsed.path!="/device-control":
        self._send_text(404,"PNDCC 404 - Not Found"); return
    try:
        length=int(self.headers.get("Content-Length","0"))
        if length<=0 or length>PNDCC_UPLOAD_MAX_BYTES+2*1024*1024: raise ValueError("Invalid request size")
        raw=self.rfile.read(length)
        ctype=self.headers.get("Content-Type","").lower()
        if ctype.startswith("application/json"):
            obj=json.loads(raw.decode("utf-8")); action=obj.get("action","")
            source=obj.get("source","remote"); source="local" if source=="local" else "remote"
            if action=="open_local": _open_local(obj.get("path","/")); _json_response(self,{"ok":True,"message":"Opened on Mac"}); return
            if action=="mkdir":
                name=str(obj.get("name","")).strip(); parent=obj.get("path","/")
                if not name or "/" in name or "\\" in name: raise ValueError("Folder name must be a single name")
                if source=="local": os.mkdir(os.path.join(_local_path(parent),name))
                else: _ftp_make_directory(_join_remote_path(parent,name))
                _json_response(self,{"ok":True,"message":"Folder created: "+name}); return
            if action=="rename":
                if source=="local": _local_rename(obj["path"],obj["name"])
                else: _ftp_rename(obj["path"],obj["name"])
                _json_response(self,{"ok":True,"message":"Rename successful"}); return
            if action=="delete_many":
                for x in obj.get("items",[]):
                    if source=="local":
                        _local_delete(x["path"],x.get("type")=="directory")
                    else:
                        # FTP RMD only deletes EMPTY directories. Use the proven
                        # recursive Phase 2D delete engine for remote folders.
                        if x.get("type")=="directory":
                            _ftp_delete_tree(x["path"])
                        else:
                            _ftp_delete_item(x["path"],False)
                _json_response(self,{"ok":True,"message":"Deleted selected item(s)"}); return
            if action=="paste":
                dest_source=obj.get("destination_source","remote"); dest_source="local" if dest_source=="local" else "remote"
                mode=obj.get("mode","copy"); conflict=obj.get("conflict","replace")
                results=[]
                for x in obj.get("items",[]):
                    src=x["path"]
                    if source=="local" and dest_source=="local":
                        if mode=="move": r=_local_move(src,obj["destination"],conflict=="keep_both")
                        else: r=_local_copy(src,obj["destination"],conflict=="keep_both")
                    elif source=="remote" and dest_source=="remote":
                        if mode=="move": r=_ftp_move_item_recursive(src,obj["destination"],conflict=="keep_both")
                        else: r=_ftp_copy_item_recursive(src,obj["destination"],conflict=="keep_both")
                    elif source=="remote" and dest_source=="local":
                        if x.get("type")=="directory":
                            # recursive remote folder -> local folder
                            target=os.path.join(_local_path(obj["destination"]),os.path.basename(_clean_remote_path(src)))
                            if os.path.exists(target):
                                if conflict=="keep_both": target=_local_unique_name(_local_path(obj["destination"]),os.path.basename(src))
                                elif conflict=="replace": import shutil; shutil.rmtree(target)
                                else: raise FileExistsError(os.path.basename(src))
                            import shutil; os.makedirs(target,exist_ok=True)
                            def rec(rp,lp):
                                for it in _ftp_list_directory(rp).get("entries",[]):
                                    cp=_join_remote_path(rp,it["name"]); lp2=os.path.join(lp,it["name"])
                                    if it["type"]=="directory": os.makedirs(lp2,exist_ok=True); rec(cp,lp2)
                                    else:
                                        with open(lp2,"wb") as f:f.write(_remote_read_bytes(cp))
                            rec(src,target); r=_local_rel(target)
                        else: r=_download_to_local(src,obj["destination"],conflict=="keep_both")
                        if mode=="move": _ftp_delete_item(src,x.get("type")=="directory")
                    elif source=="local" and dest_source=="remote":
                        r=_upload_from_local(src,obj["destination"],conflict=="keep_both")
                        if mode=="move": _local_delete(src,x.get("type")=="directory")
                    else: raise ValueError("Unsupported storage combination")
                    results.append(r)
                _json_response(self,{"ok":True,"message":("Pasted " + str(len(results)) + " item(s)")}); return
            raise ValueError("Unsupported Phase 2D action")
        if ctype.startswith("multipart/form-data"):
            filename,data=_parse_multipart_upload(raw,self.headers.get("Content-Type",""))
            m=re.search(rb'name="path"\r\n\r\n([^\r\n]+)',raw); path=m.group(1).decode("utf-8","replace") if m else "/"
            m2=re.search(rb'name="source"\r\n\r\n([^\r\n]+)',raw); source=m2.group(1).decode("utf-8","replace") if m2 else "remote"
            if source=="local":
                p=os.path.join(_local_path(path),filename); 
                if os.path.exists(p): raise FileExistsError(filename)
                with open(p,"wb") as f:f.write(data)
            else:
                _ftp_upload_bytes(_join_remote_path(path,filename),data)
            self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length","0"); self.end_headers(); return
        # Legacy Phase 2C form compatibility.
        form=urllib.parse.parse_qs(raw.decode("utf-8","replace")); action=form.get("action",[""])[0]
        if action in {"mkdir","rename","delete","move","copy"}:
            source=form.get("source",["remote"])[0]; path=form.get("path",["/"])[0]
            if source=="local":
                if action=="mkdir": os.mkdir(os.path.join(_local_path(path),form.get("name",[""])[0]))
                elif action=="rename": _local_rename(path,form.get("name",[""])[0])
                elif action=="delete": _local_delete(path,form.get("kind",["file"])[0]=="directory")
                elif action=="move": _local_move(path,form.get("destination",["/"])[0])
                elif action=="copy": _local_copy(path,form.get("destination",["/"])[0])
            else:
                if action=="mkdir": _ftp_make_directory(_join_remote_path(path,form.get("name",[""])[0]))
                elif action=="rename": _ftp_rename(path,form.get("name",[""])[0])
                elif action=="delete": _ftp_delete_item(path,form.get("kind",["file"])[0]=="directory")
                elif action=="move": _ftp_move_item_recursive(path,form.get("destination",["/"])[0])
                elif action=="copy": _ftp_copy_item_recursive(path,form.get("destination",["/"])[0])
            self.send_response(303); self.send_header("Location","/device-control?source="+source+"&path="+urllib.parse.quote(path,safe="")); self.end_headers(); return
        raise ValueError("Unsupported request")
    except Exception as e:
        try: _json_response(self,{"ok":False,"message":f"{type(e).__name__}: {e}"},500)
        except Exception: self._send_text(500,str(e))


def _phase2d_get(self):
    parsed=urllib.parse.urlparse(self.path); path=parsed.path; params=urllib.parse.parse_qs(parsed.query)
    try:
        if path=="/device-control":
            body=_device_control_page_2d(params.get("source",["remote"])[0],params.get("path",["/"])[0]); data=body.encode("utf-8"); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(data))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(data); return
        if path=="/local-download":
            p=_local_path(params.get("path",["/"])[0]);
            if os.path.isdir(p): self._send_text(400,"Cannot download a folder"); return
            with open(p,"rb") as f:data=f.read()
            self.send_response(200); self.send_header("Content-Type",mimetypes.guess_type(p)[0] or "application/octet-stream"); self.send_header("Content-Disposition",'attachment; filename="'+os.path.basename(p).replace('"','')+'"'); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data); return
        # All other dashboard/health/history/download routes remain exactly as Phase 2C.
        return _OLD_GET(self)
    except Exception as e:
        self._send_text(500,f"PNDCC Phase 2D error: {type(e).__name__}: {e}")

_OLD_GET=H.do_GET
H.do_GET=_phase2d_get
H.do_POST=_phase2d_post

# Startup is intentionally placed after the isolated v2.1 configuration layer.
# This keeps the frozen Phase 2D code above intact while allowing configuration
# to be loaded before the HTTP server begins accepting requests.

# ============================================================================
# PNDCC v2.1 — Persistent Configuration Layer
# ============================================================================
# Isolated add-on. The frozen Phase 2D / FTPS / 550 Paste engine above is not
# modified. This section adds a small persistent JSON configuration store and
# a Settings page so normal configuration changes never require Python edits.
# Passwords remain outside this file and continue to use environment variables
# or the existing macOS Keychain integration.

PNDCC_VERSION = "2.1"
PNDCC_UPDATED = "2026-10-05 Persistent Configuration Layer"
PNDCC_CONFIG_DIR = os.path.join(BASE, "config")
PNDCC_PERSISTENT_CONFIG = os.path.join(PNDCC_CONFIG_DIR, "pndcc_config.json")


def _pndcc21_default_config():
    """Build a safe, non-secret configuration snapshot from the current run."""
    ftp = {
        "host": FTP_HOST,
        "port": FTP_PORT,
        "mode": FTP_MODE,
        "user": FTP_USER,
        "timeout": FTP_TIMEOUT,
    }
    monitoring = dict(SET.get("monitoring", {}) or {})
    thresholds = dict(SET.get("thresholds", {}) or {})
    server = dict(SET.get("server", {}) or {})
    return {
        "schema_version": 1,
        "project": PNDCC_PROJECT,
        "saved_at": now(),
        "server": server,
        "ftp": ftp,
        "monitoring": monitoring,
        "thresholds": thresholds,
    }


def _pndcc21_load_config():
    """Load persistent settings once at startup; create them on first run."""
    global FTP_HOST, FTP_PORT, FTP_MODE, FTP_USER, FTP_TIMEOUT, FTP_PASSWORD, SET
    os.makedirs(PNDCC_CONFIG_DIR, exist_ok=True)

    if not os.path.exists(PNDCC_PERSISTENT_CONFIG):
        with open(PNDCC_PERSISTENT_CONFIG, "w", encoding="utf-8") as f:
            json.dump(_pndcc21_default_config(), f, indent=2, ensure_ascii=False)
        try:
            os.chmod(PNDCC_PERSISTENT_CONFIG, 0o600)
        except OSError:
            pass
        return

    try:
        with open(PNDCC_PERSISTENT_CONFIG, encoding="utf-8") as f:
            saved = json.load(f)
        if not isinstance(saved, dict):
            raise ValueError("Configuration root must be an object")

        ftp = saved.get("ftp", {}) if isinstance(saved.get("ftp", {}), dict) else {}
        for key in ("server", "monitoring", "thresholds"):
            value = saved.get(key)
            if isinstance(value, dict):
                SET[key] = dict(value)

        if "ftp" in saved:
            FTP_HOST = str(ftp.get("host", FTP_HOST)).strip()
            try:
                FTP_PORT = int(ftp.get("port", FTP_PORT))
            except (TypeError, ValueError):
                FTP_PORT = 21
            FTP_MODE = str(ftp.get("mode", FTP_MODE)).strip().lower()
            if FTP_MODE not in {"ftp", "ftps"}:
                FTP_MODE = "ftp"
            FTP_USER = str(ftp.get("user", FTP_USER)).strip()
            # Refresh the Keychain lookup when the configured user changes.
            FTP_PASSWORD = os.environ.get("PNDCC_FTP_PASSWORD", "") or _ftp_password_from_keychain()
            try:
                FTP_TIMEOUT = float(ftp.get("timeout", FTP_TIMEOUT))
            except (TypeError, ValueError):
                FTP_TIMEOUT = 5.0
    except (OSError, ValueError, json.JSONDecodeError):
        # Do not break PNDCC because a configuration file is damaged. Keep the
        # already-loaded working configuration and let the Settings page repair it.
        pass



def _pndcc21_save_config(form):
    """Validate and persist non-secret runtime settings."""
    global FTP_HOST, FTP_PORT, FTP_MODE, FTP_USER, FTP_TIMEOUT, FTP_PASSWORD, SET

    host = str(form.get("ftp_host", [""])[0]).strip()
    mode = str(form.get("ftp_mode", ["ftp"])[0]).strip().lower()
    user = str(form.get("ftp_user", [""])[0]).strip()
    port_text = str(form.get("ftp_port", ["21"])[0]).strip()
    timeout_text = str(form.get("ftp_timeout", ["5"])[0]).strip()

    if mode not in {"ftp", "ftps"}:
        raise ValueError("FTP mode must be FTP or FTPS")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("FTP port must be between 1 and 65535")
    timeout = float(timeout_text)
    if not 1 <= timeout <= 120:
        raise ValueError("FTP timeout must be between 1 and 120 seconds")

    ping_count = max(1, int(form.get("ping_count", ["2"])[0]))
    ping_timeout = max(0.2, min(30.0, float(form.get("ping_timeout_seconds", ["1"])[0])))

    warning_latency = max(0.0, float(form.get("warning_latency_ms", ["100"])[0]))
    critical_latency = max(warning_latency, float(form.get("critical_latency_ms", ["250"])[0]))
    warning_loss = max(0.0, min(100.0, float(form.get("warning_packet_loss_pct", ["10"])[0])))
    critical_loss = max(warning_loss, min(100.0, float(form.get("critical_packet_loss_pct", ["50"])[0])))

    FTP_HOST, FTP_PORT, FTP_MODE, FTP_USER, FTP_TIMEOUT = host, port, mode, user, timeout
    FTP_PASSWORD = os.environ.get("PNDCC_FTP_PASSWORD", "") or _ftp_password_from_keychain()
    SET.setdefault("monitoring", {})
    SET.setdefault("thresholds", {})
    SET["monitoring"].update({
        "ping_count": ping_count,
        "ping_timeout_seconds": ping_timeout,
    })
    SET["thresholds"].update({
        "warning_latency_ms": warning_latency,
        "critical_latency_ms": critical_latency,
        "warning_packet_loss_pct": warning_loss,
        "critical_packet_loss_pct": critical_loss,
    })

    payload = _pndcc21_default_config()
    payload["saved_at"] = now()
    with open(PNDCC_PERSISTENT_CONFIG, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    try:
        os.chmod(PNDCC_PERSISTENT_CONFIG, 0o600)
    except OSError:
        pass


def _pndcc21_settings_page(message="", error=""):
    mon = SET.get("monitoring", {}) or {}
    th = SET.get("thresholds", {}) or {}
    escv = lambda v: esc(v)
    body = f"""
    <section class='hero'>
      <div class='hero-head'><div><h2>PNDCC Settings</h2><p>Persistent configuration · no Python code changes required.</p></div><div class='small' style='color:#d8e3ff'>v2.1</div></div>
    </section>
    {f"<section class='section'><div class='card'><div class='notice'>{esc(message)}</div></div></section>" if message else ""}
    {f"<section class='section'><div class='card'><div class='alert'>{esc(error)}</div></div></section>" if error else ""}
    <form method='POST' action='/settings'>
      <section class='section'><div class='section-head'><h2 class='section-title'>FTP / FTPS</h2><span class='section-note'>Saved locally</span></div>
        <div class='card'>
          <div class='grid'>
            <label>Host<input name='ftp_host' value='{escv(FTP_HOST)}' placeholder='192.168.2.162'></label>
            <label>Port<input name='ftp_port' type='number' min='1' max='65535' value='{escv(FTP_PORT)}'></label>
            <label>Mode<select name='ftp_mode'><option value='ftp' {'selected' if FTP_MODE=='ftp' else ''}>FTP</option><option value='ftps' {'selected' if FTP_MODE=='ftps' else ''}>FTPS</option></select></label>
            <label>User<input name='ftp_user' value='{escv(FTP_USER)}' autocomplete='username'></label>
            <label>Timeout (seconds)<input name='ftp_timeout' type='number' min='1' max='120' step='0.5' value='{escv(FTP_TIMEOUT)}'></label>
          </div>
          <div class='small' style='margin-top:12px'>Password is not stored in this configuration file. PNDCC continues to use the existing macOS Keychain / environment-variable password mechanism.</div>
        </div>
      </section>
      <section class='section'><div class='section-head'><h2 class='section-title'>Monitoring</h2><span class='section-note'>Persistent thresholds</span></div>
        <div class='card'><div class='grid'>
          <label>Ping count<input name='ping_count' type='number' min='1' max='10' value='{escv(mon.get("ping_count", 2))}'></label>
          <label>Ping timeout (seconds)<input name='ping_timeout_seconds' type='number' min='0.2' max='30' step='0.1' value='{escv(mon.get("ping_timeout_seconds", 1))}'></label>
          <label>Warning latency (ms)<input name='warning_latency_ms' type='number' min='0' step='1' value='{escv(th.get("warning_latency_ms", 100))}'></label>
          <label>Critical latency (ms)<input name='critical_latency_ms' type='number' min='0' step='1' value='{escv(th.get("critical_latency_ms", 250))}'></label>
          <label>Warning packet loss (%)<input name='warning_packet_loss_pct' type='number' min='0' max='100' step='1' value='{escv(th.get("warning_packet_loss_pct", 10))}'></label>
          <label>Critical packet loss (%)<input name='critical_packet_loss_pct' type='number' min='0' max='100' step='1' value='{escv(th.get("critical_packet_loss_pct", 50))}'></label>
        </div></div>
      </section>
      <section class='section'><div class='card'><button class='linkbtn' type='submit'>Save Configuration</button> <a class='linkbtn' href='/settings'>Reload</a> <a class='linkbtn' href='/'>← Dashboard</a></div></section>
    </form>
    """
    return page_shell("PNDCC Settings · v2.1", body).replace("Version 2.0", "Version 2.1").replace("PNDCC v2.0", "PNDCC v2.1")


# Load the persistent layer after the frozen Phase 2D code has been defined.
# This changes configuration values only; it does not replace any Phase 2D
# functions or FTP transfer functions.
_pndcc21_load_config()

# Add a Settings link without rewriting the existing dashboard renderer.
_PNDCC21_OLD_DASHBOARD = dashboard

def dashboard():
    page = _PNDCC21_OLD_DASHBOARD()
    page = page.replace("<a href='/api/status'>JSON status →</a>", "<a href='/settings'>Settings →</a><a href='/api/status'>JSON status →</a>")
    return page.replace("Version 2.0", "Version 2.1").replace("PNDCC v2.0", "PNDCC v2.1")


# Extend the already-installed Phase 2D handlers without modifying them.
_PNDCC21_OLD_GET = H.do_GET
_PNDCC21_OLD_POST = H.do_POST

def _pndcc21_get(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path == "/settings":
        data = _pndcc21_settings_page().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        return
    return _PNDCC21_OLD_GET(self)


def _pndcc21_post(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path != "/settings":
        return _PNDCC21_OLD_POST(self)
    try:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 64 * 1024:
            self._send_text(400, "Invalid settings request")
            return
        raw = self.rfile.read(length)
        form = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
        _pndcc21_save_config(form)
        data = _pndcc21_settings_page("Configuration saved successfully. PNDCC will use it on future starts.").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
    except Exception as e:
        data = _pndcc21_settings_page(error=f"Configuration was not saved: {type(e).__name__}: {e}").encode("utf-8")
        self.send_response(400)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


H.do_GET = _pndcc21_get
H.do_POST = _pndcc21_post

# ============================================================================
# End PNDCC v2.1 Persistent Configuration Layer
# ============================================================================


# ============================================================================
# PNDCC v2.2 — Phase 3A: Network Pulse
# ============================================================================
# ADDITIVE ONLY:
# The complete v2.1 Phase 2D / FTPS / 550 Paste / persistent configuration
# implementation above remains intact. This section only adds Network Pulse.
#
# Network Pulse is read-only and local to the Mac:
# - Internet reachability / latency / packet loss
# - DNS response time
# - Download / upload throughput from macOS interface byte counters
# - Active TCP / UDP connection counts
# - Network health score
#
# No existing monitoring, FTP/FTPS, File Manager, history, alert, storage,
# cloud, or Settings functions are replaced.

PNDCC_PHASE3A_VERSION = "3A"
PNDCC_PHASE3A_NAME = "Network Pulse"

_PNDCC3A_TRAFFIC_BASELINE = None
_PNDCC3A_TRAFFIC_TIME = None


def _pndcc3a_run_cmd(args, timeout=5):
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return (p.stdout or "").strip(), (p.stderr or "").strip(), p.returncode
    except (OSError, subprocess.SubprocessError):
        return "", "", 1


def _pndcc3a_ping(host="1.1.1.1", count=3, timeout=6):
    out, _, rc = _pndcc3a_run_cmd(
        ["/sbin/ping", "-c", str(count), host],
        timeout=timeout,
    )
    loss_match = re.search(r"([0-9.]+)% packet loss", out)
    avg_match = re.search(
        r"round-trip .*?= [0-9.]+/([0-9.]+)/[0-9.]+/[0-9.]+ ms",
        out,
    )
    loss = float(loss_match.group(1)) if loss_match else None
    latency = float(avg_match.group(1)) if avg_match else None
    return {
        "host": host,
        "packet_loss_pct": loss,
        "latency_ms": latency,
        "reachable": bool(rc == 0 and loss is not None and loss < 100.0),
    }


def _pndcc3a_dns():
    # dig is read-only and normally available on macOS.
    start = time.perf_counter()
    out, _, rc = _pndcc3a_run_cmd(
        ["/usr/bin/dig", "+time=2", "+tries=1", "example.com"],
        timeout=4,
    )
    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)

    server_match = re.search(r"SERVER:\s*([^\s#]+)", out)
    query_match = re.search(r"Query time:\s*(\d+)\s*msec", out)
    answer_match = re.search(r"ANSWER:\s*(\d+)", out)

    query_ms = float(query_match.group(1)) if query_match else elapsed_ms
    answer_count = int(answer_match.group(1)) if answer_match else 0
    ok = rc == 0 and answer_count > 0

    return {
        "status": "ONLINE" if ok else "OFFLINE",
        "response_ms": round(query_ms, 2) if ok else None,
        "server": server_match.group(1) if server_match else "—",
        "answer_count": answer_count,
    }


def _pndcc3a_interface_traffic():
    """
    Read aggregate interface byte counters from netstat -ib.
    Loopback is excluded. Values are deltas from the previous snapshot.
    """
    out, _, rc = _pndcc3a_run_cmd(["/usr/sbin/netstat", "-ib"], timeout=4)
    if rc != 0 or not out:
        return {
            "download_mbps": None,
            "upload_mbps": None,
            "rx_bytes": None,
            "tx_bytes": None,
            "interfaces": 0,
        }

    totals = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 10:
            continue
        name = parts[0]
        if name == "Name" or name == "lo0" or name.startswith("lo"):
            continue

        # macOS netstat -ib commonly reports:
        # Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes ...
        try:
            rx = int(parts[6])
            tx = int(parts[9])
        except (ValueError, IndexError):
            continue

        # Keep the largest byte counters seen for each physical interface.
        if name not in totals:
            totals[name] = [rx, tx]
        else:
            totals[name][0] = max(totals[name][0], rx)
            totals[name][1] = max(totals[name][1], tx)

    rx_total = sum(v[0] for v in totals.values())
    tx_total = sum(v[1] for v in totals.values())

    global _PNDCC3A_TRAFFIC_BASELINE, _PNDCC3A_TRAFFIC_TIME
    now_mono = time.monotonic()

    download_mbps = None
    upload_mbps = None
    if _PNDCC3A_TRAFFIC_BASELINE is not None and _PNDCC3A_TRAFFIC_TIME is not None:
        elapsed = now_mono - _PNDCC3A_TRAFFIC_TIME
        old_rx, old_tx = _PNDCC3A_TRAFFIC_BASELINE
        if elapsed > 0:
            download_mbps = max(0.0, (rx_total - old_rx) * 8.0 / elapsed / 1_000_000.0)
            upload_mbps = max(0.0, (tx_total - old_tx) * 8.0 / elapsed / 1_000_000.0)

    _PNDCC3A_TRAFFIC_BASELINE = (rx_total, tx_total)
    _PNDCC3A_TRAFFIC_TIME = now_mono

    return {
        "download_mbps": round(download_mbps, 2) if download_mbps is not None else None,
        "upload_mbps": round(upload_mbps, 2) if upload_mbps is not None else None,
        "rx_bytes": rx_total,
        "tx_bytes": tx_total,
        "interfaces": len(totals),
    }


def _pndcc3a_connections():
    tcp_out, _, tcp_rc = _pndcc3a_run_cmd(
        ["/usr/sbin/netstat", "-an", "-p", "tcp"],
        timeout=4,
    )
    udp_out, _, udp_rc = _pndcc3a_run_cmd(
        ["/usr/sbin/netstat", "-an", "-p", "udp"],
        timeout=4,
    )

    tcp = 0
    udp = 0
    established = 0

    if tcp_rc == 0:
        for line in tcp_out.splitlines():
            if not line.startswith("tcp"):
                continue
            tcp += 1
            if "ESTABLISHED" in line:
                established += 1

    if udp_rc == 0:
        for line in udp_out.splitlines():
            if not line.startswith("udp"):
                continue
            udp += 1

    return {
        "tcp": tcp,
        "udp": udp,
        "established_tcp": established,
        "total": tcp + udp,
    }


def _pndcc3a_health(ping_result, dns_result):
    score = 100.0
    loss = ping_result.get("packet_loss_pct")
    latency = ping_result.get("latency_ms")
    dns_ms = dns_result.get("response_ms")

    if loss is None:
        score -= 25
    elif loss > 0:
        score -= min(45, loss * 2.0)

    if latency is None:
        score -= 15
    elif latency > 20:
        score -= min(20, (latency - 20) / 10.0)
    if latency is not None and latency > 100:
        score -= min(20, (latency - 100) / 10.0)

    if dns_result.get("status") != "ONLINE":
        score -= 20
    elif dns_ms is not None and dns_ms > 100:
        score -= min(15, (dns_ms - 100) / 20.0)

    score = max(0.0, min(100.0, score))
    if score >= 90:
        status = "EXCELLENT"
    elif score >= 75:
        status = "GOOD"
    elif score >= 50:
        status = "WARNING"
    else:
        status = "CRITICAL"

    return {"score": round(score, 1), "status": status}


def _pndcc3a_network_pulse():
    ping_result = _pndcc3a_ping()
    dns_result = _pndcc3a_dns()
    traffic = _pndcc3a_interface_traffic()
    connections = _pndcc3a_connections()
    health = _pndcc3a_health(ping_result, dns_result)

    return {
        "phase": PNDCC_PHASE3A_VERSION,
        "name": PNDCC_PHASE3A_NAME,
        "timestamp": now(),
        "internet": {
            "status": "ONLINE" if ping_result["reachable"] else "OFFLINE",
            "latency_ms": ping_result["latency_ms"],
            "packet_loss_pct": ping_result["packet_loss_pct"],
            "test_host": ping_result["host"],
        },
        "dns": dns_result,
        "traffic": traffic,
        "connections": connections,
        "network_health": health,
    }


def _pndcc3a_fmt(value, suffix=""):
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.2f}{suffix}"
    return f"{value}{suffix}"


def _pndcc3a_network_pulse_html(pulse):
    internet = pulse["internet"]
    dns = pulse["dns"]
    traffic = pulse["traffic"]
    connections = pulse["connections"]
    health = pulse["network_health"]

    health_cls = health["status"]
    internet_status = internet["status"]

    return f"""
    <section class='section'>
      <div class='section-head'>
        <h2 class='section-title'>Network Pulse</h2>
        <span class='section-note'>Phase 3A · read-only network snapshot</span>
      </div>
      <div class='grid'>
        <div class='card'>
          <div class='metric-label'>INTERNET</div>
          <div class='kpi-value {esc(internet_status)}'>{esc(internet_status)}</div>
          <div class='small'>Latency {_pndcc3a_fmt(internet.get('latency_ms'), ' ms')} · Loss {_pndcc3a_fmt(internet.get('packet_loss_pct'), '%')}</div>
        </div>
        <div class='card'>
          <div class='metric-label'>DNS</div>
          <div class='kpi-value'>{esc(dns.get('status', '—'))}</div>
          <div class='small'>Response {_pndcc3a_fmt(dns.get('response_ms'), ' ms')} · Server {esc(dns.get('server', '—'))}</div>
        </div>
        <div class='card'>
          <div class='metric-label'>DOWNLOAD</div>
          <div class='kpi-value'>{_pndcc3a_fmt(traffic.get('download_mbps'), ' Mbps')}</div>
          <div class='small'>Live interface throughput</div>
        </div>
        <div class='card'>
          <div class='metric-label'>UPLOAD</div>
          <div class='kpi-value'>{_pndcc3a_fmt(traffic.get('upload_mbps'), ' Mbps')}</div>
          <div class='small'>Live interface throughput</div>
        </div>
        <div class='card'>
          <div class='metric-label'>CONNECTIONS</div>
          <div class='kpi-value'>{connections.get('total', 0)}</div>
          <div class='small'>TCP {connections.get('tcp', 0)} · UDP {connections.get('udp', 0)} · Established TCP {connections.get('established_tcp', 0)}</div>
        </div>
        <div class='card'>
          <div class='metric-label'>NETWORK HEALTH</div>
          <div class='kpi-value {esc(health_cls)}'>{esc(health.get('score'))}/100</div>
          <div class='small'>{esc(health_cls)}</div>
          <div class='bar'><span style='width:{max(0, min(100, health.get("score", 0)))}%'></span></div>
        </div>
      </div>
    </section>
    """


_PNDCC3A_OLD_DASHBOARD = dashboard

def dashboard():
    # Preserve the complete v2.1 dashboard and append one new Network Pulse
    # section before the existing Control Center navigation.
    page = _PNDCC3A_OLD_DASHBOARD()
    try:
        pulse = _pndcc3a_network_pulse()
        panel = _pndcc3a_network_pulse_html(pulse)
        marker = "<section class='section'><div class='section-head'><h2 class='section-title'>Control Center</h2>"
        if marker in page:
            page = page.replace(marker, panel + marker, 1)
        else:
            page = page.replace("</div></body></html>", panel + "</div></body></html>", 1)
    except Exception as e:
        # Network Pulse must never break the frozen v2.1 dashboard.
        fallback = (
            "<section class='section'><div class='section-head'>"
            "<h2 class='section-title'>Network Pulse</h2>"
            "<span class='section-note'>Phase 3A</span></div>"
            "<div class='card'><div class='notice'>Network Pulse temporarily unavailable: "
            + esc(type(e).__name__) + "</div></div></section>"
        )
        marker = "<section class='section'><div class='section-head'><h2 class='section-title'>Control Center</h2>"
        if marker in page:
            page = page.replace(marker, fallback + marker, 1)

    return page.replace("Version 2.0", "Version 2.2").replace("PNDCC v2.0", "PNDCC v2.2")


_PNDCC3A_OLD_GET = H.do_GET

def _pndcc3a_get(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path == "/api/network-pulse":
        try:
            self._send_json(_pndcc3a_network_pulse())
        except Exception as e:
            self._send_json(
                {"ok": False, "message": f"{type(e).__name__}: {e}"},
                500,
            )
        return
    if parsed.path == "/network-pulse":
        try:
            pulse = _pndcc3a_network_pulse()
            body = page_shell(
                "PNDCC Network Pulse · Phase 3A",
                _pndcc3a_network_pulse_html(pulse) +
                "<section class='section'><div class='card'><div class='nav'>"
                "<a href='/'>← Dashboard</a>"
                "<a href='/api/network-pulse'>JSON Network Pulse →</a>"
                "</div></div></section>"
            )
        except Exception as e:
            body = page_shell(
                "PNDCC Network Pulse · Phase 3A",
                "<section class='section'><div class='card'><div class='notice'>"
                + esc(type(e).__name__) + ": " + esc(str(e)) +
                "</div></div></section>"
            )
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        return
    return _PNDCC3A_OLD_GET(self)


H.do_GET = _pndcc3a_get

# Add one navigation link without altering the existing dashboard content.
_PNDCC3A_OLD_DASHBOARD2 = dashboard

def dashboard():
    page = _PNDCC3A_OLD_DASHBOARD2()
    link = "<a href='/network-pulse'>Network Pulse →</a>"
    marker = "<a href='/network-diagnostics'>Open Network Diagnostics →</a>"
    if link not in page and marker in page:
        page = page.replace(marker, marker + link, 1)
    return page


PNDCC_VERSION = "2.2"
PNDCC_UPDATED = "2026-10-05 Phase 3A Network Pulse"


# ============================================================================
# PNDCC v2.2 Phase 3A — Network Pulse reliability patch
# Author: Saiful Quadir
# Project: PNDCC
# Updated: 2026-10-05
# Copyright: © Saiful Quadir
#
# ADDITIVE ONLY. This patch replaces only the Phase 3A measurement helpers.
# Phase 2D, 550 Paste, FTP/FTPS, persistent settings, history, alerts,
# storage/cloud, device monitoring, and their handlers are not modified.
# ============================================================================


def _pndcc3a_dns():
    """Measure DNS with multiple known-good domains.

    A single NXDOMAIN response does not mean the DNS server is offline.
    The resolver must successfully answer at least one known-good public
    domain before PNDCC reports DNS ONLINE.
    """
    test_domains = ("example.com", "google.com", "cloudflare.com")
    last_server = "—"
    last_error_domain = None

    for domain in test_domains:
        start = time.perf_counter()
        out, _, rc = _pndcc3a_run_cmd(
            ["/usr/bin/dig", "+time=2", "+tries=1", domain],
            timeout=4,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        server_match = re.search(r"SERVER:\s*([^\s#]+)", out)
        query_match = re.search(r"Query time:\s*(\d+)\s*msec", out)
        answer_match = re.search(r"ANSWER:\s*(\d+)", out)
        status_match = re.search(r"status:\s*([A-Z]+)", out)

        if server_match:
            last_server = server_match.group(1)
        answer_count = int(answer_match.group(1)) if answer_match else 0
        query_ms = float(query_match.group(1)) if query_match else elapsed_ms
        dns_status = status_match.group(1) if status_match else ""

        if rc == 0 and answer_count > 0:
            return {
                "status": "ONLINE",
                "response_ms": round(query_ms, 2),
                "server": last_server,
                "answer_count": answer_count,
                "method": "dig",
                "test_domain": domain,
            }

        last_error_domain = domain

    # Final fallback: use the macOS/Python system resolver.
    fallback_start = time.perf_counter()
    try:
        socket.getaddrinfo("google.com", 80, type=socket.SOCK_STREAM)
        return {
            "status": "ONLINE",
            "response_ms": round((time.perf_counter() - fallback_start) * 1000.0, 2),
            "server": last_server if last_server != "—" else "System Resolver",
            "answer_count": 1,
            "method": "system resolver",
            "test_domain": "google.com",
        }
    except OSError:
        return {
            "status": "OFFLINE",
            "response_ms": None,
            "server": last_server,
            "answer_count": 0,
            "method": "dig + system resolver",
            "test_domain": last_error_domain or "—",
        }


def _pndcc3a_interface_totals():
    """Return aggregate non-loopback interface byte counters."""
    out, _, rc = _pndcc3a_run_cmd(["/usr/sbin/netstat", "-ib"], timeout=4)
    if rc != 0 or not out:
        return None

    totals = {}
    header = None
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "Name":
            header = parts
            continue
        if len(parts) < 2 or parts[0] == "Name":
            continue

        name = parts[0]
        if name == "lo0" or name.startswith("lo"):
            continue

        # Prefer named columns so this remains correct if macOS output adds
        # or reorders fields. Fall back to the common macOS positions.
        try:
            if header and "Ibytes" in header and "Obytes" in header:
                rx = int(parts[header.index("Ibytes")])
                tx = int(parts[header.index("Obytes")])
            else:
                rx = int(parts[6])
                tx = int(parts[9])
        except (ValueError, IndexError):
            continue

        if name not in totals:
            totals[name] = [rx, tx]
        else:
            totals[name][0] = max(totals[name][0], rx)
            totals[name][1] = max(totals[name][1], tx)

    if not totals:
        return None
    return sum(v[0] for v in totals.values()), sum(v[1] for v in totals.values()), len(totals)


def _pndcc3a_interface_traffic():
    """Measure live aggregate throughput over a short read-only interval."""
    first = _pndcc3a_interface_totals()
    if first is None:
        return {
            "download_mbps": None,
            "upload_mbps": None,
            "rx_bytes": None,
            "tx_bytes": None,
            "interfaces": 0,
            "sample_seconds": None,
        }

    # A short second sample makes the metric useful on the first page load;
    # the old one-snapshot baseline otherwise displayed an unavoidable '—'.
    time.sleep(0.35)
    second = _pndcc3a_interface_totals() or first
    elapsed = 0.35

    rx_delta = max(0, second[0] - first[0])
    tx_delta = max(0, second[1] - first[1])
    download_mbps = rx_delta * 8.0 / elapsed / 1_000_000.0
    upload_mbps = tx_delta * 8.0 / elapsed / 1_000_000.0

    return {
        "download_mbps": round(download_mbps, 2),
        "upload_mbps": round(upload_mbps, 2),
        "rx_bytes": second[0],
        "tx_bytes": second[1],
        "interfaces": second[2],
        "sample_seconds": elapsed,
    }


# Make the completed Phase 3A version visible on the existing dashboard only.
_PNDCC3A_OLD_DASHBOARD3 = dashboard

def dashboard():
    page = _PNDCC3A_OLD_DASHBOARD3()
    return page.replace("Version 2.1", "Version 2.2").replace("PNDCC v2.1", "PNDCC v2.2")

PNDCC_VERSION = "2.2"
PNDCC_UPDATED = "2026-10-05 Phase 3A Network Pulse"


# ============================================================================
# PNDCC v2.2 Phase 3A — Final Network Pulse health correction
# Additive only. Existing Phase 2D / FTP / device-monitoring code is untouched.
# ============================================================================

def _pndcc3a_health(ping_result, dns_result):
    """Score Internet/network health without treating a false DNS reading as an Internet failure."""
    score = 100.0
    loss = ping_result.get("packet_loss_pct")
    latency = ping_result.get("latency_ms")
    dns_ms = dns_result.get("response_ms")
    internet_online = bool(ping_result.get("reachable"))

    if loss is None:
        score -= 10
    elif loss > 0:
        score -= min(45.0, loss * 2.0)

    if latency is None:
        score -= 10
    elif latency > 20:
        score -= min(20.0, (latency - 20.0) / 10.0)
    if latency is not None and latency > 100:
        score -= min(20.0, (latency - 100.0) / 10.0)

    # DNS is a separate signal. If Internet ping is healthy but DNS reports
    # OFFLINE, do not let a resolver/parser anomaly dominate the score.
    if dns_result.get("status") == "ONLINE":
        if dns_ms is not None and dns_ms > 100:
            score -= min(10.0, (dns_ms - 100.0) / 20.0)
    elif not internet_online:
        score -= 15.0

    score = max(0.0, min(100.0, score))
    if score >= 90:
        status = "EXCELLENT"
    elif score >= 75:
        status = "GOOD"
    elif score >= 50:
        status = "WARNING"
    else:
        status = "CRITICAL"

    return {"score": round(score, 1), "status": status}


# ============================================================================
# PNDCC v2.2 FINAL — Dashboard response isolation
# Additive-only fix: live device/FTP/storage/cloud checks run in a background
# refresh loop. The HTTP dashboard renders the latest completed snapshot so a
# slow FTPS/storage check can never block GET /.
# ============================================================================

_PNDCC_DASHBOARD_CACHE = {
    "results": [],
    "ftp": {"status": "NOT CHECKED", "latency_ms": "—", "test": "Waiting for monitor", "mode": FTP_MODE.upper()},
    "storage": [],
    "cloud": [],
    "pulse": None,
    "updated": None,
}
_PNDCC_DASHBOARD_CACHE_LOCK = Lock()


def _pndcc_dashboard_cache_snapshot():
    with _PNDCC_DASHBOARD_CACHE_LOCK:
        return dict(_PNDCC_DASHBOARD_CACHE)


def _pndcc_dashboard_refresh_once():
    results = check_all()
    log_alerts(results)
    ftp = ftp_check()
    log_ftp(ftp)
    storage = storage_items()
    cloud = cloud_items()
    try:
        pulse = _pndcc3a_network_pulse()
    except Exception:
        pulse = None
    with _PNDCC_DASHBOARD_CACHE_LOCK:
        _PNDCC_DASHBOARD_CACHE.update({
            "results": results,
            "ftp": ftp,
            "storage": storage,
            "cloud": cloud,
            "pulse": pulse,
            "updated": now(),
        })


def _pndcc_dashboard_monitor():
    while True:
        try:
            _pndcc_dashboard_refresh_once()
        except Exception as e:
            print(f"PNDCC dashboard monitor warning: {type(e).__name__}: {e}")
        time.sleep(30)


def _pndcc_dashboard_fast():
    snap = _pndcc_dashboard_cache_snapshot()
    results = snap.get("results") or []
    ftp = snap.get("ftp") or {}
    personal = personal_devices()
    x = {r.get("target_id"): r for r in results}
    online = sum(1 for d in personal if x.get(d.get("id"), {}).get("status") == "ONLINE")
    alerts = sum(1 for r in results if r.get("status") in {"WARNING", "CRITICAL", "OFFLINE"})
    hs = health_summary(results)
    recent = list(reversed(recent_alerts(5)))
    cards = [device_card(d, x.get(d.get("id"), {"status": "NOT CHECKED", "latency_ms": "—", "packet_loss_pct": "—"})) for d in personal]
    rr = next((r for r in results if r.get("target_id") == "router"), None)
    router_status = rr.get("status", "NOT CHECKED") if rr else "NOT CHECKED"

    pulse = snap.get("pulse") or {}
    internet = pulse.get("internet", {}) if isinstance(pulse, dict) else {}
    internet_status = internet.get("status", "NOT CHECKED")
    ftpcls = str(ftp.get("status", "NOT CONFIGURED")).replace(" ", "-")

    body = f"""
    <section class='hero'>
      <div class='hero-head'><div><h2>Network overview</h2><p>At-a-glance status of connected devices and services.</p></div><div class='small' style='color:#d8e3ff'>Auto-refresh: 30 seconds</div></div>
      <div class='kpis'>
        <div class='kpi'><div class='kpi-label'>ACTIVE DEVICES ONLINE</div><div class='kpi-value'>{online}/{len(personal)}</div></div>
        <div class='kpi'><div class='kpi-label'>ROUTER</div><div class='kpi-value {esc(router_status)}'>{esc(router_status)}</div></div>
        <div class='kpi'><div class='kpi-label'>INTERNET</div><div class='kpi-value {esc(internet_status)}'>{esc(internet_status)}</div></div>
        <div class='kpi'><div class='kpi-label'>FTP / FTPS</div><div class='kpi-value {esc(ftpcls)}'>{esc(ftp.get('status'))}</div></div>
        <div class='kpi'><div class='kpi-label'>ACTIVE ALERTS</div><div class='kpi-value'>{alerts}</div></div>
      </div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Network devices</h2><span class='section-note'>Latest monitoring snapshot</span></div><div class='grid'>{''.join(cards) or '<div class="notice">No enabled personal devices found.</div>'}</div></section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Network health</h2><span class='section-note'>Current monitoring snapshot</span></div>
      <div class='card'><div class='metric-label'>ONLINE RATIO</div><div class='kpi-value'>{hs["health_pct"]}%</div><div class='bar'><span style='width:{hs["health_pct"]}%'></span></div><div class='small'>Online {hs["counts"]["ONLINE"]} · Warning {hs["counts"]["WARNING"]} · Critical {hs["counts"]["CRITICAL"]} · Offline {hs["counts"]["OFFLINE"]}</div></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Active alerts</h2><span class='section-note'>Latest recorded events</span></div>
      <div class='card'><div class='alert-list'>{''.join(f"<div class='alert-item'><span class='pill {esc(a.get('status',''))}'>{esc(a.get('status',''))}</span><div class='message'><b>{esc(a.get('name','Device'))}</b><div class='meta'>{esc(a.get('message',''))} · {esc(a.get('ip',''))}</div></div><span class='meta'>{esc(a.get('timestamp',''))}</span></div>" for a in recent) or '<div class="notice">No active alert events recorded.</div>'}</div><div class='nav' style='margin-top:12px'><a href='/alerts'>Open alert history →</a></div></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>FTP monitor</h2><span class='section-note'>Latest completed service handshake</span></div>
      <div class='card ftp-card'><div class='ftp-main'><h3>{esc(FTP_HOST or 'FTP host not configured')}</h3><div class='small'>Mode: {esc(ftp.get('mode', FTP_MODE.upper()))} · Port {esc(FTP_PORT)}</div><div class='ftp-status {esc(ftpcls)}'>{esc(ftp.get('status'))}</div></div><div><div class='metric-label'>Connection latency</div><div class='metric-value'>{esc(ftp.get('latency_ms'))}</div></div><div><div class='metric-label'>Test</div><div class='metric-value'>{esc(ftp.get('test'))}</div></div></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Storage</h2><span class='section-note'>Latest completed snapshot</span></div><div class='grid'>{''.join(storage_card(x) for x in (snap.get('storage') or []))}</div></section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Cloud storage</h2><span class='section-note'>Latest completed snapshot</span></div><div class='grid'>{''.join(cloud_card(x) for x in (snap.get('cloud') or []))}</div></section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Network Pulse</h2><span class='section-note'>Phase 3A · latest completed snapshot</span></div>
      <div class='card'><div class='grid'>
        <div><div class='metric-label'>INTERNET LATENCY</div><div class='metric-value'>{esc(internet.get('latency_ms', '—'))} ms</div></div>
        <div><div class='metric-label'>PACKET LOSS</div><div class='metric-value'>{esc(internet.get('packet_loss_pct', '—'))}%</div></div>
        <div><div class='metric-label'>DNS</div><div class='metric-value'>{esc((pulse.get('dns') or {}).get('status', '—'))}</div></div>
        <div><div class='metric-label'>NETWORK HEALTH</div><div class='metric-value'>{esc((pulse.get('network_health') or {}).get('score', '—'))}/100</div></div>
      </div><div class='nav' style='margin-top:12px'><a href='/network-pulse'>Open Network Pulse →</a></div></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Control Center</h2><span class='section-note'>Phase 2 · safe file access</span></div><div class='card'><div class='nav'><a href='/device-control'>Open Device Control →</a><a href='/network-diagnostics'>Open Network Diagnostics →</a><a href='/history'>Open device history →</a><a href='/ftp-history'>Open FTP history →</a><a href='/api/status'>JSON status →</a></div></div></section>
    """
    return page_shell("PNDCC v2.2", body).replace("Version 2.0", "Version 2.2").replace("PNDCC v2.0", "PNDCC v2.2")


# Replace only the dashboard renderer; all existing engines/routes remain intact.
dashboard = _pndcc_dashboard_fast

# Start the live monitor without blocking the HTTP server startup or requests.
Thread(target=_pndcc_dashboard_monitor, daemon=True, name="PNDCC-Dashboard-Monitor").start()


# ============================================================================
# PNDCC v2.3 Phase 3B — Decision / Action Engine
# Additive-only safety layer.
#
# IMPORTANT:
# - Existing Phase 2D, FTP/FTPS, Keychain, Network Pulse, storage, cloud,
#   device configuration, and connection code are NOT modified here.
# - This phase is recommendation-only. It NEVER changes passwords,
#   connections, files, device configuration, or services automatically.
# - Powered-off personal devices are treated as informational and do not
#   create action recommendations.
# ============================================================================

PNDCC_PHASE3B_VERSION = "3B"
PNDCC_PHASE3B_HISTORY = os.path.join(BASE, "data", "phase3b_decisions.jsonl")


def _pndcc3b_safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _pndcc3b_add_decision(items, severity, area, subject, condition, recommendation):
    items.append({
        "severity": severity,
        "area": area,
        "subject": subject,
        "condition": condition,
        "recommendation": recommendation,
    })


def _pndcc3b_decide(snapshot=None):
    """Read the latest completed PNDCC snapshot and make safe recommendations."""
    snap = snapshot if isinstance(snapshot, dict) else _pndcc_dashboard_cache_snapshot()
    results = snap.get("results") or []
    ftp = snap.get("ftp") or {}
    storage = snap.get("storage") or []
    cloud = snap.get("cloud") or []
    pulse = snap.get("pulse") or {}

    decisions = []
    checked = 0

    # Network Pulse / Internet / DNS — read-only observation.
    internet = (pulse.get("internet") or {}) if isinstance(pulse, dict) else {}
    dns = (pulse.get("dns") or {}) if isinstance(pulse, dict) else {}
    health = (pulse.get("network_health") or {}) if isinstance(pulse, dict) else {}
    internet_status = str(internet.get("status", "")).upper()
    dns_status = str(dns.get("status", "")).upper()

    if internet_status == "OFFLINE":
        _pndcc3b_add_decision(
            decisions, "CRITICAL", "Network Pulse", "Internet",
            "Internet connectivity is offline.",
            "Run Network Diagnostics and verify router/Wi-Fi connectivity. No automatic network change will be made.",
        )
    elif internet_status == "ONLINE":
        checked += 1
        latency = _pndcc3b_safe_float(internet.get("latency_ms"))
        loss = _pndcc3b_safe_float(internet.get("packet_loss_pct"))
        if (latency is not None and latency >= 100) or (loss is not None and loss >= 10):
            _pndcc3b_add_decision(
                decisions, "WARNING", "Network Pulse", "Internet",
                f"Elevated latency/loss detected ({latency if latency is not None else '—'} ms, {loss if loss is not None else '—'}% loss).",
                "Review Network Diagnostics before taking any action.",
            )

    if dns_status == "OFFLINE" and internet_status != "OFFLINE":
        _pndcc3b_add_decision(
            decisions, "WARNING", "Network Pulse", "DNS",
            "Internet is reachable but DNS is not reporting ONLINE.",
            "Review DNS diagnostics; do not change resolver settings automatically.",
        )
    elif dns_status == "ONLINE":
        checked += 1

    # FTP/FTPS — observation only. Passwords are never read or changed here.
    ftp_status = str(ftp.get("status", "")).upper()
    if ftp_status in {"OFFLINE", "ERROR", "FAILED"}:
        _pndcc3b_add_decision(
            decisions, "CRITICAL", "FTP/FTPS", str(FTP_HOST or "FTP host"),
            f"FTP/FTPS monitor reports {ftp_status}.",
            "Run the existing FTPS service test/history. Do not change the saved password or connection settings automatically.",
        )
    elif ftp_status == "ONLINE":
        checked += 1

    # Device state — OFFLINE is informational because devices may simply be off.
    # WARNING/CRITICAL are useful decisions when a device is actually responding.
    for row in results:
        status_value = str(row.get("status", "")).upper()
        name = str(row.get("name", "Device"))
        ip = str(row.get("ip", ""))
        if status_value == "CRITICAL":
            _pndcc3b_add_decision(
                decisions, "CRITICAL", "Device", name,
                f"Device {ip} reports critical latency or packet loss.",
                "Review device/network diagnostics. No device settings or connections will be changed automatically.",
            )
        elif status_value == "WARNING":
            _pndcc3b_add_decision(
                decisions, "WARNING", "Device", name,
                f"Device {ip} reports elevated latency or packet loss.",
                "Monitor the next samples and review diagnostics if the warning persists.",
            )
        elif status_value == "ONLINE":
            checked += 1

    # Storage — recommendation only; no deletion/cleanup action is performed.
    for item in storage:
        pct = _pndcc3b_safe_float(item.get("used_pct"))
        if pct is not None and pct >= 95:
            _pndcc3b_add_decision(
                decisions, "CRITICAL", "Storage", str(item.get("name", "Storage")),
                f"Storage usage is {pct:.1f}%.",
                "Review large files and backup strategy before any cleanup. Nothing is deleted automatically.",
            )
        elif pct is not None and pct >= 90:
            _pndcc3b_add_decision(
                decisions, "WARNING", "Storage", str(item.get("name", "Storage")),
                f"Storage usage is {pct:.1f}%.",
                "Review storage usage when convenient; no automatic cleanup is performed.",
            )

    # Cloud — recommendation only; provider connections remain untouched.
    for item in cloud:
        pct = _pndcc3b_safe_float(item.get("used_pct"))
        status_value = str(item.get("status", "")).upper()
        if pct is not None and pct >= 99.5:
            _pndcc3b_add_decision(
                decisions, "CRITICAL", "Cloud", str(item.get("name", "Cloud")),
                f"Cloud storage is {pct:.1f}% used.",
                "Review provider storage options. No cloud files, sync settings, or accounts will be changed automatically.",
            )
        elif pct is not None and pct >= 90:
            _pndcc3b_add_decision(
                decisions, "WARNING", "Cloud", str(item.get("name", "Cloud")),
                f"Cloud storage is {pct:.1f}% used.",
                "Review provider storage usage; no cloud files or sync settings are changed automatically.",
            )
        elif status_value in {"OFFLINE", "ERROR", "FAILED"}:
            _pndcc3b_add_decision(
                decisions, "WARNING", "Cloud", str(item.get("name", "Cloud")),
                f"Cloud monitor reports {status_value}.",
                "Review the existing provider connection/status. No account or sync changes are performed automatically.",
            )

    # Network health is a summary signal; avoid duplicate noise when the
    # underlying Internet/DNS checks already explain the problem.
    score = _pndcc3b_safe_float(health.get("score")) if isinstance(health, dict) else None
    if score is not None and score < 50 and not any(d["area"] == "Network Pulse" for d in decisions):
        _pndcc3b_add_decision(
            decisions, "CRITICAL", "Network Pulse", "Network health",
            f"Network health score is {score:.1f}/100.",
            "Open Network Diagnostics and review the underlying signals before taking action.",
        )

    severity_rank = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    decisions.sort(key=lambda d: (severity_rank.get(d.get("severity", "INFO"), 9), d.get("area", ""), d.get("subject", "")))

    if not decisions:
        overall = "NORMAL"
        summary = "No action is recommended. Current monitored services are stable."
    elif any(d.get("severity") == "CRITICAL" for d in decisions):
        overall = "ACTION REVIEW"
        summary = "Critical conditions detected. Review the recommended actions before doing anything."
    else:
        overall = "MONITOR"
        summary = "Warnings detected. Monitor and review if they persist."

    return {
        "phase": PNDCC_PHASE3B_VERSION,
        "timestamp": now(),
        "overall": overall,
        "summary": summary,
        "checked_signals": checked,
        "decision_count": len(decisions),
        "decisions": decisions,
        "automatic_actions": False,
        "passwords_modified": False,
        "connections_modified": False,
    }


def _pndcc3b_save_decision(result):
    """Append a small decision record. This does not alter PNDCC histories."""
    try:
        os.makedirs(os.path.dirname(PNDCC_PHASE3B_HISTORY), exist_ok=True)
        with open(PNDCC_PHASE3B_HISTORY, "a", encoding="utf-8") as f:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")
    except (OSError, TypeError, ValueError):
        pass


def _pndcc3b_page(result):
    decisions = result.get("decisions") or []
    rows = []
    for d in decisions:
        rows.append(
            "<div class='alert-item'>"
            f"<span class='pill {esc(d.get('severity', 'INFO'))}'>{esc(d.get('severity', 'INFO'))}</span>"
            f"<div class='message'><b>{esc(d.get('area', ''))} · {esc(d.get('subject', ''))}</b>"
            f"<div class='meta'>{esc(d.get('condition', ''))}</div>"
            f"<div class='small' style='margin-top:6px'><b>Recommended:</b> {esc(d.get('recommendation', ''))}</div></div>"
            "</div>"
        )
    if not rows:
        rows.append("<div class='notice'>No action is recommended from the current snapshot.</div>")

    body = f"""
    <section class='hero'>
      <div class='hero-head'><div><h2>Decision / Action Engine</h2><p>Phase 3B · recommendation-only safety layer.</p></div><div class='small' style='color:#d8e3ff'>Latest completed snapshot</div></div>
      <div class='kpis'>
        <div class='kpi'><div class='kpi-label'>OVERALL</div><div class='kpi-value'>{esc(result.get('overall', '—'))}</div></div>
        <div class='kpi'><div class='kpi-label'>DECISIONS</div><div class='kpi-value'>{esc(result.get('decision_count', 0))}</div></div>
        <div class='kpi'><div class='kpi-label'>AUTO ACTIONS</div><div class='kpi-value'>DISABLED</div></div>
        <div class='kpi'><div class='kpi-label'>PASSWORD CHANGES</div><div class='kpi-value'>NONE</div></div>
      </div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Decision summary</h2><span class='section-note'>{esc(result.get('timestamp', ''))}</span></div>
      <div class='card'><p>{esc(result.get('summary', ''))}</p><div class='small'>Signals checked: {esc(result.get('checked_signals', 0))} · Existing connections and credentials remain untouched.</div></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Recommendations</h2><span class='section-note'>No automatic changes</span></div>
      <div class='card'><div class='alert-list'>{''.join(rows)}</div></div>
    </section>
    <section class='section'><div class='card'><div class='small'><b>Safety:</b> Phase 3B only observes completed PNDCC snapshots and produces recommendations. It does not change passwords, Keychain items, FTP/FTPS settings, network connections, device configuration, files, cloud settings, or services.</div><div class='nav' style='margin-top:12px'><a href='/'>← Dashboard</a><a href='/api/decision-engine'>JSON decision data →</a></div></div></section>
    """
    return page_shell("PNDCC Phase 3B · Decision Engine", body)


def _pndcc3b_get(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path == "/decision-engine":
        result = _pndcc3b_decide()
        _pndcc3b_save_decision(result)
        data = _pndcc3b_page(result).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        return
    if parsed.path == "/api/decision-engine":
        result = _pndcc3b_decide()
        _pndcc3b_save_decision(result)
        _json_response(self, result)
        return
    return _PNDCC3B_OLD_GET(self)


# Extend the already-installed GET handler. No existing handler is replaced.
_PNDCC3B_OLD_GET = H.do_GET
H.do_GET = _pndcc3b_get

# Add one navigation link by wrapping the current dashboard renderer.
_PNDCC3B_OLD_DASHBOARD = dashboard

def dashboard():
    page = _PNDCC3B_OLD_DASHBOARD()
    link = "<a href='/decision-engine'>Decision / Action Engine →</a>"
    if "/decision-engine" not in page:
        page = page.replace("<a href='/api/status'>JSON status →</a>", link + "<a href='/api/status'>JSON status →</a>")
    return page


# ============================================================================
# PNDCC v2.3 Phase 3B — Cloud Storage Recommendation Enhancement
# Additive-only. Reads the existing dashboard cloud snapshot.
# Uses the same reasonable capacity thresholds as the Phase 3B storage logic:
#   >= 99.5% = CRITICAL
#   >= 90.0% = WARNING
# No cloud files, accounts, sync settings, passwords, or connections are changed.
# ============================================================================

def _pndcc3b_cloud_used_pct(item):
    """Read cloud usage from the dashboard's nested quota structure."""
    if not isinstance(item, dict):
        return None
    pct = item.get("used_pct")
    if pct is None:
        quota = item.get("quota") or {}
        if isinstance(quota, dict):
            pct = quota.get("used_pct")
    return _pndcc3b_safe_float(pct)


_PNDCC3B_OLD_DECIDE = _pndcc3b_decide


def _pndcc3b_decide(snapshot=None):
    """Add cloud-capacity recommendations from the existing dashboard snapshot."""
    snap = snapshot if isinstance(snapshot, dict) else _pndcc_dashboard_cache_snapshot()
    result = _PNDCC3B_OLD_DECIDE(snap)
    decisions = list(result.get("decisions") or [])
    existing = {(d.get("area"), d.get("subject")) for d in decisions}

    for item in (snap.get("cloud") or []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "Cloud storage"))
        pct = _pndcc3b_cloud_used_pct(item)
        if pct is None:
            continue

        if pct >= 99.5:
            severity = "CRITICAL"
            condition = f"{name} storage is {pct:.1f}% used and is effectively full."
            recommendation = (
                f"Review {name} storage and free space or consider increasing capacity. "
                "No cloud files, sync settings, accounts, or connections will be changed automatically."
            )
        elif pct >= 90.0:
            severity = "WARNING"
            condition = f"{name} storage is {pct:.1f}% used and is approaching capacity."
            recommendation = (
                f"Review {name} storage usage and large files before capacity is exhausted. "
                "No cloud files, sync settings, accounts, or connections will be changed automatically."
            )
        else:
            continue

        key = ("Cloud", name)
        if key not in existing:
            _pndcc3b_add_decision(
                decisions, severity, "Cloud", name, condition, recommendation
            )
            existing.add(key)

    severity_rank = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    decisions.sort(
        key=lambda d: (
            severity_rank.get(d.get("severity", "INFO"), 9),
            d.get("area", ""),
            d.get("subject", ""),
        )
    )
    result["decisions"] = decisions
    result["decision_count"] = len(decisions)
    if any(d.get("severity") == "CRITICAL" for d in decisions):
        result["overall"] = "ACTION REVIEW"
        result["summary"] = "Critical conditions detected. Review the recommended actions before doing anything."
    elif decisions:
        result["overall"] = "MONITOR"
        result["summary"] = "Warnings detected. Monitor and review if they persist."
    else:
        result["overall"] = "NORMAL"
        result["summary"] = "No action is recommended. Current monitored services are stable."
    return result


# ============================================================================
# PNDCC v2.3 Phase 3C — Diagnostic & Explanation
# Author: Saiful Quadir
# Project: Personal Network & Device Command Center (PNDCC)
# Updated: 2026-10-06
# Copyright: © Saiful Quadir
# Design rule: Simple is the best.
#
# ADDITIVE-ONLY diagnostic layer.
# Reads completed PNDCC snapshots and explains:
#   Detect → Explain → Likely Cause → Evidence → Check First
# It does NOT change passwords, Keychain items, FTP/FTPS settings, network
# connections, device configuration, files, cloud settings, or services.
# ============================================================================

PNDCC_PHASE3C_VERSION = "3C"
PNDCC_PHASE3C_HISTORY = os.path.join(BASE, "data", "phase3c_diagnostics.jsonl")


def _pndcc3c_num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _pndcc3c_add_evidence(items, label, value):
    if value not in (None, "", "—"):
        items.append({"label": label, "value": str(value)})


def _pndcc3c_diagnose(snapshot=None):
    """Create a small, read-only diagnostic explanation from the latest snapshot."""
    snap = snapshot if isinstance(snapshot, dict) else _pndcc_dashboard_cache_snapshot()
    results = list(snap.get("results") or [])
    pulse = snap.get("pulse") or {}
    ftp = snap.get("ftp") or {}
    storage = list(snap.get("storage") or [])
    cloud = list(snap.get("cloud") or [])

    internet = (pulse.get("internet") or {}) if isinstance(pulse, dict) else {}
    dns = (pulse.get("dns") or {}) if isinstance(pulse, dict) else {}
    health = (pulse.get("network_health") or {}) if isinstance(pulse, dict) else {}
    internet_status = str(internet.get("status", "")).upper()
    dns_status = str(dns.get("status", "")).upper()
    health_score = _pndcc3c_num(health.get("score")) if isinstance(health, dict) else None

    online = [r for r in results if str(r.get("status", "")).upper() == "ONLINE"]
    warning = [r for r in results if str(r.get("status", "")).upper() == "WARNING"]
    critical = [r for r in results if str(r.get("status", "")).upper() == "CRITICAL"]
    offline = [r for r in results if str(r.get("status", "")).upper() == "OFFLINE"]

    abnormal_devices = warning + critical
    evidence = []
    causes = []
    checks = []
    scope = "NO ACTIVE NETWORK FAULT IDENTIFIED"
    overall = "NORMAL"
    explanation = "Current completed monitoring signals do not indicate an active network-wide fault."

    # Network-wide diagnosis first: the common path must actually be unhealthy.
    network_bad = (
        internet_status == "OFFLINE"
        or dns_status == "OFFLINE"
        or (health_score is not None and health_score < 50)
        or (
            _pndcc3c_num(internet.get("latency_ms")) is not None
            and _pndcc3c_num(internet.get("latency_ms")) >= 100
        )
        or (
            _pndcc3c_num(internet.get("packet_loss_pct")) is not None
            and _pndcc3c_num(internet.get("packet_loss_pct")) >= 10
        )
    )

    if network_bad:
        overall = "CRITICAL" if internet_status == "OFFLINE" or (health_score is not None and health_score < 50) else "WARNING"
        scope = "NETWORK / INTERNET"
        explanation = "A shared network signal is abnormal, so investigate the common path before focusing on one device."
        causes.extend(["Router/Wi-Fi path", "Internet connection", "DNS or upstream connectivity"])
        checks.extend(["Router/Wi-Fi connectivity", "Network Pulse latency and packet loss", "DNS status"])
    elif critical or warning:
        overall = "CRITICAL" if critical else "WARNING"
        scope = "DEVICE-SPECIFIC"
        explanation = "Network Pulse is not showing a matching network-wide failure; the abnormal device signal is therefore more likely device-specific or local to that device's connection."
        causes.extend(["Device Wi-Fi/connection quality", "Device-side network condition", "Local signal or interference"])
        checks.extend(["Device Wi-Fi connection", "Device signal/location", "Next monitoring samples before taking action"])
    elif str(ftp.get("status", "")).upper() in {"OFFLINE", "ERROR", "FAILED"}:
        overall = "CRITICAL"
        scope = "SERVICE-SPECIFIC"
        explanation = "Internet/network monitoring is available but the FTP/FTPS service monitor is not healthy."
        causes.extend(["Windows/FileZilla service", "FTP/FTPS reachability or service state"])
        checks.extend(["FTP history/service test", "Windows FileZilla Server status"])

    # Evidence is deliberately limited to the signals used for the explanation.
    _pndcc3c_add_evidence(evidence, "Internet", internet_status)
    _pndcc3c_add_evidence(evidence, "Internet latency", f"{internet.get('latency_ms')} ms" if internet.get("latency_ms") is not None else None)
    _pndcc3c_add_evidence(evidence, "Packet loss", f"{internet.get('packet_loss_pct')}%" if internet.get("packet_loss_pct") is not None else None)
    _pndcc3c_add_evidence(evidence, "DNS", dns_status)
    _pndcc3c_add_evidence(evidence, "Network health", f"{health_score:.1f}/100" if health_score is not None else None)
    _pndcc3c_add_evidence(evidence, "Devices", f"{len(online)} online · {len(warning)} warning · {len(critical)} critical · {len(offline)} offline")
    if abnormal_devices:
        for row in abnormal_devices[:4]:
            _pndcc3c_add_evidence(
                evidence,
                str(row.get("name", "Device")),
                f"{row.get('status', '—')} · {row.get('latency_ms', '—')} ms"
            )
    _pndcc3c_add_evidence(evidence, "FTP/FTPS", ftp.get("status"))

    # Storage/cloud conditions are separate from network root cause.
    secondary = []
    for item in storage:
        pct = _pndcc3c_num(item.get("used_pct"))
        if pct is not None and pct >= 90:
            secondary.append({
                "severity": "CRITICAL" if pct >= 95 else "WARNING",
                "area": "Storage",
                "subject": str(item.get("name", "Storage")),
                "message": f"Storage usage is {pct:.1f}%."
            })
    for item in cloud:
        pct = _pndcc3c_num(item.get("used_pct"))
        if pct is not None and pct >= 90:
            secondary.append({
                "severity": "CRITICAL" if pct >= 99.5 else "WARNING",
                "area": "Cloud",
                "subject": str(item.get("name", "Cloud")),
                "message": f"Cloud storage usage is {pct:.1f}%."
            })

    if offline:
        secondary.append({
            "severity": "INFO",
            "area": "Device state",
            "subject": "Offline devices",
            "message": "Offline devices are not treated as faults by Phase 3C because a powered-off device cannot be distinguished from an unexpected outage from the current snapshot alone."
        })

    return {
        "phase": PNDCC_PHASE3C_VERSION,
        "timestamp": now(),
        "overall": overall,
        "scope": scope,
        "explanation": explanation,
        "likely_causes": causes[:4],
        "check_first": checks[:4],
        "evidence": evidence,
        "secondary_findings": secondary,
        "automatic_actions": False,
        "credentials_modified": False,
        "connections_modified": False,
    }


def _pndcc3c_save_diagnostic(result):
    try:
        os.makedirs(os.path.dirname(PNDCC_PHASE3C_HISTORY), exist_ok=True)
        with open(PNDCC_PHASE3C_HISTORY, "a", encoding="utf-8") as f:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")
    except (OSError, TypeError, ValueError):
        pass


def _pndcc3c_page(result):
    evidence_rows = "".join(
        f"<div class='alert-item'><div class='message'><b>{esc(x.get('label',''))}</b><div class='meta'>{esc(x.get('value',''))}</div></div></div>"
        for x in result.get("evidence", [])
    ) or "<div class='notice'>No supporting evidence was available.</div>"
    cause_rows = "".join(f"<li>{esc(x)}</li>" for x in result.get("likely_causes", [])) or "<li>No specific cause indicated.</li>"
    check_rows = "".join(f"<li>{esc(x)}</li>" for x in result.get("check_first", [])) or "<li>Continue monitoring.</li>"
    secondary_rows = "".join(
        f"<div class='alert-item'><span class='pill {esc(x.get('severity','INFO'))}'>{esc(x.get('severity','INFO'))}</span><div class='message'><b>{esc(x.get('area',''))} · {esc(x.get('subject',''))}</b><div class='meta'>{esc(x.get('message',''))}</div></div></div>"
        for x in result.get("secondary_findings", [])
    ) or "<div class='notice'>No secondary findings.</div>"

    body = f"""
    <section class='hero'>
      <div class='hero-head'><div><h2>Diagnostic &amp; Explanation</h2><p>Phase 3C · read-only diagnostic layer.</p></div><div class='small' style='color:#d8e3ff'>Latest completed snapshot</div></div>
      <div class='kpis'>
        <div class='kpi'><div class='kpi-label'>ASSESSMENT</div><div class='kpi-value'>{esc(result.get('overall','—'))}</div></div>
        <div class='kpi'><div class='kpi-label'>LIKELY SCOPE</div><div class='kpi-value'>{esc(result.get('scope','—'))}</div></div>
        <div class='kpi'><div class='kpi-label'>AUTO ACTIONS</div><div class='kpi-value'>DISABLED</div></div>
        <div class='kpi'><div class='kpi-label'>CREDENTIAL CHANGES</div><div class='kpi-value'>NONE</div></div>
      </div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>What happened?</h2><span class='section-note'>{esc(result.get('timestamp',''))}</span></div>
      <div class='card'><p>{esc(result.get('explanation',''))}</p></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Check first</h2><span class='section-note'>Recommended order</span></div>
      <div class='card'><ol>{check_rows}</ol></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Likely causes</h2><span class='section-note'>Evidence-based hints</span></div>
      <div class='card'><ul>{cause_rows}</ul></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Evidence</h2><span class='section-note'>Signals used</span></div>
      <div class='card'><div class='alert-list'>{evidence_rows}</div></div>
    </section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Secondary findings</h2><span class='section-note'>Separate from root cause</span></div>
      <div class='card'><div class='alert-list'>{secondary_rows}</div></div>
    </section>
    <section class='section'><div class='card'><div class='small'><b>Safety:</b> Phase 3C observes completed PNDCC snapshots only. It does not change passwords, Keychain items, FTP/FTPS settings, network connections, device configuration, files, cloud settings, or services.</div><div class='nav' style='margin-top:12px'><a href='/'>← Dashboard</a><a href='/api/diagnostic-explanation'>JSON diagnostic data →</a></div></div></section>
    """
    return page_shell("PNDCC Phase 3C · Diagnostic & Explanation", body)


# Extend the current GET chain. Existing routes remain delegated unchanged.
_PNDCC3C_OLD_GET = H.do_GET

def _pndcc3c_get(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path in {"/diagnostic-explanation", "/api/diagnostic-explanation"}:
        result = _pndcc3c_diagnose()
        _pndcc3c_save_diagnostic(result)
        if parsed.path == "/api/diagnostic-explanation":
            _json_response(self, result)
            return
        data = _pndcc3c_page(result).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        return
    return _PNDCC3C_OLD_GET(self)

H.do_GET = _pndcc3c_get

# Add one dashboard navigation link without replacing dashboard content.
_PNDCC3C_OLD_DASHBOARD = dashboard

def dashboard():
    page = _PNDCC3C_OLD_DASHBOARD()
    link = "<a href='/diagnostic-explanation'>Diagnostic &amp; Explanation →</a>"
    marker = "<a href='/decision-engine'>Decision / Action Engine →</a>"
    if link not in page and marker in page:
        page = page.replace(marker, marker + link, 1)
    return page.replace("Version 2.2", "Version 2.3").replace("PNDCC v2.2", "PNDCC v2.3")

PNDCC_VERSION = "2.6.3"
PNDCC_UPDATED = "2026-10-06 Phase 3C Verified + Phase 3D Controlled Action & Recovery"

# ============================================================================
# PNDCC v2.6.3 Phase 3D — Controlled Action & Recovery + Manual Screenshot
# Author: Saiful Quadir
# Project: Personal Network & Device Command Center (PNDCC)
# Updated: 2026-10-06
# Copyright: © Saiful Quadir
# Design rule: Simple is the best.
#
# SAFE INITIAL 3D SCOPE:
#   Observe → Recommend → Explicit User Approval → Safe Action → Verify
#
# This first 3D implementation deliberately limits actions to READ-ONLY
# verification and a local recovery-watch record. It does NOT modify:
# passwords, Keychain, FTP/FTPS settings, network settings, device settings,
# files, cloud settings, or external services.
# ============================================================================

PNDCC_PHASE3D_VERSION = "3D"
PNDCC_PHASE3D_HISTORY = os.path.join(BASE, "data", "phase3d_action_history.jsonl")
PNDCC_PHASE3D_WATCH = os.path.join(BASE, "data", "phase3d_recovery_watch.json")


def _pndcc3d_action_catalog():
    return {
        "diagnostic_recheck": {
            "name": "Run Diagnostic Re-check",
            "description": "Re-run the current read-only Phase 3C assessment.",
            "safety": "READ-ONLY",
        },
        "network_recheck": {
            "name": "Run Network Pulse Re-check",
            "description": "Run a fresh read-only Network Pulse measurement.",
            "safety": "READ-ONLY",
        },
        "ftp_recheck": {
            "name": "Run FTP/FTPS Health Re-check",
            "description": "Run a fresh read-only FTP/FTPS service handshake test.",
            "safety": "READ-ONLY",
        },
        "recovery_watch": {
            "name": "Start Recovery Watch",
            "description": "Record that the user approved continued monitoring; no system setting is changed.",
            "safety": "LOCAL RECORD ONLY",
        },
    }


def _pndcc3d_save_action(entry):
    try:
        os.makedirs(os.path.dirname(PNDCC_PHASE3D_HISTORY), exist_ok=True)
        with open(PNDCC_PHASE3D_HISTORY, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except (OSError, TypeError, ValueError):
        pass


def _pndcc3d_write_watch(reason="User-approved recovery watch"):
    record = {
        "started_at": now(),
        "status": "ACTIVE",
        "reason": reason,
        "automatic_repair": False,
        "system_changes": False,
    }
    try:
        os.makedirs(os.path.dirname(PNDCC_PHASE3D_WATCH), exist_ok=True)
        tmp = PNDCC_PHASE3D_WATCH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False, indent=2)
        os.replace(tmp, PNDCC_PHASE3D_WATCH)
    except (OSError, TypeError, ValueError):
        pass
    return record


def _pndcc3d_execute(action_id):
    catalog = _pndcc3d_action_catalog()
    action = catalog.get(action_id)
    if not action:
        return {"ok": False, "message": "Unknown or unavailable action."}

    started = time.perf_counter()
    result = {"ok": True, "action_id": action_id, "action": action["name"], "safety": action["safety"]}
    try:
        if action_id == "diagnostic_recheck":
            result["result"] = _pndcc3c_diagnose()
        elif action_id == "network_recheck":
            result["result"] = _pndcc3a_network_pulse()
        elif action_id == "ftp_recheck":
            result["result"] = ftp_check()
        elif action_id == "recovery_watch":
            result["result"] = _pndcc3d_write_watch()
        result["message"] = "Approved safe action completed."
    except Exception as e:
        result["ok"] = False
        result["message"] = f"Action failed safely: {type(e).__name__}: {e}"
    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    result["automatic_action"] = False
    result["credential_changes"] = False
    result["network_configuration_changed"] = False
    _pndcc3d_save_action({"timestamp": now(), **result})
    return result


def _pndcc3d_current_state():
    diagnostic = _pndcc3c_diagnose()
    watch = None
    try:
        if os.path.exists(PNDCC_PHASE3D_WATCH):
            with open(PNDCC_PHASE3D_WATCH, encoding="utf-8") as f:
                watch = json.load(f)
    except (OSError, ValueError, TypeError):
        watch = None
    return {"phase": PNDCC_PHASE3D_VERSION, "diagnostic": diagnostic, "watch": watch,
            "actions": _pndcc3d_action_catalog(), "automatic_actions": False}


def _pndcc3d_page(state, message=""):
    d = state.get("diagnostic") or {}
    actions = state.get("actions") or {}
    action_rows = "".join(
        f"<article class='card'><div class='device-top'><div><h3>{esc(v['name'])}</h3><div class='small'>{esc(v['description'])}</div></div><span class='pill ONLINE'>{esc(v['safety'])}</span></div>"
        f"<form method='post' action='/controlled-action' style='margin-top:12px'><input type='hidden' name='action_id' value='{esc(k)}'><button class='linkbtn' type='submit'>Approve &amp; Run</button></form></article>"
        for k, v in actions.items()
    )
    watch = state.get("watch")
    watch_text = "ACTIVE · " + str(watch.get("started_at")) if isinstance(watch, dict) and watch.get("status") == "ACTIVE" else "NOT ACTIVE"
    msg = f"<div class='notice' style='margin-bottom:12px'>{esc(message)}</div>" if message else ""
    body = f"""
    <section class='hero'>
      <div class='hero-head'><div><h2>Controlled Action &amp; Recovery</h2><p>Phase 3D · explicit approval gate.</p></div><div class='small' style='color:#d8e3ff'>No automatic actions</div></div>
      <div class='kpis'>
        <div class='kpi'><div class='kpi-label'>CURRENT ASSESSMENT</div><div class='kpi-value'>{esc(d.get('overall','—'))}</div></div>
        <div class='kpi'><div class='kpi-label'>LIKELY SCOPE</div><div class='kpi-value'>{esc(d.get('scope','—'))}</div></div>
        <div class='kpi'><div class='kpi-label'>USER APPROVAL</div><div class='kpi-value'>REQUIRED</div></div>
        <div class='kpi'><div class='kpi-label'>RECOVERY WATCH</div><div class='kpi-value'>{esc(watch_text)}</div></div>
      </div>
    </section>
    {msg}
    <section class='section'><div class='section-head'><h2 class='section-title'>Approved Safe Actions</h2><span class='section-note'>Read-only / local record only</span></div><div class='grid'>{action_rows}</div></section>
    <section class='section'><div class='card'><b>Approval rule:</b> PNDCC never runs these actions automatically. Clicking <b>Approve &amp; Run</b> is the user's explicit approval for that one action.</div></section>
    <section class='section'><div class='card'><b>Safety:</b> Phase 3D does not change passwords, Keychain items, FTP/FTPS configuration, network settings, device configuration, files, cloud settings, or external services.</div></section>
    <section class='section'><div class='card'><div class='nav'><a href='/'>← Dashboard</a><a href='/diagnostic-explanation'>← Phase 3C</a><a href='/api/controlled-action'>JSON action status →</a></div></div></section>
    """
    return page_shell("PNDCC Phase 3D · Controlled Action & Recovery", body)


# Extend the existing Phase 3C GET handler; all older routes continue through it.
_PNDCC3D_OLD_GET = H.do_GET

def _pndcc3d_get(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path in {"/controlled-action", "/api/controlled-action"}:
        state = _pndcc3d_current_state()
        if parsed.path == "/api/controlled-action":
            _json_response(self, state)
        else:
            data = _pndcc3d_page(state).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
        return
    return _PNDCC3D_OLD_GET(self)


def _pndcc3d_post(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path != "/controlled-action":
        return _PNDCC3D_OLD_POST(self) if "_PNDCC3D_OLD_POST" in globals() else self._send_text(404, "Not found")
    try:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 16 * 1024:
            self._send_text(400, "Invalid action request")
            return
        raw = self.rfile.read(length)
        form = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
        action_id = (form.get("action_id") or [""])[0]
        result = _pndcc3d_execute(action_id)
        state = _pndcc3d_current_state()
        msg = result.get("message", "Action completed.")
        if result.get("ok") and action_id == "diagnostic_recheck":
            state["diagnostic"] = result.get("result") or state["diagnostic"]
        data = _pndcc3d_page(state, msg).encode("utf-8")
        self.send_response(200 if result.get("ok") else 400)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
    except Exception as e:
        self._send_text(400, f"Controlled action failed safely: {type(e).__name__}")


H.do_GET = _pndcc3d_get
try:
    _PNDCC3D_OLD_POST = H.do_POST
    H.do_POST = _pndcc3d_post
except AttributeError:
    pass

# Final dashboard wrapper: add Phase 3D and display the verified 2.6 build.
_PNDCC3D_OLD_DASHBOARD = dashboard

def dashboard():
    page = _PNDCC3D_OLD_DASHBOARD()
    marker = "<a href='/diagnostic-explanation'>Diagnostic &amp; Explanation →</a>"
    link = "<a href='/controlled-action'>Controlled Action &amp; Recovery →</a>"
    if link not in page:
        if marker in page:
            page = page.replace(marker, marker + link, 1)
        else:
            page = page.replace("<a href='/api/status'>", link + "<a href='/api/status'>", 1)
    page = page.replace("Version 2.3.1", "Version 2.6.3").replace("Version 2.3", "Version 2.6.3").replace("Version 2.2", "Version 2.6.3").replace("Version 2.1", "Version 2.6.3").replace("Version 2.0", "Version 2.6.3")
    page = page.replace("PNDCC v2.3.1", "PNDCC v2.6.3").replace("PNDCC v2.3", "PNDCC v2.6.3").replace("PNDCC v2.2", "PNDCC v2.6.3").replace("PNDCC v2.1", "PNDCC v2.6.3").replace("PNDCC v2.0", "PNDCC v2.6.3")
    return page



# ---------------------------------------------------------------------------
# PNDCC Documentation Set — selectable DOCX + PDF generation
# ---------------------------------------------------------------------------
# This section is additive and isolated. It does not alter monitoring,
# FTP/FTPS, device control, diagnostics, or the existing PDF page capture.

def _pndcc_documentation_specs():
    return {
        "1": {
            "base": "PNDCC-01_User_Guide",
            "title": "PNDCC-01 — User Guide",
            "subtitle": "Personal Network & Device Command Center",
            "sections": [
                ("Purpose", ["PNDCC is a simple local-only command center for seeing important home-network status in one place, detecting abnormal behavior, and understanding what action to take."]),
                ("Getting Started", ["Start the PNDCC Python application from the app folder, then open http://127.0.0.1:8787 in a browser.", "The dashboard is the main control screen. Use the navigation links to open Settings, Device Control, Network Diagnostics, History, FTP History, Diagnostic & Explanation, and Controlled Action & Recovery."]),
                ("Dashboard", ["The dashboard provides an at-a-glance view of devices, network services, storage/cloud information, alerts, and current health. Latency, packet loss, service state, and recent history help identify abnormal conditions."]),
                ("Device Control", ["Device Control provides safe file operations through the configured FTP/FTPS service. Phase 2D preserves the existing FTP/FTPS engine and uses the configured Windows FileZilla Server connection.", "Use the normal selection, navigation, upload, create-folder, rename, delete, move, and copy controls only when you understand the target path."]),
                ("Network Diagnostics", ["Network Diagnostics is read-only. It collects basic Wi-Fi, route, ARP, router, and Internet measurements when requested. It does not change network configuration."]),
                ("History and Alerts", ["Device History and FTP History provide recorded observations so a current problem can be compared with previous samples. Alerts identify conditions that deserve attention rather than automatically changing the system."]),
                ("All PNDCC Pages → PDF", ["Open Screenshot and choose All PNDCC Pages → PDF to collect live PNDCC pages. When collection finishes, the browser print dialog opens; choose Save as PDF.", "A slow or unresponsive page is skipped after the built-in collection timeout so one page does not freeze the complete export. This live-page report is separate from the documentation-set ZIP."]),
                ("Documentation Set", ["In Screenshot, click Capture Screenshot first, then select User Guide, Technical Reference, Admin & Diagnostics Runbook, or all three under PNDCC Documentation Set. Choose Generate ZIP · Send / Store or Generate + Archive. Each selected set contains both DOCX and PDF.", "When a screenshot is available, it is embedded in each selected DOCX and PDF. If capture fails, the text documents are still generated."]),
                ("Safety", ["PNDCC is designed around observation first. Phase 3B recommendations and Phase 3C explanations do not change passwords, Keychain items, network connections, device configuration, files, cloud settings, or services. Controlled Action & Recovery is deliberately limited and requires explicit action."]),
                ("Simple is the best.", ["When troubleshooting, change one thing at a time, test it, and keep the last known working PNDCC build available."]),
            ]
        },
        "2": {
            "base": "PNDCC-02_Technical_Reference",
            "title": "PNDCC-02 — Technical Reference",
            "subtitle": "Architecture, Routes, Configuration, Monitoring and Export",
            "sections": [
                ("Architecture", ["PNDCC is a local Python HTTP application using the standard library HTTP server and a browser-based dashboard. The app is intended for a trusted home LAN and localhost control center use.", "The implementation is layered additively: the frozen baseline is extended with Phase 2D, persistent configuration, Network Pulse, Decision Engine, Diagnostic & Explanation, Controlled Action & Recovery, and export features."]),
                ("Canonical Runtime", ["Application folder: /Users/x/Documents/Personal_Network_Device_Command_Center/app", "Dashboard: http://127.0.0.1:8787", "Normal launch: cd \"/Users/x/Documents/Personal_Network_Device_Command_Center/app\" then python3 <file>.py"]),
                ("Core Routes", ["/ — Dashboard", "/settings — persistent configuration", "/device-control — Phase 2D file control", "/network-diagnostics — read-only network diagnostics", "/history — device history", "/ftp-history — FTP/FTPS history", "/health — health probe", "/api/status — live status JSON", "/api/network-diagnostics — diagnostics JSON", "/diagnostic-explanation — Phase 3C", "/controlled-action — Phase 3D", "/api/controlled-action — Phase 3D API"]),
                ("Configuration", ["PNDCC supports persistent device and settings configuration. FTP/FTPS values include host, port, mode, username, timeout, and credential handling. Passwords are not intended to be stored in the application source; the existing Keychain/environment path is preserved."]),
                ("FTP / FTPS", ["The proven Windows endpoint is FileZilla Server on the configured LAN host, normally TCP port 21. FTPS uses AUTH TLS and the existing PNDCC_FTP_TLS compatibility path for FileZilla TLS session reuse on protected data connections.", "A service handshake, optional login, and data-channel protection are treated as separate layers. A successful TCP connection alone does not prove successful FTPS login or data transfer."]),
                ("Monitoring", ["Device monitoring records timestamp, target ID, name, IP, status, latency, and packet loss. Thresholds distinguish ONLINE, WARNING, CRITICAL, and OFFLINE conditions. FTP history records service state and test information."]),
                ("Phase 3 Flow", ["Phase 3A Network Pulse observes network conditions. Phase 3B turns completed observations into recommendations. Phase 3C explains abnormal conditions and evidence. Phase 3D provides controlled, explicit recovery actions. The layers are intentionally isolated from the existing Phase 2D file/FTP engine."]),
                ("Export Architecture", ["Current-page capture uses the existing screenshot path. All-Pages PDF collection opens the report window before asynchronous fetch operations, preventing browser popup blocking. Each page is fetched with a 15-second AbortController timeout; timed-out pages are skipped and collection continues."]),
                ("Documentation Generation", ["The documentation selector sends the selected set numbers and an optional PNG screenshot to /api/documentation/with-screenshot. The server generates DOCX and PDF versions and returns a ZIP containing only the selected files. If no valid screenshot is available, text-only documents are still generated."]),
                ("Design Constraints", ["Prefer smallest additive patches. Preserve working Phase 2D, FTPS, Keychain, persistent configuration, monitoring, and history behavior. Diagnose → smallest patch → test."]),
            ]
        },
        "3": {
            "base": "PNDCC-03_Admin_Diagnostics_Runbook",
            "title": "PNDCC-03 — Admin & Diagnostics Runbook",
            "subtitle": "Operational Checks, FTPS Recovery and Safe Troubleshooting",
            "sections": [
                ("Golden Rule", ["Diagnose first. Apply the smallest isolated change. Test immediately. Do not replace a working PNDCC build while investigating a single subsystem."]),
                ("Startup Check", ["Confirm the app folder is /Users/x/Documents/Personal_Network_Device_Command_Center/app.", "Start the intended PNDCC Python file with python3.", "Open http://127.0.0.1:8787 and verify the dashboard loads.", "Check /health and /api/status before changing configuration."]),
                ("FTPS Diagnostic Chain", ["1. Confirm the Windows host is reachable on TCP 21. 2. Confirm FileZilla Server is listening. 3. Confirm AUTH TLS succeeds. 4. Confirm certificate/TLS negotiation. 5. Confirm PNDCC username/password source. 6. Confirm login. 7. Confirm protected data-channel/session reuse. 8. Confirm PNDCC history records the result."]),
                ("Known FileZilla Conditions", ["A plain FTP attempt may return '503 Use AUTH first' when the server requires TLS. A self-signed LAN certificate can require the existing PNDCC local-certificate handling. A successful control-channel login does not by itself prove protected data-channel success."]),
                ("Credential Checks", ["Verify PNDCC_FTP_USER and the password source without exposing the password in logs. If macOS Keychain is used, confirm the expected item exists and that the running Python process can read it. Avoid writing credentials to source files, screenshots, or reports."]),
                ("Network Diagnostics", ["Use Network Diagnostics to collect router reachability, Internet reachability, Wi-Fi details, route information, and ARP observations. Compare these results with device latency and packet-loss history before changing network settings."]),
                ("All-Pages PDF Problems", ["If the progress window stalls, check the current page shown in the progress window. The current build applies a 15-second fetch timeout to each discovered page and continues after a timeout. If the print dialog is blocked, allow pop-ups for localhost and retry."]),
                ("Documentation Export", ["For the documentation ZIP, use the PNDCC Documentation Set selector and choose sets 1, 2, 3, or all. This is separate from All PNDCC Pages → PDF. The ZIP contains the selected DOCX and PDF files, with the captured screenshot embedded when available; capture failure must not block text export."]),
                ("Recovery Checklist", ["Keep the last known working PNDCC source. Stop only the affected process when possible. Capture /api/status, FTP history, and relevant diagnostic output. Change one variable at a time. Re-test TCP, TLS, login, and data transfer in that order."]),
                ("Escalation Evidence", ["For a repeat incident, collect the PNDCC version, timestamp, exact error text, /api/status result, FTP history entry, Windows FileZilla Server status/log evidence, TCP test result, TLS result, and credential-source state (without the secret itself)."]),
            ]
        }
    }


def _pndcc_docx_bytes(spec, screenshot_png=None):
    from docx import Document
    from docx.shared import Pt, Inches
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    doc = Document()
    sec = doc.sections[0]
    sec.top_margin = Inches(0.65); sec.bottom_margin = Inches(0.65)
    sec.left_margin = Inches(0.75); sec.right_margin = Inches(0.75)
    normal = doc.styles['Normal']; normal.font.name = 'Aptos'; normal.font.size = Pt(10)
    title = doc.add_paragraph(); title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = title.add_run(spec['title']); r.bold = True; r.font.size = Pt(20)
    sub = doc.add_paragraph(); sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = sub.add_run(spec['subtitle']); r.italic = True; r.font.size = Pt(11)
    meta = doc.add_paragraph(); meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    meta.add_run('Created by: Saiful Quadir  ·  PNDCC v2.6.3  ·  2026-10-07').font.size = Pt(9)
    if screenshot_png:
        try:
            from PIL import Image as PILImage
            image = PILImage.open(io.BytesIO(screenshot_png)).convert('RGB')
            image.thumbnail((1500, 1800))
            image_buf = io.BytesIO(); image.save(image_buf, format='PNG'); image_buf.seek(0)
            doc.add_heading('PNDCC Dashboard Screenshot', level=1)
            doc.add_picture(image_buf, width=Inches(7.0))
            doc.add_paragraph('Live dashboard capture included at documentation-generation time. Values may change as the network changes.')
        except Exception:
            pass  # Never block a text-only documentation export because of an image.
    for heading, paragraphs in spec['sections']:
        doc.add_heading(heading, level=1)
        for text in paragraphs:
            p = doc.add_paragraph(style='List Bullet' if text[:2].isdigit() and text[1:2] == '.' else None)
            p.paragraph_format.space_after = Pt(5)
            p.add_run(text)
    footer = doc.sections[0].footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run('PNDCC · Saiful Quadir · Simple is the best.').font.size = Pt(8)
    out = io.BytesIO(); doc.save(out); return out.getvalue()


def _pndcc_pdf_bytes(spec, screenshot_png=None):
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
    styles = getSampleStyleSheet()
    title = ParagraphStyle('PNDCCTitle', parent=styles['Title'], fontSize=20, leading=24, alignment=TA_CENTER, spaceAfter=8)
    subtitle = ParagraphStyle('PNDCCSub', parent=styles['Normal'], fontSize=11, leading=15, alignment=TA_CENTER, spaceAfter=6)
    h = ParagraphStyle('PNDCCH', parent=styles['Heading1'], fontSize=14, leading=18, spaceBefore=10, spaceAfter=6)
    body = ParagraphStyle('PNDCCBody', parent=styles['BodyText'], fontSize=9.5, leading=14, spaceAfter=6)
    story = [Paragraph(spec['title'], title), Paragraph(spec['subtitle'], subtitle), Paragraph('Created by: Saiful Quadir · PNDCC v2.6.3 · 2026-10-07', subtitle), Spacer(1, 0.12*inch)]
    if screenshot_png:
        try:
            from reportlab.platypus import Image as ReportLabImage
            from PIL import Image as PILImage
            image = PILImage.open(io.BytesIO(screenshot_png)).convert('RGB')
            image.thumbnail((1400, 1600))
            image_buf = io.BytesIO(); image.save(image_buf, format='PNG'); image_buf.seek(0)
            iw, ih = image.size
            # Fit the entire screenshot inside a single page content area.
            # The same scale factor is applied to width and height, preserving
            # the original aspect ratio and never cropping any edge.
            max_w, max_h = 7.95*inch, 6.0*inch
            scale = min(max_w / float(iw), max_h / float(ih))
            screenshot = ReportLabImage(image_buf, width=iw*scale, height=ih*scale)
            screenshot.hAlign = 'CENTER'
            story.extend([Paragraph('PNDCC Dashboard Screenshot', h), screenshot, Spacer(1, 0.08*inch), Paragraph('Live dashboard capture included at documentation-generation time. Values may change as the network changes.', body), Spacer(1, 0.12*inch)])
        except Exception:
            pass  # Never block a text-only documentation export because of an image.
    for heading, paragraphs in spec['sections']:
        story.append(Paragraph(heading, h))
        for text in paragraphs:
            safe = html.escape(text).replace('  ', '&nbsp;&nbsp;')
            story.append(Paragraph('• ' + safe, body))
    out = io.BytesIO()
    def footer(canvas, doc):
        canvas.saveState(); canvas.setFont('Helvetica', 8); canvas.drawCentredString(LETTER[0]/2, 0.35*inch, 'PNDCC · Saiful Quadir · Simple is the best.'); canvas.restoreState()
    SimpleDocTemplate(out, pagesize=LETTER, rightMargin=0.25*inch, leftMargin=0.25*inch, topMargin=0.5*inch, bottomMargin=0.5*inch, title=spec['title'], author='Saiful Quadir').build(story, onFirstPage=footer, onLaterPages=footer)
    return out.getvalue()


def _pndcc_documentation_zip(selected, screenshot_png=None):
    specs = _pndcc_documentation_specs()
    selected = [x for x in selected if x in specs]
    if not selected:
        raise ValueError('No valid documentation set selected')
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for key in selected:
            spec = specs[key]
            z.writestr(spec['base'] + '.docx', _pndcc_docx_bytes(spec, screenshot_png))
            z.writestr(spec['base'] + '.pdf', _pndcc_pdf_bytes(spec, screenshot_png))
    return out.getvalue()

_PNDCC_DOC_OLD_GET = H.do_GET

def _pndcc_documentation_get(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path == '/api/documentation/generate':
        try:
            params = urllib.parse.parse_qs(parsed.query)
            selected = params.get('docs', [''])[0].split(',')
            selected = [x for x in selected if x in {'1','2','3'}]
            if not selected:
                raise ValueError('No valid documentation set selected')
            data = _pndcc_documentation_zip(selected)
            archive_requested = params.get('archive', ['0'])[0] == '1'
            archive_path = None
            if archive_requested:
                archive_dir = os.path.join(APP_DIR, 'PNDCC_Archive', 'Documentation')
                os.makedirs(archive_dir, exist_ok=True)
                stamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                archive_name = 'PNDCC_Documentation_' + '_'.join(selected) + '_' + stamp + '.zip'
                archive_path = os.path.join(archive_dir, archive_name)
                with open(archive_path, 'wb') as af:
                    af.write(data)
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Disposition', 'attachment; filename="PNDCC_Documentation_' + '_'.join(selected) + '.zip"')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            if archive_path:
                self.send_header('X-PNDCC-Archive', os.path.basename(archive_path))
            self.end_headers()
            self.wfile.write(data)
            return
        except Exception as e:
            self._send_text(500, 'PNDCC documentation generation failed: ' + type(e).__name__)
            return
    return _PNDCC_DOC_OLD_GET(self)

H.do_GET = _pndcc_documentation_get


# ============================================================================
# PNDCC v2.7 — Network Pulse Graphical Visualization Module
# Additive-only visualization layer.
#
# Purpose:
#   Convert the existing read-only Network Pulse measurements into a compact,
#   live visual dashboard: status lights, meters, sparklines, trend charts,
#   and a clock-style health dial.
#
# Safety:
#   This layer reads the existing dashboard snapshot only. It does not run a
#   second monitoring engine and does not change network, FTP/FTPS, Keychain,
#   device, file, cloud, or system settings.
# ============================================================================

PNDCC_VERSION = "2.7.2"
PNDCC_UPDATED = "2026-10-08 Phase 3A Reality & Measurement Clarity"
PNDCC_PHASE3A_VIS_VERSION = "3A-VIS"

_PNDCC27_HISTORY_MAX = 60
_PNDCC27_HISTORY = []
_PNDCC27_HISTORY_LOCK = Lock()


def _pndcc27_record_snapshot(snap):
    """Record the already-computed monitor snapshot for graphical trends."""
    pulse = snap.get("pulse") if isinstance(snap, dict) else None
    results = snap.get("results") if isinstance(snap, dict) else None
    if not isinstance(pulse, dict):
        return
    internet = pulse.get("internet") or {}
    dns = pulse.get("dns") or {}
    traffic = pulse.get("traffic") or {}
    connections = pulse.get("connections") or {}
    health = pulse.get("network_health") or {}
    device_rows = []
    for row in results or []:
        if not isinstance(row, dict):
            continue
        device_rows.append({
            "id": row.get("target_id"),
            "name": row.get("name") or row.get("target_id") or "Device",
            "status": row.get("status", "UNKNOWN"),
            "latency_ms": row.get("latency_ms"),
            "packet_loss_pct": row.get("packet_loss_pct"),
        })
    sample = {
        "timestamp": pulse.get("timestamp") or now(),
        "latency_ms": internet.get("latency_ms"),
        "packet_loss_pct": internet.get("packet_loss_pct"),
        "dns_ms": dns.get("response_ms"),
        "download_mbps": traffic.get("download_mbps"),
        "upload_mbps": traffic.get("upload_mbps"),
        "tcp": connections.get("tcp"),
        "udp": connections.get("udp"),
        "established_tcp": connections.get("established_tcp"),
        "health_score": health.get("score"),
        "internet_status": internet.get("status", "UNKNOWN"),
        "dns_status": dns.get("status", "UNKNOWN"),
        "devices": device_rows,
    }
    with _PNDCC27_HISTORY_LOCK:
        if _PNDCC27_HISTORY and _PNDCC27_HISTORY[-1].get("timestamp") == sample.get("timestamp"):
            _PNDCC27_HISTORY[-1] = sample
        else:
            _PNDCC27_HISTORY.append(sample)
        del _PNDCC27_HISTORY[:-_PNDCC27_HISTORY_MAX]


_PNDCC27_OLD_REFRESH = _pndcc_dashboard_refresh_once

def _pndcc27_refresh_once():
    _PNDCC27_OLD_REFRESH()
    _pndcc27_record_snapshot(_pndcc_dashboard_cache_snapshot())

_pndcc_dashboard_refresh_once = _pndcc27_refresh_once


def _pndcc27_payload():
    snap = _pndcc_dashboard_cache_snapshot()
    _pndcc27_record_snapshot(snap)
    with _PNDCC27_HISTORY_LOCK:
        history = list(_PNDCC27_HISTORY)
    pulse = snap.get("pulse") or {}
    results = snap.get("results") or []
    return {
        "phase": PNDCC_PHASE3A_VIS_VERSION,
        "version": PNDCC_VERSION,
        "read_only": True,
        "timestamp": pulse.get("timestamp") or snap.get("updated") or now(),
        "pulse": pulse,
        "devices": [
            {
                "id": r.get("target_id"),
                "name": r.get("name") or r.get("target_id") or "Device",
                "status": r.get("status", "UNKNOWN"),
                "latency_ms": r.get("latency_ms"),
                "packet_loss_pct": r.get("packet_loss_pct"),
            }
            for r in results if isinstance(r, dict)
        ],
        "history": history,
    }


def _pndcc27_visual_page():
    body = r"""
    <style>
    .npv{--b:#0b1324;--p:#101b30;--p2:#0d1729;--bd:#263958;--tx:#f2f7ff;--mu:#8ea3c3;--blue:#4fb4ff;--cyan:#45e6d0;--vio:#a37cff;--green:#42e6a4;--amber:#ffc857;--red:#ff5f7a;color:var(--tx)}
    .npv-hero{padding:24px;border:1px solid var(--bd);border-radius:24px;background:radial-gradient(circle at 88% 8%,rgba(79,180,255,.20),transparent 27%),radial-gradient(circle at 10% 100%,rgba(163,124,255,.14),transparent 32%),linear-gradient(135deg,#13223b,#0b1324 70%);box-shadow:0 20px 55px rgba(0,0,0,.25)}
    .npv-brand{display:flex;gap:13px;align-items:center}.npv-orb{width:46px;height:46px;border-radius:15px;display:grid;place-items:center;background:linear-gradient(145deg,#168cff,#735cff);box-shadow:0 0 30px rgba(79,180,255,.32);font-size:22px}.npv-title{font-size:26px;font-weight:900;letter-spacing:-.03em}.npv-sub{font-size:12px;color:var(--mu);margin-top:3px}.npv-live{display:inline-flex;align-items:center;gap:7px;margin-top:15px;padding:7px 11px;border-radius:999px;background:rgba(66,230,164,.08);border:1px solid rgba(66,230,164,.22);color:#baffdf;font-size:11px;font-weight:800}.npv-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 13px var(--green);animation:npvPulse 1.8s infinite}@keyframes npvPulse{50%{opacity:.45;transform:scale(.7)}}
    .npv-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-top:16px}.npv-kpi{position:relative;overflow:hidden;min-height:126px;padding:17px;border:1px solid var(--bd);border-radius:18px;background:linear-gradient(145deg,#121f35,#0d1728);box-shadow:0 10px 28px rgba(0,0,0,.16)}.npv-kpi:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--ac);box-shadow:0 0 18px var(--ac)}.npv-top{display:flex;justify-content:space-between;align-items:center}.npv-label{font-size:10px;font-weight:900;letter-spacing:.12em;color:var(--mu)}.npv-icon{font-size:19px}.npv-state{font-size:10px;font-weight:900;color:var(--ac);letter-spacing:.06em}.npv-val{font-size:31px;font-weight:900;letter-spacing:-.04em;margin-top:14px}.npv-foot{display:flex;justify-content:space-between;margin-top:9px;font-size:11px;color:var(--mu)}
    .npv-sec{margin-top:18px}.npv-panel{border:1px solid var(--bd);border-radius:21px;background:linear-gradient(145deg,#111d32,#0b1425);box-shadow:0 12px 34px rgba(0,0,0,.17);overflow:hidden}.npv-head{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:17px 18px 9px}.npv-pt{font-weight:850;font-size:14px}.npv-note{font-size:10px;color:var(--mu)}.npv-chart{display:block;width:100%;height:235px}.npv-stat{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;padding:0 18px 17px}.npv-mini{padding:10px 12px;border-radius:13px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.06)}.npv-mini span{display:block;font-size:9px;color:var(--mu);text-transform:uppercase;letter-spacing:.1em}.npv-mini b{display:block;margin-top:4px;font-size:15px}
    .npv-health{display:grid;grid-template-columns:1.2fr .8fr}.npv-gauge{min-height:310px;display:grid;place-items:center;padding:8px 18px 18px}.npv-gauge svg{width:100%;max-width:410px;height:295px}.npv-health-side{border-left:1px solid var(--bd);padding:25px}.npv-score{font-size:52px;font-weight:950;letter-spacing:-.06em;margin-top:3px}.npv-health-state{font-size:12px;font-weight:900;margin-top:4px}.npv-copy{font-size:11px;line-height:1.55;color:var(--mu);margin-top:16px}.npv-list{margin-top:17px;display:grid;gap:8px}.npv-item{display:flex;justify-content:space-between;border-bottom:1px solid rgba(255,255,255,.06);padding-bottom:8px;font-size:11px}.npv-item span{color:var(--mu)}
    .npv-activity{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:16px 18px 7px}.npv-act{padding:13px;border-radius:15px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.06)}.npv-act-i{font-size:16px}.npv-act-l{font-size:9px;color:var(--mu);font-weight:900;letter-spacing:.1em;margin-top:7px}.npv-act-v{font-size:20px;font-weight:900;margin-top:3px}.npv-legend{display:flex;gap:14px;flex-wrap:wrap;padding:0 18px 16px;color:var(--mu);font-size:10px}.npv-legend i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}
    .npv-devices{padding:5px 14px 16px;display:grid;gap:9px}.npv-device{display:grid;grid-template-columns:minmax(180px,1.2fr) 115px 115px minmax(150px,1fr);align-items:center;gap:12px;padding:13px;border:1px solid rgba(255,255,255,.06);border-radius:15px;background:rgba(255,255,255,.022)}.npv-dname{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:800;min-width:0}.npv-dname span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.npv-dstatus{font-size:10px;font-weight:900}.npv-dmetric{font-size:11px;color:var(--mu)}.npv-spark{width:100%;height:38px}.npv-read{margin-top:18px;padding:12px 14px;border-radius:14px;background:rgba(79,180,255,.06);border:1px solid rgba(79,180,255,.16);font-size:11px;color:#c8dcf8}.npv-nav{display:flex;gap:10px;flex-wrap:wrap}.npv-nav a{padding:9px 12px;border-radius:11px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);text-decoration:none}
    @media(max-width:820px){.npv-grid{grid-template-columns:repeat(2,1fr)}.npv-health{grid-template-columns:1fr}.npv-health-side{border-left:0;border-top:1px solid var(--bd)}.npv-activity{grid-template-columns:repeat(2,1fr)}.npv-device{grid-template-columns:1fr 1fr}.npv-spark{grid-column:1/-1}}@media(max-width:560px){.npv-grid{grid-template-columns:1fr}.npv-stat{grid-template-columns:1fr}.npv-activity{grid-template-columns:1fr}.npv-title{font-size:21px}}
    </style>
    <div class='npv'>
      <section class='npv-hero'><div class='npv-brand'><div class='npv-orb'>📡</div><div><div class='npv-title'>Network Pulse</div><div class='npv-sub'>Your network, at a glance — vibrant, live and read-only.</div></div></div><div class='npv-live'><span class='npv-dot'></span> LIVE · PHASE 3A · v2.7.2</div><div class='npv-read'>🛡️ <b>Read-only monitor</b> — no automatic changes to network settings, connections, FTP/FTPS, devices, files, Keychain or system configuration.</div></section>
      <section class='npv-grid'>
        <div class='npv-kpi' style='--ac:#4fb4ff'><div class='npv-top'><span class='npv-icon'>🌐</span><span id='v-inet-state' class='npv-state'>—</span></div><div class='npv-label'>INTERNET</div><div id='v-inet' class='npv-val'>—</div><div id='v-inet-foot' class='npv-foot'>—</div></div>
        <div class='npv-kpi' style='--ac:#ffc857'><div class='npv-top'><span class='npv-icon'>⚡</span><span id='v-lat-state' class='npv-state'>—</span></div><div class='npv-label'>LATENCY</div><div id='v-lat' class='npv-val'>—</div><div class='npv-foot'><span>Internet response</span><span>ms</span></div></div>
        <div class='npv-kpi' style='--ac:#42e6a4'><div class='npv-top'><span class='npv-icon'>📉</span><span id='v-loss-state' class='npv-state'>—</span></div><div class='npv-label'>PACKET LOSS</div><div id='v-loss' class='npv-val'>—</div><div class='npv-foot'><span>Measured loss</span><span>%</span></div></div>
        <div class='npv-kpi' style='--ac:#a37cff'><div class='npv-top'><span class='npv-icon'>🔎</span><span id='v-dns-state' class='npv-state'>—</span></div><div class='npv-label'>DNS RESPONSE</div><div id='v-dns' class='npv-val'>—</div><div class='npv-foot'><span>Resolver response</span><span>ms</span></div></div>
        <div class='npv-kpi' style='--ac:#45e6d0'><div class='npv-top'><span class='npv-icon'>❤️</span><span class='npv-state'>SCORE</span></div><div class='npv-label'>NETWORK HEALTH SCORE</div><div id='v-health' class='npv-val'>—</div><div id='v-health-foot' class='npv-foot'>—</div></div>
        <div class='npv-kpi' style='--ac:#ff7bb7'><div class='npv-top'><span class='npv-icon'>🖥️</span><span id='v-dev-state' class='npv-state'>—</span></div><div class='npv-label'>DEVICES</div><div id='v-dev' class='npv-val'>—</div><div class='npv-foot'><span>Online now</span><span id='v-dev-foot'>—</span></div></div>
      </section>
      <section class='npv-sec'><div class='npv-panel'><div class='npv-head'><div><div class='npv-pt'>📈 Latency intelligence</div><div class='npv-note'>Real monitor samples · no synthetic history</div></div><div id='v-updated' class='npv-note'>Waiting…</div></div><svg id='v-lat-chart' class='npv-chart' viewBox='0 0 900 235' aria-label='Latency trend'></svg><div class='npv-stat'><div class='npv-mini'><span>Current</span><b id='v-lat-cur'>—</b></div><div class='npv-mini'><span>Average</span><b id='v-lat-avg'>—</b></div><div class='npv-mini'><span>Peak</span><b id='v-lat-peak'>—</b></div></div></div></section>
      <section class='npv-sec'><div class='npv-panel npv-health'><div class='npv-gauge'><svg id='v-gauge' viewBox='0 0 410 295' aria-label='Network health gauge'></svg></div><div class='npv-health-side'><div class='npv-label'>NETWORK HEALTH</div><div id='v-score' class='npv-score'>—</div><div id='v-health-state' class='npv-health-state'>—</div><div class='npv-copy'>A calculated decision score derived from the existing read-only measurements. Latency, packet loss and DNS remain the source-of-truth metrics.</div><div class='npv-list'><div class='npv-item'><span>🌐 Internet</span><b id='v-hi'>—</b></div><div class='npv-item'><span>⚡ Latency</span><b id='v-hl'>—</b></div><div class='npv-item'><span>📉 Packet loss</span><b id='v-hloss'>—</b></div><div class='npv-item'><span>🔎 DNS</span><b id='v-hdns'>—</b></div></div></div></div></section>
      <section class='npv-sec'><div class='npv-panel'><div class='npv-head'><div><div class='npv-pt'>📡 Network activity</div><div class='npv-note'>Current snapshot and observed trend</div></div></div><div class='npv-activity'><div class='npv-act'><div class='npv-act-i'>⬇️</div><div class='npv-act-l'>DOWNLOAD · MEASURED</div><div id='v-down' class='npv-act-v'>—</div></div><div class='npv-act'><div class='npv-act-i'>⬆️</div><div class='npv-act-l'>UPLOAD · MEASURED</div><div id='v-up' class='npv-act-v'>—</div></div><div class='npv-act'><div class='npv-act-i'>🔗</div><div class='npv-act-l'>TCP / UDP</div><div id='v-tcpudp' class='npv-act-v'>—</div></div><div class='npv-act'><div class='npv-act-i'>🔒</div><div class='npv-act-l'>ESTABLISHED TCP</div><div id='v-est' class='npv-act-v'>—</div></div></div><svg id='v-traffic' class='npv-chart' viewBox='0 0 900 215' aria-label='Traffic trend'></svg><div class='npv-legend'><span><i style='background:#4fb4ff'></i>Download</span><span><i style='background:#45e6d0'></i>Upload</span></div></div></section>
      <section class='npv-sec'><div class='npv-panel'><div class='npv-head'><div><div class='npv-pt'>🖥️ Device health</div><div class='npv-note'>Status · latency · loss · recent latency shape</div></div><div class='npv-note'>Read-only</div></div><div id='v-devices' class='npv-devices'></div></div></section>
      <section class='npv-sec'><div class='npv-nav'><a href='/'>← Dashboard</a><a href='/network-diagnostics'>Network Diagnostics →</a><a href='/api/network-pulse'>JSON Network Pulse →</a></div></section>
    </div>
    <script>
    (function(){const $=id=>document.getElementById(id), num=v=>Number.isFinite(Number(v))?Number(v):null, fmt=(v,d=1)=>num(v)==null?'—':Number(v).toFixed(d), arr=a=>a.filter(v=>num(v)!=null).map(Number), esc=v=>String(v??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
      const health=v=>{v=num(v);return v==null?['—','#8ea3c3']:v>=90?['EXCELLENT','#42e6a4']:v>=75?['HEALTHY','#4fb4ff']:v>=50?['DEGRADED','#ffc857']:['CRITICAL','#ff5f7a']};
      const status=s=>{s=String(s||'').toUpperCase();return s.includes('CRITICAL')?['CRITICAL','#ff5f7a']:s.includes('OFFLINE')?['OFFLINE','#7f8da6']:s.includes('DEGRADED')||s.includes('WARNING')?['DEGRADED','#ffc857']:s.includes('ONLINE')?['ONLINE','#42e6a4']:[s||'UNKNOWN','#8ea3c3']};
      function line(svgId,a,b,labels){const svg=$(svgId),A=arr(a),B=arr(b),all=arr(a.concat(b));if(!svg)return;if(!all.length){svg.innerHTML='<text x="450" y="118" text-anchor="middle" fill="#8ea3c3" font-size="13">Collecting live samples…</text>';return}const W=900,H=svgId==='v-traffic'?215:235,L=46,R=20,T=18,BT=32,IW=W-L-R,IH=H-T-BT,hi=Math.max(...all,1)*1.15;let o='';for(let k=0;k<5;k++){let y=T+IH*k/4;o+=`<line x1="${L}" y1="${y}" x2="${W-R}" y2="${y}" stroke="#2a4161" opacity=".55"/>`;o+=`<text x="${L-8}" y="${y+4}" text-anchor="end" fill="#7186a5" font-size="9">${Math.round(hi*(1-k/4))}</text>`}function pts(vals){return vals.map((v,i)=>num(v)==null?null:`${L+i/Math.max(vals.length-1,1)*IW},${T+IH-num(v)/hi*IH}`).filter(Boolean)}const pa=pts(a),pb=pts(b);if(pa.length>1){const base=pa[0].split(',')[0]+','+(T+IH)+' '+pa.join(' ')+' '+pa.at(-1).split(',')[0]+','+(T+IH);o+=`<polygon points="${base}" fill="#4fb4ff" opacity=".09"/>`;o+=`<polyline points="${pa.join(' ')}" fill="none" stroke="#4fb4ff" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>`}if(pb.length>1)o+=`<polyline points="${pb.join(' ')}" fill="none" stroke="#45e6d0" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>`;if(pa.length){let [x,y]=pa.at(-1).split(',');o+=`<circle cx="${x}" cy="${y}" r="5" fill="#4fb4ff"/><circle cx="${x}" cy="${y}" r="11" fill="#4fb4ff" opacity=".12"/>`}for(let i=0;i<labels.length;i+=Math.max(1,Math.floor(labels.length/4))){let x=L+i/Math.max(labels.length-1,1)*IW;o+=`<text x="${x}" y="${H-8}" text-anchor="middle" fill="#7186a5" font-size="9">${esc(labels[i])}</text>`}svg.innerHTML=o}
      function gauge(score){const svg=$('v-gauge'),v=Math.max(0,Math.min(100,num(score)==null?0:num(score))),[lab,c]=health(v),cx=205,cy=190,r=122,st=-135,en=135,rad=d=>d*Math.PI/180,pt=d=>({x:cx+r*Math.cos(rad(d)),y:cy+r*Math.sin(rad(d))}),arc=(a,b)=>{let p=pt(a),q=pt(b),lg=Math.abs(b-a)>180?1:0;return`M${p.x} ${p.y} A${r} ${r} 0 ${lg} 1 ${q.x} ${q.y}`},ang=st+(en-st)*v/100;let ticks='';for(let i=0;i<=10;i++){let d=st+(en-st)*i/10,a=pt(d),ri=r-5,b={x:cx+ri*Math.cos(rad(d)),y:cy+ri*Math.sin(rad(d))};ticks+=`<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#7186a5" opacity=".45" stroke-width="2"/>`}svg.innerHTML=`<path d="${arc(st,en)}" fill="none" stroke="#263a58" stroke-width="25" stroke-linecap="round"/><path d="${arc(st,st+(en-st)*.5)}" fill="none" stroke="#ffc857" opacity=".28" stroke-width="25"/><path d="${arc(st+(en-st)*.5,st+(en-st)*.75)}" fill="none" stroke="#4fb4ff" opacity=".28" stroke-width="25"/><path d="${arc(st+(en-st)*.75,en)}" fill="none" stroke="#42e6a4" opacity=".28" stroke-width="25"/><path d="${arc(st,ang)}" fill="none" stroke="${c}" stroke-width="25" stroke-linecap="round"/>${ticks}<line x1="${cx}" y1="${cy}" x2="${cx+(r-9)*Math.cos(rad(ang))}" y2="${cy+(r-9)*Math.sin(rad(ang))}" stroke="${c}" stroke-width="5" stroke-linecap="round"/><circle cx="${cx}" cy="${cy}" r="10" fill="${c}"/><text x="${cx}" y="132" text-anchor="middle" fill="#f2f7ff" font-size="54" font-weight="900">${Math.round(v)}</text><text x="${cx}" y="154" text-anchor="middle" fill="${c}" font-size="12" font-weight="900" letter-spacing="2">${lab}</text><text x="70" y="242" fill="#7186a5" font-size="10">0</text><text x="340" y="242" text-anchor="end" fill="#7186a5" font-size="10">100</text>`}
      function spark(hist,id,c){const vals=hist.map(h=>(h.devices||[]).find(d=>d.id===id)?.latency_ms),v=arr(vals);if(!v.length)return'<span style="color:#7186a5;font-size:10px">No history yet</span>';const W=220,H=38,hi=Math.max(...v,1),p=3,pts=vals.map((x,i)=>num(x)==null?null:`${p+i/Math.max(vals.length-1,1)*(W-2*p)},${H-p-num(x)/hi*(H-2*p)}`).filter(Boolean);return`<svg class="npv-spark" viewBox="0 0 ${W} ${H}"><polyline points="${pts.join(' ')}" fill="none" stroke="${c}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`}
      function setSignal(state, score){const lights={HEALTHY:$('dh29-signal-green'),WATCH:$('dh29-signal-yellow'),PROBLEM:$('dh29-signal-red')};Object.values(lights).forEach(el=>{if(el)el.classList.remove('active','level1','level2','level3')});const key=state==='ATTENTION'?'PROBLEM':(state==='WATCH'?'WATCH':'HEALTHY');const n=Number.isFinite(Number(score))?Number(score):0;const level=n>=90?1:(n>=70?2:3);const el=lights[key];if(el)el.classList.add('active','level'+level);const label=$('dh29-signal-label'),detail=$('dh29-signal-detail');const name=key==='HEALTHY'?'Green':key==='WATCH'?'Yellow':'Red';const intensity=level===1?'low':level===2?'medium':'strong';if(label)label.textContent=key;if(detail)detail.textContent=name+' active · '+intensity+' intensity · dynamic pulse'}
      function render(d){const p=d.pulse||{},i=p.internet||{},dns=p.dns||{},t=p.traffic||{},c=p.connections||{},h=p.network_health||{},hist=d.history||[],dev=d.devices||[],score=num(h.score),[hl,hc]=health(score);let online=dev.filter(x=>String(x.status||'').toUpperCase().includes('ONLINE')).length; $('v-inet').textContent=i.status||'—';$('v-inet-state').textContent=i.status||'—';$('v-inet-foot').textContent=i.test_host?'Test host '+i.test_host:'—';$('v-lat').textContent=fmt(i.latency_ms);$('v-lat-state').textContent=num(i.latency_ms)==null?'—':num(i.latency_ms)<30?'FAST':num(i.latency_ms)<100?'NORMAL':'ELEVATED';$('v-loss').textContent=fmt(i.packet_loss_pct)+'%';$('v-loss-state').textContent=num(i.packet_loss_pct)==null?'—':num(i.packet_loss_pct)===0?'EXCELLENT':num(i.packet_loss_pct)<2?'LOW':'HIGH';$('v-dns').textContent=fmt(dns.response_ms);$('v-dns-state').textContent=dns.status||'—';$('v-health').textContent=score==null?'—':Math.round(score);$('v-health-foot').textContent=hl;$('v-dev').textContent=`${online} / ${dev.length}`;$('v-dev-state').textContent='INVENTORY';$('v-dev-foot').textContent='online now';$('v-updated').textContent=d.timestamp?'Updated '+d.timestamp:'—';$('v-health-state').textContent='● '+hl;$('v-health-state').style.color=hc;$('v-score').textContent=score==null?'—':Math.round(score);$('v-score').style.color=hc;$('v-hi').textContent=i.status||'—';$('v-hl').textContent=fmt(i.latency_ms)+' ms';$('v-hloss').textContent=fmt(i.packet_loss_pct)+'%';$('v-hdns').textContent=fmt(dns.response_ms)+' ms';$('v-down').textContent=num(t.download_mbps)==null?'Not measured':Number(t.download_mbps).toFixed(2)+' Mbps';$('v-up').textContent=num(t.upload_mbps)==null?'Not measured':Number(t.upload_mbps).toFixed(2)+' Mbps';$('v-tcpudp').textContent=`${c.tcp??'—'} / ${c.udp??'—'}`;$('v-est').textContent=c.established_tcp??'—';let l=hist.map(x=>x.latency_ms),labels=hist.map(x=>{try{return new Date(x.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})}catch(e){return''}});$('v-lat-cur').textContent=fmt(i.latency_ms)+' ms';$('v-lat-avg').textContent=(arr(l).length?(arr(l).reduce((a,b)=>a+b,0)/arr(l).length).toFixed(1):'—')+' ms';$('v-lat-peak').textContent=(arr(l).length?Math.max(...arr(l)).toFixed(1):'—')+' ms';line('v-lat-chart',l,[],labels);line('v-traffic',hist.map(x=>x.download_mbps),hist.map(x=>x.upload_mbps),labels);gauge(score);$('v-devices').innerHTML=dev.map(x=>{let [sl,sc]=status(x.status);return`<div class="npv-device"><div class="npv-dname">${String(x.name||'').toLowerCase().includes('router')?'📡':String(x.name||'').toLowerCase().includes('phone')||String(x.name||'').toLowerCase().includes('ipad')||String(x.name||'').toLowerCase().includes('android')||String(x.name||'').toLowerCase().includes('oneplus')?'📱':'💻'}<span>${esc(x.name)}</span></div><div class="npv-dstatus" style="color:${sc}">● ${sl}</div><div class="npv-dmetric">${String(x.status||'').toUpperCase().includes('OFFLINE')?'<b style=\"color:#7f8da6\">Offline · —</b>':'<b style=\"color:#f2f7ff\">'+(x.latency_ms==null?'—':fmt(x.latency_ms)+' ms')+'</b><br>'+(x.packet_loss_pct==null?'—':fmt(x.packet_loss_pct)+'% loss')}</div><div>${spark(hist,x.id,sc)}</div></div>`}).join('')||'<div class="npv-device">No device snapshot available.</div>'}
      async function refresh(){try{let r=await fetch('/api/network-pulse?visual=1',{cache:'no-store'});if(!r.ok)throw Error(r.status);render(await r.json())}catch(e){$('v-updated').textContent='Network Pulse temporarily unavailable'}}refresh();setInterval(refresh,5000)})();
    </script>
    """
    return page_shell("PNDCC v2.7.2 · Network Pulse", body).replace("Version 2.6.3", "Version 2.7.2").replace("PNDCC v2.6.3</footer>", "PNDCC v2.7.2</footer>").replace("Local-only dashboard · 30-second refresh · persistent CSV history", "Local-only dashboard · 5-second visual refresh · bounded live history")


_PNDCC27_OLD_GET = H.do_GET

def _pndcc27_get(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path == "/api/network-pulse":
        try:
            _json_response(self, _pndcc27_payload())
        except Exception as e:
            self._send_text(500, "Network Pulse visualization API failed: " + type(e).__name__)
        return
    if parsed.path == "/network-pulse":
        data = _pndcc27_visual_page().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        return
    return _PNDCC27_OLD_GET(self)

H.do_GET = _pndcc27_get



# ============================================================================
# PNDCC v2.8 — Decision Center + Vibrant Visualization
# Additive-only layer built on the validated v2.7.2 Network Pulse snapshot.
#
# Purpose:
#   Interpret existing read-only measurements, explain what they mean, and
#   provide a conservative recommended action without changing the monitor.
#
# Safety:
#   No second monitoring engine. No automatic network/device/FTP action.
#   Existing v2.7.2 routes and functionality remain intact.
# ============================================================================

PNDCC_VERSION = "2.8"
PNDCC_UPDATED = "2026-10-08 Phase 3B Decision Center + Vibrant Visualization"
PNDCC_PHASE3B_VERSION = "3B-DECISION"


def _pndcc28_decision_snapshot():
    """Interpret the existing v2.7.2 read-only Network Pulse snapshot."""
    base = _pndcc27_payload()
    pulse = base.get("pulse") or {}
    internet = pulse.get("internet") or {}
    dns = pulse.get("dns") or {}
    health = pulse.get("network_health") or {}
    devices = base.get("devices") or []

    latency = internet.get("latency_ms")
    loss = internet.get("packet_loss_pct")
    dns_ms = dns.get("response_ms")
    internet_status = str(internet.get("status") or "UNKNOWN").upper()
    score = health.get("score")

    alerts = []
    observations = []

    # Conservative decision rules. Offline inventory devices are not treated as
    # failures because network reachability does not prove physical power state.
    if internet_status == "OFFLINE":
        alerts.append({
            "level": "CRITICAL",
            "title": "Internet connectivity unavailable",
            "detail": "The existing Internet reachability test is offline.",
            "action": "Check the router and Internet connection, then retest.",
        })
    if loss is not None and loss >= 50:
        alerts.append({
            "level": "CRITICAL",
            "title": "Severe packet loss",
            "detail": f"Current measured packet loss is {loss:.1f}%.",
            "action": "Check Wi-Fi/router conditions and retest before deeper diagnosis.",
        })
    elif loss is not None and loss >= 2:
        alerts.append({
            "level": "WARNING",
            "title": "Packet loss detected",
            "detail": f"Current measured packet loss is {loss:.1f}%.",
            "action": "Monitor for persistence and retest if it continues.",
        })
    if latency is not None and latency >= 100:
        alerts.append({
            "level": "WARNING",
            "title": "Internet latency elevated",
            "detail": f"Current Internet latency is {latency:.1f} ms.",
            "action": "Retest and check whether the elevation persists.",
        })
    if dns_ms is not None and dns_ms >= 100:
        alerts.append({
            "level": "WARNING",
            "title": "DNS response elevated",
            "detail": f"Current DNS response is {dns_ms:.1f} ms.",
            "action": "Retest DNS and investigate only if the delay persists.",
        })

    degraded_devices = []
    for device in devices:
        status = str(device.get("status") or "").upper()
        dlat = device.get("latency_ms")
        if "CRITICAL" in status or (isinstance(dlat, (int, float)) and dlat >= 100):
            degraded_devices.append(device.get("name") or "Device")
    if degraded_devices:
        name_list = ", ".join(degraded_devices[:3])
        alerts.append({
            "level": "WARNING",
            "title": "Device latency needs attention",
            "detail": f"Elevated device latency detected: {name_list}.",
            "action": "Check the affected device's Wi-Fi state and retest.",
        })

    offline = [d.get("name") or "Device" for d in devices if "OFFLINE" in str(d.get("status") or "").upper()]
    if offline:
        observations.append({
            "label": "Inventory reachability",
            "value": f"{len(offline)} device(s) currently unreachable",
            "detail": "This is informational unless you expected those devices to be connected.",
        })

    if alerts:
        priority = "CRITICAL" if any(a["level"] == "CRITICAL" for a in alerts) else "WARNING"
        headline = "Action recommended" if priority == "WARNING" else "Immediate attention recommended"
        summary = alerts[0]["detail"]
        action = alerts[0]["action"]
    else:
        priority = "NORMAL"
        headline = "Network operating normally"
        if internet_status == "ONLINE" and score is not None and score >= 90:
            summary = "Internet, latency, packet loss and DNS are within the current normal range."
        else:
            summary = "No immediate network action is indicated by the current measurements."
        action = "No action required. Continue normal monitoring."

    return {
        "phase": PNDCC_PHASE3B_VERSION,
        "version": PNDCC_VERSION,
        "timestamp": base.get("timestamp") or now(),
        "decision": {
            "priority": priority,
            "headline": headline,
            "summary": summary,
            "recommended_action": action,
        },
        "alerts": alerts,
        "observations": observations,
        "pulse": pulse,
        "devices": devices,
        "history": base.get("history") or [],
        "rules_note": "Decision Center interprets existing read-only measurements; it does not automatically change network or device state.",
    }


def _pndcc28_visual_page():
    body = r"""
    <style>
    .d28{--bg:#07111f;--panel:#0c192b;--panel2:#10213a;--bd:#24405f;--tx:#f4f8ff;--mu:#91a7c6;--cyan:#39e6ff;--blue:#5aa9ff;--vio:#a678ff;--green:#42e6a4;--amber:#ffc857;--red:#ff5d78;color:var(--tx)}
    .d28 *{box-sizing:border-box}.d28-hero{position:relative;overflow:hidden;padding:25px;border:1px solid var(--bd);border-radius:26px;background:radial-gradient(circle at 88% 18%,rgba(57,230,255,.20),transparent 26%),radial-gradient(circle at 15% 100%,rgba(166,120,255,.18),transparent 31%),linear-gradient(135deg,#142c49,#081321 68%);box-shadow:0 20px 60px rgba(0,0,0,.28)}
    .d28-hero:after{content:"";position:absolute;inset:0;pointer-events:none;background:linear-gradient(115deg,transparent 15%,rgba(255,255,255,.045) 48%,transparent 75%);animation:d28Sweep 7s ease-in-out infinite}@keyframes d28Sweep{0%,100%{transform:translateX(-35%)}50%{transform:translateX(35%)}}
    .d28-top{position:relative;z-index:1;display:flex;justify-content:space-between;gap:16px;align-items:flex-start}.d28-brand{display:flex;gap:13px;align-items:center}.d28-orb{width:50px;height:50px;border-radius:16px;display:grid;place-items:center;font-size:23px;background:linear-gradient(145deg,#18bfff,#815dff);box-shadow:0 0 34px rgba(57,230,255,.28)}.d28-title{font-size:27px;font-weight:950;letter-spacing:-.04em}.d28-sub{font-size:12px;color:var(--mu);margin-top:3px}.d28-live{display:inline-flex;align-items:center;gap:7px;margin-top:15px;padding:7px 11px;border-radius:999px;background:rgba(66,230,164,.09);border:1px solid rgba(66,230,164,.22);color:#bfffe2;font-size:10px;font-weight:900;letter-spacing:.08em}.d28-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 15px var(--green);animation:d28Pulse 1.7s infinite}@keyframes d28Pulse{50%{opacity:.45;transform:scale(.7)}}
    .d28-priority{position:relative;z-index:1;display:inline-flex;align-items:center;gap:8px;margin-top:18px;padding:8px 12px;border-radius:999px;font-size:10px;font-weight:950;letter-spacing:.08em}.d28-priority.NORMAL{color:#bfffe2;background:rgba(66,230,164,.1);border:1px solid rgba(66,230,164,.25)}.d28-priority.WARNING{color:#ffe5a0;background:rgba(255,200,87,.1);border:1px solid rgba(255,200,87,.27)}.d28-priority.CRITICAL{color:#ffd0d8;background:rgba(255,93,120,.11);border:1px solid rgba(255,93,120,.3)}
    .d28-decision{position:relative;z-index:1;display:grid;grid-template-columns:1.25fr .75fr;gap:16px;margin-top:16px}.d28-message{padding:19px;border:1px solid rgba(255,255,255,.08);border-radius:20px;background:rgba(4,12,23,.42);backdrop-filter:blur(8px)}.d28-message h2{font-size:22px;margin:0;font-weight:950;letter-spacing:-.03em}.d28-message p{font-size:12px;line-height:1.55;color:#b5c7df;margin:9px 0 0}.d28-action{padding:19px;border-radius:20px;background:linear-gradient(145deg,rgba(57,230,255,.11),rgba(166,120,255,.08));border:1px solid rgba(57,230,255,.18)}.d28-action-label{font-size:9px;letter-spacing:.12em;font-weight:950;color:var(--cyan)}.d28-action b{display:block;margin-top:7px;font-size:14px;line-height:1.45}.d28-time{font-size:10px;color:var(--mu);margin-top:12px}
    .d28-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:16px}.d28-kpi{padding:15px;border:1px solid var(--bd);border-radius:18px;background:linear-gradient(145deg,#10213a,#0a1728);position:relative;overflow:hidden}.d28-kpi:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--ac);box-shadow:0 0 17px var(--ac)}.d28-klabel{font-size:9px;color:var(--mu);font-weight:900;letter-spacing:.11em}.d28-kvalue{font-size:27px;font-weight:950;letter-spacing:-.04em;margin-top:9px}.d28-kstate{font-size:9px;font-weight:900;color:var(--ac);margin-top:4px}.d28-section{margin-top:17px}.d28-panel{border:1px solid var(--bd);border-radius:21px;background:linear-gradient(145deg,#0f1f34,#091524);overflow:hidden;box-shadow:0 12px 34px rgba(0,0,0,.18)}.d28-head{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:17px 18px 10px}.d28-pt{font-size:14px;font-weight:900}.d28-note{font-size:10px;color:var(--mu)}
    .d28-two{display:grid;grid-template-columns:1.15fr .85fr;gap:17px}.d28-chart{width:100%;height:245px;display:block}.d28-insights{padding:0 18px 17px;display:grid;gap:9px}.d28-insight{display:grid;grid-template-columns:10px 1fr;gap:9px;padding:11px 12px;border-radius:13px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.06)}.d28-insight i{width:8px;height:8px;border-radius:50%;background:var(--ac);box-shadow:0 0 11px var(--ac);margin-top:4px}.d28-insight b{font-size:11px}.d28-insight span{display:block;color:var(--mu);font-size:10px;line-height:1.4;margin-top:3px}
    .d28-alerts{padding:5px 14px 16px;display:grid;gap:9px}.d28-alert{display:grid;grid-template-columns:90px 1fr auto;gap:12px;align-items:center;padding:13px;border-radius:15px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07)}.d28-badge{font-size:9px;font-weight:950;letter-spacing:.1em;padding:6px 8px;border-radius:8px;text-align:center}.d28-badge.WARNING{color:#ffe5a0;background:rgba(255,200,87,.1)}.d28-badge.CRITICAL{color:#ffd0d8;background:rgba(255,93,120,.11)}.d28-alert-title{font-size:12px;font-weight:900}.d28-alert-detail{font-size:10px;color:var(--mu);margin-top:3px}.d28-alert-action{font-size:10px;color:#cde0f8;max-width:240px;text-align:right}
    .d28-devices{padding:5px 14px 16px;display:grid;gap:9px}.d28-device{display:grid;grid-template-columns:minmax(170px,1.2fr) 90px 90px minmax(150px,1fr);gap:11px;align-items:center;padding:12px;border:1px solid rgba(255,255,255,.06);border-radius:14px;background:rgba(255,255,255,.02)}.d28-dname{font-size:12px;font-weight:850;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.d28-status{font-size:9px;font-weight:950}.d28-metric{font-size:10px;color:var(--mu)}.d28-spark{width:100%;height:34px}.d28-footer{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-top:15px;padding:11px 13px;border-radius:13px;background:rgba(57,230,255,.045);border:1px solid rgba(57,230,255,.12);font-size:10px;color:#b9cde7}.d28-nav{display:flex;gap:9px;flex-wrap:wrap}.d28-nav a{padding:9px 12px;border-radius:11px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);text-decoration:none}
    @media(max-width:860px){.d28-decision,.d28-two{grid-template-columns:1fr}.d28-grid{grid-template-columns:repeat(2,1fr)}.d28-alert{grid-template-columns:80px 1fr}.d28-alert-action{grid-column:2;text-align:left;max-width:none}.d28-device{grid-template-columns:1fr 1fr}.d28-spark{grid-column:1/-1}}@media(max-width:560px){.d28-grid{grid-template-columns:1fr}.d28-top{flex-direction:column}.d28-title{font-size:22px}.d28-device{grid-template-columns:1fr}.d28-spark{grid-column:auto}.d28-alert{grid-template-columns:1fr}.d28-alert-action{grid-column:auto}}
    @media(prefers-reduced-motion:reduce){.d28-hero:after,.d28-dot{animation:none}}
    </style>
    <div class='d28'>
      <section class='d28-hero'>
        <div class='d28-top'><div><div class='d28-brand'><div class='d28-orb'>🧠</div><div><div class='d28-title'>Decision Center</div><div class='d28-sub'>Your network, interpreted — vibrant, clear and conservative.</div></div></div><div id='d28-priority' class='d28-priority NORMAL'>● NORMAL</div></div><div class='d28-live'><span class='d28-dot'></span> LIVE · PHASE 3B · v2.8</div></div>
        <div class='d28-decision'><div class='d28-message'><h2 id='d28-headline'>Collecting the current network picture…</h2><p id='d28-summary'>Reading the existing Network Pulse measurements.</p><div id='d28-time' class='d28-time'>—</div></div><div class='d28-action'><div class='d28-action-label'>RECOMMENDED ACTION</div><b id='d28-action'>No action required while the current measurements are healthy.</b></div></div>
      </section>
      <section class='d28-grid'>
        <div class='d28-kpi' style='--ac:#39e6ff'><div class='d28-klabel'>NETWORK HEALTH</div><div id='d28-health' class='d28-kvalue'>—</div><div id='d28-health-state' class='d28-kstate'>—</div></div>
        <div class='d28-kpi' style='--ac:#42e6a4'><div class='d28-klabel'>INTERNET</div><div id='d28-internet' class='d28-kvalue'>—</div><div id='d28-internet-state' class='d28-kstate'>—</div></div>
        <div class='d28-kpi' style='--ac:#5aa9ff'><div class='d28-klabel'>LATENCY</div><div id='d28-latency' class='d28-kvalue'>—</div><div id='d28-latency-state' class='d28-kstate'>—</div></div>
        <div class='d28-kpi' style='--ac:#a678ff'><div class='d28-klabel'>DEVICES</div><div id='d28-devices-count' class='d28-kvalue'>—</div><div id='d28-devices-state' class='d28-kstate'>—</div></div>
      </section>
      <section class='d28-section d28-two'>
        <div class='d28-panel'><div class='d28-head'><div class='d28-pt'>⚡ Live network picture</div><div class='d28-note'>Existing read-only measurements</div></div><svg id='d28-chart' class='d28-chart' viewBox='0 0 900 245' role='img' aria-label='Network latency trend'></svg><div class='d28-insights'><div class='d28-insight' style='--ac:#39e6ff'><i></i><div><b id='d28-lat-current'>Latency —</b><span>Current Internet latency</span></div></div><div class='d28-insight' style='--ac:#42e6a4'><i></i><div><b id='d28-loss'>Packet loss —</b><span>Current Internet packet loss</span></div></div><div class='d28-insight' style='--ac:#a678ff'><i></i><div><b id='d28-dns'>DNS —</b><span>Current DNS response</span></div></div></div></div>
        <div class='d28-panel'><div class='d28-head'><div class='d28-pt'>🧭 What happened?</div><div class='d28-note'>Decision context</div></div><div id='d28-context' class='d28-insights'><div class='d28-insight' style='--ac:#5aa9ff'><i></i><div><b>Waiting for measurements</b><span>The decision engine will explain the current state here.</span></div></div></div></div>
      </section>
      <section class='d28-section d28-panel'><div class='d28-head'><div class='d28-pt'>🎯 Attention & recommended action</div><div class='d28-note'>No automatic action is performed</div></div><div id='d28-alerts' class='d28-alerts'></div></section>
      <section class='d28-section d28-panel'><div class='d28-head'><div class='d28-pt'>🖥️ Device reachability</div><div class='d28-note'>Network reachability, not physical usage</div></div><div id='d28-device-list' class='d28-devices'></div></section>
      <div class='d28-footer'><span>🛡️ Read-only decision support · existing Network Pulse source of truth</span><span>5-second refresh · bounded history · © Saiful Quadir</span></div>
      <section class='d28-section'><div class='d28-nav'><a href='/'>← Dashboard</a><a href='/network-pulse'>Network Pulse →</a><a href='/network-diagnostics'>Network Diagnostics →</a><a href='/api/decision-center'>JSON Decision Center →</a></div></section>
    </div>
    <script>
    (function(){
      const $=id=>document.getElementById(id), num=v=>Number.isFinite(Number(v))?Number(v):null;
      const fmt=(v,d=1)=>num(v)==null?'—':Number(v).toFixed(d);
      const esc=v=>String(v??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
      const tone=p=>p==='CRITICAL'?['#ff5d78','CRITICAL']:p==='WARNING'?['#ffc857','WARNING']:['#42e6a4','NORMAL'];
      function chart(hist){const svg=$('d28-chart');const vals=hist.map(x=>num(x.latency_ms));const clean=vals.filter(v=>v!=null);if(clean.length<2){svg.innerHTML='<text x="450" y="122" text-anchor="middle" fill="#91a7c6" font-size="13">Collecting live samples…</text>';return}const W=900,H=245,L=45,R=20,T=18,B=30,hi=Math.max(...clean,1)*1.18,IH=H-T-B,IW=W-L-R;let o='';for(let k=0;k<5;k++){const y=T+IH*k/4;o+=`<line x1="${L}" y1="${y}" x2="${W-R}" y2="${y}" stroke="#294563" opacity=".55"/><text x="${L-8}" y="${y+4}" text-anchor="end" fill="#7186a5" font-size="9">${Math.round(hi*(1-k/4))}</text>`}const pts=vals.map((v,i)=>v==null?null:`${L+i/Math.max(vals.length-1,1)*IW},${T+IH-v/hi*IH}`).filter(Boolean);o+=`<polyline points="${pts.join(' ')}" fill="none" stroke="#39e6ff" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>`;const last=pts.at(-1).split(',');o+=`<circle cx="${last[0]}" cy="${last[1]}" r="5" fill="#39e6ff"/><circle cx="${last[0]}" cy="${last[1]}" r="12" fill="#39e6ff" opacity=".12"/>`;svg.innerHTML=o}
      function spark(hist,id,c){const vals=hist.map(h=>(h.devices||[]).find(d=>d.id===id)?.latency_ms),clean=vals.filter(v=>num(v)!=null);if(!clean.length)return'<span style="color:#7186a5;font-size:9px">No history yet</span>';const W=220,H=34,hi=Math.max(...clean,1),p=3,pts=vals.map((v,i)=>num(v)==null?null:`${p+i/Math.max(vals.length-1,1)*(W-2*p)},${H-p-num(v)/hi*(H-2*p)}`).filter(Boolean);return`<svg class="d28-spark" viewBox="0 0 ${W} ${H}"><polyline points="${pts.join(' ')}" fill="none" stroke="${c}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`}
      function render(d){const dec=d.decision||{},p=d.pulse||{},i=p.internet||{},dns=p.dns||{},h=p.network_health||{},dev=d.devices||[],hist=d.history||[];const score=num(h.score),online=dev.filter(x=>String(x.status||'').toUpperCase().includes('ONLINE')).length,[c,label]=tone(dec.priority||'NORMAL');const pri=$('d28-priority');pri.textContent='● '+label;pri.className='d28-priority '+label;pri.style.color=c;$('d28-headline').textContent=dec.headline||'—';$('d28-summary').textContent=dec.summary||'—';$('d28-action').textContent=dec.recommended_action||'—';$('d28-time').textContent=d.timestamp?'Updated '+d.timestamp:'—';$('d28-health').textContent=score==null?'—':Math.round(score);$('d28-health-state').textContent=String(h.status||'—');$('d28-health-state').style.color=c;$('d28-internet').textContent=i.status||'—';$('d28-internet-state').textContent=i.status==='ONLINE'?'Reachable':'Check connection';$('d28-internet-state').style.color=i.status==='ONLINE'?'#42e6a4':'#ff5d78';$('d28-latency').textContent=fmt(i.latency_ms)+' ms';$('d28-latency-state').textContent=num(i.latency_ms)==null?'Not measured':num(i.latency_ms)<30?'FAST':num(i.latency_ms)<100?'NORMAL':'ELEVATED';$('d28-devices-count').textContent=`${online} / ${dev.length}`;$('d28-devices-state').textContent='ONLINE NOW';$('d28-lat-current').textContent='Latency '+fmt(i.latency_ms)+' ms';$('d28-loss').textContent='Packet loss '+fmt(i.packet_loss_pct)+'%';$('d28-dns').textContent='DNS '+fmt(dns.response_ms)+' ms';chart(hist);let ctx=[];if(i.status==='ONLINE')ctx.push({t:'Internet',v:'Reachability test is online.'});if(i.latency_ms!=null)ctx.push({t:'Latency',v:`Current ${fmt(i.latency_ms)} ms.`});if(i.packet_loss_pct!=null)ctx.push({t:'Packet loss',v:`Current ${fmt(i.packet_loss_pct)}%.`});if(dns.response_ms!=null)ctx.push({t:'DNS',v:`Response ${fmt(dns.response_ms)} ms.`});if((d.observations||[]).length)ctx=ctx.concat((d.observations||[]).map(x=>({t:x.label,v:x.value+' — '+x.detail})));$('d28-context').innerHTML=ctx.map(x=>`<div class="d28-insight" style="--ac:#5aa9ff"><i></i><div><b>${esc(x.t)}</b><span>${esc(x.v)}</span></div></div>`).join('')||'<div class="d28-insight"><i></i><div><b>No context available</b><span>Waiting for the next measurement.</span></div></div>';
        const alerts=d.alerts||[];$('d28-alerts').innerHTML=alerts.length?alerts.map(a=>`<div class="d28-alert"><div class="d28-badge ${esc(a.level)}">${esc(a.level)}</div><div><div class="d28-alert-title">${esc(a.title)}</div><div class="d28-alert-detail">${esc(a.detail)}</div></div><div class="d28-alert-action">${esc(a.action)}</div></div>`).join(''):`<div class="d28-alert"><div class="d28-badge NORMAL">NORMAL</div><div><div class="d28-alert-title">No active attention items</div><div class="d28-alert-detail">Current measurements do not indicate an immediate problem.</div></div><div class="d28-alert-action">No action required.</div></div>`;
        $('d28-device-list').innerHTML=dev.map(x=>{const s=String(x.status||'UNKNOWN').toUpperCase(),online=s.includes('ONLINE'),col=online?'#42e6a4':s.includes('CRITICAL')?'#ff5d78':'#7f8da6';return`<div class="d28-device"><div class="d28-dname">${esc(x.name)}</div><div class="d28-status" style="color:${col}">● ${esc(s)}</div><div class="d28-metric">${s.includes('OFFLINE')?'Offline · —':fmt(x.latency_ms)+' ms · '+fmt(x.packet_loss_pct)+'% loss'}</div><div>${spark(hist,x.id,col)}</div></div>`}).join('')||'<div class="d28-device">No device snapshot available.</div>';
      }
      async function refresh(){try{const r=await fetch('/api/decision-center',{cache:'no-store'});if(!r.ok)throw Error(r.status);render(await r.json())}catch(e){$('d28-summary').textContent='Decision Center temporarily unavailable.'}}refresh();setInterval(refresh,5000);
    })();
    </script>
    """
    return page_shell("PNDCC v2.8 · Decision Center", body).replace("Version 2.6.3", "Version 2.8").replace("PNDCC v2.6.3</footer>", "PNDCC v2.8</footer>")


_PNDCC28_OLD_GET = H.do_GET

def _pndcc28_get(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path == "/api/decision-center":
        try:
            _json_response(self, _pndcc28_decision_snapshot())
        except Exception as e:
            self._send_text(500, "Decision Center API failed: " + type(e).__name__)
        return
    if parsed.path == "/decision-center":
        data = _pndcc28_visual_page().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        return
    return _PNDCC28_OLD_GET(self)

H.do_GET = _pndcc28_get



# ============================================================================
# PNDCC v2.9 — Device Health Intelligence
# Additive-only layer built from the validated v2.8 Decision Center baseline.
#
# Purpose:
#   Answer: "Which device needs attention, why, and is it recovering?"
#
# Safety:
#   Read-only. Reuses the existing v2.7.2 measurement/history source.
#   No second monitoring engine. No automatic network/device/FTP action.
#   Existing v2.8 functionality is preserved.
# ============================================================================

PNDCC_V29_VERSION = "2.9"
PNDCC_V29_UPDATED = "2026-10-08 Phase 3C Device Health Intelligence"
PNDCC_PHASE3C_VERSION = "3C-DEVICE-HEALTH"
_PNDCC29_HISTORY_MAX = 60


def _pndcc29_num(value):
    try:
        n = float(value)
        return n if n == n and abs(n) != float("inf") else None
    except (TypeError, ValueError):
        return None


def _pndcc29_device_icon(name):
    n = str(name or "").lower()
    if "router" in n or "gateway" in n:
        return "📡"
    if "ipad" in n or "tablet" in n:
        return "📱"
    if "iphone" in n or "oneplus" in n or "phone" in n:
        return "📱"
    if "mac" in n or "windows" in n or "laptop" in n or "computer" in n:
        return "💻"
    return "🖥️"


def _pndcc29_history_for_device(history, device_id):
    rows = []
    for sample in history or []:
        if not isinstance(sample, dict):
            continue
        for d in sample.get("devices") or []:
            if isinstance(d, dict) and d.get("id") == device_id:
                rows.append({
                    "timestamp": sample.get("timestamp"),
                    "latency_ms": d.get("latency_ms"),
                    "packet_loss_pct": d.get("packet_loss_pct"),
                    "status": d.get("status", "UNKNOWN"),
                })
                break
    return rows[-_PNDCC29_HISTORY_MAX:]


def _pndcc29_classify(device, history):
    name = device.get("name") or device.get("id") or "Device"
    status = str(device.get("status") or "UNKNOWN").upper()
    latency = _pndcc29_num(device.get("latency_ms"))
    loss = _pndcc29_num(device.get("packet_loss_pct"))
    series = _pndcc29_history_for_device(history, device.get("id"))
    prior = [x for x in series[:-1] if _pndcc29_num(x.get("latency_ms")) is not None]
    previous_latency = _pndcc29_num(prior[-1].get("latency_ms")) if prior else None

    if "OFFLINE" in status or latency is None:
        health = "OFFLINE"
        icon = "⚪"
        score = None
        reason = "Network reachability is currently unavailable."
        action = "No action unless you expected this device to be connected."
    else:
        # Conservative device-health score from the same read-only measurements.
        score = 100.0
        if latency >= 300:
            score -= 65
        elif latency >= 150:
            score -= 40
        elif latency >= 100:
            score -= 25
        elif latency >= 50:
            score -= 10
        if loss is not None:
            if loss >= 50:
                score -= 45
            elif loss >= 10:
                score -= 30
            elif loss >= 2:
                score -= 15
        score = max(0, min(100, round(score)))
        if score >= 85:
            health, icon = "HEALTHY", "🟢"
        elif score >= 60:
            health, icon = "WATCH", "🟡"
        else:
            health, icon = "PROBLEM", "🔴"
        if latency >= 300:
            reason = f"Very high device latency: {latency:.1f} ms."
            action = "Check the device's Wi-Fi state and retest."
        elif latency >= 100:
            reason = f"Elevated device latency: {latency:.1f} ms."
            action = "Monitor the device and retest if the elevation persists."
        elif loss is not None and loss >= 2:
            reason = f"Packet loss is elevated at {loss:.1f}%."
            action = "Check Wi-Fi conditions and retest."
        else:
            reason = "Current reachability and latency are within the normal range."
            action = "No action required. Continue normal monitoring."

    recovered = False
    recovery_text = ""
    if previous_latency is not None and latency is not None and previous_latency >= 100 and latency < 100:
        recovered = True
        recovery_text = f"Recovered from {previous_latency:.0f} ms → {latency:.0f} ms."
    elif previous_latency is not None and latency is not None and previous_latency >= 300 and latency < previous_latency * 0.5:
        recovered = True
        recovery_text = f"Major recovery: {previous_latency:.0f} ms → {latency:.0f} ms."

    return {
        "id": device.get("id"),
        "name": name,
        "icon": _pndcc29_device_icon(name),
        "status": status,
        "health": health,
        "health_icon": icon,
        "score": score,
        "latency_ms": latency,
        "packet_loss_pct": loss,
        "reason": reason,
        "recommended_action": action,
        "recovered": recovered,
        "recovery": recovery_text,
        "history": series,
    }


def _pndcc29_snapshot():
    base = _pndcc27_payload()
    devices = base.get("devices") or []
    history = base.get("history") or []
    health_rows = [_pndcc29_classify(d, history) for d in devices if isinstance(d, dict)]
    active = [x for x in health_rows if x["health"] != "OFFLINE"]
    healthy = [x for x in active if x["health"] == "HEALTHY"]
    watch = [x for x in active if x["health"] == "WATCH"]
    problem = [x for x in active if x["health"] == "PROBLEM"]
    online_count = len(active)

    if problem:
        overall, overall_icon = "ATTENTION", "🔴"
    elif watch:
        overall, overall_icon = "WATCH", "🟡"
    elif active and len(healthy) == len(active):
        overall, overall_icon = "EXCELLENT", "🟢"
    else:
        overall, overall_icon = "NORMAL", "🟢"

    insights = []
    recovered = [x for x in health_rows if x.get("recovered")]
    if recovered:
        x = recovered[0]
        insights.append({
            "type": "RECOVERY",
            "icon": "🔄",
            "title": f"{x['name']} recovered",
            "detail": x.get("recovery") or "Device latency has improved.",
            "action": "Connectivity is currently improved. Continue monitoring.",
        })
    elif problem:
        x = problem[0]
        insights.append({
            "type": "PROBLEM",
            "icon": "🚨",
            "title": f"{x['name']} needs attention",
            "detail": x["reason"],
            "action": x["recommended_action"],
        })
    elif watch:
        x = watch[0]
        insights.append({
            "type": "WATCH",
            "icon": "👀",
            "title": f"{x['name']} is worth watching",
            "detail": x["reason"],
            "action": x["recommended_action"],
        })
    else:
        insights.append({
            "type": "NORMAL",
            "icon": "💚",
            "title": "Devices are operating normally",
            "detail": "Current reachable devices are within the device-health thresholds.",
            "action": "No action required. Continue normal monitoring.",
        })

    return {
        "phase": PNDCC_PHASE3C_VERSION,
        "version": PNDCC_V29_VERSION,
        "timestamp": base.get("timestamp") or now(),
        "overall": {
            "status": overall,
            "icon": overall_icon,
            "online": online_count,
            "total": len(health_rows),
            "healthy": len(healthy),
            "watch": len(watch),
            "problem": len(problem),
            "offline": len(health_rows) - online_count,
        },
        "insights": insights,
        "devices": health_rows,
        "network_health": (base.get("pulse") or {}).get("network_health") or {},
        "rules_note": "Device Health Intelligence interprets existing read-only reachability, latency and packet-loss measurements. It does not automatically change device or network state.",
    }


def _pndcc29_visual_page():
    body = r"""
    <style>
    .dh29{--bg:#07101f;--panel:#0e1a2d;--panel2:#101f35;--bd:#263b5b;--tx:#f4f8ff;--mu:#8fa5c5;--cyan:#43d9ff;--green:#42e6a4;--amber:#ffc857;--red:#ff5d78;--vio:#a678ff;color:var(--tx)}
    .dh29-hero{padding:25px;border:1px solid var(--bd);border-radius:25px;background:radial-gradient(circle at 90% 10%,rgba(67,217,255,.20),transparent 28%),radial-gradient(circle at 8% 100%,rgba(166,120,255,.18),transparent 33%),linear-gradient(135deg,#132640,#07101f 72%);box-shadow:0 20px 55px rgba(0,0,0,.28)}
    .dh29-brand{display:flex;align-items:center;gap:13px}.dh29-orb{width:50px;height:50px;border-radius:16px;display:grid;place-items:center;background:linear-gradient(145deg,#0e9bff,#805bff);font-size:24px;box-shadow:0 0 32px rgba(67,217,255,.30)}.dh29-title{font-size:27px;font-weight:950;letter-spacing:-.04em}.dh29-sub{font-size:12px;color:var(--mu);margin-top:3px}.dh29-live{display:inline-flex;gap:7px;align-items:center;margin-top:15px;padding:7px 11px;border-radius:999px;background:rgba(66,230,164,.08);border:1px solid rgba(66,230,164,.22);color:#baffdf;font-size:10px;font-weight:900;letter-spacing:.08em}.dh29-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 14px var(--green);animation:dh29pulse 1.8s infinite}@keyframes dh29pulse{50%{opacity:.4;transform:scale(.7)}}
    .dh29-hero-main{display:grid;grid-template-columns:1fr auto;gap:20px;align-items:center;margin-top:18px}.dh29-overline{font-size:10px;font-weight:900;color:var(--mu);letter-spacing:.15em}.dh29-overall{font-size:43px;font-weight:950;letter-spacing:-.05em;margin-top:5px}.dh29-overall small{font-size:20px;color:var(--mu);font-weight:800}.dh29-summary{font-size:12px;color:#c8d8ee;line-height:1.55;margin-top:7px;max-width:590px}.dh29-ring{width:138px;height:138px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--green) 0deg 300deg,rgba(255,255,255,.07) 300deg 360deg);position:relative}.dh29-ring:after{content:"";position:absolute;inset:9px;border-radius:50%;background:#0a1527;border:1px solid rgba(255,255,255,.08)}.dh29-ring-inner{position:relative;z-index:1;text-align:center}.dh29-ring-score{font-size:30px;font-weight:950}.dh29-ring-label{font-size:9px;color:var(--mu);font-weight:900;letter-spacing:.08em}
    .dh29-signal-wrap{display:flex;align-items:center;justify-content:center;gap:16px;margin-top:18px;padding:14px 16px;border:1px solid rgba(255,255,255,.09);border-radius:18px;background:linear-gradient(135deg,rgba(255,255,255,.035),rgba(0,0,0,.18))}.dh29-signal{display:flex;align-items:center;gap:12px;padding:10px 13px;border-radius:999px;background:#050b15;border:1px solid rgba(255,255,255,.08);box-shadow:inset 0 0 18px rgba(0,0,0,.38)}.dh29-light{width:30px;height:30px;border-radius:50%;display:block;opacity:.12;filter:saturate(.35);transition:opacity .25s ease,filter .25s ease,box-shadow .25s ease,transform .25s ease}.dh29-light.green{background:#42e6a4}.dh29-light.yellow{background:#ffc857}.dh29-light.red{background:#ff5d78}.dh29-light.active{opacity:1;filter:saturate(1);transform:scale(1.04)}.dh29-light.green.active{color:#42e6a4}.dh29-light.yellow.active{color:#ffc857}.dh29-light.red.active{color:#ff5d78}.dh29-light.active.level1{box-shadow:0 0 7px currentColor,0 0 15px currentColor;animation:dh29SignalLow 2.8s ease-in-out infinite}.dh29-light.active.level2{box-shadow:0 0 12px currentColor,0 0 25px currentColor,0 0 38px rgba(255,255,255,.08);animation:dh29SignalMedium 1.8s ease-in-out infinite}.dh29-light.active.level3{box-shadow:0 0 18px currentColor,0 0 34px currentColor,0 0 55px currentColor;animation:dh29SignalStrong 1.05s ease-in-out infinite}@keyframes dh29SignalLow{0%,100%{opacity:.62;transform:scale(1)}50%{opacity:1;transform:scale(1.05)}}@keyframes dh29SignalMedium{0%,100%{opacity:.48;transform:scale(1)}50%{opacity:1;transform:scale(1.08)}}@keyframes dh29SignalStrong{0%,100%{opacity:.32;transform:scale(1)}50%{opacity:1;transform:scale(1.11)}}.dh29-signal-copy{min-width:160px}.dh29-signal-label{font-size:11px;font-weight:950;letter-spacing:.12em}.dh29-signal-detail{font-size:9px;color:var(--mu);margin-top:3px;line-height:1.35}@media (prefers-reduced-motion:reduce){.dh29-light.active{animation:none!important}}
        .dh29-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-top:16px}.dh29-stat{padding:14px;border:1px solid rgba(255,255,255,.07);border-radius:16px;background:rgba(255,255,255,.025)}.dh29-stat-i{font-size:17px}.dh29-stat-l{font-size:9px;color:var(--mu);font-weight:900;letter-spacing:.1em;margin-top:7px}.dh29-stat-v{font-size:23px;font-weight:950;margin-top:2px}
    .dh29-sec{margin-top:18px}.dh29-panel{border:1px solid var(--bd);border-radius:21px;background:linear-gradient(145deg,#101e33,#0b1526);overflow:hidden;box-shadow:0 12px 34px rgba(0,0,0,.18)}.dh29-head{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:17px 18px 10px}.dh29-pt{font-size:14px;font-weight:900}.dh29-note{font-size:10px;color:var(--mu)}
    .dh29-insight{display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:center;margin:6px 14px 14px;padding:16px;border-radius:16px;background:linear-gradient(135deg,rgba(66,230,164,.09),rgba(67,217,255,.04));border:1px solid rgba(66,230,164,.18)}.dh29-insight-icon{font-size:27px}.dh29-insight-title{font-size:15px;font-weight:900}.dh29-insight-detail{font-size:11px;color:var(--mu);margin-top:4px;line-height:1.45}.dh29-insight-action{font-size:10px;color:#d7e7fb;text-align:right;max-width:220px}
    .dh29-grid{padding:5px 14px 17px;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:11px}.dh29-card{position:relative;overflow:hidden;padding:15px;border:1px solid rgba(255,255,255,.07);border-radius:18px;background:rgba(255,255,255,.025)}.dh29-card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--ac);box-shadow:0 0 16px var(--ac)}.dh29-card-top{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.dh29-device{display:flex;gap:10px;align-items:center;min-width:0}.dh29-device-icon{font-size:24px}.dh29-name{font-size:14px;font-weight:900;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.dh29-status{font-size:9px;font-weight:950;letter-spacing:.08em;margin-top:3px}.dh29-health-icon{font-size:18px}.dh29-metrics{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:15px}.dh29-metric{padding:9px 10px;border-radius:12px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.05)}.dh29-metric-l{display:block;font-size:8px;color:var(--mu);font-weight:900;letter-spacing:.08em}.dh29-metric-v{display:block;font-size:16px;font-weight:900;margin-top:3px}.dh29-recovery{margin-top:11px;padding:8px 9px;border-radius:10px;background:rgba(66,230,164,.07);border:1px solid rgba(66,230,164,.13);font-size:10px;color:#baffdf}.dh29-reason{margin-top:10px;font-size:10px;color:var(--mu);line-height:1.45}.dh29-spark{width:100%;height:42px;margin-top:9px}.dh29-action{margin-top:9px;font-size:10px;color:#d8e6f8}.dh29-empty{padding:18px;color:var(--mu);font-size:11px}
    .dh29-footer{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:16px;padding:0 3px;color:#7187a8;font-size:10px}.dh29-nav{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}.dh29-nav a{padding:9px 12px;border-radius:11px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);text-decoration:none}
    @media(max-width:820px){.dh29-hero-main{grid-template-columns:1fr}.dh29-ring{width:112px;height:112px}.dh29-stats{grid-template-columns:repeat(2,1fr)}.dh29-grid{grid-template-columns:1fr}.dh29-insight{grid-template-columns:auto 1fr}.dh29-insight-action{grid-column:2;text-align:left;max-width:none}}@media(max-width:520px){.dh29-title{font-size:21px}.dh29-overall{font-size:34px}.dh29-stats{grid-template-columns:1fr}.dh29-metrics{grid-template-columns:1fr 1fr}}
    </style>
    <div class='dh29'>
      <section class='dh29-hero'>
        <div class='dh29-brand'><div class='dh29-orb'>🩺</div><div><div class='dh29-title'>Device Health Intelligence</div><div class='dh29-sub'>Know which device needs attention — and whether it is recovering.</div></div></div>
        <div class='dh29-live'><span class='dh29-dot'></span> LIVE · PHASE 3C · v2.9</div>
        <div class='dh29-hero-main'><div><div class='dh29-overline'>OVERALL DEVICE HEALTH</div><div id='dh29-overall' class='dh29-overall'>—</div><div id='dh29-summary' class='dh29-summary'>Collecting the current device picture…</div></div><div id='dh29-ring' class='dh29-ring'><div class='dh29-ring-inner'><div id='dh29-ring-score' class='dh29-ring-score'>—</div><div class='dh29-ring-label'>HEALTHY</div></div></div></div>
        <div class='dh29-signal-wrap' aria-label='Overall device health traffic signal'><div class='dh29-signal' role='img' aria-label='Traffic signal: one active light communicates overall device health'><span id='dh29-signal-green' class='dh29-light green' aria-label='Healthy'></span><span id='dh29-signal-yellow' class='dh29-light yellow' aria-label='Watch'></span><span id='dh29-signal-red' class='dh29-light red' aria-label='Problem'></span></div><div class='dh29-signal-copy'><div id='dh29-signal-label' class='dh29-signal-label'>HEALTHY</div><div id='dh29-signal-detail' class='dh29-signal-detail'>Green active · low intensity · dynamic pulse</div></div></div>
        <div class='dh29-stats'><div class='dh29-stat'><div class='dh29-stat-i'>💚</div><div class='dh29-stat-l'>HEALTHY</div><div id='dh29-healthy' class='dh29-stat-v'>—</div></div><div class='dh29-stat'><div class='dh29-stat-i'>👀</div><div class='dh29-stat-l'>WATCH</div><div id='dh29-watch' class='dh29-stat-v'>—</div></div><div class='dh29-stat'><div class='dh29-stat-i'>🚨</div><div class='dh29-stat-l'>PROBLEM</div><div id='dh29-problem' class='dh29-stat-v'>—</div></div><div class='dh29-stat'><div class='dh29-stat-i'>⚪</div><div class='dh29-stat-l'>OFFLINE</div><div id='dh29-offline' class='dh29-stat-v'>—</div></div></div>
      </section>
      <section class='dh29-sec dh29-panel'><div class='dh29-head'><div class='dh29-pt'>💡 Device Health Insight</div><div class='dh29-note'>Interprets existing read-only measurements</div></div><div id='dh29-insights'></div></section>
      <section class='dh29-sec dh29-panel'><div class='dh29-head'><div class='dh29-pt'>🖥️ Device Health Map</div><div class='dh29-note'>Latency · packet loss · recovery</div></div><div id='dh29-devices' class='dh29-grid'><div class='dh29-empty'>Collecting device measurements…</div></div></section>
      <div class='dh29-footer'><span>🛡️ Read-only device intelligence · 5-second refresh · bounded history</span><span>© Saiful Quadir · PNDCC v2.9</span></div>
      <section class='dh29-nav'><a href='/'>← Dashboard</a><a href='/network-pulse'>Network Pulse →</a><a href='/decision-center'>Decision Center →</a><a href='/api/device-health'>JSON Device Health →</a></section>
    </div>
    <script>
    (function(){
      const $=id=>document.getElementById(id), num=v=>Number.isFinite(Number(v))?Number(v):null;
      const esc=v=>String(v??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
      function color(h){return h==='PROBLEM'?'#ff5d78':h==='WATCH'?'#ffc857':h==='OFFLINE'?'#7f8da6':'#42e6a4'}
      function setSignal(state, score){
        const lights={HEALTHY:$('dh29-signal-green'),WATCH:$('dh29-signal-yellow'),PROBLEM:$('dh29-signal-red')};
        Object.values(lights).forEach(el=>{if(el)el.classList.remove('active','level1','level2','level3')});
        const key=state==='ATTENTION'?'PROBLEM':(state==='WATCH'?'WATCH':'HEALTHY');
        const n=Number.isFinite(Number(score))?Number(score):0;
        const level=n>=90?1:(n>=70?2:3);
        const el=lights[key];
        if(el)el.classList.add('active','level'+level);
        const label=$('dh29-signal-label'),detail=$('dh29-signal-detail');
        const name=key==='HEALTHY'?'Green':key==='WATCH'?'Yellow':'Red';
        const intensity=level===1?'low':level===2?'medium':'strong';
        if(label)label.textContent=key;
        if(detail)detail.textContent=name+' active · '+intensity+' intensity · dynamic pulse';
      }
      function spark(rows,col){const vals=(rows||[]).map(x=>num(x.latency_ms));const clean=vals.filter(v=>v!=null);if(clean.length<2)return'<div style="color:#7187a8;font-size:9px">Collecting trend…</div>';const W=250,H=42,p=3,hi=Math.max(...clean,1),pts=vals.map((v,i)=>v==null?null:`${p+i/Math.max(vals.length-1,1)*(W-2*p)},${H-p-v/hi*(H-2*p)}`).filter(Boolean);return`<svg class="dh29-spark" viewBox="0 0 ${W} ${H}" role="img" aria-label="Device latency trend"><polyline points="${pts.join(' ')}" fill="none" stroke="${col}" stroke-width="2.7" stroke-linecap="round" stroke-linejoin="round"/></svg>`}
      function render(d){const o=d.overall||{},rows=d.devices||[],ins=d.insights||[];const active=rows.filter(x=>x.health!=='OFFLINE');const avg=active.map(x=>num(x.score)).filter(x=>x!=null);const score=avg.length?Math.round(avg.reduce((a,b)=>a+b,0)/avg.length):0;setSignal(o.status,score);$('dh29-overall').textContent=`${o.online||0} / ${o.total||0} REACHABLE`;$('dh29-summary').textContent=o.status==='EXCELLENT'?'All currently reachable devices are operating within normal device-health thresholds.':o.status==='WATCH'?'One or more devices show elevated latency or packet loss and deserve attention.':o.status==='ATTENTION'?'A reachable device is currently showing a significant performance issue.':'Device reachability is being monitored; offline devices are not automatically treated as failures.';$('dh29-healthy').textContent=o.healthy??0;$('dh29-watch').textContent=o.watch??0;$('dh29-problem').textContent=o.problem??0;$('dh29-offline').textContent=o.offline??0;$('dh29-ring-score').textContent=active.length?score:'—';const ring=active.length?Math.max(0,Math.min(360,score*3.6)):0;const ringColor=o.problem?'#ff5d78':o.watch?'#ffc857':'#42e6a4';$('dh29-ring').style.background=`conic-gradient(${ringColor} 0deg ${ring}deg,rgba(255,255,255,.07) ${ring}deg 360deg)`;$('dh29-ring').querySelector('.dh29-ring-label').textContent=o.status||'NORMAL';$('dh29-insights').innerHTML=ins.map(x=>`<div class="dh29-insight"><div class="dh29-insight-icon">${esc(x.icon)}</div><div><div class="dh29-insight-title">${esc(x.title)}</div><div class="dh29-insight-detail">${esc(x.detail)}</div></div><div class="dh29-insight-action">${esc(x.action)}</div></div>`).join('');$('dh29-devices').innerHTML=rows.length?rows.map(x=>{const col=color(x.health);const lat=x.latency_ms==null?'—':`${Number(x.latency_ms).toFixed(1)} ms`;const loss=x.packet_loss_pct==null?'—':`${Number(x.packet_loss_pct).toFixed(1)}%`;return`<article class="dh29-card" style="--ac:${col}"><div class="dh29-card-top"><div class="dh29-device"><div class="dh29-device-icon">${esc(x.icon)}</div><div><div class="dh29-name">${esc(x.name)}</div><div class="dh29-status" style="color:${col}">${esc(x.health_icon)} ${esc(x.health)}</div></div></div><div class="dh29-health-icon">${esc(x.health_icon)}</div></div><div class="dh29-metrics"><div class="dh29-metric"><span class="dh29-metric-l">LATENCY</span><span class="dh29-metric-v">${esc(lat)}</span></div><div class="dh29-metric"><span class="dh29-metric-l">PACKET LOSS</span><span class="dh29-metric-v">${esc(loss)}</span></div></div>${x.recovered?`<div class="dh29-recovery">🔄 ${esc(x.recovery)}</div>`:''}<div class="dh29-reason">${esc(x.reason)}</div>${spark(x.history,col)}<div class="dh29-action"><b>Recommended:</b> ${esc(x.recommended_action)}</div></article>`}).join(''):'<div class="dh29-empty">No device snapshot available.</div>'}
      async function refresh(){try{const r=await fetch('/api/device-health',{cache:'no-store'});if(!r.ok)throw Error(r.status);render(await r.json())}catch(e){$('dh29-summary').textContent='Device Health temporarily unavailable.'}}refresh();setInterval(refresh,5000);
    })();
    </script>
    """
    return page_shell("PNDCC v2.9 · Device Health Intelligence", body).replace("Version 2.6.3", "Version 2.9").replace("PNDCC v2.6.3</footer>", "PNDCC v2.9</footer>")


_PNDCC29_OLD_GET = H.do_GET

def _pndcc29_get(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path == "/api/device-health":
        try:
            _json_response(self, _pndcc29_snapshot())
        except Exception as e:
            self._send_text(500, "Device Health API failed: " + type(e).__name__)
        return
    if parsed.path == "/device-health":
        data = _pndcc29_visual_page().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        return
    return _PNDCC29_OLD_GET(self)

H.do_GET = _pndcc29_get

# ============================================================================
# PNDCC v2.9.1 — Stability & Recovery Intelligence
# Additive refinement on top of frozen/validated v2.9.
# Purpose: prevent device-health flicker from isolated Wi-Fi latency spikes.
# Policy: current measurements remain source-of-truth; status changes require
# short-term persistence, while recovery requires consecutive healthy samples.
# ============================================================================
PNDCC_V291_VERSION = "2.9.1"
PNDCC_V291_UPDATED = "2026-10-08 Phase 3C Stability & Recovery Intelligence"
_PNDCC291_WINDOW = 3
_PNDCC291_REQUIRED_BAD = 2
_PNDCC291_REQUIRED_RECOVERY = 2


def _pndcc291_classify(device, history):
    name = device.get("name") or device.get("id") or "Device"
    status = str(device.get("status") or "UNKNOWN").upper()
    latency = _pndcc29_num(device.get("latency_ms"))
    loss = _pndcc29_num(device.get("packet_loss_pct"))
    series = _pndcc29_history_for_device(history, device.get("id"))

    if "OFFLINE" in status or latency is None:
        return {
            "id": device.get("id"), "name": name,
            "icon": _pndcc29_device_icon(name), "status": status,
            "health": "OFFLINE", "health_icon": "⚪", "score": None,
            "latency_ms": latency, "packet_loss_pct": loss,
            "reason": "Network reachability is currently unavailable.",
            "recommended_action": "No action unless you expected this device to be connected.",
            "recovered": False, "recovery": "", "history": series,
            "stability": {"state": "OFFLINE", "recent_samples": 0,
                           "elevated_samples": 0, "severe_samples": 0,
                           "healthy_samples": 0, "persistent": False},
        }

    # Preserve the original v2.9 score calculation exactly.
    score = 100.0
    if latency >= 300:
        score -= 65
    elif latency >= 150:
        score -= 40
    elif latency >= 100:
        score -= 25
    elif latency >= 50:
        score -= 10
    if loss is not None:
        if loss >= 50:
            score -= 45
        elif loss >= 10:
            score -= 30
        elif loss >= 2:
            score -= 15
    score = max(0, min(100, round(score)))

    def severity(lat, pkt):
        if lat is None:
            return "UNKNOWN"
        if (lat >= 300) or (pkt is not None and pkt >= 50):
            return "SEVERE"
        if (lat >= 100) or (pkt is not None and pkt >= 2):
            return "ELEVATED"
        return "HEALTHY"

    current_severity = severity(latency, loss)
    recent = []
    for row in series[-_PNDCC291_WINDOW:]:
        rlat = _pndcc29_num(row.get("latency_ms"))
        rloss = _pndcc29_num(row.get("packet_loss_pct"))
        sev = severity(rlat, rloss)
        if sev != "UNKNOWN":
            recent.append(sev)
    if not recent or recent[-1] != current_severity:
        recent.append(current_severity)
    recent = recent[-_PNDCC291_WINDOW:]

    elevated_count = sum(x == "ELEVATED" for x in recent)
    severe_count = sum(x == "SEVERE" for x in recent)
    healthy_count = sum(x == "HEALTHY" for x in recent)
    bad_count = elevated_count + severe_count

    # Stability rules:
    # - One isolated severe sample is WATCH, not immediate PROBLEM.
    # - Two bad samples in the recent window make the condition persistent.
    # - Two consecutive healthy samples are required to declare recovery.
    if current_severity == "SEVERE":
        if severe_count >= _PNDCC291_REQUIRED_BAD or bad_count >= _PNDCC291_REQUIRED_BAD:
            health, icon = "PROBLEM", "🔴"
            persistent = True
        else:
            health, icon = "WATCH", "🟡"
            persistent = False
    elif current_severity == "ELEVATED":
        if bad_count >= _PNDCC291_REQUIRED_BAD:
            health, icon = "WATCH", "🟡"
            persistent = True
        else:
            # A single elevated reading is treated as a transient condition.
            health, icon = "HEALTHY", "🟢"
            persistent = False
    else:
        # If a device is recovering from recent trouble, hold WATCH for one
        # healthy sample so the UI does not oscillate immediately.
        recent_tail = recent[-_PNDCC291_REQUIRED_RECOVERY:]
        recovery_pending = any(x in ("ELEVATED", "SEVERE") for x in recent_tail[:-1])
        if recovery_pending and healthy_count < _PNDCC291_REQUIRED_RECOVERY:
            health, icon = "WATCH", "🟡"
        else:
            health, icon = "HEALTHY", "🟢"
        persistent = False

    if latency >= 300:
        raw_reason = f"Very high device latency: {latency:.1f} ms."
        raw_action = "Check the device's Wi-Fi state and retest."
    elif latency >= 100:
        raw_reason = f"Elevated device latency: {latency:.1f} ms."
        raw_action = "Monitor the device and retest if the elevation persists."
    elif loss is not None and loss >= 2:
        raw_reason = f"Packet loss is elevated at {loss:.1f}%."
        raw_action = "Check Wi-Fi conditions and retest."
    else:
        raw_reason = "Current reachability and latency are within the normal range."
        raw_action = "No action required. Continue normal monitoring."

    recovered = False
    recovery_text = ""
    prior_health = [x for x in recent[:-1] if x in ("ELEVATED", "SEVERE")]
    if current_severity == "HEALTHY" and prior_health and health == "HEALTHY":
        prev_bad = next((r for r in reversed(series[:-1]) if _pndcc29_num(r.get("latency_ms")) is not None), None)
        prev_lat = _pndcc29_num(prev_bad.get("latency_ms")) if prev_bad else None
        if prev_lat is not None and prev_lat >= 100:
            recovered = True
            recovery_text = f"Recovered after elevated latency: {prev_lat:.0f} ms → {latency:.0f} ms."
    elif current_severity == "HEALTHY" and prior_health:
        recovery_text = "Improving — one more healthy sample is needed to confirm recovery."

    if health == "PROBLEM":
        reason = raw_reason + " Persistent across recent measurements."
        action = raw_action
    elif health == "WATCH" and current_severity == "SEVERE":
        if persistent:
            reason = raw_reason + " Persistent across recent measurements."
            action = raw_action
        else:
            reason = raw_reason + " Isolated spike; stability confirmation is in progress."
            action = "Retest before taking action unless the problem persists."
    elif health == "WATCH" and current_severity == "ELEVATED":
        reason = raw_reason + " Elevated across recent measurements."
        action = raw_action
    elif health == "WATCH" and current_severity == "HEALTHY":
        reason = recovery_text or "Latency has improved; recovery confirmation is in progress."
        action = "Continue monitoring; two consecutive healthy samples confirm recovery."
    else:
        reason = "Current reachability and latency are within the normal range."
        action = "No action required. Continue normal monitoring."

    return {
        "id": device.get("id"), "name": name,
        "icon": _pndcc29_device_icon(name), "status": status,
        "health": health, "health_icon": icon, "score": score,
        "latency_ms": latency, "packet_loss_pct": loss,
        "reason": reason, "recommended_action": action,
        "recovered": recovered, "recovery": recovery_text,
        "history": series,
        "stability": {
            "state": "PERSISTENT" if persistent else ("RECOVERING" if health == "WATCH" and current_severity == "HEALTHY" else "STABLE"),
            "recent_samples": len(recent),
            "elevated_samples": elevated_count,
            "severe_samples": severe_count,
            "healthy_samples": healthy_count,
            "persistent": persistent,
        },
    }


def _pndcc291_snapshot():
    base = _pndcc27_payload()
    devices = base.get("devices") or []
    history = base.get("history") or []
    health_rows = [_pndcc291_classify(d, history) for d in devices if isinstance(d, dict)]
    active = [x for x in health_rows if x["health"] != "OFFLINE"]
    healthy = [x for x in active if x["health"] == "HEALTHY"]
    watch = [x for x in active if x["health"] == "WATCH"]
    problem = [x for x in active if x["health"] == "PROBLEM"]
    online_count = len(active)

    if problem:
        overall, overall_icon = "ATTENTION", "🔴"
    elif watch:
        overall, overall_icon = "WATCH", "🟡"
    elif active and len(healthy) == len(active):
        overall, overall_icon = "EXCELLENT", "🟢"
    else:
        overall, overall_icon = "NORMAL", "🟢"

    recovered = [x for x in health_rows if x.get("recovered")]
    recovering = [x for x in health_rows if x.get("stability", {}).get("state") == "RECOVERING"]
    persistent = [x for x in health_rows if x.get("stability", {}).get("persistent")]
    insights = []
    if recovered:
        x = recovered[0]
        insights.append({"type":"RECOVERY","icon":"🔄","title":f"{x['name']} recovery confirmed","detail":x.get("recovery") or "Device health has returned to normal.","action":"Continue normal monitoring."})
    elif recovering:
        x = recovering[0]
        insights.append({"type":"RECOVERY","icon":"🔄","title":f"{x['name']} is recovering","detail":x.get("reason") or "The latest reading is healthy after recent elevation.","action":x.get("recommended_action") or "Continue monitoring."})
    elif problem:
        x = problem[0]
        insights.append({"type":"PROBLEM","icon":"🚨","title":f"{x['name']} needs attention","detail":x["reason"],"action":x["recommended_action"]})
    elif watch:
        x = watch[0]
        insights.append({"type":"WATCH","icon":"👀","title":f"{x['name']} is worth watching","detail":x["reason"],"action":x["recommended_action"]})
    else:
        insights.append({"type":"NORMAL","icon":"💚","title":"Devices are operating normally","detail":"Current reachable devices are within the device-health thresholds.","action":"No action required. Continue normal monitoring."})

    return {
        "phase": PNDCC_PHASE3C_VERSION,
        "version": PNDCC_V291_VERSION,
        "timestamp": base.get("timestamp") or now(),
        "overall": {"status": overall, "icon": overall_icon, "online": online_count, "total": len(health_rows), "healthy": len(healthy), "watch": len(watch), "problem": len(problem), "offline": len(health_rows)-online_count},
        "insights": insights,
        "devices": health_rows,
        "network_health": (base.get("pulse") or {}).get("network_health") or {},
        "stability_policy": {"window_samples": _PNDCC291_WINDOW, "required_bad_samples": _PNDCC291_REQUIRED_BAD, "required_recovery_samples": _PNDCC291_REQUIRED_RECOVERY, "persistent_conditions": len(persistent)},
        "rules_note": "v2.9.1 keeps isolated latency spikes from immediately changing health state. Persistent trouble requires short-term confirmation; recovery requires consecutive healthy samples. Existing read-only measurements remain the source of truth.",
    }

# Override only the Phase 3C decision layer; underlying measurements remain untouched.
_pndcc29_classify = _pndcc291_classify
_pndcc29_snapshot = _pndcc291_snapshot
_PNDCC29_OLD_VISUAL_PAGE = _pndcc29_visual_page

def _pndcc291_visual_page():
    return (_PNDCC29_OLD_VISUAL_PAGE()
            .replace("LIVE · PHASE 3C · v2.9</div>", "LIVE · PHASE 3C · v2.9.1 · STABILITY</div>")
            .replace("© Saiful Quadir · PNDCC v2.9</span>", "© Saiful Quadir · PNDCC v2.9.1</span>")
            .replace("Latency · packet loss · recovery", "Latency · persistence · recovery"))

_pndcc29_visual_page = _pndcc291_visual_page
PNDCC_V29_VERSION = "2.9.6"  # final build label; earlier v2.9.1 compatibility layer remains intact
PNDCC_V29_UPDATED = PNDCC_V291_UPDATED
PNDCC_VERSION = PNDCC_V291_VERSION
PNDCC_UPDATED = PNDCC_V291_UPDATED


# Restored v2.7.1 IP-resilience helper dependencies from the locked source.
PNDCC_V27_PROTOTYPE = True
PNDCC_V27_VERSION = "2.7.1-FINAL"
PNDCC_V27_POLICY = "CURRENT_LOCAL_LAN_ONLY"


def _v27_norm_identity(value):
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")


def _v27_local_network():
    """Return active LAN context without changing any PNDCC state."""
    route_out, _, _ = _run_cmd(["/sbin/route", "-n", "get", "default"], timeout=3)
    iface_m = re.search(r"interface:\s*(\S+)", route_out or "")
    iface = iface_m.group(1) if iface_m else "en0"
    ifconfig_out, _, _ = _run_cmd(["/sbin/ifconfig", iface], timeout=3)
    ip_m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", ifconfig_out or "")
    if not ip_m:
        return {"interface": iface, "ip": None, "netmask": None, "network": None}
    ip = ip_m.group(1)
    mask_raw = ip_m.group(2)
    try:
        if str(mask_raw).lower().startswith("0x"):
            mask_raw = str(ipaddress.IPv4Address(int(str(mask_raw), 16)))
        net = ipaddress.IPv4Network(f"{ip}/{mask_raw}", strict=False)
        return {"interface": iface, "ip": ip, "netmask": str(net.netmask), "network": str(net)}
    except Exception:
        return {"interface": iface, "ip": ip, "netmask": mask_raw, "network": None}


def _v27_same_network(ip, network):
    try:
        return bool(network and ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False))
    except Exception:
        return False


def _v27_arp_entries():
    out, _, _ = _run_cmd(["/usr/sbin/arp", "-a"], timeout=3)
    entries = {}
    for line in (out or "").splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+|<incomplete>)", line)
        if not m or m.group(2).lower() == "<incomplete>":
            continue
        entries[m.group(1)] = m.group(2).lower()
    return entries


def _v27_reverse_identity(ip):
    out, _, rc = _run_cmd(["/usr/bin/dig", "+short", "-x", ip], timeout=3)
    if rc == 0:
        for line in (out or "").splitlines():
            value = line.strip().rstrip(".")
            if value:
                return _v27_norm_identity(value)
    out, _, rc = _run_cmd(["/usr/bin/host", ip], timeout=3)
    if rc == 0:
        m = re.search(r"pointer\s+([^\s.]+(?:\.[^\s.]+)*)\.?$", out or "", re.I)
        if m:
            return _v27_norm_identity(m.group(1))
    return ""


def _v27_ping(ip):
    out, _, rc = _run_cmd(["/sbin/ping", "-c", "1", "-W", "1000", ip], timeout=3)
    return rc == 0 and "100.0% packet loss" not in (out or "")


def _v27_device_identity(device):
    identity = device.get("identity") or device.get("hostname") or device.get("id") or device.get("name")
    return _v27_norm_identity(identity)


def _v27_identity_matches(target_identity, ip):
    if not target_identity:
        return False
    discovered = _v27_reverse_identity(ip)
    return bool(discovered and discovered == target_identity)


_PNDCC_V27_DISCOVERY_CACHE = {"timestamp": 0.0, "network": None, "ips": set()}
_PNDCC_V27_DISCOVERY_LOCK = Lock()
_PNDCC_V27_DISCOVERY_CACHE_SECONDS = 30.0


def _v27_auto_discover_local_ips(local):
    """Automatically discover live IPv4 hosts on the current LAN (read-only)."""
    network_text = local.get("network") if isinstance(local, dict) else None
    if not network_text:
        return set()
    with _PNDCC_V27_DISCOVERY_LOCK:
        now_ts = time.time()
        if (_PNDCC_V27_DISCOVERY_CACHE.get("network") == network_text
                and now_ts - _PNDCC_V27_DISCOVERY_CACHE.get("timestamp", 0.0) < _PNDCC_V27_DISCOVERY_CACHE_SECONDS):
            return set(_PNDCC_V27_DISCOVERY_CACHE.get("ips", set()))

    try:
        net = ipaddress.ip_network(network_text, strict=False)
        targets = [str(ip) for ip in net.hosts()]
    except Exception:
        return set()

    discovered = set()
    # Start with the ARP table, then actively probe the remaining LAN addresses.
    arp = _v27_arp_entries()
    discovered.update(arp.keys())
    local_ip = local.get("ip")
    if local_ip:
        discovered.add(local_ip)
    targets = [ip for ip in targets if ip != local_ip and ip not in discovered]

    def probe(ip):
        out, _, rc = _run_cmd(["/sbin/ping", "-c", "1", "-W", "250", ip], timeout=1.5)
        return ip if rc == 0 and "100.0% packet loss" not in (out or "") else None

    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = [pool.submit(probe, ip) for ip in targets]
        for future in as_completed(futures):
            try:
                hit = future.result()
            except Exception:
                hit = None
            if hit:
                discovered.add(hit)

    # Refresh ARP after the sweep; some hosts answer through ARP without ICMP.
    discovered.update(_v27_arp_entries().keys())
    if network_text:
        discovered = {ip for ip in discovered if _v27_same_network(ip, network_text)}

    with _PNDCC_V27_DISCOVERY_LOCK:
        _PNDCC_V27_DISCOVERY_CACHE.update({
            "timestamp": time.time(),
            "network": network_text,
            "ips": set(discovered),
        })
    return discovered


def _v27_identity_recovery_snapshot(extra_candidates=None):
    local = _v27_local_network()
    network = local.get("network")
    arp = _v27_arp_entries()
    discovered = _v27_auto_discover_local_ips(local)
    candidates = set(extra_candidates or [])
    candidates.update(arp.keys())
    candidates.update(discovered)
    if network:
        candidates = {ip for ip in candidates if _v27_same_network(ip, network)}
    result = []
    for device in personal_devices():
        stored_ip = str(device.get("ip") or "").strip()
        identity = _v27_device_identity(device)
        stored_reachable = bool(stored_ip and _v27_ping(stored_ip))
        matches = []
        if stored_reachable:
            if identity and _v27_identity_matches(identity, stored_ip):
                matches = [stored_ip]
            status = "CONFIRMED"
        else:
            for ip in sorted(candidates, key=lambda x: tuple(int(p) for p in x.split(".")) if re.fullmatch(r"\d+(?:\.\d+){3}", x) else (999,999,999,999)):
                if ip == stored_ip or not _v27_same_network(ip, network):
                    continue
                if not _v27_ping(ip):
                    continue
                if _v27_identity_matches(identity, ip):
                    matches.append(ip)
            if len(matches) == 1:
                status = "RECOVERED — SAFE CANDIDATE"
            elif len(matches) > 1:
                status = "AMBIGUOUS — DO NOT RECOVER"
            else:
                status = "NO RECOVERY"
        result.append({
            "name": device.get("name", "Device"),
            "stored_ip": stored_ip,
            "identity": identity,
            "stored_reachable": stored_reachable,
            "candidate_ips": matches,
            "status": status,
            "safe_to_auto_reassign": False,
        })
    return {
        "prototype": PNDCC_V27_VERSION,
        "policy": PNDCC_V27_POLICY,
        "timestamp": now(),
        "local_network": local,
        "automatic_discovery": {
            "enabled": True,
            "method": "ARP + local-subnet ping sweep",
            "cache_seconds": _PNDCC_V27_DISCOVERY_CACHE_SECONDS,
            "discovered_ips": sorted(discovered, key=lambda x: tuple(int(p) for p in x.split("."))),
        },
        "devices": result,
        "external_candidates": [
            {"ip": ip, "classification": "DIFFERENT NETWORK — DO NOT RECOVER"}
            for ip in sorted(set(extra_candidates or []))
            if network and not _v27_same_network(ip, network)
        ],
        "safety": {
            "config_modified": False,
            "persistent_ip_changed": False,
            "identity_reassigned": False,
            "automatic_recovery_performed": False,
        },
    }



# PNDCC v2.7.2 IP Resilience integration layer (preserved from locked build)
PNDCC_V272_VERSION = "2.7.2"
PNDCC_V272_POLICY = "RUNTIME_ONLY_CONFIDENCE_GATED"
PNDCC_V272_CACHE_SECONDS = 30.0
PNDCC_V272_IDENTITY_CACHE_FILE = os.path.join(BASE, "data", "ip_identity_cache.json")
_PNDCC_V272_LOCK = Lock()
_PNDCC_V272_SNAPSHOT = {"timestamp": 0.0, "data": None}
_PNDCC_V272_RUNTIME_IPS = {}
_PNDCC_V272_IDENTITY_CACHE = {}


def _v272_norm(value):
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")


def _v272_tokens(value):
    value = _v272_norm(value)
    return [x for x in value.split("-") if len(x) >= 3]


def _v272_local_mac(interface):
    out, _, _ = _run_cmd(["/sbin/ifconfig", str(interface)], timeout=3)
    m = re.search(r"\bether\s+([0-9a-fA-F:]{17})", out or "")
    return m.group(1).lower() if m else ""


def _v272_arp_mac(ip, arp=None):
    arp = arp or {}
    mac = str(arp.get(ip) or "").lower()
    if mac and mac != "<incomplete>":
        return mac
    out, _, _ = _run_cmd(["/usr/sbin/arp", "-n", str(ip)], timeout=2)
    m = re.search(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b", out or "")
    return m.group(1).lower() if m else ""


def _v272_hostname(ip):
    raw = ""
    out, _, rc = _run_cmd(["/usr/bin/dig", "+short", "-x", str(ip)], timeout=2)
    if rc == 0:
        for line in (out or "").splitlines():
            value = line.strip().rstrip(".")
            if value:
                raw = value
                break
    if not raw:
        out, _, rc = _run_cmd(["/usr/bin/host", str(ip)], timeout=2)
        if rc == 0:
            m = re.search(r"pointer\s+([^\s]+)\.?$", out or "", re.I)
            if m:
                raw = m.group(1).rstrip(".")
    return {"raw": raw, "norm": _v272_norm(raw)}


def _v272_load_identity_cache():
    global _PNDCC_V272_IDENTITY_CACHE
    try:
        with open(PNDCC_V272_IDENTITY_CACHE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _PNDCC_V272_IDENTITY_CACHE = data
    except (OSError, ValueError, TypeError):
        _PNDCC_V272_IDENTITY_CACHE = {}


def _v272_save_identity_cache():
    try:
        os.makedirs(os.path.dirname(PNDCC_V272_IDENTITY_CACHE_FILE), exist_ok=True)
        tmp = PNDCC_V272_IDENTITY_CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_PNDCC_V272_IDENTITY_CACHE, f, indent=2, sort_keys=True)
        os.replace(tmp, PNDCC_V272_IDENTITY_CACHE_FILE)
    except OSError:
        pass


_v272_load_identity_cache()


def _v272_collect_mdns():
    """Best-effort mDNS service browse; supporting evidence only."""
    services = ["_airplay._tcp", "_companion-link._tcp"]
    result = {}
    for service in services:
        out, _, rc = _run_cmd(["/usr/bin/dns-sd", "-B", service, "local."], timeout=4)
        if rc != 0 and not out:
            continue
        instances = []
        for line in (out or "").splitlines():
            if " Add " not in line and " Add   " not in line:
                continue
            parts = line.split()
            if len(parts) >= 7:
                name = " ".join(parts[6:]).strip()
                if name and name not in instances:
                    instances.append(name)
        if instances:
            result[service] = instances[:20]
    return result


def _v272_mdns_supports(device_name, mdns):
    tokens = set(_v272_tokens(device_name))
    if not tokens:
        return False
    for instances in (mdns or {}).values():
        for name in instances:
            norm = _v272_norm(name)
            if all(tok in norm for tok in tokens if tok not in {"lite", "5g"}):
                return True
    return False


def _v272_identity_record(device, ip, mac, hostname, mdns, local_ip, local_mac):
    name = str(device.get("name") or "Device")
    identity = _v272_norm(device.get("identity") or device.get("id") or name)
    key = str(device.get("id") or identity or name)
    prior = _PNDCC_V272_IDENTITY_CACHE.get(key, {}) if isinstance(_PNDCC_V272_IDENTITY_CACHE, dict) else {}
    macs = set(str(x).lower() for x in prior.get("macs", []) if x)
    hosts = set(str(x) for x in prior.get("hostnames", []) if x)
    if mac:
        macs.add(mac.lower())
    if hostname.get("norm"):
        hosts.add(hostname["norm"])
    _PNDCC_V272_IDENTITY_CACHE[key] = {
        "name": name,
        "identity": identity,
        "macs": sorted(macs),
        "hostnames": sorted(hosts),
        "last_seen": now(),
    }
    return {"macs": macs, "hostnames": hosts, "identity": identity}


def _v272_is_local_device(device, local_hostname_norm):
    """Return True only when the configured device identity matches this Mac's hostname."""
    name = _v272_norm(device.get("name") or "")
    identity = _v272_norm(device.get("identity") or device.get("id") or "")
    compact = lambda value: re.sub(r"[^a-z0-9]", "", str(value or "").lower())
    local_compact = compact(local_hostname_norm)
    if not local_compact:
        return False
    return any(value and compact(value) == local_compact for value in (name, identity))


def _v272_clean_hostname(raw, mac):
    """Reject MAC-looking hostnames; they are not useful identity evidence."""
    norm = _v272_norm(raw)
    mac_norm = _v272_norm(mac)
    if norm and mac_norm and norm == mac_norm:
        return {"raw": "", "norm": ""}
    return {"raw": raw or "", "norm": norm}


def _v272_score(device, ip, mac, hostname, identity_record, mdns, local_ip, local_mac, stored_reachable, local_device=False):
    name = str(device.get("name") or "Device")
    identity = identity_record.get("identity", "")
    learned_macs = identity_record.get("macs", set())
    learned_hosts = identity_record.get("hostnames", set())
    score = 0
    evidence = []

    # The local interface MAC/IP is identity evidence for the Mac running PNDCC
    # only. It must never be reusable as evidence for another configured device.
    if stored_reachable and ip == str(device.get("ip") or "").strip():
        score += 40
        evidence.append("stored-IP-reachable")
    if local_device and ip == local_ip and local_mac and mac and mac == local_mac.lower():
        score += 90
        evidence.append("local-interface-IP")
        evidence.append("MAC-match")
    elif (not local_device) and mac and mac.lower() == local_mac.lower():
        # Never use the PNDCC host's own MAC as identity evidence for a remote device.
        pass
    elif mac and mac.lower() in learned_macs:
        score += 90
        evidence.append("MAC-match")
    if hostname.get("norm"):
        if hostname["norm"] in learned_hosts:
            score += 25
            evidence.append("learned-hostname-match")
        name_tokens = [t for t in _v272_tokens(name) if t not in {"the", "5g"}]
        if name_tokens and all(t in hostname["norm"] for t in name_tokens):
            score += 25
            evidence.append("hostname-identity-match")
        elif identity and identity in hostname["norm"]:
            score += 25
            evidence.append("hostname-match")
        elif _v272_norm(name) and _v272_norm(name) in hostname["norm"]:
            score += 25
            evidence.append("hostname-name-match")
    # Local IP alone is not identity evidence for remote devices.
    if local_device and ip == local_ip and "local-interface-IP" not in evidence:
        score += 5
        evidence.append("local-IP")
    return min(100, score), evidence


def _v272_snapshot(force=False):
    global _PNDCC_V272_SNAPSHOT, _PNDCC_V272_RUNTIME_IPS
    with _PNDCC_V272_LOCK:
        if (not force and _PNDCC_V272_SNAPSHOT.get("data") is not None
                and time.time() - float(_PNDCC_V272_SNAPSHOT.get("timestamp", 0)) < PNDCC_V272_CACHE_SECONDS):
            return _PNDCC_V272_SNAPSHOT["data"]

    local = _v27_local_network()
    network = local.get("network")
    local_ip = local.get("ip") or ""
    local_mac = _v272_local_mac(local.get("interface", "en0"))
    local_hostname = socket.gethostname()
    local_hostname_norm = _v272_norm(local_hostname)
    discovered = _v27_auto_discover_local_ips(local)
    if network:
        try:
            net_obj = ipaddress.ip_network(network, strict=False)
            discovered = {ip for ip in discovered if ipaddress.ip_address(ip) not in {net_obj.network_address, net_obj.broadcast_address}}
        except Exception:
            pass
    arp = _v27_arp_entries()
    for ip in list(discovered):
        if ip == local_ip:
            arp[ip] = local_mac or arp.get(ip, "")
        elif ip not in arp:
            mac = _v272_arp_mac(ip, arp)
            if mac:
                arp[ip] = mac

    mdns = _v272_collect_mdns()
    personal = personal_devices()

    # Safety cleanup: a local-interface MAC may identify this Mac only.
    # Remove any stale accidental association of the local MAC with remote devices
    # that could have been learned by an earlier buggy trial/build.
    if local_mac and isinstance(_PNDCC_V272_IDENTITY_CACHE, dict):
        for device in personal:
            if _v272_is_local_device(device, local_hostname_norm):
                continue
            key = str(device.get("id") or _v272_norm(device.get("name")))
            prior = _PNDCC_V272_IDENTITY_CACHE.get(key)
            if isinstance(prior, dict):
                old_macs = list(prior.get("macs", []) or [])
                clean_macs = [m for m in old_macs if str(m).lower() != local_mac.lower()]
                if clean_macs != old_macs:
                    prior["macs"] = clean_macs
                    _PNDCC_V272_IDENTITY_CACHE[key] = prior

    records = []
    runtime_ips = {}
    cache_changed = False

    # First learn strong identity evidence from devices currently reachable at
    # their configured address. This makes later IP changes recoverable without
    # requiring manual MAC entry.
    for device in personal:
        stored_ip = str(device.get("ip") or "").strip()
        if not stored_ip or not _v27_same_network(stored_ip, network):
            continue
        reachable = bool(_v27_ping(stored_ip))
        if not reachable and stored_ip == local_ip:
            reachable = True
        if reachable:
            mac = arp.get(stored_ip) or _v272_arp_mac(stored_ip, arp)
            if stored_ip == local_ip and local_mac:
                mac = local_mac
            host = _v272_hostname(stored_ip) if stored_ip != local_ip else {"raw": local_hostname, "norm": local_hostname_norm}
            host = _v272_clean_hostname(host.get("raw", ""), mac)
            key = str(device.get("id") or _v272_norm(device.get("name")))
            before = json.dumps(_PNDCC_V272_IDENTITY_CACHE.get(key, {}), sort_keys=True)
            rec = _v272_identity_record(device, stored_ip, mac, host, mdns, local_ip, local_mac)
            after = json.dumps(_PNDCC_V272_IDENTITY_CACHE.get(key, {}), sort_keys=True)
            cache_changed |= before != after

    # Evaluate every configured device independently. All six remain visible.
    for device in personal:
        stored_ip = str(device.get("ip") or "").strip()
        key = str(device.get("id") or _v272_norm(device.get("name")))
        prior = _PNDCC_V272_IDENTITY_CACHE.get(key, {}) if isinstance(_PNDCC_V272_IDENTITY_CACHE, dict) else {}
        identity = _v272_norm(device.get("identity") or device.get("id") or device.get("name"))
        local_device = _v272_is_local_device(device, local_hostname_norm)
        learned_macs = set(str(x).lower() for x in prior.get("macs", []) if x)
        learned_hosts = set(str(x) for x in prior.get("hostnames", []) if x)
        stored_reachable = bool(stored_ip and _v27_ping(stored_ip))
        if stored_ip == local_ip:
            stored_reachable = True

        best = None
        best_score = -1
        best_evidence = []
        best_mac = ""
        candidate_details = []
        weak_identity = False

        # Always evaluate the stored address first.
        if stored_ip:
            stored_mac = local_mac if stored_ip == local_ip else (arp.get(stored_ip) or _v272_arp_mac(stored_ip, arp))
            stored_host = _v272_hostname(stored_ip) if stored_reachable and stored_ip != local_ip else ({"raw":local_hostname,"norm":local_hostname_norm} if stored_ip == local_ip else {"raw":"","norm":""})
            stored_host = _v272_clean_hostname(stored_host.get("raw", ""), stored_mac)
            score, evidence = _v272_score(device, stored_ip, stored_mac, stored_host,
                                           {"identity": identity, "macs": learned_macs, "hostnames": learned_hosts},
                                           mdns, local_ip, local_mac, stored_reachable, local_device=local_device)
            if stored_reachable:
                if not stored_mac:
                    score = min(score, 55)
                    weak_identity = True
                    if "weak-identity" not in evidence:
                        evidence.append("weak-identity")
                best = stored_ip
                best_score = score
                best_evidence = evidence
                best_mac = stored_mac
                candidate_details.append({"ip": stored_ip, "score": score, "evidence": evidence, "mac": stored_mac})

        # Search discovered local candidates when the stored IP is offline.
        if not stored_reachable:
            for ip in sorted(discovered, key=lambda x: tuple(int(p) for p in x.split("."))):
                if not _v27_same_network(ip, network):
                    continue
                if ip == stored_ip:
                    continue
                if not _v27_ping(ip):
                    continue
                mac = local_mac if ip == local_ip else (arp.get(ip) or _v272_arp_mac(ip, arp))
                host = {"raw":local_hostname,"norm":local_hostname_norm} if (ip == local_ip and local_device) else _v272_hostname(ip)
                host = _v272_clean_hostname(host.get("raw", ""), mac)
                score, evidence = _v272_score(device, ip, mac, host,
                                               {"identity": identity, "macs": learned_macs, "hostnames": learned_hosts},
                                               mdns, local_ip, local_mac, False, local_device=local_device)
                if score >= 40:
                    candidate_details.append({"ip": ip, "score": score, "evidence": evidence, "mac": mac})
                if score > best_score:
                    best, best_score, best_evidence, best_mac = ip, score, evidence, mac

        candidate_details = sorted(candidate_details, key=lambda x: (-int(x.get("score",0)), x.get("ip", "")))
        high = [x for x in candidate_details if int(x.get("score", 0)) >= 90]
        same_top = [x for x in candidate_details if best_score >= 70 and int(x.get("score", 0)) == best_score]

        if stored_reachable:
            detected_ip = stored_ip
            status = "CONFIRMED — WEAK IDENTITY" if weak_identity else "CONFIRMED"
            confidence = max(50, best_score)
            candidates = [stored_ip]
        elif len(high) == 1:
            detected_ip = high[0]["ip"]
            confidence = int(high[0]["score"])
            status = "RECOVERED — HIGH CONFIDENCE"
            candidates = [high[0]["ip"]]
            runtime_id = device.get("id") or _v272_norm(device.get("name"))
            if runtime_id:
                runtime_ips[runtime_id] = detected_ip
        elif len(high) > 1:
            detected_ip = ""
            confidence = int(high[0]["score"])
            status = "AMBIGUOUS — DO NOT RECOVER"
            candidates = [x["ip"] for x in high]
        elif best_score >= 70 and len(same_top) == 1:
            detected_ip = best
            confidence = int(best_score)
            status = "RECOVERY CANDIDATE — REVIEW"
            candidates = [best]
        else:
            detected_ip = ""
            confidence = 0 if best_score < 40 else int(best_score)
            status = "OFFLINE — NOT ON CURRENT LAN" if not candidate_details else "NO RECOVERY"
            candidates = [x["ip"] for x in candidate_details[:3]]

        last_seen = prior.get("last_seen", "") if isinstance(prior, dict) else ""
        records.append({
            "name": device.get("name", "Device"),
            "identity": identity,
            "stored_ip": stored_ip,
            "stored_ip_reachable": stored_reachable,
            "detected_ip": detected_ip,
            "detected_mac": best_mac or ((arp.get(detected_ip) if detected_ip else "") or (local_mac if detected_ip == local_ip else "")),
            "confidence": confidence,
            "status": status,
            "evidence": best_evidence if best else [],
            "candidate_count": len(candidates),
            "candidate_ips": candidates,
            "weak_identity": weak_identity,
            "last_seen": last_seen,
            "network_presence_alert": status == "OFFLINE — NOT ON CURRENT LAN",
            "runtime_reassigned": bool(device.get("id") in runtime_ips),
        })

    if cache_changed:
        _v272_save_identity_cache()

    _PNDCC_V272_RUNTIME_IPS = runtime_ips
    discovered_hosts = []
    for ip in sorted(discovered, key=lambda x: tuple(int(p) for p in x.split("."))):
        if ip == local_ip:
            host = "macbookpro"
        else:
            host = _v272_hostname(ip).get("raw", "")
        discovered_hosts.append({"ip": ip, "mac": arp.get(ip, ""), "hostname": host})

    data = {
        "prototype": PNDCC_V272_VERSION,
        "policy": PNDCC_V272_POLICY,
        "timestamp": now(),
        "local_network": {
            "interface": local.get("interface"),
            "ip": local_ip,
            "netmask": local.get("netmask"),
            "network": network,
            "mac": local_mac,
        },
        "automatic_discovery": {
            "enabled": True,
            "method": "ARP + local-subnet ping sweep + reverse DNS + best-effort mDNS",
            "cache_seconds": PNDCC_V272_CACHE_SECONDS,
            "discovered_hosts": discovered_hosts,
            "mDNS": mdns,
        },
        "devices": records,
        "runtime_ip_overrides": dict(runtime_ips),
        "safety": {
            "config_modified": False,
            "persistent_ip_changed": False,
            "identity_reassigned": False,
            "automatic_recovery_performed": False,
            "local_identity_scope_enforced": True,
            "ftp_ftps_touched": False,
            "keychain_touched": False,
        },
        "production_decision": {
            "architecture": "IP + MAC/ARP + hostname/mDNS + reachability",
            "mode": PNDCC_V272_POLICY,
            "high_confidence_runtime_recovery_only": True,
            "dhcp_reservation": "OPTIONAL_ROUTER_SIDE_PREVENTION",
            "agent_required": False,
            "confidence_gates": {
                "auto_recover": 90,
                "manual_review": 70,
                "reject_below": 70,
                "missing_mac_cap": 55
            },
            "persistent_config_update": "MANUAL_APPROVAL_ONLY",
            "offline_policy": "SIGNAL_ONLY_NO_GUESSING",
        },
    }
    with _PNDCC_V272_LOCK:
        _PNDCC_V272_SNAPSHOT = {"timestamp": time.time(), "data": data}
    return data


def _v272_dashboard_section():
    data = _v272_snapshot()
    rows = []
    for d in data.get("devices", []):
        status = esc(d.get("status"))
        detected = esc(d.get("detected_ip") or "—")
        confidence = esc(d.get("confidence"))
        stored = esc(d.get("stored_ip") or "—")
        rows.append(
            f"<div class='card'><div style='display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap'>"
            f"<div><strong>{esc(d.get('name'))}</strong><div class='small'>Stored {stored} · Current {detected}</div></div>"
            f"<div><span class='pill {status}'>{status}</span> <strong>{confidence}%</strong></div></div>"
            f"<div class='small' style='margin-top:8px'>Evidence: {esc(', '.join(d.get('evidence') or []) or 'No identity evidence available')}</div></div>"
        )
    return """<section class='section'><div class='section-head'><h2 class='section-title'>IP Identity &amp; Network Context</h2><span class='section-note'>v2.7.2 · automatic · confidence-gated · runtime only</span></div><div class='grid'>""" + "".join(rows) + """</div><div class='card' style='margin-top:12px'><div class='small'>Identity rule: IP = current location · MAC/ARP = strongest identity evidence · hostname/mDNS = supporting evidence · ambiguous matches are never auto-reassigned.</div><div class='nav' style='margin-top:10px'><a href='/ip-resilience'>Open IP Identity details →</a></div></div></section>"""


# Preserve the final dashboard and add one isolated identity section.
_PNDCC_V272_OLD_DASHBOARD = dashboard

def dashboard():
    page = _PNDCC_V272_OLD_DASHBOARD()
    section = _v272_dashboard_section()
    marker = "<section class='section'><div class='section-head'><h2 class='section-title'>Network health</h2>"
    if marker in page:
        page = page.replace(marker, section + marker, 1)
    else:
        page = page.replace("</body>", section + "</body>", 1)
    page = page.replace("Version 2.6.3", "Version 2.7.2").replace("PNDCC v2.6.3", "PNDCC v2.7.2")
    return page


def _v272_ip_page():
    data = _v272_snapshot()
    rows = []
    for d in data.get("devices", []):
        rows.append(
            "<tr>"
            f"<td><strong>{esc(d.get('name'))}</strong><div class='small'>{esc(d.get('identity'))}</div></td>"
            f"<td>{esc(d.get('stored_ip') or '—')}</td>"
            f"<td>{esc(d.get('detected_ip') or '—')}</td>"
            f"<td>{esc(d.get('detected_mac') or '—')}</td>"
            f"<td>{esc(d.get('confidence'))}%</td>"
            f"<td><span class='pill {esc(d.get('status'))}'>{esc(d.get('status'))}</span></td>"
            f"<td>{esc(', '.join(d.get('evidence') or []) or '—')}</td>"
            "</tr>"
        )
    body = f"""
    <section class='hero'><div class='hero-head'><div><h2>IP Identity Resilience</h2><p>Automatic local-LAN discovery with confidence-gated runtime recovery.</p></div><div class='small'>No persistent IP reassignment</div></div></section>
    <section class='section'><div class='card' style='overflow:auto'><table><thead><tr><th>Device</th><th>Stored IP</th><th>Detected IP</th><th>MAC</th><th>Confidence</th><th>Status</th><th>Evidence</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></section>
    <section class='section'><div class='section-head'><h2 class='section-title'>Discovery</h2><span class='section-note'>{esc(len(data.get('automatic_discovery',{}).get('discovered_hosts',[])))} hosts</span></div><div class='card'><div class='small'>LAN: {esc(data.get('local_network',{}).get('network'))} · Interface: {esc(data.get('local_network',{}).get('interface'))} · Current IP: {esc(data.get('local_network',{}).get('ip'))}</div><div class='small' style='margin-top:8px'>DHCP reservation is an optional router-side prevention measure. PNDCC does not configure the router.</div></div></section>
    """
    return page_shell("PNDCC v2.7.2 — IP Identity Resilience", body).replace("Version 2.6.3", "Version 2.7.2").replace("PNDCC v2.6.3", "PNDCC v2.7.2")


# Monitoring integration: apply only high-confidence runtime IP overrides to
# monitoring/history. CFG/device configuration remains unchanged.
_PNDCC_V272_OLD_CHECK_ALL = check_all

def check_all():
    try:
        snapshot = _v272_snapshot()
        overrides = snapshot.get("runtime_ip_overrides", {}) if isinstance(snapshot, dict) else {}
    except Exception:
        overrides = {}
    rows = []
    stamp = now()
    for d in enabled_devices():
        device_id = d.get("id") or _v272_norm(d.get("name")) or "unknown"
        ip = str(overrides.get(device_id) or d.get("ip", ""))
        ok, lat, loss = ping(ip)
        rows.append({
            "timestamp": stamp,
            "target_id": device_id,
            "name": d.get("name", "Unnamed device"),
            "ip": ip,
            "status": status(ok, lat, loss),
            "latency_ms": round(lat, 2) if lat is not None else "",
            "packet_loss_pct": round(loss, 2),
        })
    if rows:
        new = not os.path.exists(DEVICE_HIST)
        try:
            with open(DEVICE_HIST, "a", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=FIELDS)
                if new:
                    w.writeheader()
                w.writerows(rows)
        except OSError:
            pass
    return rows


# Final GET wrapper: identity API + human-readable identity page.
_PNDCC_V272_OLD_GET = H.do_GET

def _v272_production_get(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path == "/api/ip-resilience":
        body = json.dumps(_v272_snapshot(), indent=2, ensure_ascii=False)
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))
        return
    if parsed.path == "/ip-resilience":
        body = _v272_ip_page().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return
    return _PNDCC_V272_OLD_GET(self)


H.do_GET = _v272_production_get


# ============================================================================
# PNDCC v2.7.2.2 — Final dashboard runtime-IP integration + screenshot button fix
# ============================================================================
# Additive-only. The identity layer remains confidence-gated and runtime-only.
# This final wrapper makes the main device cards use the current runtime IP and
# treats the PNDCC host itself as online from active interface ownership.
# No persistent configuration, FTP/FTPS, Keychain, storage, or identity data
# is modified by this layer.

PNDCC_V2722_VERSION = "2.7.2.2"

_PNDCC_V2722_OLD_DEVICE_CARD = device_card

def device_card(d, r):
    s = str(r.get("status", "NOT CHECKED"))
    cls = s.replace(" ", "-")
    latency = r.get("latency_ms") or "—"
    loss = r.get("packet_loss_pct") or "—"
    current_ip = r.get("ip") or d.get("ip") or "—"
    return f"""
    <article class='card'>
      <div class='device-top'>
        <div><h3>{esc(d.get('name','Unnamed device'))}</h3><div class='small'>{esc(current_ip)}</div></div>
        <span class='pill {esc(cls)}'>{esc(s)}</span>
      </div>
      <div class='metrics'>
        <div><div class='metric-label'>Latency</div><div class='metric-value'>{esc(latency)}{' ms' if latency != '—' and str(latency).find('ms') < 0 else ''}</div></div>
        <div><div class='metric-label'>Packet loss</div><div class='metric-value'>{esc(loss)}{'%' if loss != '—' and str(loss).find('%') < 0 else ''}</div></div>
      </div>
    </article>"""

_PNDCC_V2722_OLD_CHECK_ALL = check_all

def check_all():
    try:
        snapshot = _v272_snapshot()
        overrides = snapshot.get("runtime_ip_overrides", {}) if isinstance(snapshot, dict) else {}
        local_ip = str((snapshot.get("local_network") or {}).get("ip") or "") if isinstance(snapshot, dict) else ""
        local_ids = {
            str(rec.get("id") or _v272_norm(rec.get("name")))
            for rec in (snapshot.get("devices") or [])
            if isinstance(rec, dict)
            and rec.get("detected_ip") == local_ip
            and "local-interface-IP" in (rec.get("evidence") or [])
        }
    except Exception:
        overrides, local_ip, local_ids = {}, "", set()

    rows = []
    stamp = now()
    for d in enabled_devices():
        device_id = d.get("id") or _v272_norm(d.get("name")) or "unknown"
        ip = str(overrides.get(device_id) or d.get("ip", ""))
        if local_ip and ip == local_ip and str(device_id) in local_ids:
            # The PNDCC host owns this active interface/IP. A self-ping can be
            # blocked by local firewall behavior, so interface ownership is the
            # authoritative local reachability signal.
            ok, lat, loss = True, 0.0, 0.0
        else:
            ok, lat, loss = ping(ip)
        rows.append({
            "timestamp": stamp,
            "target_id": device_id,
            "name": d.get("name", "Unnamed device"),
            "ip": ip,
            "status": status(ok, lat, loss),
            "latency_ms": round(lat, 2) if lat is not None else "",
            "packet_loss_pct": round(loss, 2),
        })

    if rows:
        new = not os.path.exists(DEVICE_HIST)
        try:
            with open(DEVICE_HIST, "a", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=FIELDS)
                if new:
                    w.writeheader()
                w.writerows(rows)
        except OSError:
            pass
    return rows

# PNDCC v2.9 launch
PNDCC_VERSION = PNDCC_V29_VERSION
PNDCC_UPDATED = PNDCC_V29_UPDATED
PORT = int(os.environ.get("PORT", "8787"))  # Production target; set PORT explicitly for isolated tests.



# PNDCC documentation screenshot embedding — isolated final POST route.
# All pre-existing POST routes delegate unchanged to the handler captured here.
_PNDCC_DOC_SCREENSHOT_OLD_POST = H.do_POST

def _pndcc_documentation_screenshot_post(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path != '/api/documentation/with-screenshot':
        return _PNDCC_DOC_SCREENSHOT_OLD_POST(self)
    try:
        length = int(self.headers.get('Content-Length', '0') or 0)
        if length <= 0 or length > 18 * 1024 * 1024:
            raise ValueError('Invalid documentation request size')
        payload = json.loads(self.rfile.read(length).decode('utf-8'))
        selected = [str(x) for x in (payload.get('docs') or []) if str(x) in {'1','2','3'}]
        if not selected:
            raise ValueError('No valid documentation set selected')
        screenshot_png = None
        data_url = payload.get('screenshot')
        if isinstance(data_url, str) and data_url.startswith('data:image/png;base64,'):
            try:
                candidate = base64.b64decode(data_url.split(',', 1)[1], validate=True)
                if 8 <= len(candidate) <= 12 * 1024 * 1024 and candidate.startswith(b'\x89PNG\r\n\x1a\n'):
                    screenshot_png = candidate
            except Exception:
                screenshot_png = None
        data = _pndcc_documentation_zip(selected, screenshot_png)
        archive_path = None
        if urllib.parse.parse_qs(parsed.query).get('archive', ['0'])[0] == '1':
            archive_dir = os.path.join(APP_DIR, 'PNDCC_Archive', 'Documentation')
            os.makedirs(archive_dir, exist_ok=True)
            stamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            archive_name = 'PNDCC_Documentation_' + '_'.join(selected) + '_' + stamp + '.zip'
            archive_path = os.path.join(archive_dir, archive_name)
            with open(archive_path, 'wb') as af:
                af.write(data)
        self.send_response(200)
        self.send_header('Content-Type', 'application/zip')
        self.send_header('Content-Disposition', 'attachment; filename="PNDCC_Documentation_' + '_'.join(selected) + '.zip"')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        if archive_path:
            self.send_header('X-PNDCC-Archive', os.path.basename(archive_path))
        self.end_headers()
        self.wfile.write(data)
    except Exception as e:
        try:
            self._send_text(400, 'PNDCC documentation generation failed safely: ' + type(e).__name__)
        except Exception:
            pass

H.do_POST = _pndcc_documentation_screenshot_post


# PNDCC cloud-storage usability patch: on-demand iCloud refresh.
# This wrapper is placed after prior POST handlers so all existing routes are
# delegated unchanged except the one explicitly added endpoint.
_PNDCC_ICLOUD_REFRESH_OLD_POST = H.do_POST

def _pndcc_icloud_refresh_post(self):
    parsed = urllib.parse.urlparse(self.path)
    if parsed.path != "/api/cloud/icloud-refresh":
        return _PNDCC_ICLOUD_REFRESH_OLD_POST(self)
    try:
        # The endpoint only refreshes the current user's iCloud quota metadata.
        # Reject cross-origin browser calls when an Origin header is present.
        origin = self.headers.get("Origin")
        host_header = self.headers.get("Host", "")
        if origin:
            origin_netloc = urllib.parse.urlparse(origin).netloc
            if not origin_netloc or origin_netloc.lower() != host_header.lower():
                self._send_json({"ok": False, "message": "Refresh request rejected because its origin did not match this PNDCC page."})
                return

        live = _read_icloud_system_settings()
        if live:
            live["source"] = "Live macOS System Settings · Apple Account > iCloud"
            live["snapshot"] = False
            cache_saved = _write_icloud_quota_cache(live)
            try:
                verified_at = str(live.get("verified_at") or datetime.now().astimezone().isoformat(timespec="seconds"))
                local_stamp = datetime.fromisoformat(verified_at).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
            except Exception:
                local_stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
            message = (
                f"Live iCloud storage refreshed successfully at {local_stamp}. "
                + ("The verified reading was saved for fallback." if cache_saved else "The live reading succeeded, but saving the fallback cache failed.")
            )
            self._send_json({"ok": True, "quota": live, "message": message, "cache_saved": cache_saved})
            return

        # Capture the live-read failure before reading the cache, because the
        # cache helper updates the diagnostic to its own fallback status.
        diagnostic = str(_ICLOUD_READ_DIAGNOSTIC or "No additional diagnostic was returned")[:220]
        cached = _read_icloud_quota_cache()
        advice = (
            "Open System Settings → Apple Account → iCloud, keep that page visible, "
            "wait until the Storage line is shown, and press Refresh again. "
            "Your Accessibility and Automation permissions were already checked; "
            "if this repeats, share the timestamp and diagnostic rather than changing more settings."
        )
        payload = {
            "ok": False,
            "message": "PNDCC could not obtain a new live iCloud quota.",
            "diagnostic": diagnostic,
            "advice": advice,
            "last_verified_at": None,
        }
        if cached:
            payload["last_verified_at"] = cached.get("verified_at")
            payload["cached_quota"] = {
                "used_gb": cached.get("used_gb"),
                "free_gb": cached.get("free_gb"),
                "total_gb": cached.get("total_gb"),
                "used_pct": cached.get("used_pct"),
            }
        self._send_json(payload)
    except Exception as exc:
        try:
            self._send_json({
                "ok": False,
                "message": "The iCloud refresh request failed safely.",
                "diagnostic": type(exc).__name__,
                "advice": "Keep the iCloud pane open and retry once. If the failure repeats, share the server log; do not change account settings or delete credentials.",
            })
        except Exception:
            pass

H.do_POST = _pndcc_icloud_refresh_post


# PNDCC v2.9.6 — Control Center card layout only.
# This isolated wrapper replaces only the old navigation-link strip on the
# main dashboard. Existing page routes, monitoring, file operations, and PDF
# screenshot functions are intentionally left unchanged.
_PNDCC_CONTROL_CENTER_CARDS_V296_OLD_DASHBOARD = dashboard

_PNDCC_CONTROL_CENTER_CARDS_V296_CSS = r"""
<style id="pndcc-control-center-cards-v296">
.pndcc-cc-group{margin-top:24px}
.pndcc-cc-heading{display:flex;align-items:center;gap:10px;margin:0 0 7px;font-size:1.22rem;font-weight:800;letter-spacing:-.02em}
.pndcc-cc-subtitle{margin:0 0 14px;color:var(--muted,#64748b);font-size:.94rem}
.pndcc-cc-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,235px),1fr));gap:14px}
.pndcc-cc-card{--cc-accent:#3984ff;position:relative;display:flex;min-height:156px;flex-direction:column;gap:11px;padding:17px 17px 15px;border:1px solid var(--border,#dce4ef);border-radius:16px;background:linear-gradient(145deg,var(--card,#fff),color-mix(in srgb,var(--cc-accent) 5%,var(--card,#fff)));box-shadow:0 5px 18px rgba(20,39,75,.07);text-decoration:none!important;color:inherit!important;overflow:hidden;transition:transform .16s ease,box-shadow .16s ease,border-color .16s ease}
.pndcc-cc-card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--cc-accent)}
.pndcc-cc-card:hover,.pndcc-cc-card:focus-visible{transform:translateY(-2px);border-color:var(--cc-accent);box-shadow:0 10px 26px rgba(20,39,75,.13);outline:none}
.pndcc-cc-card-top{display:flex;align-items:center;gap:12px}
.pndcc-cc-icon{display:flex;align-items:center;justify-content:center;flex:0 0 44px;width:44px;height:44px;border-radius:13px;background:color-mix(in srgb,var(--cc-accent) 13%,transparent);font-size:24px;line-height:1}
.pndcc-cc-card-title{margin:0;font-size:1rem;font-weight:800;line-height:1.3}
.pndcc-cc-card-desc{margin:0;color:var(--muted,#64748b);font-size:.9rem;line-height:1.48;flex:1}
.pndcc-cc-card-footer{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:auto;color:var(--cc-accent);font-size:.88rem;font-weight:750}
.pndcc-cc-card-footer a{color:var(--cc-accent)!important;text-decoration:none!important}
.pndcc-cc-card-footer a:hover{text-decoration:underline!important}
.pndcc-cc-card-footer .cc-arrow{font-size:1.05rem}
@media(max-width:560px){.pndcc-cc-grid{grid-template-columns:1fr}.pndcc-cc-card{min-height:132px}.pndcc-cc-heading{font-size:1.1rem}}
@media(prefers-reduced-motion:reduce){.pndcc-cc-card{transition:none}.pndcc-cc-card:hover{transform:none}}
</style>
"""


def _pndcc_control_center_cards_v296_markup():
    network_cards = [
        ("📡", "Network Pulse", "Live network status and trends", "/network-pulse", "#3984ff"),
        ("🩺", "Device Health Intelligence", "Traffic signals and recovery", "/device-health", "#10a985"),
        ("🧭", "Network Diagnostics", "Connectivity and network evidence", "/network-diagnostics", "#8b5cf6"),
        ("🛡️", "IP Resilience", "IP identity and address recovery", "/ip-resilience", "#0891b2"),
        ("🧠", "Decision Center", "Interpret findings and recommend actions", "/decision-center", "#d97706"),
    ]
    operations_cards = [
        ("💻", "Device Control", "Phase 2 · Safe file access", "/device-control", "#3984ff"),
        ("🗂️", "Device History &amp; FTP History", "Review past measurements and transfers", "/history", "#10a985"),
        ("🛡️", "Controlled Action &amp; Recovery", "Review controlled operations and recovery records", "/controlled-action", "#d97706"),
    ]

    def card(icon, title, desc, href, accent, history=False):
        extra = (
            "<a href='/history'>Device History</a><span aria-hidden='true'>·</span>"
            "<a href='/ftp-history'>FTP History</a>"
            if history else "<span class='cc-arrow' aria-hidden='true'>→</span>"
        )
        return (
            f"<article class='pndcc-cc-card' style='--cc-accent:{accent}'>"
            f"<a class='pndcc-cc-card-top' href='{href}' aria-label='Open {title.replace('&amp;', 'and')}'>"
            f"<span class='pndcc-cc-icon' aria-hidden='true'>{icon}</span>"
            f"<span class='pndcc-cc-card-title'>{title}</span></a>"
            f"<p class='pndcc-cc-card-desc'>{desc}</p>"
            f"<div class='pndcc-cc-card-footer'><a href='{href}'>Open interface</a>{extra}</div>"
            "</article>"
        )

    net = "".join(card(*item) for item in network_cards)
    ops = "".join(card(*item, history=(item[1] == "Device History &amp; FTP History")) for item in operations_cards)
    return (
        "<section class='section pndcc-cc-group' id='pndcc-network-intelligence'>"
        "<div class='section-head'><h2 class='section-title'>🌐 Network Intelligence</h2>"
        "<span class='section-note'>Monitoring · evidence · recommendations</span></div>"
        "<p class='pndcc-cc-subtitle'>Open each interface directly from the main dashboard.</p>"
        f"<div class='pndcc-cc-grid'>{net}</div></section>"
        "<section class='section pndcc-cc-group' id='pndcc-device-file-operations'>"
        "<div class='section-head'><h2 class='section-title'>🗂️ Device &amp; File Operations</h2>"
        "<span class='section-note'>Phase 2 · safe file access</span></div>"
        "<p class='pndcc-cc-subtitle'>Manage files, review history, and inspect controlled recovery records.</p>"
        f"<div class='pndcc-cc-grid'>{ops}</div></section>"
    )


def dashboard():
    page = _PNDCC_CONTROL_CENTER_CARDS_V296_OLD_DASHBOARD()
    import re as _pndcc_cc_re
    page, replacements = _pndcc_cc_re.subn(
        r"<section class='section'><div class='section-head'><h2 class='section-title'>Control Center</h2>.*?</section>",
        lambda _match: _pndcc_control_center_cards_v296_markup(),
        page,
        count=1,
        flags=_pndcc_cc_re.DOTALL,
    )
    if replacements != 1:
        # Fail visibly instead of silently adding duplicate cards or changing
        # unrelated dashboard content if the source layout differs.
        raise RuntimeError("PNDCC Control Center navigation section was not found; dashboard left unchanged")
    if "id=\"pndcc-control-center-cards-v296\"" not in page:
        if "</head>" in page:
            page = page.replace("</head>", _PNDCC_CONTROL_CENTER_CARDS_V296_CSS + "</head>", 1)
        elif "</body>" in page:
            page = page.replace("</body>", _PNDCC_CONTROL_CENTER_CARDS_V296_CSS + "</body>", 1)
        else:
            page = _PNDCC_CONTROL_CENTER_CARDS_V296_CSS + page
    return page


if __name__ == "__main__":
    print(f"PNDCC v{PNDCC_V29_VERSION} running at http://{HOST}:{PORT}")
    print(f"Project: {BASE}")
    print("Dashboard: /")
    print("Settings: /settings")
    print("Device control: /device-control")
    print("Network diagnostics: /network-diagnostics")
    print("Network diagnostics API: /api/network-diagnostics")
    print("Device history: /history")
    print("FTP history: /ftp-history")
    print("Health: /health")
    print("API status: /api/status")
    print("Controlled Action & Recovery: /controlled-action")
    print("Controlled Action API: /api/controlled-action")
    print("Decision Center: /decision-center")
    print("Decision Center API: /api/decision-center")
    print("Device Health Intelligence: /device-health")
    print("Device Health API: /api/device-health")
    print("Simple is the best.")
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
