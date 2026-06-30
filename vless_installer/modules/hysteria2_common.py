"""
vless_installer/modules/hysteria2_common.py
───────────────────────────────────────────────────────────────────────────────
Общие утилиты для всех Hysteria2-модулей.
Не импортируется напрямую из _core.py — используется внутри h2-модулей.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# ── Цвета (идентичны остальным модулям проекта) ───────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
            DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Файлы и пути ──────────────────────────────────────────────────────────────
STATE_FILE      = Path("/var/lib/xray-installer/state.json")
LOG_FILE        = Path("/var/log/vless-install.log")
H2_CONFIG_DIR   = Path("/etc/hysteria")
H2_CONFIG_FILE  = H2_CONFIG_DIR / "config.yaml"
H2_BINARY       = Path("/usr/local/bin/hysteria")
H2_SERVICE      = "hysteria-server"
H2_LOG_FILE     = Path("/var/log/hysteria.log")
H2_CERT_DIR     = Path("/etc/xray")
H2_CERT_FILE    = H2_CERT_DIR / "hysteria.crt"
H2_KEY_FILE     = H2_CERT_DIR / "hysteria.key"
TG_CONFIG_FILE  = Path("/var/lib/xray-installer/telegram.json")

# ── Логирование ───────────────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] [H2] {clean}\n")
    except Exception:
        pass

def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO",    msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN",   msg)
def error(msg: str)   -> None: print(f"{RED}[ERR]{NC}   {msg}");   _log("ERROR",   msg)
def log_to_file(level: str, msg: str) -> None: _log(level, msg)

# ── subprocess helper ─────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False, timeout: int = 60) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8",
                  errors="replace", timeout=timeout)
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                  timeout=timeout)
    return subprocess.run(cmd, **kw)

# ── state.json helpers ────────────────────────────────────────────────────────
def _load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    except Exception:
        return {}

def _save_state(st: dict) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(st, indent=2, ensure_ascii=False))
    except Exception as e:
        error(f"Ошибка записи state.json: {e}")

def _load_h2_state() -> dict:
    """Возвращает секцию hysteria2 из state.json (создаёт если нет)."""
    st = _load_state()
    return st.get("hysteria2", {})

def _save_h2_state(h2: dict) -> None:
    """Атомарно обновляет секцию hysteria2 в state.json."""
    st = _load_state()
    st["hysteria2"] = h2
    _save_state(st)

def _h2_default_state() -> dict:
    """Возвращает default-секцию hysteria2."""
    return {
        "enabled": False,
        "transport_only": False,
        "exit_nodes": [],
        "cert": {
            "crt": str(H2_CERT_FILE),
            "key": str(H2_KEY_FILE),
            "auto_renew": True,
            "expire_date": "",
            "ipv6_support": True,
        },
        "health_check": {
            "interval_sec": 60,
            "timeout_sec": 5,
            "method": "quic_ping",
            "fail_threshold": 3,
        },
        "firewall": {
            "udp_ports": [443],
            "ip6tables_rules": True,
            "fallback_ports": [8443, 2083],
            "auto_configure": True,
        },
        "balancer": {
            "strategy": "weightedRandom",
            "switch_threshold": 0.5,
            "current_weights": {},
            "ipv4_weight": 1.0,
            "ipv6_weight": 1.0,
        },
        "auto_update": {
            "enabled": True,
            "check_interval_hours": 24,
        },
    }

def _ensure_h2_state() -> dict:
    """Гарантирует наличие секции hysteria2, возвращает её."""
    h2 = _load_h2_state()
    if not h2:
        h2 = _h2_default_state()
        _save_h2_state(h2)
    return h2

# ── Telegram helper (не зависит от _core.py) ─────────────────────────────────
def _tg_send(msg: str) -> bool:
    try:
        if not TG_CONFIG_FILE.exists():
            return False
        cfg = json.loads(TG_CONFIG_FILE.read_text())
        token   = cfg.get("token", "")
        chat_id = cfg.get("chat_id", "")
        if not token or not chat_id:
            return False
        r = _run([
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-m", "10",
            f"https://api.telegram.org/bot{token}/sendMessage",
            "-d", f"chat_id={chat_id}",
            "-d", f"text={msg}",
            "-d", "parse_mode=HTML",
        ], capture=True, check=False)
        return r.stdout.strip() == "200"
    except Exception:
        return False

def _tg_h2_event(event: str, detail: str = "") -> None:
    icons = {
        "h2_up":      "🟢",
        "h2_down":    "🔴",
        "h2_cert":    "🔒",
        "h2_switch":  "🔀",
        "h2_update":  "⬆️",
        "h2_weights": "⚖️",
        "h2_port_fb": "🔁",
    }
    icon = icons.get(event, "ℹ️")
    hostname = ""
    try:
        hostname = _run(["hostname", "-s"], capture=True).stdout.strip()
    except Exception:
        pass
    ts = datetime.now().strftime("%d.%m.%Y %H:%M")
    _tg_send(f"{icon} <b>[{hostname}] Hysteria2</b> {detail}\n<i>{ts}</i>")
    _log("INFO", f"TG H2 event: {event} — {detail}")

# ── IPv6 helper ───────────────────────────────────────────────────────────────
def h2_cert_sha256_local(cert_path: str) -> str:
    """
    Возвращает SHA256-отпечаток сертификата в hex (нижний регистр, без
    двоеточий) — нужен для Xray-core streamSettings.tlsSettings.
    pinnedPeerCertSha256 (с июня 2026 это единственный способ "доверять"
    самоподписанному сертификату — поле allowInsecure из Xray-core убрано).
    """
    try:
        r = _run(["openssl", "x509", "-noout", "-fingerprint", "-sha256",
                   "-in", cert_path], capture=True)
        # Вывод вида: "sha256 Fingerprint=AE:24:3D:...:BF:77"
        raw = r.stdout.split("=", 1)[-1].strip()
        return raw.replace(":", "").lower()
    except Exception:
        return ""


def _is_ipv6(addr: str) -> bool:
    return ":" in addr

def _bracket(addr: str) -> str:
    """Оборачивает IPv6-адрес в квадратные скобки для URL/конфигов."""
    return f"[{addr}]" if _is_ipv6(addr) and not addr.startswith("[") else addr

def _detect_ipv6_available() -> bool:
    try:
        r = _run(["ip", "-6", "addr", "show"], capture=True, quiet=False)
        return bool(r.stdout and "inet6" in r.stdout)
    except Exception:
        return False

# ── iptables helpers ──────────────────────────────────────────────────────────
def _ipt_allow_udp(port: int, ipv6: bool = False) -> None:
    ipt = "ip6tables" if ipv6 else "iptables"
    _run([ipt, "-C", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"],
         quiet=True)
    if _run([ipt, "-C", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"],
             quiet=True).returncode != 0:
        _run([ipt, "-I", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"],
             quiet=True)

def _ipt_remove_udp(port: int, ipv6: bool = False) -> None:
    ipt = "ip6tables" if ipv6 else "iptables"
    _run([ipt, "-D", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"],
         quiet=True)

def open_udp_ports(ports: list[int], ipv6: bool = False) -> None:
    for p in ports:
        _ipt_allow_udp(p, ipv6=False)
        if ipv6 and _detect_ipv6_available():
            _ipt_allow_udp(p, ipv6=True)

def close_udp_ports(ports: list[int], ipv6: bool = False) -> None:
    for p in ports:
        _ipt_remove_udp(p, ipv6=False)
        if ipv6:
            _ipt_remove_udp(p, ipv6=True)

# ── systemd helpers ───────────────────────────────────────────────────────────
def _systemctl(action: str, service: str) -> bool:
    r = _run(["systemctl", action, service], quiet=True)
    return r.returncode == 0

def _service_active(service: str) -> bool:
    r = _run(["systemctl", "is-active", "--quiet", service], quiet=True)
    return r.returncode == 0

# ── H2 binary helpers ─────────────────────────────────────────────────────────
def _h2_binary_version() -> str:
    try:
        r = _run([str(H2_BINARY), "version"], capture=True)
        m = re.search(r'v?(\d+\.\d+\.\d+)', r.stdout)
        return m.group(1) if m else ""
    except Exception:
        return ""

def _h2_binary_exists() -> bool:
    return H2_BINARY.exists() and os.access(str(H2_BINARY), os.X_OK)
