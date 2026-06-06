"""
vless_installer/modules/tg_bot.py
───────────────────────────────────────────────────────────────────────────────
Telegram Bot — единая точка для всего, что связано с Telegram в проекте.

Объединяет и заменяет разрозненные TG_CONFIG_FILE / _tg_load / _tg_save /
tg_send / _tg_notify_event / _tg_install_monitor_cron из _core.py.
В _core.py оставляем тонкие обёртки-делегаты (2 строки), которые
импортируют функции отсюда — обратная совместимость полная.

════════════════════════════════════════════════════════════════════════════════
ЧАСТЬ 1: Уведомления (admin-only, одностороннее)
  Текущая функциональность: xray_down/up, cert_expire, traffic_limit,
  health_report, node_down — всё сохранено без изменений.

ЧАСТЬ 2: Пользовательский бот (раздача конфигов)
  Пользователь пишет боту → получает свою ссылку/QR/конфиг.
  Поддерживает все режимы: A, B, B-Multi, REALITY, xHTTP.
  Работает как systemd-сервис (long-polling), никаких внешних зависимостей
  кроме python3 и curl (уже есть на сервере).

Команды бота:
  /start       — приветствие, список команд
  /config      — VLESS-ссылка для этого пользователя (если авторизован)
  /status      — статус сервера (только для admin chat_id)
  /users       — список пользователей (только admin)
  /help        — справка

Авторизация пользователей:
  Белый список Telegram user_id в tg_bot.json → "allowed_users": [123, 456]
  Или открытый режим: admin выдаёт одноразовый invite-токен через меню.
  Пользователь вводит /start <token> → добавляется в allowed_users.

Хранение:
  /var/lib/xray-installer/tg_bot.json   — конфиг бота
  /var/lib/xray-installer/telegram.json — конфиг уведомлений (совместимость)

Публичное API (обратная совместимость с _core.py):
  tg_load()                    → dict  (= _tg_load)
  tg_save(cfg)                          (= _tg_save)
  tg_send(msg, token, chat_id) → bool  (= tg_send)
  tg_notify_event(event, detail)        (= _tg_notify_event)
  do_manage_telegram()                  — меню уведомлений (как раньше)
  do_tg_bot_menu()                      — меню бота (новое)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        light = os.environ.get("VLESS_THEME", "").lower() == "light"
        if light:
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                        CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                        DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m')
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
BLUE=_C['BLUE']; BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']

# ── Константы ─────────────────────────────────────────────────────────────────
_NOTIF_FILE  = Path("/var/lib/xray-installer/telegram.json")   # уведомления (совместимость)
_BOT_FILE    = Path("/var/lib/xray-installer/tg_bot.json")     # бот
_STATE_FILE  = Path("/var/lib/xray-installer/state.json")
_LOG_FILE    = Path("/var/log/vless-install.log")
_BOT_SVC     = Path("/etc/systemd/system/xray-tg-bot.service")
_BOT_SCRIPT  = Path("/usr/local/bin/xray-tg-bot.py")
_MONITOR_SVC = Path("/etc/cron.d/xray-tg-monitor")

# ── box_renderer ───────────────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item,
    _box_back, _box_info, _box_warn, _box_desc,
)

# ── Логирование ────────────────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [TG] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str):  print(f"{CYAN}[INFO]{NC}  {msg}");   _log("INFO",    msg)
def _ok(msg: str):    print(f"{GREEN}[OK]{NC}    {msg}");  _log("SUCCESS", msg)
def _warn(msg: str):  print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN",    msg)
def _err(msg: str):   print(f"{RED}[ERR]{NC}   {msg}");    _log("ERROR",   msg)

def _run(cmd: list, capture: bool = False, quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

# ══════════════════════════════════════════════════════════════════════════════
#  ЧАСТЬ 1: Уведомления — публичное API (обратная совместимость с _core.py)
# ══════════════════════════════════════════════════════════════════════════════

def tg_load() -> dict:
    """Загружает конфиг уведомлений. Совместим с _tg_load() из _core.py."""
    try:
        if _NOTIF_FILE.exists():
            return json.loads(_NOTIF_FILE.read_text())
    except Exception:
        pass
    return {}


def tg_save(cfg: dict) -> None:
    """Сохраняет конфиг уведомлений. Совместим с _tg_save() из _core.py."""
    _NOTIF_FILE.parent.mkdir(parents=True, exist_ok=True)
    _NOTIF_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    _NOTIF_FILE.chmod(0o600)


def tg_send(msg: str, token: str = "", chat_id: str = "") -> bool:
    """
    Отправляет сообщение в Telegram через curl.
    Если token/chat_id не переданы — берёт из _NOTIF_FILE.
    Совместим с tg_send() из _core.py.
    """
    if not token or not chat_id:
        cfg = tg_load()
        token   = cfg.get("token", "")
        chat_id = cfg.get("chat_id", "")
    if not token or not chat_id:
        return False
    try:
        r = _run([
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-m", "10",
            f"https://api.telegram.org/bot{token}/sendMessage",
            "-d", f"chat_id={chat_id}",
            "-d", f"text={msg}",
            "-d", "parse_mode=HTML",
        ], capture=True)
        return r.stdout.strip() == "200"
    except Exception:
        return False


def tg_notify_event(event: str, detail: str = "") -> None:
    """
    Отправляет уведомление если соответствующее событие включено.
    Совместим с _tg_notify_event() из _core.py.
    """
    cfg = tg_load()
    if not cfg.get("token") or not cfg.get("chat_id"):
        return
    events = cfg.get("events", {})
    if not events.get(event, True):
        return
    hostname = ""
    try:
        hostname = _run(["hostname", "-s"], capture=True).stdout.strip()
    except Exception:
        pass
    ts = datetime.now().strftime("%d.%m.%Y %H:%M")
    icons = {
        "xray_down":     "🔴",
        "xray_up":       "🟢",
        "cert_expire":   "🔒",
        "traffic_limit": "⚠️",
        "user_connect":  "👤",
        "health_report": "📋",
        "node_down":     "📡",
        "port_blocked":  "🚫",
        "port_hopping":  "⚡",
    }
    icon = icons.get(event, "ℹ️")
    text = f"{icon} <b>[{hostname}]</b> {detail}\n<i>{ts}</i>"
    tg_send(text)
    _log("INFO", f"TG notify: {event} — {detail}")


def _install_monitor_cron() -> None:
    """Устанавливает cron-скрипт мониторинга Xray (xray_down/up, cert)."""
    cfg = tg_load()
    token   = cfg.get("token", "")
    chat_id = cfg.get("chat_id", "")
    if not token or not chat_id:
        _warn("Сначала настройте токен и Chat ID")
        return

    script = Path("/usr/local/bin/xray-tg-monitor.sh")
    script.write_text(
        "#!/bin/bash\n"
        f"TOKEN=\"{token}\"\n"
        f"CHAT=\"{chat_id}\"\n"
        "send() { curl -s -o /dev/null -m 10 "
        "\"https://api.telegram.org/bot$TOKEN/sendMessage\" "
        "-d \"chat_id=$CHAT\" -d \"text=$1\" -d \"parse_mode=HTML\" || true; }\n"
        "HOST=$(hostname -s)\n"
        "TS=$(date '+%d.%m.%Y %H:%M')\n"
        "if ! systemctl is-active --quiet xray 2>/dev/null; then\n"
        "  STAMP=/tmp/xray-tg-down.stamp\n"
        "  if [ ! -f \"$STAMP\" ]; then touch \"$STAMP\";\n"
        "    send \"🔴 <b>[$HOST]</b> Xray не запущен!\\n<i>$TS</i>\"; fi\n"
        "else\n"
        "  if [ -f /tmp/xray-tg-down.stamp ]; then rm -f /tmp/xray-tg-down.stamp;\n"
        "    send \"🟢 <b>[$HOST]</b> Xray восстановился.\\n<i>$TS</i>\"; fi\n"
        "fi\n"
        "# Проверка срока сертификата (< 30 дней)\n"
        "CERT=$(find /etc/letsencrypt/live -name 'cert.pem' 2>/dev/null | head -1)\n"
        "if [ -n \"$CERT\" ]; then\n"
        "  EXP=$(openssl x509 -enddate -noout -in \"$CERT\" 2>/dev/null | cut -d= -f2)\n"
        "  if [ -n \"$EXP\" ]; then\n"
        "    DAYS=$(( ( $(date -d \"$EXP\" +%s) - $(date +%s) ) / 86400 ))\n"
        "    if [ \"$DAYS\" -lt 30 ]; then\n"
        "      send \"🔒 <b>[$HOST]</b> Сертификат истекает через $DAYS дн.\\n<i>$TS</i>\"; fi\n"
        "  fi\n"
        "fi\n"
    )
    script.chmod(0o755)

    _MONITOR_SVC.parent.mkdir(parents=True, exist_ok=True)
    _MONITOR_SVC.write_text(
        "# xray-tg-monitor — installed by vless-installer\n"
        f"*/5 * * * * root {script} 2>/dev/null\n"
    )
    _ok(f"Cron-мониторинг установлен: {script}")
    _log("INFO", "TG monitor cron installed")


# ══════════════════════════════════════════════════════════════════════════════
#  ЧАСТЬ 2: Пользовательский бот — раздача конфигов
# ══════════════════════════════════════════════════════════════════════════════

def _bot_load() -> dict:
    try:
        if _BOT_FILE.exists():
            return json.loads(_BOT_FILE.read_text())
    except Exception:
        pass
    return {}


def _bot_save(cfg: dict) -> None:
    _BOT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _BOT_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    _BOT_FILE.chmod(0o600)


def _bot_running() -> bool:
    """Проверяет, запущен ли systemd-сервис бота."""
    r = _run(["systemctl", "is-active", "--quiet", "xray-tg-bot"], quiet=False)
    return r.returncode == 0


def _load_state() -> dict:
    try:
        if _STATE_FILE.exists():
            return json.loads(_STATE_FILE.read_text())
    except Exception:
        pass
    return {}


def _get_vless_link(user_uuid: Optional[str] = None) -> str:
    """
    Формирует VLESS-ссылку из state.json.
    Поддерживает все режимы: A, B, B-Multi, REALITY, xHTTP.
    user_uuid — если задан, подставляется вместо основного UUID (для мультипользователей).
    """
    state = _load_state()
    domain       = state.get("domain", "")
    port         = state.get("server_port", 443)
    uuid_val     = user_uuid or state.get("uuid", "")
    proto        = state.get("protocol_mode", "reality")
    pub_key      = state.get("public_key", "")
    short_id     = state.get("short_id", "")
    fp           = state.get("fingerprint", "chrome") or "chrome"
    xtls_flow    = state.get("xtls_flow", "xtls-rprx-vision") or ""
    xhttp_path   = state.get("xhttp_path", "/")
    install_mode = state.get("install_mode", "A")
    awg_exit     = state.get("awg_exit_enabled", False)

    # SNI: для режима B с AWG — используем reality_dest, иначе domain
    sni = domain
    if proto == "reality" and awg_exit and install_mode == "B":
        sni = state.get("reality_dest", domain).split(":")[0]

    if not domain or not uuid_val:
        return ""

    if proto == "xhttp":
        link = (
            f"vless://{uuid_val}@{domain}:{port}"
            f"?type=xhttp&security=tls&path={xhttp_path}"
            f"&sni={sni}&fp={fp}#VLESS-xHTTP"
        )
    else:
        flow_part = f"&flow={xtls_flow}" if xtls_flow else ""
        link = (
            f"vless://{uuid_val}@{domain}:{port}"
            f"?type=tcp&security=reality"
            f"&pbk={pub_key}&sid={short_id}&sni={sni}&fp={fp}"
            f"{flow_part}#VLESS-REALITY"
        )
    return link


def _get_server_status_text() -> str:
    """Формирует текст статуса сервера для отправки в бот."""
    state = _load_state()
    hostname = ""
    try:
        hostname = _run(["hostname", "-s"], capture=True).stdout.strip()
    except Exception:
        pass

    # Статус Xray
    r = _run(["systemctl", "is-active", "xray"], capture=True)
    xray_status = "🟢 запущен" if r.stdout.strip() == "active" else "🔴 не запущен"

    # Аптайм
    uptime_str = ""
    try:
        r2 = _run(["uptime", "-p"], capture=True)
        uptime_str = r2.stdout.strip()
    except Exception:
        pass

    lines = [
        f"📊 <b>Статус сервера [{hostname}]</b>",
        f"",
        f"Xray: {xray_status}",
        f"Протокол: {state.get('protocol_mode', '?').upper()}",
        f"Порт: {state.get('server_port', '?')}",
        f"Режим: {state.get('install_mode', '?')}",
    ]
    if uptime_str:
        lines.append(f"Аптайм: {uptime_str}")
    lines.append(f"\n<i>{datetime.now().strftime('%d.%m.%Y %H:%M')}</i>")
    return "\n".join(lines)


def _generate_bot_script(bot_cfg: dict, notif_cfg: dict) -> str:
    """
    Генерирует Python-скрипт бота (long-polling, без внешних зависимостей).
    Скрипт запускается как systemd-сервис.
    """
    token        = bot_cfg.get("token") or notif_cfg.get("token", "")
    admin_id     = str(bot_cfg.get("admin_id") or notif_cfg.get("chat_id", ""))
    allowed      = json.dumps(bot_cfg.get("allowed_users", []))
    invite_tokens = json.dumps(bot_cfg.get("invite_tokens", {}))
    state_file   = str(_STATE_FILE)
    bot_file     = str(_BOT_FILE)

    return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# xray-tg-bot — auto-generated by vless-installer
# НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ — перегенерируется из меню установщика

import json, os, sys, time, re, subprocess, urllib.request, urllib.parse, urllib.error
from pathlib import Path
from datetime import datetime

TOKEN    = "{token}"
ADMIN_ID = "{admin_id}"
BOT_FILE = Path("{bot_file}")
STATE_F  = Path("{state_file}")
LOG_F    = Path("/var/log/vless-install.log")
OFFSET   = 0

def _log(msg):
    try:
        with LOG_F.open("a") as f:
            f.write(f"[{{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}}] [BOT] {{msg}}\\n")
    except Exception:
        pass

def _bot_load():
    try:
        return json.loads(BOT_FILE.read_text()) if BOT_FILE.exists() else {{}}
    except Exception:
        return {{}}

def _bot_save(cfg):
    BOT_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    BOT_FILE.chmod(0o600)

def _state():
    try:
        return json.loads(STATE_F.read_text()) if STATE_F.exists() else {{}}
    except Exception:
        return {{}}

def api(method, **params):
    """Вызов Telegram Bot API через urllib (нет зависимостей)."""
    url = f"https://api.telegram.org/bot{{TOKEN}}/{{method}}"
    data = urllib.parse.urlencode(params).encode()
    try:
        req = urllib.request.Request(url, data=data)
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())
    except Exception as e:
        _log(f"API error {{method}}: {{e}}")
        return {{}}

def send(chat_id, text, parse_mode="HTML"):
    api("sendMessage", chat_id=chat_id, text=text, parse_mode=parse_mode)

def is_admin(uid):
    return str(uid) == ADMIN_ID

def is_allowed(uid):
    cfg = _bot_load()
    allowed = cfg.get("allowed_users", [])
    return str(uid) in [str(x) for x in allowed] or is_admin(uid)

def get_vless_link(user_uuid=None):
    st = _state()
    domain    = st.get("domain", "")
    port      = st.get("server_port", 443)
    uuid_val  = user_uuid or st.get("uuid", "")
    proto     = st.get("protocol_mode", "reality")
    pub_key   = st.get("public_key", "")
    short_id  = st.get("short_id", "")
    fp        = st.get("fingerprint", "chrome") or "chrome"
    xtls_flow = st.get("xtls_flow", "xtls-rprx-vision") or ""
    xhttp_path = st.get("xhttp_path", "/")
    awg_exit  = st.get("awg_exit_enabled", False)
    mode      = st.get("install_mode", "A")
    sni = domain
    if proto == "reality" and awg_exit and mode == "B":
        sni = st.get("reality_dest", domain).split(":")[0]
    if not domain or not uuid_val:
        return ""
    if proto == "xhttp":
        return (f"vless://{{uuid_val}}@{{domain}}:{{port}}"
                f"?type=xhttp&security=tls&path={{xhttp_path}}"
                f"&sni={{sni}}&fp={{fp}}#VLESS-xHTTP")
    flow_part = f"&flow={{xtls_flow}}" if xtls_flow else ""
    return (f"vless://{{uuid_val}}@{{domain}}:{{port}}"
            f"?type=tcp&security=reality"
            f"&pbk={{pub_key}}&sid={{short_id}}&sni={{sni}}&fp={{fp}}"
            f"{{flow_part}}#VLESS-REALITY")

def get_status_text():
    st = _state()
    try:
        host = subprocess.check_output(["hostname", "-s"], text=True).strip()
    except Exception:
        host = "server"
    try:
        r = subprocess.run(["systemctl", "is-active", "xray"],
                           capture_output=True, text=True)
        xs = "🟢 запущен" if r.stdout.strip() == "active" else "🔴 не запущен"
    except Exception:
        xs = "❓ неизвестно"
    try:
        up = subprocess.check_output(["uptime", "-p"], text=True).strip()
    except Exception:
        up = ""
    ts = datetime.now().strftime("%d.%m.%Y %H:%M")
    return (f"📊 <b>Статус [{{host}}]</b>\\n\\n"
            f"Xray: {{xs}}\\n"
            f"Протокол: {{st.get('protocol_mode','?').upper()}}\\n"
            f"Порт: {{st.get('server_port','?')}}\\n"
            f"Режим: {{st.get('install_mode','?')}}\\n"
            + (f"Аптайм: {{up}}\\n" if up else "") +
            f"\\n<i>{{ts}}</i>")

def get_users_text():
    """Список пользователей Xray (из config.json)."""
    cfg_paths = [
        Path("/usr/local/etc/xray/config.json"),
        Path("/etc/xray/config.json"),
    ]
    for p in cfg_paths:
        if p.exists():
            try:
                cfg = json.loads(p.read_text())
                users = []
                for ib in cfg.get("inbounds", []):
                    for client in ib.get("settings", {{}}).get("clients", []):
                        email = client.get("email", "—")
                        uid   = client.get("id", "")[:8] + "..."
                        users.append(f"  • {{email}}  <code>{{uid}}</code>")
                if users:
                    return "👥 <b>Пользователи:</b>\\n" + "\\n".join(users)
            except Exception:
                pass
    return "Список пользователей недоступен"

def handle_start(msg, args):
    uid  = msg["from"]["id"]
    uname = msg["from"].get("username", str(uid))
    cfg = _bot_load()

    # Invite-токен
    if args:
        token_val = args[0]
        invites = cfg.get("invite_tokens", {{}})
        if token_val in invites:
            allowed = cfg.get("allowed_users", [])
            if uid not in allowed:
                allowed.append(uid)
                cfg["allowed_users"] = allowed
            del invites[token_val]
            cfg["invite_tokens"] = invites
            _bot_save(cfg)
            send(uid, f"✅ Вы авторизованы! Используйте /config для получения ссылки.")
            _log(f"User @{{uname}} ({{uid}}) authorized via invite token")
            return

    if is_admin(uid):
        send(uid, (
            "👋 <b>VLESS Admin Bot</b>\\n\\n"
            "Команды:\\n"
            "/config — ваша VLESS-ссылка\\n"
            "/status — статус сервера\\n"
            "/users  — список пользователей\\n"
            "/invite — сгенерировать invite-ссылку\\n"
            "/broadcast &lt;текст&gt; — разослать всем пользователям\\n"
            "/help   — справка"
        ))
    elif is_allowed(uid):
        send(uid, "👋 Привет! Используйте /config для получения вашей ссылки.")
    else:
        send(uid, (
            "👋 Для доступа запросите у администратора invite-ссылку.\\n"
            f"Ваш ID: <code>{{uid}}</code>"
        ))

def handle_config(msg):
    uid = msg["from"]["id"]
    if not is_allowed(uid):
        send(uid, "⛔ Нет доступа. Запросите invite-ссылку у администратора.")
        return
    link = get_vless_link()
    if not link:
        send(uid, "⚠️ Сервер ещё не настроен или конфиг недоступен.")
        return
    send(uid, (
        f"🔗 <b>Ваша VLESS-ссылка:</b>\\n\\n"
        f"<code>{{link}}</code>\\n\\n"
        f"Скопируйте и импортируйте в NekoBox / v2rayNG / Happ."
    ))
    _log(f"Config sent to user {{uid}}")

def handle_status(msg):
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    send(uid, get_status_text())

def handle_users(msg):
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    send(uid, get_users_text())

def handle_invite(msg):
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    cfg = _bot_load()
    invites = cfg.get("invite_tokens", {{}})
    import secrets as _sec
    tok = _sec.token_urlsafe(12)
    invites[tok] = {{"created": datetime.now().isoformat(), "by": uid}}
    cfg["invite_tokens"] = invites
    _bot_save(cfg)
    bot_info = api("getMe")
    bot_username = bot_info.get("result", {{}}).get("username", "YOUR_BOT")
    invite_link = f"https://t.me/{{bot_username}}?start={{tok}}"
    send(uid, (
        f"🔑 <b>Invite-ссылка создана:</b>\\n\\n"
        f"<code>{{invite_link}}</code>\\n\\n"
        f"Одноразовая. Отправьте пользователю."
    ))
    _log(f"Invite token created by admin {{uid}}: {{tok}}")

def handle_broadcast(msg, args):
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    if not args:
        send(uid, "Использование: /broadcast текст сообщения")
        return
    text = " ".join(args)
    cfg = _bot_load()
    allowed = cfg.get("allowed_users", [])
    ok = 0
    for u in allowed:
        try:
            send(u, f"📢 <b>Сообщение от администратора:</b>\\n\\n{{text}}")
            ok += 1
            time.sleep(0.05)
        except Exception:
            pass
    send(uid, f"✅ Разослано {{ok}} из {{len(allowed)}} пользователей.")
    _log(f"Broadcast by admin {{uid}}: {{text[:50]}}")

def handle_help(msg):
    uid = msg["from"]["id"]
    text = (
        "📖 <b>Справка</b>\\n\\n"
        "/start  — начало работы\\n"
        "/config — получить VLESS-ссылку\\n"
        "/help   — эта справка\\n"
    )
    if is_admin(uid):
        text += (
            "\\n<b>Только для администратора:</b>\\n"
            "/status    — статус сервера\\n"
            "/users     — список пользователей\\n"
            "/invite    — создать invite-ссылку\\n"
            "/broadcast — рассылка всем пользователям"
        )
    send(uid, text)

def process_update(update):
    msg = update.get("message") or update.get("edited_message")
    if not msg or "text" not in msg:
        return
    text  = msg["text"].strip()
    parts = text.split()
    cmd   = parts[0].split("@")[0].lower() if parts else ""
    args  = parts[1:]
    if cmd == "/start":   handle_start(msg, args)
    elif cmd == "/config": handle_config(msg)
    elif cmd == "/status": handle_status(msg)
    elif cmd == "/users":  handle_users(msg)
    elif cmd == "/invite": handle_invite(msg)
    elif cmd == "/broadcast": handle_broadcast(msg, args)
    elif cmd == "/help":   handle_help(msg)

def main():
    global OFFSET
    _log("Bot started")
    while True:
        try:
            r = api("getUpdates", offset=OFFSET, timeout=25, limit=10)
            for upd in r.get("result", []):
                OFFSET = upd["update_id"] + 1
                try:
                    process_update(upd)
                except Exception as e:
                    _log(f"Update error: {{e}}")
        except Exception as e:
            _log(f"Poll error: {{e}}")
            time.sleep(5)

if __name__ == "__main__":
    main()
'''


def _install_bot_service(bot_cfg: dict) -> bool:
    """Устанавливает systemd-сервис для бота."""
    notif_cfg = tg_load()
    script_content = _generate_bot_script(bot_cfg, notif_cfg)

    _BOT_SCRIPT.write_text(script_content)
    _BOT_SCRIPT.chmod(0o700)

    svc = (
        "[Unit]\n"
        "Description=VLESS Telegram Config Bot\n"
        "After=network.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/bin/python3 /usr/local/bin/xray-tg-bot.py\n"
        "Restart=always\n"
        "RestartSec=10\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _BOT_SVC.write_text(svc)
    _run(["systemctl", "daemon-reload"], quiet=True)
    _run(["systemctl", "enable", "xray-tg-bot"], quiet=True)
    r = _run(["systemctl", "restart", "xray-tg-bot"])
    time.sleep(2)
    return _bot_running()


def _stop_bot_service() -> None:
    _run(["systemctl", "stop", "xray-tg-bot"], quiet=True)
    _run(["systemctl", "disable", "xray-tg-bot"], quiet=True)
    _BOT_SCRIPT.unlink(missing_ok=True)
    _BOT_SVC.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"], quiet=True)


def _regenerate_bot() -> bool:
    """Перегенерирует скрипт бота (после смены токена/пользователей)."""
    bot_cfg  = _bot_load()
    notif_cfg = tg_load()
    if not (bot_cfg.get("token") or notif_cfg.get("token")):
        return False
    script_content = _generate_bot_script(bot_cfg, notif_cfg)
    _BOT_SCRIPT.write_text(script_content)
    _BOT_SCRIPT.chmod(0o700)
    if _bot_running():
        _run(["systemctl", "restart", "xray-tg-bot"], quiet=True)
        time.sleep(1)
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  МЕНЮ: Уведомления (оригинальная функциональность, без изменений интерфейса)
# ══════════════════════════════════════════════════════════════════════════════

def do_manage_telegram() -> None:
    """Меню настройки Telegram-уведомлений. Совместим с _core.py."""
    while True:
        os.system("clear")
        cfg = tg_load()
        token   = cfg.get("token", "")
        chat_id = cfg.get("chat_id", "")
        events  = cfg.get("events", {})
        configured = bool(token and chat_id)

        print()
        _box_top("🔔  Telegram-уведомления (admin)")
        _box_row(f"  Статус:  {''+GREEN+'НАСТРОЕН'+NC if configured else ''+YELLOW+'НЕ НАСТРОЕН'+NC}")
        if configured:
            _box_row(f"  Токен:   {DIM}{token[:10]}...{NC}")
            _box_row(f"  Chat ID: {CYAN}{chat_id}{NC}")
            _box_row(f"  {BOLD}Включённые события:{NC}")
            event_labels = {
                "xray_down":    "Xray упал / не отвечает",
                "xray_up":      "Xray восстановился",
                "cert_expire":  "Сертификат истекает (< 30 дней)",
                "traffic_limit":"Трафик пользователя превысил лимит",
                "health_report":"Ежедневный health-отчёт (08:00)",
                "node_down":    "Exit-нода недоступна",
                "port_blocked": "Порт заблокирован ТСПУ",
            }
            for ev, label in event_labels.items():
                en = events.get(ev, True)
                col = GREEN if en else DIM
                _box_row(f"    {col}{'✓' if en else '✗'}{NC} {label}")
        _box_sep()
        _box_item("1", f"{'Изменить' if configured else 'Настроить'} токен и Chat ID")
        _box_item("2", "Тест — отправить тестовое сообщение")
        _box_item("3", "Включить/выключить отдельные события")
        _box_item("4", "Установить cron-мониторинг Xray")
        _box_item("5", f"{RED}Отключить уведомления{NC} (удалить конфиг)")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return

        if ch == "1":
            print()
            new_token = input(f"  Bot Token (Enter = оставить): ").strip()
            if new_token:
                cfg["token"] = new_token
            new_chat = input(f"  Chat ID (Enter = оставить): ").strip()
            if new_chat:
                cfg["chat_id"] = new_chat
            if "events" not in cfg:
                cfg["events"] = {k: True for k in event_labels}
            tg_save(cfg)
            # Перегенерируем бот-скрипт если он настроен
            _regenerate_bot()
            _ok("Конфиг сохранён")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            if not cfg.get("token") or not cfg.get("chat_id"):
                _warn("Сначала настройте токен и Chat ID [1]")
            else:
                _info("Отправка тестового сообщения...")
                ok = tg_send(
                    "✅ <b>VLESS Installer</b>: тестовое сообщение. Уведомления работают!",
                    cfg["token"], cfg["chat_id"]
                )
                _ok("Сообщение отправлено!") if ok else _warn("Ошибка — проверьте токен и chat_id")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            ev_keys = ["xray_down","xray_up","cert_expire","traffic_limit",
                       "health_report","node_down","port_blocked"]
            ev_labels = [
                "Xray упал","Xray восстановился","Сертификат истекает",
                "Лимит трафика","Daily health-отчёт","Exit-нода недоступна",
                "Порт заблокирован ТСПУ",
            ]
            events = cfg.get("events", {k: True for k in ev_keys})
            print()
            _box_top("Уведомления — вкл/выкл событий")
            for i, (k, lbl) in enumerate(zip(ev_keys, ev_labels), 1):
                en = events.get(k, True)
                _box_item(f"{i}", f"{''+GREEN+'[ВКЛ]'+NC if en else ''+DIM+'[ВЫКЛ]'+NC} {lbl}")
            _box_back()
            _box_bottom()
            raw = input("  Номер для переключения (Enter = выход): ").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(ev_keys):
                k = ev_keys[int(raw)-1]
                events[k] = not events.get(k, True)
                cfg["events"] = events
                tg_save(cfg)
                _ok(f"{'Включено' if events[k] else 'Выключено'}: {ev_labels[int(raw)-1]}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            _install_monitor_cron()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            try:
                ans = input(f"  {RED}Удалить конфиг уведомлений? [y/N]:{NC} ").strip().lower()
            except KeyboardInterrupt:
                continue
            if ans == "y":
                _NOTIF_FILE.unlink(missing_ok=True)
                Path("/etc/cron.d/xray-tg-monitor").unlink(missing_ok=True)
                Path("/usr/local/bin/xray-tg-monitor.sh").unlink(missing_ok=True)
                _ok("Конфиг уведомлений удалён")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", "0", ""):
            return
        else:
            _warn("Неверный выбор")
            time.sleep(1)

# ══════════════════════════════════════════════════════════════════════════════
#  МЕНЮ: Пользовательский бот
# ══════════════════════════════════════════════════════════════════════════════

def do_tg_bot_menu() -> None:
    """Меню управления Telegram Config Bot."""

    while True:
        os.system("clear")
        bot_cfg   = _bot_load()
        notif_cfg = tg_load()
        running   = _bot_running()

        # Токен может быть в bot_cfg или взят из notif_cfg
        token     = bot_cfg.get("token") or notif_cfg.get("token", "")
        admin_id  = bot_cfg.get("admin_id") or notif_cfg.get("chat_id", "")
        allowed   = bot_cfg.get("allowed_users", [])
        invites   = bot_cfg.get("invite_tokens", {})

        configured = bool(token and admin_id)

        print()
        _box_top("🤖  TELEGRAM CONFIG BOT — раздача конфигов пользователям")
        _box_desc(
            "Пользователь пишет боту /config → получает свою VLESS-ссылку. "
            "Администратор управляет доступом через invite-токены."
        )
        _box_sep()
        _box_row(f"  Статус бота:      {''+GREEN+'ЗАПУЩЕН'+NC if running else ''+DIM+'ОСТАНОВЛЕН'+NC}")
        _box_row(f"  Конфиг:           {''+GREEN+'НАСТРОЕН'+NC if configured else ''+YELLOW+'НЕ НАСТРОЕН'+NC}")
        if configured:
            _box_row(f"  Токен:            {DIM}{token[:10]}...{NC}")
            _box_row(f"  Admin Chat ID:    {CYAN}{admin_id}{NC}")
            _box_row(f"  Авторизовано:     {CYAN}{len(allowed)}{NC} пользователей")
            if invites:
                _box_row(f"  Активных invite:  {YELLOW}{len(invites)}{NC}")
        _box_sep()
        if not configured:
            _box_item("1", f"Настроить бота (токен + admin ID)")
        else:
            _box_item("1", f"Изменить настройки")
            if running:
                _box_item("2", f"Перезапустить бота")
                _box_item("3", f"{RED}Остановить бота{NC}")
            else:
                _box_item("2", f"{GREEN}Запустить бота{NC}")
            _box_item("4", f"Создать invite-ссылку для пользователя")
            _box_item("5", f"Список авторизованных пользователей")
            _box_item("6", f"Удалить пользователя из списка")
            _box_item("7", f"Проверить статус сервиса")
        _box_sep()
        _box_info("Бот работает как systemd-сервис xray-tg-bot")
        _box_info("Токен: @BotFather → /newbot")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return

        if ch == "1":
            _menu_bot_configure(bot_cfg, notif_cfg)
        elif ch == "2" and configured:
            if running:
                _info("Перезапускаю...")
                _run(["systemctl", "restart", "xray-tg-bot"], quiet=True)
                time.sleep(2)
                _ok("Перезапущен") if _bot_running() else _warn("Не запустился — см. journalctl -u xray-tg-bot")
            else:
                _menu_bot_start(bot_cfg)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3" and configured and running:
            _menu_bot_stop()
        elif ch == "4" and configured:
            _menu_bot_invite(bot_cfg, token, admin_id)
        elif ch == "5" and configured:
            _menu_bot_list_users(bot_cfg)
        elif ch == "6" and configured:
            _menu_bot_remove_user(bot_cfg)
        elif ch == "7" and configured:
            _menu_bot_svc_status()
        elif ch in ("q", "Q", "0", ""):
            return
        else:
            _warn("Неверный выбор")
            time.sleep(1)


def _menu_bot_configure(bot_cfg: dict, notif_cfg: dict) -> None:
    """Настройка токена и admin ID."""
    os.system("clear")
    print()
    _box_top("🤖  Настройка Telegram Bot")
    _box_desc(
        "Создайте бота через @BotFather (/newbot). "
        "Если токен тот же что для уведомлений — можно использовать один бот. "
        "Admin Chat ID — ваш личный Telegram ID (узнать: @userinfobot)."
    )
    _box_sep()
    cur_token    = bot_cfg.get("token") or notif_cfg.get("token", "")
    cur_admin_id = bot_cfg.get("admin_id") or notif_cfg.get("chat_id", "")
    if cur_token:
        _box_row(f"  Текущий токен:    {DIM}{cur_token[:10]}...{NC}")
    if cur_admin_id:
        _box_row(f"  Текущий admin ID: {CYAN}{cur_admin_id}{NC}")
    _box_bottom()
    print()

    try:
        new_token = input(f"  Bot Token [{DIM}Enter = оставить{NC}]: ").strip()
        new_admin = input(f"  Admin Chat ID [{DIM}Enter = оставить{NC}]: ").strip()
    except KeyboardInterrupt:
        return

    if new_token:
        bot_cfg["token"] = new_token
    elif cur_token and not bot_cfg.get("token"):
        bot_cfg["token"] = cur_token

    if new_admin:
        bot_cfg["admin_id"] = new_admin
    elif cur_admin_id and not bot_cfg.get("admin_id"):
        bot_cfg["admin_id"] = cur_admin_id

    if not bot_cfg.get("token") or not bot_cfg.get("admin_id"):
        _warn("Токен и Admin ID обязательны")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    _bot_save(bot_cfg)

    # Синхронизируем токен в уведомлениях если это тот же токен
    if bot_cfg["token"] == notif_cfg.get("token") or not notif_cfg.get("token"):
        notif_cfg["token"]   = bot_cfg["token"]
        notif_cfg["chat_id"] = bot_cfg["admin_id"]
        tg_save(notif_cfg)

    print()
    _info("Устанавливаю systemd-сервис бота...")
    if _install_bot_service(bot_cfg):
        _ok("Бот запущен!")
        print()
        # Проверяем токен через getMe
        r = _run([
            "curl", "-s", "-m", "10",
            f"https://api.telegram.org/bot{bot_cfg['token']}/getMe"
        ], capture=True)
        try:
            data = json.loads(r.stdout)
            if data.get("ok"):
                uname = data["result"].get("username", "")
                _ok(f"Бот: @{uname}")
                _box_top("📋  Готово!")
                _box_row(f"  Ссылка на бота: {CYAN}https://t.me/{uname}{NC}")
                _box_info(f"Напишите боту /start для проверки")
                _box_info(f"Admin Chat ID {bot_cfg['admin_id']} имеет полный доступ")
                _box_bottom()
            else:
                _warn("Бот запущен, но токен может быть неверным")
        except Exception:
            _ok("Бот запущен (не удалось проверить токен)")
    else:
        _err("Бот не запустился — проверьте journalctl -u xray-tg-bot")

    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_bot_start(bot_cfg: dict) -> None:
    _info("Запускаю бота...")
    if _install_bot_service(bot_cfg):
        _ok("Бот запущен")
    else:
        _err("Не удалось запустить — проверьте journalctl -u xray-tg-bot")


def _menu_bot_stop() -> None:
    try:
        ans = input(f"  {YELLOW}Остановить бота? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return
    if ans == "y":
        _stop_bot_service()
        _ok("Бот остановлен и удалён из автозапуска")
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_bot_invite(bot_cfg: dict, token: str, admin_id: str) -> None:
    """Создаёт одноразовый invite-токен и показывает ссылку."""
    # Получаем username бота
    bot_username = ""
    try:
        r = _run([
            "curl", "-s", "-m", "10",
            f"https://api.telegram.org/bot{token}/getMe"
        ], capture=True)
        data = json.loads(r.stdout)
        if data.get("ok"):
            bot_username = data["result"].get("username", "")
    except Exception:
        pass

    tok = secrets.token_urlsafe(12)
    invites = bot_cfg.get("invite_tokens", {})
    invites[tok] = {"created": datetime.now().isoformat(), "by": "admin_menu"}
    bot_cfg["invite_tokens"] = invites
    _bot_save(bot_cfg)
    _regenerate_bot()

    print()
    _ok(f"Invite-токен создан")
    print()
    if bot_username:
        invite_link = f"https://t.me/{bot_username}?start={tok}"
        _box_top("📋  Invite-ссылка")
        _box_row(f"  {CYAN}{invite_link}{NC}")
        _box_info("Одноразовая — после использования удаляется")
        _box_info("Отправьте пользователю — он нажмёт и получит доступ к /config")
        _box_bottom()
    else:
        _box_top("📋  Invite-токен")
        _box_row(f"  Токен: {CYAN}{tok}{NC}")
        _box_info("Пользователь должен написать боту: /start <токен>")
        _box_bottom()

    # Уведомляем себя в TG
    if bot_username:
        tg_send(
            f"🔑 <b>Новая invite-ссылка создана:</b>\n\nhttps://t.me/{bot_username}?start={tok}",
            token, admin_id
        )

    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_bot_list_users(bot_cfg: dict) -> None:
    os.system("clear")
    print()
    allowed = bot_cfg.get("allowed_users", [])
    _box_top("👥  Авторизованные пользователи")
    if not allowed:
        _box_row(f"  {DIM}(пусто){NC}")
    else:
        for i, uid in enumerate(allowed, 1):
            _box_row(f"  {i}. {CYAN}{uid}{NC}")
    _box_bottom()
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_bot_remove_user(bot_cfg: dict) -> None:
    allowed = bot_cfg.get("allowed_users", [])
    if not allowed:
        _warn("Список пользователей пуст")
        time.sleep(1)
        return
    print()
    _box_top("Удалить пользователя")
    for i, uid in enumerate(allowed, 1):
        _box_row(f"  {i}. {uid}")
    _box_back()
    _box_bottom()
    try:
        raw = input(f"  Номер (Enter = отмена): ").strip()
    except KeyboardInterrupt:
        return
    if raw.isdigit() and 1 <= int(raw) <= len(allowed):
        removed = allowed.pop(int(raw)-1)
        bot_cfg["allowed_users"] = allowed
        _bot_save(bot_cfg)
        _regenerate_bot()
        _ok(f"Удалён: {removed}")
    time.sleep(1)


def _menu_bot_svc_status() -> None:
    os.system("clear")
    print()
    _box_top("🔍  Статус сервиса xray-tg-bot")
    _box_bottom()
    print()
    _run(["systemctl", "status", "xray-tg-bot", "--no-pager", "-l"])
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


# ── Алиасы для обратной совместимости с _core.py ──────────────────────────────
# В _core.py достаточно заменить:
#   from vless_installer.modules.tg_bot import (
#       tg_load as _tg_load, tg_save as _tg_save,
#       tg_send, tg_notify_event as _tg_notify_event,
#       do_manage_telegram,
#   )
# И убрать дублирующиеся определения TG_CONFIG_FILE/_tg_load/_tg_save/tg_send/_tg_notify_event

TG_CONFIG_FILE = _NOTIF_FILE  # совместимость
_tg_load       = tg_load
_tg_save       = tg_save
_tg_notify_event = tg_notify_event
