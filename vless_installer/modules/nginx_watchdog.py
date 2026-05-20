"""
vless_installer/modules/nginx_watchdog.py
───────────────────────────────────────────────────────────────────────────────
Watchdog для nginx — аналог xray-watchdog.timer, который уже есть в проекте.

Зачем: Xray живёт, но nginx упал (OOM / истёк сертификат / обновление systemd)
→ клиенты получают EOF на Reality unix-socket.

Systemd timer каждые 2 минуты:
  • Проверяет systemctl is-active nginx
  • Fallback: curl 127.0.0.1 (на случай рассинхрона systemd)
  • Перезапускает nginx при падении
  • В Reality-режиме: systemctl reload xray (пересоздание unix-socket)
  • Telegram-уведомление если настроен tg_bot_token в state.json

Точки входа из _core.py:
    from vless_installer.modules.nginx_watchdog import (
        nginx_watchdog_install, nginx_watchdog_remove, do_manage_nginx_watchdog,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m', NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'], _C['BOLD'], _C['DIM'], _C['NC'],
)

# ── Пути ──────────────────────────────────────────────────────────────────────
_SCRIPT   = Path('/usr/local/bin/nginx-watchdog.sh')
_SERVICE  = Path('/etc/systemd/system/nginx-watchdog.service')
_TIMER    = Path('/etc/systemd/system/nginx-watchdog.timer')
_LOG      = Path('/var/log/nginx-watchdog.log')
_LOGROTATE = Path('/etc/logrotate.d/nginx-watchdog')
_STATE    = Path('/var/lib/xray-installer/state.json')


# ── Внутренние хелперы ────────────────────────────────────────────────────────
def _ok(msg: str)   -> None: print(f'  {GREEN}✓{NC} {msg}')
def _warn(msg: str) -> None: print(f'  {YELLOW}⚠{NC}  {msg}')
def _info(msg: str) -> None: print(f'  {CYAN}•{NC} {msg}')

def _run(cmd: list) -> int:
    return subprocess.run(cmd, capture_output=True).returncode

def _protocol_mode() -> str:
    try:
        return json.loads(_STATE.read_text()).get('protocol_mode', 'reality')
    except Exception:
        return 'reality'

def _is_active(unit: str) -> bool:
    r = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True)
    return r.stdout.strip() == 'active'

def _is_enabled(unit: str) -> bool:
    r = subprocess.run(['systemctl', 'is-enabled', unit], capture_output=True, text=True)
    return 'enabled' in r.stdout


# ── Генерация скрипта ─────────────────────────────────────────────────────────
def _build_watchdog_script() -> str:
    mode = _protocol_mode()
    xray_reload = ''
    if mode == 'reality':
        xray_reload = textwrap.dedent("""\
            # Reality: nginx перезапустился — пересоздаём unix-socket xray
            systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null
        """)

    return textwrap.dedent(f"""\
        #!/bin/bash
        # nginx-watchdog.sh — VLESS Ultimate Installer
        # Автоматически создан. Управляется через меню установщика.
        LOG="{_LOG}"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')

        _notify_tg() {{
            local MSG="$1"
            local STATE="{_STATE}"
            [[ ! -f "$STATE" ]] && return
            BOT=$(python3 -c "import json; d=json.load(open('$STATE')); print(d.get('tg_bot_token',''))" 2>/dev/null)
            CID=$(python3 -c "import json; d=json.load(open('$STATE')); print(d.get('tg_chat_id',''))"   2>/dev/null)
            [[ -z "$BOT" || -z "$CID" ]] && return
            curl -s -X POST "https://api.telegram.org/bot${{BOT}}/sendMessage" \\
                --data-urlencode "chat_id=${{CID}}" \\
                --data-urlencode "text=${{MSG}}" \\
                --data-urlencode "parse_mode=HTML" >/dev/null 2>&1
        }}

        # Проверка 1: systemd
        STATUS=$(systemctl is-active nginx 2>/dev/null)
        [[ "$STATUS" == "active" ]] && exit 0

        # Проверка 2: curl fallback (рассинхрон systemd)
        HTTP=$(curl -s -o /dev/null -w "%{{http_code}}" --max-time 3 http://127.0.0.1/ 2>/dev/null || true)
        [[ "$HTTP" =~ ^[2-4] ]] && exit 0

        echo "[$DATE] WARN nginx упал (status=$STATUS http=$HTTP) — перезапуск" >> "$LOG"
        systemctl restart nginx 2>&1 | tee -a "$LOG"
        sleep 3

        STATUS2=$(systemctl is-active nginx 2>/dev/null)
        if [[ "$STATUS2" == "active" ]]; then
            echo "[$DATE] OK nginx перезапущен" >> "$LOG"
            _notify_tg "🔄 nginx-watchdog: nginx перезапущен на $(hostname)"
            {xray_reload}
        else
            echo "[$DATE] ERROR nginx не поднялся" >> "$LOG"
            _notify_tg "🚨 nginx-watchdog: nginx НЕ запустился на $(hostname)"
            journalctl -u nginx -n 20 --no-pager >> "$LOG" 2>/dev/null
        fi
    """)


# ── Публичный API ─────────────────────────────────────────────────────────────
def nginx_watchdog_install() -> None:
    """Устанавливает nginx watchdog: скрипт + systemd timer (каждые 2 минуты)."""
    _SCRIPT.write_text(_build_watchdog_script())
    _SCRIPT.chmod(0o755)

    _SERVICE.write_text(textwrap.dedent(f"""\
        [Unit]
        Description=nginx Watchdog (VLESS Ultimate)
        After=nginx.service

        [Service]
        Type=oneshot
        ExecStart={_SCRIPT}
        StandardOutput=append:{_LOG}
        StandardError=append:{_LOG}
    """))

    _TIMER.write_text(textwrap.dedent("""\
        [Unit]
        Description=nginx Watchdog Timer (VLESS Ultimate)
        After=nginx.service

        [Timer]
        OnBootSec=90
        OnUnitActiveSec=2min
        AccuracySec=30

        [Install]
        WantedBy=timers.target
    """))

    _LOGROTATE.write_text(textwrap.dedent(f"""\
        {_LOG} {{
            daily
            rotate 7
            compress
            delaycompress
            missingok
            notifempty
            create 0640 root root
        }}
    """))

    _run(['systemctl', 'daemon-reload'])
    _run(['systemctl', 'enable', '--now', 'nginx-watchdog.timer'])
    _ok('nginx-watchdog.timer установлен (каждые 2 минуты)')
    _info(f'Лог: {_LOG}')


def nginx_watchdog_remove() -> None:
    """Удаляет nginx watchdog."""
    _run(['systemctl', 'disable', '--now', 'nginx-watchdog.timer'])
    for f in (_TIMER, _SERVICE, _SCRIPT, _LOGROTATE):
        f.unlink(missing_ok=True)
    _run(['systemctl', 'daemon-reload'])
    _ok('nginx-watchdog удалён')


def do_manage_nginx_watchdog() -> None:
    """Интерактивное меню управления nginx watchdog."""
    import os
    while True:
        os.system('clear')
        active  = _is_active('nginx-watchdog.timer')
        enabled = _is_enabled('nginx-watchdog.timer')

        status_str = f'{GREEN}активен{NC}' if active else f'{YELLOW}не активен{NC}'
        print()
        print(f'  {CYAN}{"═"*54}{NC}')
        print(f'  {CYAN}  🔁 NGINX WATCHDOG{NC}')
        print(f'  {CYAN}{"─"*54}{NC}')
        print(f'  Статус:  {status_str}')
        print(f'  Таймер:  {"enabled" if enabled else "disabled"}')
        print(f'  Режим:   {_protocol_mode()}')
        print()

        if _LOG.exists():
            lines = _LOG.read_text(errors='replace').splitlines()[-6:]
            if lines:
                print(f'  {DIM}Последние события:{NC}')
                for line in lines:
                    print(f'    {DIM}{line[:72]}{NC}')
                print()

        print(f'  {CYAN}{"─"*54}{NC}')
        if active:
            print(f'  1. Отключить watchdog')
        else:
            print(f'  1. Включить watchdog (timer каждые 2 минуты)')
        print(f'  2. Запустить проверку вручную прямо сейчас')
        print(f'  3. Показать полный лог')
        print(f'  Q. Назад')
        print(f'  {CYAN}{"═"*54}{NC}')
        print()

        try:
            ch = input(f'  {CYAN}Выбор:{NC} ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if ch == '1':
            if active:
                nginx_watchdog_remove()
            else:
                nginx_watchdog_install()
            input(f'  {CYAN}Нажмите Enter...{NC}')

        elif ch == '2':
            if _SCRIPT.exists():
                subprocess.run(['bash', str(_SCRIPT)])
            else:
                _warn('Watchdog не установлен')
            input(f'  {CYAN}Нажмите Enter...{NC}')

        elif ch == '3':
            print()
            if _LOG.exists():
                print(_LOG.read_text(errors='replace')[-4000:])
            else:
                _warn('Лог пуст или не создан')
            input(f'  {CYAN}Нажмите Enter...{NC}')

        elif ch in ('q', ''):
            break
