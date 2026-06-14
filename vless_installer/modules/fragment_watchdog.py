"""
vless_installer/modules/fragment_watchdog.py
───────────────────────────────────────────────────────────────────────────────
Watchdog автопереключения пресетов фрагментации (пункт 3).

Мониторит /var/log/xray/error.log в фоне. Если за скользящее окно
в 5 минут число RST-сбросов или таймаутов превышает порог —
автоматически переключается на более агрессивный пресет фрагментации
и пишет событие в /var/log/vless-fragment-watchdog.log.

Работает как systemd-сервис vless-fragment-watchdog.service.
Управление: запуск, остановка, статус, просмотр лога.

ВАЖНО: серверный /etc/xray/config.json не затрагивается.
Watchdog переключает только КЛИЕНТСКИЕ конфиги в
/var/lib/xray-installer/fragment_configs/.

Публичное API:
    do_fragment_watchdog_menu()  → Меню 4 → F8
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────
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

# ── Логирование ────────────────────────────────────────────────────────────
_LOG_FILE      = Path("/var/log/vless-install.log")
_WATCHDOG_LOG  = Path("/var/log/vless-fragment-watchdog.log")
_STATE_FILE    = Path("/var/lib/xray-installer/state.json")
_XRAY_LOG      = Path("/var/log/xray/error.log")
_WATCHDOG_STATE = Path("/var/lib/xray-installer/watchdog_state.json")
_SERVICE_NAME  = "vless-fragment-watchdog"
_SCRIPT_PATH   = Path("/usr/local/bin/vless_fragment_watchdog.py")

def _log(level: str, msg: str) -> None:
    try:
        import re as _re
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] [WATCHDOG] [{level}] {_re.sub(chr(27)+'[0-9;]*m','',msg)}\n")
    except Exception:
        pass

def _info(msg): print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def _ok(msg):   print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg): print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)

# ── Импорты ────────────────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn, _box_desc, _get_box_width,
)

# ── Последовательность эскалации пресетов ─────────────────────────────────
# При срабатывании watchdog переключается на следующий по списку
_ESCALATION = [
    {"name": "Лёгкая",          "packets": "1-2", "length": "5-15",  "interval": "20-50"},
    {"name": "Средняя",         "packets": "1-3", "length": "3-7",   "interval": "10-20"},
    {"name": "Агрессивная",     "packets": "1-3", "length": "1-3",   "interval": "5-10"},
    {"name": "Ультра-агрессив", "packets": "1-3", "length": "1-1",   "interval": "5-10"},
]

# ── Генерация скрипта watchdog ─────────────────────────────────────────────
_WATCHDOG_SCRIPT = '''#!/usr/bin/env python3
"""
vless_fragment_watchdog.py — фоновый демон автопереключения пресетов.
Устанавливается в /usr/local/bin/ и запускается как systemd-сервис.
"""
import json, re, time, subprocess, sys
from pathlib import Path
from datetime import datetime

XRAY_LOG       = Path("/var/log/xray/error.log")
WATCHDOG_LOG   = Path("/var/log/vless-fragment-watchdog.log")
STATE_FILE     = Path("/var/lib/xray-installer/watchdog_state.json")
FRAGMENT_DIR   = Path("/var/lib/xray-installer/fragment_configs")
CHECK_INTERVAL = 60        # секунд между проверками
WINDOW_MINUTES = 5         # скользящее окно анализа
RST_THRESHOLD  = 10        # RST/таймаутов за окно → переключить пресет

ESCALATION = {json_escalation}

RE_BAD = re.compile(
    r"connection reset|rst|connection.*refused|broken pipe|"
    r"i/o timeout|context deadline|read tcp",
    re.I
)

def wlog(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{{ts}}] {{msg}}\\n"
    try:
        WATCHDOG_LOG.parent.mkdir(parents=True, exist_ok=True)
        with WATCHDOG_LOG.open("a") as f:
            f.write(line)
    except Exception:
        pass
    print(line, end="", flush=True)

def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    except Exception:
        return {}

def save_state(s: dict) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(s, ensure_ascii=False, indent=2))
    except Exception:
        pass

def count_bad_events(since_ts: float) -> int:
    """Считает RST/таймауты в xray error.log начиная с since_ts."""
    if not XRAY_LOG.exists():
        return 0
    count = 0
    try:
        with XRAY_LOG.open("r", errors="replace") as f:
            f.seek(max(0, XRAY_LOG.stat().st_size - 200_000))
            for line in f:
                if RE_BAD.search(line):
                    count += 1
    except Exception:
        pass
    return count

def get_current_preset_idx(state: dict) -> int:
    return state.get("watchdog_preset_idx", 0)

def apply_preset(idx: int) -> bool:
    """Применяет пресет: перегенерирует рекомендованный конфиг."""
    if idx >= len(ESCALATION):
        return False
    preset = ESCALATION[idx]
    try:
        sys.path.insert(0, "/home/inferno1978/VLESS-Ultimate-Installer")
        sys.path.insert(0, "/opt/vless-ultimate")
        from vless_installer.modules.fragment_config import generate_fragment_client_config
        path = generate_fragment_client_config(
            packets=preset["packets"],
            length=preset["length"],
            interval=preset["interval"],
            label="fragment_recommended",
        )
        if path:
            wlog(f"[SWITCH] Пресет → {{preset['name']}} "
                 f"(length={{preset['length']}} interval={{preset['interval']}}мс) "
                 f"→ {{path}}")
            return True
    except Exception as e:
        wlog(f"[ERROR] Не удалось применить пресет: {{e}}")
    return False

def main() -> None:
    wlog("[START] Watchdog запущен")
    state    = load_state()
    prev_bad = count_bad_events(time.time() - WINDOW_MINUTES * 60)
    baseline = prev_bad

    while True:
        time.sleep(CHECK_INTERVAL)
        now     = time.time()
        cur_bad = count_bad_events(now - WINDOW_MINUTES * 60)
        delta   = cur_bad - baseline

        if delta >= RST_THRESHOLD:
            idx = get_current_preset_idx(state)
            next_idx = min(idx + 1, len(ESCALATION) - 1)
            wlog(f"[ALERT] RST/timeout за {WINDOW_MINUTES} мин: {{delta}} >= {{RST_THRESHOLD}}")
            if next_idx != idx:
                if apply_preset(next_idx):
                    state["watchdog_preset_idx"] = next_idx
                    save_state(state)
                else:
                    wlog("[WARN] Не удалось применить следующий пресет")
            else:
                wlog("[WARN] Уже на максимальном пресете")
            baseline = cur_bad  # сброс базовой линии после переключения

        baseline = cur_bad  # обновляем каждую итерацию

if __name__ == "__main__":
    main()
'''

# ── systemd unit ──────────────────────────────────────────────────────────
_SYSTEMD_UNIT = """[Unit]
Description=VLESS Fragment Watchdog — auto-switching fragmentation presets
After=network.target xray.service
Wants=xray.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/vless_fragment_watchdog.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

# ── Установка/удаление сервиса ────────────────────────────────────────────

def _install_watchdog() -> bool:
    """Устанавливает скрипт и systemd unit, запускает сервис."""
    import json as _json
    script_content = _WATCHDOG_SCRIPT.replace(
        "{json_escalation}",
        _json.dumps(_ESCALATION, ensure_ascii=False)
    )
    try:
        _SCRIPT_PATH.write_text(script_content)
        _SCRIPT_PATH.chmod(0o755)
        _ok(f"Скрипт: {_SCRIPT_PATH}")
    except Exception as e:
        _warn(f"Не удалось записать скрипт: {e}")
        return False

    unit_path = Path(f"/etc/systemd/system/{_SERVICE_NAME}.service")
    try:
        unit_path.write_text(_SYSTEMD_UNIT)
        _ok(f"Unit: {unit_path}")
    except Exception as e:
        _warn(f"Не удалось записать unit: {e}")
        return False

    for cmd in [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", _SERVICE_NAME],
        ["systemctl", "restart", _SERVICE_NAME],
    ]:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            _warn(f"Ошибка: {' '.join(cmd)}: {r.stderr.strip()[:100]}")
            return False

    _ok(f"Сервис {_SERVICE_NAME} запущен")
    _log("INFO", "Fragment watchdog installed and started")
    return True


def _remove_watchdog() -> bool:
    """Останавливает и удаляет watchdog."""
    for cmd in [
        ["systemctl", "stop",    _SERVICE_NAME],
        ["systemctl", "disable", _SERVICE_NAME],
    ]:
        subprocess.run(cmd, capture_output=True)

    for p in [
        _SCRIPT_PATH,
        Path(f"/etc/systemd/system/{_SERVICE_NAME}.service"),
    ]:
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass

    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    _ok("Watchdog остановлен и удалён")
    _log("INFO", "Fragment watchdog removed")
    return True


def _watchdog_status() -> str:
    r = subprocess.run(
        ["systemctl", "is-active", _SERVICE_NAME],
        capture_output=True, text=True,
    )
    return r.stdout.strip()


def _show_watchdog_log(lines: int = 30) -> None:
    if not _WATCHDOG_LOG.exists():
        print(f"  {DIM}Лог пуст{NC}")
        return
    all_lines = _WATCHDOG_LOG.read_text(errors="replace").splitlines()
    for line in all_lines[-lines:]:
        if "[SWITCH]" in line:
            print(f"  {YELLOW}{line}{NC}")
        elif "[ALERT]" in line:
            print(f"  {RED}{line}{NC}")
        elif "[START]" in line:
            print(f"  {GREEN}{line}{NC}")
        else:
            print(f"  {DIM}{line}{NC}")


def do_fragment_watchdog_menu() -> None:
    """
    Управление watchdog автопереключения пресетов.
    Вызывается из _menu_diagnostics() (пункт F8).
    """
    while True:
        os.system("clear")
        print()
        status = _watchdog_status()
        status_str = (f"{GREEN}● активен{NC}" if status == "active"
                      else f"{RED}○ неактивен{NC}")

        _box_top("🔄  WATCHDOG АВТОПЕРЕКЛЮЧЕНИЯ ПРЕСЕТОВ")
        _box_desc(
            "Мониторит соединения. При росте RST-сбросов "
            "автоматически переключается на более агрессивный пресет. "
            "Работает как системный сервис в фоне."
        )
        _box_sep()
        _box_row(f"  Статус: {status_str}")
        _box_sep()
        _box_row()
        if status == "active":
            _box_item("1", f"⏹  Остановить и удалить watchdog")
            _box_item("2", f"📋 Просмотр лога переключений")
            _box_item("3", f"↺  Сбросить на начальный пресет")
        else:
            _box_item("1", f"▶  Установить и запустить watchdog")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "q" or ch == "":
            break

        if status == "active":
            if ch == "1":
                _remove_watchdog()
                time.sleep(1)
            elif ch == "2":
                print()
                _box_top(f"📋  Последние события watchdog")
                _show_watchdog_log(40)
                _box_bottom()
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "3":
                state = {}
                _WATCHDOG_STATE.write_text(json.dumps(state))
                _ok("Пресет сброшен на начальный")
                time.sleep(1)
        else:
            if ch == "1":
                print()
                _info("Устанавливаю watchdog...")
                _info(f"Порог RST: 10 за 5 минут → переключение пресета")
                _info(f"Эскалация: Лёгкая → Средняя → Агрессивная → Ультра")
                print()
                if _install_watchdog():
                    _ok("Watchdog активен — мониторинг запущен")
                    # Ждём пока systemd переведёт сервис в active
                    for _ in range(10):
                        time.sleep(1)
                        if _watchdog_status() == "active":
                            break
                else:
                    time.sleep(2)
