"""
cold_boot_restore.py — восстановление после перезагрузки сервера.

После `reboot` теряются:
  1. Telemt tproxy: iptables-правила и dokodemo-door inbound в xray config
  2. nginx Unix-сокет: xray пересоздаёт сокет при старте, nginx держит старый путь

Этот модуль вызывается из systemd ExecStartPost xray.service (устанавливается
функцией install_cold_boot_restore()) и восстанавливает оба компонента автоматически.

Публичный API:
    run_cold_boot_restore()         — точка входа для systemd/cron
    install_cold_boot_restore()     — установить хук в xray.service
    uninstall_cold_boot_restore()   — удалить хук из xray.service
    do_cold_boot_menu()             — интерактивное меню
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

# ── Константы ─────────────────────────────────────────────────────────────────
RESTORE_SCRIPT   = Path("/usr/local/bin/xray-cold-boot-restore.sh")
SYSTEMD_OVERRIDE = Path("/etc/systemd/system/xray.service.d/cold-boot-restore.conf")
STATE_FILE       = Path("/var/lib/xray-installer/state.json")

# ── Цвета ─────────────────────────────────────────────────────────────────────
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
NC     = "\033[0m"

# ── Скрипт восстановления (запускается systemd после старта xray) ─────────────
_RESTORE_SCRIPT_CONTENT = """\
#!/bin/bash
# xray-cold-boot-restore.sh — вызывается systemd после старта xray.service
# Восстанавливает Telemt tproxy и nginx Unix-сокет.

INSTALLER_DIR="$(dirname "$(realpath "$0")")"
LOG="/var/log/xray-cold-boot-restore.log"
STATE="/var/lib/xray-installer/state.json"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; }

log "=== cold-boot-restore: старт ==="

# Ждём пока xray полностью запустится
sleep 3

# ── 1. Восстановление nginx Unix-сокет ───────────────────────────────────────
# Читаем PARAM_SOCKET_PATH из state.json
SOCKET_PATH=""
if [ -f "$STATE" ]; then
    SOCKET_PATH=$(python3 -c "
import json, sys
try:
    d = json.load(open('$STATE'))
    print(d.get('PARAM_SOCKET_PATH', ''))
except Exception:
    print('')
" 2>/dev/null)
fi

PROTOCOL_MODE=""
if [ -f "$STATE" ]; then
    PROTOCOL_MODE=$(python3 -c "
import json, sys
try:
    d = json.load(open('$STATE'))
    print(d.get('PROTOCOL_MODE', 'reality'))
except Exception:
    print('reality')
" 2>/dev/null)
fi

AWG_EXIT=$(python3 -c "
import json, sys
try:
    d = json.load(open('$STATE'))
    print('1' if d.get('AWG_EXIT_ENABLED') else '0')
except Exception:
    print('0')
" 2>/dev/null 2>/dev/null)

if [ "$PROTOCOL_MODE" = "reality" ] && [ -n "$SOCKET_PATH" ] && [ "$AWG_EXIT" = "0" ]; then
    # Ждём пока xray создаст Unix-сокет (до 20 сек)
    for i in $(seq 1 20); do
        if [ -S "$SOCKET_PATH" ]; then
            break
        fi
        sleep 1
    done

    if systemctl is-active --quiet nginx; then
        sudo systemctl restart nginx
        log "nginx перезапущен (Unix-сокет: $SOCKET_PATH)"
    fi
fi

# ── 2. Восстановление Telemt tproxy ──────────────────────────────────────────
# Проверяем установлен ли Telemt (наличие сервиса)
if systemctl list-unit-files mtproxy.service &>/dev/null 2>&1 || \\
   systemctl list-unit-files telemt.service &>/dev/null 2>&1; then
    python3 -c "
import sys
sys.path.insert(0, '/usr/local/lib/vless-installer')
try:
    from vless_installer.modules.mtproto import telemt_tproxy_emergency_restore
    ok, msg = telemt_tproxy_emergency_restore()
    print(f'Telemt tproxy: {msg}')
except Exception as e:
    print(f'Telemt tproxy restore error: {e}')
" >> "$LOG" 2>&1
fi

log "=== cold-boot-restore: завершён ==="
"""

# ── systemd override (ExecStartPost) ─────────────────────────────────────────
_SYSTEMD_OVERRIDE_CONTENT = """\
[Service]
ExecStartPost=/usr/local/bin/xray-cold-boot-restore.sh
"""


# ── Вспомогательные ───────────────────────────────────────────────────────────

def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _is_installed() -> bool:
    return RESTORE_SCRIPT.exists() and SYSTEMD_OVERRIDE.exists()


# ── Публичный API ─────────────────────────────────────────────────────────────

def install_cold_boot_restore() -> tuple[bool, str]:
    """
    Устанавливает скрипт восстановления и systemd override для xray.service.
    Возвращает (True, msg) или (False, msg).
    """
    try:
        # Находим путь установки vless-installer
        installer_path = _find_installer_path()

        # Пишем скрипт восстановления
        RESTORE_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
        script = _RESTORE_SCRIPT_CONTENT.replace(
            "sys.path.insert(0, '/usr/local/lib/vless-installer')",
            f"sys.path.insert(0, '{installer_path}')"
        )
        RESTORE_SCRIPT.write_text(script, encoding="utf-8")
        RESTORE_SCRIPT.chmod(0o755)

        # Пишем systemd override
        SYSTEMD_OVERRIDE.parent.mkdir(parents=True, exist_ok=True)
        SYSTEMD_OVERRIDE.write_text(_SYSTEMD_OVERRIDE_CONTENT, encoding="utf-8")

        # Создаём лог-файл с правами пользователя xray
        log_path = Path("/var/log/xray-cold-boot-restore.log")
        if not log_path.exists():
            log_path.touch()
        _run(["chown", "xray:xray", str(log_path)])
        log_path.chmod(0o644)

        # Создаём sudoers-правило: xray может рестартовать nginx без пароля
        sudoers_path = Path("/etc/sudoers.d/xray-nginx")
        sudoers_path.write_text(
            "xray ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx\n",
            encoding="utf-8"
        )
        sudoers_path.chmod(0o440)

        # Перечитываем systemd
        _run(["systemctl", "daemon-reload"])

        return True, "Cold boot restore установлен"
    except Exception as e:
        return False, f"Ошибка установки: {e}"


def uninstall_cold_boot_restore() -> tuple[bool, str]:
    """Удаляет скрипт и systemd override."""
    try:
        RESTORE_SCRIPT.unlink(missing_ok=True)
        SYSTEMD_OVERRIDE.unlink(missing_ok=True)
        # Удаляем директорию override если пустая
        try:
            SYSTEMD_OVERRIDE.parent.rmdir()
        except Exception:
            pass
        _run(["systemctl", "daemon-reload"])
        return True, "Cold boot restore удалён"
    except Exception as e:
        return False, f"Ошибка удаления: {e}"


def _find_installer_path() -> str:
    """Находит корневой путь установки vless-installer."""
    import importlib.util
    spec = importlib.util.find_spec("vless_installer")
    if spec and spec.submodule_search_locations:
        p = Path(list(spec.submodule_search_locations)[0]).parent
        return str(p)
    # Fallback — ищем по типичным путям
    for candidate in [
        Path("/root/VLESS-Ultimate-Installer"),
        Path("/home/*/VLESS-Ultimate-Installer"),
        Path("/opt/VLESS-Ultimate-Installer"),
    ]:
        matches = list(Path("/").glob(str(candidate).lstrip("/")))
        for m in matches:
            if (m / "vless_installer").exists():
                return str(m)
    return "/root/VLESS-Ultimate-Installer"


def run_cold_boot_restore() -> None:
    """
    Точка входа для запуска из systemd/cron.
    Выполняет восстановление и пишет лог в /var/log/xray-cold-boot-restore.log.
    """
    import sys
    log_path = Path("/var/log/xray-cold-boot-restore.log")

    def log(msg: str) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"{ts} {msg}\n"
        try:
            with open(log_path, "a") as f:
                f.write(line)
        except Exception:
            pass
        print(line, end="")

    log("=== cold-boot-restore (python): старт ===")
    time.sleep(3)

    # Telemt tproxy
    try:
        from vless_installer.modules.mtproto import telemt_tproxy_emergency_restore
        ok, msg = telemt_tproxy_emergency_restore()
        log(f"Telemt tproxy: {msg}")
    except ImportError:
        log("Telemt tproxy: модуль не найден — пропуск")
    except Exception as e:
        log(f"Telemt tproxy: ошибка — {e}")

    log("=== cold-boot-restore: завершён ===")


# ── Интерактивное меню ────────────────────────────────────────────────────────

def do_cold_boot_menu() -> None:
    """Интерактивное меню управления cold boot restore."""
    from vless_installer._core import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back,
        _box_ok, _box_warn,
    )

    while True:
        os.system("clear")
        installed = _is_installed()
        status = f"{GREEN}установлен{NC}" if installed else f"{YELLOW}не установлен{NC}"

        _box_top("🔄  COLD BOOT RESTORE")
        _box_row("  Автовосстановление после перезагрузки сервера.")
        _box_row("  Восстанавливает Telemt tproxy и nginx Unix-сокет")
        _box_row("  автоматически после каждого старта xray.service.")
        _box_sep()
        _box_row(f"  Статус:  {status}")
        if installed:
            _box_row(f"  Скрипт:  {DIM}{RESTORE_SCRIPT}{NC}")
            _box_row(f"  Override:{DIM}{SYSTEMD_OVERRIDE}{NC}")
        _box_sep()

        if not installed:
            _box_item("I", "Установить")
        else:
            _box_item("U", "Удалить")
            _box_item("T", "Тест (запустить вручную)")
        _box_back()
        _box_bottom()

        ch = input(f"{CYAN}Выбор: {NC}").strip().upper()

        if ch == "0":
            break

        elif ch == "I" and not installed:
            ok, msg = install_cold_boot_restore()
            if ok:
                _box_ok(msg)
            else:
                _box_warn(msg)
            input(f"{CYAN}Нажмите Enter...{NC}")

        elif ch == "U" and installed:
            ok, msg = uninstall_cold_boot_restore()
            if ok:
                _box_ok(msg)
            else:
                _box_warn(msg)
            input(f"{CYAN}Нажмите Enter...{NC}")

        elif ch == "T" and installed:
            _box_row(f"  {DIM}Запуск скрипта восстановления...{NC}")
            r = _run(["bash", str(RESTORE_SCRIPT)])
            if r.returncode == 0:
                _box_ok("Скрипт выполнен успешно")
            else:
                _box_warn(f"Скрипт завершился с кодом {r.returncode}")
                if r.stderr:
                    _box_row(f"  {RED}{r.stderr[:200]}{NC}")
            input(f"{CYAN}Нажмите Enter...{NC}")
