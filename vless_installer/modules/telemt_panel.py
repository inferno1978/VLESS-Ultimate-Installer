"""
vless_installer/modules/telemt_panel.py
───────────────────────────────────────────────────────────────────────────────
Модуль Telemt Panel — веб-панель управления для Telemt MTProxy
(https://github.com/amirotin/telemt_panel), Go-бинарник + встроенный React-фронт.

Точка входа из mtproto.py:
    from vless_installer.modules.telemt_panel import telemt_panel_menu
    telemt_panel_menu()

Принципы:
  • Полностью отдельный сервис/systemd-юнит/конфиг — panel и telemt друг с
    другом общаются только через HTTP API Telemt (127.0.0.1), файлы telemt
    напрямую не трогает.
  • config_edit_mode = "api" всегда (см. обоснование в шапке _generate_config) —
    так panel структурно не может задеть [server]/[network]/[access] в
    конфиге telemt (client_mss, MSS-clamp порты и т.д.), даже случайно.
  • [api]-секцию в конфиге telemt включает/обновляет mtproto.ensure_api_enabled() —
    единая точка правды для файла telemt.toml остаётся в mtproto.py.
  • Ctrl+C на любом шаге → возврат в меню (через _Cancelled).
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА
# ══════════════════════════════════════════════════════════════════════════════
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ══════════════════════════════════════════════════════════════════════════════
#  ПУТИ И КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
BIN_PATH        = Path("/usr/local/bin/telemt-panel")
CONFIG_DIR      = Path("/etc/telemt-panel")
CONFIG_FILE     = CONFIG_DIR / "config.toml"
DATA_DIR        = Path("/var/lib/telemt-panel")
SERVICE_FILE    = Path("/etc/systemd/system/telemt-panel.service")
LOG_FILE        = Path("/var/log/telemt_panel_install.log")

SERVICE_NAME    = "telemt-panel"
SYSTEM_USER     = "telemt-panel"
GITHUB_API      = "https://api.github.com/repos/amirotin/telemt_panel/releases/latest"

# Адрес, на котором telemt должен отдавать свой собственный API —
# строго localhost, наружу это лезть не должно ни при каких обстоятельствах.
TELEMT_API_HOST = "127.0.0.1"
TELEMT_API_PORT = 9091

# На чём слушает сама панель (веб-интерфейс). По умолчанию тоже только
# localhost — наружу пробрасывается через существующий Reality-домен
# (reverse-proxy на подпуть) либо через SSH-туннень, см. меню "N".
PANEL_LISTEN_HOST = "127.0.0.1"
PANEL_LISTEN_PORT = 8080

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ (1-в-1 со стилем mtproto.py/mieru.py)
# ══════════════════════════════════════════════════════════════════════════════
_BOX_W = 66

def _plain(s: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', s)

def _wlen(s: str) -> int:
    import unicodedata as _ud
    plain = _plain(s)
    width = 0
    chars = list(plain)
    i = 0
    while i < len(chars):
        ch = chars[i]
        cp = ord(ch)
        next_cp = ord(chars[i + 1]) if i + 1 < len(chars) else 0
        if next_cp == 0xFE0F:
            width += 2; i += 2; continue
        if cp == 0x200D or (0x300 <= cp <= 0x36F) or (0xFE00 <= cp <= 0xFE0F):
            i += 1; continue
        eaw = _ud.east_asian_width(ch)
        if eaw in ('W', 'F'):
            width += 2
        elif eaw == 'N' and (0x1F300 <= cp <= 0x1FAFF or 0x2B00 <= cp <= 0x2BFF):
            width += 2
        else:
            width += 1
        i += 1
    return width

def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad  = _BOX_W - _wlen(title)
        lpad = pad // 2
        rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None:
    print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_bot() -> None:
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        acc, plain = 0, _plain(text)
        cut = 0
        for i, ch in enumerate(plain):
            import unicodedata as _ud
            acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc > _BOX_W - 1:
                cut = i
                break
        text = text[:cut] + "…"
        w = _wlen(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")

def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

def _box_ok(msg: str)   -> None: _box_row(f"  {GREEN}✓{NC}  {msg}")
def _box_warn(msg: str) -> None: _box_row(f"  {YELLOW}⚠{NC}  {msg}")
def _box_info(msg: str) -> None: _box_row(f"  {CYAN}→{NC}  {msg}")
def _box_err(msg: str)  -> None: _box_row(f"  {RED}✗{NC}  {msg}")

def _box_kv(key: str, val: str, kw: int = 22) -> None:
    key_colored = f"{CYAN}{key}{NC}"
    key_pad = kw - _wlen(key_colored)
    _box_row(f"  {key_colored}{' ' * max(0, key_pad)}  {val}")

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
def _run(cmd: list, capture: bool = False, check: bool = False, input_data: str = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if input_data is not None:
        kw.update(input=input_data)
    if capture or input_data is not None:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _log(msg: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(_plain(msg) + "\n")
    except Exception:
        pass

def _ok(msg: str)   -> None: print(f"  {GREEN}✓{NC}  {msg}"); _log(f"[OK] {msg}")
def _warn(msg: str) -> None: print(f"  {YELLOW}⚠{NC}  {msg}"); _log(f"[WARN] {msg}")
def _info(msg: str) -> None: print(f"  {CYAN}→{NC}  {msg}"); _log(f"[INFO] {msg}")
def _err(msg: str)  -> None: print(f"  {RED}✗{NC}  {msg}"); _log(f"[ERR] {msg}")

class _Cancelled(Exception):
    """Пользователь нажал Ctrl+C — возврат в вызывающее меню."""

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True)
        input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

def _ask(prompt: str, default: str = "", c: bool = False) -> str:
    try:
        print(prompt, end="", flush=True)
        val = input().strip()
        return val if val else default
    except (EOFError, UnicodeDecodeError):
        print(); return default
    except KeyboardInterrupt:
        print()
        if c: raise _Cancelled()
        return default

def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _is_installed() -> bool:
    return BIN_PATH.exists() and CONFIG_FILE.exists()

def _is_active() -> bool:
    r = _run(["systemctl", "is-active", "--quiet", SERVICE_NAME])
    return r.returncode == 0

# ══════════════════════════════════════════════════════════════════════════════
#  ИНТЕГРАЦИЯ С mtproto.py (единая точка правды для telemt.toml)
# ══════════════════════════════════════════════════════════════════════════════
def _get_mtproto_module():
    """Ленивый импорт, чтобы не тянуть mtproto.py при простом просмотре меню."""
    try:
        from vless_installer.modules import mtproto as _mp
        return _mp
    except Exception as e:
        _err(f"Не удалось импортировать модуль mtproto: {e}")
        return None

def _telemt_is_installed(mp) -> bool:
    return bool(mp) and mp.CONFIG_FILE.exists() and mp.BIN_PATH.exists()

# ══════════════════════════════════════════════════════════════════════════════
#  СКАЧИВАНИЕ / УСТАНОВКА БИНАРНИКА ПАНЕЛИ
# ══════════════════════════════════════════════════════════════════════════════
def _get_latest_release() -> tuple:
    """Возвращает (tag, url) под текущую архитектуру или ('', '') при ошибке."""
    try:
        req = urllib.request.Request(GITHUB_API, headers={"User-Agent": "VLESS-Ultimate-Installer"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        tag  = data.get("tag_name", "").lstrip("v")
        arch = "aarch64" if platform.machine().lower() in ("aarch64", "arm64") else "x86_64"
        url  = (f"https://github.com/amirotin/telemt_panel/releases/latest/download/"
                f"telemt-panel-{arch}-linux")
        return tag, url
    except Exception as e:
        _err(f"Не удалось получить релиз: {e}")
        return "", ""

def _install_binary(url: str) -> bool:
    _info("Загрузка telemt-panel...")
    tmp = Path(tempfile.mkdtemp())
    dst = tmp / "telemt-panel"
    try:
        urllib.request.urlretrieve(url, dst)
        if dst.stat().st_size < 1_000_000:
            _err("Скачанный файл подозрительно маленький — похоже на ошибку 404/редирект.")
            return False
        shutil.copy2(str(dst), str(BIN_PATH))
        BIN_PATH.chmod(0o755)
        _ok(f"Установлено: {BIN_PATH}")
        return True
    except Exception as e:
        _err(f"Ошибка: {e}")
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def _create_system_user() -> None:
    r = _run(["id", SYSTEM_USER], capture=True)
    if r.returncode == 0:
        return
    _run(["useradd", "--system", "--shell", "/usr/sbin/nologin",
          "--home", "/nonexistent", "--no-create-home", SYSTEM_USER], check=False)
    _ok(f"Системный пользователь {SYSTEM_USER} создан")

def _hash_password(password: str) -> Optional[str]:
    r = _run([str(BIN_PATH), "hash-password"], input_data=password + "\n")
    if r.returncode != 0 or not r.stdout.strip():
        _err(f"Не удалось сгенерировать хеш пароля: {r.stderr.strip()}")
        return None
    return r.stdout.strip()

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ ПАНЕЛИ
# ══════════════════════════════════════════════════════════════════════════════
def _generate_config(username: str, password_hash: str, jwt_secret: str,
                      telemt_api_token: str, base_path: str = "") -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Telemt Panel — generated by VLESS Ultimate Installer (Chimera)",
        f'listen = "{PANEL_LISTEN_HOST}:{PANEL_LISTEN_PORT}"',
    ]
    if base_path:
        lines.append(f'base_path = "{base_path}"')
    lines += [
        "",
        "[telemt]",
        f'url = "http://{TELEMT_API_HOST}:{TELEMT_API_PORT}"',
        f'auth_header = "{telemt_api_token}"',
        # config_edit_mode оставляем "api" СОЗНАТЕЛЬНО и без права выбора из
        # меню — это единственный режим, при котором панель структурно не
        # может задеть [server]/[network]/[access] (client_mss, MSS-clamp
        # порты SYN-limiter/iOS-фикса и т.д.), см. шапку файла.
        'config_edit_mode = "api"',
        "",
        "[auth]",
        f'username = "{username}"',
        f'password_hash = "{password_hash}"',
        f'jwt_secret = "{jwt_secret}"',
        'session_ttl = "24h"',
        "",
        "[panel]",
        f'binary_path = "{BIN_PATH}"',
        f'service_name = "{SERVICE_NAME}"',
        'github_repo = "amirotin/telemt_panel"',
    ]
    CONFIG_FILE.write_text("\n".join(lines) + "\n")
    CONFIG_FILE.chmod(0o640)
    _run(["chown", f"{SYSTEM_USER}:{SYSTEM_USER}", str(CONFIG_FILE)], check=False)
    _run(["chown", "-R", f"{SYSTEM_USER}:{SYSTEM_USER}", str(DATA_DIR)], check=False)

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD
# ══════════════════════════════════════════════════════════════════════════════
def _install_service() -> None:
    SERVICE_FILE.write_text(f"""[Unit]
Description=Telemt Panel — web UI for Telemt MTProxy
After=network-online.target telemt.service
Wants=network-online.target

[Service]
Type=simple
User={SYSTEM_USER}
Group={SYSTEM_USER}
ExecStart={BIN_PATH} --config {CONFIG_FILE}
Restart=on-failure
RestartSec=3
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths={CONFIG_DIR} {DATA_DIR}

[Install]
WantedBy=multi-user.target
""")
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", SERVICE_NAME])
    _ok("systemd-юнит установлен и включён в автозапуск")

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install() -> None:
    mp = _get_mtproto_module()
    if not _telemt_is_installed(mp):
        _err("Telemt не установлен — панели нечего показывать.")
        _box_info("Сначала установите Telemt через пункт '1' в его собственном меню.")
        _pause()
        return

    if _is_installed():
        _box_warn("Telemt Panel уже установлена.")
        if _ask(f"  Переустановить поверх? (y/N): ", "n", c=True).lower() != "y":
            return

    _box_top("УСТАНОВКА TELEMT PANEL")
    _box_row()
    _box_info("Панель будет слушать только 127.0.0.1:8080 — наружу")
    _box_info("не светится. Доступ снаружи: SSH-туннель или reverse-proxy")
    _box_info("на подпуть через уже существующий Reality-домен.")
    _box_bot()
    print()

    # ── 1. Включаем [api] в конфиге telemt (единая точка правды — mtproto.py)
    _info("Проверяю/включаю API у Telemt...")
    telemt_api_token = secrets.token_hex(24)
    ok, msg = mp.ensure_api_enabled(telemt_api_token, host=TELEMT_API_HOST, port=TELEMT_API_PORT)
    if not ok:
        _err(f"Не удалось включить API Telemt: {msg}")
        _pause()
        return
    _ok(msg)

    # ── 2. Скачиваем бинарник панели
    tag, url = _get_latest_release()
    if not url:
        _pause(); return
    _info(f"Последний релиз: {tag or '?'}")
    if not _install_binary(url):
        _pause(); return

    # ── 3. Системный пользователь + директории
    _create_system_user()

    # ── 4. Учётные данные панели
    print()
    username = _ask(f"  Логин администратора [{CYAN}admin{NC}]: ", "admin", c=True)
    while True:
        password = _ask(f"  Пароль администратора (не короче 8 симв.): ", "", c=True)
        if len(password) >= 8:
            break
        _warn("Слишком короткий пароль.")

    password_hash = _hash_password(password)
    if not password_hash:
        _pause(); return
    jwt_secret = secrets.token_hex(32)

    base_path = _ask(f"  Base path за reverse-proxy (Enter — не использовать): ", "", c=True)

    # ── 5. Конфиг + systemd
    _generate_config(username, password_hash, jwt_secret, telemt_api_token, base_path)
    _install_service()
    _run(["systemctl", "restart", SERVICE_NAME])

    if _is_active():
        _ok("Telemt Panel запущена")
    else:
        _err("Сервис не поднялся — смотри 'journalctl -u telemt-panel -n 50'")

    print()
    _box_top("ГОТОВО")
    _box_kv("URL (локально):", f"http://{PANEL_LISTEN_HOST}:{PANEL_LISTEN_PORT}")
    _box_kv("Логин:", username)
    _box_kv("Пароль:", "тот, что вы ввели — нигде не хранится в открытом виде")
    _box_row()
    _box_warn("Панель на 127.0.0.1 — прокиньте порт через:")
    _box_info(f"ssh -L {PANEL_LISTEN_PORT}:127.0.0.1:{PANEL_LISTEN_PORT} root@<ваш_сервер>")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС / УПРАВЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    _box_top("СТАТУС TELEMT PANEL")
    if not _is_installed():
        _box_warn("Не установлена.")
        _box_bot(); _pause(); return
    _box_kv("Сервис:", f"{GREEN}активен{NC}" if _is_active() else f"{RED}остановлен{NC}")
    _box_kv("Бинарник:", str(BIN_PATH))
    _box_kv("Конфиг:", str(CONFIG_FILE))
    _box_kv("Слушает:", f"{PANEL_LISTEN_HOST}:{PANEL_LISTEN_PORT}")
    r = _run([str(BIN_PATH), "version"], capture=True)
    if r.returncode == 0:
        _box_kv("Версия:", r.stdout.strip())
    _box_bot()
    _pause()

def _update() -> None:
    if not _is_installed():
        _warn("Telemt Panel не установлена."); _pause(); return
    tag, url = _get_latest_release()
    if not url:
        _pause(); return
    _info(f"Обновляю до {tag or 'последней версии'}...")
    if _install_binary(url):
        _run(["systemctl", "restart", SERVICE_NAME])
        _ok("Обновлено и перезапущено")
    _pause()

def _uninstall() -> None:
    if not _is_installed():
        _warn("Telemt Panel не установлена."); _pause(); return
    if _ask(f"  {RED}Точно удалить Telemt Panel полностью? (y/N): {NC}", "n", c=True).lower() != "y":
        return
    _run(["systemctl", "stop", SERVICE_NAME], check=False)
    _run(["systemctl", "disable", SERVICE_NAME], check=False)
    SERVICE_FILE.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"])
    shutil.rmtree(CONFIG_DIR, ignore_errors=True)
    shutil.rmtree(DATA_DIR, ignore_errors=True)
    BIN_PATH.unlink(missing_ok=True)
    _run(["userdel", SYSTEM_USER], check=False)
    _ok("Telemt Panel полностью удалена.")
    _box_info("API у Telemt (секция [api] в telemt.toml) оставлена как есть —")
    _box_info("отключить можно из меню самого Telemt при необходимости.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def telemt_panel_menu() -> None:
    while True:
        print()
        _box_top("TELEMT PANEL — веб-интерфейс для Telemt")
        _box_row()
        status = f"{GREEN}установлена, активна{NC}" if (_is_installed() and _is_active()) \
            else f"{YELLOW}установлена, остановлена{NC}" if _is_installed() \
            else f"{DIM}не установлена{NC}"
        _box_kv("Статус:", status)
        _box_row(); _box_sep()
        _box_item("1", "🚀  Установить / переустановить")
        _box_item("2", "📋  Статус")
        _box_item("3", "🔄  Перезапустить сервис")
        _box_item("4", "⬆️   Проверить и обновить")
        _box_item("8", f"{RED}🗑️   Полное удаление{NC}")
        _box_sep()
        _box_item("Q", "← Назад в меню Telemt")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _run_install()
        elif ch == "2":
            _show_status()
        elif ch == "3":
            if not _is_installed():
                _warn("Не установлена."); _pause(); continue
            _run(["systemctl", "restart", SERVICE_NAME])
            _ok("Сервис перезапущен."); _pause()
        elif ch == "4":
            _update()
        elif ch == "8":
            _uninstall()
        elif ch in ("q", ""):
            break
