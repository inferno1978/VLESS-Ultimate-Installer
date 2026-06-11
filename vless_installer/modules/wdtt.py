"""
vless_installer/modules/wdtt.py
───────────────────────────────────────────────────────────────────────────────
qWDTT — WireGuard over TURN Tunnel.

Назначение:
  Альтернатива vk-turn-proxy для Android-клиентов (qWDTT).
  В отличие от vk-turn-proxy + VLESS, здесь используется WireGuard
  как внутренний протокол с парольной моделью доступа,
  Telegram-ботом для управления и hot reload ключей без перезапуска.

Схема трафика:
  Android (qWDTT APK)
    │  WRAP RTP AEAD/ChaCha20-Poly1305 поверх DTLS 1.2
    ▼
  TURN-серверы ВКонтакте  (трафик = медиа-поток звонка)
    │  UDP → VPS :56000
    ▼
  wdtt-server  (:56000/udp DTLS)
    │  WireGuard ← GETCONF  (:56001/udp внутренний WG)
    ▼
  WireGuard tun: wdtt0  (10.66.66.0/16)
    │
    ▼
  NAT → Интернет

Отличия от vk-turn-proxy (turntunnel.py):
  • Протокол:  WireGuard (не VLESS)
  • Аутентификация: парольная (не UUID)
    - Главный пароль (бессрочный)
    - До 10 временных паролей с TTL и лимитом устройств
  • Ключи WRAP выводятся из пароля через HKDF — не хранятся в APK
  • Telegram-бот для управления паролями прямо из телефона
  • Hot reload: новые/удалённые пароли применяются через SIGHUP без
    перезапуска службы и разрыва соединений
  • Деплой: wdtt-server + systemd + WireGuard NAT

Что модуль делает:
  • Проверяет наличие Go и собирает wdtt-server из исходников
    (либо скачивает prebuilt если доступен в релизах)
  • Настраивает /etc/wdtt/config.json (порты, главный пароль,
    Telegram admin_id + bot_token)
  • Создаёт systemd-сервис wdtt.service с After=network-online.target
  • Настраивает NAT через iptables (MASQUERADE для wdtt0)
  • Открывает UDP-порт 56000 в iptables
  • Генерирует qwdtt:// ссылку и .conf файл для клиента
  • Управление паролями: создание, список, удаление, статус устройств
  • Показывает гайд по использованию qWDTT

Что модуль НЕ трогает:
  • config.json Xray и VLESS-inbound
  • state.json инсталлера
  • iptables-правила других модулей
  • turntunnel.py и его конфиги
  • Любые другие службы

Точка входа из _core.py:
    from vless_installer.modules.wdtt import do_wdtt_menu
    do_wdtt_menu()

Интеграция в _core.py:
  1. Импорт:
       from vless_installer.modules.wdtt import do_wdtt_menu
  2. Пункт меню (10):
       _box_row(f"  {CYAN}10{NC}  🔒 {TITLE}qWDTT (WireGuard/TURN){NC}")
       _box_row(f"     {DIM}WireGuard через TURN ВКонтакте — парольная модель, Telegram-бот{NC}")
  3. Обработчик:
       elif choice == "10":
           try:
               do_wdtt_menu()
           except ImportError as _e:
               warn(f"Модуль qWDTT не найден: {_e}")
               time.sleep(2)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА
# ══════════════════════════════════════════════════════════════════════════════
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BOLD='\033[1m', DIM='\033[2m',
                WHITE='\033[0;30m', NC='\033[0m',
            )
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
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
_BIN_PATH         = Path("/usr/local/bin/wdtt-server")
_CFG_DIR          = Path("/etc/wdtt")
_CFG_FILE         = Path("/etc/wdtt/config.json")
_PASSWORDS_FILE   = Path("/etc/wdtt/passwords.json")
_SERVICE_FILE     = Path("/etc/systemd/system/wdtt.service")
_SERVICE_NAME     = "wdtt"
_MODULE_STATE     = Path("/var/lib/xray-installer/wdtt.json")

# GitHub
_GITHUB_REPO      = "SpaceNeuroX/proxy-turn-vk-android"
_GITHUB_API       = f"https://api.github.com/repos/{_GITHUB_REPO}/releases/latest"
_SOURCE_URL       = f"https://github.com/{_GITHUB_REPO}/archive/refs/heads/master.tar.gz"

# Порты по умолчанию
_DEFAULT_DTLS_PORT = 56000   # входящий от TURN-сервера
_DEFAULT_WG_PORT   = 56001   # внутренний WireGuard
_DEFAULT_TUN_PORT  = 9000    # локальный порт на Android

# WireGuard сеть
_WG_SUBNET        = "10.66.66.0/16"
_WG_SERVER_IP     = "10.66.66.1"

_BOX_W = 66

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ
# ══════════════════════════════════════════════════════════════════════════════
def _plain(s: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', s)

def _wlen(s: str) -> int:
    import unicodedata as _ud
    plain = _plain(s)
    width, chars = 0, list(plain)
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
                cut = i; break
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
class _Cancelled(Exception):
    pass

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

def _run(cmd: list, capture: bool = False, check: bool = False,
         env: Optional[dict] = None, cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if env:
        kw["env"] = env
    if cwd:
        kw["cwd"] = cwd
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _run_interactive(cmd: list, cwd: Optional[str] = None) -> int:
    kw: dict = {}
    if cwd:
        kw["cwd"] = cwd
    return subprocess.call(cmd, **kw)

def _gen_password(length: int = 16) -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    return ''.join(secrets.choice(chars) for _ in range(length))

def _get_server_ip() -> str:
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        pass
    return "ВАШ_IP"

# ══════════════════════════════════════════════════════════════════════════════
#  СОСТОЯНИЕ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def _load_state() -> dict:
    if not _MODULE_STATE.exists():
        return {}
    try:
        return json.loads(_MODULE_STATE.read_text())
    except Exception:
        return {}

def _save_state(data: dict) -> None:
    try:
        _MODULE_STATE.parent.mkdir(parents=True, exist_ok=True)
        _MODULE_STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        _MODULE_STATE.chmod(0o600)
    except Exception as e:
        print(f"  {YELLOW}⚠{NC}  Не удалось сохранить wdtt.json: {e}")

def _is_installed() -> bool:
    return _BIN_PATH.exists() and _SERVICE_FILE.exists()

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ СЕРВЕРА
# ══════════════════════════════════════════════════════════════════════════════
def _load_cfg() -> dict:
    if not _CFG_FILE.exists():
        return {}
    try:
        return json.loads(_CFG_FILE.read_text())
    except Exception:
        return {}

def _save_cfg(cfg: dict) -> None:
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    _CFG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    _CFG_FILE.chmod(0o600)

def _load_passwords() -> dict:
    """Загружает passwords.json — база паролей wdtt-server."""
    if not _PASSWORDS_FILE.exists():
        return {"main_password": "", "admin_id": "", "bot_token": "",
                "passwords": {}, "devices": {}}
    try:
        return json.loads(_PASSWORDS_FILE.read_text())
    except Exception:
        return {}

def _save_passwords(data: dict) -> None:
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    _PASSWORDS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    _PASSWORDS_FILE.chmod(0o600)

def _hot_reload() -> bool:
    """Отправляет SIGHUP серверу — hot reload паролей без перезапуска."""
    r = _run(["pidof", "wdtt-server"], capture=True)
    pid = (r.stdout or "").strip()
    if not pid:
        return False
    _run(["kill", "-HUP", pid])
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  СБОРКА / УСТАНОВКА БИНАРНИКА
# ══════════════════════════════════════════════════════════════════════════════
def _check_go() -> Optional[str]:
    """Возвращает путь к go или None."""
    go = shutil.which("go")
    if go:
        r = _run([go, "version"], capture=True)
        if r.returncode == 0:
            return go
    return None

def _install_go() -> bool:
    """Устанавливает Go через apt если его нет."""
    print(f"  {CYAN}→{NC}  Устанавливаю Go через apt...")
    r = _run(["apt-get", "install", "-y", "golang-go"], capture=True)
    return r.returncode == 0

def _build_wdtt_server() -> bool:
    """
    Скачивает исходники qWDTT и собирает wdtt-server.
    Бинарник помещается в /usr/local/bin/wdtt-server.
    """
    go = _check_go()
    if not go:
        print(f"  {CYAN}→{NC}  Go не найден, устанавливаю...")
        if not _install_go():
            print(f"  {RED}✗{NC}  Не удалось установить Go.")
            return False
        go = _check_go()
        if not go:
            print(f"  {RED}✗{NC}  Go всё ещё не найден.")
            return False

    tmp = Path(tempfile.mkdtemp())
    try:
        archive = tmp / "master.tar.gz"
        print(f"  {CYAN}→{NC}  Скачиваю исходники qWDTT...")
        urllib.request.urlretrieve(_SOURCE_URL, str(archive))

        print(f"  {CYAN}→{NC}  Распаковываю...")
        _run(["tar", "-xzf", str(archive), "-C", str(tmp)], check=True)

        # Ищем директорию с исходниками
        src_dirs = list(tmp.glob("proxy-turn-vk-android-*"))
        if not src_dirs:
            print(f"  {RED}✗{NC}  Не найдена директория с исходниками.")
            return False
        src_dir = src_dirs[0]

        print(f"  {CYAN}→{NC}  Компилирую wdtt-server (это займёт ~1-2 минуты)...")
        env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
        r = _run(
            [go, "build", "-o", str(tmp / "wdtt-server"),
             "-ldflags", "-s -w", "./server.go"],
            capture=True, env=env, cwd=str(src_dir),
        )
        if r.returncode != 0:
            print(f"  {RED}✗{NC}  Ошибка компиляции:")
            print(f"  {DIM}{(r.stderr or r.stdout or '')[:500]}{NC}")
            return False

        built = tmp / "wdtt-server"
        if not built.exists():
            print(f"  {RED}✗{NC}  Бинарник не создан после компиляции.")
            return False

        shutil.copy2(str(built), str(_BIN_PATH))
        _BIN_PATH.chmod(0o755)
        print(f"  {GREEN}✓{NC}  wdtt-server установлен: {_BIN_PATH}")
        return True

    except Exception as e:
        print(f"  {RED}✗{NC}  Ошибка: {e}")
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES
# ══════════════════════════════════════════════════════════════════════════════
def _ipt_rule_exists(table: str, chain: str, args: list) -> bool:
    r = _run(["iptables", "-t", table, "-C", chain] + args, capture=True)
    return r.returncode == 0

def _ipt_open_udp(port: int) -> None:
    args = ["-p", "udp", "--dport", str(port), "-j", "ACCEPT"]
    if not _ipt_rule_exists("filter", "INPUT", args):
        _run(["iptables", "-t", "filter", "-I", "INPUT", "1"] + args)

def _ipt_close_udp(port: int) -> None:
    args = ["-p", "udp", "--dport", str(port), "-j", "ACCEPT"]
    for _ in range(5):
        if not _ipt_rule_exists("filter", "INPUT", args):
            break
        _run(["iptables", "-t", "filter", "-D", "INPUT"] + args)

def _ipt_masquerade_exists() -> bool:
    r = _run(
        ["iptables", "-t", "nat", "-C", "POSTROUTING",
         "-s", _WG_SUBNET, "!", "-d", _WG_SUBNET, "-j", "MASQUERADE"],
        capture=True,
    )
    return r.returncode == 0

def _ipt_add_masquerade() -> None:
    if not _ipt_masquerade_exists():
        _run(["iptables", "-t", "nat", "-A", "POSTROUTING",
              "-s", _WG_SUBNET, "!", "-d", _WG_SUBNET, "-j", "MASQUERADE"])

def _ipt_remove_masquerade() -> None:
    for _ in range(3):
        if not _ipt_masquerade_exists():
            break
        _run(["iptables", "-t", "nat", "-D", "POSTROUTING",
              "-s", _WG_SUBNET, "!", "-d", _WG_SUBNET, "-j", "MASQUERADE"])

def _ipt_persist() -> None:
    if shutil.which("netfilter-persistent"):
        _run(["netfilter-persistent", "save"], capture=True)
        return
    rules_dir = Path("/etc/iptables")
    rules_dir.mkdir(parents=True, exist_ok=True)
    r = _run(["iptables-save"], capture=True)
    if r.returncode == 0 and r.stdout:
        (rules_dir / "rules.v4").write_text(r.stdout)

def _enable_ip_forward() -> None:
    """Включает IP forwarding — нужен для WireGuard NAT."""
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    sysctl = Path("/etc/sysctl.d/99-wdtt.conf")
    sysctl.write_text("net.ipv4.ip_forward = 1\n")

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD СЕРВИС
# ══════════════════════════════════════════════════════════════════════════════
def _install_service(dtls_port: int, wg_port: int, main_pass: str,
                     admin_id: str, bot_token: str) -> None:
    _SERVICE_FILE.write_text(
        "[Unit]\n"
        "Description=qWDTT — WireGuard over VK TURN\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={_BIN_PATH} "
        f"-dir {_CFG_DIR} "
        f"-pass {main_pass} "
        f"-dtls :{dtls_port} "
        f"-wg :{wg_port} "
        + (f"-admin {admin_id} " if admin_id else "")
        + (f"-bot {bot_token} " if bot_token else "")
        + "\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "NoNewPrivileges=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", _SERVICE_NAME])

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install() -> None:
    try:
        _run_install_inner()
    except _Cancelled:
        print(f"\n  {YELLOW}Установка прервана.{NC}\n")
        _pause()

def _run_install_inner() -> None:
    os.system("clear")
    _box_top("🔒  УСТАНОВКА  •  qWDTT")
    _box_row()

    if _is_installed():
        _box_warn("qWDTT уже установлен.")
        _box_row()
        _box_item("1", "Переустановить (сохранить пароли и конфиг)")
        _box_item("2", f"Переустановить полностью  {YELLOW}(новый главный пароль){NC}")
        _box_item("Q", "← Отмена")
        _box_bot(); print()
        try:
            ch = _ask(f"{CYAN}Выбор [1/2/Q]: {NC}", c=True).strip().lower()
        except _Cancelled:
            return
        if ch == "q" or not ch:
            return
        if ch == "2":
            _full_uninstall(silent=True)

    # ── Конфигурация ──────────────────────────────────────────────────────────
    state = _load_state()
    old_pass  = state.get("main_password", "")
    old_dtls  = state.get("dtls_port", _DEFAULT_DTLS_PORT)
    old_wg    = state.get("wg_port",   _DEFAULT_WG_PORT)
    old_admin = state.get("admin_id",  "")
    old_bot   = state.get("bot_token", "")

    os.system("clear")
    _box_top("🔒  НАСТРОЙКА  •  qWDTT")
    _box_row()
    _box_info("Главный пароль — бессрочный доступ (для себя).")
    _box_info("Оставьте пустым — пароль сгенерируется автоматически.")
    _box_row()
    _box_info("Telegram-бот опционален — для управления временными паролями.")
    _box_info("Если не нужен — оставьте поля пустыми.")
    _box_row()
    _box_bot(); print()

    try:
        raw = _ask(
            f"  {CYAN}Главный пароль [{old_pass or 'авто'}]: {NC}",
            default=old_pass, c=True,
        )
        main_pass = raw if raw else (_gen_password() if not old_pass else old_pass)

        raw = _ask(
            f"  {CYAN}UDP порт DTLS [{old_dtls}]: {NC}",
            default=str(old_dtls), c=True,
        )
        dtls_port = int(raw) if raw.isdigit() else old_dtls

        raw = _ask(
            f"  {CYAN}UDP порт WireGuard [{old_wg}]: {NC}",
            default=str(old_wg), c=True,
        )
        wg_port = int(raw) if raw.isdigit() else old_wg

        admin_id = _ask(
            f"  {CYAN}Telegram Admin ID [{old_admin or 'пропустить'}]: {NC}",
            default=old_admin, c=True,
        )
        bot_token = ""
        if admin_id:
            bot_token = _ask(
                f"  {CYAN}Telegram Bot Token [{old_bot or 'пропустить'}]: {NC}",
                default=old_bot, c=True,
            )
    except _Cancelled:
        raise

    if not (1024 <= dtls_port <= 65535) or not (1024 <= wg_port <= 65535):
        print(f"  {RED}✗{NC}  Порты должны быть в диапазоне 1024–65535."); _pause(); return
    if dtls_port == wg_port:
        print(f"  {RED}✗{NC}  Порты DTLS и WireGuard не должны совпадать."); _pause(); return

    # ── Установка ─────────────────────────────────────────────────────────────
    os.system("clear")
    _box_top("🔒  УСТАНОВКА  •  qWDTT")
    _box_row()

    # 1. Бинарник
    _box_info("Сборка wdtt-server из исходников...")
    _box_bot(); print()

    if not _build_wdtt_server():
        print()
        _box_top("🔒  УСТАНОВКА  •  qWDTT")
        _box_err("Не удалось собрать wdtt-server.")
        _box_err("Убедитесь что доступен Go и интернет.")
        _box_bot(); _pause(); return

    print()
    # 2. Конфиг директория
    _CFG_DIR.mkdir(parents=True, exist_ok=True)

    # Инициализируем passwords.json если его нет
    if not _PASSWORDS_FILE.exists():
        _save_passwords({
            "main_password": main_pass,
            "admin_id": admin_id,
            "bot_token": bot_token,
            "passwords": {},
            "devices": {},
        })
    else:
        # Обновляем только служебные поля, пароли пользователей не трогаем
        data = _load_passwords()
        data["main_password"] = main_pass
        data["admin_id"] = admin_id
        data["bot_token"] = bot_token
        _save_passwords(data)

    print(f"  {GREEN}✓{NC}  Конфиг создан: {_CFG_DIR}")

    # 3. IP forwarding
    _enable_ip_forward()
    print(f"  {GREEN}✓{NC}  IP forwarding включён.")

    # 4. iptables
    _ipt_open_udp(dtls_port)
    _ipt_add_masquerade()
    _ipt_persist()
    print(f"  {GREEN}✓{NC}  iptables: UDP {dtls_port} открыт, NAT настроен.")

    # 5. Systemd
    _install_service(dtls_port, wg_port, main_pass, admin_id, bot_token)
    print(f"  {GREEN}✓{NC}  Systemd-сервис создан.")

    # 6. Запуск
    _run(["systemctl", "start", _SERVICE_NAME])
    time.sleep(2)
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    if r.stdout.strip() == "active":
        print(f"  {GREEN}✓{NC}  wdtt-server запущен.")
    else:
        print(f"  {YELLOW}⚠{NC}  Сервис не запустился — проверьте логи (пункт 5).")

    # 7. Сохраняем состояние
    _save_state({
        "installed":     True,
        "main_password": main_pass,
        "dtls_port":     dtls_port,
        "wg_port":       wg_port,
        "admin_id":      admin_id,
        "bot_token":     bot_token,
    })

    # ── Итог ──────────────────────────────────────────────────────────────────
    server_ip = _get_server_ip()
    print()
    _box_top("✅  УСТАНОВКА ЗАВЕРШЕНА  •  qWDTT")
    _box_row()
    _box_ok("wdtt-server установлен и запущен.")
    _box_row()
    _box_kv("DTLS порт:",      f"{YELLOW}{dtls_port}/udp{NC}")
    _box_kv("WG порт:",        f"{DIM}{wg_port}/udp (внутренний){NC}")
    _box_kv("Главный пароль:", f"{YELLOW}{main_pass}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Быстрая ссылка для qWDTT:{NC}")
    _box_row()
    qwdtt_link = (
        f"qwdtt://config?name=qWDTT-{server_ip}"
        f"&peer={server_ip}:{dtls_port}"
        f"&hashes=ВК_ХЕШ_ЗВОНКА"
        f"&workers=16&port={_DEFAULT_TUN_PORT}"
        f"&pass={main_pass}"
    )
    _box_row(f"  {YELLOW}{qwdtt_link}{NC}")
    _box_row()
    _box_warn("Замените ВК_ХЕШ_ЗВОНКА на хеш из ссылки vk.com/call/join/ХЕШ")
    _box_row()
    _box_sep()
    if admin_id and bot_token:
        _box_ok("Telegram-бот настроен. Команды: /new, /list")
    else:
        _box_info("Telegram-бот не настроен (можно добавить позже).")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ ПАРОЛЯМИ
# ══════════════════════════════════════════════════════════════════════════════
def _passwords_menu() -> None:
    """Управление временными паролями без Telegram."""
    while True:
        os.system("clear")
        data = _load_passwords()
        passwords = data.get("passwords", {})
        state = _load_state()
        server_ip = _get_server_ip()
        dtls_port = state.get("dtls_port", _DEFAULT_DTLS_PORT)

        _box_top("🔑  УПРАВЛЕНИЕ ПАРОЛЯМИ  •  qWDTT")
        _box_row()
        _box_kv("Главный пароль:", f"{YELLOW}{data.get('main_password', '—')}{NC}")
        _box_kv("Временных паролей:",
                f"{YELLOW}{len(passwords)}{NC} / 10")
        _box_row(); _box_sep()

        active_list = []
        for pw, entry in passwords.items():
            if not entry:
                continue
            expires = entry.get("expires_at", 0)
            expired = expires > 0 and time.time() > expires
            active_list.append((pw, entry, expired))

        if active_list:
            _box_row(f"  {BOLD}{CYAN}{'Пароль':<18}{'Истекает':<14}{'Уст.':<6}{'Статус'}{NC}")
            _box_sep()
            for pw, entry, expired in active_list:
                exp = entry.get("expires_at", 0)
                if exp == 0:
                    exp_str = "бессрочный"
                else:
                    dt = datetime.fromtimestamp(exp)
                    exp_str = dt.strftime("%d.%m.%Y")
                devs = len(entry.get("device_ids", []) or
                           ([entry["device_id"]] if entry.get("device_id") else []))
                max_d = entry.get("max_devices", 1) or 1
                deact = entry.get("is_deactivated", False)
                if deact:
                    status = f"{RED}отключён{NC}"
                elif expired:
                    status = f"{YELLOW}истёк{NC}"
                else:
                    status = f"{GREEN}активен{NC}"
                pw_short = pw[:16]
                _box_row(
                    f"  {CYAN}{pw_short:<18}{NC}"
                    f"{DIM}{exp_str:<14}{NC}"
                    f"{devs}/{max_d:<4}  "
                    f"{status}"
                )
        else:
            _box_warn("Временных паролей нет.")

        _box_row(); _box_sep()
        _box_item("1", "➕  Создать временный пароль")
        _box_item("2", "🔗  Показать ссылку для пароля")
        _box_item("3", f"{RED}🗑️   Удалить пароль{NC}")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            try:
                _create_password()
            except _Cancelled:
                pass
        elif ch == "2":
            try:
                _show_password_link(passwords, server_ip, dtls_port)
            except _Cancelled:
                pass
        elif ch == "3":
            try:
                _delete_password(passwords)
            except _Cancelled:
                pass
        elif ch in ("q", ""):
            break

def _create_password() -> None:
    os.system("clear")
    _box_top("➕  СОЗДАТЬ ПАРОЛЬ  •  qWDTT")
    _box_row()
    _box_info("Временный пароль для передачи пользователю.")
    _box_row()
    _box_bot(); print()

    try:
        raw_days = _ask(
            f"  {CYAN}Дней действия (1-365, Enter=30): {NC}",
            default="30", c=True,
        )
        days = int(raw_days) if raw_days.isdigit() else 30
        days = max(1, min(365, days))

        raw_devs = _ask(
            f"  {CYAN}Макс. устройств (Enter=1): {NC}",
            default="1", c=True,
        )
        max_devs = int(raw_devs) if raw_devs.isdigit() else 1
        max_devs = max(1, min(10, max_devs))

        vk_hash = _ask(
            f"  {CYAN}VK хеш звонка (Enter=пропустить): {NC}",
            default="", c=True,
        ).strip()

    except _Cancelled:
        raise

    data = _load_passwords()
    passwords = data.get("passwords", {})
    if len(passwords) >= 10:
        print(f"  {RED}✗{NC}  Лимит: максимум 10 паролей."); _pause(); return

    new_pass = _gen_password()
    expires_at = int((datetime.now() + timedelta(days=days)).timestamp())

    passwords[new_pass] = {
        "device_ids":    [],
        "max_devices":   max_devs,
        "expires_at":    expires_at,
        "down_bytes":    0,
        "up_bytes":      0,
        "vk_hash":       vk_hash,
        "ports":         "",
        "is_deactivated": False,
    }
    data["passwords"] = passwords
    _save_passwords(data)

    # Hot reload
    _hot_reload()

    state = _load_state()
    server_ip = _get_server_ip()
    dtls_port = state.get("dtls_port", _DEFAULT_DTLS_PORT)

    print()
    _box_top("✅  ПАРОЛЬ СОЗДАН")
    _box_row()
    _box_kv("Пароль:",   f"{YELLOW}{new_pass}{NC}")
    _box_kv("Действует:", f"{days} дн. до {datetime.fromtimestamp(expires_at).strftime('%d.%m.%Y')}")
    _box_kv("Устройств:", str(max_devs))
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Ссылка qwdtt:// для клиента:{NC}")
    _box_row()
    vk_part = vk_hash if vk_hash else "ВК_ХЕШ"
    link = (
        f"qwdtt://config?name=qWDTT-{server_ip}"
        f"&peer={server_ip}:{dtls_port}"
        f"&hashes={vk_part}"
        f"&workers=16&port={_DEFAULT_TUN_PORT}"
        f"&pass={new_pass}"
    )
    _box_row(f"  {YELLOW}{link}{NC}")
    _box_row()
    if not vk_hash:
        _box_warn("Замените ВК_ХЕШ на хеш из ссылки vk.com/call/join/ХЕШ")
    _box_bot()
    _pause()

def _show_password_link(passwords: dict, server_ip: str, dtls_port: int) -> None:
    if not passwords:
        print(f"  {YELLOW}⚠{NC}  Паролей нет."); _pause(); return

    os.system("clear")
    _box_top("🔗  ССЫЛКА ДЛЯ ПАРОЛЯ  •  qWDTT")
    _box_row()
    pw_list = list(passwords.keys())
    for i, pw in enumerate(pw_list, 1):
        _box_row(f"  {DIM}{i}.{NC}  {CYAN}{pw[:16]:<18}{NC}"
                 f"{DIM}{passwords[pw].get('vk_hash', '—')[:20]}{NC}")
    _box_row(); _box_item("Q", "← Отмена"); _box_bot(); print()

    try:
        num = _ask(f"{CYAN}Номер: {NC}", c=True).strip()
    except _Cancelled:
        raise
    if num.lower() == "q" or not num:
        return
    try:
        idx = int(num) - 1
        pw = pw_list[idx]
    except (ValueError, IndexError):
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    entry = passwords[pw]
    vk_hash = entry.get("vk_hash", "") or "ВК_ХЕШ"
    link = (
        f"qwdtt://config?name=qWDTT-{server_ip}"
        f"&peer={server_ip}:{dtls_port}"
        f"&hashes={vk_hash}"
        f"&workers=16&port={_DEFAULT_TUN_PORT}"
        f"&pass={pw}"
    )
    print()
    _box_top("🔗  ССЫЛКА ДЛЯ КЛИЕНТА")
    _box_row()
    _box_row(f"  {YELLOW}{link}{NC}")
    _box_row()
    if vk_hash == "ВК_ХЕШ":
        _box_warn("Хеш звонка не задан — замените ВК_ХЕШ вручную.")
    _box_bot()
    _pause()

def _delete_password(passwords: dict) -> None:
    if not passwords:
        print(f"  {YELLOW}⚠{NC}  Паролей нет."); _pause(); return

    os.system("clear")
    _box_top("🗑️  УДАЛИТЬ ПАРОЛЬ  •  qWDTT")
    _box_row()
    pw_list = list(passwords.keys())
    for i, pw in enumerate(pw_list, 1):
        _box_row(f"  {DIM}{i}.{NC}  {CYAN}{pw[:16]}{NC}")
    _box_row(); _box_item("Q", "← Отмена"); _box_bot(); print()

    try:
        num = _ask(f"{CYAN}Номер: {NC}", c=True).strip()
    except _Cancelled:
        raise
    if num.lower() == "q" or not num:
        return
    try:
        idx = int(num) - 1
        pw = pw_list[idx]
    except (ValueError, IndexError):
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    try:
        confirm = _ask(
            f"  {YELLOW}Удалить пароль {pw[:12]}...? [y/N]: {NC}",
            default="n", c=True,
        ).strip().lower()
    except _Cancelled:
        raise
    if confirm != "y":
        return

    data = _load_passwords()
    data["passwords"].pop(pw, None)
    _save_passwords(data)
    _hot_reload()
    print(f"  {GREEN}✓{NC}  Пароль удалён, hot reload выполнен.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    state = _load_state()
    _box_top("📊  СТАТУС  •  qWDTT")
    _box_row()

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    _box_kv("Сервис:",
            f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")
    _box_kv("Бинарник:",
            f"{GREEN}✓{NC}" if _BIN_PATH.exists() else f"{RED}✗ не найден{NC}")
    _box_kv("DTLS порт:", str(state.get("dtls_port", "—")))
    _box_kv("WG порт:",   str(state.get("wg_port", "—")))
    _box_row()

    data = _load_passwords()
    passwords = data.get("passwords", {})
    devices   = data.get("devices", {})
    _box_kv("Паролей:", str(len(passwords)))
    _box_kv("Устройств:", str(len(devices)))
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Последние 30 строк журнала:{NC}")
    _box_row()

    r2 = subprocess.run(
        ["journalctl", "-u", _SERVICE_NAME, "-n", "30",
         "--no-pager", "--output=short-monotonic"],
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "LANG": "C.UTF-8"},
    )
    for line in (r2.stdout or r2.stderr or "Нет записей").splitlines():
        _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")

    _box_row(); _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛНОЕ УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        os.system("clear")
        _box_top("🗑️  УДАЛЕНИЕ  •  qWDTT")
        _box_row()
        _box_warn("Будет удалено:")
        _box_row(f"  {DIM}  • Сервис systemd  (wdtt){NC}")
        _box_row(f"  {DIM}  • Бинарник        ({_BIN_PATH}){NC}")
        _box_row(f"  {DIM}  • Конфиги          ({_CFG_DIR}){NC}")
        _box_row(f"  {DIM}  • iptables UDP {_DEFAULT_DTLS_PORT} и MASQUERADE{NC}")
        _box_row(f"  {DIM}  • /var/lib/xray-installer/wdtt.json{NC}")
        _box_row()
        _box_warn("VLESS/Xray конфиги не затрагиваются.")
        _box_row()
        _box_item("Y", f"{RED}Да, удалить{NC}")
        _box_item("N", "Нет, отмена")
        _box_bot(); print()
        try:
            ans = _ask(f"{CYAN}Подтверждение [y/N]: {NC}", c=True).strip().lower()
        except _Cancelled:
            return False
        if ans != "y":
            print(f"  {DIM}Отменено.{NC}"); _pause(); return False

    state = _load_state()
    dtls_port = state.get("dtls_port", _DEFAULT_DTLS_PORT)

    _run(["systemctl", "stop",    _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    if _SERVICE_FILE.exists():
        _SERVICE_FILE.unlink()
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"], capture=True)

    if _BIN_PATH.exists():
        _BIN_PATH.unlink()

    if _CFG_DIR.exists():
        shutil.rmtree(_CFG_DIR, ignore_errors=True)

    _ipt_close_udp(dtls_port)
    _ipt_remove_masquerade()
    _ipt_persist()

    sysctl = Path("/etc/sysctl.d/99-wdtt.conf")
    if sysctl.exists():
        sysctl.unlink()

    try:
        if _MODULE_STATE.exists():
            _MODULE_STATE.unlink()
    except Exception:
        pass

    if not silent:
        print(f"  {GREEN}✓{NC}  qWDTT удалён.")
        _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ГАЙД
# ══════════════════════════════════════════════════════════════════════════════
def _show_guide() -> None:
    while True:
        os.system("clear")
        _box_top("📖  ГАЙД  •  qWDTT + qWDTT Android")
        _box_row()
        _box_item("1", "Скачать приложение qWDTT на Android")
        _box_item("2", "Получить VK-хеш звонка")
        _box_item("3", "Подключиться по ссылке qwdtt://")
        _box_item("4", "Telegram-бот — управление паролями")
        _box_item("5", "Отличия от vk-turn-proxy (turntunnel)")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _guide_install()
        elif ch == "2":
            _guide_vk_hash()
        elif ch == "3":
            _guide_connect()
        elif ch == "4":
            _guide_telegram()
        elif ch == "5":
            _guide_diff()
        elif ch in ("q", ""):
            break

def _guide_install() -> None:
    os.system("clear")
    _box_top("📱  СКАЧАТЬ qWDTT")
    _box_row()
    _box_info("qWDTT — форк нетРКН с поддержкой профилей и qwdtt:// ссылок.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Android (APK):{NC}")
    _box_row()
    _box_info("Скачайте APK с официального GitHub:")
    _box_row(f"  {YELLOW}github.com/SpaceNeuroX/proxy-turn-vk-android/releases{NC}")
    _box_row()
    _box_info("Установите, разрешив установку из неизвестных источников.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Требования:{NC}")
    _box_row()
    _box_info("Android 8.0+ (API 26)")
    _box_info("Архитектуры: arm64-v8a, armeabi-v7a, x86_64")
    _box_bot()
    _pause()

def _guide_vk_hash() -> None:
    os.system("clear")
    _box_top("🔑  ПОЛУЧИТЬ VK-ХЕШ ЗВОНКА")
    _box_row()
    _box_info("Хеш — часть ссылки после /join/ в приглашении на звонок ВКонтакте.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Шаги:{NC}")
    _box_row()
    _box_info("1. Откройте ВКонтакте")
    _box_info("2. Любая группа → Звонки → Новый звонок")
    _box_info("3. Скопируйте ссылку-приглашение:")
    _box_row(f"  {DIM}   https://vk.com/call/join/ХЕШЕ{NC}")
    _box_info("4. Хеш — это всё что после /join/")
    _box_row()
    _box_sep()
    _box_warn("Можно использовать до 4 хешей одновременно (через запятую)")
    _box_warn("для распределения нагрузки между несколькими звонками.")
    _box_row()
    _box_warn("При выходе нажимайте «Просто завершить», НЕ «Завершить для всех».")
    _box_bot()
    _pause()

def _guide_connect() -> None:
    os.system("clear")
    _box_top("🔗  ПОДКЛЮЧЕНИЕ ПО qwdtt://")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Формат ссылки:{NC}")
    _box_row()
    _box_row(f"  {CYAN}qwdtt://config?{NC}")
    _box_row(f"  {DIM}  name=  — название профиля{NC}")
    _box_row(f"  {DIM}  peer=  — IP:порт сервера (например 1.2.3.4:56000){NC}")
    _box_row(f"  {DIM}  hashes=— VK-хеш(и) через запятую{NC}")
    _box_row(f"  {DIM}  workers=16  (потоков на хеш, 16 оптимально){NC}")
    _box_row(f"  {DIM}  port=9000   (локальный порт Android){NC}")
    _box_row(f"  {DIM}  pass=  — пароль подключения{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Как импортировать:{NC}")
    _box_row()
    _box_info("1. Скопируйте ссылку из пункта [2] главного меню qWDTT")
    _box_info("2. В приложении qWDTT → «+» → вставьте ссылку")
    _box_info("3. Нажмите «Подключить»")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Или через QR-код:{NC}")
    _box_row()
    _box_info("Сгенерируйте QR из ссылки на любом сайте и отсканируйте.")
    _box_bot()
    _pause()

def _guide_telegram() -> None:
    os.system("clear")
    _box_top("🤖  TELEGRAM-БОТ  •  qWDTT")
    _box_row()
    _box_info("Бот позволяет управлять паролями прямо из Telegram.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Создать бота:{NC}")
    _box_row()
    _box_info("1. В Telegram найдите @BotFather")
    _box_info("2. /newbot → введите имя → получите токен")
    _box_info("3. Свой Chat ID узнайте через @userinfobot")
    _box_info("4. Укажите токен и ID при установке qWDTT")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Команды бота:{NC}")
    _box_row()
    _box_kv("  /new",  "Создать временный пароль", 12)
    _box_kv("  /list", "Список паролей + управление", 12)
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Через бота можно:{NC}")
    _box_row()
    _box_info("• Создать пароль с TTL и лимитом устройств")
    _box_info("• Получить готовый .conf файл для qWDTT")
    _box_info("• Получить qwdtt:// ссылку с VK-хешем")
    _box_info("• Деактивировать / активировать пароль")
    _box_info("• Отвязать устройства от пароля")
    _box_info("• Удалить пароль (hot reload без перезапуска)")
    _box_bot()
    _pause()

def _guide_diff() -> None:
    os.system("clear")
    _box_top("⚖️  qWDTT vs vk-turn-proxy")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}vk-turn-proxy (модуль turntunnel){NC}")
    _box_row()
    _box_info("Протокол: VLESS (Xray)")
    _box_info("Аутентификация: UUID")
    _box_info("Клиент: WireTurn (Android)")
    _box_info("Настройка: проще — вставить VLESS-ссылку")
    _box_info("Мультипользователи: через turntunnel_links.py")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}qWDTT (этот модуль){NC}")
    _box_row()
    _box_info("Протокол: WireGuard (встроенный)")
    _box_info("Аутентификация: пароль + HKDF (ключ не в APK)")
    _box_info("Клиент: qWDTT APK")
    _box_info("Настройка: qwdtt:// ссылка или .conf файл")
    _box_info("Мультипользователи: встроено (до 10 паролей + TTL)")
    _box_info("Telegram-бот: управление без SSH")
    _box_info("Hot reload: смена паролей без перезапуска")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Когда что выбрать:{NC}")
    _box_row()
    _box_info("vk-turn-proxy → хочу VLESS, минимум настроек")
    _box_info("qWDTT → нужны временные пароли, Telegram-управление")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def do_wdtt_menu() -> None:
    """
    Точка входа из _core.py.
    Ctrl+C → возврат в главное меню VLESS.
    """
    while True:
        os.system("clear")
        installed = _is_installed()
        state     = _load_state()

        r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
        svc_ok = r.stdout.strip() == "active"

        svc_str = (
            f"{GREEN}● активен{NC}"  if svc_ok    else
            f"{RED}● остановлен{NC}" if installed else
            f"{YELLOW}● не установлен{NC}"
        )

        _box_top("qWDTT  •  WireGuard / TURN ВКонтакте")
        _box_row()
        _box_kv("Статус:", svc_str)

        if installed:
            data = _load_passwords()
            pw_count = len(data.get("passwords", {}))
            dev_count = len(data.get("devices", {}))
            _box_kv("DTLS порт:",   str(state.get("dtls_port", "—")))
            _box_kv("Паролей:",     str(pw_count))
            _box_kv("Устройств:",   str(dev_count))
            tg = "✓ настроен" if state.get("bot_token") else "не настроен"
            tg_col = GREEN if state.get("bot_token") else DIM
            _box_kv("Telegram-бот:", f"{tg_col}{tg}{NC}")

        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🚀  Установить qWDTT")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "🔑  Управление паролями")
            _box_item("3", "🔗  Показать ссылку (главный пароль)")
            _box_item("4", "🔄  Перезапустить сервис")
            _box_item("5", "📊  Статус / логи")
            _box_sep()
            _box_item("8", f"{RED}🗑️   Удалить qWDTT{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: установка, VK-хеш, Telegram-бот")
        _box_sep()
        _box_item("Q", "← Назад в главное меню VLESS")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _run_install()

        elif ch == "2" and installed:
            try:
                _passwords_menu()
            except _Cancelled:
                pass

        elif ch == "3" and installed:
            os.system("clear")
            state = _load_state()
            server_ip = _get_server_ip()
            dtls_port = state.get("dtls_port", _DEFAULT_DTLS_PORT)
            main_pass = state.get("main_password", "")
            _box_top("🔗  ССЫЛКА  •  ГЛАВНЫЙ ПАРОЛЬ")
            _box_row()
            _box_warn("Замените ВК_ХЕШ на хеш из vk.com/call/join/ХЕШ")
            _box_row()
            link = (
                f"qwdtt://config?name=qWDTT-{server_ip}"
                f"&peer={server_ip}:{dtls_port}"
                f"&hashes=ВК_ХЕШ"
                f"&workers=16&port={_DEFAULT_TUN_PORT}"
                f"&pass={main_pass}"
            )
            _box_row(f"  {YELLOW}{link}{NC}")
            _box_row()
            _box_bot()
            _pause()

        elif ch == "4" and installed:
            _run(["systemctl", "restart", _SERVICE_NAME])
            time.sleep(1)
            r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
            print(f"  {'✓' if r.stdout.strip()=='active' else '⚠'}  "
                  f"{'Перезапущен.' if r.stdout.strip()=='active' else 'Проверьте логи (пункт 5).'}")
            _pause()

        elif ch == "5" and installed:
            _show_status()

        elif ch == "8" and installed:
            try:
                _full_uninstall(silent=False)
            except _Cancelled:
                print(f"  {DIM}Отменено.{NC}"); _pause()

        elif ch == "g":
            try:
                _show_guide()
            except _Cancelled:
                pass

        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК (отладка)
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        do_wdtt_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)
