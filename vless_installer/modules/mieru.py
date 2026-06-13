"""
vless_installer/modules/mieru.py
───────────────────────────────────────────────────────────────────────────────
Mieru — mTLS туннель с рандомным padding и защитой от анализа трафика.

Как это работает:
  Mieru использует mTLS (mutual TLS) поверх TCP или UDP.
  Трафик выглядит как случайный зашумлённый поток — нет паттернов
  которые DPI может идентифицировать. Дополнительно — рандомный padding
  и задержки делают статистический анализ неэффективным.
  Не требует домена — работает по IP.

Схема трафика:
  Клиент (Karing / sing-box / Nekobox)
    │  mTLS + random padding, TCP или UDP
    ▼
  mita server :2012  (или диапазон портов)
    │  проверка временной метки ±30 сек
    ▼
  SOCKS5 :1080 (встроенный)
    │
    ▼
  Интернет

Схема с каскадом (Entry→Exit):
  Клиент
    │  mTLS
    ▼
  mita Entry (RU)
    │  redsocks + iptables → Exit
    ▼
  mita Exit (EU)
    │
    ▼
  Интернет

Отличия от NaiveProxy:
  • Не требует домена — только IP и порт
  • mTLS вместо HTTPS — другой fingerprint
  • Рандомный padding — против статистического анализа
  • Требует синхронизацию времени ±30 сек (ntpd/chrony)
  • Клиенты: Karing, sing-box, Nekobox

Что модуль делает:
  • Скачивает mita (server) и mieru (client CLI) с GitHub
  • Генерирует server config (mita apply config)
  • Создаёт systemd-сервис mita
  • Открывает TCP/UDP порты в iptables
  • Управление пользователями через mita CLI
  • Генерация sing-box JSON конфига и QR-кода для клиента
  • Проверка синхронизации времени

Что модуль НЕ трогает:
  • Xray config.json и VLESS-inbound
  • state.json инсталлера
  • iptables-правила других модулей
  • Любые другие службы

Точка входа из _core.py:
    from vless_installer.modules.mieru import do_mieru_menu
    do_mieru_menu()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
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
_MITA_BIN        = Path("/usr/local/bin/mita")
_MIERU_BIN       = Path("/usr/local/bin/mieru")
_CFG_DIR         = Path("/etc/mita")
_SERVER_CFG      = Path("/etc/mita/server.json")
_SERVICE_FILE    = Path("/etc/systemd/system/mita.service")
_SERVICE_NAME    = "mita"
_MODULE_STATE    = Path("/var/lib/xray-installer/mieru.json")

_GITHUB_API      = "https://api.github.com/repos/enfein/mieru/releases/latest"

# Порты по умолчанию — диапазон для мультиплексирования
_DEFAULT_PORT_START = 2012
_DEFAULT_PORT_END   = 2022
_DEFAULT_PROTOCOL   = "TCP"  # TCP или UDP

_BOX_W = 66

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ
# ══════════════════════════════════════════════════════════════════════════════
def _plain(s: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', s)

def _wlen(s: str) -> int:
    import unicodedata as _ud
    plain = _plain(s); width, chars = 0, list(plain); i = 0
    while i < len(chars):
        ch = chars[i]; cp = ord(ch)
        next_cp = ord(chars[i + 1]) if i + 1 < len(chars) else 0
        if next_cp == 0xFE0F: width += 2; i += 2; continue
        if cp == 0x200D or (0x300 <= cp <= 0x36F) or (0xFE00 <= cp <= 0xFE0F):
            i += 1; continue
        eaw = _ud.east_asian_width(ch)
        if eaw in ('W', 'F'): width += 2
        elif eaw == 'N' and (0x1F300 <= cp <= 0x1FAFF or 0x2B00 <= cp <= 0x2BFF): width += 2
        else: width += 1
        i += 1
    return width

def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad = _BOX_W - _wlen(title); lpad = pad // 2; rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None: print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
def _box_bot() -> None: print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        acc, plain = 0, _plain(text); cut = 0
        for i, ch in enumerate(plain):
            import unicodedata as _ud
            acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc > _BOX_W - 1: cut = i; break
        text = text[:cut] + "…"; w = _wlen(text)
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

def _box_link(link: str, color: str = "") -> None:
    color = color or YELLOW; max_w = _BOX_W - 2; plain_link = _plain(link); i = 0
    while i < len(plain_link):
        chunk = plain_link[i:i + max_w]
        pad = max(0, _BOX_W - 2 - len(chunk))
        print(f"{CYAN}║{NC}  {color}{chunk}{NC}{' ' * pad}{CYAN}║{NC}")
        i += max_w

def _print_qr(data: str, label: str = "") -> None:
    if not shutil.which("qrencode"):
        print(f"  {YELLOW}⚠{NC}  qrencode не установлен: apt install qrencode")
        return
    if label:
        print(f"  {CYAN}→{NC}  QR: {YELLOW}{label}{NC}")
    print()
    try:
        subprocess.run(["qrencode", "-t", "UTF8", "-m", "1", data], check=True)
    except Exception as e:
        print(f"  {RED}✗{NC}  QR ошибка: {e}")
    print()

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
class _Cancelled(Exception):
    pass

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True); input()
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
         cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if cwd: kw["cwd"] = cwd
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _gen_password(length: int = 16) -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    return ''.join(secrets.choice(chars) for _ in range(length))

def _get_server_ip() -> str:
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
    except Exception: pass
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except Exception: pass
    return "ВАШ_IP"

def _is_amd64() -> bool:
    return platform.machine().lower() in ("x86_64", "amd64")

# ══════════════════════════════════════════════════════════════════════════════
#  СОСТОЯНИЕ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def _load_state() -> dict:
    if not _MODULE_STATE.exists(): return {}
    try: return json.loads(_MODULE_STATE.read_text())
    except Exception: return {}

def _save_state(data: dict) -> None:
    try:
        _MODULE_STATE.parent.mkdir(parents=True, exist_ok=True)
        _MODULE_STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        _MODULE_STATE.chmod(0o600)
    except Exception as e:
        print(f"  {YELLOW}⚠{NC}  Не удалось сохранить mieru.json: {e}")

def _is_installed() -> bool:
    return _MITA_BIN.exists() and _SERVICE_FILE.exists()

# ══════════════════════════════════════════════════════════════════════════════
#  БИНАРНИКИ
# ══════════════════════════════════════════════════════════════════════════════
def _get_latest_version() -> str:
    try:
        req = urllib.request.Request(
            _GITHUB_API, headers={"User-Agent": "VLESS-Ultimate-Installer"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        return data.get("tag_name", "unknown").lstrip("v")
    except Exception: return "unknown"

def _get_download_urls(version: str) -> tuple[str, str]:
    """Возвращает (mita_url, mieru_url) для текущей архитектуры."""
    arch = "amd64" if _is_amd64() else "arm64"
    base = f"https://github.com/enfein/mieru/releases/download/v{version}"
    mita_url  = f"{base}/mita_{version}_linux_{arch}.tar.gz"
    mieru_url = f"{base}/mieru_{version}_linux_{arch}.tar.gz"
    return mita_url, mieru_url

def _download_binary(url: str, dest: Path, name: str) -> bool:
    tmp = Path(tempfile.mkdtemp())
    try:
        archive = tmp / "bin.tar.gz"
        print(f"  {CYAN}→{NC}  Скачиваю {name}...")
        urllib.request.urlretrieve(url, str(archive))

        _run(["tar", "-xzf", str(archive), "-C", str(tmp)], check=True)

        # Ищем бинарник в распакованном
        candidates = list(tmp.glob(f"**/{name}"))
        if not candidates:
            candidates = list(tmp.glob("**/mita")) + list(tmp.glob("**/mieru"))
        if not candidates:
            print(f"  {RED}✗{NC}  {name} не найден в архиве.")
            return False

        bin_file = candidates[0]
        with bin_file.open("rb") as f:
            if f.read(4) != b'\x7fELF':
                print(f"  {RED}✗{NC}  {name} — не ELF бинарник.")
                return False

        shutil.copy2(str(bin_file), str(dest))
        dest.chmod(0o755)
        print(f"  {GREEN}✓{NC}  {name} установлен: {dest}")
        return True
    except Exception as e:
        print(f"  {RED}✗{NC}  Ошибка загрузки {name}: {e}")
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def _get_installed_version() -> Optional[str]:
    if not _MITA_BIN.exists(): return None
    r = _run([str(_MITA_BIN), "version"], capture=True)
    out = (r.stdout or "") + (r.stderr or "")
    m = re.search(r'v?(\d+\.\d+[\.\d]*)', out)
    return m.group(1) if m else "unknown"

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ СЕРВЕРА
# ══════════════════════════════════════════════════════════════════════════════
def _build_server_config(users: list, port_start: int, port_end: int,
                          protocol: str) -> dict:
    """
    Генерирует server config для mita apply config.
    Формат: https://github.com/enfein/mieru/blob/main/docs/server-config.md
    """
    port_bindings = []
    if port_start == port_end:
        port_bindings.append({
            "port": port_start,
            "protocol": protocol,
        })
    else:
        port_bindings.append({
            "portRange": f"{port_start}-{port_end}",
            "protocol": protocol,
        })

    user_entries = []
    for u in users:
        user_entries.append({
            "name":     u["username"],
            "password": u["password"],
        })

    return {
        "portBindings": port_bindings,
        "users": user_entries,
        "loggingLevel": "WARNING",
        "mtu": 1400,
    }

def _apply_server_config(cfg: dict) -> Optional[str]:
    """Применяет конфиг через mita apply config. Возвращает ошибку или None."""
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    cfg_path = _CFG_DIR / "server.json"
    cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    cfg_path.chmod(0o600)
    _SERVER_CFG.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))

    r = _run([str(_MITA_BIN), "apply", "config", str(cfg_path)], capture=True)
    if r.returncode != 0:
        return (r.stderr or r.stdout or "")[:300]
    return None

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES
# ══════════════════════════════════════════════════════════════════════════════
def _ipt_rule_exists(proto: str, port: int) -> bool:
    r = _run(
        ["iptables", "-t", "filter", "-C", "INPUT",
         "-p", proto.lower(), "--dport", str(port), "-j", "ACCEPT"],
        capture=True,
    )
    return r.returncode == 0

def _ipt_open_port(proto: str, port_start: int, port_end: int) -> None:
    proto = proto.lower()
    if port_start == port_end:
        if not _ipt_rule_exists(proto, port_start):
            _run(["iptables", "-t", "filter", "-I", "INPUT", "1",
                  "-p", proto, "--dport", str(port_start), "-j", "ACCEPT"])
    else:
        # Диапазон портов
        r = _run(
            ["iptables", "-t", "filter", "-C", "INPUT",
             "-p", proto, "--dport", f"{port_start}:{port_end}", "-j", "ACCEPT"],
            capture=True,
        )
        if r.returncode != 0:
            _run(["iptables", "-t", "filter", "-I", "INPUT", "1",
                  "-p", proto, "--dport", f"{port_start}:{port_end}", "-j", "ACCEPT"])

def _ipt_close_port(proto: str, port_start: int, port_end: int) -> None:
    proto = proto.lower()
    if port_start == port_end:
        for _ in range(5):
            if not _ipt_rule_exists(proto, port_start): break
            _run(["iptables", "-t", "filter", "-D", "INPUT",
                  "-p", proto, "--dport", str(port_start), "-j", "ACCEPT"])
    else:
        for _ in range(5):
            r = _run(
                ["iptables", "-t", "filter", "-C", "INPUT",
                 "-p", proto, "--dport", f"{port_start}:{port_end}", "-j", "ACCEPT"],
                capture=True,
            )
            if r.returncode != 0: break
            _run(["iptables", "-t", "filter", "-D", "INPUT",
                  "-p", proto, "--dport", f"{port_start}:{port_end}", "-j", "ACCEPT"])

def _ipt_persist() -> None:
    if shutil.which("netfilter-persistent"):
        _run(["netfilter-persistent", "save"], capture=True); return
    rules_dir = Path("/etc/iptables")
    rules_dir.mkdir(parents=True, exist_ok=True)
    r = _run(["iptables-save"], capture=True)
    if r.returncode == 0 and r.stdout:
        (rules_dir / "rules.v4").write_text(r.stdout)

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD
# ══════════════════════════════════════════════════════════════════════════════
def _install_service() -> None:
    _SERVICE_FILE.write_text(
        "[Unit]\n"
        "Description=Mieru Proxy Server (mita)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={_MITA_BIN} start\n"
        f"ExecStop={_MITA_BIN} stop\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "NoNewPrivileges=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", _SERVICE_NAME])

# ══════════════════════════════════════════════════════════════════════════════
#  СИНХРОНИЗАЦИЯ ВРЕМЕНИ
# ══════════════════════════════════════════════════════════════════════════════
def _check_time_sync() -> tuple[bool, str]:
    """Проверяет синхронизацию времени. Mieru требует ±30 сек."""
    # Через timedatectl
    r = _run(["timedatectl", "status"], capture=True)
    if r.returncode == 0:
        out = r.stdout or ""
        if "synchronized: yes" in out or "NTP synchronized: yes" in out:
            return True, "NTP синхронизирован (timedatectl)"
        if "synchronized: no" in out or "NTP synchronized: no" in out:
            return False, "NTP не синхронизирован!"

    # Через chronyc
    r2 = _run(["chronyc", "tracking"], capture=True)
    if r2.returncode == 0:
        return True, "Chrony активен"

    return True, "Статус неизвестен — проверьте вручную"

def _ensure_time_sync() -> None:
    """Устанавливает chrony если нет NTP."""
    if shutil.which("chronyc") or shutil.which("ntpd"):
        return
    print(f"  {CYAN}→{NC}  Устанавливаю chrony для синхронизации времени...")
    _run(["apt-get", "install", "-y", "chrony"], capture=True)
    _run(["systemctl", "enable", "--now", "chrony"])

# ══════════════════════════════════════════════════════════════════════════════
#  SING-BOX КОНФИГ ДЛЯ КЛИЕНТА
# ══════════════════════════════════════════════════════════════════════════════
def _gen_singbox_outbound(server_ip: str, port_start: int, port_end: int,
                           protocol: str, username: str, password: str) -> dict:
    """
    Генерирует sing-box outbound для mieru.
    Импортируется в Karing / Nekobox / sing-box CLI.
    """
    port_entry = port_start if port_start == port_end else f"{port_start}-{port_end}"
    return {
        "type": "mieru",
        "tag": f"mieru-{username}",
        "server": server_ip,
        "server_port": port_entry,
        "transport": protocol.upper(),
        "username": username,
        "password": password,
    }

def _gen_client_share_link(server_ip: str, port_start: int, port_end: int,
                            protocol: str, username: str, password: str) -> str:
    """
    Генерирует mieru:// share link.
    Формат: mieru://user:pass@host:port?protocol=TCP
    """
    port_str = str(port_start) if port_start == port_end else f"{port_start}-{port_end}"
    return (
        f"mieru://{username}:{password}@{server_ip}:{port_str}"
        f"?protocol={protocol.upper()}"
    )

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install() -> None:
    try: _run_install_inner()
    except _Cancelled:
        print(f"\n  {YELLOW}Установка прервана.{NC}\n"); _pause()

def _run_install_inner() -> None:
    os.system("clear")
    _box_top("🔒  УСТАНОВКА  •  MIERU")
    _box_row()

    if _is_installed():
        _box_warn("Mieru уже установлен.")
        _box_row()
        _box_item("1", "Переустановить (сохранить пользователей)")
        _box_item("2", f"Переустановить полностью  {YELLOW}(новые пользователи){NC}")
        _box_item("Q", "← Отмена")
        _box_bot(); print()
        try:
            ch = _ask(f"{CYAN}Выбор [1/2/Q]: {NC}", c=True).strip().lower()
        except _Cancelled: return
        if ch == "q" or not ch: return
        if ch == "2": _full_uninstall(silent=True)

    # ── Параметры ─────────────────────────────────────────────────────────────
    state = _load_state()
    old_port_start = state.get("port_start", _DEFAULT_PORT_START)
    old_port_end   = state.get("port_end",   _DEFAULT_PORT_END)
    old_protocol   = state.get("protocol",   _DEFAULT_PROTOCOL)

    os.system("clear")
    _box_top("🔒  НАСТРОЙКА  •  MIERU")
    _box_row()
    _box_info("Mieru не требует домена — работает по IP.")
    _box_info("Рекомендуется диапазон портов для лучшей маскировки.")
    _box_row()
    _box_warn("ВАЖНО: синхронизация времени ±30 сек обязательна!")
    _box_bot(); print()

    try:
        raw = _ask(
            f"  {CYAN}Начальный порт [{old_port_start}]: {NC}",
            default=str(old_port_start), c=True,
        )
        port_start = int(raw) if raw.isdigit() else old_port_start

        raw = _ask(
            f"  {CYAN}Конечный порт [{old_port_end}] (=начальный для одного порта): {NC}",
            default=str(old_port_end), c=True,
        )
        port_end = int(raw) if raw.isdigit() else old_port_end
        if port_end < port_start:
            port_end = port_start

        raw = _ask(
            f"  {CYAN}Протокол [TCP/UDP, Enter={old_protocol}]: {NC}",
            default=old_protocol, c=True,
        ).strip().upper()
        protocol = raw if raw in ("TCP", "UDP") else old_protocol

    except _Cancelled: raise

    # ── Установка ─────────────────────────────────────────────────────────────
    os.system("clear")
    _box_top("🔒  УСТАНОВКА  •  MIERU")
    _box_row()

    # 1. Версия
    _box_info("Определяю последнюю версию...")
    _box_bot(); print()
    version = _get_latest_version()
    if version == "unknown":
        print(f"  {YELLOW}⚠{NC}  Не удалось определить версию, использую 1.17.0")
        version = "1.17.0"
    print(f"  {GREEN}✓{NC}  Версия: {version}")

    # 2. Бинарники
    mita_url, mieru_url = _get_download_urls(version)
    if not _download_binary(mita_url, _MITA_BIN, "mita"):
        print(f"  {RED}✗{NC}  Не удалось установить mita."); _pause(); return
    _download_binary(mieru_url, _MIERU_BIN, "mieru")  # опционально, не критично

    # 3. Синхронизация времени
    print(f"  {CYAN}→{NC}  Проверяю синхронизацию времени...")
    _ensure_time_sync()
    sync_ok, sync_msg = _check_time_sync()
    if sync_ok:
        print(f"  {GREEN}✓{NC}  {sync_msg}")
    else:
        print(f"  {YELLOW}⚠{NC}  {sync_msg}")
        print(f"  {DIM}Mieru может не работать без синхронизации времени!{NC}")

    # 4. Пользователи
    users = state.get("users") or []
    if not users:
        first_user = "admin"
        first_pass = _gen_password()
        users = [{"username": first_user, "password": first_pass}]
        print(f"  {GREEN}✓{NC}  Создан первый пользователь: "
              f"{YELLOW}{first_user}{NC} / {YELLOW}{first_pass}{NC}")

    # 5. Конфиг
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    cfg = _build_server_config(users, port_start, port_end, protocol)
    err = _apply_server_config(cfg)
    if err:
        print(f"  {RED}✗{NC}  Ошибка применения конфига: {err}")
        _pause(); return
    print(f"  {GREEN}✓{NC}  Конфиг применён.")

    # 6. Systemd
    _install_service()

    # 7. iptables
    _ipt_open_port(protocol, port_start, port_end)
    _ipt_persist()
    print(f"  {GREEN}✓{NC}  iptables: {protocol} {port_start}-{port_end} открыт.")

    # 8. Запуск
    _run(["systemctl", "start", _SERVICE_NAME])
    time.sleep(2)
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    if svc_ok:
        print(f"  {GREEN}✓{NC}  mita запущен.")
    else:
        print(f"  {YELLOW}⚠{NC}  Сервис не запустился — проверьте логи (пункт 5).")

    # 9. Сохраняем состояние
    _save_state({
        "installed":  True,
        "port_start": port_start,
        "port_end":   port_end,
        "protocol":   protocol,
        "version":    version,
        "users":      users,
    })

    # ── Итог ──────────────────────────────────────────────────────────────────
    server_ip  = _get_server_ip()
    share_link = _gen_client_share_link(
        server_ip, port_start, port_end, protocol,
        users[0]["username"], users[0]["password"],
    )

    os.system("clear")
    _box_top("✅  УСТАНОВКА ЗАВЕРШЕНА  •  MIERU")
    _box_row()
    _box_ok("mita установлен и запущен." if svc_ok else
            "Установлен, но сервис не запустился — проверьте логи.")
    _box_row()
    _box_kv("IP сервера:", f"{YELLOW}{server_ip}{NC}")
    port_str = str(port_start) if port_start == port_end else f"{port_start}-{port_end}"
    _box_kv("Порт(ы):",    f"{YELLOW}{port_str}/{protocol}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Ссылка для клиента (первый пользователь):{NC}")
    _box_row()
    _box_link(share_link)
    _box_row()
    _box_sep()
    _box_info("Клиенты: Karing, Nekobox (Android), sing-box CLI")
    _box_info("Добавьте пользователей через пункт [2].")
    _box_warn("Убедитесь что время на клиенте синхронизировано!")
    _box_bot()
    print()
    _print_qr(share_link, f"mieru:// для {users[0]['username']}")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# ══════════════════════════════════════════════════════════════════════════════
def _users_menu() -> None:
    while True:
        os.system("clear")
        state  = _load_state()
        users  = state.get("users", [])
        server_ip  = _get_server_ip()
        port_start = state.get("port_start", _DEFAULT_PORT_START)
        port_end   = state.get("port_end",   _DEFAULT_PORT_END)
        protocol   = state.get("protocol",   _DEFAULT_PROTOCOL)

        _box_top("👥  ПОЛЬЗОВАТЕЛИ  •  MIERU")
        _box_row()
        _box_kv("Пользователей:", str(len(users)))
        port_str = str(port_start) if port_start == port_end else f"{port_start}-{port_end}"
        _box_kv("Порт(ы):", f"{port_str}/{protocol}")
        _box_row(); _box_sep()

        if users:
            _box_row(f"  {BOLD}{CYAN}{'№':<4}{'Логин':<20}{'Пароль'}{NC}")
            _box_sep()
            for i, u in enumerate(users, 1):
                _box_row(
                    f"  {DIM}{i:<4}{NC}"
                    f"{CYAN}{u.get('username','?'):<20}{NC}"
                    f"{DIM}{u.get('password','?')[:16]}...{NC}"
                )
        else:
            _box_warn("Пользователей нет.")

        _box_row(); _box_sep()
        _box_item("1", "➕  Добавить пользователя")
        _box_item("2", "🔗  Показать ссылку + QR")
        _box_item("3", "📋  Показать sing-box JSON")
        _box_item("4", f"{RED}🗑️   Удалить пользователя{NC}")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":
            try: _add_user(state)
            except _Cancelled: pass
        elif ch == "2":
            try: _show_user_link(users, server_ip, port_start, port_end, protocol)
            except _Cancelled: pass
        elif ch == "3":
            try: _show_singbox_json(users, server_ip, port_start, port_end, protocol)
            except _Cancelled: pass
        elif ch == "4":
            try: _delete_user(users, state)
            except _Cancelled: pass
        elif ch in ("q", ""): break

def _add_user(state: dict) -> None:
    os.system("clear")
    _box_top("➕  ДОБАВИТЬ ПОЛЬЗОВАТЕЛЯ  •  MIERU")
    _box_row(); _box_bot(); print()

    try:
        username = _ask(f"  {CYAN}Логин: {NC}", c=True).strip()
        if not username:
            print(f"  {RED}✗{NC}  Логин не может быть пустым."); _pause(); return

        users = state.get("users", [])
        if any(u["username"] == username for u in users):
            print(f"  {YELLOW}⚠{NC}  Пользователь уже существует."); _pause(); return

        raw_pass = _ask(
            f"  {CYAN}Пароль (Enter=авто): {NC}", default="", c=True,
        ).strip()
        password = raw_pass or _gen_password()
    except _Cancelled: raise

    users.append({"username": username, "password": password})
    state["users"] = users
    _save_state(state)

    # Применяем новый конфиг
    cfg = _build_server_config(
        users,
        state.get("port_start", _DEFAULT_PORT_START),
        state.get("port_end",   _DEFAULT_PORT_END),
        state.get("protocol",   _DEFAULT_PROTOCOL),
    )
    err = _apply_server_config(cfg)
    if not err:
        _run(["systemctl", "reload-or-restart", _SERVICE_NAME])

    server_ip  = _get_server_ip()
    port_start = state.get("port_start", _DEFAULT_PORT_START)
    port_end   = state.get("port_end",   _DEFAULT_PORT_END)
    protocol   = state.get("protocol",   _DEFAULT_PROTOCOL)
    share_link = _gen_client_share_link(
        server_ip, port_start, port_end, protocol, username, password,
    )

    os.system("clear")
    _box_top("✅  ПОЛЬЗОВАТЕЛЬ ДОБАВЛЕН")
    _box_row()
    _box_kv("Логин:", f"{YELLOW}{username}{NC}")
    _box_kv("Пароль:", f"{YELLOW}{password}{NC}")
    if err: _box_warn(f"Ошибка конфига: {err}")
    else: _box_ok("Конфиг применён.")
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}mieru:// ссылка:{NC}")
    _box_row()
    _box_link(share_link)
    _box_row(); _box_bot()
    print()
    _print_qr(share_link, f"mieru:// для {username}")
    _pause()

def _show_user_link(users: list, server_ip: str,
                    port_start: int, port_end: int, protocol: str) -> None:
    if not users:
        print(f"  {YELLOW}⚠{NC}  Пользователей нет."); _pause(); return

    os.system("clear")
    _box_top("🔗  ССЫЛКА  •  MIERU")
    _box_row()
    for i, u in enumerate(users, 1):
        _box_row(f"  {DIM}{i}.{NC}  {CYAN}{u.get('username','?')}{NC}")
    _box_row(); _box_item("Q", "← Отмена"); _box_bot(); print()

    try:
        num = _ask(f"{CYAN}Номер: {NC}", c=True).strip()
    except _Cancelled: raise
    if num.lower() == "q" or not num: return
    try:
        idx = int(num) - 1; user = users[idx]
    except (ValueError, IndexError):
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    share_link = _gen_client_share_link(
        server_ip, port_start, port_end, protocol,
        user["username"], user["password"],
    )
    os.system("clear")
    _box_top(f"🔗  {user['username']}  •  MIERU")
    _box_row()
    _box_kv("Логин:", f"{YELLOW}{user['username']}{NC}")
    _box_kv("Пароль:", f"{YELLOW}{user['password']}{NC}")
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}mieru:// ссылка:{NC}")
    _box_row()
    _box_link(share_link)
    _box_row(); _box_bot()
    print()
    _print_qr(share_link, f"mieru:// для {user['username']}")
    _pause()

def _show_singbox_json(users: list, server_ip: str,
                        port_start: int, port_end: int, protocol: str) -> None:
    if not users:
        print(f"  {YELLOW}⚠{NC}  Пользователей нет."); _pause(); return

    os.system("clear")
    _box_top("📋  SING-BOX JSON  •  MIERU")
    _box_row()
    for i, u in enumerate(users, 1):
        _box_row(f"  {DIM}{i}.{NC}  {CYAN}{u.get('username','?')}{NC}")
    _box_row(); _box_item("Q", "← Отмена"); _box_bot(); print()

    try:
        num = _ask(f"{CYAN}Номер: {NC}", c=True).strip()
    except _Cancelled: raise
    if num.lower() == "q" or not num: return
    try:
        idx = int(num) - 1; user = users[idx]
    except (ValueError, IndexError):
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    outbound = _gen_singbox_outbound(
        server_ip, port_start, port_end, protocol,
        user["username"], user["password"],
    )
    json_str = json.dumps(outbound, indent=2, ensure_ascii=False)

    os.system("clear")
    _box_top("📋  SING-BOX OUTBOUND JSON")
    _box_row()
    _box_info("Вставьте в секцию outbounds вашего sing-box конфига:")
    _box_row()
    for line in json_str.splitlines():
        _box_row(f"  {DIM}{line}{NC}")
    _box_row(); _box_bot()
    _pause()

def _delete_user(users: list, state: dict) -> None:
    if not users:
        print(f"  {YELLOW}⚠{NC}  Пользователей нет."); _pause(); return
    if len(users) == 1:
        print(f"  {RED}✗{NC}  Нельзя удалить последнего пользователя."); _pause(); return

    os.system("clear")
    _box_top("🗑️  УДАЛИТЬ ПОЛЬЗОВАТЕЛЯ  •  MIERU")
    _box_row()
    for i, u in enumerate(users, 1):
        _box_row(f"  {DIM}{i}.{NC}  {CYAN}{u.get('username','?')}{NC}")
    _box_row(); _box_item("Q", "← Отмена"); _box_bot(); print()

    try:
        num = _ask(f"{CYAN}Номер: {NC}", c=True).strip()
    except _Cancelled: raise
    if num.lower() == "q" or not num: return
    try:
        idx = int(num) - 1; user = users[idx]
    except (ValueError, IndexError):
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    try:
        confirm = _ask(
            f"  {YELLOW}Удалить {user['username']}? [y/N]: {NC}",
            default="n", c=True,
        ).strip().lower()
    except _Cancelled: raise
    if confirm != "y": return

    users.pop(idx)
    state["users"] = users
    _save_state(state)

    cfg = _build_server_config(
        users,
        state.get("port_start", _DEFAULT_PORT_START),
        state.get("port_end",   _DEFAULT_PORT_END),
        state.get("protocol",   _DEFAULT_PROTOCOL),
    )
    err = _apply_server_config(cfg)
    if not err:
        _run(["systemctl", "reload-or-restart", _SERVICE_NAME])
    print(f"  {GREEN}✓{NC}  Пользователь удалён.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    state = _load_state()
    _box_top("📊  СТАТУС  •  MIERU")
    _box_row()

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    _box_kv("Сервис:",
            f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")
    _box_kv("Версия:", state.get("version", _get_installed_version() or "—"))

    port_start = state.get("port_start", "—")
    port_end   = state.get("port_end",   "—")
    protocol   = state.get("protocol",   "—")
    port_str   = str(port_start) if port_start == port_end else f"{port_start}-{port_end}"
    _box_kv("Порт(ы):", f"{port_str}/{protocol}")
    _box_kv("Пользователей:", str(len(state.get("users", []))))

    sync_ok, sync_msg = _check_time_sync()
    _box_kv("Время NTP:",
            f"{GREEN}✓ {sync_msg}{NC}" if sync_ok else f"{RED}✗ {sync_msg}{NC}")

    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Последние 30 строк журнала:{NC}")
    _box_row()

    r2 = subprocess.run(
        ["journalctl", "-u", _SERVICE_NAME, "-n", "30",
         "--no-pager", "--output=short-monotonic"],
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "LANG": "C.UTF-8"},
    )
    for line in (r2.stdout or "Нет записей").splitlines():
        _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")
    _box_row(); _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГАЙД
# ══════════════════════════════════════════════════════════════════════════════
def _show_guide() -> None:
    while True:
        os.system("clear")
        _box_top("📖  ГАЙД  •  MIERU")
        _box_row()
        _box_item("1", "Как работает Mieru")
        _box_item("2", "Синхронизация времени — почему важна")
        _box_item("3", "Клиентские приложения")
        _box_item("4", "TCP vs UDP — что выбрать")
        _box_item("5", "Чем Mieru отличается от NaiveProxy")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":   _guide_how()
        elif ch == "2": _guide_time()
        elif ch == "3": _guide_clients()
        elif ch == "4": _guide_protocol()
        elif ch == "5": _guide_diff()
        elif ch in ("q", ""): break

def _guide_how() -> None:
    os.system("clear")
    _box_top("⚙️  КАК РАБОТАЕТ MIERU")
    _box_row()
    _box_info("Mieru — mTLS туннель с защитой от анализа трафика.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Принцип:")
    _box_row()
    _box_info("mTLS — взаимная аутентификация клиента и сервера")
    _box_info("Рандомный padding — размер пакетов непредсказуем")
    _box_info("Временная метка — защита от replay атак (±30 сек)")
    _box_info("DPI видит зашумлённый зашифрованный поток без паттернов")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Схема:")
    _box_row()
    _box_row(f"  {CYAN}Клиент → mTLS/random padding → mita → SOCKS5 → Интернет{NC}")
    _box_row()
    _box_sep()
    _box_info("Домен не нужен — достаточно IP и порта.")
    _box_info("Работает на портах 2012-2022 по умолчанию.")
    _box_bot(); _pause()

def _guide_time() -> None:
    os.system("clear")
    _box_top("⏱️  СИНХРОНИЗАЦИЯ ВРЕМЕНИ  •  MIERU")
    _box_row()
    _box_warn("Mieru проверяет временную метку в каждом пакете!")
    _box_warn("Расхождение более ±30 сек = соединение отклоняется.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}На сервере:")
    _box_row()
    _box_row(f"  {DIM}timedatectl status{NC}")
    _box_row(f"  {DIM}# NTP synchronized: yes{NC}")
    _box_row()
    _box_row(f"  {DIM}# Если нет — установить chrony:{NC}")
    _box_row(f"  {DIM}apt install chrony && systemctl enable --now chrony{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}На клиенте (Android):")
    _box_row()
    _box_info("Настройки → Дата и время → Авто-синхронизация: ВКЛ")
    _box_row()
    _box_sep()
    _box_warn("Модуль автоматически устанавливает chrony при установке.")
    _box_bot(); _pause()

def _guide_clients() -> None:
    os.system("clear")
    state     = _load_state()
    server_ip = _get_server_ip()
    port_start = state.get("port_start", _DEFAULT_PORT_START)
    port_end   = state.get("port_end",   _DEFAULT_PORT_END)

    _box_top("📱  КЛИЕНТСКИЕ ПРИЛОЖЕНИЯ  •  MIERU")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Клиенты с поддержкой Mieru:")
    _box_row()
    _box_kv("  Karing",   "iOS / Android / Windows / macOS", 16)
    _box_kv("  Nekobox",  "Android", 16)
    _box_kv("  sing-box", "CLI — все платформы", 16)
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Импорт:")
    _box_row()
    _box_info("1. Через QR-код: пункт [2] → выбрать пользователя → QR")
    _box_info("2. Через mieru:// ссылку: пункт [2] → скопировать ссылку")
    _box_info("3. Через sing-box JSON: пункт [3] → вставить в конфиг")
    _box_row()
    _box_sep()
    _box_warn("Убедитесь что время синхронизировано на клиенте!")
    _box_bot(); _pause()

def _guide_protocol() -> None:
    os.system("clear")
    _box_top("🔌  TCP vs UDP  •  MIERU")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}TCP:")
    _box_row()
    _box_info("Надёжная доставка, встроенное управление потоком")
    _box_info("Лучше для HTTP/HTTPS трафика")
    _box_info("Стабильнее на плохих каналах")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}UDP:")
    _box_row()
    _box_info("Меньше задержки, лучше для VoIP/игр")
    _box_info("Может быть заблокирован операторами РФ")
    _box_info("Нужно открыть UDP-порты на firewall")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Рекомендация:")
    _box_row()
    _box_info("Для большинства случаев — TCP")
    _box_info("UDP — только если TCP медленный или недоступен")
    _box_bot(); _pause()

def _guide_diff() -> None:
    os.system("clear")
    _box_top("⚖️  MIERU vs NAIVEPROXY")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}NaiveProxy:")
    _box_row()
    _box_info("Маскировка: HTTPS/HTTP2 с Chromium fingerprint")
    _box_info("Требует домен + TLS сертификат")
    _box_info("Probe resistance — фейковый сайт для зондов")
    _box_info("Клиенты: Karing, Nekobox, ShadowRocket")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Mieru:")
    _box_row()
    _box_info("Маскировка: mTLS + random padding (нет паттернов)")
    _box_info("Домен НЕ нужен — только IP и порт")
    _box_info("Требует синхронизацию времени ±30 сек")
    _box_info("Клиенты: Karing, Nekobox, sing-box CLI")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Когда что выбрать:")
    _box_row()
    _box_info("Есть домен + нужен probe resistance → NaiveProxy")
    _box_info("Нет домена + нужна маскировка трафика → Mieru")
    _box_info("Максимальная защита → оба одновременно")
    _box_bot(); _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        os.system("clear")
        _box_top("🗑️  УДАЛЕНИЕ  •  MIERU")
        _box_row()
        _box_warn("Будет удалено:")
        _box_row(f"  {DIM}  • Сервис systemd  (mita){NC}")
        _box_row(f"  {DIM}  • Бинарники       ({_MITA_BIN}, {_MIERU_BIN}){NC}")
        _box_row(f"  {DIM}  • Конфиги          ({_CFG_DIR}){NC}")
        _box_row(f"  {DIM}  • iptables порты{NC}")
        _box_row()
        _box_warn("Xray, VLESS и другие службы не затрагиваются.")
        _box_row()
        _box_item("Y", f"{RED}Да, удалить{NC}")
        _box_item("N", "Нет, отмена")
        _box_bot(); print()
        try:
            ans = _ask(f"{CYAN}Подтверждение [y/N]: {NC}", c=True).strip().lower()
        except _Cancelled: return False
        if ans != "y":
            print(f"  {DIM}Отменено.{NC}"); _pause(); return False

    state = _load_state()
    port_start = state.get("port_start", _DEFAULT_PORT_START)
    port_end   = state.get("port_end",   _DEFAULT_PORT_END)
    protocol   = state.get("protocol",   _DEFAULT_PROTOCOL)

    _run(["systemctl", "stop",    _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    if _SERVICE_FILE.exists(): _SERVICE_FILE.unlink()
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"], capture=True)

    for b in (_MITA_BIN, _MIERU_BIN):
        if b.exists(): b.unlink()
    if _CFG_DIR.exists():
        shutil.rmtree(_CFG_DIR, ignore_errors=True)

    _ipt_close_port(protocol, port_start, port_end)
    _ipt_persist()

    try:
        if _MODULE_STATE.exists(): _MODULE_STATE.unlink()
    except Exception: pass

    if not silent:
        print(f"  {GREEN}✓{NC}  Mieru полностью удалён.")
        _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def do_mieru_menu() -> None:
    """Точка входа из _core.py."""
    while True:
        os.system("clear")
        installed  = _is_installed()
        state      = _load_state()

        r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
        svc_ok = r.stdout.strip() == "active"

        svc_str = (
            f"{GREEN}● активен{NC}"  if svc_ok    else
            f"{RED}● остановлен{NC}" if installed else
            f"{YELLOW}● не установлен{NC}"
        )

        _box_top("MIERU  •  mTLS / random padding")
        _box_row()
        _box_kv("Статус:", svc_str)

        if installed:
            port_start = state.get("port_start", "—")
            port_end   = state.get("port_end",   "—")
            protocol   = state.get("protocol",   "—")
            port_str   = (str(port_start) if port_start == port_end
                          else f"{port_start}-{port_end}")
            _box_kv("Порт(ы):",       f"{YELLOW}{port_str}/{protocol}{NC}")
            _box_kv("Пользователей:", str(len(state.get("users", []))))
            sync_ok, _ = _check_time_sync()
            _box_kv("Время NTP:",
                    f"{GREEN}✓ синхронизировано{NC}" if sync_ok
                    else f"{RED}✗ не синхронизировано{NC}")

        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🚀  Установить Mieru")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "👥  Управление пользователями")
            _box_item("3", "🔄  Перезапустить сервис")
            _box_item("4", "📊  Статус / логи")
            _box_sep()
            _box_item("9", f"{RED}🗑️   Удалить Mieru{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: как работает, клиенты, TCP vs UDP")
        _box_sep()
        _box_item("Q", "← Назад в главное меню VLESS")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":
            _run_install()
        elif ch == "2" and installed:
            try: _users_menu()
            except _Cancelled: pass
        elif ch == "3" and installed:
            _run(["systemctl", "restart", _SERVICE_NAME])
            time.sleep(1)
            r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
            print(f"\n  {'✓' if r.stdout.strip()=='active' else '⚠'}  "
                  f"{'Перезапущен.' if r.stdout.strip()=='active' else 'Проверьте логи.'}")
            _pause()
        elif ch == "4" and installed:
            _show_status()
        elif ch == "9" and installed:
            try: _full_uninstall(silent=False)
            except _Cancelled:
                print(f"  {DIM}Отменено.{NC}"); _pause()
        elif ch == "g":
            try: _show_guide()
            except _Cancelled: pass
        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        do_mieru_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)
