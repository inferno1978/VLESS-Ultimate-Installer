"""
vless_installer/modules/mtproto.py
───────────────────────────────────────────────────────────────────────────────
Модуль Telemt MTProxy — Telegram MTProto-прокси на Rust/Tokio.
Интегрируется в VLESS Ultimate Installer v4.11.3

Точка входа из _core.py:
    from vless_installer.modules.mtproto import mtproto_menu
    mtproto_menu()

Принципы:
  • Статистика вынесена в mtproto_stats.py
  • Ctrl+C на любом шаге → возврат в меню (через _Cancelled)
  • При переустановке предлагается полная очистка или поверх
  • iptables accounting настраивается при установке автоматически
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
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
BIN_PATH        = Path("/usr/local/bin/telemt")
CONFIG_DIR      = Path("/etc/telemt")
CONFIG_FILE     = CONFIG_DIR / "telemt.toml"
WORK_DIR        = Path("/var/lib/telemt")
SERVICE_FILE    = Path("/etc/systemd/system/telemt.service")
LOG_FILE        = Path("/var/log/telemt_install.log")
OPTIMIZER_CONF  = Path("/etc/sysctl.d/99-telemt-performance.conf")
LIMITS_CONF     = Path("/etc/security/limits.d/99-telemt-limits.conf")
CRON_FILE       = Path("/etc/cron.d/telemt-stats")

SERVICE_NAME    = "telemt"
GITHUB_API      = "https://api.github.com/repos/telemt/telemt/releases/latest"

CHAIN_IN        = "TELEMT_STATS_IN"
CHAIN_OUT       = "TELEMT_STATS_OUT"

# ── Xray tproxy-интеграция ────────────────────────────────────────────────────
# Telemt (Rust, без поддержки SOCKS5-upstream) работает в режиме direct.
# Трафик к Telegram-подсетям перехватывается iptables REDIRECT и отправляется
# в dokodemo-door inbound xray, который уже настроен на cascade (VLESS или AWG).
# Схема:  Telemt → iptables REDIRECT → dokodemo :10811 → xray → exit VPS → TG
#
# Это работает одинаково для обоих транспортов:
#   VLESS: xray направляет по chain-exit outbound / balancer
#   AWG:   xray направляет через freedom+fwmark → awg0 → exit VPS
#          (dokodemo обрабатывается uid xray → fwmark проставляется корректно)
XRAY_TPROXY_TAG    = "tproxy-telemt"
XRAY_TPROXY_PORT   = 10811          # порт dokodemo-door; не конфликтует с 10808
XRAY_CONFIG_PATHS  = [
    Path("/etc/xray/config.json"),
    Path("/usr/local/etc/xray/config.json"),
]
XRAY_SERVICE_NAME  = "xray"

# Подсети Telegram — загружаются динамически из tg_nets.py
# Встроенный список (fallback) обновлён: добавлен AS42065 109.239.140.0/24
# Для обновления используйте меню Telemt → "Обновить подсети Telegram"
from vless_installer.modules.tg_nets import (
    get_tg_nets          as _get_tg_nets,
    update_tg_nets_interactive as _update_tg_nets_interactive,
    tg_nets_status_line  as _tg_nets_status_line,
)

# Гибридный fallback: Middle Proxy → Direct Mode (telemt_fallback.py)
# Импортируем lazy чтобы не замедлять старт при первом импорте mtproto.
def _get_fallback_module():
    """Lazy-import telemt_fallback — изолирует ошибки импорта."""
    try:
        from vless_installer.modules import telemt_fallback as _fb_mod
        return _fb_mod
    except ImportError:
        return None

# MSS-фрагментация против TSPU JA4: telemt_mss_selector.py
def _get_mss_module():
    """Lazy-import telemt_mss_selector — изолирует ошибки импорта."""
    try:
        from vless_installer.modules import telemt_mss_selector as _mss_mod
        return _mss_mod
    except ImportError:
        return None

def _TG_NETS_current() -> list:
    """Возвращает актуальный список подсетей TG (файл → встроенный)."""
    return _get_tg_nets()

# Для обратной совместимости с кодом, который обращается к _TG_NETS напрямую.
# Вычисляется один раз при импорте; для применения свежих данных используйте
# _TG_NETS_current() внутри функций, работающих с iptables.
_TG_NETS = _TG_NETS_current()

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ
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
        # Обрезаем по визуальной ширине чтобы не сломать рамку
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
def _run(cmd: list, capture: bool = False, check: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
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
    """c=True → при Ctrl+C бросает _Cancelled вместо возврата default."""
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

def _generate_secret() -> str:
    try:
        return os.urandom(16).hex()
    except Exception:
        import random
        return ''.join(f'{random.randint(0,255):02x}' for _ in range(16))

def _validate_username(name: str) -> bool:
    return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_\-]{2,15}$', name))

def _validate_domain(domain: str) -> bool:
    return bool(
        domain and '.' in domain and
        re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9])?$', domain)
    )

def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PiB"

# ══════════════════════════════════════════════════════════════════════════════
#  БАННЕР
# ══════════════════════════════════════════════════════════════════════════════
def _banner() -> None:
    os.system("clear")
    print(f"{CYAN}{BOLD}")
    print("  ████████╗███████╗██╗     ███████╗███╗   ███╗████████╗")
    print("     ██║   ██╔════╝██║     ██╔════╝████╗ ████║╚══██╔══╝")
    print("     ██║   █████╗  ██║     █████╗  ██╔████╔██║   ██║   ")
    print("     ██║   ██╔══╝  ██║     ██╔══╝  ██║╚██╔╝██║   ██║   ")
    print("     ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║   ██║   ")
    print("     ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝   ╚═╝   ")
    print(f"{NC}")
    print(f"  {DIM}Telegram MTProto Proxy  •  Telemt (Rust/Tokio)  •  VLESS Ultimate{NC}")
    print()

# ══════════════════════════════════════════════════════════════════════════════
#  IP И СЕТЬ
# ══════════════════════════════════════════════════════════════════════════════
def _get_local_primary_ipv4() -> str:
    """Return the primary non-loopback IPv4 address assigned to a local interface."""
    try:
        import socket
        # Connect to an external address (no data sent) to discover the outbound interface IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass
    # Fallback: parse `ip addr` for the first global inet address
    try:
        out = _run(["ip", "-4", "addr", "show", "scope", "global"], capture=True).stdout
        m = re.search(r'inet\s+([\d.]+)/', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""

def _get_public_ip() -> tuple:
    """
    Возвращает (ipv4, ipv6) для использования в tg:// ссылках.

    Логика выбора IPv4:
      1. Читаем IP локального интерфейса (тот, на котором слушает telemt).
         Это единственно правильный адрес для tg:// ссылки — пользователь
         должен подключаться к ЭТОЙ машине, а не к exit-ноде.
      2. Если локальный IP приватный (NAT) — запрашиваем внешний.
         Но если внешний не совпадает с локальным (Режим B — трафик уходит
         через exit-ноду), всё равно возвращаем локальный.
      3. IPv6 всегда через api6.ipify.org.
    """
    local_ip = _get_local_primary_ipv4()
    ipv4 = ""

    if local_ip and _is_public_ip(local_ip):
        # Локальный интерфейс уже имеет публичный IP — используем его
        ipv4 = local_ip
    else:
        # Сервер за NAT — запрашиваем внешний IP
        for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    external_ip = r.read().decode().strip()
                if external_ip:
                    # Если внешний IP принадлежит этой машине — используем его.
                    # Если нет (Режим B: трафик идёт через exit-ноду) —
                    # используем локальный: ссылка должна вести на entry-ноду.
                    ipv4 = external_ip if _is_direct_ip(external_ip) else (local_ip or external_ip)
                    break
            except Exception:
                pass

    if not ipv4:
        ipv4 = local_ip

    ipv6 = ""
    try:
        with urllib.request.urlopen("https://api6.ipify.org", timeout=5) as r:
            ipv6 = r.read().decode().strip()
    except Exception:
        pass
    return ipv4, ipv6


def _is_public_ip(ip: str) -> bool:
    """True если IP публичный (не RFC-1918, не loopback, не link-local)."""
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local)
    except ValueError:
        return False

def _is_direct_ip(ipv4: str) -> bool:
    if not ipv4: return False
    return ipv4 in _run(["ip", "addr"], capture=True).stdout

# ══════════════════════════════════════════════════════════════════════════════
#  ВЕРСИЯ И РЕЛИЗ
# ══════════════════════════════════════════════════════════════════════════════
def _get_installed_version() -> Optional[str]:
    if not BIN_PATH.exists(): return None
    r = _run([str(BIN_PATH), "--version"], capture=True)
    m = re.search(r'(\d+\.\d+[\.\d]*)', r.stdout + r.stderr)
    return m.group(1) if m else "unknown"

def _get_latest_release() -> tuple:
    try:
        req = urllib.request.Request(GITHUB_API, headers={"User-Agent": "VLESS-Ultimate-Installer"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        tag  = data.get("tag_name", "").lstrip("v")
        arch = "aarch64" if platform.machine().lower() in ("aarch64", "arm64") else "x86_64"
        libc = "musl" if "musl" in _run(["ldd", "--version"], capture=True).stdout.lower() else "gnu"
        url  = (f"https://github.com/telemt/telemt/releases/latest/download/"
                f"telemt-{arch}-linux-{libc}.tar.gz")
        return tag, url
    except Exception:
        return "", ""

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ
# ══════════════════════════════════════════════════════════════════════════════
def _make_tls_secret(base_secret: str, domain: str) -> str:
    return f"ee{base_secret}{domain.encode().hex()}"

def _get_port() -> int:
    if not CONFIG_FILE.exists(): return 8443
    m = re.search(r'^port\s*=\s*(\d+)', CONFIG_FILE.read_text(), re.MULTILINE)
    return int(m.group(1)) if m else 8443

def _get_domain() -> str:
    if not CONFIG_FILE.exists(): return ""
    m = re.search(r'^tls_domain\s*=\s*"(.+?)"', CONFIG_FILE.read_text(), re.MULTILINE)
    return m.group(1) if m else ""

def _load_users() -> dict:
    users: dict = {}
    if not CONFIG_FILE.exists(): return users
    in_sec = False
    for line in CONFIG_FILE.read_text().splitlines():
        if line.strip() == "[access.users]":
            in_sec = True; continue
        if in_sec and line.strip().startswith("["): break
        if in_sec:
            m = re.match(r'^([a-zA-Z][a-zA-Z0-9_\-]+)\s*=\s*"([a-f0-9]{32})"', line)
            if m: users[m.group(1)] = m.group(2)
    return users

def _save_users(users: dict) -> None:
    if not CONFIG_FILE.exists(): return
    lines = CONFIG_FILE.read_text().splitlines()
    out, in_sec, written = [], False, False
    for line in lines:
        if line.strip() == "[access.users]":
            in_sec = True; out.append(line)
            for n, s in users.items(): out.append(f'{n} = "{s}"')
            written = True; continue
        if in_sec and line.strip().startswith("["): in_sec = False
        if in_sec: continue
        out.append(line)
    if not written:
        out += ["[access.users]"] + [f'{n} = "{s}"' for n, s in users.items()]
    CONFIG_FILE.write_text("\n".join(out) + "\n")
    CONFIG_FILE.chmod(0o640)
    arr = ", ".join(f'"{u}"' for u in users)
    content = re.sub(r'^show\s*=\s*\[.*?\]', f'show = [{arr}]',
                     CONFIG_FILE.read_text(), flags=re.MULTILINE)
    CONFIG_FILE.write_text(content)

def _write_config(port, ipv4, ipv6, tls_domain, users, use_middle_proxy,
                  socks5_port: int = 0, fallback_cfg=None,
                  client_mss: str = "") -> None:
    """
    socks5_port > 0  →  upstream через локальный SOCKS5 (xray), иначе direct.
    fallback_cfg     →  FallbackConfig (из telemt_fallback); None = не писать секцию.
    client_mss       →  пресет MSS для TSPU anti-JA4 ("tspu", "2in8", числовой или "").
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    arr = ", ".join(f'"{u}"' for u in users)
    lines = [
        "# Telemt v3.x — generated by VLESS Ultimate Installer",
        "", "[general]", "prefer_ipv6 = false", "fast_mode = true",
        f"use_middle_proxy = {str(use_middle_proxy).lower()}",
        "", "[general.modes]", "classic = false", "secure = false", "tls = true",
        "", "[general.links]", f"show = [{arr}]",
        "", "[server]", f"port = {port}", "",
    ]
    if ipv4: lines += ['[[server.listeners]]', 'ip = "0.0.0.0"', ""]
    if ipv6: lines += ['[[server.listeners]]', 'ip = "::"', ""]
    censorship_lines = [
        "[timeouts]", "client_handshake = 300", "client_keepalive = 60", "client_ack = 300",
        "", "[censorship]", f'tls_domain = "{tls_domain}"',
        "mask = true", "mask_port = 443", "fake_cert_len = 2048",
    ]
    if client_mss:
        censorship_lines.append(f'client_mss = "{client_mss}"')
    lines += censorship_lines
    lines += [
        "", "[access]", "replay_check_len = 65536", "ignore_time_skew = false",
        "", "[access.users]",
    ]
    for n, s in users.items(): lines.append(f'{n} = "{s}"')
    if socks5_port > 0:
        lines += [
            "", "[[upstreams]]",
            'type = "socks5"',
            f'addr = "127.0.0.1:{socks5_port}"',
            "enabled = true", "weight = 10",
        ]
    else:
        lines += ["", "[[upstreams]]", 'type = "direct"', "enabled = true", "weight = 10"]
    if not use_middle_proxy:
        lines += [
            "", "[dc_overrides]",
            '"1"   = "149.154.175.50:443"',
            '"2"   = "149.154.167.51:443"',
            '"3"   = "149.154.175.100:443"',
            '"4"   = "149.154.167.91:443"',
            '"5"   = "149.154.171.5:443"',
            '"203" = "91.105.192.100:443"',
        ]
    CONFIG_FILE.write_text("\n".join(lines) + "\n")
    CONFIG_FILE.chmod(0o640)

    # Записываем секцию [middle_proxy] с параметрами fallback (если передана)
    if fallback_cfg is not None:
        _fb_mod = _get_fallback_module()
        if _fb_mod is not None:
            try:
                _fb_mod.append_fallback_section(CONFIG_FILE, fallback_cfg)
            except Exception as _e:
                _warn(f"Не удалось записать [middle_proxy]: {_e}")



# ══════════════════════════════════════════════════════════════════════════════
#  XRAY TPROXY-ИНТЕГРАЦИЯ  (dokodemo-door + iptables REDIRECT)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Почему не SOCKS5:
#    Текущая версия telemt (Rust/Tokio) не поддерживает SOCKS5-upstream.
#    Используем обходной путь на уровне ядра:
#      1. Xray слушает dokodemo-door на 127.0.0.1:XRAY_TPROXY_PORT
#      2. iptables REDIRECT перехватывает TCP telemt → Telegram IP → :XRAY_TPROXY_PORT
#      3. Xray обрабатывает пакет под uid xray:
#           VLESS: → chain-exit outbound / balancer → exit VPS → Telegram
#           AWG:   → freedom+fwmark → awg0 → exit VPS → Telegram
#             (uid xray получает fwmark от policy routing → пакет идёт через awg0 ✓)
#
#  Схема одинакова для обоих транспортов — VLESS-цепочки и AWG 2.0.
# ──────────────────────────────────────────────────────────────────────────────

def _xray_config_path() -> Optional[Path]:
    """Возвращает первый найденный config.json xray, иначе None."""
    for p in XRAY_CONFIG_PATHS:
        if p.exists():
            return p
    return None


def _xray_cascade_mode() -> str:
    """
    Определяет режим каскада по state.json.
    Возвращает: "awg" | "vless" | "none"
    """
    state_file = Path("/var/lib/xray-installer/state.json")
    if not state_file.exists():
        return "none"
    try:
        state = json.loads(state_file.read_text())
        if state.get("awg_exit_enabled"):
            return "awg"
        mode = state.get("install_mode", state.get("mode", ""))
        if str(mode).upper() == "B":
            return "vless"
    except Exception:
        pass
    return "none"


def _find_xray_bin() -> Optional[str]:
    """Возвращает путь к бинарнику xray или None."""
    for candidate in ("/usr/local/bin/xray", "/usr/bin/xray"):
        if Path(candidate).exists():
            return candidate
    import shutil as _sh
    return _sh.which("xray")


def _xray_has_inbound(cfg: dict, tag: str) -> bool:
    """Проверяет наличие inbound с данным тегом."""
    return any(ib.get("tag") == tag for ib in cfg.get("inbounds", []))


def _xray_get_proxy_tag(cfg: dict) -> tuple:
    """
    Находит тег главного outbound/balancer каскада.
    Возвращает (tag: str, is_balancer: bool).

    Balancer (2+ нод) требует balancerTag в routing rule — это другое поле,
    не outboundTag; путать нельзя, xray не найдёт outboundTag среди outbounds.
    """
    for b in cfg.get("routing", {}).get("balancers", []):
        if "chain" in b.get("tag", ""):
            return b["tag"], True
    outbounds = cfg.get("outbounds", [])
    for prefer in ("chain-exit-1", "chain-exit"):
        if any(ob.get("tag") == prefer for ob in outbounds):
            return prefer, False
    # AWG-режим: freedom outbound с fwmark
    for ob in outbounds:
        tag = ob.get("tag", "")
        if tag in ("BLOCK", "xray-stats-api", "direct"):
            continue
        sm = ob.get("streamSettings", {}).get("sockopt", {}).get("mark", 0)
        if ob.get("protocol") == "freedom" and sm:
            return tag, False
        if ob.get("protocol") == "vless":
            return tag, False
    return "chain-exit", False


# ── Xray config: dokodemo-door inbound ───────────────────────────────────────

def _xray_inject_dokodemo(cfg: dict, port: int) -> bool:
    """
    Добавляет dokodemo-door inbound + routing rule в конфиг xray.
    followRedirect=True: принимает TCP переброшенные iptables REDIRECT.
    Возвращает True если конфиг изменён.
    """
    if _xray_has_inbound(cfg, XRAY_TPROXY_TAG):
        return False

    cfg.setdefault("inbounds", []).append({
        "tag":      XRAY_TPROXY_TAG,
        "port":     port,
        "listen":   "127.0.0.1",
        "protocol": "dokodemo-door",
        "settings": {"network": "tcp", "followRedirect": True},
        "sniffing": {"enabled": False},
    })

    proxy_tag, is_balancer = _xray_get_proxy_tag(cfg)
    rule: dict = {"type": "field", "inboundTag": [XRAY_TPROXY_TAG]}
    if is_balancer:
        rule["balancerTag"] = proxy_tag
    else:
        rule["outboundTag"] = proxy_tag

    rules: list = cfg.setdefault("routing", {}).setdefault("rules", [])
    rules.insert(0, rule)
    return True


def _xray_remove_dokodemo(cfg: dict) -> bool:
    """Удаляет dokodemo inbound и routing rule из конфига xray."""
    changed = False
    inbounds = cfg.get("inbounds", [])
    new_ib = [ib for ib in inbounds if ib.get("tag") != XRAY_TPROXY_TAG]
    if len(new_ib) != len(inbounds):
        cfg["inbounds"] = new_ib
        changed = True
    rules = cfg.get("routing", {}).get("rules", [])
    new_r = [r for r in rules if XRAY_TPROXY_TAG not in r.get("inboundTag", [])]
    if len(new_r) != len(rules):
        cfg["routing"]["rules"] = new_r
        changed = True
    return changed


def _xray_dokodemo_port(cfg: dict) -> int:
    """Возвращает порт dokodemo inbound если настроен, иначе 0."""
    for ib in cfg.get("inbounds", []):
        if ib.get("tag") == XRAY_TPROXY_TAG:
            return int(ib.get("port", 0))
    return 0


def _xray_write_and_test(cfg_path: Path, cfg: dict) -> Optional[str]:
    """
    Записывает конфиг и проверяет синтаксис через xray -test.
    Возвращает None при успехе, строку с ошибкой при неудаче.
    """
    try:
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        cfg_path.chmod(0o640)
    except Exception as e:
        return f"Не удалось записать {cfg_path}: {e}"
    xray_bin = _find_xray_bin()
    if xray_bin:
        r = _run([xray_bin, "run", "-test", "-config", str(cfg_path)], capture=True)
        if r.returncode != 0:
            return f"xray -test провалился: {(r.stderr or r.stdout)[:300]}"
    return None


# ── iptables REDIRECT для Telegram-подсетей ───────────────────────────────────

def _ipt_rule_exists(net: str, port: int) -> bool:
    """Проверяет наличие REDIRECT-правила через iptables -C (не дублирует)."""
    v6  = ":" in net
    ipt = "ip6tables" if v6 else "iptables"
    r   = _run([ipt, "-t", "nat", "-C", "OUTPUT",
                "-d", net, "-p", "tcp",
                "-j", "REDIRECT", "--to-port", str(port)],
               capture=True)
    return r.returncode == 0


def _ipt_add_redirect(net: str, port: int) -> bool:
    """Добавляет REDIRECT-правило если ещё нет. Возвращает True при успехе."""
    if _ipt_rule_exists(net, port):
        return True
    v6  = ":" in net
    ipt = "ip6tables" if v6 else "iptables"
    r   = _run([ipt, "-t", "nat", "-A", "OUTPUT",
                "-d", net, "-p", "tcp",
                "-j", "REDIRECT", "--to-port", str(port)],
               capture=True)
    return r.returncode == 0


def _ipt_del_redirect(net: str, port: int) -> None:
    """Удаляет REDIRECT-правило (все копии, идемпотентно)."""
    for _ in range(5):
        if not _ipt_rule_exists(net, port):
            break
        v6  = ":" in net
        ipt = "ip6tables" if v6 else "iptables"
        _run([ipt, "-t", "nat", "-D", "OUTPUT",
              "-d", net, "-p", "tcp",
              "-j", "REDIRECT", "--to-port", str(port)],
             capture=True)


def _iptables_persist() -> None:
    """
    Сохраняет iptables-правила для выживания после ребута.
    Порядок попыток:
      1. netfilter-persistent save  (Debian/Ubuntu с iptables-persistent)
      2. iptables-save → /etc/iptables/rules.v4 + rules.v6
      3. systemd-сервис telemt-iptables (fallback)
    """
    if shutil.which("netfilter-persistent"):
        _run(["netfilter-persistent", "save"], capture=True)
        return
    rules_dir = Path("/etc/iptables")
    rules_dir.mkdir(parents=True, exist_ok=True)
    r4 = _run(["iptables-save"],  capture=True)
    if r4.returncode == 0 and r4.stdout:
        (rules_dir / "rules.v4").write_text(r4.stdout)
    r6 = _run(["ip6tables-save"], capture=True)
    if r6.returncode == 0 and r6.stdout:
        (rules_dir / "rules.v6").write_text(r6.stdout)
    _ensure_ipt_restore_service()


def _ensure_ipt_restore_service() -> None:
    """
    Создаёт systemd-сервис восстановления iptables при загрузке,
    если нет netfilter-persistent.
    """
    svc_path = Path("/etc/systemd/system/telemt-iptables.service")
    if svc_path.exists():
        # Пересоздаём чтобы обновить пути если изменились
        pass
    rules_v4 = Path("/etc/iptables/rules.v4")
    rules_v6 = Path("/etc/iptables/rules.v6")
    exec_lines = ""
    if rules_v4.exists():
        exec_lines += f"ExecStart=/bin/sh -c 'iptables-restore < {rules_v4}'\n"
    if rules_v6.exists():
        exec_lines += f"ExecStart=/bin/sh -c 'ip6tables-restore < {rules_v6}'\n"
    if not exec_lines:
        return
    svc_path.write_text(
        "[Unit]\n"
        "Description=Restore iptables REDIRECT rules for telemt tproxy\n"
        "Before=network-pre.target\n"
        "Wants=network-pre.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        + exec_lines +
        "\n[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"], capture=True)
    _run(["systemctl", "enable", "telemt-iptables.service"], capture=True)


# ── Публичный API ─────────────────────────────────────────────────────────────

def xray_enable_tproxy_for_telemt(port: int = XRAY_TPROXY_PORT) -> tuple:
    """
    Полная активация tproxy-интеграции (VLESS-цепочки и AWG 2.0).

    Шаги:
      1. dokodemo-door inbound → xray config.json
      2. routing rule: tproxy-telemt → balancer/chain-exit
      3. iptables REDIRECT всех Telegram-подсетей → port
      4. Persist iptables (netfilter-persistent / iptables-save / systemd)
      5. Перезапуск xray

    Идемпотентна: повторный вызов не дублирует правила.
    Возвращает (ok: bool, message: str).
    """
    cfg_path = _xray_config_path()
    if not cfg_path:
        return False, "xray config.json не найден — xray не установлен"

    cascade = _xray_cascade_mode()
    if cascade == "none":
        return False, (
            "xray не настроен в режиме каскада (Режим B). "
            "Сначала установите xray с Режимом B, затем повторите."
        )

    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        return False, f"Не удалось прочитать {cfg_path}: {e}"

    # Если порт поменялся — пересоздаём inbound
    existing_port = _xray_dokodemo_port(cfg)
    if existing_port and existing_port != port:
        _xray_remove_dokodemo(cfg)
        existing_port = 0

    xray_changed = False
    if not existing_port:
        xray_changed = _xray_inject_dokodemo(cfg, port)

    if xray_changed:
        err = _xray_write_and_test(cfg_path, cfg)
        if err:
            # Откат
            _xray_remove_dokodemo(cfg)
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            return False, err
        _run(["systemctl", "restart", XRAY_SERVICE_NAME])

    # ── iptables REDIRECT ─────────────────────────────────────────────────────
    tg_nets = _TG_NETS_current()
    failed = [net for net in tg_nets if not _ipt_add_redirect(net, port)]
    _iptables_persist()

    if failed:
        return False, f"iptables REDIRECT не удалось для: {', '.join(failed)}"

    mode_label = "AWG 2.0" if cascade == "awg" else "VLESS"
    status = "уже был настроен" if (existing_port and not xray_changed) else "добавлен"
    return True, (
        f"dokodemo-door {status} (:{port}), "
        f"iptables REDIRECT активен [{len(tg_nets)} подсетей], "
        f"транспорт: {mode_label}"
    )


def xray_disable_tproxy_for_telemt() -> tuple:
    """
    Полное отключение tproxy-интеграции:
      1. Удаляет dokodemo-door из xray config, перезапускает xray
      2. Удаляет iptables REDIRECT для всех Telegram-подсетей
      3. Сохраняет состояние iptables
    Возвращает (ok: bool, message: str).
    """
    cfg_path = _xray_config_path()
    if cfg_path:
        try:
            cfg = json.loads(cfg_path.read_text())
            port = _xray_dokodemo_port(cfg)
            if _xray_remove_dokodemo(cfg):
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                cfg_path.chmod(0o640)
                _run(["systemctl", "restart", XRAY_SERVICE_NAME])
        except Exception as e:
            return False, f"Не удалось обновить xray config: {e}"
    else:
        port = XRAY_TPROXY_PORT

    for net in _TG_NETS_current():
        _ipt_del_redirect(net, port or XRAY_TPROXY_PORT)

    _iptables_persist()

    svc = Path("/etc/systemd/system/telemt-iptables.service")
    if svc.exists():
        _run(["systemctl", "disable", "--now", "telemt-iptables.service"], capture=True)
        svc.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"], capture=True)

    return True, "tproxy-интеграция отключена: dokodemo удалён, iptables очищен"


def telemt_tproxy_emergency_restore() -> tuple:
    """
    Восстанавливает tproxy-интеграцию Telemt→Xray после аварийного восстановления.

    Вызывается из do_emergency_repair() в _core.py.
    Детектирует факт установки Telemt по бинарнику / systemd-сервису — без опоры
    на флаги в state.json (которых для tproxy нет).

    Логика:
      1. Если Telemt не установлен — возвращает (None, "не установлен"), вызывающий
         код выводит "пропуск". None сигнализирует: не ошибка, просто не применимо.
      2. Если Xray не в каскадном режиме (Режим B / AWG) — возвращает (None, причина).
         xray_enable_tproxy_for_telemt сама это проверит, но ранняя проверка позволяет
         вернуть корректный статус без лишних операций.
      3. Если dokodemo уже есть в config.json и все iptables-правила на месте —
         возвращает (True, "уже активна"). Функция идемпотентна.
      4. Иначе — вызывает xray_enable_tproxy_for_telemt() и возвращает её результат.

    Возвращает:
      (True,  сообщение) — интеграция восстановлена или уже была активна
      (False, сообщение) — ошибка при восстановлении
      (None,  сообщение) — Telemt не установлен или неприменимо (не ошибка)
    """
    # ── Детект установки Telemt ───────────────────────────────────────────────
    telemt_installed = BIN_PATH.exists() or SERVICE_FILE.exists()
    if not telemt_installed:
        # Дополнительная проверка через systemctl (на случай нестандартного пути)
        r_svc = _run(["systemctl", "is-active", SERVICE_NAME], capture=True, check=False)
        telemt_installed = r_svc.stdout.strip() in ("active", "inactive", "failed")

    if not telemt_installed:
        return None, "Telemt не установлен"

    # ── Проверка каскадного режима ────────────────────────────────────────────
    cascade = _xray_cascade_mode()
    if cascade == "none":
        return None, "xray-каскад (Режим B) не активен — tproxy неприменим"

    # ── Статус текущей интеграции ─────────────────────────────────────────────
    status = _xray_tproxy_status()
    if status["enabled"] and status["ipt_ok"]:
        return True, (
            f"tproxy-интеграция уже активна "
            f"(dokodemo :{status['port']}, "
            f"iptables {status['ipt_count']}/{status['ipt_total']} подсетей)"
        )

    # ── Применяем / восстанавливаем ───────────────────────────────────────────
    return xray_enable_tproxy_for_telemt(XRAY_TPROXY_PORT)


def _xray_tproxy_status() -> dict:
    """
    Возвращает dict со статусом tproxy-интеграции:
      enabled   – bool  (dokodemo inbound настроен)
      port      – int   (0 если нет)
      cascade   – str   ("awg" | "vless" | "none")
      proxy_tag – str
      ipt_ok    – bool  (все iptables-правила на месте)
      ipt_count – int   (сколько из len(_TG_NETS) правил активно)
    """
    cfg_path = _xray_config_path()
    cascade  = _xray_cascade_mode()
    base     = {"enabled": False, "port": 0, "cascade": cascade,
                "proxy_tag": "—", "ipt_ok": False, "ipt_count": 0,
                "ipt_total": len(_TG_NETS_current())}
    if not cfg_path:
        return base
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception:
        return base

    port = _xray_dokodemo_port(cfg)
    if not port:
        return base

    pt, is_bal   = _xray_get_proxy_tag(cfg)
    proxy_tag    = pt + (" [balancer]" if is_bal else "")
    tg_nets      = _TG_NETS_current()
    ipt_active   = sum(1 for n in tg_nets if _ipt_rule_exists(n, port))

    return {
        "enabled":   True,
        "port":      port,
        "cascade":   cascade,
        "proxy_tag": proxy_tag,
        "ipt_ok":    ipt_active == len(tg_nets),
        "ipt_count": ipt_active,
        "ipt_total": len(tg_nets),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА БИНАРНИКА
# ══════════════════════════════════════════════════════════════════════════════
def _install_binary(url: str) -> bool:
    _info("Загрузка telemt...")
    tmp = Path(tempfile.mkdtemp())
    archive = tmp / "telemt.tar.gz"
    try:
        urllib.request.urlretrieve(url, archive)
        with tarfile.open(archive) as tf:
            tf.extractall(tmp)
        found = list(tmp.rglob("telemt"))
        if not found:
            _err("Бинарник не найден в архиве"); return False
        shutil.copy2(str(found[0]), str(BIN_PATH))
        BIN_PATH.chmod(0o755)
        _ok(f"Установлено: {BIN_PATH}")
        return True
    except Exception as e:
        _err(f"Ошибка: {e}"); return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD / UFW / ОПТИМИЗАЦИЯ
# ══════════════════════════════════════════════════════════════════════════════
def _install_service() -> None:
    SERVICE_FILE.write_text("""[Unit]
Description=Telemt MTProxy Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/telemt
ExecStart=/usr/local/bin/telemt /etc/telemt/telemt.toml
Restart=on-failure
RestartSec=10
TimeoutStartSec=90
TimeoutStopSec=10s
StartLimitIntervalSec=60s
StartLimitBurst=3
LimitNOFILE=1048576
LimitNPROC=infinity
Nice=-10
IOSchedulingClass=best-effort
IOSchedulingPriority=0

[Install]
WantedBy=multi-user.target
""")
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", SERVICE_NAME])

def _setup_ufw(port: int) -> None:
    if not shutil.which("ufw"): return
    if "active" in _run(["ufw", "status"], capture=True).stdout.lower():
        _run(["ufw", "allow", f"{port}/tcp", "comment", "Telemt MTProxy"])
        _ok(f"UFW: открыт порт {port}/tcp")

def _apply_optimizations() -> None:
    try:
        ram_mb = int(subprocess.check_output(
            ["awk", "/^MemTotal/{print int($2/1024)}", "/proc/meminfo"], text=True
        ).strip())
    except Exception:
        ram_mb = 1024
    conntrack = "2000000" if ram_mb >= 1024 else ("524288" if ram_mb >= 512 else "262144")
    file_max  = "2097152" if ram_mb >= 1024 else ("1048576" if ram_mb >= 512 else "524288")
    bbr = False
    try:
        kv = os.uname().release.split(".")
        if int(kv[0]) > 4 or (int(kv[0]) == 4 and int(kv[1]) >= 9):
            _run(["modprobe", "tcp_bbr"])
            bbr = "bbr" in _run(["sysctl", "net.ipv4.tcp_available_congestion_control"], capture=True).stdout
    except Exception:
        pass
    cc = ("net.ipv4.tcp_congestion_control = bbr\nnet.core.default_qdisc = fq"
          if bbr else "net.ipv4.tcp_congestion_control = cubic")
    OPTIMIZER_CONF.parent.mkdir(parents=True, exist_ok=True)
    OPTIMIZER_CONF.write_text(f"""# Telemt MTProxy — kernel optimizations
{cc}
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 250000
net.netfilter.nf_conntrack_max = {conntrack}
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 600
net.ipv4.ip_local_port_range = 1024 65535
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
fs.file-max = {file_max}
vm.swappiness = 10
""")
    _run(["sysctl", "-p", str(OPTIMIZER_CONF)])
    LIMITS_CONF.parent.mkdir(parents=True, exist_ok=True)
    LIMITS_CONF.write_text("""* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
""")
    _ok(f"Оптимизация ядра (BBR: {'да' if bbr else 'нет'})")

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES ACCOUNTING (делегируем в mtproto_stats.py)
# ══════════════════════════════════════════════════════════════════════════════
def _setup_accounting(port: int) -> bool:
    """Настраивает iptables-цепочки учёта. Возвращает True при успехе."""
    try:
        from vless_installer.modules.mtproto_stats import setup_iptables_accounting
        setup_iptables_accounting(port)
        return True
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛНОЕ УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        _banner()
        _box_top("🗑️  ПОЛНОЕ УДАЛЕНИЕ  •  TELEMT")
        _box_row()
        _box_warn("Будет удалено ВСЁ:")
        _box_row()
        _box_row(f"  {DIM}  • Сервис systemd  ({SERVICE_NAME}){NC}")
        _box_row(f"  {DIM}  • Бинарник        ({BIN_PATH}){NC}")
        _box_row(f"  {DIM}  • Конфиги         ({CONFIG_DIR}){NC}")
        _box_row(f"  {DIM}  • Данные / стата  ({WORK_DIR}){NC}")
        _box_row(f"  {DIM}  • Журнал          ({LOG_FILE}){NC}")
        _box_row(f"  {DIM}  • iptables-цепочки (TELEMT_STATS_*){NC}")
        _box_row(f"  {DIM}  • Cron            ({CRON_FILE}){NC}")
        _box_row(f"  {DIM}  • Sysctl / limits  (99-telemt-*){NC}")
        _box_row()
        _box_warn("Это действие необратимо.")
        _box_warn("Все пользователи и ссылки будут удалены.")
        _box_row()
        _box_sep()
        _box_item("Y", f"{RED}Да, удалить полностью{NC}")
        _box_item("N", "Нет, отмена")
        _box_bot()
        print()
        ans = _ask(f"{CYAN}Подтверждение [y/N]: {NC}", c=True).strip().lower()
        if ans != "y":
            _info("Удаление отменено."); _pause(); return False

    _banner()
    _box_top("🗑️  УДАЛЕНИЕ TELEMT...")
    _box_row()

    _box_info("Останавливаю сервис...")
    _run(["systemctl", "stop", SERVICE_NAME])
    _run(["systemctl", "disable", SERVICE_NAME])
    _box_ok("Сервис остановлен и отключён.")

    _box_info("Удаляю iptables-правила...")
    port = _get_port()
    _run(["iptables", "-D", "INPUT",  "-p", "tcp", "--dport", str(port), "-j", CHAIN_IN])
    _run(["iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", str(port), "-j", CHAIN_OUT])
    for chain in (CHAIN_IN, CHAIN_OUT):
        _run(["iptables", "-F", chain])
        _run(["iptables", "-X", chain])
    _box_ok("iptables-цепочки удалены.")

    if shutil.which("ufw") and "active" in _run(["ufw", "status"], capture=True).stdout.lower():
        _run(["ufw", "delete", "allow", f"{port}/tcp"])
        _box_ok(f"UFW: правило для порта {port}/tcp удалено.")

    _box_info("Удаляю файлы...")
    for t in [BIN_PATH, SERVICE_FILE, CONFIG_DIR, WORK_DIR,
              LOG_FILE, CRON_FILE, OPTIMIZER_CONF, LIMITS_CONF]:
        try:
            if t.is_dir(): shutil.rmtree(t)
            elif t.exists(): t.unlink()
        except Exception as e:
            _box_warn(f"Не удалось удалить {t}: {e}")
    _box_ok("Файлы удалены.")

    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"])
    _box_ok("systemd обновлён.")
    _run(["sysctl", "--system"])
    _box_ok("sysctl сброшен.")

    _box_row()
    _box_ok(f"{GREEN}{BOLD}Telemt полностью удалён с сервера.{NC}")
    _box_row(); _box_bot()

    if not silent: _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ВЫБОР TLS-ДОМЕНА
# ══════════════════════════════════════════════════════════════════════════════
_DOMAINS: dict = {
    "1":  ("🔍 Поисковики и почта",
           ["yandex.ru", "ya.ru", "mail.ru", "rambler.ru", "maps.yandex.ru"]),
    "2":  ("🛒 Маркетплейсы",
           ["ozon.ru", "wildberries.ru", "wb.ru", "market.yandex.ru", "avito.ru"]),
    "3":  ("🎬 Онлайн-кино и ТВ",
           ["ivi.ru", "kinopoisk.ru", "okko.tv", "more.tv", "premier.one", "kion.ru"]),
    "4":  ("🎵 Музыка и подкасты",
           ["music.yandex.ru", "zvuk.com", "boom.ru", "podcasts.yandex.ru"]),
    "5":  ("🎮 Игры",
           ["vkplay.ru", "games.mail.ru", "wargaming.net", "worldoftanks.ru"]),
    "6":  ("📱 Операторы",
           ["mts.ru", "megafon.ru", "beeline.ru", "tele2.ru", "rostelecom.ru"]),
    "7":  ("🏦 Банки",
           ["sber.ru", "tbank.ru", "vtb.ru", "alfabank.ru", "raiffeisen.ru"]),
    "8":  ("🏛️  Госсервисы",
           ["gosuslugi.ru", "nalog.ru", "mos.ru", "pfr.gov.ru"]),
    "9":  ("💬 Соцсети",
           ["vk.com", "ok.ru", "odnoklassniki.ru", "tenchat.ru"]),
    "10": ("📰 Новости",
           ["ria.ru", "rbc.ru", "tass.ru", "kommersant.ru", "lenta.ru"]),
    "11": ("💻 IT",
           ["habr.com", "github.com", "selectel.ru", "timeweb.cloud", "reg.ru"]),
    "12": ("🌍 Международные",
           ["microsoft.com", "apple.com", "google.com", "cloudflare.com"]),
}

def _select_domain() -> str:
    """Возвращает выбранный домен. Бросает _Cancelled при Ctrl+C."""
    while True:
        _banner()
        _box_top("ВЫБОР FAKE TLS ДОМЕНА")
        _box_row()
        _box_info("Telemt маскируется под HTTPS сайта — DPI меньше подозревает.")
        _box_row(); _box_sep()
        for k, (label, _) in _DOMAINS.items():
            _box_item(k.rjust(2), label)
        _box_sep()
        _box_item("99", "✏️   Свой домен")
        _box_item(" Q", "← Назад (ivi.ru)")
        _box_bot(); print()

        cat = _ask(f"{CYAN}Категория: {NC}", c=True).strip()
        if cat.lower() == "q" or not cat:
            return "ivi.ru"
        if cat == "99":
            try:
                print("  Домен: ", end="", flush=True)
                d = input().strip()
            except KeyboardInterrupt:
                print(); raise _Cancelled()
            return d if _validate_domain(d) else "ivi.ru"
        if cat in _DOMAINS:
            label, doms = _DOMAINS[cat]
            _banner(); _box_top(label); _box_row()
            for i, d in enumerate(doms, 1):
                _box_item(str(i), d)
            _box_sep(); _box_item("Q", "← Назад"); _box_bot(); print()
            p = _ask(f"{CYAN}Выбор [1-{len(doms)}]: {NC}", c=True).strip()
            if p.lower() == "q": continue
            try:
                idx = int(p) - 1
                if 0 <= idx < len(doms): return doms[idx]
            except ValueError:
                pass
            return doms[0]

# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# ══════════════════════════════════════════════════════════════════════════════
def _menu_users(server_ip: str) -> None:
    while True:
        _banner()
        users  = _load_users()
        port   = _get_port()
        domain = _get_domain()

        _box_top("УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ")
        _box_row()
        _box_row(f"  {DIM}{'№':<4} {'Имя':<18} Секрет{NC}")
        _box_sep()
        for i, (n, s) in enumerate(users.items(), 1):
            _box_row(f"  {DIM}{i:<4}{NC} {n:<18} {DIM}{s[:16]}…{NC}")
        _box_row(); _box_sep()
        _box_item("1", "➕  Добавить")
        _box_item("2", "➖  Удалить")
        _box_item("3", "✏️   Переименовать")
        _box_item("4", "🔗  Показать ссылки")
        _box_sep(); _box_item("Q", "← Назад"); _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            try:
                print(f"  {CYAN}Имя (3-16 символов): {NC}", end="", flush=True)
                n = input().strip()
            except KeyboardInterrupt:
                print(); continue
            if not _validate_username(n):
                _warn("Недопустимое имя.")
            elif n in users:
                _warn(f"'{n}' уже существует.")
            else:
                users[n] = _generate_secret()
                _save_users(users)
                _run(["systemctl", "restart", SERVICE_NAME])
                _ok(f"Добавлен '{n}'.")
            _pause()

        elif ch == "2":
            if len(users) <= 1:
                _warn("Нельзя удалить последнего.")
            else:
                try:
                    print(f"  {CYAN}Имя для удаления: {NC}", end="", flush=True)
                    n = input().strip()
                except KeyboardInterrupt:
                    print(); continue
                if n not in users:
                    _warn(f"'{n}' не найден.")
                else:
                    del users[n]
                    _save_users(users)
                    _run(["systemctl", "restart", SERVICE_NAME])
                    _ok(f"Удалён '{n}'.")
            _pause()

        elif ch == "3":
            try:
                print(f"  {CYAN}Текущее имя: {NC}", end="", flush=True)
                o = input().strip()
            except KeyboardInterrupt:
                print(); continue
            if o not in users:
                _warn(f"'{o}' не найден.")
            else:
                try:
                    print(f"  {CYAN}Новое имя: {NC}", end="", flush=True)
                    n = input().strip()
                except KeyboardInterrupt:
                    print(); continue
                if not _validate_username(n):
                    _warn("Недопустимое имя.")
                elif n in users:
                    _warn(f"'{n}' занято.")
                else:
                    users[n] = users.pop(o)
                    _save_users(users)
                    _run(["systemctl", "restart", SERVICE_NAME])
                    _ok(f"'{o}' → '{n}'.")
            _pause()

        elif ch == "4":
            print()
            if not domain or not server_ip:
                _warn("Нет данных. Выполните установку.")
            else:
                for n, s in users.items():
                    sec  = _make_tls_secret(s, domain)
                    link = f"tg://proxy?server={server_ip}&port={port}&secret={sec}"
                    print(f"  {BOLD}{n}:{NC}")
                    print(f"  {YELLOW}{link}{NC}")
                    print()
            _pause()

        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  АВТООБНОВЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _menu_update() -> None:
    _info("Проверяю обновления...")
    cur = _get_installed_version()
    tag, url = _get_latest_release()
    if not tag:
        _warn("Не удалось получить данные с GitHub."); _pause(); return
    print()
    _ok(f"Установлена:  {cur or '—'}")
    _ok(f"Последняя:    {tag}")
    if cur == tag:
        print(); _info("Уже последняя версия."); _pause(); return
    print()
    if _ask(f"  {CYAN}Обновить до {tag}? [y/N]: {NC}", c=True).strip().lower() != "y":
        return
    _run(["systemctl", "stop", SERVICE_NAME])
    if _install_binary(url):
        _run(["systemctl", "start", SERVICE_NAME])
        _ok(f"Обновлено до {tag}.")
    else:
        _err("Обновление не удалось.")
        _run(["systemctl", "start", SERVICE_NAME])
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛНАЯ УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install(server_ip: str, server_ipv6: str) -> None:
    """Обёртка: перехватывает _Cancelled и возвращает в меню."""
    try:
        _run_install_inner(server_ip, server_ipv6)
    except _Cancelled:
        print(f"\n  {YELLOW}Установка прервана — возврат в меню.{NC}\n")
        _pause()

def _run_install_inner(server_ip: str, server_ipv6: str) -> None:
    # ── Если уже установлено ──────────────────────────────────────────────────
    already_installed = (
        BIN_PATH.exists() or CONFIG_FILE.exists() or
        SERVICE_FILE.exists() or WORK_DIR.exists()
    )
    if already_installed:
        _banner()
        _box_top("ПЕРЕУСТАНОВКА  •  TELEMT")
        _box_row()
        _box_warn("Обнаружена существующая установка Telemt.")
        _box_row()
        _box_info("Выберите режим переустановки:")
        _box_row()
        _box_item("1", f"🗑️   Полная очистка + установка с нуля  {YELLOW}(рекомендуется){NC}")
        _box_item("2", "♻️   Переустановить поверх  (конфиг и данные сохраняются)")
        _box_item("0", "← Отмена  (Ctrl+C)")
        _box_bot(); print()
        ch = _ask(f"{CYAN}Выбор [1/2/0]: {NC}", c=True).strip()
        if ch in ("0", "Q", "q", ""): return
        if ch == "1":
            if not _full_uninstall(silent=True): return
            print()

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text(f"=== Telemt Install {_now_str()} ===\n")

    # ── Сеть ──────────────────────────────────────────────────────────────────
    _banner(); _box_top("НАСТРОЙКА СЕТИ"); _box_row()
    _box_item("1", "IPv4 только")
    _box_item("2", "IPv6 только")
    _box_item("3", "DualStack IPv4+IPv6  ✓ рекомендуется")
    _box_row(); _box_sep()
    _box_item("A", "Порт 443")
    _box_item("B", "Порт 8443  ✓ рекомендуется")
    _box_item("C", "Свой порт...")
    _box_bot(); print()

    proto = _ask(f"{CYAN}Протокол [1-3] (Enter=3): {NC}", default="3", c=True).strip() or "3"
    ipv4  = proto in ("1", "3")
    ipv6  = proto in ("2", "3")

    pc = _ask(f"{CYAN}Порт [A/B/C] (Enter=B): {NC}", default="B", c=True).strip().upper() or "B"
    if pc == "A":
        port = 443
    elif pc == "C":
        try:
            print(f"  {CYAN}Порт (1024-65535): {NC}", end="", flush=True)
            port = int(input())
            assert 1024 <= port <= 65535
        except KeyboardInterrupt:
            print(); raise _Cancelled()
        except Exception:
            port = 8443
    else:
        port = 8443

    tls_domain = _select_domain()

    # ── MSS-фрагментация против TSPU JA4 DPI ─────────────────────────────────
    # Шаг обязателен при сервере в РФ; safe skip для прочих регионов.
    # Модуль telemt_mss_selector изолирован — ошибка импорта не ломает установку.
    _client_mss = ""
    _mss_mod = _get_mss_module()
    if _mss_mod is not None:
        try:
            _client_mss = _mss_mod.mss_select_interactive()
        except Exception as _me:
            _warn(f"Шаг MSS пропущен: {_me}")
            _client_mss = ""
    # ── Регион сервера: РФ / страна с блокировкой Telegram ─────────────────
    # _is_direct_ip() возвращает True если IP напрямую на интерфейсе (не NAT).
    # Это не означает доступность ME-серверов: в РФ они заблокированы.
    # Явный вопрос позволяет сразу ставить use_middle_proxy=false и
    # избежать варнингов "All ME servers for DC failed" в логах.
    _direct_ip = _is_direct_ip(server_ip)
    _banner()
    _box_top("РЕГИОН СЕРВЕРА")
    _box_row()
    _box_info("Telegram заблокирован в РФ и ряде других стран.")
    _box_info("В таком регионе Middle Proxy недоступен — нужен Direct Mode.")
    _box_row()
    _box_item("Y", f"Да, сервер в РФ / регионе с блокировкой  {GREEN}(Direct Mode){NC}")
    _box_item("N", f"Нет, Telegram доступен напрямую  {DIM}(Middle Proxy){NC}")
    _box_bot(); print()
    _region_blocked = _ask(
        f"{CYAN}Telegram заблокирован на этом сервере? [Y/n]: {NC}",
        default="y", c=True,
    ).strip().lower()
    # При блокировке — принудительно Direct; иначе — автоопределение по IP
    use_mp = False if _region_blocked in ("y", "") else _direct_ip

    # ── Настройка гибридного fallback (Middle Proxy → Direct) ────────────────
    # Шаг показывается только если use_mp=True (Middle Proxy актуален).
    # При use_mp=False сервер за NAT — Middle Proxy уже отключён, fallback не нужен.
    _fb_cfg = None
    if use_mp:
        _fb_mod = _get_fallback_module()
        if _fb_mod is not None:
            try:
                _banner()
                _box_top("HYBRID FALLBACK  •  MIDDLE PROXY → DIRECT")
                _box_row()
                _box_info("Telemt может автоматически переключаться в Direct Mode")
                _box_info("при деградации ME-серверов Telegram.")
                _box_row()
                _box_info("Переключение затрагивает только транспорт до Telegram DC.")
                _box_info("Порты, iptables и xray-интеграция не изменяются.")
                _box_row()
                _box_item("Y", f"Настроить fallback  {GREEN}(рекомендуется){NC}")
                _box_item("N", f"Пропустить (всегда Middle Proxy)")
                _box_bot(); print()
                _fb_ans = _ask(
                    f"{CYAN}Настроить hybrid fallback? [Y/n]: {NC}",
                    default="y", c=True,
                ).strip().lower()
                if _fb_ans in ("y", ""):
                    _fb_cfg = _fb_mod.me_probe_menu(CONFIG_FILE)
                else:
                    # Создаём конфиг с дефолтами (fallback разрешён, но без интерактива)
                    _fb_cfg = _fb_mod.FallbackConfig.defaults()
            except Exception as _fe:
                _warn(f"Модуль fallback недоступен: {_fe}")
                _fb_cfg = None

    # ── Xray tproxy-интеграция (dokodemo + iptables REDIRECT) ────────────────
    # Работает для VLESS-цепочек и AWG 2.0 — транспорт прозрачен для схемы.
    _xs       = _xray_tproxy_status()
    _cascade  = _xs["cascade"]
    _tproxy_already = _xs["enabled"]

    _banner()
    _box_top("ИНТЕГРАЦИЯ С XRAY (ОБХОД БЛОКИРОВКИ)")
    _box_row()
    if _cascade == "none":
        _box_warn("xray не обнаружен в режиме каскада (Режим B).")
        _box_info("Telemt будет работать в режиме direct — Telegram недоступен из РФ.")
        _box_info("Сначала установите xray в Режиме B, затем переустановите Telemt.")
    else:
        _cascade_label = "AWG 2.0" if _cascade == "awg" else "VLESS"
        _box_ok(f"Обнаружен xray-каскад: {_cascade_label}")
        _box_info(f"Схема: Telemt → iptables REDIRECT → dokodemo :{XRAY_TPROXY_PORT} → xray → exit VPS → Telegram")
        if _tproxy_already:
            ipt_str = f"{_xs['ipt_count']}/{_xs.get('ipt_total', len(_TG_NETS_current()))} подсетей"
            _box_ok(f"tproxy уже настроен (порт {_xs['port']}, iptables: {ipt_str})")
        _box_row()
        _box_item("Y", f"Направить трафик Telemt через xray ({_cascade_label})  ✓ рекомендуется")
        _box_item("N", "Прямое подключение (direct) — Telegram будет заблокирован в РФ")
    _box_bot()
    print()

    _use_tproxy = False
    if _cascade != "none":
        _use_xray = _ask(
            f"{CYAN}Использовать xray для проксирования? [Y/n]: {NC}",
            default="y", c=True,
        ).strip().lower()
        _use_tproxy = _use_xray in ("y", "")

    # ── Пользователи ─────────────────────────────────────────────────────────
    _banner(); _box_top("ПОЛЬЗОВАТЕЛИ"); _box_row()
    _box_info("Введите имя первого пользователя (Enter = user1).")
    _box_info("Допустимо: латиница, цифры, _ и - ; длина 3-16.")
    _box_info("Ctrl+C — отмена.")
    _box_bot(); print()
    while True:
        first_name = _ask(f"  {CYAN}Имя первого пользователя: {NC}", c=True).strip()
        if not first_name:
            first_name = "user1"; break
        if _validate_username(first_name): break
        _warn("Недопустимое имя. Попробуйте ещё раз.")
    users: dict = {first_name: _generate_secret()}
    _ok(f"Пользователь: {first_name}")
    print()
    while True:
        ans = _ask(f"  {CYAN}Добавить ещё пользователя? [y/N]: {NC}", c=True).strip().lower()
        if ans != "y": break
        try:
            print(f"  {CYAN}Имя (3-16): {NC}", end="", flush=True)
            n = input().strip()
        except KeyboardInterrupt:
            print(); raise _Cancelled()
        if _validate_username(n) and n not in users:
            users[n] = _generate_secret(); _ok(f"Добавлен: {n}")
        else:
            _warn("Недопустимое имя или уже есть.")

    # ── Установка ─────────────────────────────────────────────────────────────
    print()
    _info("Останавливаю старую установку...")
    _run(["systemctl", "stop", SERVICE_NAME])
    time.sleep(1)

    _info("Генерирую конфиг...")
    # telemt всегда в режиме direct — xray перехватывается на уровне iptables
    _write_config(port, ipv4, ipv6, tls_domain, users, use_mp, socks5_port=0,
                  fallback_cfg=_fb_cfg, client_mss=_client_mss)
    _ok(f"Конфиг: {CONFIG_FILE}")

    _info("Устанавливаю зависимости...")
    _run(["apt-get", "install", "-y", "-q",
          "curl", "wget", "ca-certificates", "openssl", "iproute2", "procps", "iptables"])

    _info("Получаю последнюю версию telemt...")
    tag, url = _get_latest_release()
    if not url:
        _err("Не удалось получить URL. Проверьте соединение."); _pause(); return
    _info(f"Скачиваю telemt {tag}...")
    if not _install_binary(url):
        _pause(); return

    _info("Оптимизация ядра...")
    _apply_optimizations()

    _info("Установка systemd-сервиса...")
    _install_service()
    _setup_ufw(port)

    # ── Xray: dokodemo-door + iptables REDIRECT ───────────────────────────────
    tproxy_ok_msg = ""
    if _use_tproxy:
        _info("Настраиваю tproxy-интеграцию (dokodemo + iptables REDIRECT)...")
        _ok_tp, _msg_tp = xray_enable_tproxy_for_telemt(XRAY_TPROXY_PORT)
        if _ok_tp:
            _ok(_msg_tp)
            tproxy_ok_msg = _msg_tp
        else:
            _warn(f"Не удалось настроить tproxy: {_msg_tp}")
            _warn("Telemt будет работать в режиме direct (Telegram может быть заблокирован).")

    _info("Настройка учёта трафика (iptables)...")
    ipt_ok = _setup_accounting(port)
    if ipt_ok: _ok("Учёт трафика активирован.")

    _info("Запуск telemt...")
    _run(["systemctl", "start", SERVICE_NAME])

    waited = 0
    while waited < 40:
        if f":{port}" in _run(["ss", "-tln"], capture=True).stdout:
            _ok(f"Порт {port} слушается ({waited}с)"); break
        time.sleep(2); waited += 2
    else:
        _warn(f"Порт не открылся за 40с — journalctl -u telemt -n 30")

    # ── Post-install: проверка ME-серверов и автоматический fallback ──────────
    # Выполняется только при use_mp=True и если fallback настроен.
    # Не блокирует установку при ошибке — предупреждает и продолжает.
    _fallback_triggered = False
    _fallback_msg = ""
    if use_mp and _fb_cfg is not None and getattr(_fb_cfg, "fallback_to_direct", False):
        _fb_mod = _get_fallback_module()
        if _fb_mod is not None:
            _info("Проверяю доступность ME-серверов (Telegram Middle Proxy)...")
            try:
                _fb_result = _fb_mod.run_post_install_fallback_check(
                    config_file=CONFIG_FILE,
                    service=SERVICE_NAME,
                    warmup_wait=8,
                )
                if _fb_result:
                    # Fallback сработал
                    _warn("Middle Proxy недоступен — активирован Direct Mode.")
                    _warn("Конфиг обновлён автоматически (telemt.toml не перезаписан).")
                    _fallback_triggered = True
                    _fallback_msg = _fb_result
                else:
                    _ok("Middle Proxy доступен — работаем в режиме Middle Proxy.")
            except Exception as _fe:
                _warn(f"Проверка ME-серверов не удалась: {_fe}")
    _banner(); _box_top("✅ УСТАНОВКА ЗАВЕРШЕНА"); _box_row()
    _box_ok(f"Версия:  telemt {tag}")
    _box_ok(f"Порт:    {port}")
    _box_ok(f"Домен:   {tls_domain}")
    _box_ok(f"IPv4:    {server_ip or '—'}")
    if server_ipv6: _box_ok(f"IPv6:    {server_ipv6}")
    if use_mp and not _fallback_triggered:
        _box_ok(f"Middle:  да (активен)")
    elif use_mp and _fallback_triggered:
        _box_warn(f"Middle:  отказ → Direct Mode (ME-серверы недоступны)")
    else:
        _box_ok(f"Middle:  нет (NAT / Direct)")
    # Статус fallback-настройки
    if _fb_cfg is not None:
        _fb_status = (
            f"включён (попыток: {_fb_cfg.fallback_after_attempts}, "
            f"timeout: {_fb_cfg.fallback_after_seconds}s)"
        )
        _box_ok(f"Fallback: {_fb_status}")
    _box_ok(f"Учёт:    {'активен (iptables)' if ipt_ok else 'journalctl'}")
    if _use_tproxy and tproxy_ok_msg:
        _cascade_label = "AWG 2.0" if _cascade == "awg" else "VLESS"
        _box_ok(f"Xray:    dokodemo :{XRAY_TPROXY_PORT} + iptables REDIRECT → {_cascade_label} ✓")
    else:
        _box_warn("Xray:    не используется (direct — Telegram может быть заблокирован)")
    # MSS anti-JA4 статус
    _mss_mod_summary = _get_mss_module()
    if _mss_mod_summary is not None:
        _box_ok(f"MSS:     {_mss_mod_summary.mss_status_line(_client_mss)}")
    elif _client_mss:
        _box_ok(f"MSS:     {_client_mss}")
    _box_row(); _box_sep()
    _box_row(f"  {DIM}journalctl -u telemt -f   # логи{NC}")
    _box_bot()
    print()
    print(f"  {BOLD}{CYAN}🔗 Ссылки для Telegram:{NC}")
    print()
    for n, s in users.items():
        sec  = _make_tls_secret(s, tls_domain)
        link = f"tg://proxy?server={server_ip}&port={port}&secret={sec}"
        print(f"  {BOLD}{WHITE}{n}:{NC}")
        print(f"  {YELLOW}{link}{NC}")
        print()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ПОДМЕНЮ: XRAY SOCKS5-ИНТЕГРАЦИЯ
# ══════════════════════════════════════════════════════════════════════════════

def _menu_xray_integration() -> None:
    """
    Управление tproxy-интеграцией: dokodemo-door + iptables REDIRECT.
    Поддерживает VLESS+REALITY и AWG 2.0 без изменений логики.
    """
    while True:
        _banner()
        xs      = _xray_tproxy_status()
        cascade = xs["cascade"]
        enabled = xs["enabled"]

        _box_top("XRAY ИНТЕГРАЦИЯ  •  TELEMT → XRAY → EXIT VPS")
        _box_row()

        if cascade == "none":
            _box_err("xray-каскад (Режим B) не обнаружен на этом сервере.")
            _box_row()
            _box_info("Для работы интеграции необходимо:")
            _box_info("1. Установить xray через VLESS Ultimate (пункт 1 → Режим B)")
            _box_info("2. Вернуться в это меню и включить интеграцию.")
            _box_row(); _box_sep()
            _box_item("Q", "← Назад"); _box_bot(); print()
            _ask(f"{CYAN}Выбор: {NC}", c=True)
            break

        cascade_label = "AWG 2.0" if cascade == "awg" else "VLESS+REALITY"
        _box_kv("Каскад:", f"{GREEN}{cascade_label}{NC}")
        _box_kv("Proxy tag:", xs["proxy_tag"])

        if enabled:
            ipt_str = f"{xs['ipt_count']}/{xs.get('ipt_total', len(_TG_NETS_current()))}"
            ipt_col = GREEN if xs["ipt_ok"] else YELLOW
            _box_kv("dokodemo:", f"{GREEN}✓ активен  →  :{xs['port']}{NC}")
            _box_kv("iptables:", f"{ipt_col}REDIRECT {ipt_str} подсетей{NC}")
            _box_row()
            _box_info("Схема трафика:")
            _box_info(f"  Telemt → iptables REDIRECT → dokodemo :{xs['port']} → xray → {cascade_label} → exit VPS → Telegram")
            if not xs["ipt_ok"]:
                _box_warn(f"Не все iptables-правила на месте ({ipt_str}). Используйте [2] для восстановления.")
        else:
            _box_kv("tproxy:", f"{RED}✗ не настроен (telemt работает через direct){NC}")
            _box_row()
            _box_warn("Telegram недоступен с российских IP без интеграции с xray!")

        # Статус подсетей TG
        _box_kv("Подсети:", _tg_nets_status_line())

        _box_row(); _box_sep()
        if not enabled:
            _box_item("1", f"✅  Включить интеграцию (dokodemo :{XRAY_TPROXY_PORT} + iptables)")
        else:
            _box_item("1", f"🔄  Переприменить / восстановить правила")
            _box_item("2", f"❌  Отключить интеграцию (перейти на direct)")
        _box_item("3", "🔍  Проверить статус xray inbound + iptables")
        _box_item("N", "🌐  Обновить подсети Telegram + переприменить iptables")
        _box_sep()
        from vless_installer.modules.telemt_self_route import status as _sr_status
        _sr = _sr_status()
        if _sr["return_rule"] and _sr["after_xray"]:
            _box_item("R", f"🔁  Маршрут DC/ME трафика: {GREEN}ВКЛЮЧЁН{NC}  (after=xray + RETURN rule)")
        else:
            _box_item("R", f"🔁  Маршрут DC/ME трафика: {YELLOW}ВЫКЛЮЧЕН{NC}  (telemt стартует до iptables)")
        _box_sep()
        _box_item("Q", "← Назад"); _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _info(f"Применяю tproxy-интеграцию (dokodemo :{XRAY_TPROXY_PORT})...")
            ok, msg = xray_enable_tproxy_for_telemt(XRAY_TPROXY_PORT)
            if ok:
                _ok(msg)
            else:
                _err(msg)
            _pause()

        elif ch == "2" and enabled:
            ok, msg = xray_disable_tproxy_for_telemt()
            if ok:
                _ok(msg)
            else:
                _err(msg)
            _pause()

        elif ch == "r":
            from vless_installer.modules.telemt_self_route import enable as _sr_enable, disable as _sr_disable, status as _sr_status
            _sr = _sr_status()
            print()
            if _sr["return_rule"] and _sr["after_xray"]:
                _info("Маршрутизация DC/ME уже включена. Отключить?")
                if _ask(f"{CYAN}Отключить? [y/N]: {NC}", c=True).strip().lower() == "y":
                    ok, msg = _sr_disable()
                    _ok(msg) if ok else _err(msg)
            else:
                _info("Включаю маршрутизацию DC/ME трафика Telemt через xray...")
                ok, msg = _sr_enable()
                if ok:
                    _ok(msg)
                else:
                    _err(msg)
            _pause()

        elif ch == "3":
            cfg_path = _xray_config_path()
            print()
            if not cfg_path:
                _warn("xray config.json не найден.")
            else:
                try:
                    cfg = json.loads(cfg_path.read_text())
                    # dokodemo inbound
                    inbounds = [ib for ib in cfg.get("inbounds", [])
                                if ib.get("tag") == XRAY_TPROXY_TAG]
                    rules    = [r for r in cfg.get("routing", {}).get("rules", [])
                                if XRAY_TPROXY_TAG in r.get("inboundTag", [])]
                    if inbounds:
                        _ok(f"dokodemo inbound: порт {inbounds[0].get('port')}, "
                            f"listen {inbounds[0].get('listen')}, "
                            f"followRedirect {inbounds[0].get('settings', {}).get('followRedirect')}")
                    else:
                        _warn("dokodemo inbound не найден в xray config.")
                    if rules:
                        dest = rules[0].get("outboundTag") or rules[0].get("balancerTag") or "?"
                        _ok(f"Routing rule: {XRAY_TPROXY_TAG} → {dest}")
                    else:
                        _warn("Routing rule не найден.")
                    # xray service
                    r = _run(["systemctl", "is-active", XRAY_SERVICE_NAME], capture=True)
                    svc = r.stdout.strip()
                    _ok(f"xray сервис: {svc}") if svc == "active" else _warn(f"xray сервис: {svc}")
                    # iptables
                    port = _xray_dokodemo_port(cfg) or XRAY_TPROXY_PORT
                    tg_nets_now = _TG_NETS_current()
                    active = sum(1 for n in tg_nets_now if _ipt_rule_exists(n, port))
                    total  = len(tg_nets_now)
                    col    = GREEN if active == total else YELLOW
                    _ok(f"iptables REDIRECT: {col}{active}/{total} подсетей{NC}")
                    if active < total:
                        missing = [n for n in tg_nets_now if not _ipt_rule_exists(n, port)]
                        for n in missing:
                            _warn(f"  отсутствует: {n}")
                except Exception as e:
                    _err(f"Ошибка: {e}")
            _pause()

        elif ch == "n":
            # ── Обновление подсетей + переприменение iptables ─────────────
            print()
            new_nets = _update_tg_nets_interactive()
            xs_now = _xray_tproxy_status()
            if xs_now["enabled"]:
                port = xs_now["port"]
                print()
                _info(f"Переприменяю iptables REDIRECT для {len(new_nets)} подсетей → :{port}...")
                failed = [n for n in new_nets if not _ipt_add_redirect(n, port)]
                _iptables_persist()
                if failed:
                    _warn(f"Не удалось добавить {len(failed)} правил")
                else:
                    _ok(f"iptables REDIRECT обновлён: {len(new_nets)} подсетей активны")
            else:
                _info("tproxy не активен — только файл обновлён.")
            _pause()

        elif ch in ("q", ""):
            break
def mtproto_menu() -> None:
    """
    Точка входа из _core.py → главное меню VLESS Ultimate → пункт 6.
    Ctrl+C внутри подменю → возврат сюда.
    Ctrl+C здесь → пробрасывается в _core.py (KeyboardInterrupt не ловим).
    """
    server_ip, server_ipv6 = "", ""

    while True:
        _banner()
        r         = _run(["systemctl", "is-active", SERVICE_NAME], capture=True)
        is_active = r.stdout.strip() == "active"
        installed = BIN_PATH.exists()
        ver       = _get_installed_version() if installed else None
        svc_str   = (f"{GREEN}● запущен   {ver or ''}{NC}" if is_active else
                     f"{RED}● остановлен{NC}"               if installed  else
                     f"{YELLOW}● не установлен{NC}")

        _box_top("TELEMT MTPROXY")
        _box_row(); _box_kv("Статус:", svc_str); _box_row()

        # tproxy-интеграция — статус одной строкой
        _xs  = _xray_tproxy_status()
        if _xs["enabled"]:
            _mode  = "AWG 2.0" if _xs["cascade"] == "awg" else "VLESS"
            ipt_s  = f"{_xs['ipt_count']}/{_xs.get('ipt_total', len(_TG_NETS_current()))}"
            ipt_c  = GREEN if _xs["ipt_ok"] else YELLOW
            _box_kv("Xray:", f"{GREEN}dokodemo :{_xs['port']} → {_mode}{NC}  iptables {ipt_c}{ipt_s}{NC}")
        elif _xs["cascade"] != "none":
            _box_kv("Xray:", f"{YELLOW}каскад есть, tproxy не настроен{NC}")
        else:
            _box_kv("Xray:", f"{RED}каскад не обнаружен (direct){NC}")

        # Статус подсетей Telegram
        _box_kv("Подсети:", _tg_nets_status_line())

        # Статус hybrid fallback одной строкой
        _fb_mod_for_status = _get_fallback_module()
        if _fb_mod_for_status is not None and CONFIG_FILE.exists():
            _box_kv("Fallback:", _fb_mod_for_status.fallback_status_line(CONFIG_FILE))

        _box_row(); _box_sep()
        _box_item("1", "🚀  Установить / переустановить")
        _box_item("2", "👥  Управление пользователями")
        _box_item("3", "🔗  Показать ссылки")
        _box_item("4", "🔄  Перезапустить сервис")
        _box_item("5", "⬆️   Проверить и обновить")
        _box_item("6", "📊  Статистика трафика")
        _box_item("7", "📋  Статус / логи")
        _box_item("X", "🔗  Xray-интеграция (SOCKS5 ↔ каскад)")
        _box_item("F", "🔀  Hybrid Fallback (Middle Proxy → Direct)")
        _box_item("N", "🌐  Обновить подсети Telegram (RIPE NCC)")
        _box_item("8", f"{RED}🗑️   Полное удаление{NC}")
        _box_sep()
        _box_item("Q", "← Назад в главное меню VLESS")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            if not server_ip:
                _info("Определяю внешний IP...")
                server_ip, server_ipv6 = _get_public_ip()
            _run_install(server_ip, server_ipv6)

        elif ch == "2":
            if not CONFIG_FILE.exists():
                _warn("Telemt не установлен."); _pause(); continue
            if not server_ip:
                server_ip, _ = _get_public_ip()
            _menu_users(server_ip)

        elif ch == "3":
            if not CONFIG_FILE.exists():
                _warn("Telemt не установлен."); _pause(); continue
            if not server_ip:
                server_ip, _ = _get_public_ip()
            users  = _load_users()
            port   = _get_port()
            domain = _get_domain()
            print()
            for n, s in users.items():
                sec  = _make_tls_secret(s, domain)
                link = f"tg://proxy?server={server_ip}&port={port}&secret={sec}"
                print(f"  {BOLD}{n}:{NC}")
                print(f"  {YELLOW}{link}{NC}")
                print()
            _pause()

        elif ch == "4":
            _run(["systemctl", "restart", SERVICE_NAME])
            _ok("Сервис перезапущен."); _pause()

        elif ch == "5":
            try:
                _menu_update()
            except _Cancelled:
                pass

        elif ch == "6":
            try:
                from vless_installer.modules.mtproto_stats import stats_menu
                stats_menu()
            except ImportError as e:
                _err(f"Модуль статистики не найден: {e}"); _pause()

        elif ch == "7":
            os.system("clear")
            _box_top("СТАТУС И ЛОГИ  •  TELEMT"); _box_row()
            r1 = subprocess.run(
                ["systemctl", "status", SERVICE_NAME, "--no-pager"],
                capture_output=True, encoding="utf-8", errors="replace"
            )
            for line in (r1.stdout or r1.stderr or "Нет данных").splitlines():
                _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")
            _box_sep()
            _box_row(f"  {BOLD}{CYAN}Последние 30 строк журнала:{NC}"); _box_row()
            r2 = subprocess.run(
                ["journalctl", "-u", SERVICE_NAME, "-n", "30",
                 "--no-pager", "--output=short-monotonic"],
                capture_output=True, encoding="utf-8", errors="replace",
                env={**os.environ, "LANG": "C.UTF-8"}
            )
            for line in (r2.stdout or r2.stderr or "Нет записей").splitlines():
                _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")
            _box_row(); _box_bot(); _pause()

        elif ch == "8":
            if not (BIN_PATH.exists() or CONFIG_FILE.exists() or SERVICE_FILE.exists()):
                _warn("Telemt не установлен — нечего удалять."); _pause(); continue
            try:
                _full_uninstall(silent=False)
            except _Cancelled:
                _info("Удаление отменено."); _pause()

        elif ch == "x":
            try:
                _menu_xray_integration()
            except _Cancelled:
                pass

        elif ch == "f":
            # ── Hybrid Fallback управление ────────────────────────────────────
            if not CONFIG_FILE.exists():
                _warn("Telemt не установлен."); _pause(); continue
            _fb_mod = _get_fallback_module()
            if _fb_mod is None:
                _warn("Модуль telemt_fallback недоступен."); _pause(); continue
            try:
                _banner()
                _box_top("🔀  HYBRID FALLBACK  •  MIDDLE PROXY → DIRECT")
                _box_row()
                _fb_now = _fb_mod.read_fallback_config(CONFIG_FILE)
                _mp_now = _fb_mod.read_runtime_middle_proxy(CONFIG_FILE)
                _box_kv("Текущий режим:",    f"{'Middle Proxy' if _mp_now else 'Direct'}")
                _box_kv("fallback_to_direct:",       f"{GREEN if _fb_now.fallback_to_direct else RED}{_fb_now.fallback_to_direct}{NC}")
                _box_kv("fallback_after_attempts:",  str(_fb_now.fallback_after_attempts))
                _box_kv("fallback_after_seconds:",   str(_fb_now.fallback_after_seconds))
                _box_kv("auto_revert_to_middle:",    f"{GREEN if _fb_now.auto_revert_to_middle else DIM}{_fb_now.auto_revert_to_middle}{NC}")
                _box_row(); _box_sep()
                _box_item("1", "⚙️   Изменить параметры fallback")
                _box_item("2", "🔍  Проверить ME-серверы сейчас")
                _box_item("3", "🔄  Применить reload (hot-reload конфига)")
                _box_item("4", f"→  Переключить в Direct Mode вручную")
                _box_item("5", f"←  Переключить в Middle Proxy вручную")
                _box_sep()
                _box_item("Q", "← Назад")
                _box_bot(); print()

                try:
                    fb_ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
                except _Cancelled:
                    fb_ch = "q"

                if fb_ch == "1":
                    new_fb_cfg = _fb_mod.me_probe_menu(CONFIG_FILE)
                    _fb_mod.append_fallback_section(CONFIG_FILE, new_fb_cfg)
                    _ok("Параметры fallback обновлены в конфиге.")
                    _pause()

                elif fb_ch == "2":
                    print()
                    _info("Проверяю ME-серверы...")
                    probe = _fb_mod.MiddleProxyProbe()
                    ok_c, total_c = probe.probe_all()
                    ratio = ok_c / total_c if total_c else 0
                    if ratio >= _fb_mod._ME_QUORUM:
                        _ok(f"ME-серверы доступны: {ok_c}/{total_c} ({ratio:.0%})")
                    else:
                        _warn(f"ME-серверы НЕДОСТУПНЫ: {ok_c}/{total_c} ({ratio:.0%} < кворум)")
                    hits = _fb_mod.check_journal_for_me_failures()
                    if hits:
                        _warn(f"В журнале найдены сигналы отказа ME ({len(hits)} строк):")
                        for h in hits[:3]:
                            print(f"    {DIM}{h[:70]}{NC}")
                    else:
                        _ok("Журнал: сигналов отказа ME не найдено.")
                    _pause()

                elif fb_ch == "3":
                    _info("Выполняю hot-reload конфига...")
                    fb_orch = _fb_mod.FallbackOrchestrator(
                        fb_config=_fb_now, config_file=CONFIG_FILE, service=SERVICE_NAME,
                    )
                    result = fb_orch.apply_reload_config()
                    _ok(result)
                    _pause()

                elif fb_ch == "4":
                    _info("Переключаю в Direct Mode (runtime)...")
                    ok_p = _fb_mod._patch_config_middle_proxy(CONFIG_FILE, enable=False)
                    if ok_p:
                        _fb_mod._reload_telemt(SERVICE_NAME)
                        _ok("Переключено в Direct Mode. use_middle_proxy=false в конфиге.")
                    else:
                        _err("Не удалось обновить конфиг.")
                    _pause()

                elif fb_ch == "5":
                    _info("Переключаю в Middle Proxy (runtime)...")
                    ok_p = _fb_mod._patch_config_middle_proxy(CONFIG_FILE, enable=True)
                    if ok_p:
                        _fb_mod._reload_telemt(SERVICE_NAME)
                        _ok("Переключено в Middle Proxy. use_middle_proxy=true в конфиге.")
                    else:
                        _err("Не удалось обновить конфиг.")
                    _pause()

            except Exception as _fe:
                _err(f"Ошибка fallback-меню: {_fe}"); _pause()

        elif ch == "n":
            # ── Обновление подсетей Telegram ──────────────────────────────
            _banner()
            _box_top("🌐  ОБНОВЛЕНИЕ ПОДСЕТЕЙ TELEGRAM")
            _box_row()
            _box_info("Источники: RIPE NCC stat.ripe.net")
            _box_info("ASN: AS62041, AS59930, AS44907, AS211157, AS42065")
            _box_row()
            _box_info("После обновления новые правила будут применены к iptables.")
            _box_row()
            _box_item("Y", "Обновить и применить")
            _box_item("N", "← Отмена")
            _box_bot(); print()
            try:
                ans = _ask(f"{CYAN}Выбор [Y/n]: {NC}", default="y", c=True).strip().lower()
            except _Cancelled:
                continue
            if ans not in ("y", ""):
                continue
            print()
            new_nets = _update_tg_nets_interactive()
            # Применяем к iptables если tproxy активен
            xs = _xray_tproxy_status()
            if xs["enabled"]:
                port = xs["port"]
                print()
                _info(f"Применяю iptables REDIRECT для {len(new_nets)} подсетей → :{port}...")
                failed = [n for n in new_nets if not _ipt_add_redirect(n, port)]
                _iptables_persist()
                if failed:
                    _warn(f"Не удалось добавить {len(failed)} правил: {', '.join(failed[:3])}{'…' if len(failed)>3 else ''}")
                else:
                    _ok(f"iptables REDIRECT обновлён: {len(new_nets)} подсетей")
            else:
                _info("tproxy не активен — iptables не обновляем.")
            _pause()

        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        mtproto_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)
