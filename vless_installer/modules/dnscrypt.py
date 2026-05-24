"""
vless_installer/modules/dnscrypt.py
───────────────────────────────────────────────────────────────────────────────
Модуль DNSCrypt-proxy — установка, управление, оптимизация.
Интегрируется в VLESS Ultimate Installer v4.11.3

Точка входа из _core.py:
    from vless_installer.modules.dnscrypt import dnscrypt_menu
    dnscrypt_menu()

Точка входа для полного установщика (вместо install_dnscrypt из _core.py):
    from vless_installer.modules.dnscrypt import (
        install_dnscrypt,
        apply_dnscrypt_tuning,
        is_dnscrypt_running,
        get_dnscrypt_port,
        DNSCRYPT_BIN,
        DNSCRYPT_CONF,
        DNSCRYPT_CONF_DIR,
        DNSCRYPT_SERVICE,
        DNSCRYPT_LISTEN_ADDR,
        DNSCRYPT_LISTEN_PORT,
    )

Принципы:
  • install_dnscrypt() используется и в полном флоу, и в standalone
  • install_dnscrypt_standalone() — обёртка для вызова из меню без PARAM_USE_DNSCRYPT
  • После standalone-установки автоматически патчится /etc/xray/config.json
  • Ctrl+C на любом шаге → возврат в вызывающее меню (через _Cancelled)
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
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
DNSCRYPT_BIN         = Path("/usr/local/bin/dnscrypt-proxy")
DNSCRYPT_CONF_DIR    = Path("/etc/dnscrypt-proxy")
DNSCRYPT_CONF        = DNSCRYPT_CONF_DIR / "dnscrypt-proxy.toml"
DNSCRYPT_SERVICE     = Path("/etc/systemd/system/dnscrypt-proxy.service")
DNSCRYPT_LISTEN_ADDR = "127.0.0.1"
DNSCRYPT_LISTEN_PORT = 5300

XRAY_CONFIG_PATHS = [
    Path("/etc/xray/config.json"),
    Path("/usr/local/etc/xray/config.json"),
]
XRAY_SERVICE_NAME = "xray"

LOG_FILE = Path("/var/log/vless-install.log")

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
        print(f"{CYAN}╠{'═' * _BOX_W}╣{NC}")

def _box_sep() -> None:
    print(f"{CYAN}╠{'═' * _BOX_W}╣{NC}")

def _box_bot() -> None:
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        plain = _plain(text)
        cut = 0
        acc = 0
        import unicodedata as _ud
        for i, ch in enumerate(plain):
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

def _box_kv(key: str, val: str, kw: int = 22) -> None:
    key_colored = f"{CYAN}{key}{NC}"
    key_pad = kw - _wlen(key_colored)
    _box_row(f"  {key_colored}{' ' * max(0, key_pad)}  {val}")

def _box_ok(msg: str)   -> None: _box_row(f"  {GREEN}✓{NC}  {msg}")
def _box_warn(msg: str) -> None: _box_row(f"  {YELLOW}⚠{NC}  {msg}")
def _box_info(msg: str) -> None: _box_row(f"  {CYAN}→{NC}  {msg}")
def _box_err(msg: str)  -> None: _box_row(f"  {RED}✗{NC}  {msg}")

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _log(msg: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] {_plain(msg)}\n")
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
    except (KeyboardInterrupt, EOFError):
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

# ══════════════════════════════════════════════════════════════════════════════
#  ПУБЛИЧНОЕ API — используется из _core.py
# ══════════════════════════════════════════════════════════════════════════════
def get_dnscrypt_port() -> int:
    """Надёжное определение реального порта DNSCrypt-proxy из конфига."""
    if not DNSCRYPT_CONF.exists():
        return DNSCRYPT_LISTEN_PORT
    try:
        content = DNSCRYPT_CONF.read_text()
        m = re.search(
            r"listen_addresses\s*=\s*\[\s*['\"][^:]+:(\d+)",
            content, re.IGNORECASE,
        )
        if m:
            port = int(m.group(1))
            if 1024 <= port <= 65535:
                return port
    except Exception:
        pass
    return DNSCRYPT_LISTEN_PORT


def is_dnscrypt_running() -> bool:
    """Проверяет что dnscrypt-proxy активен в systemd."""
    r = _run(["systemctl", "is-active", "dnscrypt-proxy"], capture=True, check=False)
    return r.stdout.strip() == "active"


def is_dnscrypt_installed() -> bool:
    """Проверяет наличие бинарника и конфига."""
    return DNSCRYPT_BIN.exists() and DNSCRYPT_CONF.exists()


# ══════════════════════════════════════════════════════════════════════════════
#  ОПРЕДЕЛЕНИЕ АРХИТЕКТУРЫ
# ══════════════════════════════════════════════════════════════════════════════
def _get_arch() -> Optional[str]:
    arch = _run(["uname", "-m"], capture=True, check=False).stdout.strip()
    arch_map = {
        "x86_64":  "linux_x86_64",
        "aarch64": "linux_arm64",
        "armv7l":  "linux_arm",
        "i386":    "linux_386",
        "i686":    "linux_386",
    }
    return arch_map.get(arch)


# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛУЧЕНИЕ ПОСЛЕДНЕЙ ВЕРСИИ
# ══════════════════════════════════════════════════════════════════════════════
def _get_latest_tag() -> str:
    """Получает последний тег релиза DNSCrypt-proxy с GitHub. Три попытки."""
    for attempt in range(1, 4):
        try:
            r = _run(
                ["curl", "-fsSL", "--connect-timeout", "10",
                 "https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest"],
                capture=True, check=False,
            )
            data = json.loads(r.stdout)
            tag = data.get("tag_name", "")
            if tag:
                return tag
        except Exception:
            pass
        _warn(f"Попытка {attempt}: не удалось получить тег DNSCrypt-proxy, повтор...")
        time.sleep(3)
    return ""


# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛУЧЕНИЕ УСТАНОВЛЕННОЙ ВЕРСИИ
# ══════════════════════════════════════════════════════════════════════════════
def _get_installed_version() -> str:
    if not DNSCRYPT_BIN.exists():
        return ""
    r = _run([str(DNSCRYPT_BIN), "--version"], capture=True, check=False)
    m = re.search(r"(\d+\.\d+[\.\d]*)", r.stdout + r.stderr)
    return m.group(1) if m else "unknown"


# ══════════════════════════════════════════════════════════════════════════════
#  ГЕНЕРАЦИЯ КОНФИГА
# ══════════════════════════════════════════════════════════════════════════════
def _write_default_config() -> None:
    """Записывает конфиг dnscrypt-proxy по умолчанию."""
    DNSCRYPT_CONF_DIR.mkdir(parents=True, exist_ok=True)
    DNSCRYPT_CONF.write_text(textwrap.dedent(f"""\
        ## dnscrypt-proxy.toml — сгенерирован VLESS Ultimate Installer
        ## Слушает на {DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT}

        listen_addresses = ['{DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT}']

        max_clients = 250

        ipv4_servers = true
        ipv6_servers = false
        dnscrypt_servers = true
        doh_servers = true
        odoh_servers = false

        require_dnssec = false
        require_nolog = true
        require_nofilter = false

        force_tcp = false
        timeout = 2500
        keepalive = 30

        log_level = 1
        use_syslog = true

        cert_refresh_delay = 240

        bootstrap_resolvers = ['1.1.1.1:53', '8.8.8.8:53']
        ignore_system_dns = true

        fallback_resolvers = ['1.1.1.1:53', '8.8.8.8:53']

        netprobe_timeout = 5
        netprobe_address = '1.1.1.1:53'

        offline_mode = false
        reject_ttl = 10

        cache = true
        cache_size = 32768
        cache_min_ttl = 60
        cache_max_ttl = 86400
        cache_neg_min_ttl = 60
        cache_neg_max_ttl = 600

        [blocked_names]
          blocked_names_file = '/etc/dnscrypt-proxy/blocked-names.txt'
          log_file = '/var/log/dnscrypt-proxy-blocked.log'
          log_format = 'tsv'

        [blocked_ips]
          blocked_ips_file = '/etc/dnscrypt-proxy/blocked-ips.txt'

        [sources]
          [sources.public-resolvers]
            urls = [
              'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
              'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md'
            ]
            cache_file = '/etc/dnscrypt-proxy/public-resolvers.md'
            minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
            refresh_delay = 72
            prefix = ''

          [sources.relays]
            urls = [
              'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
              'https://download.dnscrypt.info/resolvers-list/v3/relays.md'
            ]
            cache_file = '/etc/dnscrypt-proxy/relays.md'
            minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
            refresh_delay = 72
            prefix = ''
    """))

    for f in ("blocked-names.txt", "blocked-ips.txt"):
        fp = DNSCRYPT_CONF_DIR / f
        fp.touch()
        fp.chmod(0o644)
    DNSCRYPT_CONF.chmod(0o644)


# ══════════════════════════════════════════════════════════════════════════════
#  ЗАПИСЬ SYSTEMD-ЮНИТА
# ══════════════════════════════════════════════════════════════════════════════
def _write_service() -> None:
    DNSCRYPT_SERVICE.write_text(textwrap.dedent("""\
        [Unit]
        Description=DNSCrypt-proxy — зашифрованный DNS-резолвер
        Documentation=https://github.com/DNSCrypt/dnscrypt-proxy
        After=network.target network-online.target
        Wants=network-online.target
        Before=xray.service nginx.service

        [Service]
        Type=simple
        NonBlocking=true
        ExecStart=/usr/local/bin/dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy.toml
        Restart=on-failure
        RestartSec=5s
        TimeoutStartSec=60s
        TimeoutStopSec=10s
        User=dnscrypt
        Group=dnscrypt
        AmbientCapabilities=CAP_NET_BIND_SERVICE
        CapabilityBoundingSet=CAP_NET_BIND_SERVICE
        NoNewPrivileges=yes

        [Install]
        WantedBy=multi-user.target
    """))


# ══════════════════════════════════════════════════════════════════════════════
#  ОЖИДАНИЕ ЗАПУСКА СЕРВИСА
# ══════════════════════════════════════════════════════════════════════════════
def _wait_for_service(tag: str) -> bool:
    """
    Ждёт до 30 секунд пока dnscrypt-proxy перейдёт в active.
    Возвращает True если сервис запустился, False если failed/таймаут.
    """
    for _ in range(30):
        time.sleep(1)
        r = _run(["systemctl", "is-active", "dnscrypt-proxy"], capture=True, check=False)
        if r.stdout.strip() == "active":
            # Проверяем что порт действительно слушает
            port = get_dnscrypt_port()
            for _ in range(3):
                rs = _run(["ss", "-ulnp"], capture=True, check=False)
                if f":{port} " in rs.stdout:
                    _ok(f"DNSCrypt-proxy {tag} запущен на {DNSCRYPT_LISTEN_ADDR}:{port}")
                    return True
                time.sleep(1)
            _warn(f"DNSCrypt-proxy активен, но порт {port} не слушает")
            return False
        r2 = _run(["systemctl", "is-failed", "dnscrypt-proxy"], capture=True, check=False)
        if r2.stdout.strip() == "failed":
            _err("DNSCrypt-proxy перешёл в состояние failed")
            return False
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА — основная функция, вызывается и из полного флоу и standalone
# ══════════════════════════════════════════════════════════════════════════════
def install_dnscrypt(force: bool = False) -> bool:
    """
    Устанавливает DNSCrypt-proxy.

    Args:
        force: если True — устанавливает даже если уже запущен (переустановка).

    Returns:
        True при успехе, False при ошибке.

    Используется:
        - из _core.py в полном флоу установки (PARAM_USE_DNSCRYPT уже проверен там)
        - из install_dnscrypt_standalone() при установке из меню
    """
    _info("Установка DNSCrypt-proxy...")

    dc_arch = _get_arch()
    if not dc_arch:
        arch = _run(["uname", "-m"], capture=True, check=False).stdout.strip()
        _warn(f"Неподдерживаемая архитектура: {arch} — пропускаем")
        return False

    if not force and is_dnscrypt_running() and DNSCRYPT_BIN.exists():
        _info("DNSCrypt-proxy уже установлен и запущен")
        return True

    # Получаем последний тег
    dc_tag = _get_latest_tag()
    if not dc_tag:
        _err("Не удалось получить версию DNSCrypt-proxy с GitHub")
        _warn("Проверьте интернет-соединение и попробуйте снова")
        return False

    _info(f"DNSCrypt-proxy: {dc_tag} ({dc_arch})")
    dc_url = (
        f"https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/"
        f"{dc_tag}/dnscrypt-proxy-{dc_arch}-{dc_tag}.tar.gz"
    )

    # Скачиваем и распаковываем
    with tempfile.TemporaryDirectory(prefix="dnscrypt.") as dc_tmp:
        dc_archive = Path(dc_tmp) / "dnscrypt.tar.gz"
        _info("Скачиваю архив...")
        r = _run(
            ["curl", "-fsSL", "--connect-timeout", "30", "--retry", "3",
             dc_url, "-o", str(dc_archive)],
            check=False, quiet=True,
        )
        if r.returncode != 0:
            _err("Не удалось скачать DNSCrypt-proxy")
            return False

        _run(["tar", "-xzf", str(dc_archive), "-C", dc_tmp], check=False, quiet=True)

        bin_found: Optional[Path] = None
        for p in Path(dc_tmp).rglob("dnscrypt-proxy"):
            if p.is_file():
                bin_found = p
                break

        if not bin_found:
            _err("Бинарник dnscrypt-proxy не найден в архиве")
            return False

        shutil.copy2(bin_found, DNSCRYPT_BIN)
        DNSCRYPT_BIN.chmod(0o755)

    _ok(f"Бинарник установлен: {DNSCRYPT_BIN}")

    # Пользователь dnscrypt (отдельный uid для AWG iptables mark-правил)
    _run(
        ["useradd", "-r", "-s", "/usr/sbin/nologin", "-d",
         "/var/lib/dnscrypt-proxy", "-m", "dnscrypt"],
        check=False, quiet=True,
    )

    # Конфиг
    _write_default_config()
    _run(["chown", "-R", "dnscrypt:dnscrypt", str(DNSCRYPT_CONF_DIR)],
         check=False, quiet=True)

    # Systemd-юнит
    _write_service()
    _run(["systemctl", "daemon-reload"],          check=False, quiet=True)
    _run(["systemctl", "enable", "dnscrypt-proxy"], check=False, quiet=True)
    _run(["systemctl", "start",  "dnscrypt-proxy"], check=False, quiet=True)

    _info("Ожидаю запуска сервиса...")
    ok = _wait_for_service(dc_tag)
    if not ok:
        _warn("DNSCrypt-proxy не запустился")
        _warn("Проверьте: journalctl -u dnscrypt-proxy -n 30")
    return ok


# ══════════════════════════════════════════════════════════════════════════════
#  ОПТИМИЗАЦИЯ КОНФИГА
# ══════════════════════════════════════════════════════════════════════════════
def apply_dnscrypt_tuning() -> bool:
    """
    Применяет оптимизированные параметры к существующему конфигу.
    Делает .bak-копию перед изменением. Перезапускает сервис.

    Returns:
        True при успехе, False при ошибке.
    """
    if not DNSCRYPT_BIN.exists():
        _warn("DNSCrypt-proxy не установлен")
        return False

    if not DNSCRYPT_CONF.exists():
        _warn(f"Конфиг не найден: {DNSCRYPT_CONF}")
        return False

    _info("Применяю оптимизированный конфиг DNSCrypt-proxy...")

    bak = DNSCRYPT_CONF.parent / (
        DNSCRYPT_CONF.name + "."
        + datetime.now().strftime("%Y%m%d%H%M%S") + ".bak"
    )
    shutil.copy2(DNSCRYPT_CONF, bak)
    _info(f"Резервная копия: {bak.name}")

    TOP_PARAMS: dict[str, str] = {
        "doh_servers":        "true",
        "force_tcp":          "false",
        "odoh_servers":       "false",
        "timeout":            "2500",
        "netprobe_timeout":   "5",
        "reject_ttl":         "10",
        "fallback_resolvers": "['1.1.1.1:53', '8.8.8.8:53']",
        "cache":              "true",
        "cache_size":         "32768",
        "cache_min_ttl":      "60",
        "use_syslog":         "true",
    }

    lines = DNSCRYPT_CONF.read_text().splitlines(keepends=True)
    result: list[str] = []
    in_section = False
    applied_top: set[str] = set()

    for line in lines:
        stripped = line.strip()
        if re.match(r'^\[', stripped):
            in_section = True
        if not in_section:
            if re.match(r'^log_file\s*=', stripped):
                result.append("## log_file удалён apply_dnscrypt_tuning — используем journald\n")
                continue
            m = re.match(r'^(\w+)\s*=\s*.*$', stripped)
            if m and m.group(1) in TOP_PARAMS:
                key = m.group(1)
                indent = line[: len(line) - len(line.lstrip())]
                line = f"{indent}{key} = {TOP_PARAMS[key]}\n"
                applied_top.add(key)
        result.append(line)

    missing_top = [k for k in TOP_PARAMS if k not in applied_top]
    if missing_top:
        result.append("\n## Добавлено apply_dnscrypt_tuning\n")
        for k in missing_top:
            result.append(f"{k} = {TOP_PARAMS[k]}\n")

    DNSCRYPT_CONF.write_text("".join(result))
    _ok(f"Конфиг обновлён: {DNSCRYPT_CONF}")

    _run(["systemctl", "restart", "dnscrypt-proxy"], check=False, quiet=True)
    time.sleep(2)
    r = _run(["systemctl", "is-active", "dnscrypt-proxy"], capture=True, check=False)
    if r.stdout.strip() == "active":
        _ok("DNSCrypt-proxy перезапущен с оптимизированным конфигом")
        content = DNSCRYPT_CONF.read_text()
        for key in ("doh_servers", "timeout", "cache_size", "cache_min_ttl"):
            m = re.search(rf'^{key}\s*=\s*(.+)$', content, re.MULTILINE)
            val = m.group(1).strip() if m else "?"
            print(f"    {DIM}{key} = {val}{NC}")
        return True
    else:
        _warn("DNSCrypt-proxy не запустился после оптимизации")
        _warn("journalctl -u dnscrypt-proxy -n 20")
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  ПАТЧ XRAY CONFIG.JSON
# ══════════════════════════════════════════════════════════════════════════════
def _patch_xray_config() -> bool:
    """
    Обновляет блок dns в config.json Xray чтобы использовать DNSCrypt.
    Делает .bak-копию. Перезапускает Xray.

    Returns:
        True при успехе, False при ошибке.
    """
    cfg_path: Optional[Path] = None
    for p in XRAY_CONFIG_PATHS:
        if p.exists():
            cfg_path = p
            break

    if not cfg_path:
        _warn("config.json Xray не найден — обновите DNS вручную")
        _warn(f"Ожидаемые пути: {', '.join(str(p) for p in XRAY_CONFIG_PATHS)}")
        return False

    _info(f"Патчу {cfg_path} ...")

    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        _err(f"Не удалось прочитать config.json: {e}")
        return False

    # Резервная копия
    bak = cfg_path.parent / (cfg_path.name + "." + datetime.now().strftime("%Y%m%d%H%M%S") + ".bak")
    shutil.copy2(cfg_path, bak)
    _info(f"Резервная копия: {bak.name}")

    port = get_dnscrypt_port()

    # Новый DNS-блок с DNSCrypt как primary
    new_dns_servers = [
        {
            "address":      DNSCRYPT_LISTEN_ADDR,
            "port":         port,
            "network":      "udp",
            "skipFallback": False,
        },
        {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": True},
        {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": True},
    ]

    if "dns" not in cfg:
        cfg["dns"] = {}

    cfg["dns"]["servers"] = new_dns_servers

    # Сохраняем hosts и остальные поля если были
    cfg["dns"].setdefault("hosts", {
        "dns.google":         "8.8.8.8",
        "dns.cloudflare.com": "1.1.1.1",
        "localhost":          "127.0.0.1",
    })
    cfg["dns"].setdefault("disableCache",           False)
    cfg["dns"].setdefault("disableFallback",        False)
    cfg["dns"].setdefault("disableFallbackIfMatch", True)

    try:
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    except Exception as e:
        _err(f"Не удалось записать config.json: {e}")
        return False

    _ok(f"config.json обновлён — DNS → DNSCrypt {DNSCRYPT_LISTEN_ADDR}:{port}")

    # Перезапускаем Xray
    ans = _ask(
        f"\n  {YELLOW}Перезапустить Xray для применения? [Y/n]: {NC}",
        default="y",
    ).lower()
    if ans != "n":
        _run(["systemctl", "restart", XRAY_SERVICE_NAME], check=False, quiet=True)
        time.sleep(3)
        r = _run(["systemctl", "is-active", XRAY_SERVICE_NAME], capture=True, check=False)
        if r.stdout.strip() == "active":
            _ok("Xray перезапущен — DNSCrypt активен")
        else:
            _warn("Xray не запустился — проверьте: journalctl -u xray -n 20")
            _info("Откат config.json:")
            shutil.copy2(bak, cfg_path)
            _run(["systemctl", "restart", XRAY_SERVICE_NAME], check=False, quiet=True)
            _warn("config.json откатан к резервной копии")
            return False

    return True


# ══════════════════════════════════════════════════════════════════════════════
#  STANDALONE-УСТАНОВКА — вызывается из меню без полного флоу инсталлятора
# ══════════════════════════════════════════════════════════════════════════════
def install_dnscrypt_standalone() -> None:
    """
    Полная standalone-установка DNSCrypt-proxy из меню Сети.
    Не требует запуска полного инсталлятора.
    После установки автоматически патчит /etc/xray/config.json.
    """
    os.system("clear")
    print()
    _box_top("🔒  УСТАНОВКА DNSCrypt-proxy")
    _box_row()
    _box_info("Зашифрованный DNS-резолвер для защиты от слежки провайдера")
    _box_info(f"Слушает на {DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT}")
    _box_row()

    if is_dnscrypt_installed():
        ver = _get_installed_version()
        running = is_dnscrypt_running()
        status = f"{GREEN}запущен{NC}" if running else f"{YELLOW}остановлен{NC}"
        _box_warn(f"DNSCrypt-proxy уже установлен (v{ver}), статус: {status}")
        _box_row()
        _box_item("1", "Переустановить (скачать свежую версию)")
        _box_item("2", "Только обновить конфиг Xray (без переустановки)")
        _box_item("Q", "Отмена")
        _box_bot()
        print()
        ch = _ask(f"{CYAN}Выбор: {NC}").lower()
        if ch == "q" or ch == "":
            return
        if ch == "2":
            _patch_xray_config()
            _pause()
            return
        # ch == "1" → продолжаем с force=True
        ok = install_dnscrypt(force=True)
    else:
        _box_item("Y", f"Установить DNSCrypt-proxy {GREEN}(рекомендуется){NC}")
        _box_item("N", "Отмена")
        _box_bot()
        print()
        ch = _ask(f"{CYAN}Установить? [Y/n]: {NC}", default="y").lower()
        if ch == "n":
            return
        ok = install_dnscrypt(force=False)

    if ok:
        print()
        _box_top("🔒  ОБНОВЛЕНИЕ КОНФИГА XRAY")
        _box_row()
        _box_info("DNSCrypt установлен. Обновляю config.json Xray...")
        _box_row()
        _box_bot()
        print()
        _patch_xray_config()
    else:
        _box_warn("Установка завершилась с ошибкой — config.json Xray не изменён")

    _pause()


# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    print()
    _box_top("🔒  DNSCrypt-proxy — Статус")
    _box_row()

    installed = is_dnscrypt_installed()
    running   = is_dnscrypt_running()
    ver       = _get_installed_version() if installed else ""

    if not installed:
        _box_err("DNSCrypt-proxy не установлен")
    elif running:
        port = get_dnscrypt_port()
        _box_ok(f"Запущен  v{ver}  →  {DNSCRYPT_LISTEN_ADDR}:{port}")
    else:
        _box_warn(f"Установлен v{ver}, но не запущен")

    _box_row()

    # Проверяем config.json Xray
    for p in XRAY_CONFIG_PATHS:
        if p.exists():
            try:
                cfg = json.loads(p.read_text())
                servers = cfg.get("dns", {}).get("servers", [])
                uses_dc = any(
                    isinstance(s, dict) and
                    s.get("address") == DNSCRYPT_LISTEN_ADDR and
                    s.get("port") == get_dnscrypt_port()
                    for s in servers
                )
                if uses_dc:
                    _box_ok(f"Xray config.json использует DNSCrypt")
                else:
                    _box_warn(f"Xray config.json НЕ использует DNSCrypt")
                    _box_info("Пункт [2] → Обновить конфиг Xray")
            except Exception:
                _box_warn("Не удалось прочитать config.json Xray")
            break

    _box_row()

    # Последние строки лога
    r = _run(["journalctl", "-u", "dnscrypt-proxy", "-n", "5", "--no-pager"],
             capture=True, check=False)
    if r.stdout.strip():
        _box_sep()
        _box_row(f"  {DIM}Последние записи журнала:{NC}")
        for line in r.stdout.strip().splitlines()[-5:]:
            _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")

    _box_bot()
    _pause()


# ══════════════════════════════════════════════════════════════════════════════
#  УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _uninstall_dnscrypt() -> None:
    os.system("clear")
    print()
    _box_top(f"  {RED}УДАЛЕНИЕ DNSCrypt-proxy{NC}")
    _box_row()
    _box_warn("Будут удалены: бинарник, конфиг, systemd-юнит")
    _box_warn("config.json Xray будет переключён на 1.1.1.1 / 8.8.8.8")
    _box_row()
    _box_bot()
    print()

    ans = _ask(f"  {RED}Подтвердите удаление [yes/N]: {NC}").lower()
    if ans != "yes":
        _info("Удаление отменено")
        _pause()
        return

    _run(["systemctl", "stop",    "dnscrypt-proxy"], check=False, quiet=True)
    _run(["systemctl", "disable", "dnscrypt-proxy"], check=False, quiet=True)

    DNSCRYPT_BIN.unlink(missing_ok=True)
    DNSCRYPT_SERVICE.unlink(missing_ok=True)
    shutil.rmtree(DNSCRYPT_CONF_DIR, ignore_errors=True)

    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _ok("DNSCrypt-proxy удалён")

    # Откатываем DNS в config.json Xray
    for p in XRAY_CONFIG_PATHS:
        if p.exists():
            try:
                cfg = json.loads(p.read_text())
                bak = p.parent / (p.name + "." + datetime.now().strftime("%Y%m%d%H%M%S") + ".bak")
                shutil.copy2(p, bak)
                cfg.setdefault("dns", {})["servers"] = [
                    {"address": "1.1.1.1", "port": 53, "network": "udp", "skipFallback": False},
                    {"address": "8.8.8.8", "port": 53, "network": "udp", "skipFallback": False},
                ]
                p.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                _ok("config.json Xray переключён на публичные DNS")
                _run(["systemctl", "restart", XRAY_SERVICE_NAME], check=False, quiet=True)
                time.sleep(2)
                r = _run(["systemctl", "is-active", XRAY_SERVICE_NAME], capture=True, check=False)
                if r.stdout.strip() == "active":
                    _ok("Xray перезапущен")
                else:
                    _warn("Xray не запустился — проверьте вручную")
            except Exception as e:
                _warn(f"Не удалось обновить config.json: {e}")
            break

    _pause()


# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ — точка входа из _core.py
# ══════════════════════════════════════════════════════════════════════════════
def dnscrypt_menu() -> None:
    """
    Точка входа из _core.py → меню Сети → пункт 3.
    Ctrl+C внутри подменю → возврат сюда.
    Ctrl+C здесь → пробрасывается в _core.py (KeyboardInterrupt не ловим).
    """
    while True:
        os.system("clear")
        print()

        installed = is_dnscrypt_installed()
        running   = is_dnscrypt_running()
        ver       = _get_installed_version() if installed else ""
        port      = get_dnscrypt_port()

        if not installed:
            svc_str = f"{YELLOW}● не установлен{NC}"
        elif running:
            svc_str = f"{GREEN}● запущен   v{ver}   →  {DNSCRYPT_LISTEN_ADDR}:{port}{NC}"
        else:
            svc_str = f"{RED}● остановлен   v{ver}{NC}"

        # Статус Xray DNS
        xray_uses_dc = False
        for p in XRAY_CONFIG_PATHS:
            if p.exists():
                try:
                    cfg = json.loads(p.read_text())
                    servers = cfg.get("dns", {}).get("servers", [])
                    xray_uses_dc = any(
                        isinstance(s, dict) and
                        s.get("address") == DNSCRYPT_LISTEN_ADDR and
                        s.get("port") == port
                        for s in servers
                    )
                except Exception:
                    pass
                break

        xray_str = (
            f"{GREEN}✓ config.json использует DNSCrypt{NC}"
            if xray_uses_dc
            else f"{YELLOW}⚠ config.json НЕ использует DNSCrypt{NC}"
        )

        _box_top("🔒  DNSCrypt-proxy")
        _box_row()
        _box_kv("Статус:",    svc_str)
        _box_kv("Xray DNS:",  xray_str)
        _box_row()
        _box_sep()

        if not installed:
            _box_item("1", f"🚀  Установить DNSCrypt-proxy {GREEN}(рекомендуется){NC}")
        else:
            _box_item("1", "🚀  Переустановить / обновить")

        _box_item("2", "🔧  Обновить конфиг Xray (переключить DNS на DNSCrypt)")
        _box_item("3", "⚙️   Оптимизировать конфиг DNSCrypt")
        _box_item("4", "🔄  Перезапустить сервис")
        _box_item("5", "📋  Статус / журнал")
        _box_item("6", f"  {RED}🗑️   Удалить DNSCrypt-proxy{NC}")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot()
        print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            try:
                install_dnscrypt_standalone()
            except _Cancelled:
                pass

        elif ch == "2":
            if not installed:
                print()
                _warn("DNSCrypt-proxy не установлен — сначала установите (пункт 1)")
                _pause()
                continue
            print()
            _patch_xray_config()
            _pause()

        elif ch == "3":
            print()
            apply_dnscrypt_tuning()
            _pause()

        elif ch == "4":
            if not installed:
                _warn("DNSCrypt-proxy не установлен")
                _pause()
                continue
            _run(["systemctl", "restart", "dnscrypt-proxy"], check=False, quiet=True)
            time.sleep(2)
            r = _run(["systemctl", "is-active", "dnscrypt-proxy"], capture=True, check=False)
            print()
            if r.stdout.strip() == "active":
                _ok("DNSCrypt-proxy перезапущен")
            else:
                _warn("Не удалось запустить — journalctl -u dnscrypt-proxy -n 20")
            _pause()

        elif ch == "5":
            try:
                _show_status()
            except _Cancelled:
                pass

        elif ch == "6":
            try:
                _uninstall_dnscrypt()
            except _Cancelled:
                pass

        elif ch in ("q", "0", ""):
            break
