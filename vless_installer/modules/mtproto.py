"""
vless_installer/modules/mtproto.py
───────────────────────────────────────────────────────────────────────────────
Модуль Telemt MTProxy — Telegram MTProto-прокси на Rust/Tokio.
Интегрируется в VLESS Ultimate Installer v4.11.

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
def _get_public_ip() -> tuple:
    ipv4, ipv6 = "", ""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ipv4 = r.read().decode().strip()
            break
        except Exception:
            pass
    try:
        with urllib.request.urlopen("https://api6.ipify.org", timeout=5) as r:
            ipv6 = r.read().decode().strip()
    except Exception:
        pass
    return ipv4, ipv6

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

def _write_config(port, ipv4, ipv6, tls_domain, users, use_middle_proxy) -> None:
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
    lines += [
        "[timeouts]", "client_handshake = 60", "tg_connect = 10",
        "client_keepalive = 60", "client_ack = 300",
        "", "[censorship]", f'tls_domain = "{tls_domain}"',
        "mask = true", "mask_port = 443", "fake_cert_len = 2048",
        "", "[access]", "replay_check_len = 65536", "ignore_time_skew = false",
        "", "[access.users]",
    ]
    for n, s in users.items(): lines.append(f'{n} = "{s}"')
    lines += ["", "[[upstreams]]", 'type = "direct"', "enabled = true", "weight = 10"]
    if not use_middle_proxy:
        lines += ["", "[dc_overrides]", '"203" = "91.105.192.100:443"']
    CONFIG_FILE.write_text("\n".join(lines) + "\n")
    CONFIG_FILE.chmod(0o640)

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
        if ch == "0" or ch == "": return
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
    use_mp     = _is_direct_ip(server_ip)

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
    _write_config(port, ipv4, ipv6, tls_domain, users, use_mp)
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

    # ── Финальный отчёт ───────────────────────────────────────────────────────
    _banner(); _box_top("✅ УСТАНОВКА ЗАВЕРШЕНА"); _box_row()
    _box_ok(f"Версия:  telemt {tag}")
    _box_ok(f"Порт:    {port}")
    _box_ok(f"Домен:   {tls_domain}")
    _box_ok(f"IPv4:    {server_ip or '—'}")
    if server_ipv6: _box_ok(f"IPv6:    {server_ipv6}")
    _box_ok(f"Middle:  {'да' if use_mp else 'нет (NAT)'}")
    _box_ok(f"Учёт:    {'активен (iptables)' if ipt_ok else 'journalctl'}")
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
#  ГЛАВНОЕ МЕНЮ MTProxy  ←  точка входа из _core.py
# ══════════════════════════════════════════════════════════════════════════════
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
        _box_row(); _box_kv("Статус:", svc_str); _box_row(); _box_sep()
        _box_item("1", "🚀  Установить / переустановить")
        _box_item("2", "👥  Управление пользователями")
        _box_item("3", "🔗  Показать ссылки")
        _box_item("4", "🔄  Перезапустить сервис")
        _box_item("5", "⬆️   Проверить и обновить")
        _box_item("6", "📊  Статистика трафика")
        _box_item("7", "📋  Статус / логи")
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
