"""
vless_installer/modules/naiveproxy.py
───────────────────────────────────────────────────────────────────────────────
NaiveProxy — HTTPS forward proxy с Chromium fingerprint и probe resistance.

Как это работает:
  Клиент использует Chromium HTTP/2 fingerprint для подключения к серверу.
  DPI видит обычный HTTPS/HTTP2 трафик. Неопознанные клиенты (сканеры,
  зонды РКН) получают ответ от фейкового сайта — probe resistance.

Схема трафика (одна нода):
  Клиент (Karing / NekoBox / ShadowRocket)
    │  HTTPS/HTTP2 с Chromium fingerprint
    ▼
  caddy-naive :443  (probe resistance → фейковый сайт для незнакомых)
    │
    ▼
  Интернет

Схема трафика (каскад Entry→Exit):
  Клиент
    │  HTTPS/HTTP2
    ▼
  caddy-naive Entry (RU) :443
    │  upstream → https://user:pass@exit-host:443
    ▼
  caddy-naive Exit (EU) :443
    │
    ▼
  Интернет

Требования:
  • Домен с A-записью на IP VPS (нужен для TLS-ALPN-01)
  • Порт 443/tcp открыт
  • amd64 — caddy-forwardproxy-naive только amd64

Клиентские приложения:
  • Karing   — iOS / Android / Windows / macOS / Linux
  • NekoBox  — Android
  • ShadowRocket — iOS
  • naiveproxy CLI — все платформы
  Ссылка: naive+https://user:pass@domain:443

Что модуль делает:
  • Скачивает caddy-forwardproxy-naive (prebuilt amd64)
  • Генерирует Caddyfile с probe resistance и basicauth
  • Создаёт фейковый сайт (заглушка для зондов)
  • Создаёт systemd-сервис caddy-naive
  • Открывает порт 443/tcp в iptables
  • Управление пользователями: добавление, список, удаление
  • Каскад: настройка upstream для Entry→Exit схемы
  • Генерация naive+https:// ссылок и QR-кодов

Что модуль НЕ трогает:
  • Xray config.json и VLESS-inbound
  • state.json инсталлера
  • iptables-правила других модулей
  • Любые другие службы (в т.ч. nginx если уже установлен на 443)

Точка входа из _core.py:
    from vless_installer.modules.naiveproxy import do_naiveproxy_menu
    do_naiveproxy_menu()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import hashlib
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
_BIN_PATH        = Path("/usr/local/bin/caddy-naive")
_CFG_DIR         = Path("/etc/caddy-naive")
_CADDYFILE       = Path("/etc/caddy-naive/Caddyfile")
_PROBE_SECRET    = Path("/etc/caddy-naive/probe_secret")
_FAKE_SITE_DIR   = Path("/var/www/naive-fake")
_LOG_DIR         = Path("/var/log/caddy-naive")
_SERVICE_FILE    = Path("/etc/systemd/system/caddy-naive.service")
_SERVICE_NAME    = "caddy-naive"
_MODULE_STATE    = Path("/var/lib/xray-installer/naiveproxy.json")

# GitHub: caddy-forwardproxy-naive — только amd64
_GITHUB_API      = "https://api.github.com/repos/klzgrad/naiveproxy/releases/latest"
_BIN_URL_AMD64   = (
    "https://github.com/klzgrad/naiveproxy/releases/latest/download/"
    "naiveproxy-linux-amd64.tar.xz"
)
# Caddy с forwardproxy плагином (альтернатива)
_CADDY_NAIVE_URL = (
    "https://github.com/Michaol/caddy-naive/releases/latest/download/"
    "caddy-linux-amd64"
)

_DEFAULT_PORT    = 443
_DEFAULT_FAKE    = "https://www.bing.com"
_BOX_W           = 66

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
        ch = chars[i]; cp = ord(ch)
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
    color = color or YELLOW
    max_w = _BOX_W - 2
    plain_link = _plain(link)
    i = 0
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

def _gen_probe_secret() -> str:
    return secrets.token_urlsafe(24)

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
        print(f"  {YELLOW}⚠{NC}  Не удалось сохранить naiveproxy.json: {e}")

def _is_installed() -> bool:
    return _BIN_PATH.exists() and _SERVICE_FILE.exists() and _CADDYFILE.exists()

def _load_users() -> list:
    state = _load_state()
    return state.get("users", [])

def _save_users(users: list) -> None:
    state = _load_state()
    state["users"] = users
    _save_state(state)

# ══════════════════════════════════════════════════════════════════════════════
#  БИНАРНИК
# ══════════════════════════════════════════════════════════════════════════════
def _is_amd64() -> bool:
    return platform.machine().lower() in ("x86_64", "amd64")

def _get_latest_version() -> str:
    try:
        req = urllib.request.Request(
            _GITHUB_API, headers={"User-Agent": "VLESS-Ultimate-Installer"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("tag_name", "unknown").lstrip("v")
    except Exception: return "unknown"

def _download_binary() -> bool:
    if not _is_amd64():
        print(f"  {RED}✗{NC}  caddy-forwardproxy-naive только amd64. "
              f"Текущая: {platform.machine()}")
        return False

    print(f"  {CYAN}→{NC}  Скачиваю caddy-forwardproxy-naive...")
    tmp = Path(tempfile.mktemp(suffix=".bin"))
    try:
        urllib.request.urlretrieve(_CADDY_NAIVE_URL, str(tmp))
        with tmp.open("rb") as f:
            if f.read(4) != b'\x7fELF':
                print(f"  {RED}✗{NC}  Скачанный файл не ELF-бинарник.")
                return False
        shutil.copy2(str(tmp), str(_BIN_PATH))
        _BIN_PATH.chmod(0o755)
        print(f"  {GREEN}✓{NC}  caddy-naive установлен: {_BIN_PATH}")
        return True
    except Exception as e:
        print(f"  {RED}✗{NC}  Ошибка загрузки: {e}")
        return False
    finally:
        tmp.unlink(missing_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
#  CADDYFILE
# ══════════════════════════════════════════════════════════════════════════════
def _build_caddyfile(domain: str, port: int, users: list,
                     fake_url: str, probe_secret: str,
                     upstream: str = "") -> str:
    """
    Генерирует Caddyfile для caddy-forwardproxy-naive.
    upstream — опциональный, для каскада Entry→Exit.
    """
    # basicauth блок
    auth_lines = ""
    for u in users:
        # caddy-naive принимает bcrypt хеш или plaintext с {sha1}prefix
        # Используем формат: username <bcrypt_hash>
        # Для простоты храним plaintext и хэшируем через caddy hash-password
        auth_lines += f"            basic_auth {u['username']} {u['password_hash']}\n"

    upstream_line = ""
    if upstream:
        upstream_line = f"        upstream {upstream}\n"

    caddyfile = f"""{{\n    http_port 0\n}}\n\n{domain}:{port} {{\n    tls {{
        on_demand
    }}
    route {{
        forward_proxy {{
{auth_lines}            hide_ip
            hide_via
            probe_resistance {probe_secret}
{upstream_line}        }}
        file_server {{
            root {_FAKE_SITE_DIR}
        }}
    }}
    log {{
        output file {_LOG_DIR}/access.log {{
            roll_size 10mb
            roll_keep 3
        }}
    }}
}}
"""
    return caddyfile

def _reload_caddy() -> bool:
    """Перезагружает конфиг без перезапуска сервиса."""
    r = _run(
        [str(_BIN_PATH), "reload",
         "--config", str(_CADDYFILE), "--adapter", "caddyfile"],
        capture=True,
    )
    return r.returncode == 0

def _validate_caddy() -> Optional[str]:
    r = _run(
        [str(_BIN_PATH), "validate",
         "--config", str(_CADDYFILE), "--adapter", "caddyfile"],
        capture=True,
    )
    if r.returncode != 0:
        return (r.stderr or r.stdout or "")[:300]
    return None

def _hash_password(password: str) -> str:
    """
    Генерирует bcrypt хеш через caddy hash-password.
    Fallback — SHA256 если caddy недоступен.
    """
    if _BIN_PATH.exists():
        r = _run(
            [str(_BIN_PATH), "hash-password", "--plaintext", password],
            capture=True,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    # fallback
    return "{sha256}" + hashlib.sha256(password.encode()).hexdigest()

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES
# ══════════════════════════════════════════════════════════════════════════════
def _ipt_tcp_rule_exists(port: int) -> bool:
    r = _run(
        ["iptables", "-t", "filter", "-C", "INPUT",
         "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
        capture=True,
    )
    return r.returncode == 0

def _ipt_open_tcp(port: int) -> None:
    if not _ipt_tcp_rule_exists(port):
        _run(["iptables", "-t", "filter", "-I", "INPUT", "1",
              "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])

def _ipt_close_tcp(port: int) -> None:
    for _ in range(5):
        if not _ipt_tcp_rule_exists(port): break
        _run(["iptables", "-t", "filter", "-D", "INPUT",
              "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])

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
        "Description=NaiveProxy (caddy-forwardproxy-naive)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=notify\n"
        f"ExecStart={_BIN_PATH} run "
        f"--config {_CADDYFILE} --adapter caddyfile\n"
        "ExecReload=/bin/kill -USR1 $MAINPID\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "LimitNOFILE=1048576\n"
        f"ReadWritePaths={_CFG_DIR} {_LOG_DIR} {_FAKE_SITE_DIR}\n"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
        "NoNewPrivileges=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", _SERVICE_NAME])

# ══════════════════════════════════════════════════════════════════════════════
#  ФЕЙКОВЫЙ САЙТ
# ══════════════════════════════════════════════════════════════════════════════
def _create_fake_site() -> None:
    _FAKE_SITE_DIR.mkdir(parents=True, exist_ok=True)
    (_FAKE_SITE_DIR / "index.html").write_text(
        "<!DOCTYPE html><html><head><title>Welcome</title></head>"
        "<body><h1>Welcome</h1><p>This site is under maintenance.</p></body></html>\n"
    )

# ══════════════════════════════════════════════════════════════════════════════
#  ПРИМЕНЕНИЕ КОНФИГА
# ══════════════════════════════════════════════════════════════════════════════
def _apply_config(domain: str, port: int, users: list,
                  fake_url: str, probe_secret: str, upstream: str = "") -> Optional[str]:
    """Записывает Caddyfile и перезагружает сервис. Возвращает ошибку или None."""
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    _LOG_DIR.mkdir(parents=True, exist_ok=True)

    caddyfile_content = _build_caddyfile(
        domain, port, users, fake_url, probe_secret, upstream
    )
    _CADDYFILE.write_text(caddyfile_content)
    _CADDYFILE.chmod(0o640)

    err = _validate_caddy()
    if err:
        return f"Caddyfile не прошёл валидацию: {err}"

    # Перезапускаем или reload
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    if r.stdout.strip() == "active":
        if not _reload_caddy():
            _run(["systemctl", "restart", _SERVICE_NAME])
    else:
        _run(["systemctl", "start", _SERVICE_NAME])
    return None

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install() -> None:
    try: _run_install_inner()
    except _Cancelled:
        print(f"\n  {YELLOW}Установка прервана.{NC}\n"); _pause()

def _run_install_inner() -> None:
    os.system("clear")
    _box_top("🔐  УСТАНОВКА  •  NAIVEPROXY")
    _box_row()

    if not _is_amd64():
        _box_err(f"Только amd64. Текущая: {platform.machine()}")
        _box_bot(); _pause(); return

    if _is_installed():
        _box_warn("NaiveProxy уже установлен.")
        _box_row()
        _box_item("1", "Переустановить (сохранить пользователей)")
        _box_item("2", f"Переустановить полностью  {YELLOW}(новые ключи){NC}")
        _box_item("Q", "← Отмена")
        _box_bot(); print()
        try:
            ch = _ask(f"{CYAN}Выбор [1/2/Q]: {NC}", c=True).strip().lower()
        except _Cancelled: return
        if ch == "q" or not ch: return
        if ch == "2": _full_uninstall(silent=True)

    # ── Ввод параметров ───────────────────────────────────────────────────────
    state = _load_state()
    old_domain    = state.get("domain", "")
    old_port      = state.get("port", _DEFAULT_PORT)
    old_fake      = state.get("fake_url", _DEFAULT_FAKE)
    old_upstream  = state.get("upstream", "")

    os.system("clear")
    _box_top("🔐  НАСТРОЙКА  •  NAIVEPROXY")
    _box_row()
    _box_info("NaiveProxy требует домен с A-записью на IP этого VPS.")
    _box_info("Caddy автоматически получит TLS сертификат (порт 443).")
    _box_row()
    _box_warn("Если на порту 443 уже работает nginx — остановите его сначала.")
    _box_bot(); print()

    try:
        domain = _ask(
            f"  {CYAN}Домен (например vpn.example.com) [{old_domain or 'обязательно'}]: {NC}",
            default=old_domain, c=True,
        ).strip()
        if not domain:
            print(f"  {RED}✗{NC}  Домен обязателен."); _pause(); return

        raw = _ask(
            f"  {CYAN}Порт [{old_port}]: {NC}",
            default=str(old_port), c=True,
        )
        port = int(raw) if raw.isdigit() else old_port

        fake_url = _ask(
            f"  {CYAN}URL фейкового сайта [{old_fake}]: {NC}",
            default=old_fake, c=True,
        ).strip() or old_fake

        upstream = _ask(
            f"  {CYAN}Upstream (каскад Entry→Exit, Enter=пропустить): {NC}",
            default=old_upstream, c=True,
        ).strip()
    except _Cancelled: raise

    # ── Установка ─────────────────────────────────────────────────────────────
    os.system("clear")
    _box_top("🔐  УСТАНОВКА  •  NAIVEPROXY")
    _box_row()

    # 1. Бинарник
    _box_info("Скачиваю caddy-forwardproxy-naive...")
    _box_bot(); print()
    if not _download_binary():
        _box_top("🔐  УСТАНОВКА  •  NAIVEPROXY")
        _box_err("Не удалось скачать бинарник.")
        _box_bot(); _pause(); return
    print()

    # 2. Probe secret
    probe_secret = state.get("probe_secret") or _gen_probe_secret()

    # 3. Пользователи — создаём первого если нет
    users = state.get("users") or []
    if not users:
        first_user = "admin"
        first_pass = _gen_password()
        first_hash = _hash_password(first_pass)
        users = [{"username": first_user, "password": first_pass,
                  "password_hash": first_hash}]
        print(f"  {GREEN}✓{NC}  Создан первый пользователь: {YELLOW}{first_user}{NC} / {YELLOW}{first_pass}{NC}")

    # 4. Фейковый сайт
    _create_fake_site()
    print(f"  {GREEN}✓{NC}  Фейковый сайт создан: {_FAKE_SITE_DIR}")

    # 5. Caddyfile + сервис
    _install_service()
    err = _apply_config(domain, port, users, fake_url, probe_secret, upstream)
    if err:
        print(f"  {RED}✗{NC}  {err}")
        _pause(); return

    # 6. iptables
    _ipt_open_tcp(port)
    _ipt_persist()
    print(f"  {GREEN}✓{NC}  iptables: TCP {port} открыт.")

    # 7. Сохраняем состояние
    _save_state({
        "installed":    True,
        "domain":       domain,
        "port":         port,
        "fake_url":     fake_url,
        "probe_secret": probe_secret,
        "upstream":     upstream,
        "users":        users,
    })

    # ── Итог ──────────────────────────────────────────────────────────────────
    time.sleep(2)
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"

    os.system("clear")
    _box_top("✅  УСТАНОВКА ЗАВЕРШЕНА  •  NAIVEPROXY")
    _box_row()
    _box_ok("caddy-naive установлен и запущен." if svc_ok else
            "Установлен, но сервис не запустился — проверьте логи.")
    _box_row()
    _box_kv("Домен:",   f"{YELLOW}{domain}:{port}{NC}")
    _box_kv("Probe:",   f"{DIM}{probe_secret[:16]}...{NC}")
    if upstream:
        _box_kv("Upstream:", f"{DIM}{upstream}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Первый пользователь — ссылка для клиента:{NC}")
    _box_row()
    naive_link = f"naive+https://{users[0]['username']}:{users[0]['password']}@{domain}:{port}"
    _box_link(naive_link)
    _box_row()
    _box_sep()
    _box_info("Клиенты: Karing, NekoBox (Android), ShadowRocket (iOS)")
    _box_info("Добавьте пользователей через пункт [2].")
    _box_bot()
    print()
    _print_qr(naive_link, "naive+https:// для клиента")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# ══════════════════════════════════════════════════════════════════════════════
def _users_menu() -> None:
    while True:
        os.system("clear")
        state = _load_state()
        users = state.get("users", [])
        domain = state.get("domain", "—")
        port   = state.get("port", _DEFAULT_PORT)

        _box_top("👥  ПОЛЬЗОВАТЕЛИ  •  NAIVEPROXY")
        _box_row()
        _box_kv("Пользователей:", str(len(users)))
        _box_kv("Домен:", f"{domain}:{port}")
        _box_row(); _box_sep()

        if users:
            _box_row(f"  {BOLD}{CYAN}{'№':<4}{'Логин':<20}{'Ссылка (начало)'}{NC}")
            _box_sep()
            for i, u in enumerate(users, 1):
                login = u.get("username", "?")
                link_start = f"naive+https://{login}:****@{domain}:{port}"
                _box_row(f"  {DIM}{i:<4}{NC}{CYAN}{login:<20}{NC}{DIM}{link_start[:30]}...{NC}")
        else:
            _box_warn("Пользователей нет.")

        _box_row(); _box_sep()
        _box_item("1", "➕  Добавить пользователя")
        _box_item("2", "🔗  Показать ссылку + QR для пользователя")
        _box_item("3", f"{RED}🗑️   Удалить пользователя{NC}")
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
            try: _show_user_link(users, domain, port)
            except _Cancelled: pass
        elif ch == "3":
            try: _delete_user(users, state)
            except _Cancelled: pass
        elif ch in ("q", ""): break

def _add_user(state: dict) -> None:
    os.system("clear")
    _box_top("➕  ДОБАВИТЬ ПОЛЬЗОВАТЕЛЯ  •  NAIVEPROXY")
    _box_row()
    _box_bot(); print()

    try:
        username = _ask(f"  {CYAN}Логин: {NC}", c=True).strip()
        if not username:
            print(f"  {RED}✗{NC}  Логин не может быть пустым."); _pause(); return

        users = state.get("users", [])
        if any(u["username"] == username for u in users):
            print(f"  {YELLOW}⚠{NC}  Пользователь уже существует."); _pause(); return

        raw_pass = _ask(
            f"  {CYAN}Пароль (Enter=авто): {NC}",
            default="", c=True,
        ).strip()
        password = raw_pass or _gen_password()
    except _Cancelled: raise

    print(f"  {CYAN}→{NC}  Хэширую пароль...")
    password_hash = _hash_password(password)

    users.append({
        "username": username,
        "password": password,
        "password_hash": password_hash,
    })
    state["users"] = users
    _save_state(state)

    # Применяем новый конфиг
    err = _apply_config(
        state["domain"], state["port"], users,
        state.get("fake_url", _DEFAULT_FAKE),
        state.get("probe_secret", ""),
        state.get("upstream", ""),
    )

    domain = state.get("domain", "—")
    port   = state.get("port", _DEFAULT_PORT)
    naive_link = f"naive+https://{username}:{password}@{domain}:{port}"

    os.system("clear")
    _box_top("✅  ПОЛЬЗОВАТЕЛЬ ДОБАВЛЕН")
    _box_row()
    _box_kv("Логин:", f"{YELLOW}{username}{NC}")
    _box_kv("Пароль:", f"{YELLOW}{password}{NC}")
    if err: _box_warn(f"Ошибка применения конфига: {err}")
    else: _box_ok("Конфиг применён.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}naive+https:// ссылка:{NC}")
    _box_row()
    _box_link(naive_link)
    _box_row()
    _box_bot()
    print()
    _print_qr(naive_link, f"naive+https:// для {username}")
    _pause()

def _show_user_link(users: list, domain: str, port: int) -> None:
    if not users:
        print(f"  {YELLOW}⚠{NC}  Пользователей нет."); _pause(); return

    os.system("clear")
    _box_top("🔗  ССЫЛКА ДЛЯ ПОЛЬЗОВАТЕЛЯ  •  NAIVEPROXY")
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

    naive_link = f"naive+https://{user['username']}:{user['password']}@{domain}:{port}"
    os.system("clear")
    _box_top(f"🔗  {user['username']}  •  NAIVEPROXY")
    _box_row()
    _box_kv("Логин:", f"{YELLOW}{user['username']}{NC}")
    _box_kv("Пароль:", f"{YELLOW}{user['password']}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}naive+https:// ссылка:{NC}")
    _box_row()
    _box_link(naive_link)
    _box_row()
    _box_bot()
    print()
    _print_qr(naive_link, f"naive+https:// для {user['username']}")
    _pause()

def _delete_user(users: list, state: dict) -> None:
    if not users:
        print(f"  {YELLOW}⚠{NC}  Пользователей нет."); _pause(); return
    if len(users) == 1:
        print(f"  {RED}✗{NC}  Нельзя удалить последнего пользователя."); _pause(); return

    os.system("clear")
    _box_top("🗑️  УДАЛИТЬ ПОЛЬЗОВАТЕЛЯ")
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

    _apply_config(
        state["domain"], state["port"], users,
        state.get("fake_url", _DEFAULT_FAKE),
        state.get("probe_secret", ""),
        state.get("upstream", ""),
    )
    print(f"  {GREEN}✓{NC}  Пользователь удалён, конфиг применён.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  КАСКАД (Entry → Exit)
# ══════════════════════════════════════════════════════════════════════════════
def _cascade_menu() -> None:
    """Настройка upstream для Entry→Exit каскада."""
    os.system("clear")
    state = _load_state()
    current = state.get("upstream", "")

    _box_top("🔗  КАСКАД ENTRY→EXIT  •  NAIVEPROXY")
    _box_row()
    _box_info("Каскад: клиент → Entry (RU) → Exit (EU) → интернет")
    _box_info("Провайдер видит только Entry-ноду.")
    _box_row()
    if current:
        _box_kv("Текущий upstream:", f"{YELLOW}{current}{NC}")
        _box_row()
        _box_item("1", "Изменить upstream")
        _box_item("2", f"{RED}Отключить каскад{NC}")
        _box_item("Q", "← Отмена")
    else:
        _box_info("Каскад не настроен.")
        _box_row()
        _box_info("Формат: https://user:pass@exit-host:443")
        _box_item("1", "Включить каскад")
        _box_item("Q", "← Отмена")
    _box_bot(); print()

    try:
        ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
    except _Cancelled: return

    if ch == "1":
        try:
            new_upstream = _ask(
                f"  {CYAN}Upstream URL: {NC}",
                default=current, c=True,
            ).strip()
        except _Cancelled: return
        if not new_upstream:
            print(f"  {RED}✗{NC}  URL не может быть пустым."); _pause(); return

        state["upstream"] = new_upstream
        _save_state(state)
        err = _apply_config(
            state["domain"], state["port"], state.get("users", []),
            state.get("fake_url", _DEFAULT_FAKE),
            state.get("probe_secret", ""),
            new_upstream,
        )
        if err: print(f"  {RED}✗{NC}  {err}")
        else: print(f"  {GREEN}✓{NC}  Каскад включён. upstream: {new_upstream}")
        _pause()

    elif ch == "2" and current:
        state["upstream"] = ""
        _save_state(state)
        _apply_config(
            state["domain"], state["port"], state.get("users", []),
            state.get("fake_url", _DEFAULT_FAKE),
            state.get("probe_secret", ""),
            "",
        )
        print(f"  {GREEN}✓{NC}  Каскад отключён.")
        _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    state = _load_state()
    _box_top("📊  СТАТУС  •  NAIVEPROXY")
    _box_row()

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    _box_kv("Сервис:",
            f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")
    _box_kv("Домен:", f"{state.get('domain','—')}:{state.get('port','—')}")
    _box_kv("Пользователей:", str(len(state.get("users", []))))
    upstream = state.get("upstream", "")
    _box_kv("Каскад:",
            f"{GREEN}✓ {upstream[:30]}{NC}" if upstream else f"{DIM}отключён{NC}")
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
        _box_top("📖  ГАЙД  •  NAIVEPROXY")
        _box_row()
        _box_item("1", "Как работает NaiveProxy")
        _box_item("2", "Требования и настройка DNS")
        _box_item("3", "Клиентские приложения")
        _box_item("4", "Каскад Entry→Exit — зачем и как")
        _box_item("5", "Probe resistance — что это")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":   _guide_how()
        elif ch == "2": _guide_dns()
        elif ch == "3": _guide_clients()
        elif ch == "4": _guide_cascade()
        elif ch == "5": _guide_probe()
        elif ch in ("q", ""): break

def _guide_how() -> None:
    os.system("clear")
    _box_top("⚙️  КАК РАБОТАЕТ NAIVEPROXY")
    _box_row()
    _box_info("NaiveProxy маскирует трафик под обычный HTTPS/HTTP2.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Принцип:")
    _box_row()
    _box_info("Клиент использует Chromium HTTP/2 fingerprint")
    _box_info("Сервер — Caddy с плагином forwardproxy")
    _box_info("DPI видит легитимный HTTPS трафик к вашему домену")
    _box_info("Неизвестные клиенты (зонды РКН) видят фейковый сайт")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Схема:")
    _box_row()
    _box_row(f"  {CYAN}Клиент → HTTPS/H2 → caddy-naive:443 → Интернет{NC}")
    _box_row()
    _box_sep()
    _box_warn("Требует домен — без домена TLS сертификат не получить.")
    _box_warn("Не работает для мобильных белых списков — нужен IP в списке.")
    _box_bot(); _pause()

def _guide_dns() -> None:
    os.system("clear")
    _box_top("🌐  DNS И ТРЕБОВАНИЯ  •  NAIVEPROXY")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Что нужно:")
    _box_row()
    _box_info("1. Домен (купить на reg.ru, nic.ru, namecheap и т.п.)")
    _box_info("2. A-запись домена → IP вашего VPS")
    _box_info("   Например: vpn.example.com → 1.2.3.4")
    _box_info("3. Порт 443/tcp открыт на VPS")
    _box_info("4. Порт 80/tcp НЕ нужен — Caddy использует TLS-ALPN-01")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Проверка DNS перед установкой:")
    _box_row()
    _box_row(f"  {DIM}dig A vpn.example.com{NC}")
    _box_row(f"  {DIM}# Должен вернуть IP вашего VPS{NC}")
    _box_row()
    _box_sep()
    _box_warn("Если на 443 уже работает nginx/xray — остановите перед установкой.")
    _box_bot(); _pause()

def _guide_clients() -> None:
    os.system("clear")
    state = _load_state()
    domain = state.get("domain", "ваш-домен.com")
    port   = state.get("port", 443)

    _box_top("📱  КЛИЕНТСКИЕ ПРИЛОЖЕНИЯ  •  NAIVEPROXY")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Формат ссылки:")
    _box_row()
    _box_row(f"  {YELLOW}naive+https://логин:пароль@{domain}:{port}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Клиенты:")
    _box_row()
    _box_kv("  Karing",        "iOS / Android / Windows / macOS / Linux", 16)
    _box_kv("  NekoBox",       "Android", 16)
    _box_kv("  ShadowRocket",  "iOS", 16)
    _box_kv("  naiveproxy",    "CLI — все платформы", 16)
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Импорт в Karing:")
    _box_row()
    _box_info("1. Откройте меню → + → вставьте naive+https:// ссылку")
    _box_info("2. Или отсканируйте QR из пункта [2] → [2] меню")
    _box_bot(); _pause()

def _guide_cascade() -> None:
    os.system("clear")
    _box_top("🔗  КАСКАД ENTRY→EXIT  •  NAIVEPROXY")
    _box_row()
    _box_info("Двухузловая схема — идеально для вашей архитектуры.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Схема:")
    _box_row()
    _box_row(f"  {CYAN}Клиент → Entry (RU) → Exit (EU) → Интернет{NC}")
    _box_row()
    _box_info("Провайдер видит только соединение с Entry-нодой")
    _box_info("Entry форвардит трафик на Exit через upstream")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Настройка:")
    _box_row()
    _box_info("1. Установите NaiveProxy на Exit-ноде (EU), создайте пользователя")
    _box_info("2. На Entry-ноде (RU) → пункт [4] → Каскад")
    _box_info("3. Укажите: https://user:pass@exit-host:443")
    _box_row()
    _box_sep()
    _box_warn("Клиент подключается к Entry как обычно — никаких изменений.")
    _box_warn("Entry и Exit должны использовать разные домены.")
    _box_bot(); _pause()

def _guide_probe() -> None:
    os.system("clear")
    _box_top("🛡️  PROBE RESISTANCE  •  NAIVEPROXY")
    _box_row()
    _box_info("Защита от активного зондирования.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Как работает:")
    _box_row()
    _box_info("Обычный HTTPS сервер → ошибка proxy при неверном запросе")
    _box_info("Зонд РКН: посылает запрос без basicauth → видит ОШИБКУ")
    _box_info("Это сигнал — здесь прокси, блокируем.")
    _box_row()
    _box_info("caddy-naive с probe_resistance:")
    _box_info("Неизвестный клиент → видит обычный сайт (фейковый)")
    _box_info("Зонд не может определить что здесь прокси")
    _box_row()
    _box_sep()
    _box_warn("probe_secret — секретный токен. Не раскрывайте его.")
    _box_bot(); _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        os.system("clear")
        _box_top("🗑️  УДАЛЕНИЕ  •  NAIVEPROXY")
        _box_row()
        _box_warn("Будет удалено:")
        _box_row(f"  {DIM}  • Сервис systemd  (caddy-naive){NC}")
        _box_row(f"  {DIM}  • Бинарник        ({_BIN_PATH}){NC}")
        _box_row(f"  {DIM}  • Конфиги          ({_CFG_DIR}){NC}")
        _box_row(f"  {DIM}  • Фейковый сайт   ({_FAKE_SITE_DIR}){NC}")
        _box_row(f"  {DIM}  • Логи             ({_LOG_DIR}){NC}")
        _box_row(f"  {DIM}  • iptables TCP 443{NC}")
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
    port = state.get("port", _DEFAULT_PORT)

    _run(["systemctl", "stop",    _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    if _SERVICE_FILE.exists(): _SERVICE_FILE.unlink()
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"], capture=True)

    if _BIN_PATH.exists(): _BIN_PATH.unlink()
    for d in (_CFG_DIR, _FAKE_SITE_DIR, _LOG_DIR):
        if d.exists(): shutil.rmtree(d, ignore_errors=True)

    _ipt_close_tcp(port)
    _ipt_persist()

    try:
        if _MODULE_STATE.exists(): _MODULE_STATE.unlink()
    except Exception: pass

    if not silent:
        print(f"  {GREEN}✓{NC}  NaiveProxy полностью удалён.")
        _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def do_naiveproxy_menu() -> None:
    """Точка входа из _core.py."""
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

        _box_top("NAIVEPROXY  •  HTTPS / Chromium fingerprint")
        _box_row()
        _box_kv("Статус:", svc_str)

        if installed:
            _box_kv("Домен:",
                    f"{YELLOW}{state.get('domain','—')}:{state.get('port','—')}{NC}")
            _box_kv("Пользователей:", str(len(state.get("users", []))))
            upstream = state.get("upstream", "")
            _box_kv("Каскад:",
                    f"{GREEN}✓ включён{NC}" if upstream else f"{DIM}отключён{NC}")

        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🚀  Установить NaiveProxy")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "👥  Управление пользователями")
            _box_item("3", "🔄  Перезапустить сервис")
            _box_item("4", "🔗  Каскад Entry→Exit")
            _box_item("5", "📊  Статус / логи")
            _box_sep()
            _box_item("9", f"{RED}🗑️   Удалить NaiveProxy{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: как работает, DNS, клиенты, каскад")
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
            try: _cascade_menu()
            except _Cancelled: pass
        elif ch == "5" and installed:
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
        do_naiveproxy_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)
