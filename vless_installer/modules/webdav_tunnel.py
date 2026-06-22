"""
vless_installer/modules/webdav_tunnel.py
───────────────────────────────────────────────────────────────────────────────
webdav-tunnel — TCP/SOCKS5-туннель поверх WebDAV.

Назначение:
  Трафик сериализуется в бинарные чанки, которые загружаются/скачиваются
  как обычные файлы по протоколу WebDAV (PUT/GET/PROPFIND). Для DPI это
  выглядит как HTTP(S)-сессия с облачным хранилищем (Nextcloud/Box-подобный
  трафик), а не как VPN/проксі-протокол.

Источник: https://github.com/spkprsnts/webdav-tunnel  (Go, MIT)

Схема трафика:
  Клиент (любой ОС)
    │  SOCKS5 127.0.0.1:1080
    ▼
  webdav-tunnel -mode client
    │  yamux-стрим поверх "общего" WebDAV-пайпа
    ▼
  WebDAV (HTTP/1.1 PUT/GET файлов-чанков)
    │
    ▼  ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
    │  Режим SELFHOSTED                    │  Режим EXTERNAL
    │  webdav-tunnel -mode selfhosted       │  webdav-tunnel -mode server
    │  встроенный WebDAV-сервер на VPS      │  опрашивает внешнее облако
    │  (без сторонних аккаунтов)            │  (Nextcloud/Box/...)
    ▼                                       ▼
  Интернет                               Интернет

Два режима установки (выбираются в меню):
  • selfhosted — сервер сам поднимает встроенный WebDAV на этой VPS.
    Не требует сторонних аккаунтов, самый простой и предсказуемый вариант.
    TLS — опционально: если есть домен с уже выпущенным сертификатом
    (cert.pem/key.pem), путь к ним можно указать при установке.
    ВНИМАНИЕ: без указания cert/key сервис слушает обычный HTTP — это
    осознанный компромисс для MVP, см. секцию "Гайд" в меню.
  • external — сервер этой VPS подключается как клиент к стороннему
    WebDAV-хранилищу (Nextcloud/Box и т.п.) и через него релеит трафик.
    Нужны URL хранилища, логин и пароль (желательно app-password).

Что модуль делает:
  • Собирает webdav-tunnel из исходников (Go) — тот же подход, что в
    wdtt.py/olcrtc.py: при необходимости качает официальный тулчейн
    с go.dev, затем `go build -o webdav-tunnel .`
  • Создаёт systemd-сервис webdav-tunnel.service
  • В режиме selfhosted открывает TCP-порт (UFW, если активен, иначе
    iptables) — режим external не слушает входящих соединений
  • Генерирует клиентский webdav://...#name URI (формат — как у
    апстрима) и команду запуска клиента
  • Показывает статус/журнал, позволяет переустановить/удалить

Что модуль НЕ делает (осознанно, чтобы не плодить параллельную логику):
  • Не реализует мультипользовательскую модель — apстрим поддерживает
    один login/password на инстанс; для нескольких пользователей делитесь
    одной ссылкой (как с mTLS-логином в mieru.py) или ставьте второй
    инстанс на другом порту вручную
  • Не трогает config.json Xray, state.json инсталлера, iptables-правила
    и systemd-юниты других модулей
  • Не собирает Android/desktop-клиент — клиент собирается из того же
    репозитория отдельно (`go build .` или `gomobile bind` для AAR),
    модуль лишь печатает готовый -uri для запуска клиента

Точка входа из _core.py:
    from vless_installer.modules.webdav_tunnel import do_webdav_tunnel_menu
    do_webdav_tunnel_menu()

Интеграция в _core.py:
  1. Импорт (рядом с остальными туннельными модулями):
       from vless_installer.modules.webdav_tunnel import do_webdav_tunnel_menu
  2. Пункт меню (14):
       _box_row(f"  {CYAN}14{NC} ☁️  {TITLE}WebDAV Tunnel{NC}")
       _box_row(f"     {DIM}TCP/SOCKS5 поверх WebDAV-файлов — маскировка под облачное хранилище{NC}")
  3. Обработчик:
       elif choice == "14":
           try:
               do_webdav_tunnel_menu()
           except ImportError as _e:
               warn(f"Модуль WebDAV Tunnel не найден: {_e}")
               time.sleep(2)
     И не забыть поднять диапазон в подсказке выбора: "Выбор (1–14 / 0):"
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
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
_BIN_PATH      = Path("/usr/local/bin/webdav-tunnel")
_CFG_DIR       = Path("/etc/webdav-tunnel")
_STORAGE_DIR   = _CFG_DIR / "data"
_SERVICE_FILE  = Path("/etc/systemd/system/webdav-tunnel.service")
_SERVICE_NAME  = "webdav-tunnel"
_MODULE_STATE  = Path("/var/lib/xray-installer/webdav_tunnel.json")

_GITHUB_REPO  = "spkprsnts/webdav-tunnel"
_SOURCE_URL   = f"https://github.com/{_GITHUB_REPO}/archive/refs/heads/main.tar.gz"

_DEFAULT_PORT = 8443

# Явный тюнинг selfhosted-режима — задаётся одними и теми же значениями
# и в ExecStart, и в клиентском URI, чтобы они гарантированно совпадали
# (не полагаемся на дефолты бинарника, которые могут отличаться от
# версии к версии).
_SH_TUNING = {
    "poll-min": "50ms", "poll-max": "200ms", "coalesce": "5ms",
    "puts": "16", "read-max": "16", "read-min": "3", "chunk-size": "131071",
}

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

def _box_link(link: str, color: str = "") -> None:
    """Длинная ссылка внутри рамки, разбитая на строки по '&' без обрезания."""
    if not color:
        color = YELLOW
    max_w = _BOX_W - 4

    tokens, buf = [], ""
    for ch in link:
        buf += ch
        if ch == "&":
            tokens.append(buf)
            buf = ""
    if buf:
        tokens.append(buf)

    lines, cur = [], ""
    for tok in tokens:
        if cur and _wlen(cur) + _wlen(tok) > max_w:
            lines.append(cur)
            cur = tok
        else:
            cur += tok
        while _wlen(cur) > max_w:
            acc, cut = 0, 0
            for ch in cur:
                import unicodedata as _ud
                acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
                if acc > max_w:
                    break
                cut += 1
            lines.append(cur[:cut])
            cur = cur[cut:]
    if cur:
        lines.append(cur)

    for line in lines:
        _box_row(f"  {color}{line}{NC}")

def _save_link_file(link: str, filename: str) -> Path:
    try:
        _CFG_DIR.mkdir(parents=True, exist_ok=True)
        path = _CFG_DIR / filename
        path.write_text(link + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except Exception:
            pass
        return path
    except Exception:
        return _CFG_DIR / filename

def _print_link_file_path(path: Path) -> None:
    print(f"  {DIM}📄 Полная ссылка сохранена в файл: {NC}{CYAN}{path}{NC}")
    print(f"  {DIM}   (cat {path}  — чтобы скопировать целиком){NC}")

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

def _gen_password(length: int = 20) -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    return ''.join(secrets.choice(chars) for _ in range(length))

def _gen_login() -> str:
    return "user" + ''.join(secrets.choice("23456789") for _ in range(4))

def _get_server_ip() -> str:
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "YOUR_SERVER_IP"

# ══════════════════════════════════════════════════════════════════════════════
#  СОСТОЯНИЕ
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
        print(f"  {YELLOW}⚠{NC}  Не удалось сохранить webdav_tunnel.json: {e}")

def _is_installed() -> bool:
    return _BIN_PATH.exists() and _SERVICE_FILE.exists()

# ══════════════════════════════════════════════════════════════════════════════
#  GO ТУЛЧЕЙН (тот же подход, что в wdtt.py/olcrtc.py)
# ══════════════════════════════════════════════════════════════════════════════
def _check_go() -> Optional[str]:
    go = "/usr/local/bin/go" if Path("/usr/local/bin/go").exists() else shutil.which("go")
    if go:
        r = _run([go, "version"], capture=True)
        if r.returncode == 0:
            return go
    return None

def _go_arch() -> str:
    r = _run(["uname", "-m"], capture=True)
    m = (r.stdout or "").strip() if r.returncode == 0 else ""
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, "amd64")

def _ver_tuple(s: str) -> tuple:
    parts = re.findall(r"\d+", s)[:3]
    parts += ["0"] * (3 - len(parts))
    return tuple(int(p) for p in parts)

def _go_installed_version(go: str) -> Optional[tuple]:
    r = _run([go, "version"], capture=True)
    if r.returncode != 0:
        return None
    m = re.search(r"go(\d+\.\d+(?:\.\d+)?)", r.stdout or "")
    return _ver_tuple(m.group(1)) if m else None

def _go_required_version(gomod: Path) -> str:
    if gomod.exists():
        try:
            m = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)", gomod.read_text(), re.M)
            if m:
                return m.group(1)
        except Exception:
            pass
    return "1.22.0"

def _http_download(url: str, dest: Path, timeout: int = 180) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp, dest.open("wb") as f:
            shutil.copyfileobj(resp, f)
        return dest.exists() and dest.stat().st_size > 0
    except Exception:
        return False

def _install_go_toolchain(required: str) -> Optional[str]:
    """Качает официальный архив Go с go.dev в /usr/local/go — apt-версия
    в большинстве дистрибутивов старее, чем требует современный go.mod."""
    arch = _go_arch()
    try:
        with urllib.request.urlopen("https://go.dev/VERSION?m=text", timeout=15) as resp:
            version = resp.read().decode("utf-8", errors="replace").splitlines()[0].strip()
        if not version.startswith("go"):
            version = f"go{required}"
    except Exception:
        version = f"go{required}"

    url = f"https://go.dev/dl/{version}.linux-{arch}.tar.gz"
    tarball = Path(f"/tmp/{version}.linux-{arch}.tar.gz")
    print(f"  {CYAN}→{NC}  Скачиваю {version} ({arch})...")
    if not _http_download(url, tarball):
        print(f"  {RED}✗{NC}  Не удалось скачать {url}")
        return None

    go_dir = Path("/usr/local/go")
    if go_dir.exists():
        _run(["rm", "-rf", str(go_dir)])
    r = _run(["tar", "-C", "/usr/local", "-xzf", str(tarball)])
    tarball.unlink(missing_ok=True)
    if r.returncode != 0:
        print(f"  {RED}✗{NC}  Не удалось распаковать архив Go.")
        return None

    for exe in ("go", "gofmt"):
        src = go_dir / "bin" / exe
        dst = Path("/usr/local/bin") / exe
        if src.exists():
            try:
                if dst.exists() or dst.is_symlink():
                    dst.unlink()
                dst.symlink_to(src)
            except Exception:
                pass

    return _check_go()

def _ensure_go(required: str) -> Optional[str]:
    go = _check_go()
    if go and _go_installed_version(go) and _go_installed_version(go) >= _ver_tuple(required):
        return go
    print(f"  {CYAN}→{NC}  Нужен Go {required}+"
          f"{' (текущий старее)' if go else ' (не найден)'}, устанавливаю...")
    return _install_go_toolchain(required)

# ══════════════════════════════════════════════════════════════════════════════
#  СБОРКА БИНАРНИКА
# ══════════════════════════════════════════════════════════════════════════════
def _build_webdav_tunnel() -> bool:
    """Скачивает исходники webdav-tunnel и собирает бинарник в
    /usr/local/bin/webdav-tunnel (go build -o webdav-tunnel . — как
    описано в README апстрима, единый бинарник для всех -mode)."""
    tmp = Path(tempfile.mkdtemp())
    try:
        archive = tmp / "main.tar.gz"
        print(f"  {CYAN}→{NC}  Скачиваю исходники webdav-tunnel...")
        urllib.request.urlretrieve(_SOURCE_URL, str(archive))

        print(f"  {CYAN}→{NC}  Распаковываю...")
        _run(["tar", "-xzf", str(archive), "-C", str(tmp)], check=True)

        src_dirs = list(tmp.glob("webdav-tunnel-*"))
        if not src_dirs:
            print(f"  {RED}✗{NC}  Не найдена директория с исходниками.")
            return False
        src_dir = src_dirs[0]

        required = _go_required_version(src_dir / "go.mod")
        go = _ensure_go(required)
        if not go:
            print(f"  {RED}✗{NC}  Не удалось установить подходящий Go ({required}+).")
            return False

        print(f"  {CYAN}→{NC}  Компилирую webdav-tunnel (это займёт ~1-2 минуты)...")
        env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
        r = _run(
            [go, "build", "-o", str(tmp / "webdav-tunnel"), "-ldflags", "-s -w", "."],
            capture=True, env=env, cwd=str(src_dir),
        )
        if r.returncode != 0:
            # go.sum может не покрывать все зависимости в офлайн-среде — добираем.
            print(f"  {DIM}Доразрешаю зависимости (go mod tidy)...{NC}")
            offline_env = {**env, "GOSUMDB": "off"}
            _run([go, "mod", "tidy"], capture=True, env=offline_env, cwd=str(src_dir))
            r = _run(
                [go, "build", "-o", str(tmp / "webdav-tunnel"), "-ldflags", "-s -w", "."],
                capture=True, env=env, cwd=str(src_dir),
            )
        if r.returncode != 0:
            print(f"  {RED}✗{NC}  Ошибка компиляции:")
            print(f"  {DIM}{(r.stderr or r.stdout or '')[:500]}{NC}")
            return False

        built = tmp / "webdav-tunnel"
        if not built.exists():
            print(f"  {RED}✗{NC}  Бинарник не создан после компиляции.")
            return False

        shutil.copy2(str(built), str(_BIN_PATH))
        _BIN_PATH.chmod(0o755)
        print(f"  {GREEN}✓{NC}  webdav-tunnel установлен: {_BIN_PATH}")
        return True

    except Exception as e:
        print(f"  {RED}✗{NC}  Ошибка: {e}")
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES / UFW  (только режим selfhosted — у external нет входящего порта)
# ══════════════════════════════════════════════════════════════════════════════
def _ipt_tcp_rule_exists(port: int) -> bool:
    r = _run(["iptables", "-t", "filter", "-C", "INPUT",
              "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"], capture=True)
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

def _ufw_is_active() -> bool:
    if not shutil.which("ufw"):
        return False
    r = _run(["ufw", "status"], capture=True)
    return "status: active" in r.stdout.lower()

def _open_port(port: int) -> str:
    if _ufw_is_active():
        _run(["ufw", "allow", f"{port}/tcp", "comment", "webdav-tunnel"], capture=True)
        return f"UFW: TCP {port} открыт."
    _ipt_open_tcp(port)
    _ipt_persist()
    return f"iptables: TCP {port} открыт."

def _close_port(port: int) -> None:
    if _ufw_is_active():
        _run(["ufw", "delete", "allow", f"{port}/tcp"], capture=True)
    else:
        _ipt_close_tcp(port)
        _ipt_persist()

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD
# ══════════════════════════════════════════════════════════════════════════════
def _install_service(mode: str, port: int, login: str, password: str,
                      webdav_url: str = "", tls_cert: str = "", tls_key: str = "",
                      proxy: str = "") -> None:
    if mode == "selfhosted":
        parts = [
            str(_BIN_PATH), "-mode", "selfhosted",
            "-webdav-listen", f":{port}",
            "-webdav-storage", str(_STORAGE_DIR),
            "-login", login, "-password", password,
            "-poll-min", _SH_TUNING["poll-min"], "-poll-max", _SH_TUNING["poll-max"],
            "-coalesce", _SH_TUNING["coalesce"], "-puts", _SH_TUNING["puts"],
            "-read-max", _SH_TUNING["read-max"], "-read-min", _SH_TUNING["read-min"],
            "-chunk-size", _SH_TUNING["chunk-size"],
        ]
        if tls_cert and tls_key:
            parts += ["-webdav-tls-cert", tls_cert, "-webdav-tls-key", tls_key]
    else:  # external
        parts = [
            str(_BIN_PATH), "-mode", "server",
            "-webdav", webdav_url, "-login", login, "-password", password,
        ]
    if proxy:
        parts += ["-proxy", proxy]

    exec_start = " ".join(shlex.quote(p) for p in parts)
    cap_line = "AmbientCapabilities=CAP_NET_BIND_SERVICE\n" if (mode == "selfhosted" and port < 1024) else ""

    _SERVICE_FILE.write_text(
        "[Unit]\n"
        "Description=webdav-tunnel — TCP tunnel over WebDAV\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={exec_start}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        f"{cap_line}"
        "NoNewPrivileges=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", _SERVICE_NAME])

# ══════════════════════════════════════════════════════════════════════════════
#  КЛИЕНТСКАЯ ССЫЛКА
# ══════════════════════════════════════════════════════════════════════════════
def _build_client_uri(state: dict) -> str:
    mode  = state.get("mode", "selfhosted")
    login = state.get("login", "")
    password = state.get("password", "")

    if mode == "selfhosted":
        host = _get_server_ip()
        port = state.get("port", _DEFAULT_PORT)
        scheme = "webdavs" if state.get("tls") else "webdav"
        query = "&".join(f"{k}={v}" for k, v in _SH_TUNING.items())
        name = f"webdav-tunnel-{host}"
        return f"{scheme}://{login}:{password}@{host}:{port}?{query}#{name}"

    webdav_url = state.get("webdav_url", "")
    parsed = urllib.parse.urlparse(webdav_url)
    scheme = "webdavs" if parsed.scheme == "https" else "webdav"
    host = parsed.hostname or "host"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    name = f"webdav-tunnel-{host}"
    return f"{scheme}://{login}:{password}@{host}:{port}#{name}"

def _client_run_cmd(uri: str) -> str:
    return f'webdav-tunnel -mode client -uri "{uri}" -socks-listen 127.0.0.1:1080'

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
    _box_top("☁️  УСТАНОВКА  •  webdav-tunnel")
    _box_row()

    if _is_installed():
        _box_warn("webdav-tunnel уже установлен.")
        _box_row()
        _box_item("1", "Переустановить (сохранить логин/пароль/режим)")
        _box_item("2", f"Переустановить полностью  {YELLOW}(новые креды, выбор режима){NC}")
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

    state = _load_state()
    keep = _is_installed()  # после "2" уже False, после "1" — True

    os.system("clear")
    _box_top("☁️  РЕЖИМ  •  webdav-tunnel")
    _box_row()
    _box_info("selfhosted — сервер сам поднимает встроенный WebDAV.")
    _box_info("   Не нужен сторонний аккаунт, проще и предсказуемее.")
    _box_row()
    _box_info("external — туннель через стороннее облако (Nextcloud/Box).")
    _box_info("   Нужны URL/логин/пароль уже существующего WebDAV-хранилища.")
    _box_row()
    _box_item("1", "selfhosted  (рекомендуется)")
    _box_item("2", "external")
    _box_item("Q", "← Отмена")
    _box_bot(); print()

    try:
        mch = _ask(f"{CYAN}Выбор [1/2]: {NC}",
                    default="1" if not keep else state.get("mode", "selfhosted")[0].replace("s", "1").replace("e", "2"),
                    c=True).strip()
    except _Cancelled:
        raise
    mode = "external" if mch == "2" else "selfhosted"

    webdav_url = state.get("webdav_url", "")
    port       = state.get("port", _DEFAULT_PORT)
    tls_cert   = state.get("tls_cert", "")
    tls_key    = state.get("tls_key", "")
    login      = state.get("login", "") if keep else ""
    password   = state.get("password", "") if keep else ""

    os.system("clear")
    _box_top("☁️  НАСТРОЙКА  •  webdav-tunnel")
    _box_row()

    try:
        if mode == "selfhosted":
            raw = _ask(f"  {CYAN}TCP порт [{port}]: {NC}", default=str(port), c=True)
            port = int(raw) if raw.isdigit() else port

            _box_info("TLS опционален — нужен домен с уже выпущенным сертификатом.")
            _box_info("Пустой ввод = без TLS (обычный HTTP, см. гайд про риски).")
            tls_cert = _ask(f"  {CYAN}Путь к cert.pem [{tls_cert or 'пропустить'}]: {NC}",
                             default=tls_cert, c=True)
            tls_key = ""
            if tls_cert:
                tls_key = _ask(f"  {CYAN}Путь к key.pem: {NC}", default=tls_key, c=True)
                if not tls_key or not Path(tls_cert).exists() or not Path(tls_key).exists():
                    print(f"  {RED}✗{NC}  Файлы сертификата не найдены — продолжаю без TLS.")
                    tls_cert = tls_key = ""
        else:
            webdav_url = _ask(f"  {CYAN}WebDAV URL [{webdav_url or 'https://dav.example.com'}]: {NC}",
                               default=webdav_url, c=True)
            if not webdav_url:
                print(f"  {RED}✗{NC}  WebDAV URL обязателен."); _pause(); return

        login = _ask(f"  {CYAN}Логин [{login or 'авто'}]: {NC}", default=login, c=True) or _gen_login()
        password = _ask(f"  {CYAN}Пароль [{password or 'авто'}]: {NC}", default=password, c=True) or _gen_password()

        proxy = _ask(f"  {CYAN}Upstream SOCKS5 proxy (если сервер сам за proxy) [пропустить]: {NC}",
                      default="", c=True)
    except _Cancelled:
        raise

    if mode == "selfhosted" and not (1024 <= port <= 65535):
        print(f"  {RED}✗{NC}  Порт должен быть в диапазоне 1024–65535."); _pause(); return

    # ── Установка ─────────────────────────────────────────────────────────
    os.system("clear")
    _box_top("☁️  УСТАНОВКА  •  webdav-tunnel")
    _box_row()
    _box_info("Сборка webdav-tunnel из исходников...")
    _box_bot(); print()

    if not _build_webdav_tunnel():
        print()
        _box_top("☁️  УСТАНОВКА  •  webdav-tunnel")
        _box_err("Не удалось собрать webdav-tunnel.")
        _box_err("Убедитесь что доступен Go и интернет (github.com, go.dev).")
        _box_bot(); _pause(); return

    print()
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    _STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"  {GREEN}✓{NC}  Конфиг создан: {_CFG_DIR}")

    if mode == "selfhosted":
        port_desc = _open_port(port)
        print(f"  {GREEN}✓{NC}  {port_desc}")

    _install_service(mode, port, login, password, webdav_url, tls_cert, tls_key, proxy)
    print(f"  {GREEN}✓{NC}  Systemd-сервис создан.")

    _run(["systemctl", "start", _SERVICE_NAME])
    time.sleep(2)
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    if r.stdout.strip() == "active":
        print(f"  {GREEN}✓{NC}  webdav-tunnel запущен.")
    else:
        print(f"  {YELLOW}⚠{NC}  Сервис не запустился — проверьте логи (пункт статуса).")

    _save_state({
        "installed": True, "mode": mode, "port": port,
        "login": login, "password": password,
        "webdav_url": webdav_url, "tls": bool(tls_cert and tls_key),
        "tls_cert": tls_cert, "tls_key": tls_key, "proxy": proxy,
    })

    # ── Итог ──────────────────────────────────────────────────────────────
    state = _load_state()
    uri = _build_client_uri(state)
    print()
    _box_top("✅  УСТАНОВКА ЗАВЕРШЕНА  •  webdav-tunnel")
    _box_row()
    _box_ok(f"Режим: {mode}")
    if mode == "selfhosted":
        _box_kv("TCP порт:", f"{YELLOW}{port}{NC}")
        if not state.get("tls"):
            _box_warn("TLS не настроен — соединение НЕ шифровано на транспорте.")
    else:
        _box_kv("WebDAV:", webdav_url)
    _box_kv("Логин:",  login)
    _box_kv("Пароль:", f"{YELLOW}{password}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Клиентская ссылка:{NC}")
    _box_row()
    _box_link(uri)
    _box_row()
    _box_row(f"  {BOLD}{WHITE}Запуск клиента:{NC}")
    _box_row(f"  {DIM}{_client_run_cmd(uri)}{NC}")
    _box_row()
    _box_warn("Клиент собирается отдельно из того же репозитория (go build .).")
    _box_bot()
    link_path = _save_link_file(uri, "client_uri.txt")
    _print_link_file_path(link_path)
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    state = _load_state()
    _box_top("📊  СТАТУС  •  webdav-tunnel")
    _box_row()

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    _box_kv("Сервис:", f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")
    _box_kv("Бинарник:", f"{GREEN}✓{NC}" if _BIN_PATH.exists() else f"{RED}✗ не найден{NC}")
    _box_kv("Режим:", state.get("mode", "—"))
    if state.get("mode") == "selfhosted":
        _box_kv("Порт:", str(state.get("port", "—")))
        _box_kv("TLS:", f"{GREEN}да{NC}" if state.get("tls") else f"{YELLOW}нет{NC}")
    else:
        _box_kv("WebDAV:", state.get("webdav_url", "—"))
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

def _show_link() -> None:
    os.system("clear")
    state = _load_state()
    uri = _build_client_uri(state)
    _box_top("🔗  КЛИЕНТСКАЯ ССЫЛКА  •  webdav-tunnel")
    _box_row()
    _box_link(uri)
    _box_row()
    _box_row(f"  {BOLD}{WHITE}Запуск клиента:{NC}")
    _box_row(f"  {DIM}{_client_run_cmd(uri)}{NC}")
    _box_bot()
    link_path = _save_link_file(uri, "client_uri.txt")
    _print_link_file_path(link_path)
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛНОЕ УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        os.system("clear")
        _box_top("🗑️  УДАЛЕНИЕ  •  webdav-tunnel")
        _box_row()
        _box_warn("Будет удалено:")
        _box_row(f"  {DIM}  • Сервис systemd  ({_SERVICE_NAME}){NC}")
        _box_row(f"  {DIM}  • Бинарник        ({_BIN_PATH}){NC}")
        _box_row(f"  {DIM}  • Конфиги/данные  ({_CFG_DIR}){NC}")
        _box_row(f"  {DIM}  • Открытый TCP-порт (если режим selfhosted){NC}")
        _box_row(f"  {DIM}  • /var/lib/xray-installer/webdav_tunnel.json{NC}")
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

    _run(["systemctl", "stop", _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    if _SERVICE_FILE.exists():
        _SERVICE_FILE.unlink()
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"], capture=True)

    if _BIN_PATH.exists():
        _BIN_PATH.unlink()

    if _CFG_DIR.exists():
        shutil.rmtree(_CFG_DIR, ignore_errors=True)

    if state.get("mode") == "selfhosted" and state.get("port"):
        _close_port(int(state["port"]))

    try:
        if _MODULE_STATE.exists():
            _MODULE_STATE.unlink()
    except Exception:
        pass

    if not silent:
        print(f"  {GREEN}✓{NC}  webdav-tunnel удалён.")
        _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ГАЙД
# ══════════════════════════════════════════════════════════════════════════════
def _show_guide() -> None:
    while True:
        os.system("clear")
        _box_top("📖  ГАЙД  •  webdav-tunnel")
        _box_row()
        _box_item("1", "Как собрать и запустить клиент")
        _box_item("2", "selfhosted vs external — что выбрать")
        _box_item("3", "Про TLS / самоподписанный сертификат")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            os.system("clear")
            _box_top("📱  КЛИЕНТ")
            _box_row()
            _box_info("Клиент не входит в этот инсталлер — собирается из апстрима:")
            _box_row(f"  {DIM}git clone https://github.com/{_GITHUB_REPO}{NC}")
            _box_row(f"  {DIM}cd webdav-tunnel && go build -o webdav-tunnel .{NC}")
            _box_row()
            _box_info("Дальше — команда запуска из пункта меню «Показать ссылку».")
            _box_info("Браузер/приложение настраиваете на SOCKS5 127.0.0.1:1080.")
            _box_bot(); _pause()
        elif ch == "2":
            os.system("clear")
            _box_top("☁️  SELFHOSTED vs EXTERNAL")
            _box_row()
            _box_info("selfhosted: эта VPS сама — WebDAV-хранилище. Проще, нет")
            _box_info("зависимости от стороннего облака и его лимитов/политик.")
            _box_row()
            _box_info("external: трафик идёт через реальный Nextcloud/Box/etc.")
            _box_info("Полезно если хотите спрятать сам факт наличия VPS-сервиса")
            _box_info("за легитимным облачным провайдером, но добавляет лишний")
            _box_info("прыжок и зависимость от лимитов провайдера.")
            _box_bot(); _pause()
        elif ch == "3":
            os.system("clear")
            _box_top("🔒  TLS")
            _box_row()
            _box_warn("Без cert/key сервис в режиме selfhosted слушает HTTP.")
            _box_info("Для реалистичной маскировки под облачное хранилище")
            _box_info("нужен настоящий сертификат на реальном домене (например")
            _box_info("через certbot) — самоподписанный сертификат не проверялся")
            _box_info("на совместимость с TLS-клиентом апстрима, риск отказа")
            _box_info("соединения. Если домен есть — укажите пути к cert.pem/")
            _box_info("key.pem при установке.")
            _box_bot(); _pause()
        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def do_webdav_tunnel_menu() -> None:
    """Точка входа из _core.py. Ctrl+C → возврат в главное меню VLESS."""
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

        _box_top("☁️  webdav-tunnel  •  TCP/SOCKS5 поверх WebDAV")
        _box_row()
        _box_kv("Статус:", svc_str)

        if installed:
            _box_kv("Режим:", state.get("mode", "—"))
            if state.get("mode") == "selfhosted":
                _box_kv("Порт:", str(state.get("port", "—")))

        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🚀  Установить")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "🔗  Показать клиентскую ссылку")
            _box_item("3", "🔄  Перезапустить сервис")
            _box_item("4", "📊  Статус / логи")
            _box_sep()
            _box_item("8", f"{RED}🗑️   Удалить webdav-tunnel{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд")
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
            _show_link()

        elif ch == "3" and installed:
            os.system("clear")
            print(f"  {CYAN}→{NC}  Перезапуск...")
            _run(["systemctl", "restart", _SERVICE_NAME])
            time.sleep(2)
            r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
            if r.stdout.strip() == "active":
                print(f"  {GREEN}✓{NC}  Сервис активен.")
            else:
                print(f"  {RED}✗{NC}  Сервис не запустился, смотрите логи.")
            _pause()

        elif ch == "4" and installed:
            _show_status()

        elif ch == "8" and installed:
            _full_uninstall()

        elif ch == "g":
            _show_guide()

        elif ch in ("q", ""):
            break
