"""
vless_installer/modules/olcrtc.py
───────────────────────────────────────────────────────────────────────────────
olcRTC — туннель TCP-over-WebRTC, маскирующий трафик под обычный видеозвонок
в разрешённых "белым списком" сервисах (Jitsi / Яндекс.Телемост / WB Stream).
Источник: https://github.com/openlibrecommunity/olcrtc (Beta, нет готовых
бинарников — только сборка из исходников, Go 1.26+).

ВАЖНО — архитектурное отличие от VLESS/Mieru/NaiveProxy в этом проекте:
  olcRTC не умеет "один сервер — много пользователей одним портом". Каждый
  клиент ("линк") — это отдельный процесс olcrtc в режиме srv, который
  реально участвует в WebRTC-сессии (для vp8channel/videochannel — кодирует
  видео) и проксирует трафик именно этого одного клиента. Поэтому 10 линков
  — это 10 отдельных systemd-сервисов, потребляющих свой CPU/трафик.
  Это явно показывается в статусе и расписано в гайде модуля.

  Клиенту тоже нужен сам бинарник olcrtc (или альтернативный community-клиент
  olcbox, alpha) — обычная vless://-ссылка или QR здесь не работает, в
  актуальной версии olcrtc нет даже единого URI-формата: настройки передаются
  одним YAML-файлом. Поэтому вместо ссылки/QR модуль отдаёт готовый YAML
  клиента текстом для копирования + пошаговый гайд.

Структура на диске:
  /opt/olcrtc-src/                       — исходники (git clone, для пересборки)
  /usr/local/bin/olcrtc                  — собранный бинарник
  /etc/olcrtc/links/<name>.yaml          — серверный конфиг каждого линка
  /etc/olcrtc/links/<name>.client.yaml   — клиентский конфиг (для cat/nano,
                                            копия того, что выводится в меню)
  /var/lib/olcrtc/<name>/data/           — runtime-данные каждого линка (поле `data`)
  /etc/systemd/system/olcrtc@.service    — systemd template-юнит
  /var/lib/xray-installer/olcrtc.json    — состояние модуля (линки, версия сборки)

Точка входа из _core.py (по аналогии с do_mieru_menu/do_naiveproxy_menu):
    from vless_installer.modules.olcrtc import do_olcrtc_menu
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
import time
import urllib.request
from datetime import datetime
from pathlib import Path

# ── Цвета (идентично остальным модулям проекта) ───────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
            DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED    = _C['RED']
GREEN  = _C['GREEN']
YELLOW = _C['YELLOW']
CYAN   = _C['CYAN']
BLUE   = _C['BLUE']
BOLD   = _C['BOLD']
DIM    = _C['DIM']
WHITE  = _C['WHITE']
NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\033\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO",    msg)
def _success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN",    msg)
def _error(msg: str)   -> None: print(f"{RED}[ERROR]{NC} {msg}");   _log("ERROR",   msg)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False, timeout: int | None = None,
         env: dict | None = None, cwd: str | None = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if timeout:
        kw["timeout"] = timeout
    if env:
        kw["env"] = env
    if cwd:
        kw["cwd"] = cwd
    try:
        return subprocess.run(cmd, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="timeout")
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=str(e))

from vless_installer.modules.box_renderer import (
    _box_top, _box_bottom, _box_sep, _box_row, _box_item, _box_back,
)

# =============================================================================
#  КОНСТАНТЫ
# =============================================================================
OLC_REPO        = "https://github.com/openlibrecommunity/olcrtc.git"
OLC_SRC_DIR     = Path("/opt/olcrtc-src")
OLC_BIN         = Path("/usr/local/bin/olcrtc")
OLC_GO_DIR      = Path("/usr/local/go")
OLC_ETC_DIR     = Path("/etc/olcrtc")
OLC_LINKS_DIR   = OLC_ETC_DIR / "links"
OLC_VAR_DIR     = Path("/var/lib/olcrtc")
OLC_STATE_FILE  = Path("/var/lib/xray-installer/olcrtc.json")
OLC_UNIT_FILE   = Path("/etc/systemd/system/olcrtc@.service")

JITSI_HOSTS = ["meet.handyweb.org", "meet.small-dm.ru", "meet1.arbitr.ru"]

CARRIERS = {
    "1": ("jitsi",     "Jitsi",     "комната придумывается на лету — полная автоматизация"),
    "2": ("telemost",  "Телемост",  "комнату нужно создать вручную на telemost.yandex.ru"),
    "3": ("wbstream",  "WB Stream", "комнату нужно создать вручную на stream.wb.ru"),
}
TRANSPORTS = {
    "1": ("datachannel",  "максимум скорости, минимум маскировки под видео"),
    "2": ("vp8channel",   "маскировка под видео VP8, средняя скорость"),
    "3": ("seichannel",   "маскировка под видео H264/SEI, ниже скорость"),
    "4": ("videochannel", "полноценные видео-кадры (QR), самый медленный, лучшая маскировка"),
}

ROOM_CREATE_URL = {
    "telemost": "https://telemost.yandex.ru/",
    "wbstream":  "https://stream.wb.ru/",
}

_UNIT_CONTENT = (
    "[Unit]\n"
    "Description=olcrtc link %i (WebRTC-туннель)\n"
    "After=network-online.target\n"
    "Wants=network-online.target\n"
    "\n"
    "[Service]\n"
    "Type=simple\n"
    "ExecStart=/usr/local/bin/olcrtc /etc/olcrtc/links/%i.yaml\n"
    "WorkingDirectory=/var/lib/olcrtc/%i\n"
    "Restart=on-failure\n"
    "RestartSec=5\n"
    "User=root\n"
    "NoNewPrivileges=true\n"
    "\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n"
)


# =============================================================================
#  СОСТОЯНИЕ
# =============================================================================
def _load_state() -> dict:
    if OLC_STATE_FILE.exists():
        try:
            st = json.loads(OLC_STATE_FILE.read_text())
            st.setdefault("links", {})
            return st
        except Exception:
            pass
    return {"installed": False, "commit": "", "built_at": "", "links": {}}


def _save_state(st: dict) -> None:
    OLC_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        OLC_STATE_FILE.write_text(json.dumps(st, ensure_ascii=False, indent=2))
    except Exception as e:
        _warn(f"Не удалось сохранить состояние модуля: {e}")


# =============================================================================
#  GO TOOLCHAIN
# =============================================================================
def _go_arch() -> str:
    r = _run(["uname", "-m"], capture=True, check=False)
    m = r.stdout.strip() if r.returncode == 0 else ""
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, "amd64")


def _ver_tuple(s: str) -> tuple:
    parts = re.findall(r"\d+", s)[:3]
    parts += ["0"] * (3 - len(parts))
    return tuple(int(p) for p in parts)


def _go_installed_version() -> tuple | None:
    gobin = shutil.which("go") or (str(OLC_GO_DIR / "bin" / "go") if (OLC_GO_DIR / "bin" / "go").exists() else None)
    if not gobin:
        return None
    r = _run([gobin, "version"], capture=True, check=False, timeout=10)
    if r.returncode != 0:
        return None
    m = re.search(r"go(\d+\.\d+(?:\.\d+)?)", r.stdout)
    return _ver_tuple(m.group(1)) if m else None


def _go_required_version() -> str:
    gomod = OLC_SRC_DIR / "go.mod"
    if gomod.exists():
        try:
            m = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)", gomod.read_text(), re.M)
            if m:
                return m.group(1)
        except Exception:
            pass
    return "1.26.0"


def _go_ok(required: str) -> bool:
    cur = _go_installed_version()
    return cur is not None and cur >= _ver_tuple(required)


def _http_get_text(url: str, timeout: int = 15) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return None


def _http_download(url: str, dest: Path, timeout: int = 180) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp, dest.open("wb") as f:
            shutil.copyfileobj(resp, f)
        return dest.exists() and dest.stat().st_size > 0
    except Exception:
        return False


def _install_go(required: str) -> bool:
    """Скачивает официальный архив Go с go.dev и кладёт в /usr/local/go."""
    arch = _go_arch()
    version = _http_get_text("https://go.dev/VERSION?m=text")
    if not version or not version.startswith("go"):
        version = f"go{required}"
    else:
        version = version.splitlines()[0].strip()
    url = f"https://go.dev/dl/{version}.linux-{arch}.tar.gz"
    tarball = Path(f"/tmp/{version}.linux-{arch}.tar.gz")
    _info(f"Скачиваю {version} ({arch})...")
    if not _http_download(url, tarball, timeout=180):
        _warn(f"Не удалось скачать {url}")
        return False
    if OLC_GO_DIR.exists():
        _run(["rm", "-rf", str(OLC_GO_DIR)], check=False, quiet=True)
    r = _run(["tar", "-C", "/usr/local", "-xzf", str(tarball)], check=False, timeout=120)
    tarball.unlink(missing_ok=True)
    if r.returncode != 0:
        _warn("Не удалось распаковать архив Go")
        return False
    for exe in ("go", "gofmt"):
        src = OLC_GO_DIR / "bin" / exe
        dst = Path("/usr/local/bin") / exe
        if src.exists():
            try:
                if dst.exists() or dst.is_symlink():
                    dst.unlink()
                dst.symlink_to(src)
            except Exception:
                pass
    return _go_ok(required)


# =============================================================================
#  СБОРКА olcrtc
# =============================================================================
def _olcrtc_installed() -> bool:
    return OLC_BIN.exists() and os.access(OLC_BIN, os.X_OK)


def _olcrtc_clone_or_update() -> bool:
    if OLC_SRC_DIR.exists() and (OLC_SRC_DIR / ".git").exists():
        r = _run(["git", "-C", str(OLC_SRC_DIR), "pull", "--ff-only"],
                  capture=True, check=False, timeout=60)
        if r.returncode == 0:
            return True
        _run(["rm", "-rf", str(OLC_SRC_DIR)], check=False, quiet=True)
    OLC_SRC_DIR.parent.mkdir(parents=True, exist_ok=True)
    r = _run(["git", "clone", "--depth", "1", OLC_REPO, str(OLC_SRC_DIR)],
              capture=True, check=False, timeout=180)
    return r.returncode == 0 and OLC_SRC_DIR.exists()


def _olcrtc_build() -> bool:
    gobin = "/usr/local/bin/go" if Path("/usr/local/bin/go").exists() else (shutil.which("go") or "go")
    env = dict(os.environ)
    env["CGO_ENABLED"] = "0"
    env["GOOS"] = "linux"
    env["GOARCH"] = _go_arch()
    r = _run([gobin, "build", "-trimpath", "-ldflags", "-s -w",
              "-o", str(OLC_BIN), "./cmd/olcrtc"],
             capture=True, check=False, timeout=900, env=env, cwd=str(OLC_SRC_DIR))
    if r.returncode != 0:
        _warn("go build завершился с ошибкой:")
        for line in (r.stderr or r.stdout or "").splitlines()[-15:]:
            _box_row(f"  {DIM}{line[:100]}{NC}")
    return r.returncode == 0 and _olcrtc_installed()


def _olcrtc_commit() -> str:
    r = _run(["git", "-C", str(OLC_SRC_DIR), "rev-parse", "--short", "HEAD"],
              capture=True, check=False, timeout=10)
    return r.stdout.strip() if r.returncode == 0 else "?"


def _ensure_unit_file() -> None:
    try:
        if not OLC_UNIT_FILE.exists() or OLC_UNIT_FILE.read_text() != _UNIT_CONTENT:
            OLC_UNIT_FILE.parent.mkdir(parents=True, exist_ok=True)
            OLC_UNIT_FILE.write_text(_UNIT_CONTENT)
            _run(["systemctl", "daemon-reload"], check=False, quiet=True, timeout=15)
    except Exception as e:
        _warn(f"Не удалось записать systemd unit: {e}")


def _install_or_update() -> bool:
    """Полная установка/обновление: Go (если нужно) → клон/пул → сборка."""
    OLC_LINKS_DIR.mkdir(parents=True, exist_ok=True)
    OLC_VAR_DIR.mkdir(parents=True, exist_ok=True)

    _info("Клонирую/обновляю исходники olcrtc...")
    if not _olcrtc_clone_or_update():
        _warn("Не удалось клонировать/обновить репозиторий — проверьте доступ к github.com")
        return False

    required = _go_required_version()
    if not _go_ok(required):
        _info(f"Нужен Go {required}+, устанавливаю...")
        if not _install_go(required):
            _warn(f"Не удалось установить Go {required}+ автоматически. "
                  f"Установите вручную: https://go.dev/dl/")
            return False
        _success(f"Go установлен ({required}+)")
    else:
        _info("Go уже подходящей версии — пропускаю установку")

    _info("Собираю бинарник (go build, может занять пару минут)...")
    if not _olcrtc_build():
        _warn("Сборка не удалась")
        return False

    _ensure_unit_file()

    st = _load_state()
    st["installed"] = True
    st["commit"] = _olcrtc_commit()
    st["built_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _save_state(st)
    return True


# =============================================================================
#  ССЫЛКИ-КЛИЕНТЫ ("ЛИНКИ")
# =============================================================================
def _sanitize_name(raw: str) -> str:
    return re.sub(r"[^a-z0-9_-]", "", raw.strip().lower())[:32]


def _gen_key() -> str:
    return secrets.token_hex(32)


def _gen_jitsi_room_path() -> str:
    return "olc-" + secrets.token_hex(4)


def _link_unit(name: str) -> str:
    return f"olcrtc@{name}.service"


def _systemd_is_active(unit: str) -> bool:
    r = _run(["systemctl", "is-active", unit], capture=True, check=False, timeout=10)
    return r.stdout.strip() == "active"


def _server_yaml(carrier: str, room_id: str, key: str, transport: str, data_dir: str) -> str:
    lines = [
        "mode: srv",
        "auth:",
        f"  provider: {carrier}",
        "room:",
        f'  id: "{room_id}"',
        "crypto:",
        f'  key: "{key}"',
        "net:",
        f"  transport: {transport}",
        '  dns: "8.8.8.8:53"',
    ]
    if transport == "vp8channel":
        lines += ["vp8:", "  fps: 60", "  batch_size: 64"]
    elif transport == "videochannel":
        lines += ["video:", "  width: 1080", "  height: 1080", "  fps: 60",
                   '  bitrate: "5000k"', '  hw: "none"']
    lines += [f'data: "{data_dir}"', "debug: false"]
    return "\n".join(lines) + "\n"


def _client_yaml(carrier: str, room_id: str, key: str, transport: str, socks_port: int) -> str:
    lines = [
        "mode: cnc",
        "auth:",
        f"  provider: {carrier}",
        "room:",
        f'  id: "{room_id}"',
        "crypto:",
        f'  key: "{key}"',
        "net:",
        f"  transport: {transport}",
        '  dns: "8.8.8.8:53"',
    ]
    if transport == "vp8channel":
        lines += ["vp8:", "  fps: 60", "  batch_size: 64"]
    elif transport == "videochannel":
        lines += ["video:", "  width: 1080", "  height: 1080", "  fps: 60",
                   '  bitrate: "5000k"', '  hw: "none"']
    lines += ["socks:", '  host: "127.0.0.1"', f"  port: {socks_port}",
              'data: "olcrtc-client-data"', "debug: false"]
    return "\n".join(lines) + "\n"


def _next_socks_port(st: dict) -> int:
    used = {int(v.get("socks_port", 0)) for v in st["links"].values()}
    port = 8808
    while port in used:
        port += 1
    return port


def _create_link(st: dict, name: str, carrier: str, transport: str, room_id: str) -> bool:
    key = _gen_key()
    socks_port = _next_socks_port(st)
    data_dir = OLC_VAR_DIR / name / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    server_text = _server_yaml(carrier, room_id, key, transport, str(data_dir))
    yaml_path = OLC_LINKS_DIR / f"{name}.yaml"
    try:
        OLC_LINKS_DIR.mkdir(parents=True, exist_ok=True)
        yaml_path.write_text(server_text, encoding="utf-8")
    except Exception as e:
        _warn(f"Не удалось записать конфиг: {e}")
        return False

    # Клиентский конфиг раньше только печатался на экран и терялся при
    # потере истории терминала — сохраняем рядом с серверным, отдельным
    # файлом, чтобы можно было открыть позже через cat/nano.
    client_text = _client_yaml(carrier, room_id, key, transport, socks_port)
    client_yaml_path = OLC_LINKS_DIR / f"{name}.client.yaml"
    try:
        client_yaml_path.write_text(client_text, encoding="utf-8")
    except Exception as e:
        _warn(f"Не удалось записать клиентский конфиг: {e}")

    _ensure_unit_file()
    unit = _link_unit(name)
    _run(["systemctl", "enable", "--now", unit], check=False, quiet=True, timeout=20)
    time.sleep(2)
    active = _systemd_is_active(unit)

    st["links"][name] = {
        "carrier": carrier, "transport": transport, "room_id": room_id,
        "key": key, "socks_port": socks_port,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    _save_state(st)

    if not active:
        _warn(f"Сервис {unit} не поднялся — проверьте: journalctl -u {unit} -n 30")
    return active


def _delete_link(name: str, st: dict) -> None:
    unit = _link_unit(name)
    _run(["systemctl", "disable", "--now", unit], check=False, quiet=True, timeout=20)
    yaml_path = OLC_LINKS_DIR / f"{name}.yaml"
    yaml_path.unlink(missing_ok=True)
    (OLC_LINKS_DIR / f"{name}.client.yaml").unlink(missing_ok=True)
    shutil.rmtree(OLC_VAR_DIR / name, ignore_errors=True)
    st["links"].pop(name, None)
    _save_state(st)


# =============================================================================
#  ЭКРАН: ДОБАВИТЬ НОВЫЙ ЛИНК
# =============================================================================
def _flow_add_link(st: dict) -> None:
    print()
    _box_top("➕ Новый клиент (линк) olcRTC")
    for k, (_, title, hint) in CARRIERS.items():
        _box_item(k, f"{title}  {DIM}— {hint}{NC}")
    _box_bottom()
    c_choice = input("  Провайдер: ").strip()
    if c_choice not in CARRIERS:
        _warn("Неверный выбор")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    carrier, carrier_title, _ = CARRIERS[c_choice]

    print()
    _box_top("Транспорт (маскировка)")
    for k, (_, hint) in TRANSPORTS.items():
        _box_item(k, hint)
    _box_bottom()
    t_choice = input("  Транспорт [по умолчанию 1 — datachannel]: ").strip() or "1"
    if t_choice not in TRANSPORTS:
        _warn("Неверный выбор")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    transport, _ = TRANSPORTS[t_choice]

    print()
    raw_name = input("  Имя клиента (латиницей, например ivan-phone): ").strip()
    name = _sanitize_name(raw_name)
    if not name:
        _warn("Имя пустое или содержит только недопустимые символы")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    if name in st["links"]:
        _warn(f"Клиент с именем «{name}» уже существует")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    if carrier == "jitsi":
        print()
        _box_top("Jitsi-сервер")
        for i, h in enumerate(JITSI_HOSTS, 1):
            _box_item(str(i), h)
        _box_item(str(len(JITSI_HOSTS) + 1), "Свой сервер (ввести вручную)")
        _box_bottom()
        h_choice = input("  Сервер [по умолчанию 1]: ").strip() or "1"
        if h_choice.isdigit() and 1 <= int(h_choice) <= len(JITSI_HOSTS):
            host = JITSI_HOSTS[int(h_choice) - 1]
        else:
            host = input("  Введите домен Jitsi-сервера: ").strip()
        if not host:
            _warn("Сервер не указан")
            input(f"{BLUE}Нажмите Enter...{NC}")
            return
        room_id = f"https://{host}/{_gen_jitsi_room_path()}"
        _info(f"Комната сгенерирована автоматически: {room_id}")
    else:
        print()
        _box_top(f"Комната {carrier_title}")
        _box_row(f"  {YELLOW}Комнату нужно создать вручную:{NC}")
        _box_row(f"  {CYAN}{ROOM_CREATE_URL[carrier]}{NC}")
        _box_row(f"  {DIM}Откройте ссылку в браузере, начните звонок и скопируйте ID комнаты.{NC}")
        _box_bottom()
        room_id = input("  Вставьте ID/URL комнаты: ").strip()
        if not room_id:
            _warn("ID комнаты не указан — отменено")
            input(f"{BLUE}Нажмите Enter...{NC}")
            return

    print()
    _info(f"Создаю линк «{name}» ({carrier_title}, {transport})...")
    ok = _create_link(st, name, carrier, transport, room_id)
    link = st["links"][name]

    if ok:
        _success(f"Линк «{name}» запущен (systemd: {_link_unit(name)})")
    else:
        _warn(f"Линк «{name}» создан, но сервис не активен — проверьте логи (пункт меню «логи»)")

    print()
    _box_top(f"Конфиг клиента «{name}» — скопируйте на устройство клиента")
    client_text = _client_yaml(carrier, link["room_id"], link["key"], transport, link["socks_port"])
    for line in client_text.splitlines():
        _box_row(f"  {DIM}{line}{NC}")
    _box_sep()
    _box_row(f"  {WHITE}Сохраните это в файл client.yaml на устройстве клиента,{NC}")
    _box_row(f"  {WHITE}затем: olcrtc client.yaml  →  SOCKS5 поднимется на 127.0.0.1:{link['socks_port']}{NC}")
    _box_sep()
    _box_row(f"  {DIM}Этот конфиг также сохранён на сервере:{NC}")
    _box_row(f"  {CYAN}{OLC_LINKS_DIR / f'{name}.client.yaml'}{NC}")
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  ЭКРАН: СПИСОК / УПРАВЛЕНИЕ ЛИНКАМИ
# =============================================================================
def _flow_link_detail(st: dict, name: str) -> None:
    while True:
        link = st["links"].get(name)
        if not link:
            return
        unit = _link_unit(name)
        active = _systemd_is_active(unit)

        os.system("clear")
        print()
        _box_top(f"Клиент «{name}»")
        _box_row(f"  Провайдер:  {CYAN}{link['carrier']}{NC}")
        _box_row(f"  Транспорт:  {CYAN}{link['transport']}{NC}")
        _box_row(f"  Комната:    {DIM}{link['room_id']}{NC}")
        _box_row(f"  SOCKS-порт: {CYAN}{link['socks_port']}{NC}  {DIM}(на стороне клиента){NC}")
        _box_row(f"  Статус:     {(GREEN+'● активен') if active else (DIM+'○ остановлен')}{NC}")
        _box_sep()
        _box_item("1", f"{'Остановить' if active else 'Запустить'} сервис")
        _box_item("2", "🔁 Перезапустить")
        _box_item("3", "📋 Лог (последние 30 строк)")
        _box_item("4", "📄 Показать конфиг клиента ещё раз")
        _box_item("5", f"{RED}🗑️  Удалить этого клиента{NC}")
        _box_row()
        _box_back()
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch in ("q", ""):
            return
        if ch == "1":
            print()
            if active:
                _run(["systemctl", "stop", unit], check=False, quiet=True, timeout=15)
                _success(f"{unit} остановлен")
            else:
                _run(["systemctl", "start", unit], check=False, quiet=True, timeout=15)
                time.sleep(1)
                if _systemd_is_active(unit):
                    _success(f"{unit} запущен")
                else:
                    _warn(f"Не удалось запустить — journalctl -u {unit} -n 30")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            print()
            _run(["systemctl", "restart", unit], check=False, quiet=True, timeout=20)
            time.sleep(2)
            if _systemd_is_active(unit):
                _success(f"{unit} перезапущен")
            else:
                _warn(f"Не поднялся после перезапуска — journalctl -u {unit} -n 30")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            print()
            r = _run(["journalctl", "-u", unit, "-n", "30", "--no-pager"],
                      capture=True, check=False, timeout=15)
            _box_top(f"📋 Лог {unit}")
            lines = (r.stdout or "").splitlines()[-30:] or ["(пусто)"]
            for line in lines:
                _box_row(f"  {DIM}{line[:100]}{NC}")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            print()
            client_text = _client_yaml(link["carrier"], link["room_id"], link["key"],
                                        link["transport"], link["socks_port"])
            _box_top(f"Конфиг клиента «{name}»")
            for line in client_text.splitlines():
                _box_row(f"  {DIM}{line}{NC}")
            _box_sep()
            _box_row(f"  {DIM}Файл на сервере: {NC}{CYAN}{OLC_LINKS_DIR / f'{name}.client.yaml'}{NC}")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            print()
            confirm = input(f"  Удалить «{name}» безвозвратно? (yes/нет): ").strip().lower()
            if confirm in ("yes", "да", "y", "д"):
                _delete_link(name, st)
                _success(f"Клиент «{name}» удалён")
                input(f"{BLUE}Нажмите Enter...{NC}")
                return
            else:
                _info("Отменено")
                input(f"{BLUE}Нажмите Enter...{NC}")
        else:
            _warn("Неверный выбор")
            time.sleep(1)


def _flow_list_links(st: dict) -> None:
    while True:
        names = list(st["links"].keys())
        os.system("clear")
        print()
        _box_top(f"📋 Клиенты olcRTC ({len(names)})")
        if not names:
            _box_row(f"  {DIM}Пока нет ни одного клиента{NC}")
        else:
            for i, n in enumerate(names, 1):
                link = st["links"][n]
                active = _systemd_is_active(_link_unit(n))
                dot = f"{GREEN}●{NC}" if active else f"{DIM}○{NC}"
                _box_item(str(i), f"{dot} {n}  {DIM}({link['carrier']}/{link['transport']}){NC}")
        _box_row()
        _box_back()
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        if ch in ("q", ""):
            return
        if ch.isdigit() and 1 <= int(ch) <= len(names):
            _flow_link_detail(st, names[int(ch) - 1])
        else:
            _warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  ГАЙД
# =============================================================================
def _show_guide() -> None:
    os.system("clear")
    print()
    _box_top("📖 olcRTC — как это устроено")
    _box_row(f"  {DIM}Это не обычный VLESS-протокол, а TCP-туннель, замаскированный{NC}")
    _box_row(f"  {DIM}под видеозвонок в Jitsi / Яндекс.Телемост / WB Stream.{NC}")
    _box_sep()
    _box_row(f"  {BOLD}Главное отличие от VLESS/Mieru/NaiveProxy:{NC}")
    _box_row(f"  {WHITE}Один сервер не обслуживает много клиентов одним портом.{NC}")
    _box_row(f"  {WHITE}Каждый клиент — это отдельный процесс (отдельный systemd-сервис,{NC}")
    _box_row(f"  {WHITE}«линк»), который реально участвует в видеозвонке. Для транспортов{NC}")
    _box_row(f"  {WHITE}vp8channel и videochannel сервер кодирует настоящее видео — это{NC}")
    _box_row(f"  {WHITE}заметная нагрузка на CPU, в отличие от лёгкого TCP-релея VLESS.{NC}")
    _box_row(f"  {WHITE}Десять клиентов = десять отдельных «звонков», работающих одновременно.{NC}")
    _box_sep()
    _box_row(f"  {BOLD}Провайдеры:{NC}")
    _box_row(f"  {CYAN}Jitsi{NC}      — комната это просто произвольная строка в URL,")
    _box_row(f"             {DIM}никуда заранее создавать не нужно — полностью автоматизируется.{NC}")
    _box_row(f"  {CYAN}Телемост{NC}   — комнату нужно один раз создать на telemost.yandex.ru")
    _box_row(f"             {DIM}и вставить её ID при добавлении клиента.{NC}")
    _box_row(f"  {CYAN}WB Stream{NC}  — то же самое, комната создаётся на stream.wb.ru.")
    _box_sep()
    _box_row(f"  {BOLD}Транспорт (скорость по убыванию):{NC}")
    _box_row(f"  {DIM}datachannel  >  vp8channel  >  seichannel  >  videochannel{NC}")
    _box_row(f"  {DIM}Чем «видеоподобнее» транспорт, тем лучше маскировка, но ниже скорость.{NC}")
    _box_sep()
    _box_row(f"  {BOLD}Что нужно клиенту (важно):{NC}")
    _box_row(f"  {WHITE}Обычный vless:// / QR здесь не работает. У olcrtc нет единого{NC}")
    _box_row(f"  {WHITE}готового мобильного приложения с поддержкой ссылок — клиенту{NC}")
    _box_row(f"  {WHITE}нужен сам бинарник olcrtc (или его community-форк olcbox, alpha,{NC}")
    _box_row(f"  {WHITE}для Android — но это не официальный продукт, использовать на свой риск).{NC}")
    _box_row()
    _box_row(f"  {WHITE}1. Собрать olcrtc под свою ОС из исходников:{NC}")
    _box_row(f"     {CYAN}{OLC_REPO}{NC}")
    _box_row(f"     {DIM}(нужен Go 1.26+, команда: go build ./cmd/olcrtc){NC}")
    _box_row(f"  {WHITE}2. Сохранить выданный этим меню YAML-конфиг в файл, например{NC}")
    _box_row(f"     {DIM}client.yaml{NC}")
    _box_row(f"  {WHITE}3. Запустить: {NC}{CYAN}olcrtc client.yaml{NC}")
    _box_row(f"  {WHITE}4. На устройстве появится локальный SOCKS5 (127.0.0.1:порт из конфига).{NC}")
    _box_row(f"     {DIM}Укажите этот SOCKS5 в браузере/прокси-клиенте устройства.{NC}")
    _box_sep()
    _box_row(f"  {YELLOW}Это Beta-проект одного автора без официальных релизов — конфиг и{NC}")
    _box_row(f"  {YELLOW}флаги периодически меняются. Используйте как запасной канал для{NC}")
    _box_row(f"  {YELLOW}случаев полной блокировки «по белым спискам», а не как основной.{NC}")
    _box_bottom()
    input(f"{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  ГЛАВНОЕ МЕНЮ
# =============================================================================
def do_olcrtc_menu() -> None:
    """Интерактивное управление olcRTC: установка, клиенты (линки), гайд."""
    while True:
        st = _load_state()
        installed = _olcrtc_installed()
        n_links = len(st["links"])
        n_active = sum(1 for n in st["links"] if _systemd_is_active(_link_unit(n))) if installed else 0

        os.system("clear")
        print()
        _box_top("📹 olcRTC — ТУННЕЛЬ ПОД ВИДЕОЗВОНОК (Beta)")
        _box_row(f"  {DIM}TCP-over-WebRTC: маскирует трафик под звонок в Jitsi /{NC}")
        _box_row(f"  {DIM}Телемосте / WB Stream. Для сценариев полного белого списка.{NC}")
        _box_sep()
        if not installed:
            _box_row(f"  Статус:   {RED}не установлен{NC}")
        else:
            _box_row(f"  Статус:   {GREEN}● собран{NC}  {DIM}(коммит {st.get('commit', '?')}){NC}")
            _box_row(f"  Клиентов: {CYAN}{n_links}{NC}  {DIM}(активных: {n_active}){NC}")
        _box_sep()

        _box_item("1", f"{'🔄 Обновить' if installed else '📥 Установить'} olcrtc (сборка из исходников)")
        _box_item("2", "📖 Гайд — как это работает и что нужно клиенту")
        if installed:
            _box_item("3", "➕ Добавить нового клиента (линк)")
            _box_item("4", f"📋 Список клиентов  {DIM}({n_links} шт.){NC}")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch in ("q", ""):
            break

        if ch == "1":
            print()
            if _install_or_update():
                _success("olcrtc установлен/обновлён")
            else:
                _error("Установка не удалась — см. сообщения выше")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            _show_guide()

        elif ch == "3" and installed:
            _flow_add_link(st)

        elif ch == "4" and installed:
            _flow_list_links(st)

        else:
            _warn("Неверный выбор.")
            time.sleep(1)
