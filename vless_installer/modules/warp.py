"""
vless_installer/modules/warp.py
───────────────────────────────────────────────────────────────────────────────
Cloudflare WARP — нативная связка WireGuard + wgcf (без официального warp-cli).

  • Режимы маршрутизации: full (весь трафик), selective (выбранные IP/домены),
    runet (только заблокированные в РФ ресурсы).
  • Переключение режимов — исключительно через `ip route`, БЕЗ перезапуска
    wg-quick (интерфейс поднимается один раз, конфиг использует Table = off,
    поэтому wg-quick никогда не трогает основную таблицу маршрутизации сам).
  • SSH-сессия пользователя и сам Cloudflare-эндпоинт всегда вне туннеля
    (защита через явные маршруты к реальному, захваченному до WARP, шлюзу).
  • Фоновый ререзолв доменов в режиме selective — cron */5 мин,
    атомарная синхронизация state.json через fcntl.flock с перечитыванием
    файла перед записью (не затирает UUID пользователей Xray и прочие ключи
    ядра, изменённые конкурентно).

Точка входа из _core.py (НЕ ИЗМЕНЯТЬ — единственная точка интеграции с ядром):
    from vless_installer.modules.warp import do_manage_warp

───────────────────────────────────────────────────────────────────────────────
АРХИТЕКТУРНОЕ ЗАМЕЧАНИЕ (циклический импорт, важно для любого, кто будет
править этот файл):

_core.py импортирует `do_manage_warp` из этого модуля на верхнем уровне —
ДО того, как в _core.py определены command_exists(), log_to_file(),
_pkg_install(), STATE_FILE и сами глобали WARP_*. Поэтому ЛЮБОЙ top-level
`from vless_installer._core import ...` в этом файле гарантированно упадёт
с ImportError (partially initialized module) уже на старте инсталлятора.
Решение — отложенное (lazy) разрешение имён ядра в момент фактического
вызова через `_core_module()`, а не в момент импорта.

ПОЛНАЯ АВТОНОМНОСТЬ: модуль НЕ требует никаких изменений в _core.py.
Используются только то, что там уже реально есть и так: STATE_FILE,
log_to_file(), command_exists(), _pkg_install(). Чтение/запись WARP_*
состояния в state.json модуль выполняет полностью сам — см.
_warp_state_load_autonomously() / _warp_state_save_autonomously() ниже —
через явный маппинг JSON-ключ ⇄ имя глобали ядра (_WARP_STATE_MAP), а НЕ
слепым сканированием vars(core): под префиксом WARP_ в _core.py помимо
шести нужных ключей лежат WARP_MDM_FILE / WARP_SERVICE_FILE (Path-объекты,
не сериализуются в JSON) и унаследованные от старого warp-cli SSH-namespace
константы (WARP_SSH_NAMESPACE и т.п.) — слепой сбор всех WARP_*-атрибутов
уронил бы json.dumps() и тихо проглотил ошибку сохранения на каждом вызове.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_sep, _box_bottom,
    RED, GREEN, BLUE, CYAN, YELLOW, NC,
)


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py) — см. архитектурное замечание выше
# =============================================================================
def _core_module():
    """Возвращает модуль vless_installer._core, импортируя его лениво.

    При запуске через cron (`python warp.py --sync`) этот файл выполняется
    как `__main__`, и импорт `vless_installer._core` отрабатывает как
    обычный, без всякой цикличности (это другой процесс, другой граф
    импортов). При вызове из самого инсталлятора (do_manage_warp() уже
    вызван из полностью загруженного _core.py) модуль уже находится в
    sys.modules, и импорт — это просто бесплатный lookup.
    """
    import importlib
    return importlib.import_module("vless_installer._core")


def _state_get(name: str, default=None):
    """Читает глобаль WARP_* из _core.py (единственное реальное хранилище)."""
    return getattr(_core_module(), name, default)


def _state_set(name: str, value) -> None:
    """Пишет глобаль WARP_* в _core.py (единственное реальное хранилище)."""
    setattr(_core_module(), name, value)


def info(msg: str) -> None:
    print(f"{CYAN}[INFO]{NC}  {msg}")
    _core_module().log_to_file("INFO", msg)


def success(msg: str) -> None:
    print(f"{GREEN}[OK]{NC}    {msg}")
    _core_module().log_to_file("SUCCESS", msg)


def warn(msg: str) -> None:
    print(f"{YELLOW}[WARN]{NC}  {msg}")
    _core_module().log_to_file("WARN", msg)


def command_exists(cmd: str) -> bool:
    return _core_module().command_exists(cmd)


def _pkg_install(*pkgs: str) -> None:
    _core_module()._pkg_install(*pkgs)


# =============================================================================
#  АВТОНОМНАЯ ПЕРСИСТЕНТНОСТЬ WARP_* СОСТОЯНИЯ — без изменений в _core.py
# =============================================================================
# Явный маппинг JSON-ключ (state.json) ⇄ имя глобали ядра. НЕ простой
# .upper()/.lower(): исторически "warp_ssh_ip" ⇄ "WARP_SSH_CLIENT_IP" (а не
# "WARP_SSH_IP"). Маппинг также служит белым списком — иначе пришлось бы
# слепо собирать все атрибуты ядра с префиксом WARP_, среди которых есть
# несериализуемые Path-объекты (WARP_MDM_FILE, WARP_SERVICE_FILE) и мусор
# от старого warp-cli SSH-namespace подхода (WARP_SSH_NAMESPACE и т.п.) —
# см. подробности в шапке файла.
_WARP_STATE_MAP: tuple[tuple[str, str], ...] = (
    ("warp_installed",      "WARP_INSTALLED"),
    ("warp_connected",      "WARP_CONNECTED"),
    ("warp_mode",           "WARP_MODE"),
    ("warp_ssh_ip",         "WARP_SSH_CLIENT_IP"),
    ("warp_custom_ips",     "WARP_CUSTOM_IPS"),
    ("warp_custom_domains", "WARP_CUSTOM_DOMAINS"),
    ("warp_active_routes",  "WARP_ACTIVE_ROUTES"),
)


def _warp_state_load_autonomously() -> None:
    """Читает core.STATE_FILE напрямую и раскладывает известные warp_*
    ключи по глобалям ядра (setattr). Не требует НИЧЕГО, кроме уже
    существующего в _core.py STATE_FILE."""
    core = _core_module()
    if not core.STATE_FILE.exists():
        return
    try:
        state = json.loads(core.STATE_FILE.read_text())
    except Exception:
        return
    for json_key, attr_name in _WARP_STATE_MAP:
        if json_key in state:
            setattr(core, attr_name, state[json_key])


def _warp_state_save_autonomously() -> None:
    """Атомарно сохраняет текущие WARP_*-глобали ядра в core.STATE_FILE.

    Сама открывает файл в 'r+', блокирует через fcntl.flock(LOCK_EX),
    перечитывает содержимое непосредственно перед записью (чтобы не
    затереть UUID пользователей Xray или другие ключи ядра, изменённые
    конкурентно), обновляет только свои warp_*-ключи и пишет обратно.
    Никакой логики в _core.py для этого не требуется."""
    core = _core_module()
    if not core.STATE_FILE.exists():
        return
    import fcntl
    try:
        with core.STATE_FILE.open("r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                content = f.read()
                state = json.loads(content) if content else {}
                for json_key, attr_name in _WARP_STATE_MAP:
                    state[json_key] = getattr(core, attr_name, None)
                f.seek(0)
                f.truncate()
                f.write(json.dumps(state, indent=2, ensure_ascii=False))
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        warn(f"Не удалось сохранить WARP state: {e}")


# =============================================================================
#  КОНСТАНТЫ
# =============================================================================
WG_INTERFACE        = "wg-warp"
WG_SERVICE          = f"wg-quick@{WG_INTERFACE}"
WG_CONFIG           = Path("/etc/wireguard/wg-warp.conf")
CRON_FILE           = Path("/etc/cron.d/warp-selective-sync")
ORIG_ROUTE_FILE     = Path("/etc/warp-original-route.conf")
MODULE_PATH         = Path(__file__).resolve()
CRON_SYNC_INTERVAL  = "*/5 * * * *"

MODE_FULL           = "full"
MODE_SELECTIVE      = "selective"
MODE_RUNET          = "runet"
VALID_MODES         = (MODE_FULL, MODE_SELECTIVE, MODE_RUNET)

# Версия wgcf без буквы 'v' — именно так называется бинарник в релизе
# (тег v2.2.31 → файл wgcf_2.2.31_linux_amd64, БЕЗ расширения .tar.gz и
# БЕЗ буквы 'v' в имени файла — подтверждено напрямую по странице релизов
# ViRb3/wgcf; оба прототипа ошибались в этом по-разному).
WGCF_FALLBACK_VERSION = "2.2.31"
WGCF_API_TIMEOUT      = 3  # секунд

# Подсети Telegram + Meta для режима RUNET (runetfreedom / публичные RIPE-данные)
RUNET_CIDRS = [
    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22",
    "91.108.56.0/22", "149.154.160.0/20", "31.13.24.0/21", "31.13.32.0/17",
    "157.240.0.0/16", "103.4.96.0/22",
]


# =============================================================================
#  ЕДИНАЯ ОБЁРТКА ДЛЯ SHELL-КОМАНД
# =============================================================================
def _run(
    cmd: list[str],
    capture: bool = False,
    check: bool = False,
    quiet: bool = False,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
) -> subprocess.CompletedProcess:
    """Единственная точка выполнения внешних команд в модуле.

    check=False по умолчанию (в отличие от _core._run, где check=True) —
    осознанно: большинство вызовов здесь — идемпотентные операции с `ip
    route` / systemctl, где ненулевой код возврата (маршрут уже существует,
    юнит уже остановлен) — норма, а не повод бросать исключение."""
    kw: dict = {"check": check, "cwd": cwd}
    if env:
        merged = os.environ.copy()
        merged.update(env)
        kw["env"] = merged
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return subprocess.run(cmd, **kw)
    except FileNotFoundError:
        if check:
            raise
        return subprocess.CompletedProcess(cmd, 127, stdout="", stderr=f"command not found: {cmd[0]}")


# =============================================================================
#  WGCF: ДИНАМИЧЕСКОЕ ОПРЕДЕЛЕНИЕ ВЕРСИИ + АРХИТЕКТУРА
# =============================================================================
def _wgcf_arch() -> str:
    arch_map = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "armv7l": "arm", "armv6l": "arm",
        "i386": "386", "i686": "386",
    }
    return arch_map.get(platform.machine().lower(), "amd64")


def _get_latest_wgcf_url() -> str:
    """Определяет URL последнего релиза wgcf через GitHub API (таймаут 3с).
    При любой ошибке — фиксированный fallback на WGCF_FALLBACK_VERSION."""
    arch = _wgcf_arch()
    fallback_tag = f"v{WGCF_FALLBACK_VERSION}"
    fallback_url = (
        f"https://github.com/ViRb3/wgcf/releases/download/"
        f"{fallback_tag}/wgcf_{WGCF_FALLBACK_VERSION}_linux_{arch}"
    )

    r = _run(
        ["curl", "-s", "--max-time", str(WGCF_API_TIMEOUT),
         "https://api.github.com/repos/ViRb3/wgcf/releases/latest"],
        capture=True, check=False,
    )
    if r.returncode == 0 and r.stdout:
        m = re.search(r'"tag_name"\s*:\s*"([^"]+)"', r.stdout)
        if m:
            tag = m.group(1)
            ver = tag[1:] if tag.startswith("v") else tag
            return f"https://github.com/ViRb3/wgcf/releases/download/{tag}/wgcf_{ver}_linux_{arch}"

    warn(f"GitHub API недоступен — используется фиксированная версия wgcf {fallback_tag}")
    return fallback_url


def _inject_table_off(raw_conf: str) -> str:
    """Добавляет `Table = off` в секцию [Interface] и убирает строки DNS =,
    чтобы wg-quick никогда не трогал основную таблицу маршрутизации сам —
    весь приём трафика в туннель выполняется явными `ip route add`."""
    lines: list[str] = []
    in_interface = False
    table_added = False
    for line in raw_conf.splitlines():
        stripped = line.strip()
        if stripped == "[Interface]":
            in_interface = True
            lines.append(line)
            continue
        if in_interface and not table_added and (stripped.startswith("[") or stripped == ""):
            lines.append("Table = off")
            table_added = True
        if stripped.startswith("DNS"):
            continue
        lines.append(line)
    if not table_added:
        lines.append("Table = off")
    return "\n".join(lines) + "\n"


# =============================================================================
#  ЗАХВАТ РЕАЛЬНОГО (НЕ-WARP) ДЕФОЛТНОГО МАРШРУТА — защита SSH/Endpoint
# =============================================================================
# Сохранённый на диск шлюз/интерфейс, зафиксированные ДО подключения WARP.
# Все функции, защищающие SSH и Cloudflare-эндпоинт от закольцовывания,
# ОБЯЗАНЫ читать шлюз отсюда (см. _ensure_original_route), а не пересчитывать
# `ip route show default` заново в произвольный момент — иначе после
# применения режима FULL результат такого пересчёта неотличим от случая,
# когда WARP уже перехватил маршрутизацию, и "защита" начнёт сама
# маршрутизировать защищаемый трафик обратно в туннель.
def _capture_original_route() -> Optional[tuple[str, str]]:
    r = _run(["ip", "route", "show", "default"], capture=True, check=False)
    if r.returncode != 0 or not (r.stdout or "").strip():
        return None
    for line in r.stdout.splitlines():
        if WG_INTERFACE in line.lower():
            return None
        parts = line.split()
        if "via" in parts and "dev" in parts:
            gw = parts[parts.index("via") + 1]
            dev = parts[parts.index("dev") + 1]
            ORIG_ROUTE_FILE.write_text(f"MAIN_GW={gw}\nMAIN_IF={dev}\n")
            return gw, dev
    return None


def _load_original_route() -> Optional[tuple[str, str]]:
    if not ORIG_ROUTE_FILE.exists():
        return None
    gw = dev = None
    for line in ORIG_ROUTE_FILE.read_text().splitlines():
        if line.startswith("MAIN_GW="):
            gw = line.split("=", 1)[1].strip()
        elif line.startswith("MAIN_IF="):
            dev = line.split("=", 1)[1].strip()
    return (gw, dev) if gw and dev else None


def _ensure_original_route() -> Optional[tuple[str, str]]:
    """Сначала пробует захватить шлюз заново (первый запуск / смена сети
    провайдера), иначе откатывается на ранее сохранённое значение —
    актуально, когда вызов происходит уже ПОСЛЕ подъёма wg-warp."""
    fresh = _capture_original_route()
    return fresh if fresh else _load_original_route()


def _get_warp_endpoint() -> Optional[str]:
    """Извлекает IP эндпоинта Cloudflare из сгенерированного конфига."""
    if not WG_CONFIG.exists():
        return None
    m = re.search(r"^Endpoint\s*=\s*([\d.]+):\d+", WG_CONFIG.read_text(), re.MULTILINE)
    return m.group(1) if m else None


# =============================================================================
#  УЧЁТ АКТИВНЫХ МАРШРУТОВ (warp_active_routes)
# =============================================================================
def _clear_active_routes() -> None:
    routes = _state_get("WARP_ACTIVE_ROUTES", [])
    if not routes:
        return
    for cidr in routes:
        _run(["ip", "route", "del", cidr, "dev", WG_INTERFACE], capture=True, quiet=True)
    _state_set("WARP_ACTIVE_ROUTES", [])
    _warp_state_save_autonomously()


def _add_route(cidr: str) -> None:
    if not cidr:
        return
    r = _run(["ip", "route", "add", cidr, "dev", WG_INTERFACE], capture=True, quiet=True)
    if r.returncode == 0 or "File exists" in (r.stderr or ""):
        routes = _state_get("WARP_ACTIVE_ROUTES", [])
        if cidr not in routes:
            routes.append(cidr)
            _state_set("WARP_ACTIVE_ROUTES", routes)


def _resolve_domains(domains: list[str]) -> list[str]:
    """Возвращает отсортированный список уникальных IPv4 /32 для доменов."""
    result: set[str] = set()
    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        try:
            for item in socket.getaddrinfo(domain, None, socket.AF_INET):
                result.add(f"{item[4][0]}/32")
        except socket.gaierror:
            warn(f"Не удалось разрешить домен: {domain}")
    return sorted(result)


# =============================================================================
#  УСТАНОВКА / УДАЛЕНИЕ
# =============================================================================
def _warp_is_installed() -> bool:
    return WG_CONFIG.exists()


def _warp_service_active() -> bool:
    r = _run(["systemctl", "is-active", WG_SERVICE], capture=True, check=False)
    return (r.stdout or "").strip() == "active"


def install_warp() -> bool:
    """Устанавливает WireGuard + wgcf, генерирует конфиг с Table = off и
    поднимает туннель РОВНО ОДИН РАЗ. Идемпотентна: при уже существующем
    конфиге — no-op. При любой ошибке гарантированно зачищает временные
    файлы и не оставляет битый конфиг или незавершённую регистрацию wgcf."""
    if WG_CONFIG.exists():
        info("Конфигурация WireGuard (wg-warp) уже существует — установка пропущена.")
        _state_set("WARP_INSTALLED", True)
        return True

    info("Установка WireGuard и wgcf...")
    if not command_exists("wg-quick"):
        _pkg_install("wireguard", "wireguard-tools")
    if not command_exists("curl"):
        _pkg_install("curl")

    tmp_bin     = Path("/tmp/wgcf")
    tmp_profile = Path("/tmp/wgcf-profile.conf")
    tmp_account = Path("/tmp/wgcf-account.toml")

    try:
        url = _get_latest_wgcf_url()
        info(f"Скачивание wgcf ({url.rsplit('/', 1)[-1]})...")
        r = _run(["curl", "-fsSL", "-o", str(tmp_bin), url], capture=True, check=False)
        if r.returncode != 0 or not tmp_bin.exists() or tmp_bin.stat().st_size == 0:
            warn(f"Не удалось скачать wgcf: {(r.stderr or '').strip() or 'файл не получен'}")
            return False
        tmp_bin.chmod(0o755)

        info("Регистрация аккаунта Cloudflare WARP...")
        r2 = _run([str(tmp_bin), "register", "--accept-tos"], capture=True, check=False, cwd="/tmp")
        if r2.returncode != 0:
            warn(f"Ошибка регистрации wgcf: {(r2.stderr or r2.stdout or '').strip()}")
            return False

        info("Генерация профиля WireGuard...")
        r3 = _run([str(tmp_bin), "generate"], capture=True, check=False, cwd="/tmp")
        if r3.returncode != 0 or not tmp_profile.exists():
            warn(f"Ошибка генерации конфига wgcf: {(r3.stderr or r3.stdout or '').strip()}")
            return False

        WG_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        WG_CONFIG.write_text(_inject_table_off(tmp_profile.read_text()))
        WG_CONFIG.chmod(0o600)
    finally:
        tmp_bin.unlink(missing_ok=True)
        tmp_profile.unlink(missing_ok=True)
        tmp_account.unlink(missing_ok=True)

    if not WG_CONFIG.exists():
        return False

    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", WG_SERVICE], check=False, quiet=True)
    _run(["systemctl", "start", WG_SERVICE], check=False)
    time.sleep(2)

    if not _warp_service_active():
        warn(f"Не удалось запустить {WG_SERVICE} — проверьте: systemctl status {WG_SERVICE}")
        WG_CONFIG.unlink(missing_ok=True)
        return False

    _state_set("WARP_INSTALLED", True)
    success("WireGuard (wg-warp) установлен, конфиг сгенерирован, туннель поднят.")
    return True


def uninstall_warp() -> bool:
    """Полностью удаляет WARP: останавливает сервис, очищает cron, конфиг,
    маршруты и сбрасывает состояние. Идемпотентна при повторном вызове."""
    info("Удаление WireGuard (WARP) из системы...")
    _manage_cron(False)
    _clear_active_routes()
    _run(["systemctl", "stop", WG_SERVICE], check=False, quiet=True)
    _run(["systemctl", "disable", WG_SERVICE], check=False, quiet=True)
    WG_CONFIG.unlink(missing_ok=True)
    ORIG_ROUTE_FILE.unlink(missing_ok=True)

    _state_set("WARP_INSTALLED", False)
    _state_set("WARP_CONNECTED", False)
    _state_set("WARP_MODE", "")
    _state_set("WARP_ACTIVE_ROUTES", [])
    _warp_state_save_autonomously()
    success("WARP (WireGuard) полностью удалён из системы.")
    return True


# =============================================================================
#  РЕЖИМЫ МАРШРУТИЗАЦИИ — переключение исключительно через `ip route`
# =============================================================================
def _warp_apply_full_mode(ssh_client_ip: str) -> None:
    """FULL: весь трафик через WARP. SSH-клиент и сам Cloudflare-эндпоинт
    явно маршрутизируются через реальный (захваченный до WARP) шлюз —
    иначе полный туннель неизбежно оборвёт текущую SSH-сессию."""
    info("Применение режима FULL (весь трафик через WARP)...")
    _manage_cron(False)
    _clear_active_routes()

    orig = _ensure_original_route()
    orig_gw, orig_if = orig if orig else (None, None)
    if not orig_gw:
        warn("Не удалось определить реальный шлюз сервера — защита SSH/Endpoint может не сработать.")

    endpoint_ip = _get_warp_endpoint()
    if endpoint_ip and orig_gw:
        _run(["ip", "route", "add", f"{endpoint_ip}/32", "via", orig_gw, "dev", orig_if],
             capture=True, quiet=True)

    if ssh_client_ip and orig_gw:
        ssh_cidr = ssh_client_ip if "/" in ssh_client_ip else f"{ssh_client_ip}/32"
        _run(["ip", "route", "add", ssh_cidr, "via", orig_gw, "dev", orig_if],
             capture=True, quiet=True)

    _add_route("0.0.0.0/1")
    _add_route("128.0.0.0/1")
    _warp_state_save_autonomously()
    success("Режим FULL активирован — SSH и Cloudflare Endpoint защищены.")


def _warp_apply_selective_mode(ips: list[str], domains: list[str]) -> None:
    """SELECTIVE: в туннель идут только заданные IP/CIDR и резолвленные
    домены. Включает фоновый cron-ререзолв для доменов."""
    info("Применение режима SELECTIVE (выборочный трафик)...")
    _clear_active_routes()
    for ip in ips:
        _add_route(ip if "/" in ip else f"{ip}/32")
    for cidr in _resolve_domains(domains):
        _add_route(cidr)
    _manage_cron(True)
    _warp_state_save_autonomously()
    success(f"Режим SELECTIVE активирован (IP: {len(ips)}, доменов: {len(domains)}).")


def _warp_apply_runet_mode() -> None:
    """RUNET: в туннель идут только заблокированные в РФ подсети
    (Telegram/Meta). Дефолтный маршрут не трогается вовсе, поэтому SSH
    в этом режиме в дополнительной защите не нуждается."""
    info("Применение режима RUNET (заблокированные ресурсы)...")
    _manage_cron(False)
    _clear_active_routes()
    for cidr in RUNET_CIDRS:
        _add_route(cidr)
    _warp_state_save_autonomously()
    success(f"Режим RUNET активирован. Добавлено {len(RUNET_CIDRS)} подсетей.")


def _apply_mode(mode: str, ssh_client_ip: str, custom_ips: list[str], custom_domains: list[str]) -> None:
    if mode == MODE_FULL:
        _warp_apply_full_mode(ssh_client_ip)
    elif mode == MODE_SELECTIVE:
        _warp_apply_selective_mode(custom_ips, custom_domains)
    elif mode == MODE_RUNET:
        _warp_apply_runet_mode()


# =============================================================================
#  CRON: ФОНОВЫЙ РЕРЕЗОЛВ ДОМЕНОВ ДЛЯ SELECTIVE (--sync)
# =============================================================================
def _manage_cron(enable: bool) -> None:
    CRON_FILE.unlink(missing_ok=True)
    if enable:
        content = f"{CRON_SYNC_INTERVAL} root {sys.executable} {MODULE_PATH} --sync >/dev/null 2>&1\n"
        CRON_FILE.write_text(content)
        CRON_FILE.chmod(0o644)


def _standalone_sync() -> None:
    """Точка входа для cron (`warp.py --sync`). Атомарно перечитывает
    state.json под эксклюзивной fcntl-блокировкой и перечитывает файл ещё
    раз непосредственно перед записью — чтобы никогда не затереть UUID
    пользователей Xray или другие ключи ядра, изменённые конкурентно
    (например, активной SSH-сессией с открытым меню инсталлятора)."""
    core = _core_module()
    if not core.STATE_FILE.exists():
        return

    import fcntl
    try:
        with core.STATE_FILE.open("r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                content = f.read()
                if not content:
                    return
                try:
                    state = json.loads(content)
                except json.JSONDecodeError:
                    return

                if state.get("warp_mode") != MODE_SELECTIVE:
                    return
                if (_run(["systemctl", "is-active", WG_SERVICE], capture=True, check=False)
                        .stdout or "").strip() != "active":
                    return

                custom_ips     = state.get("warp_custom_ips", [])
                custom_domains = state.get("warp_custom_domains", [])
                old_routes     = state.get("warp_active_routes", [])

                desired = {ip if "/" in ip else f"{ip}/32" for ip in custom_ips}
                desired |= set(_resolve_domains(custom_domains))
                desired = sorted(desired)

                if desired == sorted(old_routes):
                    return  # ничего не изменилось — не трогаем ядро Linux

                for cidr in old_routes:
                    if cidr not in desired:
                        _run(["ip", "route", "del", cidr, "dev", WG_INTERFACE], capture=True, quiet=True)
                for cidr in desired:
                    if cidr not in old_routes:
                        _run(["ip", "route", "add", cidr, "dev", WG_INTERFACE], capture=True, quiet=True)

                # ВАЖНО: запись делается напрямую в fresh_state, а НЕ через
                # _warp_state_save_autonomously(). Та функция берёт значения
                # из in-memory глобалей core.WARP_*, которых в свежем
                # процессе крона (`python warp.py --sync`) просто не
                # существует (core.WARP_ACTIVE_ROUTES никогда не был
                # установлен в этом процессе) — вызов автономной save-
                # функции здесь затёр бы только что посчитанные маршруты
                # пустым списком. Поэтому old_routes/desired читаются и
                # пишутся напрямую из/в тот же JSON, под тем же flock.
                f.seek(0)
                fresh_content = f.read()
                fresh_state = json.loads(fresh_content) if fresh_content else {}
                fresh_state["warp_active_routes"] = desired
                f.seek(0)
                f.truncate()
                f.write(json.dumps(fresh_state, indent=2, ensure_ascii=False))
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        core.log_to_file("ERROR", f"WARP --sync: {e}")


# =============================================================================
#  ПУБЛИЧНЫЙ API СОВМЕСТИМОСТИ СО СТАРЫМ МОДУЛЕМ
# =============================================================================
def configure_warp(
    mode: str,
    ssh_client_ip: str,
    custom_ips: Optional[list[str]] = None,
    custom_domains: Optional[list[str]] = None,
) -> bool:
    """Сохранена сигнатура старого публичного API: одной командой
    устанавливает WARP и применяет режим маршрутизации."""
    custom_ips = custom_ips or []
    custom_domains = custom_domains or []

    if mode not in VALID_MODES:
        warn(f"Неизвестный режим WARP: {mode!r} — используется '{MODE_FULL}'")
        mode = MODE_FULL

    _state_set("WARP_SSH_CLIENT_IP", ssh_client_ip or "")
    _state_set("WARP_MODE", mode)
    _state_set("WARP_CUSTOM_IPS", custom_ips)
    _state_set("WARP_CUSTOM_DOMAINS", custom_domains)

    _ensure_original_route()
    if not install_warp():
        return False

    _state_set("WARP_CONNECTED", True)
    _apply_mode(mode, ssh_client_ip or "", custom_ips, custom_domains)
    _warp_state_save_autonomously()
    return True


# =============================================================================
#  ИНТЕРАКТИВНЫЙ ВВОД
# =============================================================================
def _detect_ssh_client_ip() -> str:
    env = os.environ.get("SSH_CLIENT", "") or os.environ.get("SSH_CONNECTION", "")
    return env.split()[0] if env else ""


def _prompt_selective_lists() -> tuple[list[str], list[str]]:
    old_ips = _state_get("WARP_CUSTOM_IPS", [])
    old_domains = _state_get("WARP_CUSTOM_DOMAINS", [])

    if old_ips or old_domains:
        _box_row(f"  Сохранённые списки: {len(old_ips)} IP, {len(old_domains)} доменов.")
        use_saved = input(f"  {BLUE}Использовать текущие списки из state.json? [Y/n]:{NC} ").strip().lower()
        if use_saved != "n":
            success(f"Используются сохранённые списки ({len(old_ips)} IP, {len(old_domains)} доменов).")
            return old_ips, old_domains

    _box_row(f"{BLUE}IP/CIDR для туннелирования через WARP:{NC}")
    _box_row("  Через запятую. Например: 1.2.3.4/32, 5.6.7.0/24")
    raw_ips = input("  IP/CIDR: ").strip()
    custom_ips = [x.strip() for x in raw_ips.split(",") if x.strip()] if raw_ips else []

    _box_row(f"{BLUE}Домены для туннелирования через WARP:{NC}")
    _box_row("  Через запятую. Например: instagram.com, t.me")
    raw_domains = input("  Домены: ").strip()
    custom_domains = [x.strip() for x in raw_domains.split(",") if x.strip()] if raw_domains else []

    return custom_ips, custom_domains


def _check_ssh_protection() -> None:
    """Проверяет напрямую по таблице маршрутизации ядра, что трафик до
    SSH-клиента не уходит в wg-warp — для новой архитектуры (без iptables
    mangle-меток и policy routing) это прямой и более надёжный эквивалент
    старой проверки `iptables -t mangle -L OUTPUT`."""
    ssh_ip = _state_get("WARP_SSH_CLIENT_IP", "") or _detect_ssh_client_ip()
    if not ssh_ip:
        ssh_ip = input(f"  {YELLOW}SSH IP не задан. Введите IP клиента:{NC} ").strip()
    if not ssh_ip:
        warn("SSH IP не определён — проверка пропущена.")
        return

    r = _run(["ip", "route", "get", ssh_ip], capture=True, check=False)
    out = r.stdout or ""
    if WG_INTERFACE in out:
        warn(f"✗ Маршрут до {ssh_ip} проходит через {WG_INTERFACE} — SSH под угрозой разрыва!")
        warn("  Переустановите режим FULL (пункт [2]), чтобы пересоздать защитный маршрут.")
    else:
        success(f"✓ Маршрут до {ssh_ip} идёт мимо {WG_INTERFACE} — SSH защищён.")


# =============================================================================
#  МЕНЮ
# =============================================================================
def _menu_install_wizard() -> None:
    print()
    _box_top("Настройка Cloudflare WARP (wgcf + WireGuard)")
    _box_row()

    detected_ssh_ip = _detect_ssh_client_ip()
    _box_row(f"{BLUE}IP вашего SSH-клиента (будет ВСЕГДА исключён из WARP):{NC}")
    _box_row("  Без этого при полном туннеле SSH может оборваться!")
    if detected_ssh_ip:
        _box_row(f"  1  {detected_ssh_ip}  {GREEN}(определён автоматически){NC}")
    else:
        _box_row(f"  1  Ввести вручную  {YELLOW}(автоопределение не удалось){NC}")
    _box_row("  2  Ввести вручную")
    _box_row("  3  Пропустить (небезопасно!)")
    _box_bottom()

    ssh_ip = ""
    while True:
        v = input("  Выбор [1]: ").strip() or "1"
        if v == "1":
            ssh_ip = detected_ssh_ip or input("  SSH client IP: ").strip()
            break
        elif v == "2":
            ssh_ip = input("  SSH client IP: ").strip()
            break
        elif v == "3":
            ssh_ip = ""
            break

    _box_row()
    _box_row(f"{BLUE}Режим маршрутизации WARP:{NC}")
    _box_row(f"  1  🌐 Весь трафик через WARP {GREEN}({MODE_FULL}){NC}")
    _box_row(f"  2  🎯 Выборочные ресурсы {GREEN}({MODE_SELECTIVE}){NC}")
    _box_row(f"  3  🇷🇺 Заблокированные РФ ресурсы {GREEN}({MODE_RUNET}){NC}")
    _box_bottom()

    mode_map = {"1": MODE_FULL, "2": MODE_SELECTIVE, "3": MODE_RUNET}
    mode_selected = MODE_FULL
    while True:
        mv = input("  Выбор [1]: ").strip() or "1"
        if mv in mode_map:
            mode_selected = mode_map[mv]
            break

    custom_ips, custom_domains = [], []
    if mode_selected == MODE_SELECTIVE:
        custom_ips, custom_domains = _prompt_selective_lists()

    ans = input(f"{YELLOW}Установить и настроить WARP? [y/N]:{NC} ").strip().lower()
    if ans != "y":
        return

    ok = configure_warp(
        mode=mode_selected,
        ssh_client_ip=ssh_ip,
        custom_ips=custom_ips,
        custom_domains=custom_domains,
    )
    if ok:
        success("✓ WARP настроен успешно!")
    else:
        warn("WARP настроен с ошибками — проверьте логи.")
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_switch_mode() -> None:
    _box_top("Смена режима маршрутизации (на лету, без рестарта wg-quick)")
    _box_row()
    _box_row(f"  1  {MODE_FULL}      — весь трафик через WARP")
    _box_row(f"  2  {MODE_SELECTIVE} — выборочные ресурсы")
    _box_row(f"  3  {MODE_RUNET}     — заблокированные РФ ресурсы")
    _box_bottom()

    mode_map = {"1": MODE_FULL, "2": MODE_SELECTIVE, "3": MODE_RUNET}
    new_mode = mode_map.get(input("  Выбор: ").strip())
    if not new_mode:
        warn("Неверный выбор.")
        time.sleep(1)
        return

    custom_ips, custom_domains = [], []
    if new_mode == MODE_SELECTIVE:
        custom_ips, custom_domains = _prompt_selective_lists()

    _state_set("WARP_MODE", new_mode)
    _state_set("WARP_CUSTOM_IPS", custom_ips)
    _state_set("WARP_CUSTOM_DOMAINS", custom_domains)
    _apply_mode(new_mode, _state_get("WARP_SSH_CLIENT_IP", ""), custom_ips, custom_domains)

    success(f"Режим бесшовно изменён на: {new_mode}")
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_status_and_diagnostics() -> None:
    _box_top("Статус и диагностика WARP")
    _box_row()

    r_show = _run(["wg", "show", WG_INTERFACE], capture=True, check=False)
    if r_show.returncode == 0 and (r_show.stdout or "").strip():
        for line in r_show.stdout.strip().splitlines()[:6]:
            _box_row(f"  {line}")
    else:
        _box_row(f"  {YELLOW}Интерфейс {WG_INTERFACE} неактивен{NC}")
    _box_row()
    _box_bottom()

    info("Проверка через Cloudflare trace...")
    r = _run(["curl", "-s", "--max-time", "10", "https://www.cloudflare.com/cdn-cgi/trace"],
             capture=True, check=False)
    trace = r.stdout or ""
    if "warp=on" in trace:
        success("✓ warp=on — трафик идёт через Cloudflare WARP.")
    elif "warp=off" in trace:
        warn("✗ warp=off — туннель неактивен либо трафик идёт мимо него.")
    else:
        warn("Не удалось получить однозначный ответ от Cloudflare trace.")

    _check_ssh_protection()


# =============================================================================
#  ГЛАВНАЯ ТОЧКА ВХОДА (НЕ МЕНЯТЬ ИМЯ/СИГНАТУРУ — вызывается из _core.py)
# =============================================================================
def do_manage_warp() -> None:
    _warp_state_load_autonomously()

    while True:
        os.system("clear")
        installed = WG_CONFIG.exists()
        active = _warp_service_active()
        mode = _state_get("WARP_MODE", "")
        ssh_ip = _state_get("WARP_SSH_CLIENT_IP", "")

        mode_labels = {
            MODE_FULL: "Весь трафик через WARP",
            MODE_SELECTIVE: "Выборочные ресурсы",
            MODE_RUNET: "Заблокированные РФ ресурсы",
            "": f"{YELLOW}не задан{NC}",
        }
        mode_str = mode_labels.get(mode, mode)
        inst_str = f"{GREEN}установлен{NC}" if installed else f"{RED}не установлен{NC}"
        svc_str  = f"{GREEN}активен{NC}" if active else f"{YELLOW}не активен{NC}"

        _box_top("CLOUDFLARE WARP (WireGuard + wgcf) — УПРАВЛЕНИЕ")
        _box_sep()
        _box_row(f"  WARP:     {inst_str}")
        _box_row(f"  Туннель:  {svc_str}")
        _box_row(f"  Режим:    {CYAN}{mode_str}{NC}")
        _box_row(f"  SSH IP:   {ssh_ip or f'{YELLOW}не задан{NC}'}  (исключён из WARP)")
        _box_row()
        _box_sep()

        if not installed:
            _box_row(f"  {GREEN}1{NC}  Установить и настроить WARP")
        else:
            action = "Остановить туннель" if active else "Запустить туннель"
            _box_row(f"  {GREEN}1{NC}  {action}")
            _box_row(f"  {GREEN}2{NC}  Сменить режим маршрутизации (на лету)")
            if mode == MODE_SELECTIVE:
                _box_row(f"  {GREEN}3{NC}  Обновить списки IP/доменов")
            _box_row(f"  {GREEN}4{NC}  Статус, диагностика и проверка SSH")
            _box_row(f"  {GREEN}5{NC}  Отключить и удалить WARP")
        _box_row()
        _box_row(f"  {RED}0{NC}  ← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            print()
            break

        if ch in ("0", "q", "Q", ""):
            break

        elif ch == "1" and not installed:
            _menu_install_wizard()

        elif ch == "1" and installed:
            if active:
                _manage_cron(False)
                _clear_active_routes()
                _run(["systemctl", "stop", WG_SERVICE], check=False)
                _state_set("WARP_CONNECTED", False)
                _warp_state_save_autonomously()
                success("Туннель WARP остановлен, маршруты сброшены.")
            else:
                _run(["systemctl", "start", WG_SERVICE], check=False)
                time.sleep(2)
                _state_set("WARP_CONNECTED", True)
                cur_mode = _state_get("WARP_MODE", MODE_FULL) or MODE_FULL
                _apply_mode(cur_mode, _state_get("WARP_SSH_CLIENT_IP", ""),
                            _state_get("WARP_CUSTOM_IPS", []), _state_get("WARP_CUSTOM_DOMAINS", []))
                success("Туннель WARP запущен, маршруты восстановлены.")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2" and installed:
            _menu_switch_mode()

        elif ch == "3" and installed and mode == MODE_SELECTIVE:
            ips, domains = _prompt_selective_lists()
            _state_set("WARP_CUSTOM_IPS", ips)
            _state_set("WARP_CUSTOM_DOMAINS", domains)
            _warp_apply_selective_mode(ips, domains)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4" and installed:
            _menu_status_and_diagnostics()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5" and installed:
            ans = input(f"{YELLOW}Вы уверены, что хотите удалить WARP? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                uninstall_warp()
            input(f"{BLUE}Нажмите Enter...{NC}")

        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
#  ТОЧКА ВХОДА ДЛЯ CRON (--sync)
# =============================================================================
if __name__ == "__main__":
    if "--sync" in sys.argv:
        _standalone_sync()
