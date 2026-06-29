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
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# При запуске файла НАПРЯМУЮ (`python3 .../warp.py --sync` из cron,
# `python3 .../warp.py --auto-rollback` из нашего systemd-run watchdog)
# Python кладёт в sys.path[0] каталог самого файла
# (.../vless_installer/modules), а НЕ корень проекта — относительный
# импорт пакета vless_installer ниже падает с ModuleNotFoundError ДО
# того, как успевает выполниться даже блок `if __name__ == "__main__":`
# в конце файла (этот импорт — на верхнем уровне модуля, выполняется при
# любом способе запуска, а не только при `import warp`). Подтверждено
# трассировкой из journalctl у Ивана: ровно эта строка импорта и падала.
# Вычисляем корень проекта от пути самого файла (а не хардкодим
# конкретную инсталляцию типа /opt/vless-ultimate — как сделано в
# fragment_watchdog.py, что ломается при другом пути установки): warp.py
# лежит в <root>/vless_installer/modules/warp.py, поэтому
# parent.parent.parent — это <root> при любой инсталляции.
if __name__ == "__main__":
    _project_root = Path(__file__).resolve().parent.parent.parent
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))

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


def _ensure_state_file() -> bool:
    """Создаёт core.STATE_FILE (и родительский каталог), если он ещё не
    существует — с пустым {}.

    НАЙДЕННЫЙ БАГ (не внесён этой правкой, но обнаружен и исправлен ею):
    _warp_state_save_autonomously() и обе новые функции
    _endpoint_cache_save()/_endpoint_history_add() проверяли
    `core.STATE_FILE.exists()` и просто молча выходили, если файла нет —
    то есть на сервере, где state.json ещё не создан какой-то другой
    частью установщика (например, при изолированном запуске/тестировании
    одного модуля WARP без полного прохождения установки Xray), ЛЮБАЯ
    персистентность WARP молча отключалась: ни режим, ни SSH IP, ни
    кастомные списки, ни кэш/история Endpoint никогда не попадали на диск,
    без единой ошибки — `warn()` даже не вызывался, потому что код просто
    возвращался раньше любой проверки. Подтверждено логом
    /var/log/vless-install.log: «state.json не найден — кэш Endpoint не
    сохранён» повторялось при каждом сканировании.

    Возвращает True, если файл существует или был успешно создан."""
    core = _core_module()
    if core.STATE_FILE.exists():
        return True
    try:
        core.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        core.STATE_FILE.write_text("{}")
        core.STATE_FILE.chmod(0o600)
        warn(f"{core.STATE_FILE} не существовал — создан пустой ({{}}).")
        return True
    except Exception as e:
        warn(f"Не удалось создать {core.STATE_FILE}: {type(e).__name__}: {e}")
        return False


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
    if not _ensure_state_file():
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

# Commit-confirm для режима FULL (см. блок ниже "COMMIT-CONFIRM"): единственный
# режим, который трогает дефолтный маршрут и поэтому единственный, способный
# оборвать текущую SSH-сессию. Таймаут — компромисс между "успеть набрать y"
# по живому каналу и "не сидеть полпути к разрыву дольше необходимого".
COMMIT_CONFIRM_TIMEOUT = 45  # секунд на подтверждение после применения FULL
ROLLBACK_UNIT          = "warp-commit-confirm"  # имя transient systemd-юнита

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
#  ENDPOINT WARP — МЕНЕДЖЕР УЗЛА ПОДКЛЮЧЕНИЯ (Anycast Cloudflare)
# =============================================================================
# Термин "Endpoint" / "узел подключения" умышленно НЕ называется "регионом":
# Cloudflare WARP работает через Anycast — один и тот же физический узел
# может обслуживать разные географии, и наоборот.
WG_CONFIG_ENDPOINT_BACKUP = Path("/etc/wireguard/wg-warp.conf.endpoint-backup")

# УТ-12: единый список портов — используется и при массовом сканировании,
# и при точечном зонде конкретного (текущего/ручного/исторического) Endpoint.
WARP_SCAN_PORTS: tuple[int, ...] = (2408, 500, 1701, 894, 4500)

# Диапазоны для автоматического поиска (п.2 ТЗ).
WARP_SCAN_RANGES: tuple[str, ...] = (
    "162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24", "162.159.197.0/24",
    "162.159.204.0/24", "162.159.239.0/24",
    "188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24",
    "188.114.100.0/24", "188.114.101.0/24", "188.114.102.0/24", "188.114.103.0/24",
    "188.114.104.0/24", "188.114.105.0/24", "188.114.106.0/24", "188.114.107.0/24",
    "172.65.4.0/24", "172.65.32.0/24",
    "104.16.10.0/24", "104.17.10.0/24",
)
WARP_HOSTS_PER_SUBNET = (2, 4)  # случайно 2–4 хоста на /24 (Anycast — весь /24 не нужен)


def _build_fallback_endpoints() -> tuple[str, ...]:
    """Fallback-список (п.1 ТЗ): фиксированные адрес:порт + .1/.10/.100 из
    каждого дополнительного диапазона. Вычисляется один раз при импорте
    модуля через ipaddress (stdlib) — не хардкодим расчётные адреса."""
    import ipaddress
    fixed = (
        "engage.cloudflareclient.com:2408",
        "162.159.192.1:2408", "162.159.193.1:500", "162.159.195.1:1701",
        "162.159.204.1:894", "162.159.239.1:4500",
    )
    extra_ranges = (
        "188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24",
        "188.114.100.0/24", "188.114.101.0/24", "188.114.102.0/24", "188.114.103.0/24",
        "188.114.104.0/24", "188.114.105.0/24", "188.114.106.0/24", "188.114.107.0/24",
        "172.65.4.0/24", "172.65.32.0/24",
        "104.16.10.0/24", "104.17.10.0/24",
    )
    generated: list[str] = []
    for cidr in extra_ranges:
        net = ipaddress.ip_network(cidr, strict=False)
        base = int(net.network_address)
        for suffix, port in ((1, 2408), (10, 500), (100, 2408)):
            generated.append(f"{ipaddress.ip_address(base + suffix)}:{port}")
    return fixed + tuple(generated)


WARP_FALLBACK_ENDPOINTS: tuple[str, ...] = _build_fallback_endpoints()

ENDPOINT_TCP_TIMEOUT          = 1.5   # сек, уровень 1 (массовый TCP-connect, УТ-3)
ENDPOINT_ICMP_TIMEOUT         = 1.0   # сек, уровень 2 (ICMP ping, если разрешён)
ENDPOINT_SWITCH_THRESHOLD_MS  = 30    # УТ-4: переключать, если RTT нового ≤ RTT текущего − 30мс
ENDPOINT_HISTORY_MAX          = 10    # УТ-6: не более 10 записей
HANDSHAKE_WAIT_ACTIVE_SEC     = 5     # УТ-2, этап 1: дождаться active
HANDSHAKE_SETTLE_SEC          = 3     # УТ-2, этап 3: пауза перед проверкой
HANDSHAKE_CURL_TIMEOUT        = 5     # УТ-2, этап 2: таймаут генерации трафика


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
    """Извлекает IP эндпоинта Cloudflare из сгенерированного конфига — для
    построения защитного маршрута в ядре (см. _ensure_endpoint_route()).

    ВАЖНО: `wgcf generate` по умолчанию пишет в Endpoint ДОМЕН
    (engage.cloudflareclient.com:2408), а не IP — это поведение самого
    wgcf, не баг установки. Старая версия этой функции матчила только
    IP-литерал и тихо возвращала None на любой свежей установке, из-за
    чего защитный маршрут к эндпоинту в _warp_apply_full_mode() не
    добавлялся вообще: после split-default (0.0.0.0/1 + 128.0.0.0/1)
    UDP-пакеты хендшейка WireGuard к самому эндпоинту Cloudflare
    заворачивались в туннель wg-warp, который этот хендшейк должен был
    сначала установить — маршрутная петля, handshake = 0.

    DNS-резолв используется ИСКЛЮЧИТЕЛЬНО для построения маршрута в ядре:
    результат никогда не записывается обратно в Endpoint конфига и не
    кешируется в state.json — живёт только в памяти на время вызова."""
    if not WG_CONFIG.exists():
        return None
    m = re.search(r"^Endpoint\s*=\s*(\S+)", WG_CONFIG.read_text(), re.MULTILINE)
    if not m:
        return None
    host = m.group(1).rsplit(":", 1)[0].strip()
    if not host:
        return None
    if re.match(r"^[\d.]+$", host):
        return host
    try:
        return socket.gethostbyname(host)
    except OSError as e:
        warn(f"Не удалось разрешить домен эндпоинта WARP ({host}): {e}")
        return None


def _get_warp_endpoint_full() -> Optional[str]:
    """Извлекает 'ip:port' текущего Endpoint (комплементарно к
    _get_warp_endpoint(), который отдаёт только IP для защитного маршрута
    в _warp_apply_full_mode — та функция не меняется)."""
    if not WG_CONFIG.exists():
        return None
    m = re.search(r"^Endpoint\s*=\s*([\d.]+:\d+)", WG_CONFIG.read_text(), re.MULTILINE)
    return m.group(1) if m else None


def _ensure_endpoint_route() -> None:
    """Единая точка добавления/поддержания защитного маршрута к эндпоинту
    Cloudflare через РЕАЛЬНЫЙ (не wg-warp) шлюз.

    Инвариант: маршрут к эндпоинту WARP никогда не должен идти через сам
    интерфейс wg-warp — иначе UDP-пакеты хендшейка WireGuard к этому же
    эндпоинту заворачиваются в туннель, который они сами должны сначала
    установить (маршрутная петля → handshake = 0, см. докстринг
    _get_warp_endpoint()).

    Идемпотентна: безопасно вызывать повторно — в т.ч. из
    _change_warp_endpoint() после смены Endpoint и из
    _warp_apply_full_mode() при каждом применении режима FULL. Не создаёт
    дублирующихся маршрутов, не использует time.sleep(), не проверяет
    handshake WireGuard (это вне её ответственности — только таблица
    маршрутизации ядра)."""
    endpoint_raw = _get_warp_endpoint_full()  # "ip:port" как в конфиге, для диагностики
    endpoint_ip = _get_warp_endpoint()
    if not endpoint_ip:
        host_part = endpoint_raw.rsplit(":", 1)[0] if endpoint_raw else "?"
        warn(f"Эндпоинт WARP ({host_part}) не определён — домен не "
             f"резолвится или строка Endpoint не найдена в конфиге. "
             f"Защитный маршрут не добавлен, риск маршрутной петли через "
             f"{WG_INTERFACE} сохраняется.")
        return

    orig = _ensure_original_route()
    if not orig or not orig[0] or not orig[1]:
        warn(f"Не удалось определить реальный шлюз сервера — защитный "
             f"маршрут к эндпоинту WARP ({endpoint_ip}) не добавлен.")
        return
    orig_gw, orig_if = orig

    def _current_route_via_kernel() -> str:
        r = _run(["ip", "route", "get", endpoint_ip], capture=True, quiet=True, check=False)
        return r.stdout or ""

    # Если маршрут к эндпоинту уже существует, но идёт через сам туннель —
    # ip route add ниже просто откажет с "File exists", и петля останется.
    # Сначала убираем неправильный маршрут.
    if WG_INTERFACE in _current_route_via_kernel():
        _run(["ip", "route", "del", f"{endpoint_ip}/32"], capture=True, quiet=True, check=False)

    def _try_add() -> tuple[bool, str]:
        r = _run(["ip", "route", "add", f"{endpoint_ip}/32", "via", orig_gw,
                   "dev", orig_if, "onlink"], capture=True, quiet=True, check=False)
        ok = r.returncode == 0 or "File exists" in (r.stderr or "")
        return ok, (r.stderr or "").strip()

    add_ok, add_err = _try_add()
    check = _current_route_via_kernel()
    route_ok = add_ok and orig_if in check and WG_INTERFACE not in check

    if not route_ok:
        # Один повтор без паузы (например, гонка с параллельным
        # применением split-default 0.0.0.0/1 + 128.0.0.0/1).
        add_ok, add_err = _try_add()
        check = _current_route_via_kernel()
        route_ok = add_ok and orig_if in check and WG_INTERFACE not in check

    if not route_ok:
        warn(f"Не удалось гарантировать защитный маршрут к эндпоинту WARP "
             f"({endpoint_ip}, в конфиге задан как {endpoint_raw or '?'}) "
             f"через {orig_if}/{orig_gw}. ip route add: "
             f"{'ok' if add_ok else (add_err or 'ошибка')}; "
             f"ip route get сейчас: {check.strip()[:200] or 'пусто'}.")


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


def _wireguard_ready() -> bool:
    """И бинарник wg-quick, И сам systemd-шаблон wg-quick@.service должны
    быть на месте. Встречаются образы VPS с частичной/битой установкой
    пакета, где одно есть, а другого нет — именно так выглядела ошибка
    'Unit wg-quick@wg-warp.service not found' при наличии самого wg-quick."""
    if not command_exists("wg-quick"):
        return False
    r = _run(["systemctl", "list-unit-files", "wg-quick@.service"], capture=True, check=False)
    return "wg-quick@.service" in (r.stdout or "")


def _ensure_wireguard_installed() -> bool:
    """Устанавливает wireguard-tools и ЯВНО проверяет результат.

    core._pkg_install() вызывает apt-get с check=False, quiet=True
    (stdout/stderr в DEVNULL) и никогда не сообщает об ошибке — если
    install молча не сработал (типичная причина на свежих образах VPS —
    протухший кэш пакетов, apt-get update никогда не вызывался), скрипт
    раньше тихо шёл дальше: скачивал wgcf, регистрировал аккаунт
    Cloudflare, генерировал конфиг — и только на systemctl start падал с
    нечитаемым 'Unit wg-quick@wg-warp.service not found', без единой
    зацепки за реальную причину. Здесь — свой explicit apt/dnf вызов с
    захватом stderr и обязательный re-check после установки (бинарник И
    systemd-юнит отдельно), до того как тратится регистрация WARP-аккаунта."""
    if _wireguard_ready():
        return True

    info("Установка пакета wireguard-tools...")
    pkg_mgr = getattr(_core_module(), "PKG_MGR", "apt")

    if pkg_mgr == "apt":
        # Свежие образы VPS нередко имеют устаревший кэш пакетов — без
        # update install иногда молча не находит актуальный пакет.
        _run(["apt-get", "update", "-q"], capture=True, check=False)
        r = _run(["apt-get", "install", "-y", "-q", "wireguard", "wireguard-tools"],
                  capture=True, check=False, env={"DEBIAN_FRONTEND": "noninteractive"})
    else:
        r = _run(["dnf", "install", "-y", "-q", "wireguard-tools"], capture=True, check=False)

    if not command_exists("wg-quick"):
        detail = (r.stderr or r.stdout or "").strip()[:300] or "(пустой вывод apt/dnf)"
        warn(f"Не удалось установить wireguard-tools: {detail}")
        warn("Установите пакет вручную (apt-get install wireguard-tools) и повторите.")
        return False

    if not _wireguard_ready():
        warn("Бинарник wg-quick найден, но systemd-юнит wg-quick@.service отсутствует "
             "— установка пакета частично повреждена.")
        warn("Проверьте: dpkg -L wireguard-tools | grep systemd; "
             "при необходимости — apt-get install --reinstall wireguard-tools.")
        return False
    return True


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
    if not _ensure_wireguard_installed():
        return False
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
    иначе полный туннель неизбежно оборвёт текущую SSH-сессию.

    ВАЖНО про `onlink`: у многих провайдеров (видно по `ip route show
    default` — `... via 10.0.0.1 dev ens3 onlink`) шлюз физически НЕ входит
    в адресный диапазон, выданный интерфейсу (типичная /32-адресация). Раз
    оригинальный default-маршрут потребовал `onlink`, чтобы ядро согласилось
    его принять, ЛЮБОЙ другой маршрут через тот же шлюз/интерфейс — в том
    числе наши защитные host-маршруты — требует ровно того же флага. Без
    него `ip route add ... via <gw> dev <if>` падает с "Network is
    unreachable" — а поскольку вызов идёт через _run(quiet=True,
    check=False), ошибка проглатывается молча: маршрут не добавляется, но
    выполнение продолжается как ни в чём не бывало, и split-default ниже
    всё равно встаёт. `onlink` добавляем безусловно (не только когда
    оригинальный маршрут был с этим флагом) — если шлюз и так лежит в
    локальной подсети, флаг просто не делает ничего ("on-link" и так
    верно), а если не лежит — без него маршрут не добавится вовсе.
    Так что `onlink` тут строго безопасен в обоих случаях."""
    info("Применение режима FULL (весь трафик через WARP)...")
    _manage_cron(False)
    _clear_active_routes()

    orig = _ensure_original_route()
    orig_gw, orig_if = orig if orig else (None, None)
    if not orig_gw:
        warn("Не удалось определить реальный шлюз сервера — защита SSH/Endpoint может не сработать.")

    _ensure_endpoint_route()

    ssh_route_ok = False
    if ssh_client_ip and orig_gw:
        ssh_cidr = ssh_client_ip if "/" in ssh_client_ip else f"{ssh_client_ip}/32"
        r_ssh = _run(["ip", "route", "add", ssh_cidr, "via", orig_gw,
                       "dev", orig_if, "onlink"], capture=True, quiet=False, check=False)
        if r_ssh.returncode == 0 or "File exists" in (r_ssh.stderr or ""):
            ssh_route_ok = True
        else:
            warn(f"Не удалось добавить защитный маршрут к SSH-клиенту "
                 f"({ssh_client_ip}): {(r_ssh.stderr or '').strip()[:200]}")
    elif not ssh_client_ip:
        warn("SSH client IP не задан — защитный маршрут к SSH не создаётся.")

    _add_route("0.0.0.0/1")
    _add_route("128.0.0.0/1")
    _warp_state_save_autonomously()

    if ssh_route_ok:
        success("Режим FULL активирован — SSH и Cloudflare Endpoint защищены.")
    else:
        warn("Режим FULL активирован, НО защитный маршрут к SSH не подтверждён — "
             "продолжайте полагаться на commit-confirm автооткат.")


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
        _apply_full_mode_with_commit_confirm(ssh_client_ip)
    elif mode == MODE_SELECTIVE:
        _warp_apply_selective_mode(custom_ips, custom_domains)
    elif mode == MODE_RUNET:
        _warp_apply_runet_mode()


# =============================================================================
#  COMMIT-CONFIRM ДЛЯ FULL-РЕЖИМА (Juniper/Cisco-style auto-rollback)
# =============================================================================
# Единственный режим, ломающий маршрут к собственной SSH-сессии — FULL (он
# единственный трогает дефолтный маршрут через split-default 0.0.0.0/1 +
# 128.0.0.0/1). Защитные host-маршруты к SSH-клиенту/эндпоинту в
# _warp_apply_full_mode() — best-effort: они зависят от того, удалось ли
# захватить шлюз (_capture_original_route — не все провайдеры отдают
# `default via X dev Y`, у некоторых это `default dev eth0 scope link` без
# `via`) и от того, актуален ли IP клиента (автоопределение через
# SSH_CLIENT/SSH_CONNECTION не работает под sudo/su, при ручном вводе можно
# опечататься или IP мог смениться). Любая из этих причин — и сколько угодно
# ещё не предусмотренных — не должна требовать ручного вмешательства через
# консоль провайдера. Поэтому здесь НЕ чиним конкретную причину, а ставим
# страховку уровня "что бы ни случилось — через N секунд откатится само":
# независимый transient systemd-таймер планируется ДО применения маршрутов
# (учли совет Ивана и сделали именно так, а не "после", иначе при разрыве
# SSH прямо во время _warp_apply_full_mode таймер просто не успел бы встать)
# и выполняет _rollback_full_mode() — БЕЗУСЛОВНУЮ остановку туннеля — если
# подтверждение не пришло вовремя. Подтверждение в свою очередь работает в
# той же самой SSH-сессии, что применяла режим: если она жива — человек
# успевает набрать "y" и таймер отменяется; если сессия упала — input()
# получает EOFError почти сразу (закрылся stdin), мы тихо выходим, а таймер
# срабатывает сам и восстанавливает доступ без участия человека.
def _schedule_rollback_watchdog(timeout_sec: int) -> bool:
    """Планирует безусловный автооткат через systemd-run --on-active.
    Намеренно простая команда без вычисления "почему откатываем" — сам
    _rollback_full_mode() ничего не диагностирует, просто гарантированно
    останавливает туннель и снимает все добавленные нами маршруты."""
    _cancel_rollback_watchdog()  # на случай висящего таймера с прошлого раза
    r = _run(
        [
            "systemd-run",
            f"--unit={ROLLBACK_UNIT}",
            f"--on-active={timeout_sec}s",
            "--description=WARP commit-confirm: автооткат FULL-режима",
            sys.executable, str(MODULE_PATH), "--auto-rollback",
        ],
        capture=True, check=False,
    )
    if r.returncode != 0:
        warn(f"Не удалось запланировать сторожевой автооткат (systemd-run): "
             f"{(r.stderr or '').strip()[:200] or 'неизвестная ошибка'}")
        return False
    return True


def _cancel_rollback_watchdog() -> None:
    """Отменяет ещё не сработавший таймер автооткат — вызывается и при
    успешном подтверждении, и превентивно перед постановкой нового."""
    _run(["systemctl", "stop", f"{ROLLBACK_UNIT}.timer"], capture=True, quiet=True, check=False)
    _run(["systemctl", "reset-failed", f"{ROLLBACK_UNIT}.service"], capture=True, quiet=True, check=False)


class _ConfirmTimeout(Exception):
    """Внутренний сигнал истечения окна подтверждения (см. _confirm_with_timeout)."""


def _confirm_with_timeout(prompt: str, timeout_sec: int) -> bool:
    """input() с жёстким wall-clock таймаутом через signal.alarm — НЕ через
    select/termios, чтобы не тянуть платформенные ограничения (Windows тут
    не актуален, модуль исполняется только на Linux-сервере, но alarm()
    проще и надёжнее прерывает блокирующий read под SIGALRM, чем опрос
    дескриптора). Если SSH-сессия порвалась, stdin закрывается и input()
    кидает EOFError даже раньше, чем долетит alarm — оба случая трактуются
    одинаково: подтверждения не было."""
    def _on_alarm(signum, frame):
        raise _ConfirmTimeout()

    old_handler = signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(timeout_sec)
    try:
        ans = input(prompt).strip().lower()
        return ans in ("y", "yes", "да", "д")
    except (_ConfirmTimeout, EOFError, KeyboardInterrupt, ValueError, OSError):
        # EOFError — обычный "чистый" обрыв канала при чтении.
        # ValueError/OSError — на случай, если stdin успел закрыться как
        # файловый объект ДО вызова input() (а не просто отдать EOF при
        # чтении) — оба исхода трактуем одинаково: подтверждения не было.
        return False
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def _rollback_full_mode() -> None:
    """Безусловный аварийный откат: останавливает туннель и снимает ВСЕ
    маршруты, учтённые в WARP_ACTIVE_ROUTES (split-default 0.0.0.0/1 +
    128.0.0.0/1, и всё, что было добавлено в SELECTIVE/RUNET до переключения
    в FULL). Намеренно не пытается восстановить orig_gw/orig_if и не читает
    ORIG_ROUTE_FILE — основной дефолтный маршрут мы никогда не трогали
    (только накладывали на него более точные split-default маршруты), так
    что простого снятия наших оверлеев достаточно для возврата к
    маршрутизации в точности как до включения WARP. Это и есть причина,
    по которой откат надёжен даже если ровно та же причина, что сломала
    SSH, мешала бы восстановить orig_gw.

    РАСШИРЕНИЕ (Endpoint-менеджер, аддитивно, не меняет логику ниже):
    _change_warp_endpoint() переиспользует ровно этот же watchdog-юнит
    (УТ-9) для смены Endpoint в FULL-режиме. Если на момент срабатывания
    watchdog существует /etc/wireguard/wg-warp.conf.endpoint-backup —
    значит откат вызван неподтверждённой сменой Endpoint, а не обычным
    включением FULL. В этом случае ПЕРЕД остановкой туннеля возвращаем
    старый конфиг — иначе при следующем запуске туннель поднялся бы уже с
    новым, непроверенным Endpoint."""
    core = _core_module()
    if WG_CONFIG_ENDPOINT_BACKUP.exists():
        core.log_to_file("WARN", "WARP commit-confirm: откат смены Endpoint — восстанавливается предыдущий конфиг.")
        try:
            WG_CONFIG.write_text(WG_CONFIG_ENDPOINT_BACKUP.read_text())
            WG_CONFIG.chmod(0o600)
        except Exception as e:
            core.log_to_file("ERROR", f"WARP commit-confirm: не удалось восстановить endpoint-backup: {e}")
        WG_CONFIG_ENDPOINT_BACKUP.unlink(missing_ok=True)

    core.log_to_file(
        "WARN",
        "WARP commit-confirm: подтверждение не получено за "
        f"{COMMIT_CONFIRM_TIMEOUT} сек — выполняется автоматический откат FULL-режима.",
    )
    _manage_cron(False)
    _clear_active_routes()
    _run(["systemctl", "stop", WG_SERVICE], capture=True, quiet=True, check=False)
    _state_set("WARP_CONNECTED", False)
    _warp_state_save_autonomously()


def _apply_full_mode_with_commit_confirm(ssh_client_ip: str) -> None:
    """Обёртка над _warp_apply_full_mode() с commit-confirm защитой.

    Порядок принципиален: таймер ставится ДО применения маршрутов — если
    процесс оборвётся (вместе с SSH) прямо посреди _warp_apply_full_mode(),
    откат всё равно сработает по расписанию независимо от живости текущего
    процесса/сессии."""
    watchdog_armed = _schedule_rollback_watchdog(COMMIT_CONFIRM_TIMEOUT)
    if not watchdog_armed:
        warn("Защитная сетка commit-confirm недоступна (нет systemd-run?) — "
             "применяем FULL без страховки, как раньше.")

    _warp_apply_full_mode(ssh_client_ip)

    if not watchdog_armed:
        return

    info(f"Изменения применены. Если связь жива — подтвердите в течение "
         f"{COMMIT_CONFIRM_TIMEOUT} сек. Если нет (или вы не успели) — "
         f"автооткат восстановит доступ сам, без вашего участия.")
    confirmed = _confirm_with_timeout(
        f"{YELLOW}SSH работает? Подтвердите [y/N]:{NC} ",
        COMMIT_CONFIRM_TIMEOUT,
    )
    if confirmed:
        _cancel_rollback_watchdog()
        success("Подтверждено — автооткат отменён, режим FULL закреплён.")
    else:
        warn(f"Подтверждение не получено — через несколько секунд (до "
             f"{COMMIT_CONFIRM_TIMEOUT} сек. с момента применения) сработает "
             f"автоматический откат и SSH будет восстановлен.")


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
#  ENDPOINT WARP — ХРАНЕНИЕ КЭША/ИСТОРИИ (мимо _WARP_STATE_MAP, п.5/УТ-6)
# =============================================================================
# _WARP_STATE_MAP — явный белый список core-глобалей (см. шапку файла), и
# расширять его не нужно: warp_endpoint_cache/warp_endpoint_history — это
# собственные данные эндпоинт-менеджера, а не состояние ядра core.WARP_*.
# Поэтому, как и _standalone_sync(), эти функции читают/пишут core.STATE_FILE
# напрямую под fcntl.flock, перечитывая файл непосредственно перед записью —
# чтобы не затереть конкурентные изменения (cron --sync, параллельная
# SSH-сессия с открытым меню).
_ENDPOINT_CACHE_KEY   = "warp_endpoint_cache"
_ENDPOINT_HISTORY_KEY = "warp_endpoint_history"


def _endpoint_cache_load() -> dict:
    core = _core_module()
    default = {"endpoints": [], "scanned_at": None, "valid": False}
    if not core.STATE_FILE.exists():
        return default
    try:
        state = json.loads(core.STATE_FILE.read_text())
    except Exception:
        return default
    cache = state.get(_ENDPOINT_CACHE_KEY)
    if not isinstance(cache, dict):
        return default
    cache.setdefault("endpoints", [])
    cache.setdefault("scanned_at", None)
    cache.setdefault("valid", False)
    return cache


def _endpoint_cache_save(endpoints: list[dict], valid: bool) -> bool:
    """УТ-14: при пустой выборке сканирования (endpoints=[]) сохраняется
    valid=False — попытка использовать такой кэш в меню даёт предупреждение
    и предложение пересканировать/взять fallback.

    Возвращает True/False — вызывающий код в меню (ветка сканирования)
    обязан проверить результат и сделать паузу перед os.system("clear"),
    иначе сообщение об ошибке физически не видно на экране (warn() в этом
    модуле и так пишет в core.log_to_file() при каждом вызове — см. шапку
    файла, строки 112–124 — поэтому в /var/log/vless-install.log сообщение
    остаётся в любом случае, даже если экран его стёр)."""
    core = _core_module()
    if not _ensure_state_file():
        return False
    import fcntl
    try:
        with core.STATE_FILE.open("r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                content = f.read()
                state = json.loads(content) if content else {}
                state[_ENDPOINT_CACHE_KEY] = {
                    "endpoints": endpoints,
                    "scanned_at": time.time(),
                    "valid": valid,
                }
                f.seek(0)
                f.truncate()
                f.write(json.dumps(state, indent=2, ensure_ascii=False))
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        return True
    except Exception as e:
        warn(f"Не удалось сохранить кэш Endpoint: {type(e).__name__}: {e}")
        return False


def _endpoint_history_load() -> list[dict]:
    core = _core_module()
    if not core.STATE_FILE.exists():
        return []
    try:
        state = json.loads(core.STATE_FILE.read_text())
    except Exception:
        return []
    history = state.get(_ENDPOINT_HISTORY_KEY, [])
    return history if isinstance(history, list) else []


def _endpoint_history_add(endpoint: str) -> None:
    """УТ-6: не более 10 записей; повторное использование — обновляет
    used_at и поднимает запись в начало, без дублей."""
    core = _core_module()
    if not _ensure_state_file():
        return
    import fcntl
    try:
        with core.STATE_FILE.open("r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                content = f.read()
                state = json.loads(content) if content else {}
                history = state.get(_ENDPOINT_HISTORY_KEY, [])
                if not isinstance(history, list):
                    history = []
                history = [h for h in history if h.get("endpoint") != endpoint]
                history.insert(0, {"endpoint": endpoint, "used_at": time.time()})
                state[_ENDPOINT_HISTORY_KEY] = history[:ENDPOINT_HISTORY_MAX]
                f.seek(0)
                f.truncate()
                f.write(json.dumps(state, indent=2, ensure_ascii=False))
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        warn(f"Не удалось обновить историю Endpoint: {type(e).__name__}: {e}")


# =============================================================================
#  ENDPOINT WARP — ЗОНДИРОВАНИЕ (уровни 1–2, п.3 ТЗ)
# =============================================================================
def _tcp_probe(host: str, port: int, timeout: float = ENDPOINT_TCP_TIMEOUT) -> Optional[float]:
    """Уровень 1: TCP-connect зонд, RTT в мс или None.
    УТ-3: UDP-зонд для WireGuard не работает (сервер молча дропает любой
    пакет, не являющийся валидным handshake-init) — поэтому используем
    TCP-connect как массовый фильтр 'узел отвечает / не отвечает'.
    Достоверное подтверждение реального WARP-трафика на конкретном Endpoint
    даёт только сам handshake-чек в _verify_warp_handshake(), выполняемый
    один раз — на этапе применения, а не на этапе массового сканирования."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (time.perf_counter() - start) * 1000.0
    except OSError:
        return None


def _icmp_probe(host: str, timeout: float = ENDPOINT_ICMP_TIMEOUT) -> bool:
    """Уровень 2: ICMP ping через системный бинарь — как и весь остальной
    модуль (curl/wg/ip/systemctl), внешние проверки идут через _run().
    Если ping недоступен или ICMP блокирован — просто False, без ошибки
    (п.3 ТЗ: 'ICMP ping, если разрешён')."""
    if not command_exists("ping"):
        return False
    r = _run(
        ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), host],
        capture=True, check=False,
    )
    return r.returncode == 0


def _select_scan_targets() -> list[str]:
    """Из каждой /24 берёт 2–4 случайных хоста (Anycast — сканировать все
    254 адреса избыточно: весь /24 отвечает с одной логической точки входа
    Cloudflare). .hosts() уже исключает адрес сети и broadcast."""
    import ipaddress
    import random
    targets: list[str] = []
    for cidr in WARP_SCAN_RANGES:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        if not hosts:
            continue
        k = min(len(hosts), random.randint(*WARP_HOSTS_PER_SUBNET))
        targets.extend(str(h) for h in random.sample(hosts, k))
    return targets


def _probe_host_all_ports(host: str) -> Optional[dict]:
    """УТ-12: проверяет ОДИН хост по ВСЕМ портам из WARP_SCAN_PORTS,
    возвращает лучший (минимальный RTT) сработавший порт + результат ICMP.
    None, если ни один порт не ответил."""
    best_port: Optional[int] = None
    best_rtt: Optional[float] = None
    for port in WARP_SCAN_PORTS:
        rtt = _tcp_probe(host, port)
        if rtt is not None and (best_rtt is None or rtt < best_rtt):
            best_port, best_rtt = port, rtt
    if best_port is None:
        return None
    return {
        "host": host,
        "port": best_port,
        "rtt_ms": round(best_rtt, 1),
        "tcp_ok": True,
        "icmp_ok": _icmp_probe(host),
    }


def _score_probe(result: dict) -> float:
    """score = (tcp_ok?50:0) + (icmp_ok?30:0) + max(0, 20 − rtt_ms/10) — формула из п.3 ТЗ."""
    tcp_part = 50.0 if result.get("tcp_ok") else 0.0
    icmp_part = 30.0 if result.get("icmp_ok") else 0.0
    rtt_ms = result.get("rtt_ms")
    rtt_part = max(0.0, 20.0 - (rtt_ms / 10.0)) if rtt_ms is not None else 0.0
    return tcp_part + icmp_part + rtt_part


def _scan_warp_endpoints() -> list[dict]:
    """Параллельное сканирование WARP_SCAN_RANGES (п.2 ТЗ). Только Python +
    stdlib (socket, concurrent.futures, ipaddress, random) + системные
    ping/curl, уже используемые в остальном модуле.
    УТ-7: ThreadPoolExecutor(max_workers=min(100,len(targets))); на
    KeyboardInterrupt — немедленный cancel_futures=True, без ожидания
    зависших проверок."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    targets = _select_scan_targets()
    if not targets:
        warn("Не удалось сформировать список адресов для сканирования.")
        return []

    info(f"Сканирование {len(targets)} адресов Cloudflare WARP "
         f"(до {len(WARP_SCAN_PORTS)} портов на хост, таймаут {ENDPOINT_TCP_TIMEOUT}с)... "
         f"Ctrl+C — прервать.")

    results: list[dict] = []
    max_workers = min(100, max(1, len(targets)))
    executor = ThreadPoolExecutor(max_workers=max_workers)
    futures = {executor.submit(_probe_host_all_ports, h): h for h in targets}
    try:
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
    except KeyboardInterrupt:
        warn("Сканирование прервано пользователем — отменяю незавершённые проверки...")
        executor.shutdown(wait=False, cancel_futures=True)
        return []
    executor.shutdown(wait=True)

    for r in results:
        r["score"] = round(_score_probe(r), 1)
        r["endpoint"] = f"{r['host']}:{r['port']}"
    results.sort(key=lambda x: x["score"], reverse=True)
    top5 = results[:5]

    if top5:
        success(f"Найдено {len(results)} отвечающих узлов, в топ-5 — score "
                f"{top5[0]['score']}–{top5[-1]['score']}.")
    else:
        warn("Сканирование не нашло ни одного отвечающего узла.")
    return top5


def _probe_single_endpoint(endpoint: str) -> dict:
    """Быстрый зонд одного известного 'ip:port' (текущий / из истории /
    введённый вручную / fallback) — TCP на указанный порт + ICMP (п.7 ТЗ:
    'перед применением — проверить доступность')."""
    try:
        host, port_s = endpoint.rsplit(":", 1)
        port = int(port_s)
    except ValueError:
        return {"endpoint": endpoint, "tcp_ok": False, "icmp_ok": False, "rtt_ms": None}
    rtt = _tcp_probe(host, port)
    icmp_ok = _icmp_probe(host) if rtt is not None else False
    return {
        "endpoint": endpoint,
        "tcp_ok": rtt is not None,
        "icmp_ok": icmp_ok,
        "rtt_ms": round(rtt, 1) if rtt is not None else None,
    }


def _pick_best_endpoint(candidates: list[dict]) -> tuple[Optional[str], str]:
    """Интеллектуальный подбор (п.4 ТЗ, УТ-4): переключать ТОЛЬКО если
    текущий недоступен ИЛИ RTT нового ≤ RTT текущего − 30мс И новый
    доступен по TCP+ICMP одновременно. Иначе — None и причина (для
    информирования, без переключения)."""
    if not candidates:
        return None, "Список кандидатов пуст — пересканируйте или используйте fallback."

    current = _get_warp_endpoint_full()
    current_probe = (
        _probe_single_endpoint(current) if current
        else {"endpoint": None, "tcp_ok": False, "icmp_ok": False, "rtt_ms": None}
    )

    best = candidates[0]
    if not current_probe["tcp_ok"]:
        return best["endpoint"], f"Текущий Endpoint ({current or 'не задан'}) недоступен."

    if not (best.get("tcp_ok") and best.get("icmp_ok")):
        return None, (f"Лучший найденный кандидат {best['endpoint']} не проходит TCP+ICMP "
                       f"одновременно — текущий ({current}) сохраняется.")

    cur_rtt, new_rtt = current_probe["rtt_ms"], best.get("rtt_ms")
    if cur_rtt is None or new_rtt is None:
        return None, "Не удалось измерить RTT для сравнения — текущий Endpoint сохраняется."

    if new_rtt <= cur_rtt - ENDPOINT_SWITCH_THRESHOLD_MS:
        return best["endpoint"], (f"Новый узел {best['endpoint']} быстрее текущего на "
                                   f"{cur_rtt - new_rtt:.0f} мс — рекомендуется переключение.")
    return None, (f"Текущий Endpoint ({current}, {cur_rtt:.0f} мс) не хуже найденных "
                  f"(порог {ENDPOINT_SWITCH_THRESHOLD_MS} мс) — переключение не требуется.")


# =============================================================================
#  ENDPOINT WARP — ПРОВЕРКА HANDSHAKE (уровень 3, п.3/УТ-2)
# =============================================================================
def _verify_warp_handshake() -> tuple[bool, bool]:
    """Трёхэтапная проверка (УТ-2): (1) дождаться active, (2) сгенерировать
    трафик curl'ом через интерфейс wg-warp на cdn-cgi/trace, (3) подождать
    HANDSHAKE_SETTLE_SEC и проверить latest-handshakes>0 И warp=on.
    Возвращает (handshake_ok, warp_on) — rollback в вызывающем коде
    выполняется только если ОБА условия не выполнены."""
    deadline = time.time() + HANDSHAKE_WAIT_ACTIVE_SEC
    active = False
    while time.time() < deadline:
        if _warp_service_active():
            active = True
            break
        time.sleep(0.5)
    if not active:
        return False, False

    r_trace = _run(
        ["curl", "-s", "--interface", WG_INTERFACE, "--max-time", str(HANDSHAKE_CURL_TIMEOUT),
         "https://www.cloudflare.com/cdn-cgi/trace"],
        capture=True, check=False,
    )
    time.sleep(HANDSHAKE_SETTLE_SEC)

    r_hs = _run(["wg", "show", WG_INTERFACE, "latest-handshakes"], capture=True, check=False)
    handshake_ok = False
    for line in (r_hs.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("-").isdigit() and int(parts[-1]) > 0:
            handshake_ok = True
            break

    warp_on = "warp=on" in (r_trace.stdout or "")
    return handshake_ok, warp_on


def _restore_endpoint_backup() -> bool:
    """Восстанавливает /etc/wireguard/wg-warp.conf из endpoint-backup и
    перезапускает wg-quick@wg-warp. Используется и синхронным rollback'ом
    внутри _change_warp_endpoint() (Selective/Runet и преждевременный фейл
    в Full — до переприменения маршрутов), и (отдельно, см. выше)
    расширённым _rollback_full_mode() при срабатывании watchdog."""
    if not WG_CONFIG_ENDPOINT_BACKUP.exists():
        return _warp_service_active()
    WG_CONFIG.write_text(WG_CONFIG_ENDPOINT_BACKUP.read_text())
    WG_CONFIG.chmod(0o600)
    WG_CONFIG_ENDPOINT_BACKUP.unlink(missing_ok=True)
    _run(["systemctl", "restart", WG_SERVICE], capture=True, quiet=True, check=False)
    time.sleep(2)
    return _warp_service_active()


# =============================================================================
#  ENDPOINT WARP — СМЕНА ENDPOINT (п.8 ТЗ)
# =============================================================================
def _change_warp_endpoint(new_endpoint: str) -> bool:
    """Меняет активный Endpoint WARP ('ip:port'). Рестарт wg-quick@wg-warp —
    единственное разрешённое исключение из правила "переключение без
    рестарта" (УТ-1).

    ЗАЩИТА SSH (приоритет №1): SSH-клиент защищён отдельным host-маршрутом
    через orig_gw/orig_if (см. _warp_apply_full_mode) — этот маршрут НЕ
    привязан к интерфейсу wg-warp и переживает его рестарт без изменений.
    Default-маршрутизация (split-default 0.0.0.0/1+128.0.0.0/1, единственное,
    что реально способно оборвать SSH) переприменяется ТОЛЬКО ПОСЛЕ того,
    как новый Endpoint уже подтверждён живым handshake'ом — до этого момента
    при любой ошибке откатываемся синхронно сами, риска для SSH не возникает
    вовсе. Сам момент переприменения (и при успехе, и при восстановлении
    после ошибки) — защищён ровно тем же commit-confirm watchdog'ом, что и
    обычное включение FULL-режима (УТ-9: используется тот же
    `warp-commit-confirm` юнит) — никакого отдельного, менее надёжного
    механизма для Endpoint-менеджера не вводится."""
    if not WG_CONFIG.exists():
        warn("WARP не установлен — менять Endpoint нечего.")
        return False

    current = _get_warp_endpoint_full()
    if current == new_endpoint:
        info(f"Endpoint {new_endpoint} уже используется — изменений не требуется.")
        return True

    info(f"Проверка доступности {new_endpoint} перед применением...")
    if not _probe_single_endpoint(new_endpoint)["tcp_ok"]:
        warn(f"Endpoint {new_endpoint} не отвечает (TCP) — отклонён, текущий Endpoint сохранён.")
        return False

    mode = _state_get("WARP_MODE", MODE_FULL) or MODE_FULL
    ssh_ip = _state_get("WARP_SSH_CLIENT_IP", "")
    custom_ips = _state_get("WARP_CUSTOM_IPS", [])
    custom_domains = _state_get("WARP_CUSTOM_DOMAINS", [])

    if mode == MODE_FULL:
        warn("Активен режим FULL — смена Endpoint меняет точку выхода ВСЕГО трафика "
             "и может вызвать кратковременное прерывание связи на несколько секунд.")
        if input(f"{YELLOW}Продолжить смену Endpoint? [y/N]:{NC} ").strip().lower() != "y":
            info("Смена Endpoint отменена.")
            return False

    old_conf = WG_CONFIG.read_text()
    new_conf = re.sub(r"^Endpoint\s*=\s*\S+", f"Endpoint = {new_endpoint}", old_conf, flags=re.MULTILINE)
    if new_conf == old_conf:
        warn("Не удалось найти строку Endpoint в конфиге — смена отменена.")
        return False

    WG_CONFIG_ENDPOINT_BACKUP.write_text(old_conf)   # УТ-11
    WG_CONFIG_ENDPOINT_BACKUP.chmod(0o600)

    watchdog_armed = False
    if mode == MODE_FULL:
        watchdog_armed = _schedule_rollback_watchdog(COMMIT_CONFIRM_TIMEOUT)
        if not watchdog_armed:
            warn("Защитная сетка commit-confirm недоступна (нет systemd-run?) — "
                 "продолжаем без неё, как и при первом включении FULL.")

    WG_CONFIG.write_text(new_conf)
    WG_CONFIG.chmod(0o600)
    info(f"Endpoint изменён на {new_endpoint}. Перезапуск {WG_SERVICE}...")
    r_restart = _run(["systemctl", "restart", WG_SERVICE], capture=True, check=False)

    restart_ok = r_restart.returncode == 0
    handshake_ok = warp_on = False
    if restart_ok:
        handshake_ok, warp_on = _verify_warp_handshake()

    # УТ-2: rollback только если ОБА условия (handshake И warp=on) не выполнены.
    healthy = restart_ok and (handshake_ok or warp_on)

    if not healthy:
        warn("Восстановление связи через новый Endpoint не подтверждено "
             f"(restart={'ok' if restart_ok else 'fail'}, "
             f"handshake={'ok' if handshake_ok else 'fail'}, warp={'on' if warp_on else 'off'}).")
        if watchdog_armed:
            # Маршруты FULL-режима к НОВОМУ endpoint'у ещё не переприменялись
            # (см. ниже) — SSH всё это время был защищён прежним host-маршрутом
            # через orig_gw, не через wg-warp. Откатываемся синхронно сами,
            # не дожидаясь срабатывания таймера.
            _cancel_rollback_watchdog()
        warn("Откат конфигурации и восстановление предыдущего рабочего состояния...")
        _restore_endpoint_backup()
        _apply_mode(mode, ssh_ip, custom_ips, custom_domains)
        warn("Откат выполнен — Endpoint и маршруты возвращены к предыдущему рабочему состоянию.")
        return False

    # п.12/УТ-13: маршруты восстанавливаются строго существующими механизмами.
    if mode == MODE_FULL:
        _warp_apply_full_mode(ssh_ip)
    else:
        _apply_mode(mode, ssh_ip, custom_ips, custom_domains)

    if mode == MODE_FULL and watchdog_armed:
        info(f"Маршруты переприменены. Если связь жива — подтвердите в течение "
             f"{COMMIT_CONFIRM_TIMEOUT} сек. Если нет — автооткат восстановит и Endpoint, "
             f"и маршруты сам, без вашего участия.")
        if _confirm_with_timeout(f"{YELLOW}SSH работает? Подтвердите [y/N]:{NC} ", COMMIT_CONFIRM_TIMEOUT):
            _cancel_rollback_watchdog()
        else:
            warn(f"Подтверждение не получено — в течение {COMMIT_CONFIRM_TIMEOUT} сек "
                 f"сработает автоматический откат (Endpoint + маршруты), SSH будет восстановлен.")
            return False

    WG_CONFIG_ENDPOINT_BACKUP.unlink(missing_ok=True)  # УТ-11: удаляется после успешного подтверждения
    _state_set("WARP_CONNECTED", True)
    _warp_state_save_autonomously()
    _endpoint_history_add(new_endpoint)
    success(f"Endpoint WARP изменён на {new_endpoint}.")
    return True


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
def _show_endpoint_pick_list(candidates: list[dict], title: str) -> None:
    """Общий список выбора для результатов скана / кэша / fallback —
    показывает RTT/score, если они есть, и применяет выбранный Endpoint."""
    if not candidates:
        warn("Список пуст.")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    os.system("clear")
    _box_top(title)
    _box_row()
    for i, c in enumerate(candidates, start=1):
        extra = ""
        if c.get("rtt_ms") is not None:
            extra = f"  RTT={c['rtt_ms']}мс  score={c.get('score', '?')}" \
                    f"{'  ICMP+' if c.get('icmp_ok') else ''}"
        _box_row(f"  {GREEN}{i}{NC}  {c['endpoint']}{extra}")
    _box_row()
    _box_row(f"  {RED}0{NC}  ← Назад")
    _box_bottom()

    choice = input("  Выбор: ").strip()
    if not choice or choice == "0":
        return
    if not choice.isdigit() or not (1 <= int(choice) <= len(candidates)):
        warn("Неверный выбор.")
        time.sleep(1)
        return

    chosen = candidates[int(choice) - 1]["endpoint"]
    if input(f"{YELLOW}Применить Endpoint {chosen}? [y/N]:{NC} ").strip().lower() == "y":
        _change_warp_endpoint(chosen)
    input(f"{BLUE}Нажмите Enter...{NC}")


def _show_history_pick_list(history: list[dict]) -> None:
    os.system("clear")
    _box_top("История использованных Endpoint")
    _box_row()
    for i, h in enumerate(history, start=1):
        used = time.strftime("%Y-%m-%d %H:%M", time.localtime(h.get("used_at", 0)))
        _box_row(f"  {GREEN}{i}{NC}  {h['endpoint']}  (использован: {used})")
    _box_row()
    _box_row(f"  {RED}0{NC}  ← Назад")
    _box_bottom()

    choice = input("  Выбор: ").strip()
    if not choice or choice == "0":
        return
    if not choice.isdigit() or not (1 <= int(choice) <= len(history)):
        warn("Неверный выбор.")
        time.sleep(1)
        return

    chosen = history[int(choice) - 1]["endpoint"]
    if input(f"{YELLOW}Применить Endpoint {chosen}? [y/N]:{NC} ").strip().lower() == "y":
        _change_warp_endpoint(chosen)
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_endpoint_manager() -> None:
    """Подменю 'Изменить Endpoint WARP' (п.15 ТЗ): текущий Endpoint, кэш,
    история, ручной ввод, fallback, интеллектуальный подбор."""
    while True:
        os.system("clear")
        current = _get_warp_endpoint_full() or "не задан"
        cache = _endpoint_cache_load()
        scanned_at = cache.get("scanned_at")
        scanned_str = (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scanned_at))
            if scanned_at else "никогда"
        )
        cache_status = f"{GREEN}актуален{NC}" if cache.get("valid") else f"{YELLOW}неактуален{NC}"

        _box_top("УПРАВЛЕНИЕ ENDPOINT WARP")
        _box_row()
        _box_row("  'Endpoint' ≠ регион: Cloudflare использует Anycast — один")
        _box_row("  физический узел может обслуживать разные географии.")
        _box_row()
        _box_row(f"  Текущий Endpoint:  {CYAN}{current}{NC}")
        _box_row(f"  Кэш сканирования:  {len(cache.get('endpoints', []))} узлов, {cache_status} "
                  f"(проверен: {scanned_str})")
        _box_row()
        _box_sep()
        _box_row(f"  {GREEN}1{NC}  Подобрать лучший Endpoint (авто-сравнение с текущим)")
        _box_row(f"  {GREEN}2{NC}  Сканировать заново и выбрать из топ-5")
        _box_row(f"  {GREEN}3{NC}  Выбрать из кэша последнего сканирования")
        _box_row(f"  {GREEN}4{NC}  Выбрать из истории")
        _box_row(f"  {GREEN}5{NC}  Ввести Endpoint вручную (ip:port)")
        _box_row(f"  {GREEN}6{NC}  Использовать fallback-список")
        _box_row()
        _box_row(f"  {RED}0{NC}  ← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            print()
            return

        if ch in ("0", "q", "Q", ""):
            return

        elif ch == "1":
            candidates = cache.get("endpoints", []) if cache.get("valid") else []
            if not candidates:
                info("Актуального кэша нет — выполняется сканирование...")
                candidates = _scan_warp_endpoints()
                _endpoint_cache_save(candidates, valid=bool(candidates))
            best, reason = _pick_best_endpoint(candidates)
            info(reason)
            if best:
                if input(f"{YELLOW}Переключиться на {best}? [y/N]:{NC} ").strip().lower() == "y":
                    _change_warp_endpoint(best)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            try:
                candidates = _scan_warp_endpoints()
            except KeyboardInterrupt:
                candidates = []
            if not _endpoint_cache_save(candidates, valid=bool(candidates)):
                input(f"{BLUE}Нажмите Enter, чтобы продолжить...{NC}")
            _show_endpoint_pick_list(candidates, "Результаты сканирования (топ-5)")

        elif ch == "3":
            fresh_cache = _endpoint_cache_load()
            if not fresh_cache.get("valid") or not fresh_cache.get("endpoints"):
                warn("Кэш пуст или помечен неактуальным — выберите пересканирование (2) "
                     "или fallback-список (6).")
                input(f"{BLUE}Нажмите Enter...{NC}")
            else:
                _show_endpoint_pick_list(fresh_cache["endpoints"], "Узлы из кэша")

        elif ch == "4":
            history = _endpoint_history_load()
            if not history:
                warn("История пуста.")
                input(f"{BLUE}Нажмите Enter...{NC}")
            else:
                _show_history_pick_list(history)

        elif ch == "5":
            raw = input("  Введите Endpoint в формате ip:port: ").strip()
            if not raw or ":" not in raw:
                warn("Неверный формат — ожидается ip:port.")
            else:
                probe = _probe_single_endpoint(raw)
                if not probe["tcp_ok"]:
                    warn(f"Endpoint {raw} не отвечает (TCP) — отклонён.")
                else:
                    _change_warp_endpoint(raw)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "6":
            _show_endpoint_pick_list(
                [{"endpoint": ep, "rtt_ms": None} for ep in WARP_FALLBACK_ENDPOINTS],
                "Fallback-список (без предварительной проверки)",
            )

        else:
            warn("Неверный выбор.")
            time.sleep(1)


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
            _box_row(f"  {GREEN}6{NC}  Изменить Endpoint WARP (узел подключения)")
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

        elif ch == "6" and installed:
            _menu_endpoint_manager()

        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
#  ТОЧКА ВХОДА ДЛЯ CRON (--sync)
# =============================================================================
if __name__ == "__main__":
    if "--sync" in sys.argv:
        _standalone_sync()
    elif "--auto-rollback" in sys.argv:
        # Точка входа для transient systemd-юнита, поставленного
        # _schedule_rollback_watchdog(). Отдельный процесс, как и --sync —
        # сначала обязательно подгружаем WARP_* состояние из state.json
        # (в свежем процессе core.WARP_ACTIVE_ROUTES ещё не существует).
        _warp_state_load_autonomously()
        _rollback_full_mode()
