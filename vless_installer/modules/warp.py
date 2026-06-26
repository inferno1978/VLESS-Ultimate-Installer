"""
vless_installer/modules/warp.py
───────────────────────────────────────────────────────────────────────────────
Cloudflare WARP — установка и управление из интерактивного меню.

  • Режимы: full (весь трафик), selective (только РФ подсети), runet (только РФ)
  • SSH namespace защита (warp-ssh-ns) — SSH всегда идёт в обход WARP
  • Сохранение/восстановление состояния через state.json
  • Интеграция с whitelist IP и custom domains

Точка входа из _core.py:
    from vless_installer.modules.warp import do_manage_warp
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        else:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
            )
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] {clean}\n")
    except Exception:
        pass

def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO",    msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN",   msg)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

# ── Делегируем в _core через importlib ────────────────────────────────────────
def _core_call(func_name: str, *args, **kwargs):
    import importlib
    _core = importlib.import_module("vless_installer._core")
    return getattr(_core, func_name)(*args, **kwargs)

def command_exists(cmd: str) -> bool:
    return _core_call("command_exists", cmd)

def _pkg_install(*pkgs: str) -> None:
    _core_call("_pkg_install", *pkgs)

def _get_pkg_mgr() -> str:
    try:
        import importlib
        _core = importlib.import_module("vless_installer._core")
        return getattr(_core, "PKG_MGR", "apt")
    except Exception:
        return "apt"

# WARP-глобали — читаем/пишем через _core
def _get_warp(attr: str, default=None):
    try:
        import importlib
        return getattr(importlib.import_module("vless_installer._core"), attr, default)
    except Exception:
        return default

def _set_warp(attr: str, val) -> None:
    try:
        import importlib
        setattr(importlib.import_module("vless_installer._core"), attr, val)
    except Exception:
        pass

# ── Импорты из других модулей ─────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_item_exit,
    _box_ok, _box_warn, _box_info, _box_desc,
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
)

# ── Константы ─────────────────────────────────────────────────────────────────
WARP_SSH_NS_SERVICE = Path("/etc/systemd/system/warp-ssh-ns.service")
_STATE_FILE         = Path("/var/lib/xray-installer/state.json")


WARP_SSH_NS_SERVICE  = Path("/etc/systemd/system/warp-ssh-ns.service")
WARP_RUNET_CIDRS_URL = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat"

# Файл с РЕАЛЬНЫМ (не-WARP) дефолтным маршрутом сервера, захваченным ДО того,
# как WARP подключился и подменил собственный default route. Все сгенерированные
# скрипты (warp-ssh-protect.sh, warp-runet.sh) ОБЯЗАНЫ читать шлюз отсюда, а не
# пересчитывать `ip route show default` сами — иначе после подключения WARP
# любой такой пересчёт поймает уже сам WARP вместо настоящего шлюза, и "защита"
# от WARP начнёт сама маршрутизировать защищаемый трафик обратно в WARP.
_ORIG_ROUTE_FILE = Path("/etc/warp-original-route.conf")


# ── Вспомогательные функции ──────────────────────────────────────────────────

def _warp_is_installed() -> bool:
    """Проверяет наличие warp-cli и warp-svc."""
    return command_exists("warp-cli") and (
        Path("/usr/bin/warp-svc").exists()
        or Path("/usr/local/bin/warp-svc").exists()
        or command_exists("warp-svc")
    )


def _warp_service_active() -> bool:
    r = _run(["systemctl", "is-active", "warp-svc"], capture=True, check=False)
    return r.stdout.strip() == "active"


def _warp_cli(*args: str, quiet: bool = True) -> subprocess.CompletedProcess:
    """Выполняет warp-cli с аргументами. Возвращает результат."""
    return _run(["warp-cli", *args], capture=True, check=False, quiet=quiet)


def _warp_status() -> str:
    """Возвращает строку статуса: Connected / Disconnected / ??? """
    r = _warp_cli("status")
    out = r.stdout.strip()
    if "Connected" in out:
        return "Connected"
    if "Disconnected" in out:
        return "Disconnected"
    return out.splitlines()[0] if out else "Unknown"


def _warp_verify_connected() -> bool:
    """Проверяет warp=on через Cloudflare trace."""
    r = _run(
        ["curl", "-s", "--max-time", "10",
         "https://www.cloudflare.com/cdn-cgi/trace"],
        capture=True, check=False
    )
    return "warp=on" in r.stdout


# ── Установка WARP ───────────────────────────────────────────────────────────

def install_warp() -> bool:
    """
    Устанавливает cloudflare-warp из официального репозитория Cloudflare.
    Поддерживает apt (Ubuntu/Debian) и dnf/yum (RHEL/CentOS).
    Возвращает True при успехе.
    """

    if _warp_is_installed():
        _box_info("Cloudflare WARP уже установлен — пропускаем установку")
        _set_warp("WARP_INSTALLED", True)
        return True

    _box_info("Установка Cloudflare WARP...")

    if _get_pkg_mgr() == "apt":
        # Добавляем GPG-ключ Cloudflare
        keyring = Path("/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg")
        r = _run([
            "curl", "-fsSL", "--connect-timeout", "15",
            "https://pkg.cloudflareclient.com/pubkey.gpg",
            "-o", "/tmp/cf-warp.gpg",
        ], check=False, quiet=True)
        if r.returncode != 0:
            _box_warn("Не удалось скачать GPG-ключ Cloudflare WARP")
            return False

        _run([
            "gpg", "--yes", "--dearmor",
            "--output", str(keyring),
            "/tmp/cf-warp.gpg",
        ], check=False, quiet=True)
        Path("/tmp/cf-warp.gpg").unlink(missing_ok=True)

        # Определяем codename дистрибутива
        r2 = _run(["lsb_release", "-cs"], capture=True, check=False)
        codename = r2.stdout.strip() or "focal"

        # Добавляем репозиторий
        repo_line = (
            f"deb [signed-by={keyring}] "
            f"https://pkg.cloudflareclient.com/ {codename} main"
        )
        Path("/etc/apt/sources.list.d/cloudflare-client.list").write_text(
            repo_line + "\n"
        )

        _run(["apt-get", "update", "-q"], check=False, quiet=True)
        r3 = _run([
            "apt-get", "install", "-y", "-q", "cloudflare-warp",
        ], env={"DEBIAN_FRONTEND": "noninteractive"},
            capture=True, check=False)

        if r3.returncode != 0:
            # Попробуем jammy если текущий codename не поддерживается
            _box_warn(f"Не удалось установить WARP для {codename} — пробуем jammy...")
            repo_line_jammy = (
                f"deb [signed-by={keyring}] "
                f"https://pkg.cloudflareclient.com/ jammy main"
            )
            Path("/etc/apt/sources.list.d/cloudflare-client.list").write_text(
                repo_line_jammy + "\n"
            )
            _run(["apt-get", "update", "-q"], check=False, quiet=True)
            _run([
                "apt-get", "install", "-y", "-q", "cloudflare-warp",
            ], env={"DEBIAN_FRONTEND": "noninteractive"},
                check=False, quiet=True)

    elif _get_pkg_mgr() == "dnf":
        _run([
            "rpm", "--import",
            "https://pkg.cloudflareclient.com/pubkey.gpg",
        ], check=False, quiet=True)

        r4 = _run(["lsb_release", "-rs"], capture=True, check=False)
        ver = r4.stdout.strip().split(".")[0] or "8"
        repo_content = textwrap.dedent(f"""\
            [cloudflare-warp]
            name=Cloudflare WARP
            baseurl=https://pkg.cloudflareclient.com/rpm/el{ver}/
            enabled=1
            gpgcheck=1
            gpgkey=https://pkg.cloudflareclient.com/pubkey.gpg
        """)
        Path("/etc/yum.repos.d/cloudflare-warp.repo").write_text(repo_content)
        _run(["dnf", "install", "-y", "cloudflare-warp"], check=False, quiet=True)

    # Проверяем результат
    if not _warp_is_installed():
        _box_warn("Cloudflare WARP не установился — warp-cli не найден")
        return False

    # Запускаем сервис
    _run(["systemctl", "enable", "warp-svc"], check=False, quiet=True)
    _run(["systemctl", "start",  "warp-svc"], check=False, quiet=True)

    # Ждём запуска
    for _ in range(20):
        if _warp_service_active():
            break
        time.sleep(1)

    if not _warp_service_active():
        _box_warn("warp-svc не запустился — попытка перезапуска...")
        _run(["systemctl", "restart", "warp-svc"], check=False, quiet=True)
        time.sleep(5)

    if _warp_service_active():
        _set_warp("WARP_INSTALLED", True)
        _box_ok("Cloudflare WARP установлен и сервис запущен")
        return True
    else:
        _box_warn("warp-svc не активен — проверьте: journalctl -u warp-svc -n 20")
        return False


# ── SSH Namespace: изоляция SSH от WARP ─────────────────────────────────────

def _warp_create_ssh_namespace() -> bool:
    """
    Создаёт отдельный network namespace для SSH-соединений.
    SSH-демон остаётся слушать на основном интерфейсе, но входящие
    SSH-соединения маршрутизируются МИМО WARP-туннеля через veth-пару.

    Схема:
      [SSH клиент] → eth0 (основной интерфейс, не в WARP для SSH)
                   → iptables PREROUTING mark → не затрагивается WARP

    Для consumer-WARP (без Zero Trust) используем более простой и надёжный
    подход: исключаем IP SSH-клиента из WARP split tunnel (exclude mode).
    Дополнительно создаём systemd-сервис с правилом iptables, который
    защищает порт 22 от попадания в WARP при любых режимах.
    """
    _box_info("Настройка защиты SSH от WARP (iptables mark + маршрутизация)...")

    orig = _load_original_route()
    if orig is None:
        _box_warn(
            "Не найден сохранённый исходный шлюз (/etc/warp-original-route.conf) — "
            "SSH-защита не настроена, чтобы не маршрутизировать SSH обратно в WARP. "
            "Выполните `warp-cli disconnect`, перезапустите настройку WARP заново."
        )
        return False
    orig_gw, orig_if = orig

    # Создаём скрипт защиты SSH
    ssh_protect_script = Path("/usr/local/bin/warp-ssh-protect.sh")
    ssh_protect_script.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # Защита SSH от WARP-туннеля
        # Помечаем пакеты SSH (порт 22) специальным fwmark и направляем
        # их через РЕАЛЬНЫЙ шлюз сервера, минуя WARP.
        #
        # ВАЖНО: MAIN_GW/MAIN_IF здесь — литералы, зафиксированные ДО подключения
        # WARP (см. _capture_original_route() в warp.py), а не результат
        # `ip route show default`, выполненного в момент запуска этого скрипта.
        # Если WARP уже подключён в момент запуска, "текущий" дефолтный маршрут —
        # это сам WARP, и пересчёт здесь привёл бы к тому, что SSH "защищали" бы
        # маршрутом обратно в WARP (баг прошлых версий).

        set -euo pipefail

        SSH_PORT=22
        SSH_TABLE=222
        MAIN_GW="{orig_gw}"
        MAIN_IF="{orig_if}"

        # Добавляем правило маршрутизации для SSH: пакеты с меткой идут через
        # реальный шлюз сервера (table 222), не через WARP
        ip rule del fwmark ${{SSH_TABLE}} table ${{SSH_TABLE}} 2>/dev/null || true
        ip rule add fwmark ${{SSH_TABLE}} table ${{SSH_TABLE}} priority 100

        ip route flush table ${{SSH_TABLE}} 2>/dev/null || true
        ip route add default via ${{MAIN_GW}} dev ${{MAIN_IF}} table ${{SSH_TABLE}}

        # iptables: помечаем входящие соединения на 22-й порт меткой SSH_TABLE
        iptables -t mangle -D OUTPUT -p tcp --sport ${{SSH_PORT}} -j MARK --set-mark ${{SSH_TABLE}} 2>/dev/null || true
        iptables -t mangle -A OUTPUT -p tcp --sport ${{SSH_PORT}} -j MARK --set-mark ${{SSH_TABLE}}

        # Также для уже установленных соединений (ESTABLISHED)
        iptables -t mangle -D OUTPUT -p tcp --sport ${{SSH_PORT}} -m conntrack --ctstate ESTABLISHED -j MARK --set-mark ${{SSH_TABLE}} 2>/dev/null || true
        iptables -t mangle -A OUTPUT -p tcp --sport ${{SSH_PORT}} -m conntrack --ctstate ESTABLISHED -j MARK --set-mark ${{SSH_TABLE}}

        # Самопроверка: если зафиксированный интерфейс сам оказался WARP
        # (например, _ORIG_ROUTE_FILE протух после смены сети сервера) —
        # не применяем правило, чтобы не молча завести SSH в WARP.
        if echo "${{MAIN_IF}}" | grep -qi "warp"; then
            echo "ОШИБКА: сохранённый интерфейс (${{MAIN_IF}}) похож на WARP — отказываюсь применять правило" >&2
            ip rule del fwmark ${{SSH_TABLE}} table ${{SSH_TABLE}} 2>/dev/null || true
            exit 1
        fi

        echo "SSH protection rules applied (port ${{SSH_PORT}} bypasses WARP via ${{MAIN_IF}})"
    """))
    ssh_protect_script.chmod(0o755)

    # Создаём systemd-сервис
    WARP_SSH_NS_SERVICE.write_text(textwrap.dedent("""\
        [Unit]
        Description=SSH Protection from WARP Tunnel
        Documentation=https://github.com/cloudflare/cloudflare-docs
        After=network.target warp-svc.service
        Wants=warp-svc.service

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/local/bin/warp-ssh-protect.sh
        ExecStop=/bin/bash -c 'iptables -t mangle -F OUTPUT 2>/dev/null || true; ip rule del fwmark 222 table 222 2>/dev/null || true; ip route flush table 222 2>/dev/null || true'

        [Install]
        WantedBy=multi-user.target
    """))

    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "warp-ssh-ns"], check=False, quiet=True)

    # Запускаем сразу
    r = _run(["bash", str(ssh_protect_script)], capture=True, check=False)
    if r.returncode == 0:
        _box_ok("SSH защита от WARP настроена (iptables mark + policy routing)")
        return True
    else:
        _box_warn(f"Ошибка SSH защиты: {r.stderr.strip()[:200]}")
        return False


def _warp_exclude_ssh_ip(ssh_ip: str) -> None:
    """Добавляет IP SSH-клиента в список исключений WARP (split tunnel exclude)."""
    if not ssh_ip:
        return
    # Добавляем /32 для точного IP
    cidr = ssh_ip if "/" in ssh_ip else f"{ssh_ip}/32"
    # Актуальный синтаксис warp-cli 2023+: split-tunnel ip add <cidr>
    r = _warp_cli("split-tunnel", "ip", "add", cidr)
    if r.returncode == 0:
        _box_ok(f"SSH IP {cidr} исключён из WARP-туннеля")
    else:
        # Fallback: старый синтаксис (до ~2022)
        r2 = _warp_cli("tunnel", "ip", "add-excluded", cidr)
        if r2.returncode == 0:
            _box_ok(f"SSH IP {cidr} исключён из WARP (legacy синтаксис)")
        else:
            _box_warn(f"Не удалось исключить {cidr} из WARP: {r.stdout.strip()}")


def _warp_exclude_localhost() -> None:
    """Исключает localhost и loopback из WARP."""
    for cidr in ("127.0.0.1/8", "::1/128"):
        r = _warp_cli("split-tunnel", "ip", "add", cidr)
        if r.returncode != 0:
            _warp_cli("tunnel", "ip", "add-excluded", cidr)


# ── Захват исходного (не-WARP) маршрута ──────────────────────────────────────

def _capture_original_route() -> Optional[tuple[str, str]]:
    """
    Захватывает текущий дефолтный маршрут (шлюз + интерфейс) и сохраняет
    в _ORIG_ROUTE_FILE. Вызывать ТОЛЬКО до подключения WARP — иначе вместо
    настоящего шлюза будет захвачен сам WARP-интерфейс (см. комментарий
    у _ORIG_ROUTE_FILE).

    Возвращает (gw, iface) либо None, если определить не удалось или если
    дефолтный маршрут уже сейчас идёт через WARP (значит вызвали слишком
    поздно — в этом случае старый сохранённый файл (если есть) не трогаем).
    """
    r = _run(["ip", "route", "show", "default"], capture=True, check=False)
    if r.returncode != 0 or not r.stdout.strip():
        return None

    for line in r.stdout.splitlines():
        if "warp" in line.lower() or "CloudflareWARP" in line:
            # Дефолтный маршрут уже подменён WARP — захватывать поздно,
            # это и есть тот самый баг. Не пишем мусор в файл.
            return None
        parts = line.split()
        if "via" in parts and "dev" in parts:
            gw  = parts[parts.index("via") + 1]
            dev = parts[parts.index("dev") + 1]
            _ORIG_ROUTE_FILE.write_text(f"MAIN_GW={gw}\nMAIN_IF={dev}\n")
            _ORIG_ROUTE_FILE.chmod(0o644)
            return (gw, dev)
    return None


def _load_original_route() -> Optional[tuple[str, str]]:
    """Читает ранее сохранённый РЕАЛЬНЫЙ шлюз из _ORIG_ROUTE_FILE."""
    if not _ORIG_ROUTE_FILE.exists():
        return None
    gw = dev = None
    for line in _ORIG_ROUTE_FILE.read_text().splitlines():
        if line.startswith("MAIN_GW="):
            gw = line.split("=", 1)[1].strip()
        elif line.startswith("MAIN_IF="):
            dev = line.split("=", 1)[1].strip()
    return (gw, dev) if gw and dev else None


def _ensure_original_route() -> Optional[tuple[str, str]]:
    """
    Гарантирует наличие сохранённого исходного маршрута: пробует захватить
    свежий (на случай, если сеть сервера поменялась), и только если сейчас
    захватить не получилось (например, WARP уже активен с прошлого запуска) —
    откатывается на ранее сохранённый файл.
    """
    fresh = _capture_original_route()
    if fresh:
        return fresh
    return _load_original_route()


# ── Регистрация WARP ─────────────────────────────────────────────────────────

def _warp_register_and_connect() -> bool:
    """
    Регистрирует WARP (consumer mode) и подключается.
    Валидирует успешность подключения через Cloudflare trace.
    """
    _box_info("Регистрация в Cloudflare WARP (consumer mode)...")

    # Проверяем есть ли уже регистрация
    r = _warp_cli("registration", "show")
    already_registered = r.returncode == 0 and "Account" in r.stdout

    if not already_registered:
        # Регистрируем — принимаем ToS автоматически.
        # В актуальных версиях warp-cli (2024+) обязателен флаг --accept-tos,
        # а субкоманда "register" (без "registration") упразднена.
        r2 = _run(
            ["warp-cli", "--accept-tos", "registration", "new"],
            capture=True, check=False
        )
        if r2.returncode != 0:
            _box_warn(f"Ошибка регистрации WARP: {r2.stdout.strip()} {r2.stderr.strip()}")
            _box_warn("Не удалось зарегистрировать WARP")
            _box_warn("Попробуйте вручную: warp-cli --accept-tos registration new")
            return False
        _box_ok("WARP зарегистрирован")
    else:
        _box_info("WARP уже зарегистрирован — используем существующую регистрацию")

    # Подключаемся
    _box_info("Подключение к WARP...")
    r3 = _warp_cli("connect")
    if r3.returncode != 0:
        _box_warn(f"warp-cli connect: {r3.stdout.strip()}")

    # Ждём подключения
    for i in range(30):
        status = _warp_status()
        if status == "Connected":
            break
        time.sleep(1)

    status = _warp_status()
    if status != "Connected":
        _box_warn(f"WARP статус: {status} — не Connected")
        _box_warn("Проверьте: warp-cli status | journalctl -u warp-svc -n 20")
        return False

    _box_ok("WARP подключён!")

    # Верифицируем через Cloudflare trace
    _box_info("Верификация WARP через Cloudflare trace...")
    time.sleep(3)
    if _warp_verify_connected():
        _box_ok("Верификация успешна: warp=on ✓")
        return True
    else:
        _box_warn("Cloudflare trace не показал warp=on — WARP может работать некорректно")
        _box_warn("Проверьте вручную: curl https://www.cloudflare.com/cdn-cgi/trace")
        # Не считаем это фатальной ошибкой — статус Connected
        return True


# ── Настройка режимов маршрутизации ─────────────────────────────────────────

def _warp_configure_full_mode(ssh_client_ip: str) -> None:
    """
    Режим FULL: весь трафик через WARP.
    SSH-клиент исключается через split tunnel + iptables защита.
    """
    _box_info("WARP: настройка режима FULL (весь трафик)...")

    # Сначала устанавливаем режим warp (full tunnel)
    r = _warp_cli("mode", "warp")
    if r.returncode != 0:
        _warp_cli("mode", "warp+doh")

    # Исключаем SSH IP клиента (КРИТИЧЕСКИ ВАЖНО для сохранения доступа)
    if ssh_client_ip:
        _warp_exclude_ssh_ip(ssh_client_ip)
        _box_ok(f"SSH доступ защищён: {ssh_client_ip} не идёт через WARP")

    # Исключаем localhost
    _warp_exclude_localhost()

    # Настраиваем iptables-защиту SSH (дополнительный уровень)
    _warp_create_ssh_namespace()

    _box_ok("WARP: режим FULL активирован")


def _warp_configure_selective_mode(
    ips: list[str],
    domains: list[str],
    ssh_client_ip: str,
) -> None:
    """
    Режим SELECTIVE: только указанные IP/домены через WARP.
    Использует exclude-mode с максимальными исключениями (всё кроме нужного).

    Consumer WARP не поддерживает include-only через CLI, поэтому используем
    exclude-режим: исключаем 0.0.0.0/0 и ::/0, потом добавляем нужные маршруты
    через iptables + ip rule, направляя их в CloudflareWARP-интерфейс.
    """
    _box_info("WARP: настройка режима SELECTIVE (выборочный трафик)...")

    # Режим warp (full), затем настраиваем маршрутизацию через iptables
    r = _warp_cli("mode", "warp")
    if r.returncode != 0:
        _warp_cli("mode", "warp+doh")

    # Исключаем весь трафик кроме нужного
    for cidr in ("0.0.0.0/0", "::/0"):
        r2 = _warp_cli("split-tunnel", "ip", "add", cidr)
        if r2.returncode != 0:
            _warp_cli("tunnel", "ip", "add-excluded", cidr)

    # Исключаем SSH клиента
    if ssh_client_ip:
        _warp_exclude_ssh_ip(ssh_client_ip)

    # Исключаем localhost
    _warp_exclude_localhost()

    # Теперь создаём скрипт для направления нужных IP через WARP-интерфейс
    selective_script = Path("/usr/local/bin/warp-selective.sh")

    ips_block = "\n".join(
        f'    ip route add {ip} dev "$WARP_IF" 2>/dev/null || true'
        for ip in ips
    )

    # Для доменов используем DNS-резолвинг и добавляем маршруты
    domains_block = "\n".join(
        f'    for IP in $(dig +short {d} 2>/dev/null | grep -E "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"); do\n'
        f'        ip route add "$IP/32" dev "$WARP_IF" 2>/dev/null || true\n'
        f'    done'
        for d in domains
    )

    selective_script.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # WARP Selective mode: маршрутизация выбранных ресурсов через WARP
        set -euo pipefail

        # Находим интерфейс WARP (CloudflareWARP)
        WARP_IF=$(ip link show | grep -oE 'CloudflareWARP[^:]*' | head -1 || true)
        if [[ -z "$WARP_IF" ]]; then
            WARP_IF="CloudflareWARP"
        fi

        if ! ip link show "$WARP_IF" &>/dev/null; then
            echo "WARP interface $WARP_IF not found — WARP disconnected?"
            exit 1
        fi

        # Маршруты для пользовательских IP
{ips_block}

        # Маршруты для доменов (DNS резолвинг)
{domains_block}

        echo "WARP selective routes applied via $WARP_IF"
    """))
    selective_script.chmod(0o755)

    # Systemd-сервис для selective режима
    Path("/etc/systemd/system/warp-selective.service").write_text(
        textwrap.dedent("""\
        [Unit]
        Description=WARP Selective Routing
        After=network.target warp-svc.service
        Wants=warp-svc.service

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStartPre=/bin/sleep 5
        ExecStart=/usr/local/bin/warp-selective.sh
        Restart=on-failure
        RestartSec=10s

        [Install]
        WantedBy=multi-user.target
    """)
    )
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "warp-selective"], check=False, quiet=True)
    _run(["bash", str(selective_script)], check=False, quiet=True)

    # SSH защита
    _warp_create_ssh_namespace()

    _box_ok(f"WARP: режим SELECTIVE активирован ({len(ips)} IP, {len(domains)} доменов)")


def _warp_configure_runet_mode(ssh_client_ip: str) -> None:
    """
    Режим RUNET: заблокированные РФ ресурсы через WARP.
    Использует списки runetfreedom (те же geoip.dat/geosite.dat что и split tunnel).
    Реализуется как FULL режим + маршрутизация РФ-трафика мимо WARP.
    """
    _box_info("WARP: настройка режима RUNET (заблокированные РФ ресурсы)...")

    # Включаем full tunnel
    r = _warp_cli("mode", "warp")
    if r.returncode != 0:
        _warp_cli("mode", "warp+doh")

    # Исключаем SSH клиента
    if ssh_client_ip:
        _warp_exclude_ssh_ip(ssh_client_ip)

    # Исключаем localhost
    _warp_exclude_localhost()

    # Исключаем российские IP-диапазоны (RFC 1918 + типичные РФ-CIDR)
    # Базовые RFC 1918 и локальные диапазоны всегда исключаем
    local_cidrs = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",  # CGNAT
    ]
    for cidr in local_cidrs:
        r2 = _warp_cli("split-tunnel", "ip", "add", cidr)
        if r2.returncode != 0:
            _warp_cli("tunnel", "ip", "add-excluded", cidr)

    # Создаём скрипт для динамического применения РФ-маршрутов
    # Используем ipset + iptables если доступен, иначе ip rule
    orig = _load_original_route()
    if orig is None:
        _box_warn(
            "Не найден сохранённый исходный шлюз (/etc/warp-original-route.conf) — "
            "режим RuNet не настроен, чтобы не маршрутизировать SSH/РФ-трафик "
            "обратно в WARP. Выполните `warp-cli disconnect` и повторите настройку."
        )
        return
    orig_gw, orig_if = orig

    runet_script = Path("/usr/local/bin/warp-runet.sh")
    runet_script.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # WARP RuNet mode: российский трафик идёт напрямую, заблокированный — через WARP
        # Источник РФ IP: runetfreedom (те же списки что и split tunneling xray)
        #
        # ВАЖНО: MAIN_GW/MAIN_IF — литералы, зафиксированные ДО подключения WARP
        # (см. _capture_original_route() в warp.py), НЕ результат живого
        # `ip route show default` на момент запуска этого скрипта — иначе после
        # подключения WARP "текущим" дефолтным маршрутом окажется сам WARP, и
        # вся прямая/SSH-маршрутизация поедет обратно в WARP (старый баг).
        set -euo pipefail

        LOG="/var/log/warp-runet.log"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Применение WARP RuNet маршрутов..." >> "$LOG"

        WARP_TABLE=223
        MAIN_GW="{orig_gw}"
        MAIN_IF="{orig_if}"

        # Таблица маршрутизации для прямого (не-WARP) трафика
        ip rule del fwmark {{WARP_TABLE}} table {{WARP_TABLE}} 2>/dev/null || true
        ip rule add fwmark {{WARP_TABLE}} table {{WARP_TABLE}} priority 50
        ip route flush table {{WARP_TABLE}} 2>/dev/null || true
        ip route add default via "$MAIN_GW" dev "$MAIN_IF" table {{WARP_TABLE}}

        # Помечаем российские IP (известные диапазоны) для прямого маршрута
        # Используем iptables + ipset если доступен
        if command -v ipset &>/dev/null; then
            ipset destroy warp-ru-direct 2>/dev/null || true
            ipset create warp-ru-direct hash:net family inet
            # Основные РФ операторские сети (публичные данные RIPE NCC)
            # Эти диапазоны НЕ заблокированы — банки, госуслуги, VK, Яндекс
            for CIDR in \\
                5.8.0.0/13 \\
                5.16.0.0/12 \\
                5.44.0.0/14 \\
                5.136.0.0/13 \\
                31.13.0.0/16 \\
                37.9.0.0/16 \\
                45.12.0.0/14 \\
                46.226.0.0/15 \\
                77.72.0.0/13 \\
                81.176.0.0/12 \\
                82.138.0.0/15 \\
                83.149.0.0/17 \\
                84.52.0.0/14 \\
                85.141.0.0/16 \\
                87.117.0.0/16 \\
                88.212.0.0/15 \\
                90.150.0.0/15 \\
                91.108.0.0/14 \\
                93.180.0.0/14 \\
                94.25.0.0/16 \\
                95.165.0.0/16 \\
                109.120.0.0/13 \\
                176.56.0.0/13 \\
                178.70.0.0/15 \\
                185.16.0.0/14 \\
                193.0.192.0/21 \\
                194.85.0.0/16 \\
                195.3.240.0/22 \\
                213.180.0.0/15; do
                ipset add warp-ru-direct "$CIDR" 2>/dev/null || true
            done
            iptables -t mangle -D OUTPUT -m set --match-set warp-ru-direct dst -j MARK --set-mark {{WARP_TABLE}} 2>/dev/null || true
            iptables -t mangle -A OUTPUT -m set --match-set warp-ru-direct dst -j MARK --set-mark {{WARP_TABLE}}
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ipset warp-ru-direct применён" >> "$LOG"
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ipset недоступен, используем warp-cli exclude" >> "$LOG"
            # Fallback: добавляем через warp-cli exclude
            for CIDR in \\
                5.8.0.0/13 \\
                5.16.0.0/12 \\
                5.44.0.0/14 \\
                37.9.0.0/16 \\
                77.72.0.0/13 \\
                81.176.0.0/12 \\
                82.138.0.0/15 \\
                83.149.0.0/17 \\
                84.52.0.0/14 \\
                87.117.0.0/16 \\
                88.212.0.0/15 \\
                90.150.0.0/15 \\
                91.108.0.0/14 \\
                93.180.0.0/14 \\
                94.25.0.0/16 \\
                95.165.0.0/16 \\
                109.120.0.0/13 \\
                176.56.0.0/13 \\
                178.70.0.0/15 \\
                185.16.0.0/14 \\
                194.85.0.0/16 \\
                213.180.0.0/15; do
                warp-cli split-tunnel ip add "$CIDR" 2>/dev/null || \\
                warp-cli tunnel ip add-excluded "$CIDR" 2>/dev/null || true
            done
        fi

        # SSH защита (порт 22 всегда напрямую)
        SSH_TABLE=222
        ip rule del fwmark $SSH_TABLE table $SSH_TABLE 2>/dev/null || true
        ip rule add fwmark $SSH_TABLE table $SSH_TABLE priority 100
        ip route flush table $SSH_TABLE 2>/dev/null || true
        if [[ -n "$MAIN_GW" && -n "$MAIN_IF" ]]; then
            ip route add default via "$MAIN_GW" dev "$MAIN_IF" table $SSH_TABLE
        fi
        iptables -t mangle -D OUTPUT -p tcp --sport 22 -j MARK --set-mark $SSH_TABLE 2>/dev/null || true
        iptables -t mangle -A OUTPUT -p tcp --sport 22 -j MARK --set-mark $SSH_TABLE

        echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARP RuNet маршруты применены" >> "$LOG"
    """))
    runet_script.chmod(0o755)

    # Устанавливаем ipset если нет
    if not command_exists("ipset"):
        _box_info("Установка ipset для WARP RuNet режима...")
        _pkg_install("ipset")

    # Systemd-сервис
    Path("/etc/systemd/system/warp-runet.service").write_text(
        textwrap.dedent("""\
        [Unit]
        Description=WARP RuNet Routing (Russian traffic direct, blocked via WARP)
        After=network.target warp-svc.service
        Wants=warp-svc.service

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStartPre=/bin/sleep 5
        ExecStart=/usr/local/bin/warp-runet.sh
        ExecStop=/bin/bash -c 'iptables -t mangle -F OUTPUT 2>/dev/null; ipset destroy warp-ru-direct 2>/dev/null; ip rule del fwmark 223 table 223 2>/dev/null; ip rule del fwmark 222 table 222 2>/dev/null; true'

        [Install]
        WantedBy=multi-user.target
    """)
    )
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "warp-runet"], check=False, quiet=True)
    _run(["bash", str(runet_script)], check=False, quiet=True)

    _box_ok("WARP: режим RUNET активирован (РФ напрямую, заблокированное через WARP)")


# ── Главная функция настройки WARP ───────────────────────────────────────────

def configure_warp(
    mode: str,
    ssh_client_ip: str,
    custom_ips: list[str] | None = None,
    custom_domains: list[str] | None = None,
) -> bool:
    """
    Полная настройка WARP: установка + регистрация + режим маршрутизации.
    mode: "full" | "selective" | "runet"
    ssh_client_ip: IP SSH-клиента (исключается из туннеля во всех режимах)
    """

    _set_warp("WARP_MODE", mode)
    _set_warp("WARP_SSH_CLIENT_IP", ssh_client_ip)
    _set_warp("WARP_CUSTOM_IPS", custom_ips or [])
    _set_warp("WARP_CUSTOM_DOMAINS", custom_domains or [])

    # 0. КРИТИЧЕСКИ ВАЖНО: захватываем реальный (не-WARP) дефолтный маршрут
    # СЕЙЧАС, до того как WARP вообще подключится. Если сделать это позже
    # (как было раньше — внутри _warp_create_ssh_namespace()/runet-скрипта,
    # уже ПОСЛЕ install_warp()+connect()), "захваченным" окажется сам
    # WARP-интерфейс — и вся защита SSH/RuNet от WARP будет на самом деле
    # маршрутизировать защищаемый трафик обратно в WARP. Именно это рубило
    # SSH при любом сбое WARP в прошлых попытках.
    if _ensure_original_route() is None:
        _box_warn(
            "Не удалось определить исходный (не-WARP) шлюз сервера — возможно, "
            "WARP уже активен с предыдущего запуска. Защита SSH/режим RuNet "
            "могут оказаться ненадёжными. Рекомендуется выполнить "
            "`warp-cli disconnect`, перезапустить настройку, и только потом "
            "снова подключать WARP."
        )

    # 1. Установка
    if not install_warp():
        _box_warn("WARP не установлен — настройка прервана")
        return False

    # 2. Регистрация и подключение
    if not _warp_register_and_connect():
        _box_warn("WARP не подключился — проверьте сеть и повторите")
        return False
    _set_warp("WARP_CONNECTED", True)

    # 3. Настройка режима маршрутизации
    if mode == "full":
        _warp_configure_full_mode(ssh_client_ip)
    elif mode == "selective":
        _warp_configure_selective_mode(
            _get_warp("WARP_CUSTOM_IPS", []), _get_warp("WARP_CUSTOM_DOMAINS", []), ssh_client_ip
        )
    elif mode == "runet":
        _warp_configure_runet_mode(ssh_client_ip)
    else:
        _box_warn(f"Неизвестный режим WARP: {mode}")
        return False

    # 4. Сохраняем настройки в state
    _warp_save_state()

    return True


def _warp_save_state() -> None:
    """Сохраняет настройки WARP в state.json."""
    if not _STATE_FILE.exists():
        return
    try:
        state = json.loads(_STATE_FILE.read_text())
        state["warp_installed"]   = _get_warp("WARP_INSTALLED", False)
        state["warp_connected"]   = _get_warp("WARP_CONNECTED", False)
        state["warp_mode"]        = _get_warp("WARP_MODE", "full")
        state["warp_ssh_ip"]      = _get_warp("WARP_SSH_CLIENT_IP", "")
        state["warp_custom_ips"]  = _get_warp("WARP_CUSTOM_IPS", [])
        state["warp_custom_domains"] = _get_warp("WARP_CUSTOM_DOMAINS", [])
        _STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as e:
        _box_warn(f"Не удалось сохранить WARP state: {e}")


def _warp_load_state() -> None:
    """Загружает настройки WARP из state.json."""
    if not _STATE_FILE.exists():
        return
    try:
        state = json.loads(_STATE_FILE.read_text())
        _set_warp("WARP_INSTALLED", state.get("warp_installed", False))
        _set_warp("WARP_CONNECTED", state.get("warp_connected", False))
        _set_warp("WARP_MODE", state.get("warp_mode", "full"))
        _set_warp("WARP_SSH_CLIENT_IP", state.get("warp_ssh_ip", ""))
        _set_warp("WARP_CUSTOM_IPS", state.get("warp_custom_ips", []))
        _set_warp("WARP_CUSTOM_DOMAINS", state.get("warp_custom_domains", []))
    except Exception:
        pass


# ── Меню управления WARP ─────────────────────────────────────────────────────

def do_manage_warp() -> None:
    """Пункт [W] главного меню: управление Cloudflare WARP."""

    _warp_load_state()

    while True:
        os.system("clear")
        _box_row()
        _box_top("CLOUDFLARE WARP — УПРАВЛЕНИЕ")
        _box_sep()

        # Статус
        inst_str = f"{GREEN}установлен{NC}" if _warp_is_installed() else f"{RED}не установлен{NC}"
        svc_str  = f"{GREEN}активен{NC}"    if _warp_service_active() else f"{YELLOW}не активен{NC}"
        st = _warp_status() if _warp_is_installed() and _warp_service_active() else "—"
        conn_str = f"{GREEN}{st}{NC}" if st == "Connected" else f"{YELLOW}{st}{NC}"

        mode_labels = {
            "full":      "Весь трафик через WARP",
            "selective": "Выборочный (конкретные ресурсы)",
            "runet":     "Заблокированные РФ ресурсы (runetfreedom)",
        }
        mode_str = mode_labels.get(_get_warp("WARP_MODE", "full"), _get_warp("WARP_MODE", "full"))

        _box_row(f"  WARP:     {inst_str}")
        _box_row(f"  Сервис:   {svc_str}")
        _box_row(f"  Статус:   {conn_str}")
        _box_row(f"  Режим:    {CYAN}{mode_str}{NC}")
        ssh_ip_disp = _get_warp("WARP_SSH_CLIENT_IP", "") or f"{YELLOW}не задан{NC}"
        _box_row(f"  SSH IP:   {ssh_ip_disp}  {DIM}(защищён от WARP){NC}")
        _box_row()
        _box_sep()
        _box_item("1", "🚀 Установить и настроить WARP")
        _box_item("2", "🔌 Подключить / Отключить WARP")
        _box_item("3", "🔀 Сменить режим маршрутизации")
        _box_item("4", "🛡️  Проверить защиту SSH")
        _box_item("5", "🔍 Верифицировать WARP (curl trace)")
        _box_item("6", "📊 Статус и информация")
        _box_item("7", "🗑️  Отключить и удалить WARP")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            print()
            break

        if ch in ("0", "Q", "q", ""):
            break

        elif ch == "1":
            # Установка и настройка
            print()
            print()
            _box_top(f"Настройка Cloudflare WARP")
            _box_row()
            _box_row()

            # IP SSH клиента — определяем автоматически из окружения
            detected_ssh_ip = ""
            # $SSH_CLIENT содержит "ip port localport", берём первое поле
            ssh_client_env = os.environ.get("SSH_CLIENT", "")
            if ssh_client_env:
                detected_ssh_ip = ssh_client_env.split()[0]
            # Fallback: $SSH_CONNECTION = "remoteip remoteport localip localport"
            if not detected_ssh_ip:
                ssh_conn_env = os.environ.get("SSH_CONNECTION", "")
                if ssh_conn_env:
                    detected_ssh_ip = ssh_conn_env.split()[0]

            _box_row(f"{BLUE}IP вашего SSH-клиента (будет ВСЕГДА исключён из WARP):{NC}")
            _box_row(f"  {DIM}Укажите IP с которого вы подключаетесь по SSH.{NC}")
            _box_row(f"  {DIM}Без этого при полном туннеле SSH может оборваться!{NC}")
            if detected_ssh_ip:
                _box_item("1", f"{detected_ssh_ip}  {GREEN}(определён автоматически){NC}")
            else:
                _box_item("1", f"Ввести вручную  {YELLOW}(автоопределение не удалось){NC}")
            _box_item("2", f"Ввести вручную")
            _box_item("3", f"Пропустить (небезопасно!)")
            _box_bottom()
            while True:
                v = input("  Выбор [1]: ").strip() or "1"
                if v == "1":
                    if detected_ssh_ip:
                        _set_warp("WARP_SSH_CLIENT_IP", detected_ssh_ip)
                        _ssh_ip_val = _get_warp("WARP_SSH_CLIENT_IP", "")
                        _box_ok(f"SSH IP: {_ssh_ip_val}")
                        break
                    else:
                        # Нет автоопределения — запрашиваем вручную
                        ip_raw = input("  SSH client IP: ").strip()
                        if ip_raw:
                            _set_warp("WARP_SSH_CLIENT_IP", ip_raw)
                            _ssh_ip_val = _get_warp("WARP_SSH_CLIENT_IP", "")
                            _box_ok(f"SSH IP: {_ssh_ip_val}")
                        break
                elif v == "2":
                    ip_raw = input("  SSH client IP: ").strip()
                    if ip_raw:
                        _set_warp("WARP_SSH_CLIENT_IP", ip_raw)
                        _ssh_ip_val = _get_warp("WARP_SSH_CLIENT_IP", "")
                        _box_ok(f"SSH IP: {_ssh_ip_val}")
                    break
                elif v == "3":
                    _box_warn("SSH IP не задан — SSH может оборваться при полном туннеле!")
                    _set_warp("WARP_SSH_CLIENT_IP", "")
                    break
                else:
                    _box_warn("Введите 1, 2 или 3")

            # Режим маршрутизации
            _box_row()
            _box_row(f"{BLUE}Режим маршрутизации WARP:{NC}")
            _box_row()
            _box_item("1", f"🌐 Весь трафик через WARP {GREEN}(full){NC}")
            _ssh_ip_desc = _get_warp("WARP_SSH_CLIENT_IP", "")
            _box_desc(f"Максимальная защита. SSH-клиент ({_ssh_ip_desc}) исключён автоматически.")
            _box_row()
            _box_item("2", f"🎯 Выборочные ресурсы {GREEN}(selective){NC}")
            _box_desc(f"Только указанные вами IP/домены идут через WARP.")
            _box_desc(f"Остальной трафик — напрямую.")
            _box_row()
            _box_item("3", f"🇷🇺 Заблокированные РФ ресурсы {GREEN}(runet){NC}")
            _box_desc(f"Российский трафик напрямую (банки, Яндекс, VK).")
            _box_desc(f"Заблокированный трафик — через WARP.")
            _box_desc(f"{DIM}Использует те же принципы что и split tunneling Xray.{NC}")
            _box_row()

            mode_selected = "full"
            _box_bottom()
            while True:
                mv = input("  Выбор [1]: ").strip() or "1"
                if mv == "1":
                    mode_selected = "full"
                    break
                elif mv == "2":
                    mode_selected = "selective"
                    break
                elif mv == "3":
                    mode_selected = "runet"
                    break
                warn("Введите 1, 2 или 3")

            # Для selective — запрашиваем IP и домены
            custom_ips: list[str] = []
            custom_domains: list[str] = []
            if mode_selected == "selective":
                _box_row(f"{BLUE}IP/CIDR для туннелирования через WARP:{NC}")
                _box_row(f"  {DIM}Введите через запятую. Например: 1.2.3.4/32, 5.6.7.0/24{NC}")
                raw_ips = input("  IP/CIDR: ").strip()
                if raw_ips:
                    custom_ips = [x.strip() for x in raw_ips.split(",") if x.strip()]
                    success(f"Добавлено {len(custom_ips)} IP/CIDR")

                _box_row(f"{BLUE}Домены для туннелирования через WARP:{NC}")
                _box_row(f"  {DIM}Введите через запятую. Например: instagram.com, youtube.com{NC}")
                raw_domains = input("  Домены: ").strip()
                if raw_domains:
                    custom_domains = [x.strip() for x in raw_domains.split(",") if x.strip()]
                    success(f"Добавлено {len(custom_domains)} доменов")

            _box_bottom()
            ans = input(f"{YELLOW}Установить и настроить WARP? [y/N]:{NC} ").strip().lower()
            if ans != "y":
                info("Отменено")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            ok = configure_warp(
                mode=mode_selected,
                ssh_client_ip=_get_warp("WARP_SSH_CLIENT_IP", ""),
                custom_ips=custom_ips,
                custom_domains=custom_domains,
            )
            if ok:
                success("✓ WARP настроен успешно!")
            else:
                warn("WARP настроен с ошибками — проверьте логи")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            if not _warp_is_installed():
                warn("Cloudflare WARP не установлен — используйте пункт [1]")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            if not _warp_is_installed():
                warn("WARP не установлен — сначала пункт [1]")
                time.sleep(2)
                continue
            st = _warp_status()
            if st == "Connected":
                ans = input(f"{YELLOW}WARP подключён. Отключить? [y/N]:{NC} ").strip().lower()
                if ans == "y":
                    _warp_cli("disconnect")
                    time.sleep(2)
                    success(f"WARP отключён: {_warp_status()}")
            else:
                info("Подключение к WARP...")
                _warp_register_and_connect()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            if not _warp_is_installed():
                warn("WARP не установлен — сначала пункт [1]")
                time.sleep(2)
                continue
            _box_top(f"Смена режима маршрутизации")
            _box_row()
            _warp_mode_cur = _get_warp("WARP_MODE", "full")
            _box_row(f"  Текущий: {CYAN}{_warp_mode_cur}{NC}")
            _box_row()
            _box_item("1", f"full      — весь трафик через WARP")
            _box_item("2", f"selective — выборочные ресурсы")
            _box_item("3", f"runet     — заблокированные РФ ресурсы")
            _box_row()
            _box_bottom()
            while True:
                mv = input("  Выбор: ").strip()
                if mv == "1":
                    _set_warp("WARP_MODE", "full")
                    break
                elif mv == "2":
                    _set_warp("WARP_MODE", "selective")
                    break
                elif mv == "3":
                    _set_warp("WARP_MODE", "runet")
                    break
                elif mv == "":
                    break
                warn("Введите 1, 2 или 3")

            if mv in ("1", "2", "3"):
                if _get_warp("WARP_MODE", "") == full:
                    _warp_configure_full_mode(_get_warp("WARP_SSH_CLIENT_IP", ""))
                elif _get_warp("WARP_MODE", "") == selective:
                    _warp_configure_selective_mode(
                        _get_warp("WARP_CUSTOM_IPS", []), _get_warp("WARP_CUSTOM_DOMAINS", []), _get_warp("WARP_SSH_CLIENT_IP", "")
                    )
                elif _get_warp("WARP_MODE", "") == runet:
                    _warp_configure_runet_mode(_get_warp("WARP_SSH_CLIENT_IP", ""))
                _warp_save_state()
                _warp_mode_new = _get_warp("WARP_MODE", "full")
                success(f"Режим изменён на: {_warp_mode_new}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            # Проверка SSH защиты
            _box_top(f"Проверка защиты SSH")
            _box_row()
            _box_row()

            ssh_ip = _get_warp("WARP_SSH_CLIENT_IP", "")
            if not ssh_ip:
                # Пробуем определить из окружения
                _env = os.environ.get("SSH_CLIENT", "") or os.environ.get("SSH_CONNECTION", "")
                if _env:
                    ssh_ip = _env.split()[0]
            if not ssh_ip:
                _box_row()
                _box_bottom()
                ssh_ip = input(f"  {YELLOW}SSH IP не задан. Введите IP клиента:{NC} ").strip()
            if not ssh_ip:
                warn("SSH IP не определён — проверка пропущена")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            # Проверяем iptables
            r = _run(["iptables", "-t", "mangle", "-L", "OUTPUT", "-n"],
                     capture=True, check=False)
            if "--sport 22" in r.stdout or "sport 22" in r.stdout:
                success("✓ iptables: SSH-порт (22) помечен для обхода WARP")
            else:
                warn("✗ iptables: правила SSH не найдены — применяем...")
                _warp_create_ssh_namespace()

            # Проверяем ip rule
            r2 = _run(["ip", "rule", "show"], capture=True, check=False)
            if "222" in r2.stdout:
                success("✓ ip rule: SSH-таблица маршрутизации (222) активна")
            else:
                warn("✗ ip rule: SSH-таблица не найдена — восстанавливаем...")
                _warp_create_ssh_namespace()

            # Проверяем исключение SSH IP (только если warp-cli установлен)
            if _warp_is_installed():
                r3 = _warp_cli("split-tunnel", "ip", "list")
                if r3.returncode != 0:
                    r3 = _warp_cli("tunnel", "ip", "list-excluded")
                if ssh_ip in r3.stdout:
                    success(f"✓ warp-cli: {ssh_ip} в списке исключений")
                else:
                    warn(f"✗ {ssh_ip} не найден в warp-cli исключениях — добавляем...")
                    _warp_exclude_ssh_ip(ssh_ip)
            else:
                warn("warp-cli не установлен — проверка split-tunnel пропущена")

            success(f"SSH клиент {ssh_ip} защищён от WARP-туннеля")
            _box_row(f"  {DIM}Порт 22 всегда идёт напрямую (минуя WARP) через policy routing.{NC}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            if not _warp_is_installed():
                warn("Cloudflare WARP не установлен — используйте пункт [1]")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            # Верификация
            info("Верификация WARP через Cloudflare trace...")
            if _warp_verify_connected():
                success("✓ warp=on — WARP активен и работает!")
            else:
                warn("✗ warp=on не найден в ответе — WARP может быть отключён")
                warn("Статус: " + _warp_status())
            r = _run([
                "curl", "-s", "--max-time", "10",
                "https://www.cloudflare.com/cdn-cgi/trace"
            ], capture=True, check=False)
            _box_row(f"{DIM}{r.stdout[:500]}{NC}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "6":
            if not _warp_is_installed():
                warn("Cloudflare WARP не установлен — используйте пункт [1]")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            # Статус
            _box_top(f"Информация о WARP")
            _box_row()
            _box_row()
            r_ver = _run(["warp-cli", "--version"], capture=True, check=False)
            _box_row(f"  Версия:   {r_ver.stdout.strip()}")
            _box_row(f"  Статус:   {_warp_status()}")
            _box_row(f"  Сервис:   {'активен' if _warp_service_active() else 'неактивен'}")
            _warp_mode_st = _get_warp("WARP_MODE", "full")
            _box_row(f"  Режим:    {_warp_mode_st}")
            _ssh_ip_st = _get_warp("WARP_SSH_CLIENT_IP", "") or "(не задан)"
            _box_row(f"  SSH IP:   {_ssh_ip_st}")
            _box_row()
            r_st = _warp_cli("settings")
            _box_row(f"{DIM}{r_st.stdout[:800]}{NC}")
            _box_row()
            r_ex = _warp_cli("split-tunnel", "ip", "list")
            if r_ex.returncode != 0:
                r_ex = _warp_cli("tunnel", "ip", "list-excluded")
            _box_row(f"{BOLD}Исключения из WARP:{NC}")
            _box_row(f"{DIM}{r_ex.stdout[:400]}{NC}")
            _box_row()
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "7":
            if not _warp_is_installed():
                warn("Cloudflare WARP не установлен — используйте пункт [1]")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            ans = input(f"{RED}Отключить и удалить WARP? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                _warp_cli("disconnect")
                _warp_cli("registration", "delete")
                # Останавливаем сервисы
                for svc in ("warp-ssh-ns", "warp-selective", "warp-runet"):
                    _run(["systemctl", "stop",    svc], check=False, quiet=True)
                    _run(["systemctl", "disable", svc], check=False, quiet=True)
                # Удаляем пакет
                if _get_pkg_mgr() == "apt":
                    _run(["apt-get", "remove", "--purge", "-y", "cloudflare-warp"],
                         check=False, quiet=True)
                else:
                    _run(["dnf", "remove", "-y", "cloudflare-warp"],
                         check=False, quiet=True)
                # Убираем iptables правила
                _run(["iptables", "-t", "mangle", "-F", "OUTPUT"],
                     check=False, quiet=True)
                _run(["ip", "rule", "del", "fwmark", "222", "table", "222"],
                     check=False, quiet=True)
                _run(["ip", "rule", "del", "fwmark", "223", "table", "223"],
                     check=False, quiet=True)
                _set_warp("WARP_INSTALLED", False)
                _set_warp("WARP_CONNECTED", False)
                _warp_save_state()
                success("WARP удалён")
            input(f"{BLUE}Нажмите Enter...{NC}")

        else:
            warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  ПАТЧ v3.5.0: НОВЫЕ ФУНКЦИИ
#  1. Live Traffic Dashboard
#  2. Авто-смена TLS Fingerprint по расписанию
#  3. Геопроверка выходного IP
#  4. Менеджер множественных пользователей
#  5. Автообновление GeoIP/GeoSite (независимо от split tunnel)
#  6. Экспорт/Импорт всей конфигурации
#  7. Тест скорости через exit-ноду
# =============================================================================

# ---------------------------------------------------------------------------
#  1. LIVE TRAFFIC DASHBOARD
