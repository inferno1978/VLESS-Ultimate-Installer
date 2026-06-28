"""
vless_installer/modules/telemt_warp_route.py
───────────────────────────────────────────────────────────────────────────────
Маршрутизация Telegram-подсетей через Cloudflare WARP — для Telemt.

Зачем
─────
Если сервер (Entry standalone ИЛИ Exit-узел каскада) физически расположен
в РФ, прямые TCP-соединения к Telegram ME-серверам/DC могут деградировать —
ТСПУ специфично режет MTProto-сигнатуру независимо от геолокации IP.

Этот модуль направляет ТОЛЬКО трафик к актуальным Telegram-подсетям (живой
список из tg_nets.py, тот же, что используется для iptables REDIRECT в
mtproto.py) через интерфейс WARP (wg-warp) — НЕЗАВИСИМО от того, в каком
режиме (FULL/SELECTIVE/RUNET/выключен) настроен WARP для обычных
VPN-клиентов в warp.py: используется отдельная таблица маршрутизации и
fwmark, без пересечения с главной таблицей и без привязки к выбранному там
режиму.

На каком сервере это реально включать
──────────────────────────────────────
  • Standalone Telemt (cascade == "none") — этот сервер сам стучится в
    Telegram, включать здесь.
  • Exit-узел каскада (Entry → Exit → Telegram) — финальное соединение к
    Telegram делает именно Exit, включать там.
  • На Entry-сервере с активным tproxy-перехватом
    (mtproto.xray_enable_tproxy_for_telemt) включение здесь НЕ имеет
    эффекта: nat OUTPUT (REDIRECT в локальный dokodemo) в порядке обработки
    netfilter идёт ПОСЛЕ mangle OUTPUT и матчится по оригинальному
    dst-адресу независимо от того, какой маршрут был выбран по fwmark —
    пакет всё равно уйдёт в локальный dokodemo, а не в WARP. Нужный сервер
    для включения — тот, что физически делает соединение в Telegram (см.
    выше).
  • Если Exit-узел сам работает через AWG (sockopt.mark у freedom outbound
    в Xray уже выставлен программно) — включение этого режима ПЕРЕБЬЁТ
    AWG-метку для пакетов к Telegram (mangle OUTPUT выполняется после
    установки SO_MARK на сокете и переписывает её при совпадении dst).
    Это осознанно: для Telegram-направления WARP получает приоритет над
    AWG. Если это не нужно — не включайте здесь, на этом Exit-узле.

Механизм
────────
  1. Отдельная таблица маршрутизации (ROUTE_TABLE) с маршрутом
     `default dev wg-warp` — основную таблицу не трогает.
  2. iptables mangle OUTPUT: для каждой Telegram-подсети — MARK --set-mark FWMARK.
  3. ip rule fwmark FWMARK table ROUTE_TABLE.
  4. Cron-watchdog каждые 2 минуты — самовосстановление после ребута и
     подхватывание изменений живого списка подсетей tg_nets.json без
     участия пользователя (если режим включён).

Требования
──────────
  • WARP должен быть установлен, интерфейс wg-warp поднят (см.
    vless_installer.modules.warp.do_manage_warp).
  • Модуль автономен: использует только публичную константу WG_INTERFACE
    из warp.py, без обращения к его приватным функциям/состоянию — чтобы не
    зависеть от внутренней механики FULL/SELECTIVE/RUNET режимов.

Точка входа из mtproto.py (телемт-меню):
    from vless_installer.modules.telemt_warp_route import (
        apply_telemt_warp_routing, refresh_telemt_warp_routing,
        telemt_warp_status, telemt_warp_status_line, do_telemt_warp_menu,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# При запуске напрямую из cron (--watchdog) — см. идентичный приём в warp.py:
# sys.path[0] указывает на каталог самого файла, а не на корень проекта.
if __name__ == "__main__":
    _project_root = Path(__file__).resolve().parent.parent.parent
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))

from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn, _box_ok,
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
)
from vless_installer.modules.warp import WG_INTERFACE as _WARP_IFACE

# ── Константы ─────────────────────────────────────────────────────────────
# Отдельно от диапазона AWG (1000 + n для нод) — без пересечения.
FWMARK        = 300
ROUTE_TABLE   = 300
RULE_PRIORITY = 150

STATE_FILE   = Path("/var/lib/xray-installer/telemt_warp_route.json")
RULES_DUMP   = Path("/etc/iptables/telemt-warp-rules.v4")
RESTORE_SVC  = Path("/etc/systemd/system/telemt-warp-restore.service")
CRON_FILE    = Path("/etc/cron.d/telemt-warp-watchdog")
WATCHDOG_LOG = Path("/var/log/telemt-warp-watchdog.log")
MODULE_PATH  = Path(__file__).resolve()

_LOG_FILE = Path("/var/log/vless-install.log")


# ── Логирование ──────────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(chr(27) + r"\[[0-9;]*m", "", msg)
            f.write(f"[{ts}] [TELEMT-WARP] [{level}] {clean}\n")
    except Exception:
        pass


def _info(msg): print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def _ok(msg):   print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg): print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _err(msg):  print(f"{RED}[ERR]{NC}   {msg}"); _log("ERROR", msg)


def _run(args: list, capture: bool = True, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=capture, text=True, check=check)


# ── tg_nets.py (живой список Telegram-подсетей) ──────────────────────────
def _get_tg_nets() -> list:
    from vless_installer.modules.tg_nets import get_tg_nets
    return get_tg_nets()


# ── Состояние ─────────────────────────────────────────────────────────────
def _state_load() -> dict:
    try:
        return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    except Exception:
        return {}


def _state_save(state: dict) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as e:
        _warn(f"Не удалось сохранить состояние: {e}")


def is_enabled() -> bool:
    return bool(_state_load().get("enabled"))


# ── WARP-интерфейс ───────────────────────────────────────────────────────
def warp_iface_up() -> bool:
    """True если интерфейс wg-warp существует.

    Намеренно не проверяем "state UP" — у WireGuard-интерфейсов `ip link`
    часто показывает `state UNKNOWN` даже при полностью рабочем туннеле
    (WG не поддерживает физическое carrier-detection), поэтому единственный
    надёжный сигнал — само существование интерфейса."""
    r = _run(["ip", "link", "show", _WARP_IFACE])
    return r.returncode == 0


# ── Таблица маршрутизации ────────────────────────────────────────────────
def _table_route_exists() -> bool:
    r = _run(["ip", "route", "show", "table", str(ROUTE_TABLE)])
    if r.returncode != 0:
        return False
    return any(line.startswith("default") and _WARP_IFACE in line
               for line in r.stdout.splitlines())


def _table_route_add() -> bool:
    if _table_route_exists():
        return True
    r = _run(["ip", "route", "add", "default", "dev", _WARP_IFACE,
              "table", str(ROUTE_TABLE)])
    return r.returncode == 0


def _table_route_del() -> None:
    _run(["ip", "route", "del", "default", "dev", _WARP_IFACE,
          "table", str(ROUTE_TABLE)])


# ── ip rule (policy routing по fwmark) ───────────────────────────────────
def _ip_rule_exists() -> bool:
    r = _run(["ip", "rule", "show"])
    for line in r.stdout.splitlines():
        m = re.search(r"fwmark\s+(0x[0-9a-fA-F]+|\d+)", line)
        if m and int(m.group(1), 0) == FWMARK and f"lookup {ROUTE_TABLE}" in line:
            return True
    return False


def _ip_rule_add() -> bool:
    if _ip_rule_exists():
        return True
    r = _run(["ip", "rule", "add", "fwmark", str(FWMARK), "table", str(ROUTE_TABLE),
              "priority", str(RULE_PRIORITY)])
    return r.returncode == 0


def _ip_rule_del() -> None:
    _run(["ip", "rule", "del", "fwmark", str(FWMARK), "table", str(ROUTE_TABLE),
          "priority", str(RULE_PRIORITY)])


# ── iptables mangle MARK (по подсетям Telegram) ──────────────────────────
def _ipt_bin(cidr: str) -> str:
    return "ip6tables" if ":" in cidr else "iptables"


def _mangle_rule_exists(cidr: str) -> bool:
    ipt = _ipt_bin(cidr)
    r = _run([ipt, "-t", "mangle", "-C", "OUTPUT", "-d", cidr, "-p", "tcp",
              "-j", "MARK", "--set-mark", str(FWMARK)])
    return r.returncode == 0


def _mangle_add(cidr: str) -> bool:
    if _mangle_rule_exists(cidr):
        return True
    ipt = _ipt_bin(cidr)
    r = _run([ipt, "-t", "mangle", "-A", "OUTPUT", "-d", cidr, "-p", "tcp",
              "-j", "MARK", "--set-mark", str(FWMARK)])
    return r.returncode == 0


def _mangle_del(cidr: str) -> None:
    ipt = _ipt_bin(cidr)
    for _ in range(5):
        if not _mangle_rule_exists(cidr):
            break
        _run([ipt, "-t", "mangle", "-D", "OUTPUT", "-d", cidr, "-p", "tcp",
              "-j", "MARK", "--set-mark", str(FWMARK)])


def _persist_iptables() -> None:
    """Сохраняет полный дамп iptables-save и ставит systemd-сервис,
    восстанавливающий его при загрузке через `iptables-restore --noflush`
    (--noflush — чтобы не затирать правила, выставленные другими модулями,
    например REDIRECT-цепочку tproxy-telemt из mtproto.py).

    Модуль автономен и не зависит от persist-механики mtproto.py."""
    try:
        RULES_DUMP.parent.mkdir(parents=True, exist_ok=True)
        r = _run(["iptables-save"])
        if r.returncode == 0 and r.stdout:
            RULES_DUMP.write_text(r.stdout)
    except Exception as e:
        _warn(f"Не удалось сохранить iptables-дамп: {e}")
        return

    if not RESTORE_SVC.exists():
        RESTORE_SVC.write_text(
            "[Unit]\n"
            "Description=Restore Telemt WARP-routing iptables rules\n"
            "After=network-pre.target\n"
            "Before=network.target\n"
            "Wants=network-pre.target\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "RemainAfterExit=yes\n"
            f"ExecStart=/bin/sh -c 'iptables-restore --noflush < {RULES_DUMP}'\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        _run(["systemctl", "daemon-reload"])
        _run(["systemctl", "enable", "telemt-warp-restore.service"])


# ── Cron watchdog ─────────────────────────────────────────────────────────
def _install_watchdog_cron() -> None:
    CRON_FILE.write_text(
        f"*/2 * * * * root {sys.executable} {MODULE_PATH} --watchdog "
        f">>{WATCHDOG_LOG} 2>&1\n"
    )
    _run(["chmod", "0644", str(CRON_FILE)])


def _remove_watchdog_cron() -> None:
    CRON_FILE.unlink(missing_ok=True)


def _watchdog_tick() -> None:
    """Идемпотентная самопроверка — вызывается из cron каждые 2 минуты.
    Восстанавливает ip rule/route table после ребута и подхватывает
    изменения живого списка подсетей tg_nets.json без участия пользователя."""
    if not is_enabled():
        return
    if not warp_iface_up():
        _log("WARN", "watchdog: интерфейс wg-warp не поднят — пропуск тика")
        return
    refresh_telemt_warp_routing(quiet=True)


# ── Публичный API ─────────────────────────────────────────────────────────
def apply_telemt_warp_routing(enable: bool) -> tuple:
    """Включает/выключает маршрутизацию Telegram-подсетей через WARP.
    Идемпотентна — повторный вызов с тем же enable безопасен.
    Возвращает (ok: bool, message: str)."""
    if enable:
        if not warp_iface_up():
            return False, (
                f"Интерфейс {_WARP_IFACE} не поднят — сначала установите/запустите "
                f"WARP (меню WARP → установка), затем повторите."
            )
        if not _table_route_add():
            return False, f"Не удалось добавить маршрут в таблицу {ROUTE_TABLE}"
        if not _ip_rule_add():
            _table_route_del()
            return False, "Не удалось добавить ip rule (fwmark)"

        nets = _get_tg_nets()
        failed = [n for n in nets if not _mangle_add(n)]
        _persist_iptables()
        _install_watchdog_cron()
        _state_save({"enabled": True, "nets": nets,
                     "updated_at": datetime.now().isoformat()})

        if failed:
            return False, (
                f"Включено частично: {len(nets) - len(failed)}/{len(nets)} подсетей, "
                f"не удалось: {', '.join(failed[:3])}{'…' if len(failed) > 3 else ''}"
            )
        return True, (
            f"Telegram → WARP включено: {len(nets)} подсетей, "
            f"fwmark={FWMARK}, table={ROUTE_TABLE}, watchdog каждые 2 мин."
        )

    # ── disable ──
    state = _state_load()
    for n in state.get("nets", []):
        _mangle_del(n)
    _ip_rule_del()
    _table_route_del()
    _remove_watchdog_cron()
    _persist_iptables()
    _state_save({"enabled": False, "nets": [], "updated_at": datetime.now().isoformat()})
    return True, "Telegram → WARP отключено, все правила сняты."


def refresh_telemt_warp_routing(quiet: bool = False) -> tuple:
    """Переприменяет маркировку под текущий живой список tg_nets.py:
    добавляет новые подсети, убирает устаревшие. No-op, если режим выключен.

    Вызывается: из cron-watchdog, и из меню Telemt после обновления подсетей
    (см. патч в mtproto.py — точки вызова _update_tg_nets_interactive())."""
    state = _state_load()
    if not state.get("enabled"):
        return True, "Режим выключен — нет действий."

    if not warp_iface_up():
        return False, f"Интерфейс {_WARP_IFACE} не поднят."

    _table_route_add()
    _ip_rule_add()

    old_nets = set(state.get("nets", []))
    new_nets = set(_get_tg_nets())

    for n in old_nets - new_nets:
        _mangle_del(n)
    failed = [n for n in (new_nets - old_nets) if not _mangle_add(n)]

    _persist_iptables()
    _state_save({"enabled": True, "nets": sorted(new_nets),
                 "updated_at": datetime.now().isoformat()})

    added, removed = len(new_nets - old_nets), len(old_nets - new_nets)
    msg = f"Синхронизировано: +{added} -{removed} подсетей (всего {len(new_nets)})."
    if failed:
        msg += f" Не удалось добавить: {', '.join(failed[:3])}"
    if not quiet:
        (_warn if failed else _ok)(msg)
    return (not failed), msg


def telemt_warp_status() -> dict:
    state = _state_load()
    enabled = bool(state.get("enabled"))
    nets = state.get("nets", [])
    return {
        "enabled":    enabled,
        "warp_up":    warp_iface_up(),
        "route_ok":   _table_route_exists() if enabled else False,
        "rule_ok":    _ip_rule_exists() if enabled else False,
        "nets_count": len(nets),
        "updated_at": state.get("updated_at"),
    }


def telemt_warp_status_line() -> str:
    st = telemt_warp_status()
    if not st["enabled"]:
        return f"{DIM}выключено{NC}"
    if not st["warp_up"]:
        return f"{RED}включено, НО {_WARP_IFACE} не поднят!{NC}"
    if st["route_ok"] and st["rule_ok"]:
        return f"{GREEN}активно ({st['nets_count']} подсетей){NC}"
    return f"{YELLOW}включено, правила не подтверждены{NC}"


# ── Интерактивное меню ────────────────────────────────────────────────────
def do_telemt_warp_menu() -> None:
    while True:
        st = telemt_warp_status()
        _box_top("🌀  TELEGRAM ЧЕРЕЗ WARP")
        _box_row()
        _box_row(f"  Статус:       {telemt_warp_status_line()}")
        _box_row(f"  Интерфейс:    {_WARP_IFACE} — "
                 f"{(GREEN + 'есть' + NC) if st['warp_up'] else (RED + 'не поднят' + NC)}")
        if st["enabled"]:
            _box_row(f"  Подсетей:     {st['nets_count']}")
            _box_row(f"  ip rule:      {(GREEN + 'OK' + NC) if st['rule_ok'] else (RED + 'нет' + NC)}")
            _box_row(f"  route table:  {(GREEN + 'OK' + NC) if st['route_ok'] else (RED + 'нет' + NC)}")
            if st.get("updated_at"):
                _box_row(f"  Обновлено:    {st['updated_at'][:19]}")
        _box_row()
        _box_info("Включайте на сервере, который физически делает")
        _box_info("исходящее соединение к Telegram (standalone Entry или Exit).")
        _box_info("На Entry с активным tproxy-перехватом эффекта не будет.")
        _box_sep()
        if st["enabled"]:
            _box_item("1", "🔴  Отключить")
            _box_item("2", "🔄  Синхронизировать с tg_nets.py сейчас")
        else:
            _box_item("1", "🟢  Включить")
        _box_back()
        _box_bottom(); print()

        try:
            ch = input(f"  {CYAN}Выбор: {NC}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if ch == "1" and not st["enabled"]:
            ok, msg = apply_telemt_warp_routing(True)
            (_ok if ok else _err)(msg)
            input("Нажмите Enter...")
        elif ch == "1" and st["enabled"]:
            ok, msg = apply_telemt_warp_routing(False)
            (_ok if ok else _err)(msg)
            input("Нажмите Enter...")
        elif ch == "2" and st["enabled"]:
            refresh_telemt_warp_routing()
            input("Нажмите Enter...")
        elif ch in ("q", "", "0", "b"):
            break


# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК (меню или cron --watchdog)
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if "--watchdog" in sys.argv:
        _watchdog_tick()
        sys.exit(0)
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        do_telemt_warp_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)
