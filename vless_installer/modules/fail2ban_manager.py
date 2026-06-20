"""
vless_installer/modules/fail2ban_manager.py
───────────────────────────────────────────────────────────────────────────────
Интерактивная панель управления Fail2ban.

Fail2ban устанавливается и настраивается автоматически на этапе установки
(см. setup_fail2ban() в _core.py — джейлы xray-reality, sshd, nginx-http-auth,
nginx-limit-req: бан за подбор пароли / TLS-ошибки рукопожатия / лишние
запросы к Nginx). Этот модуль — отдельная панель для повседневной работы
с уже настроенным Fail2ban, без необходимости заходить по SSH и руками
редактировать /etc/fail2ban/jail.d/*:

  • Статус службы + сводка по джейлам (сколько IP забанено сейчас)
  • Список забаненных IP + разбан (несколько целей сразу, в т.ч. CIDR/ASN)
  • Бан вручную в выбранном джейле: один IP, несколько IP, диапазон
    (1.2.3.1-1.2.3.50), подсеть (CIDR) или целая ASN (AS12345 — префиксы
    через RIPE Stat). Разбор входной строки делегируется модулю ipban —
    там это уже реализовано и протестировано, логика не дублируется.
  • Тонкая настройка джейла (bantime / findtime / maxretry)
  • Включение/выключение отдельного джейла
  • Просмотр лога Fail2ban
  • История банов за сутки — накопительный read-only список всех "Ban"
    из лога за сегодня (не пропадает при истечении bantime; сам сбрасывается
    с новых суток по дате в логе — ничего не разбанивает и не хранит
    отдельного state-файла)
  • Установка Fail2ban "с нуля" или восстановление базовой конфигурации,
    если служба не установлена / конфиг был случайно удалён вручную
    (вызывает ту же setup_fail2ban() из _core.py — единый источник правды
    для содержимого джейлов, без дублирования и расхождения конфигов)

Точка входа из _core.py:
    from vless_installer.modules.fail2ban_manager import do_manage_fail2ban
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import configparser
import json
import os
import re
import shutil
import subprocess
import sys
import time
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
        from datetime import datetime
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

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False, timeout: int | None = None,
         env: dict | None = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if timeout:
        kw["timeout"] = timeout
    if env:
        kw["env"] = env
    try:
        return subprocess.run(cmd, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="timeout")
    except Exception:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="error")

from vless_installer.modules.box_renderer import (
    _box_top, _box_bottom, _box_sep, _box_row, _box_item, _box_back,
)

# =============================================================================
#  МОДУЛЬ: FAIL2BAN
# =============================================================================

_STATE_FILE  = Path("/var/lib/xray-installer/state.json")
_JAIL_LOCAL  = Path("/etc/fail2ban/jail.d/xray-reality.conf")
_F2B_LOG     = Path("/var/log/fail2ban.log")

# Строка лога вида:
#   2026-06-21 01:43:30,337 fail2ban.actions [2972974]: NOTICE [sshd] Ban 45.156.87.13
_BAN_LINE_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}),\d+\s+'
    r'fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+Ban\s+(?P<ip>\S+)'
)


# ── Низкоуровневые обёртки над fail2ban-client / systemd ──────────────────────
def _f2b_installed() -> bool:
    return shutil.which("fail2ban-client") is not None


def _f2b_active() -> bool:
    r = _run(["systemctl", "is-active", "fail2ban"], capture=True, check=False)
    return r.stdout.strip() == "active"


def _f2b_client(*args: str, timeout: int = 10) -> subprocess.CompletedProcess:
    return _run(["fail2ban-client", *args], capture=True, check=False, timeout=timeout)


def _f2b_reload() -> bool:
    """Перечитывает конфигурацию джейлов. При неудаче — полный перезапуск службы."""
    r = _f2b_client("reload", timeout=15)
    if r.returncode == 0:
        return True
    _run(["systemctl", "restart", "fail2ban"], check=False, quiet=True, timeout=20)
    time.sleep(2)
    return _f2b_active()


def _f2b_list_jails() -> list:
    """Список джейлов из живого fail2ban-client (только если служба активна)."""
    r = _f2b_client("status", timeout=10)
    if r.returncode != 0:
        return []
    m = re.search(r"Jail list:\s*(.*)", r.stdout)
    if not m:
        return []
    return [j.strip() for j in m.group(1).split(",") if j.strip()]


def _extract_int(line: str) -> int:
    m = re.search(r":\s*(\d+)", line)
    return int(m.group(1)) if m else 0


def _f2b_jail_info(jail: str) -> dict:
    """Парсит вывод `fail2ban-client status <jail>`."""
    info = {"currently_failed": 0, "total_failed": 0,
            "currently_banned": 0, "total_banned": 0, "banned_ips": []}
    r = _f2b_client("status", jail, timeout=10)
    if r.returncode != 0:
        return info
    for line in r.stdout.splitlines():
        s = line.strip()
        if "Currently failed" in s:
            info["currently_failed"] = _extract_int(s)
        elif "Total failed" in s:
            info["total_failed"] = _extract_int(s)
        elif "Currently banned" in s:
            info["currently_banned"] = _extract_int(s)
        elif "Total banned" in s:
            info["total_banned"] = _extract_int(s)
        elif "Banned IP list" in s and ":" in s:
            after = s.split(":", 1)[1].strip()
            info["banned_ips"] = after.split() if after else []
    return info


# ── История банов за сутки (накопительно, read-only, не влияет на реальный бан) ─
def _f2b_log_lines() -> list:
    """
    Содержимое /var/log/fail2ban.log + предыдущего ротированного файла
    (fail2ban.log.1, если logrotate уже успел провернуть ротацию сегодня) —
    чтобы не терять события начала суток, попавшие в файл до ротации.
    """
    paths = [_F2B_LOG, Path(str(_F2B_LOG) + ".1")]
    lines: list = []
    for p in paths:
        if not p.exists():
            continue
        try:
            lines.extend(p.read_text(errors="replace").splitlines())
        except Exception:
            pass
    return lines


def _f2b_today_ban_history() -> list:
    """
    Собирает все события "Ban" из лога Fail2ban за СЕГОДНЯ (по дате,
    указанной в самой строке лога). Список естественным образом не
    "затирается" новыми банами и сам сбрасывается с наступлением новых
    суток — строки с прошлой датой просто не проходят фильтр, отдельный
    state-файл и логика сброса не нужны.

    ВАЖНО: функция только ЧИТАЕТ лог. Она не банит и не разбанивает —
    реального состояния fail2ban (и тем более VLESS Reality/прочих служб)
    это никак не касается. Даже если IP уже разбанен по истечении bantime,
    он останется в этом списке как факт истории за сегодня.

    Возвращает список dict {ip, jail, first_seen, last_seen, count},
    отсортированный по last_seen (новые сверху).
    """
    today = time.strftime("%Y-%m-%d")
    stats: dict = {}
    for line in _f2b_log_lines():
        m = _BAN_LINE_RE.match(line)
        if not m or m.group("date") != today:
            continue
        key = (m.group("ip"), m.group("jail"))
        ts = m.group("time")
        e = stats.get(key)
        if e is None:
            stats[key] = {"ip": m.group("ip"), "jail": m.group("jail"),
                          "first_seen": ts, "last_seen": ts, "count": 1}
        else:
            e["last_seen"] = ts
            e["count"] += 1
    return sorted(stats.values(), key=lambda e: e["last_seen"], reverse=True)


def _f2b_ban(jail: str, ip: str) -> bool:
    r = _f2b_client("set", jail, "banip", ip, timeout=15)
    return r.returncode == 0


def _f2b_ban_many(jail: str, ips: list, chunk: int = 50) -> int:
    """
    Банит список IP/CIDR в джейле пачками — fail2ban-client принимает
    несколько IP за один вызов banip, поэтому шлём их группами по `chunk`,
    а не по одному (важно для ASN, где префиксов может быть сотни).
    Возвращает точное число НОВЫХ записей (диф "Banned IP list" до/после),
    а не просто факт успешного завершения команды.
    """
    if not ips:
        return 0
    before = set(_f2b_jail_info(jail)["banned_ips"])
    for i in range(0, len(ips), chunk):
        batch = [str(x) for x in ips[i:i + chunk]]
        _f2b_client("set", jail, "banip", *batch, timeout=30)
    after = set(_f2b_jail_info(jail)["banned_ips"])
    return len(after - before)


def _f2b_unban(ip: str) -> bool:
    """Разбан по всем джейлам сразу (глобальная команда fail2ban-client unban)."""
    r = _f2b_client("unban", ip, timeout=15)
    return r.returncode == 0


def _f2b_unban_many(ips: list) -> tuple:
    """
    Разбанивает список IP/CIDR по всем джейлам сразу. Каждый элемент —
    отдельным вызовом (а не одной пачкой), чтобы один "не найден" не отменял
    разбан остальных. Возвращает (успешно, неудачно).
    """
    ok = fail = 0
    for ip in ips:
        if _f2b_unban(str(ip)):
            ok += 1
        else:
            fail += 1
    return ok, fail


# ── Разбор ввода: одиночный IP / несколько IP / диапазон / CIDR / ASN ─────────
def _resolve_ban_targets(raw: str) -> list:
    """
    Разбирает строку пользовательского ввода (несколько токенов через запятую
    или пробел) на список (display, kind, [CIDR, ...]).

    Сам парсинг (что является IP/CIDR/диапазоном/ASN, скачивание префиксов
    ASN с RIPE Stat) делегируется модулю ipban — там это уже реализовано
    и проверено в работе (см. vless_installer/modules/ipban.py), поэтому
    логика не дублируется и не может разойтись между двумя модулями.
    Импорт лениво через importlib — по той же причине, что и в
    _f2b_install_or_repair() (единый источник правды без циклических импортов).
    """
    import importlib
    ipban = importlib.import_module("vless_installer.modules.ipban")
    tokens = [t.strip() for t in raw.replace(",", " ").split() if t.strip()]
    results = []
    for token in tokens:
        try:
            display, kind, cidrs = ipban._resolve_to_cidrs(token)
            results.append((display, kind, cidrs))
        except (ValueError, RuntimeError) as exc:
            _warn(f"{token}: {exc}")
    return results


# ── Работа с jail.d/xray-reality.conf (bantime/findtime/maxretry/enabled) ─────
def _f2b_read_conf() -> configparser.RawConfigParser:
    cp = configparser.RawConfigParser()
    cp.optionxform = str  # не приводим ключи к нижнему регистру
    if _JAIL_LOCAL.exists():
        try:
            cp.read(_JAIL_LOCAL, encoding="utf-8")
        except Exception:
            pass
    return cp


def _f2b_write_conf(cp: configparser.RawConfigParser) -> bool:
    _JAIL_LOCAL.parent.mkdir(parents=True, exist_ok=True)
    try:
        with _JAIL_LOCAL.open("w", encoding="utf-8") as f:
            cp.write(f)
    except Exception:
        return False
    return _f2b_reload()


# ── Установка пакета / восстановление базовой конфигурации ────────────────────
def _f2b_install_package() -> bool:
    if shutil.which("apt-get"):
        _run(["apt-get", "update", "-q"], check=False, quiet=True, timeout=90)
        env = dict(os.environ); env["DEBIAN_FRONTEND"] = "noninteractive"
        _run(["apt-get", "install", "-y", "-q", "fail2ban"],
             check=False, quiet=True, timeout=180, env=env)
    elif shutil.which("dnf"):
        _run(["dnf", "install", "-y", "-q", "fail2ban"], check=False, quiet=True, timeout=180)
    elif shutil.which("yum"):
        _run(["yum", "install", "-y", "-q", "fail2ban"], check=False, quiet=True, timeout=180)
    else:
        return False
    return _f2b_installed()


def _f2b_install_or_repair() -> bool:
    """
    Устанавливает Fail2ban (если не установлен) и (пере)создаёт базовую
    конфигурацию джейлов. Намеренно вызывает setup_fail2ban() из _core.py
    лениво через importlib — это тот же код, что выполняется при первичной
    установке, поэтому конфигурация джейлов гарантированно не расходится
    с тем, что генерирует сам установщик.
    """
    if not _f2b_installed():
        if not _f2b_install_package():
            return False
    try:
        import importlib
        _core = importlib.import_module("vless_installer._core")
        _core.setup_fail2ban()
    except Exception:
        return False
    return _f2b_active()


def _f2b_conf_jails() -> list:
    return list(_f2b_read_conf().sections())


# =============================================================================
#  ИНТЕРАКТИВНОЕ МЕНЮ
# =============================================================================
def do_manage_fail2ban() -> None:
    """Интерактивное управление Fail2ban."""
    while True:
        os.system("clear")
        print()

        installed  = _f2b_installed()
        active     = _f2b_active() if installed else False
        live_jails = _f2b_list_jails() if active else []
        conf_jails = _f2b_conf_jails()
        jail_names = live_jails if live_jails else conf_jails

        total_banned = 0
        if active and live_jails:
            for j in live_jails:
                total_banned += _f2b_jail_info(j)["currently_banned"]

        _box_top("🛡️  FAIL2BAN — ЗАЩИТА ОТ ПЕРЕБОРА")
        _box_row(f"  {DIM}Банит IP за перебор авторизации, TLS-ошибки рукопожатия{NC}")
        _box_row(f"  {DIM}и лишние запросы к Nginx. Джейлы: xray-reality, sshd,{NC}")
        _box_row(f"  {DIM}nginx-http-auth, nginx-limit-req.{NC}")
        _box_sep()
        if not installed:
            _box_row(f"  Статус:    {RED}не установлен{NC}")
        else:
            _box_row(f"  Статус:    {(GREEN+'● активен') if active else (DIM+'○ остановлен')}{NC}")
            _box_row(f"  Джейлов:   {CYAN}{len(jail_names)}{NC}")
            _box_row(f"  Забанено:  {(RED if total_banned else DIM)}{total_banned}{NC} IP (сейчас)")
        _box_sep()

        if not installed:
            _box_item("1", "📥 Установить и настроить Fail2ban")
        else:
            _box_item("1", f"{'Остановить' if active else 'Запустить'} Fail2ban")
            _box_item("2", "🔁 Перезапустить / применить конфигурацию")
            _box_item("3", f"🚫 Забаненные IP  {DIM}({total_banned} шт.){NC}")
            _box_item("4", "➕ Забанить вручную (IP/диапазон/ASN)")
            _box_item("5", f"⚙️  Настройка джейла  {DIM}(bantime/findtime/maxretry){NC}")
            _box_item("6", "🔌 Включить/выключить джейл")
            _box_item("7", "📋 Лог Fail2ban (последние 30 строк)")
            _box_item("8", "🛠️  Восстановить базовую конфигурацию")
            _box_item("9", "📊 История банов за сутки  (накопительно)")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch in ("q", ""):
            break

        # ── Fail2ban не установлен — доступен только пункт установки ──────────
        if not installed:
            if ch == "1":
                print()
                _info("Устанавливаю и настраиваю Fail2ban...")
                if _f2b_install_or_repair():
                    _success("Fail2ban установлен и настроен")
                else:
                    _warn("Не удалось установить Fail2ban — проверьте интернет-соединение "
                          "и доступность репозиториев пакетов")
                input(f"{BLUE}Нажмите Enter...{NC}")
            else:
                _warn("Неверный выбор.")
                time.sleep(1)
            continue

        # ── 1. Старт/стоп службы ───────────────────────────────────────────────
        if ch == "1":
            print()
            if active:
                _run(["systemctl", "stop", "fail2ban"], check=False, quiet=True, timeout=15)
                time.sleep(1)
                if not _f2b_active():
                    _success("Fail2ban остановлен")
                else:
                    _warn("Не удалось остановить Fail2ban")
            else:
                _run(["systemctl", "start", "fail2ban"], check=False, quiet=True, timeout=15)
                time.sleep(2)
                if _f2b_active():
                    _success("Fail2ban запущен")
                else:
                    _warn("Не удалось запустить — проверьте: journalctl -u fail2ban -n 20")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 2. Reload / restart ────────────────────────────────────────────────
        elif ch == "2":
            print()
            _info("Применение конфигурации (reload)...")
            if _f2b_reload():
                _success("Конфигурация применена")
            else:
                _warn("Fail2ban не поднялся после reload/restart — "
                      "проверьте: journalctl -u fail2ban -n 20")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 3. Забаненные IP + разбан ──────────────────────────────────────────
        elif ch == "3":
            print()
            rows = []
            for j in jail_names:
                for ip in _f2b_jail_info(j)["banned_ips"]:
                    rows.append((ip, j))
            _box_top(f"Забаненные IP ({len(rows)})")
            if not rows:
                _box_row(f"  {DIM}Список пуст{NC}")
            else:
                _box_row(f"  {BOLD}{'#':<4}{'IP':<22}Джейл{NC}")
                _box_sep()
                for i, (ip, j) in enumerate(rows, 1):
                    _box_row(f"  {CYAN}{i:<4}{NC}{RED}{ip:<22}{NC}{DIM}{j}{NC}")
                _box_sep()
                _box_row(f"  {DIM}Номер(а)/IP/CIDR/диапазон/ASN через запятую{NC}")
                _box_row(f"  {DIM}или пробел (можно несколько), Enter — назад{NC}")
            _box_bottom()
            if rows:
                raw = input("  Разбанить: ").strip()
                if raw:
                    tokens = [t.strip() for t in raw.replace(",", " ").split() if t.strip()]
                    targets: list = []
                    for t in tokens:
                        if t.isdigit() and 1 <= int(t) <= len(rows):
                            targets.append(rows[int(t) - 1][0])
                        else:
                            # IP / CIDR / диапазон / ASN — разворачиваем в CIDR
                            for _disp, _kind, cidrs in _resolve_ban_targets(t):
                                targets.extend(cidrs)
                    if not targets:
                        _warn("Не удалось разобрать ввод")
                    else:
                        ok, fail = _f2b_unban_many(targets)
                        if ok:
                            _success(f"Разбанено: {ok}")
                        if fail:
                            _warn(f"Не найдено / не было забанено: {fail}")
                    input(f"{BLUE}Нажмите Enter...{NC}")
            else:
                input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 4. Бан вручную: IP / несколько IP / диапазон / CIDR / ASN ──────────
        elif ch == "4":
            print()
            if not jail_names:
                _warn("Нет доступных джейлов")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            _box_top("Забанить вручную")
            for i, j in enumerate(jail_names, 1):
                _box_item(str(i), j)
            _box_bottom()
            raw_j = input("  Номер джейла: ").strip()
            if not (raw_j.isdigit() and 1 <= int(raw_j) <= len(jail_names)):
                _warn("Неверный выбор")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            jail = jail_names[int(raw_j) - 1]

            _box_top("Что банить")
            _box_row(f"  {DIM}Можно несколько целей через запятую или пробел:{NC}")
            _box_row()
            _box_row(f"    {CYAN}1.2.3.4{NC}              — одиночный IP")
            _box_row(f"    {CYAN}10.0.0.0/24{NC}          — подсеть (CIDR)")
            _box_row(f"    {CYAN}10.0.0.1-10.0.0.255{NC}  — диапазон IPv4")
            _box_row(f"    {CYAN}AS12345{NC}              — вся ASN (через RIPE Stat)")
            _box_row()
            _box_row(f"  {DIM}Пример: 1.2.3.4, 10.0.0.0/8, AS1234{NC}")
            _box_bottom()
            raw_inp = input("  Ввод: ").strip()
            if not raw_inp:
                _warn("Не указано, что банить")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            targets = _resolve_ban_targets(raw_inp)
            if not targets:
                _warn("Не удалось разобрать ни одной цели")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            all_cidrs: list = []
            for display, kind, cidrs in targets:
                all_cidrs.extend(cidrs)
                _info(f"{display} ({kind}): {len(cidrs)} CIDR")

            print()
            _info(f"Применяю бан в джейле {jail} ({len(all_cidrs)} CIDR)...")
            newly = _f2b_ban_many(jail, all_cidrs)
            if newly:
                _success(f"Забанено новых записей: {newly} (джейл {jail})")
            else:
                _warn("Новых записей не добавлено — возможно, уже забанены "
                      "или джейл неактивен (служба запущена?)")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 5. Настройка bantime/findtime/maxretry ─────────────────────────────
        elif ch == "5":
            print()
            cp = _f2b_read_conf()
            secs = list(cp.sections())
            if not secs:
                _warn("Конфигурация джейлов не найдена — используйте пункт "
                      "«Восстановить базовую конфигурацию»")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            _box_top("Настройка джейла")
            for i, s in enumerate(secs, 1):
                _box_item(str(i), s)
            _box_bottom()
            raw_j = input("  Номер джейла: ").strip()
            if not (raw_j.isdigit() and 1 <= int(raw_j) <= len(secs)):
                _warn("Неверный выбор")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            sec = secs[int(raw_j) - 1]
            cur_bt = cp.get(sec, "bantime",  fallback="3600")
            cur_ft = cp.get(sec, "findtime", fallback="600")
            cur_mr = cp.get(sec, "maxretry", fallback="5")
            print()
            new_bt = input(f"  bantime, сек  [{cur_bt}]: ").strip() or cur_bt
            new_ft = input(f"  findtime, сек [{cur_ft}]: ").strip() or cur_ft
            new_mr = input(f"  maxretry      [{cur_mr}]: ").strip() or cur_mr
            if not (new_bt.isdigit() and new_ft.isdigit() and new_mr.isdigit()):
                _warn("Значения должны быть целыми числами — отменено")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            cp.set(sec, "bantime",  new_bt)
            cp.set(sec, "findtime", new_ft)
            cp.set(sec, "maxretry", new_mr)
            if _f2b_write_conf(cp):
                _success(f"Джейл {sec}: bantime={new_bt} findtime={new_ft} maxretry={new_mr}")
            else:
                _warn("Настройки сохранены в файл, но Fail2ban не подтвердил reload — "
                      "проверьте: journalctl -u fail2ban -n 20")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 6. Включить/выключить джейл ─────────────────────────────────────────
        elif ch == "6":
            print()
            cp = _f2b_read_conf()
            secs = list(cp.sections())
            if not secs:
                _warn("Конфигурация джейлов не найдена")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            _box_top("Включить/выключить джейл")
            for i, s in enumerate(secs, 1):
                en = cp.get(s, "enabled", fallback="true").strip().lower() == "true"
                state_str = f"{GREEN}вкл{NC}" if en else f"{DIM}выкл{NC}"
                _box_item(str(i), f"{s}  [{state_str}]")
            _box_bottom()
            raw_j = input("  Номер джейла: ").strip()
            if not (raw_j.isdigit() and 1 <= int(raw_j) <= len(secs)):
                _warn("Неверный выбор")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            sec = secs[int(raw_j) - 1]
            cur = cp.get(sec, "enabled", fallback="true").strip().lower() == "true"
            cp.set(sec, "enabled", "false" if cur else "true")
            if _f2b_write_conf(cp):
                _success(f"Джейл {sec}: {'выключен' if cur else 'включён'}")
            else:
                _warn("Настройки сохранены в файл, но Fail2ban не подтвердил reload")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 7. Лог ───────────────────────────────────────────────────────────────
        elif ch == "7":
            print()
            if _F2B_LOG.exists():
                try:
                    lines = _F2B_LOG.read_text(errors="replace").splitlines()[-30:]
                except Exception:
                    lines = []
                _box_top("📋 Лог Fail2ban (последние 30 строк)")
                if not lines:
                    _box_row(f"  {DIM}Лог пуст{NC}")
                for line in lines:
                    col = RED if " Ban " in line else (YELLOW if " Unban " in line else DIM)
                    _box_row(f"  {col}{line[:100]}{NC}")
                _box_bottom()
            else:
                _warn(f"Файл лога не найден: {_F2B_LOG}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 8. Восстановить базовую конфигурацию ─────────────────────────────────
        elif ch == "8":
            print()
            _info("Восстанавливаю базовую конфигурацию джейлов...")
            if _f2b_install_or_repair():
                _success("Базовая конфигурация восстановлена, Fail2ban активен")
            else:
                _warn("Не удалось восстановить конфигурацию — "
                      "проверьте: journalctl -u fail2ban -n 20")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 9. История банов за сутки (накопительно, read-only) ──────────────────
        elif ch == "9":
            print()
            hist = _f2b_today_ban_history()
            _box_top(f"📊 История банов за сегодня ({len(hist)})")
            _box_row(f"  {DIM}Список накопительный за текущие сутки — не зависит от{NC}")
            _box_row(f"  {DIM}bantime: IP остаётся здесь, даже если уже разбанен по{NC}")
            _box_row(f"  {DIM}истечении bantime. Сброс — автоматически с новых суток.{NC}")
            _box_sep()
            if not hist:
                _box_row(f"  {DIM}За сегодня банов не было (или лог пуст/недоступен){NC}")
            else:
                _box_row(f"  {BOLD}{'#':<4}{'IP':<22}{'Джейл':<14}{'Раз':<5}{'Впервые':<10}Последний{NC}")
                _box_sep()
                for i, e in enumerate(hist, 1):
                    _box_row(
                        f"  {CYAN}{i:<4}{NC}{RED}{e['ip']:<22}{NC}{DIM}{e['jail']:<14}{NC}"
                        f"{e['count']:<5}{DIM}{e['first_seen']:<10}{NC}{e['last_seen']}"
                    )
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")

        else:
            _warn("Неверный выбор.")
            time.sleep(1)
