"""
vless_installer/modules/mieru_stats.py
───────────────────────────────────────────────────────────────────────────────
Статистика трафика Mieru (mita-сервер).

Mieru не пишет access.log с байтами — поэтому используем несколько
источников, комбинируя их в единую картину:

Источники данных (без новых демонов, без сторонних зависимостей):
  • iptables -L INPUT -n -v -x  — байты/пакеты на TCP/UDP-порту mita
      Это основной и наиболее достоверный источник объёма трафика.
  • journalctl -u mita           — события соединений, ошибки, warn
      Парсим строки accepted / closed / error / warning за период.
  • ss -tnp / ss -unp            — активные соединения (TCP/UDP) на порт
  • /proc/net/sockstat            — глобальная статистика TCP/UDP сокетов
  • timedatectl                  — синхронизация NTP (Mieru критично зависит)

Метрики:
  • Суммарный трафик (байты, пакеты) — iptables INPUT
  • Скорость (байт/с) между двумя замерами через кэш
  • Кол-во соединений accepted / closed — из journalctl
  • Кол-во ошибок / предупреждений — из journalctl
  • Активных соединений сейчас — ss
  • Гистограмма активности по 10-мин интервалам (из журнала)
  • Тренд: рост / спад / стабильно
  • NTP-статус (отклонение > 30 сек = Mieru не будет принимать клиентов)
  • Живое обновление каждые 30 сек

Не трогает:
  • Xray config.json / state.json
  • iptables-правила других модулей
  • Конфиги mieru.py

Точка входа из mieru.py:
    from vless_installer.modules.mieru_stats import do_mieru_stats_menu
    do_mieru_stats_menu()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА — независимые от родительского модуля
# ══════════════════════════════════════════════════════════════════════════════
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
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ══════════════════════════════════════════════════════════════════════════════
#  ПУТИ
# ══════════════════════════════════════════════════════════════════════════════
_SERVICE_NAME = "mita"
_MODULE_STATE = Path("/var/lib/xray-installer/mieru.json")
_STATS_CACHE  = Path("/var/lib/xray-installer/mieru_stats_cache.json")

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ (собственный — в стиле mieru.py)
# ══════════════════════════════════════════════════════════════════════════════
import re as _re
import unicodedata as _ud

def _plain(s: str) -> str:
    return _re.sub(r'\033\[[0-9;]*m', '', s)

def _wlen(s: str) -> int:
    w = 0
    for ch in _plain(s):
        w += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
    return w

_BOX_W = 66

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
        acc, out = 0, ""
        for ch in _plain(text):
            cw = 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc + cw > _BOX_W - 1: break
            out += ch; acc += cw
        text = out + "…"; w = _wlen(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")

def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

def _box_ok(msg: str)   -> None: _box_row(f"  {GREEN}✓{NC}  {msg}")
def _box_warn(msg: str) -> None: _box_row(f"  {YELLOW}⚠{NC}  {msg}")
def _box_info(msg: str) -> None: _box_row(f"  {CYAN}→{NC}  {msg}")
def _box_err(msg: str)  -> None: _box_row(f"  {RED}✗{NC}  {msg}")

def _box_kv(key: str, val: str, kw: int = 24) -> None:
    key_col = f"{CYAN}{key}{NC}"
    pad = kw - _wlen(key_col)
    _box_row(f"  {key_col}{' ' * max(0, pad)}  {val}")

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
class _Cancelled(Exception):
    pass

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True); input()
    except (KeyboardInterrupt, EOFError):
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

def _run(cmd: list, capture: bool = False,
         timeout: int = 10) -> subprocess.CompletedProcess:
    kw: dict = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8",
                  errors="replace", timeout=timeout)
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                  timeout=timeout)
    try:
        return subprocess.run(cmd, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="timeout")
    except Exception:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="error")

def _bytes_human(b: int) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} ПБ"

def _load_mieru_state() -> dict:
    if not _MODULE_STATE.exists(): return {}
    try: return json.loads(_MODULE_STATE.read_text())
    except Exception: return {}

def _load_cache() -> dict:
    try:
        if _STATS_CACHE.exists():
            return json.loads(_STATS_CACHE.read_text())
    except Exception:
        pass
    return {}

def _save_cache(data: dict) -> None:
    try:
        _STATS_CACHE.parent.mkdir(parents=True, exist_ok=True)
        _STATS_CACHE.write_text(json.dumps(data, ensure_ascii=False))
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  ПОРТЫ: читаем portRange прямо из /etc/mita/server.json
# ══════════════════════════════════════════════════════════════════════════════
def _get_mita_ports() -> tuple[int, int]:
    """
    Читает portRange из /etc/mita/server.json.
    Возвращает (port_start, port_end).
    Поддерживает форматы: "2012", "2012-2022", "2012:2022".
    """
    cfg_path = Path("/etc/mita/server.json")
    try:
        if cfg_path.exists():
            data = json.loads(cfg_path.read_text())
            # portRange может быть в portBindings[0].portRange или верхнем уровне
            pr = None
            if "portBindings" in data and data["portBindings"]:
                pr = data["portBindings"][0].get("portRange", "")
            if not pr:
                pr = data.get("portRange", "")
            if pr:
                pr = str(pr).strip()
                for sep in ("-", ":"):
                    if sep in pr:
                        parts = pr.split(sep, 1)
                        return int(parts[0]), int(parts[1])
                return int(pr), int(pr)
    except Exception:
        pass
    return 2012, 2022


# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES: создаём счётчик на диапазон портов mita если его нет
# ══════════════════════════════════════════════════════════════════════════════
def _ensure_iptables_rule(port_start: int, port_end: int, proto: str) -> bool:
    """
    Проверяет наличие правила iptables для диапазона портов mita.
    Если правила нет — создаёт его (только ACCEPT-счётчик, без блокировок).
    Возвращает True если правило уже было или успешно создано.
    """
    p = proto.lower()
    if port_start == port_end:
        dport_arg = str(port_start)
        check_str = f"dpt:{port_start}"
    else:
        dport_arg = f"{port_start}:{port_end}"
        check_str = f"dpt:{port_start}:{port_end}"

    try:
        r = _run(["iptables", "-L", "INPUT", "-n", "-v", "-x"], capture=True)
        for line in r.stdout.splitlines():
            if p in line.lower() and check_str in line:
                return True  # правило уже есть

        # Правила нет — создаём
        # -I INPUT 1 гарантирует что счётчик первый (перед DROP-правилами)
        cmd = [
            "iptables", "-I", "INPUT", "1",
            "-p", p,
            "--dport", dport_arg,
            "-j", "ACCEPT",
            "-m", "comment", "--comment", "mita-stats"
        ]
        r2 = _run(cmd)
        return r2.returncode == 0
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  ИСТОЧНИК 1: iptables — байты/пакеты
# ══════════════════════════════════════════════════════════════════════════════
def _iptables_stats(port_start: int, port_end: int, proto: str) -> dict:
    """
    Читает счётчики байт и пакетов из iptables INPUT для правила mita.
    Возвращает {bytes, packets}.
    proto: TCP или UDP.
    """
    result = {"bytes": 0, "packets": 0}
    try:
        r = _run(["iptables", "-L", "INPUT", "-n", "-v", "-x"], capture=True)
        for line in r.stdout.splitlines():
            lp = line.lower()
            # Ищем строку с нашим протоколом и портом
            if proto.lower() not in lp:
                continue
            # Диапазон портов: --dport start:end
            if port_start != port_end:
                if f"dpt:{port_start}:{port_end}" not in line and \
                   f"dport {port_start}:{port_end}" not in line:
                    continue
            else:
                if f"dpt:{port_start}" not in line and \
                   f"dport {port_start}" not in line:
                    continue
            parts = line.split()
            # Формат iptables -vnxL: pkts bytes target prot ...
            if len(parts) >= 2:
                try:
                    result["packets"] = int(parts[0])
                    result["bytes"]   = int(parts[1])
                    break
                except (ValueError, IndexError):
                    pass
    except Exception:
        pass
    return result

def _iptables_speed(port_start: int, port_end: int, proto: str) -> dict:
    """
    Возвращает {bytes, packets, speed_bps, speed_pps} используя кэш.
    """
    now_ts = time.time()
    cache  = _load_cache()
    prev_ts    = cache.get("mita_ipt_ts", now_ts)
    prev_bytes = cache.get("mita_ipt_bytes", 0)

    stats   = _iptables_stats(port_start, port_end, proto)
    elapsed = max(now_ts - prev_ts, 1.0)
    delta_b = max(stats["bytes"] - prev_bytes, 0)
    speed_b = delta_b / elapsed

    cache.update(
        mita_ipt_ts=now_ts,
        mita_ipt_bytes=stats["bytes"],
    )
    _save_cache(cache)

    return {
        "bytes":     stats["bytes"],
        "packets":   stats["packets"],
        "speed_bps": speed_b,
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ИСТОЧНИК 2: journalctl — события соединений
# ══════════════════════════════════════════════════════════════════════════════
# Паттерны из логов mita:
#   INFO  accepted connection from X.X.X.X:PORT
#   INFO  connection closed ...
#   ERROR ...
#   WARNING ...
#   WARN  ...
_RE_JNL_TS = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"       # systemd journal monotonic
    r"|(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"           # Mmm DD HH:MM:SS
)
_RE_ACCEPTED  = re.compile(r"accepted|accept", re.I)
_RE_CLOSED    = re.compile(r"closed|close|disconnect", re.I)
_RE_ERROR     = re.compile(r"\berror\b|\bfatal\b|\bpanic\b", re.I)
_RE_WARN      = re.compile(r"\bwarn(ing)?\b", re.I)
_RE_AUTH_FAIL = re.compile(r"auth.*fail|invalid.*password|timestamp.*mismatch|"
                            r"replay|time.*diff", re.I)

def _parse_journal(window_minutes: int = 60) -> dict:
    """
    Парсит journalctl -u mita за последние window_minutes минут.
    """
    result = {
        "accepted": 0,
        "closed":   0,
        "errors":   0,
        "warnings": 0,
        "auth_fail": 0,
        "slots":    {},   # 10-мин слоты: {slot: {accepted, errors}}
        "recent_errors": [],   # последние 5 строк с ошибками
        "raw_lines": 0,
    }
    slots: dict = defaultdict(lambda: {"accepted": 0, "errors": 0, "warnings": 0})

    since = (datetime.now() - timedelta(minutes=window_minutes)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    try:
        r = _run(
            ["journalctl", "-u", _SERVICE_NAME,
             "--since", since,
             "--no-pager", "--output=short-iso",
             "-n", "5000"],
            capture=True, timeout=15,
        )
        lines = r.stdout.splitlines()
        result["raw_lines"] = len(lines)

        for line in lines:
            # Извлекаем временную метку из journalctl short-iso формата:
            # 2026-06-18T14:35:22+0300 hostname mita[PID]: message
            slot = None
            m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2})", line)
            if m:
                try:
                    dt = datetime.fromisoformat(m.group(1))
                    slot = dt.strftime("%H:%M")[:-1] + "0"
                except ValueError:
                    pass

            if _RE_ACCEPTED.search(line):
                result["accepted"] += 1
                if slot: slots[slot]["accepted"] += 1

            elif _RE_CLOSED.search(line):
                result["closed"] += 1

            if _RE_AUTH_FAIL.search(line):
                result["auth_fail"] += 1

            if _RE_ERROR.search(line):
                result["errors"] += 1
                if slot: slots[slot]["errors"] += 1
                if len(result["recent_errors"]) < 5:
                    # Сохраняем только текст после префикса
                    msg = re.sub(r"^\S+\s+\S+\s+\S+:\s*", "", line)
                    result["recent_errors"].append(msg[:80])

            elif _RE_WARN.search(line):
                result["warnings"] += 1
                if slot: slots[slot]["warnings"] += 1

    except Exception:
        pass

    result["slots"] = dict(slots)
    return result

# ══════════════════════════════════════════════════════════════════════════════
#  ИСТОЧНИК 3: ss — активные соединения
# ══════════════════════════════════════════════════════════════════════════════
def _active_connections(port_start: int, port_end: int, proto: str) -> int:
    """Считает активные TCP/UDP соединения на диапазон портов."""
    total = 0
    try:
        flag = "-tn" if proto.upper() == "TCP" else "-un"
        r = _run(["ss", flag, "state", "established"], capture=True)
        for line in r.stdout.splitlines():
            if "Recv-Q" in line or "State" in line:
                continue
            # Ищем порт в Local Address или Peer Address
            m = re.search(r':(\d+)\s', line)
            if m:
                p = int(m.group(1))
                if port_start <= p <= port_end:
                    total += 1
    except Exception:
        pass
    return total

# ══════════════════════════════════════════════════════════════════════════════
#  ИСТОЧНИК 4: NTP статус
# ══════════════════════════════════════════════════════════════════════════════
def _ntp_status() -> tuple[bool, str, float]:
    """
    Возвращает (is_synced, description, offset_ms).
    offset_ms — отклонение в миллисекундах (если доступно).
    """
    # timedatectl
    try:
        r = _run(["timedatectl", "status"], capture=True)
        out = r.stdout or ""
        synced = "synchronized: yes" in out or "NTP synchronized: yes" in out
        # Попытка извлечь offset из chronyc
        offset_ms = 0.0
        r2 = _run(["chronyc", "tracking"], capture=True)
        if r2.returncode == 0:
            m = re.search(r"System time\s*:\s*([\d.]+)\s*seconds\s*(slow|fast)", r2.stdout)
            if m:
                offset_ms = float(m.group(1)) * 1000
                direction = m.group(2)
                if direction == "fast":
                    offset_ms = -offset_ms
        if synced:
            if offset_ms:
                return True, f"синхронизирован ({offset_ms:+.0f} мс)", offset_ms
            return True, "синхронизирован (NTP)", 0.0
        return False, "НЕ синхронизирован!", 0.0
    except Exception:
        pass
    return True, "статус неизвестен", 0.0

# ══════════════════════════════════════════════════════════════════════════════
#  ГИСТОГРАММА (из journal-слотов)
# ══════════════════════════════════════════════════════════════════════════════
def _render_histogram(slots: dict) -> None:
    if not slots:
        _box_row(f"  {DIM}Нет данных для гистограммы{NC}")
        return

    keys    = sorted(slots.keys())
    max_acc = max((slots[k]["accepted"] for k in keys), default=1) or 1
    bar_w   = 24

    _box_row(f"  {BOLD}{CYAN}{'Время':<7}  {'Принято':>7}  {'Ошибок':>6}  {'Предупр':>7}  График{NC}")
    _box_sep()
    for slot in keys:
        acc  = slots[slot]["accepted"]
        err  = slots[slot]["errors"]
        wrn  = slots[slot].get("warnings", 0)
        ok_w = int(acc / max_acc * bar_w) if max_acc else 0
        er_w = min(int(err / max(max_acc, 1) * bar_w), bar_w - ok_w)
        bar  = f"{GREEN}{'█' * ok_w}{NC}{RED}{'▓' * er_w}{NC}"
        err_s = f"{RED}{err:>6}{NC}" if err else f"{DIM}{err:>6}{NC}"
        wrn_s = f"{YELLOW}{wrn:>7}{NC}" if wrn else f"{DIM}{wrn:>7}{NC}"
        _box_row(f"  {DIM}{slot:<7}{NC}  {GREEN}{acc:>7}{NC}  {err_s}  {wrn_s}  {bar}")

# ══════════════════════════════════════════════════════════════════════════════
#  ТРЕНД соединений
# ══════════════════════════════════════════════════════════════════════════════
def _calc_trend(slots: dict) -> str:
    keys = sorted(slots.keys())
    if len(keys) < 3:
        return f"{DIM}недостаточно данных{NC}"
    recent = keys[-2:]
    older  = keys[-4:-2] if len(keys) >= 4 else keys[:2]

    def avg_acc(ks: list) -> float:
        vals = [slots[k]["accepted"] for k in ks if k in slots]
        return sum(vals) / len(vals) if vals else 0.0

    r = avg_acc(recent)
    o = avg_acc(older)
    if o == 0 and r == 0:
        return f"{DIM}нет активности{NC}"
    if o == 0:
        return f"{GREEN}↑ растёт{NC}"
    ratio = r / o
    if ratio >= 1.3:
        return f"{GREEN}↑ рост активности{NC}"
    elif ratio <= 0.7:
        return f"{YELLOW}↓ спад активности{NC}"
    return f"{CYAN}→ стабильно{NC}"

# ══════════════════════════════════════════════════════════════════════════════
#  ОТОБРАЖЕНИЕ ПОЛНОЙ СТАТИСТИКИ
# ══════════════════════════════════════════════════════════════════════════════
def _show_stats(window_minutes: int = 60) -> None:
    os.system("clear")
    state      = _load_mieru_state()
    # Читаем порты прямо из /etc/mita/server.json (приоритет над state)
    port_start, port_end = _get_mita_ports()
    # Фоллбэк на state только если конфиг не читается
    if port_start == 2012 and port_end == 2022 and             "port_start" in state:
        port_start = state.get("port_start", 2012)
        port_end   = state.get("port_end",   2022)
    proto      = state.get("protocol",   "TCP")
    users      = state.get("users", [])
    version    = state.get("version", "—")
    # Гарантируем наличие iptables-счётчика для диапазона портов mita
    _ensure_iptables_rule(port_start, port_end, proto)

    port_str = str(port_start) if port_start == port_end else f"{port_start}-{port_end}"

    _box_top(f"📊  MIERU — СТАТИСТИКА  ({window_minutes} мин)")
    _box_row()

    # ── Сервис ────────────────────────────────────────────────────────────────
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    _box_kv("Сервис:",
            f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")
    _box_kv("Версия:", version)
    _box_kv("Порт(ы):", f"{YELLOW}{port_str}/{proto}{NC}")
    _box_kv("Пользователей:", str(len(users)))

    # ── NTP ───────────────────────────────────────────────────────────────────
    ntp_ok, ntp_desc, ntp_off = _ntp_status()
    ntp_col = GREEN if ntp_ok else RED
    _box_kv("NTP:",
            f"{ntp_col}{ntp_desc}{NC}")
    if not ntp_ok:
        _box_warn("Mieru НЕ будет принимать клиентов без синхронизации времени!")
    elif abs(ntp_off) > 15000:
        _box_warn(f"Отклонение NTP {ntp_off:+.0f} мс — близко к лимиту ±30 сек!")

    _box_sep()

    # ── iptables (байты + скорость) ───────────────────────────────────────────
    _box_row(f"  {BOLD}{WHITE}Трафик (iptables):{NC}")
    _box_row()
    ipt = _iptables_speed(port_start, port_end, proto)
    _box_kv("  Всего байт:",   f"{YELLOW}{_bytes_human(ipt['bytes'])}{NC}")
    _box_kv("  Всего пакетов:", f"{DIM}{ipt['packets']:,}{NC}")
    speed_kbps = ipt["speed_bps"] * 8 / 1000
    speed_col  = GREEN if speed_kbps >= 1 else DIM
    _box_kv("  Скорость:",
            f"{speed_col}{speed_kbps:.1f} кбит/с{NC}")

    if ipt["bytes"] == 0:
        _box_warn("iptables-счётчик ещё не накопил трафик — правило создано автоматически.")
        grep_arg = str(port_start) if port_start == port_end else f"{port_start}:{port_end}"
        _box_info(f"Для проверки: iptables -L INPUT -n -v -x | grep {grep_arg}")

    # ── Активные соединения ───────────────────────────────────────────────────
    active = _active_connections(port_start, port_end, proto)
    _box_kv("  Активных соед.:", f"{CYAN}{active}{NC}")

    _box_sep()

    # ── journalctl ────────────────────────────────────────────────────────────
    _box_row(f"  {BOLD}{WHITE}Из журнала systemd  (последние {window_minutes} мин):{NC}")
    _box_row()

    jnl = _parse_journal(window_minutes)

    _box_kv("  Принято соед.:", f"{GREEN}{jnl['accepted']}{NC}")
    _box_kv("  Закрыто соед.:", f"{DIM}{jnl['closed']}{NC}")
    _box_kv("  Ошибок:",
            f"{RED}{jnl['errors']}{NC}" if jnl['errors'] else f"{DIM}0{NC}")
    _box_kv("  Предупреждений:",
            f"{YELLOW}{jnl['warnings']}{NC}" if jnl['warnings'] else f"{DIM}0{NC}")
    if jnl['auth_fail']:
        _box_kv("  Сбоев авторизации:",
                f"{RED}{jnl['auth_fail']}{NC}  {DIM}(время/реплей){NC}")
    _box_kv("  Строк в журнале:", f"{DIM}{jnl['raw_lines']}{NC}")

    # ── Тренд ─────────────────────────────────────────────────────────────────
    trend = _calc_trend(jnl["slots"])
    _box_kv("  Тренд:", trend)

    # ── Последние ошибки ──────────────────────────────────────────────────────
    if jnl["recent_errors"]:
        _box_sep()
        _box_row(f"  {BOLD}{WHITE}Последние ошибки:{NC}")
        _box_row()
        for msg in jnl["recent_errors"]:
            _box_row(f"  {RED}✗{NC}  {DIM}{msg}{NC}")

    # ── Гистограмма ───────────────────────────────────────────────────────────
    if jnl["slots"]:
        _box_sep()
        _box_row(f"  {BOLD}{WHITE}Активность (10-мин интервалы):{NC}")
        _box_row()
        _render_histogram(jnl["slots"])
        _box_row()

    # ── Статистика по пользователям (если несколько) ──────────────────────────
    # Mieru не логирует username в журнале — показываем список из state
    if len(users) > 1:
        _box_sep()
        _box_row(f"  {BOLD}{WHITE}Зарегистрированные пользователи:{NC}")
        _box_row()
        for u in users:
            _box_row(f"  {CYAN}{u.get('username','?'):<20}{NC}  "
                     f"{DIM}порт {port_start}/{proto}{NC}")
        _box_info("Разбивка трафика по пользователям недоступна — mita не логирует имена.")

    # ── Рекомендация ──────────────────────────────────────────────────────────
    _box_sep()
    if not svc_ok:
        _box_err("Сервис mita не запущен — статистика неактуальна.")
        _box_info("Запустите: systemctl start mita")
    elif jnl["auth_fail"] > 5:
        _box_warn(f"Обнаружено {jnl['auth_fail']} сбоев авторизации.")
        _box_info("Причина: расхождение времени клиент/сервер > 30 сек (replay).")
        _box_info("Проверьте NTP на клиенте и сервере.")
    elif jnl["errors"] > jnl["accepted"] * 0.3 and jnl["accepted"] > 0:
        _box_warn("Много ошибок относительно принятых соединений.")
    elif ipt["bytes"] == 0 and jnl["accepted"] == 0:
        _box_info("Активности нет — сервис готов к подключениям.")
    else:
        _box_ok("Сервис работает штатно.")

    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ЖИВОЕ ОБНОВЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _show_live(interval: int = 30) -> None:
    """Выводит краткую сводку каждые interval секунд. Ctrl+C — выход."""
    state      = _load_mieru_state()
    port_start, port_end = _get_mita_ports()
    if port_start == 2012 and port_end == 2022 and "port_start" in state:
        port_start = state.get("port_start", 2012)
        port_end   = state.get("port_end",   2022)
    proto      = state.get("protocol",   "TCP")
    _ensure_iptables_rule(port_start, port_end, proto)

    print(f"\n  {CYAN}Живое обновление — Ctrl+C для выхода{NC}\n")
    try:
        while True:
            os.system("clear")
            now_str = datetime.now().strftime("%H:%M:%S")

            _box_top(f"📡  MIERU — LIVE  [{now_str}]")
            _box_row()

            r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
            svc_ok = r.stdout.strip() == "active"
            _box_kv("Сервис:",
                    f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")

            # NTP (быстрая проверка)
            ntp_ok, ntp_desc, _ = _ntp_status()
            _box_kv("NTP:", f"{'✓' if ntp_ok else '✗'}  {DIM}{ntp_desc}{NC}")

            ipt = _iptables_speed(port_start, port_end, proto)
            _box_kv("Трафик (iptables):", f"{YELLOW}{_bytes_human(ipt['bytes'])}{NC}")
            speed_kbps = ipt["speed_bps"] * 8 / 1000
            _box_kv("Скорость:", f"{GREEN}{speed_kbps:.1f} кбит/с{NC}")

            active = _active_connections(port_start, port_end, proto)
            _box_kv("Активных соед.:", f"{CYAN}{active}{NC}")

            _box_sep()

            # Последние 5 мин из журнала
            jnl5 = _parse_journal(5)
            _box_row(f"  {BOLD}{WHITE}Последние 5 мин:{NC}")
            _box_row()
            _box_kv("  Принято:", f"{GREEN}{jnl5['accepted']}{NC}")
            _box_kv("  Ошибок:",
                    f"{RED}{jnl5['errors']}{NC}" if jnl5['errors'] else f"{DIM}0{NC}")
            _box_kv("  Предупреждений:",
                    f"{YELLOW}{jnl5['warnings']}{NC}" if jnl5['warnings'] else f"{DIM}0{NC}")

            if jnl5["recent_errors"]:
                _box_sep()
                _box_row(f"  {RED}Последняя ошибка:{NC}")
                _box_row(f"  {DIM}{jnl5['recent_errors'][-1]}{NC}")

            _box_sep()
            _box_row(f"  {DIM}Обновление через {interval} сек...  Ctrl+C — выход{NC}")
            _box_bot()

            time.sleep(interval)
    except KeyboardInterrupt:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  СБРОС КЭША
# ══════════════════════════════════════════════════════════════════════════════
def _reset_cache() -> None:
    try:
        if _STATS_CACHE.exists():
            _STATS_CACHE.unlink()
        print(f"\n  {GREEN}✓{NC}  Кэш сброшен.")
    except Exception as e:
        print(f"\n  {RED}✗{NC}  Ошибка: {e}")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ДИАГНОСТИКА (отдельная страница)
# ══════════════════════════════════════════════════════════════════════════════
def _show_diagnostics() -> None:
    """Детальная диагностика: iptables, ss, NTP, последние 50 строк журнала."""
    os.system("clear")
    state      = _load_mieru_state()
    port_start, port_end = _get_mita_ports()
    if port_start == 2012 and port_end == 2022 and "port_start" in state:
        port_start = state.get("port_start", 2012)
        port_end   = state.get("port_end",   2022)
    proto      = state.get("protocol",   "TCP")
    port_str   = str(port_start) if port_start == port_end else f"{port_start}-{port_end}"

    _box_top("🔍  MIERU — ДИАГНОСТИКА")
    _box_row()
    _box_kv("Порт(ы):", f"{YELLOW}{port_str}/{proto}{NC}")
    _box_sep()

    # ── iptables dump ─────────────────────────────────────────────────────────
    _box_row(f"  {BOLD}{WHITE}iptables INPUT (все правила на порт {port_start}):{NC}")
    _box_row()
    try:
        r = _run(["iptables", "-L", "INPUT", "-n", "-v", "-x", "--line-numbers"],
                 capture=True)
        found = False
        for line in r.stdout.splitlines():
            if str(port_start) in line or "Chain" in line or "pkts" in line:
                _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")
                found = True
        if not found:
            _box_warn("Правило для порта не найдено в iptables INPUT.")
    except Exception as e:
        _box_err(f"iptables ошибка: {e}")

    # ── ss dump ───────────────────────────────────────────────────────────────
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}ss — соединения на порт {port_str}:{NC}")
    _box_row()
    try:
        flag = "-tnp" if proto.upper() == "TCP" else "-unp"
        r = _run(["ss", flag], capture=True)
        found = False
        for line in r.stdout.splitlines():
            if str(port_start) in line or "Recv-Q" in line:
                _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")
                found = True
        if not found:
            _box_info("Активных соединений нет.")
    except Exception as e:
        _box_err(f"ss ошибка: {e}")

    # ── NTP подробно ──────────────────────────────────────────────────────────
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}timedatectl status:{NC}")
    _box_row()
    try:
        r = _run(["timedatectl", "status"], capture=True)
        for line in r.stdout.splitlines():
            _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")
    except Exception:
        _box_err("timedatectl недоступен")

    # ── Последние 50 строк журнала ────────────────────────────────────────────
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}journalctl -u mita (последние 50 строк):{NC}")
    _box_row()
    try:
        r = subprocess.run(
            ["journalctl", "-u", _SERVICE_NAME, "-n", "50",
             "--no-pager", "--output=short-monotonic"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env={**os.environ, "LANG": "C.UTF-8"},
        )
        for line in (r.stdout or "Нет записей").splitlines():
            _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")
    except Exception as e:
        _box_err(f"journalctl ошибка: {e}")

    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def do_mieru_stats_menu() -> None:
    """
    Точка входа — вызывается из do_mieru_menu() в mieru.py.
    """
    while True:
        os.system("clear")
        _box_top("📊  MIERU — СТАТИСТИКА ТРАФИКА")
        _box_row()
        _box_info("Источники: iptables-счётчики, journalctl, ss, timedatectl")
        _box_row()
        _box_sep()
        _box_item("1", f"📊  Последний час         {DIM}(60 мин){NC}")
        _box_item("2", f"📊  Последние 3 часа      {DIM}(180 мин){NC}")
        _box_item("3", f"📊  Последние 24 часа     {DIM}(1440 мин){NC}")
        _box_item("4", f"📡  Живое обновление      {DIM}(каждые 30 сек, Ctrl+C — выход){NC}")
        _box_sep()
        _box_item("5", f"🔍  Диагностика           {DIM}(iptables, ss, NTP, журнал){NC}")
        _box_item("R", f"{DIM}Сбросить кэш счётчиков{NC}")
        _box_sep()
        _box_item("Q", "← Назад в меню Mieru")
        _box_bot()
        print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        windows = {"1": 60, "2": 180, "3": 1440}
        if ch in windows:
            _show_stats(windows[ch])
        elif ch == "4":
            _show_live(30)
        elif ch == "5":
            _show_diagnostics()
        elif ch == "r":
            _reset_cache()
        elif ch in ("q", ""):
            break


# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}")
        import sys; sys.exit(1)
    try:
        do_mieru_stats_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}")
