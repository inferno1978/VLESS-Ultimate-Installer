"""
vless_installer/modules/naiveproxy_stats.py
───────────────────────────────────────────────────────────────────────────────
Статистика трафика NaiveProxy (caddy-forwardproxy-naive).

Источники данных (без новых демонов, без сторонних зависимостей):
  • /var/log/caddy-naive/access.log  — основной: JSON-лог Caddy
      Поля: ts (unix), duration, request.remote_addr, status,
            resp_body_size, request.headers.Authorization (basic-auth логин)
  • iptables -L INPUT -n -v -x       — суммарные байты на TCP 443
  • ss -tnp                          — активные TCP-соединения на порт

Метрики:
  • Суммарный трафик (байты) за период: из iptables-счётчика
  • Кол-во запросов, успешных (2xx), ошибок (4xx/5xx) — из access.log
  • Статистика по пользователям (логин → запросы, байты, last_seen)
  • Топ-5 IP-адресов клиентов
  • Распределение по кодам ответа (200/407/502/...)
  • Гистограмма активности по 10-минутным слотам (последний час)
  • Среднее время запроса (latency), 95-й перцентиль
  • Текущих активных соединений (ss)
  • Живое обновление каждые 30 сек

Не трогает:
  • Xray config.json / state.json
  • iptables-правила других модулей
  • Конфиги naiveproxy.py

Точка входа из naiveproxy.py:
    from vless_installer.modules.naiveproxy_stats import do_naiveproxy_stats_menu
    do_naiveproxy_stats_menu()
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
_LOG_DIR      = Path("/var/log/caddy-naive")
_ACCESS_LOG   = Path("/var/log/caddy-naive/access.log")
_SERVICE_NAME = "caddy-naive"
_MODULE_STATE = Path("/var/lib/xray-installer/naiveproxy.json")
_STATS_CACHE  = Path("/var/lib/xray-installer/naive_stats_cache.json")
_DEFAULT_PORT = 443

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ (собственный — mieru/naiveproxy не используют box_renderer)
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
        # жёсткий обрез с эллипсисом
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

def _run(cmd: list, capture: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _bytes_human(b: int) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} ПБ"

def _fmt_pct(num: int, denom: int) -> str:
    if denom == 0: return "0%"
    return f"{num / denom * 100:.1f}%"

def _load_naive_state() -> dict:
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
#  ИСТОЧНИК 1: access.log (JSON Caddy)
# ══════════════════════════════════════════════════════════════════════════════
# Пример строки из access.log:
# {"level":"info","ts":1718000000.123,"logger":"http.log.access","msg":"handled request",
#  "request":{"remote_addr":"1.2.3.4:55123","method":"CONNECT","host":"example.com:443",
#              "headers":{"Authorization":["Basic dXNlcjpwYXNz"]}},
#  "duration":0.453,"size":102400,"status":200,"resp_headers":{}}

def _decode_basic_auth(header_val: str) -> str:
    """Декодирует Basic dXNlcjpwYXNz → 'user'."""
    try:
        import base64
        token = header_val.strip()
        if token.lower().startswith("basic "):
            token = token[6:]
        decoded = base64.b64decode(token + "==").decode("utf-8", errors="replace")
        return decoded.split(":")[0] if ":" in decoded else decoded
    except Exception:
        return "unknown"

def _parse_access_log(window_minutes: int = 60) -> dict:
    """
    Парсит /var/log/caddy-naive/access.log за последние window_minutes минут.
    Возвращает агрегированную статистику.
    """
    if not _ACCESS_LOG.exists() or _ACCESS_LOG.stat().st_size == 0:
        return _empty_log_stats()

    cutoff_ts = time.time() - window_minutes * 60

    total_requests  = 0
    total_bytes     = 0
    ok_requests     = 0   # 2xx
    err_requests    = 0   # 4xx / 5xx
    auth_fail       = 0   # 407
    latencies: list = []  # сек

    # per-user: {username: {requests, bytes, last_seen_ts}}
    per_user: dict  = defaultdict(lambda: {"requests": 0, "bytes": 0, "last_ts": 0.0})
    # per-ip:  {ip: requests}
    per_ip: dict    = defaultdict(int)
    # status codes
    status_cnt: dict = defaultdict(int)
    # 10-мин слоты для гистограммы
    slots: dict     = defaultdict(lambda: {"requests": 0, "bytes": 0, "errors": 0})

    try:
        size = _ACCESS_LOG.stat().st_size
        with _ACCESS_LOG.open("r", errors="replace") as f:
            # Читаем последние 2 МБ — достаточно для суточного окна
            f.seek(max(0, size - 2_097_152))
            for raw_line in f:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    entry = json.loads(raw_line)
                except (json.JSONDecodeError, ValueError):
                    # Не JSON — пропускаем (Caddy иногда пишет plain-text в начале)
                    continue

                ts = entry.get("ts", 0)
                if ts < cutoff_ts:
                    continue

                # ── Основные поля ──────────────────────────────────────────
                status    = entry.get("status", 0)
                resp_size = entry.get("size", 0) or 0
                duration  = entry.get("duration", 0) or 0.0
                req       = entry.get("request", {})
                remote    = req.get("remote_addr", "")
                ip        = remote.rsplit(":", 1)[0] if ":" in remote else remote
                auth_hdrs = req.get("headers", {}).get("Authorization", [])

                # ── Имя пользователя ───────────────────────────────────────
                username = "anonymous"
                if auth_hdrs:
                    username = _decode_basic_auth(auth_hdrs[0])

                # ── Статус-код ─────────────────────────────────────────────
                status_cnt[status] += 1
                if 200 <= status < 300:
                    ok_requests += 1
                elif status == 407:
                    auth_fail += 1
                    err_requests += 1
                elif status >= 400:
                    err_requests += 1

                total_requests += 1
                total_bytes    += resp_size
                if duration > 0:
                    latencies.append(duration)

                # ── Per-user ───────────────────────────────────────────────
                per_user[username]["requests"] += 1
                per_user[username]["bytes"]    += resp_size
                if ts > per_user[username]["last_ts"]:
                    per_user[username]["last_ts"] = ts

                # ── Per-IP ─────────────────────────────────────────────────
                if ip:
                    per_ip[ip] += 1

                # ── 10-мин слот ────────────────────────────────────────────
                dt   = datetime.fromtimestamp(ts)
                slot = dt.strftime("%H:%M")[:-1] + "0"  # 14:37 → "14:30"
                slots[slot]["requests"] += 1
                slots[slot]["bytes"]    += resp_size
                if status >= 400:
                    slots[slot]["errors"] += 1

    except Exception:
        pass

    # Перцентиль P95 задержки
    avg_lat  = sum(latencies) / len(latencies) if latencies else 0.0
    p95_lat  = 0.0
    if latencies:
        s = sorted(latencies)
        p95_lat = s[int(len(s) * 0.95)]

    # Топ-5 IP
    top_ips = sorted(per_ip.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_requests": total_requests,
        "total_bytes":    total_bytes,
        "ok_requests":    ok_requests,
        "err_requests":   err_requests,
        "auth_fail":      auth_fail,
        "avg_lat_ms":     avg_lat * 1000,
        "p95_lat_ms":     p95_lat * 1000,
        "per_user":       dict(per_user),
        "per_ip":         top_ips,
        "status_cnt":     dict(status_cnt),
        "slots":          dict(slots),
        "window_minutes": window_minutes,
        "has_data":       True,
    }

def _empty_log_stats() -> dict:
    return {
        "total_requests": 0, "total_bytes": 0,
        "ok_requests": 0, "err_requests": 0, "auth_fail": 0,
        "avg_lat_ms": 0.0, "p95_lat_ms": 0.0,
        "per_user": {}, "per_ip": [], "status_cnt": {},
        "slots": {}, "window_minutes": 0, "has_data": False,
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ИСТОЧНИК 2: iptables — суммарные байты на порту
# ══════════════════════════════════════════════════════════════════════════════
def _iptables_bytes(port: int) -> int:
    """Возвращает байты из iptables INPUT ACCEPT для TCP-порта."""
    try:
        r = _run(["iptables", "-L", "INPUT", "-n", "-v", "-x"], capture=True)
        for line in r.stdout.splitlines():
            if f"dpt:{port}" in line or f"--dport {port}" in line:
                parts = line.split()
                # Формат: pkts  bytes  target  prot  opt  in  out  src  dst  ...
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1])
    except Exception:
        pass
    return 0

def _iptables_speed(port: int) -> tuple[int, float]:
    """
    Возвращает (total_bytes, speed_bps) используя кэш предыдущего замера.
    """
    now_ts = time.time()
    cache  = _load_cache()
    prev_ts    = cache.get("naive_ipt_ts", now_ts)
    prev_bytes = cache.get("naive_ipt_bytes", 0)

    total = _iptables_bytes(port)
    elapsed = max(now_ts - prev_ts, 1.0)
    delta   = max(total - prev_bytes, 0)
    speed   = delta / elapsed  # bytes/sec

    cache.update(naive_ipt_ts=now_ts, naive_ipt_bytes=total)
    _save_cache(cache)

    return total, speed

# ══════════════════════════════════════════════════════════════════════════════
#  ИСТОЧНИК 3: ss — активные соединения
# ══════════════════════════════════════════════════════════════════════════════
def _active_connections(port: int) -> int:
    """Считает ESTABLISHED TCP-соединения на порт."""
    try:
        r = _run(["ss", "-tn", "state", "established",
                  f"( dport = :{port} or sport = :{port} )"], capture=True)
        lines = [l for l in r.stdout.splitlines() if l.strip() and "Recv-Q" not in l]
        return len(lines)
    except Exception:
        pass
    return 0

# ══════════════════════════════════════════════════════════════════════════════
#  ГИСТОГРАММА
# ══════════════════════════════════════════════════════════════════════════════
def _render_histogram(slots: dict) -> None:
    if not slots:
        _box_row(f"  {DIM}Нет данных для гистограммы{NC}")
        return

    keys    = sorted(slots.keys())
    max_req = max((slots[k]["requests"] for k in keys), default=1) or 1
    bar_w   = 22

    _box_row(f"  {BOLD}{CYAN}{'Время':<7}  {'Запр':>5}  {'Байт':>10}  {'Ошиб':>4}  График{NC}")
    _box_sep()
    for slot in keys:
        req = slots[slot]["requests"]
        byt = slots[slot]["bytes"]
        err = slots[slot]["errors"]
        ok  = req - err
        ok_w  = int(ok  / max_req * bar_w) if max_req else 0
        err_w = int(err / max_req * bar_w) if max_req else 0
        bar   = f"{GREEN}{'█' * ok_w}{NC}{RED}{'█' * err_w}{NC}"
        err_col = f"{RED}{err:>4}{NC}" if err else f"{DIM}{err:>4}{NC}"
        _box_row(f"  {DIM}{slot:<7}{NC}  {GREEN}{req:>5}{NC}  "
                 f"{DIM}{_bytes_human(byt):>10}{NC}  {err_col}  {bar}")

# ══════════════════════════════════════════════════════════════════════════════
#  ОТОБРАЖЕНИЕ СТАТИСТИКИ
# ══════════════════════════════════════════════════════════════════════════════
def _show_stats(window_minutes: int = 60) -> None:
    os.system("clear")
    state = _load_naive_state()
    port  = state.get("port", _DEFAULT_PORT)

    _box_top(f"📊  NAIVEPROXY — СТАТИСТИКА  ({window_minutes} мин)")
    _box_row()

    # ── Сервис ────────────────────────────────────────────────────────────────
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    _box_kv("Сервис:",
            f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")
    _box_kv("Домен:порт:", f"{state.get('domain', '—')}:{port}")

    # ── iptables (байты + скорость) ───────────────────────────────────────────
    ipt_bytes, ipt_speed = _iptables_speed(port)
    _box_kv("Трафик (iptables):", f"{YELLOW}{_bytes_human(ipt_bytes)}{NC}")
    speed_kbps = ipt_speed * 8 / 1000
    if speed_kbps >= 1:
        _box_kv("Скорость:", f"{GREEN}{speed_kbps:.1f} кбит/с{NC}")

    # ── Активные соединения ───────────────────────────────────────────────────
    active = _active_connections(port)
    _box_kv("Активных соединений:", f"{CYAN}{active}{NC}")

    _box_sep()

    # ── access.log ────────────────────────────────────────────────────────────
    _box_row(f"  {BOLD}{WHITE}Из access.log  (последние {window_minutes} мин):{NC}")
    _box_row()

    if not _ACCESS_LOG.exists():
        _box_warn("access.log не найден — логирование ещё не настроено.")
        _box_info("Логи появятся после первого запроса через NaiveProxy.")
        _box_row()
        _box_bot()
        _pause()
        return

    log = _parse_access_log(window_minutes)

    if not log["has_data"] or log["total_requests"] == 0:
        _box_warn(f"Запросов за последние {window_minutes} мин не найдено.")
        _box_row()
        _box_bot()
        _pause()
        return

    _box_kv("Запросов всего:",
            f"{GREEN}{log['total_requests']}{NC}")
    _box_kv("Успешных (2xx):",
            f"{GREEN}{log['ok_requests']}{NC}  "
            f"{DIM}({_fmt_pct(log['ok_requests'], log['total_requests'])}){NC}")
    _box_kv("Ошибок (4xx/5xx):",
            f"{RED}{log['err_requests']}{NC}  "
            f"{DIM}({_fmt_pct(log['err_requests'], log['total_requests'])}){NC}")
    if log["auth_fail"]:
        _box_kv("  в т.ч. 407 Auth:",
                f"{RED}{log['auth_fail']}{NC}  {DIM}(неверный логин/пароль){NC}")
    _box_kv("Трафик (resp):",
            f"{YELLOW}{_bytes_human(log['total_bytes'])}{NC}")
    _box_kv("Сред. задержка:",
            f"{CYAN}{log['avg_lat_ms']:.0f} мс{NC}")
    _box_kv("P95 задержка:",
            f"{CYAN}{log['p95_lat_ms']:.0f} мс{NC}")

    # ── Распределение кодов ответа ────────────────────────────────────────────
    if log["status_cnt"]:
        _box_sep()
        _box_row(f"  {BOLD}{WHITE}Коды ответа:{NC}")
        _box_row()
        for code in sorted(log["status_cnt"].keys()):
            cnt = log["status_cnt"][code]
            col = GREEN if 200 <= code < 300 else (RED if code >= 400 else YELLOW)
            _box_kv(f"  HTTP {code}:", f"{col}{cnt}{NC}")

    # ── Per-user статистика ───────────────────────────────────────────────────
    if log["per_user"]:
        _box_sep()
        _box_row(f"  {BOLD}{WHITE}По пользователям:{NC}")
        _box_row()
        users_sorted = sorted(
            log["per_user"].items(),
            key=lambda x: x[1]["requests"], reverse=True
        )
        for uname, udata in users_sorted:
            last = datetime.fromtimestamp(udata["last_ts"]).strftime("%H:%M:%S") \
                   if udata["last_ts"] else "—"
            _box_row(f"  {CYAN}{uname:<18}{NC}  "
                     f"{GREEN}{udata['requests']:>5}{NC} зап  "
                     f"{YELLOW}{_bytes_human(udata['bytes']):>9}{NC}  "
                     f"{DIM}last {last}{NC}")

    # ── Топ IP-адресов ────────────────────────────────────────────────────────
    if log["per_ip"]:
        _box_sep()
        _box_row(f"  {BOLD}{WHITE}Топ клиентских IP:{NC}")
        _box_row()
        for ip, cnt in log["per_ip"]:
            _box_row(f"  {DIM}{ip:<22}{NC}  {GREEN}{cnt:>5}{NC} запр.")

    # ── Гистограмма ───────────────────────────────────────────────────────────
    if log["slots"]:
        _box_sep()
        _box_row(f"  {BOLD}{WHITE}Активность (10-мин интервалы):{NC}")
        _box_row()
        _render_histogram(log["slots"])
        _box_row()

    # ── Рекомендация ──────────────────────────────────────────────────────────
    _box_sep()
    err_pct = log["err_requests"] / max(log["total_requests"], 1) * 100
    if log["auth_fail"] > log["total_requests"] * 0.1:
        _box_warn("Много ошибок 407 — возможно кто-то сканирует порт.")
        _box_info("Probe resistance защищает — сканер видит только фейковый сайт.")
    elif err_pct >= 30:
        _box_warn(f"Высокий процент ошибок ({err_pct:.0f}%) — проверьте логи сервиса.")
    else:
        _box_ok("Сервис работает штатно.")

    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ЖИВОЕ ОБНОВЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _show_live(interval: int = 30) -> None:
    """Выводит краткую сводку каждые interval секунд. Ctrl+C — выход."""
    state = _load_naive_state()
    port  = state.get("port", _DEFAULT_PORT)

    print(f"\n  {CYAN}Живое обновление — Ctrl+C для выхода{NC}\n")
    try:
        while True:
            os.system("clear")
            now_str = datetime.now().strftime("%H:%M:%S")

            _box_top(f"📡  NAIVEPROXY — LIVE  [{now_str}]")
            _box_row()

            r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
            svc_ok = r.stdout.strip() == "active"
            _box_kv("Сервис:",
                    f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")

            ipt_bytes, ipt_speed = _iptables_speed(port)
            _box_kv("Трафик (iptables):", f"{YELLOW}{_bytes_human(ipt_bytes)}{NC}")
            speed_kbps = ipt_speed * 8 / 1000
            _box_kv("Скорость:", f"{GREEN}{speed_kbps:.1f} кбит/с{NC}")

            active = _active_connections(port)
            _box_kv("Активных соединений:", f"{CYAN}{active}{NC}")

            _box_sep()

            # Последние 5 мин из лога
            log5 = _parse_access_log(5)
            _box_row(f"  {BOLD}{WHITE}Последние 5 мин:{NC}")
            _box_row()
            _box_kv("  Запросов:",   f"{GREEN}{log5['total_requests']}{NC}")
            _box_kv("  Ошибок:",     f"{RED}{log5['err_requests']}{NC}")
            _box_kv("  Трафик:",     f"{YELLOW}{_bytes_human(log5['total_bytes'])}{NC}")
            _box_kv("  Ср. латенс:", f"{CYAN}{log5['avg_lat_ms']:.0f} мс{NC}")

            _box_sep()
            _box_row(f"  {DIM}Обновление через {interval} сек...  Ctrl+C — выход{NC}")
            _box_bot()

            time.sleep(interval)
    except KeyboardInterrupt:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  ОЧИСТКА КЭША СТАТИСТИКИ
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
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def do_naiveproxy_stats_menu() -> None:
    """
    Точка входа — вызывается из do_naiveproxy_menu() в naiveproxy.py.
    """
    while True:
        os.system("clear")
        _box_top("📊  NAIVEPROXY — СТАТИСТИКА ТРАФИКА")
        _box_row()
        _box_info("Источники: access.log (Caddy JSON), iptables-счётчики, ss")
        _box_row()
        _box_sep()
        _box_item("1", f"📊  Последний час         {DIM}(60 мин){NC}")
        _box_item("2", f"📊  Последние 3 часа      {DIM}(180 мин){NC}")
        _box_item("3", f"📊  Последние 24 часа     {DIM}(1440 мин){NC}")
        _box_item("4", f"📡  Живое обновление      {DIM}(каждые 30 сек, Ctrl+C — выход){NC}")
        _box_sep()
        _box_item("R", f"{DIM}Сбросить кэш счётчиков{NC}")
        _box_sep()
        _box_item("Q", "← Назад в меню NaiveProxy")
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
        do_naiveproxy_stats_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}")
