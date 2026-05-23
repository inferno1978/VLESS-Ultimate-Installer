"""
vless_installer/modules/tg_nets.py
───────────────────────────────────────────────────────────────────────────────
Управление подсетями Telegram: хранение, обновление из всех доступных
источников, применение к iptables.

Архитектура источников (5 независимых каналов):
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ Источник     │ Тип данных           │ Что даёт                          │
  ├─────────────────────────────────────────────────────────────────────────┤
  │ 1. RIPE stat │ Анонсы BGP (live)   │ Реально видимые сейчас префиксы   │
  │ 2. bgp.tools │ Full table dump     │ Live BGP; 3-й независимый взгляд  │
  │ 3. RADB/IRR  │ IRR route-objects   │ Зарег. маршруты (AS-TELEGRAM set) │
  │ 4. RIPE WHOIS│ inetnum/route objs  │ Официальная регистрация в RIPE DB  │
  │ 5. Builtin   │ Hardcoded fallback  │ Всегда работает, никогда не пустой│
  └─────────────────────────────────────────────────────────────────────────┘

  Примечания:
  • BGPView отключён в ноябре 2025 — исключён.
  • bgp.tools/table.jsonl — живой дамп от ~500 BGP-пиров, обновляется каждые
    30 минут. Самый полный источник live-анонсов.
  • RADB (whois.radb.net port 43) — агрегирует все IRR (RIPE, APNIC, ARIN…),
    умеет рекурсивный expand AS-SET → все дочерние маршруты.
  • RIPE WHOIS REST API — возвращает inetnum + route-объекты от MNT-TELEGRAM.
  • При любом сочетании недоступных источников система продолжает работать.

Поддерживаемые ASN:
  AS62041  — основной (Europe / Americas / Singapore)
  AS59930  — Americas
  AS44907  — CDN India / Singapore
  AS211157 — новый (2021), Европа / Россия
  AS42065  — исторический (109.239.140.0/24, AS31500 GNM/Telegram)
  AS62014  — член AS-TELEGRAM (исторический, DC Americas)

Файл: /etc/telemt/tg_nets.txt
  Формат: одна CIDR на строку, # — комментарий.
  При каждом обновлении: дата + список источников в заголовке.
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import json
import re
import socket
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА
# ══════════════════════════════════════════════════════════════════════════════
def _detect_colors() -> dict:
    if sys.stdout.isatty():
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
NETS_FILE   = Path("/etc/telemt/tg_nets.txt")
WARN_DAYS   = 30
STALE_DAYS  = 90
HTTP_TIMEOUT = 20   # секунд на один HTTP-запрос

# Все ASN Telegram (включая исторические)
TG_ASNS     = [62041, 59930, 44907, 211157, 42065, 62014]
# AS-SET имя в RIPE/RADB
TG_AS_SET   = "AS-TELEGRAM"
# maintainer в RIPE WHOIS
TG_MNT      = "MNT-TELEGRAM"

# ══════════════════════════════════════════════════════════════════════════════
#  ВСТРОЕННЫЙ FALLBACK СПИСОК (обновлён май 2026)
#  Используется только если ВСЕ 4 онлайн-источника недоступны одновременно.
# ══════════════════════════════════════════════════════════════════════════════
_BUILTIN_NETS: list[str] = [
    # ── AS62041 ───────────────────────────────────────────────────────────────
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.56.0/22",
    "95.161.64.0/20",
    "149.154.160.0/22",
    "149.154.162.0/23",
    "149.154.164.0/22",
    "149.154.166.0/23",
    # ── AS59930 ───────────────────────────────────────────────────────────────
    "91.108.12.0/22",
    "149.154.172.0/22",
    # ── AS44907 ───────────────────────────────────────────────────────────────
    "91.108.20.0/22",
    # ── AS211157 ──────────────────────────────────────────────────────────────
    "91.105.192.0/23",
    "185.76.151.0/24",
    # ── AS42065 / TELEGRAM-NETWORK (GNM hosting) ─────────────────────────────
    "109.239.140.0/24",
    # ── IPv6 ──────────────────────────────────────────────────────────────────
    "2001:67c:4e8::/48",
    "2001:b28:f23d::/48",
    "2001:b28:f23c::/48",
    "2a0a:f280:203::/48",
]

# ══════════════════════════════════════════════════════════════════════════════
#  ВАЛИДАЦИЯ CIDR
# ══════════════════════════════════════════════════════════════════════════════
_RE_V4 = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/([0-9]|[12]\d|3[012])$')
_RE_V6 = re.compile(r'^[0-9a-fA-F:]+/(\d{1,3})$')

def _valid_cidr(cidr: str) -> bool:
    cidr = cidr.strip()
    return bool(cidr and (_RE_V4.match(cidr) or _RE_V6.match(cidr)))

def _dedup_sorted(nets: list[str]) -> list[str]:
    seen: set = set()
    result = []
    for n in nets:
        n = n.strip()
        if n and _valid_cidr(n) and n not in seen:
            seen.add(n); result.append(n)
    v4 = sorted(n for n in result if ':' not in n)
    v6 = sorted(n for n in result if ':' in n)
    return v4 + v6

# ══════════════════════════════════════════════════════════════════════════════
#  ФАЙЛОВОЕ ХРАНИЛИЩЕ
# ══════════════════════════════════════════════════════════════════════════════
def _load_from_file() -> Optional[list[str]]:
    if not NETS_FILE.exists():
        return None
    lines = NETS_FILE.read_text(encoding="utf-8").splitlines()
    nets = [l.split("#")[0].strip() for l in lines]
    nets = [n for n in nets if _valid_cidr(n)]
    return nets if nets else None

def _save_to_file(nets: list[str], sources_used: list[str]) -> None:
    NETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    v4 = [n for n in nets if ':' not in n]
    v6 = [n for n in nets if ':' in n]
    lines = [
        f"# Telegram IP networks — {len(nets)} entries ({len(v4)} IPv4 + {len(v6)} IPv6)",
        f"# Updated: {now}",
        f"# Sources: {', '.join(sources_used) if sources_used else 'builtin'}",
        f"# ASN:     AS62041 AS59930 AS44907 AS211157 AS42065 AS62014",
        "#",
        "# === IPv4 ===",
    ]
    lines += v4
    if v6:
        lines += ["", "# === IPv6 ==="]
        lines += v6
    lines.append("")
    NETS_FILE.write_text("\n".join(lines), encoding="utf-8")
    NETS_FILE.chmod(0o644)

def _file_age_days() -> Optional[int]:
    if not NETS_FILE.exists():
        return None
    return int((time.time() - NETS_FILE.stat().st_mtime) / 86400)

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ HTTP
# ══════════════════════════════════════════════════════════════════════════════
_UA = "VLESS-Ultimate-Installer/4.11 (telemt-tg-nets)"

def _http_get(url: str, timeout: int = HTTP_TIMEOUT) -> Optional[bytes]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception:
        return None

# ══════════════════════════════════════════════════════════════════════════════
#  ИСТОЧНИК 1: RIPE NCC stat.ripe.net — announced-prefixes по ASN
#  Возвращает только реально анонсируемые сейчас префиксы (live BGP view)
# ══════════════════════════════════════════════════════════════════════════════
def _src_ripe_stat(asns: list[int], verbose: bool) -> tuple[list[str], bool]:
    nets: list[str] = []
    ok = False
    for asn in asns:
        url = (f"https://stat.ripe.net/data/announced-prefixes/data.json"
               f"?resource=AS{asn}&starttime=latest")
        if verbose:
            print(f"  {DIM}  RIPE/AS{asn}...{NC}", end="", flush=True)
        raw = _http_get(url)
        if raw:
            try:
                data = json.loads(raw)
                prefixes = data.get("data", {}).get("prefixes", [])
                found = [p["prefix"] for p in prefixes if _valid_cidr(p.get("prefix", ""))]
                nets += found
                ok = bool(found) or ok
                if verbose:
                    print(f" {GREEN}{len(found)}{NC}")
            except Exception:
                if verbose: print(f" {YELLOW}parse error{NC}")
        else:
            if verbose: print(f" {YELLOW}timeout{NC}")
    return nets, ok

# ══════════════════════════════════════════════════════════════════════════════
#  ИСТОЧНИК 2: bgp.tools/table.jsonl — полный live BGP-дамп
#  ~500 пиров по всему миру, обновляется каждые 30 мин.
#  Поле "Hits" = сколько BGP-пиров видят этот маршрут — фильтруем >= 2.
# ══════════════════════════════════════════════════════════════════════════════
def _src_bgptools(asns: list[int], verbose: bool) -> tuple[list[str], bool]:
    asn_set = set(asns)
    if verbose:
        print(f"  {DIM}  bgp.tools table.jsonl (full BGP dump)...{NC}", end="", flush=True)
    raw = _http_get("https://bgp.tools/table.jsonl", timeout=30)
    if not raw:
        if verbose: print(f" {YELLOW}timeout{NC}")
        return [], False
    nets: list[str] = []
    try:
        for line in raw.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("ASN") in asn_set:
                    cidr = obj.get("CIDR", "")
                    hits = obj.get("Hits", 0)
                    # Hits >= 2: фильтруем мусор с единственным пиром
                    if _valid_cidr(cidr) and hits >= 2:
                        nets.append(cidr)
            except Exception:
                continue
    except Exception:
        if verbose: print(f" {YELLOW}parse error{NC}")
        return [], False
    if verbose:
        print(f" {GREEN}{len(nets)} префиксов{NC}")
    return nets, bool(nets)

# ══════════════════════════════════════════════════════════════════════════════
#  ИСТОЧНИК 3: RADB / IRR whois (TCP port 43)
#  Запрашиваем AS-SET "AS-TELEGRAM" рекурсивно через whois.radb.net.
#  RADB агрегирует все IRR (RIPE, APNIC, ARIN, JPIRR и др.).
#  Команды:
#    !gAS-TELEGRAM   → рекурсивный expand AS-SET → список ASN
#    !rAS62041,l     → все route-объекты для ASN (IPv4)
#    !6AS62041,l     → все route6-объекты для ASN (IPv6)
# ══════════════════════════════════════════════════════════════════════════════
def _radb_query(cmd: str, host: str = "whois.radb.net", port: int = 43,
                timeout: int = 15) -> Optional[str]:
    """Отправляет одну команду на whois-сервер и возвращает ответ."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall((cmd + "\r\n").encode("ascii"))
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()
        return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        return None

def _src_radb_irr(asns: list[int], verbose: bool) -> tuple[list[str], bool]:
    """
    Запрашивает route-объекты через RADB whois TCP.
    Для каждого ASN: IPv4 (!rASxxxx,l) и IPv6 (!6ASxxxx,l).
    """
    if verbose:
        print(f"  {DIM}  RADB/IRR whois (AS-TELEGRAM + all ASN)...{NC}", end="", flush=True)

    nets: list[str] = []
    ok   = False

    # Шаг 1: expand AS-SET → дополнительные ASN
    extra_asns: set[int] = set()
    resp = _radb_query(f"!gAS-TELEGRAM")
    if resp:
        # Ответ: список ASN через пробел
        for tok in re.split(r'[\s,]+', resp):
            tok = tok.strip().upper().lstrip("AS")
            try:
                extra_asns.add(int(tok))
            except ValueError:
                pass

    all_asns = list(set(asns) | extra_asns)

    # Шаг 2: route-объекты для каждого ASN
    for asn in all_asns:
        # IPv4
        resp4 = _radb_query(f"!rAS{asn},l")
        if resp4:
            found4 = [tok.strip() for tok in re.split(r'\s+', resp4)
                      if _valid_cidr(tok.strip()) and ':' not in tok]
            nets += found4
            if found4: ok = True
        # IPv6
        resp6 = _radb_query(f"!6AS{asn},l")
        if resp6:
            found6 = [tok.strip() for tok in re.split(r'\s+', resp6)
                      if _valid_cidr(tok.strip()) and ':' in tok]
            nets += found6
            if found6: ok = True

    if verbose:
        print(f" {GREEN if ok else YELLOW}{len(nets)} записей{NC}")
    return nets, ok

# ══════════════════════════════════════════════════════════════════════════════
#  ИСТОЧНИК 4: RIPE WHOIS REST API — inetnum + route objects по MNT-TELEGRAM
#  Возвращает все объекты с mnt-by: MNT-TELEGRAM из базы данных RIPE.
#  Это регистрационные данные (не обязательно live BGP).
# ══════════════════════════════════════════════════════════════════════════════
def _src_ripe_whois_rest(verbose: bool) -> tuple[list[str], bool]:
    """
    Запрашивает все route и route6 объекты через RIPE WHOIS REST API.
    Endpoint: /search?query-string=MNT-TELEGRAM&type-filter=route&type-filter=route6
    """
    if verbose:
        print(f"  {DIM}  RIPE WHOIS REST (MNT-TELEGRAM route objects)...{NC}",
              end="", flush=True)

    nets: list[str] = []
    ok   = False

    for obj_type in ("route", "route6"):
        url = (f"https://rest.db.ripe.net/search.json"
               f"?query-string=MNT-TELEGRAM"
               f"&type-filter={obj_type}"
               f"&flags=rG"          # rG = no-referenced, no-filtering
               f"&source=RIPE")
        raw = _http_get(url)
        if not raw:
            continue
        try:
            data = json.loads(raw)
            for obj in data.get("objects", {}).get("object", []):
                for attr in obj.get("attributes", {}).get("attribute", []):
                    if attr.get("name") == obj_type:
                        cidr = attr.get("value", "").strip()
                        if _valid_cidr(cidr):
                            nets.append(cidr)
                            ok = True
        except Exception:
            continue

    if verbose:
        print(f" {GREEN if ok else YELLOW}{len(nets)} записей{NC}")
    return nets, ok

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНАЯ ФУНКЦИЯ ОБНОВЛЕНИЯ
# ══════════════════════════════════════════════════════════════════════════════
def fetch_tg_nets_from_sources(verbose: bool = True) -> tuple[list[str], list[str]]:
    """
    Запрашивает все 4 онлайн-источника параллельно (через threading).
    Объединяет результаты, добавляет builtin-якоря.
    Возвращает (nets, sources_used).
    """
    import threading

    results: dict = {}

    def run(name: str, fn, *args):
        try:
            nets, ok = fn(*args)
            results[name] = (nets, ok)
        except Exception as e:
            results[name] = ([], False)

    sources_config = [
        ("RIPE-stat",   _src_ripe_stat,       TG_ASNS, verbose),
        ("bgp.tools",   _src_bgptools,         TG_ASNS, verbose),
        ("RADB-IRR",    _src_radb_irr,         TG_ASNS, verbose),
        ("RIPE-WHOIS",  _src_ripe_whois_rest,  verbose),
    ]

    if verbose:
        print()
        labels = {
            "RIPE-stat":  "1. RIPE NCC stat.ripe.net (live BGP annoncements)",
            "bgp.tools":  "2. bgp.tools table.jsonl  (500+ BGP peers dump)",
            "RADB-IRR":   "3. RADB / IRR whois       (AS-SET expansion)",
            "RIPE-WHOIS": "4. RIPE WHOIS REST        (MNT-TELEGRAM objects)",
        }

    threads = []
    for cfg in sources_config:
        name = cfg[0]
        fn   = cfg[1]
        args = cfg[2:]
        if verbose:
            print(f"  {CYAN}{labels[name]}{NC}")
        t = threading.Thread(target=run, args=(name, fn) + args, daemon=True)
        t.start()
        threads.append(t)

    # Ждём все потоки (max HTTP_TIMEOUT + 5s буфер)
    for t in threads:
        t.join(timeout=HTTP_TIMEOUT + 5)

    # Собираем
    all_nets: list[str] = []
    sources_used: list[str] = []
    for name, (nets, ok) in results.items():
        if ok:
            all_nets += nets
            sources_used.append(name)

    # Всегда добавляем builtin-якоря (они могут быть исторически важны
    # и не анонсироваться live — например 109.239.140.0/24)
    builtin_added = 0
    for anchor in _BUILTIN_NETS:
        if anchor not in all_nets:
            all_nets.append(anchor)
            builtin_added += 1

    result = _dedup_sorted(all_nets)

    if not sources_used:
        # Все источники упали
        result = _dedup_sorted(list(_BUILTIN_NETS))
        sources_used = ["builtin-only (all sources failed)"]

    if verbose:
        print()
        v4 = [n for n in result if ':' not in n]
        v6 = [n for n in result if ':' in n]
        src_str = ", ".join(sources_used)
        print(f"  {GREEN}{'─'*60}{NC}")
        print(f"  {GREEN}✓ Итого: {len(result)} подсетей "
              f"({len(v4)} IPv4, {len(v6)} IPv6){NC}")
        print(f"  {DIM}  Источники: {src_str}{NC}")
        if builtin_added:
            print(f"  {DIM}  + {builtin_added} якорных подсетей из builtin{NC}")

    return result, sources_used

# ══════════════════════════════════════════════════════════════════════════════
#  ПУБЛИЧНЫЙ API
# ══════════════════════════════════════════════════════════════════════════════
def get_tg_nets() -> list[str]:
    """
    Возвращает актуальный список подсетей.
    Порядок: файл → builtin. Никогда не пустой.
    """
    from_file = _load_from_file()
    return from_file if from_file else list(_BUILTIN_NETS)


def update_tg_nets_interactive() -> list[str]:
    """
    Интерактивное обновление: запрос всех источников + сохранение + вывод.
    """
    print()
    print(f"  {CYAN}{BOLD}╔══ Обновление подсетей Telegram ══╗{NC}")
    print(f"  {CYAN}║{NC}  ASN: {', '.join('AS' + str(a) for a in TG_ASNS)}")
    print(f"  {CYAN}╚{'═'*35}╝{NC}")

    nets, sources_used = fetch_tg_nets_from_sources(verbose=True)

    _save_to_file(nets, sources_used)
    print(f"  {GREEN}✓ Сохранено: {NETS_FILE}{NC}")

    return nets


def tg_nets_status_line() -> str:
    """Однострочный статус для меню."""
    age  = _file_age_days()
    nets = get_tg_nets()
    cnt  = len(nets)

    if age is None:
        return f"{YELLOW}Подсети TG: {cnt} (встроенный список){NC}"

    ts = datetime.fromtimestamp(NETS_FILE.stat().st_mtime).strftime("%Y-%m-%d")
    if age >= STALE_DAYS:
        return f"{RED}Подсети TG: {cnt} ({ts} — УСТАРЕЛ {age} дн.!){NC}"
    elif age >= WARN_DAYS:
        return f"{YELLOW}Подсети TG: {cnt} ({ts} — {age} дн., обновить){NC}"
    return f"{GREEN}Подсети TG: {cnt} ({ts}, {age} дн.){NC}"
