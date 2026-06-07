"""
vless_installer/modules/ipban.py
───────────────────────────────────────────────────────────────────────────────
Ручной бан IP на уровне iptables через ipset.

Возможности:
  • Бан одного IP                  (192.168.1.1)
  • Бан нескольких IP              (1.2.3.4, 5.6.7.8, ...)
  • Бан диапазона IP               (10.0.0.1-10.0.0.255)
  • Бан подсети (CIDR)             (10.0.0.0/24)
  • Бан целой ASN                  (AS12345 → скачивает префиксы с RIPE Stat)

Реализация:
  • ipset hash:net  xray_manual_ban   (IPv4)
  • ipset hash:net  xray_manual_ban6  (IPv6)
  • iptables  INPUT -m set --match-set xray_manual_ban  src -j DROP
  • ip6tables INPUT -m set --match-set xray_manual_ban6 src -j DROP
  • Состояние бана → /var/lib/xray-installer/ipban.json
  • Персистентность — через ipset_persist (сохранение в /etc/ipset.conf)

Бан НЕ затрагивает:
  • Xray-конфиг (никаких изменений в config.json)
  • GeoIP-блокировку (xray_ru_block / xray_ru_block6)
  • AutoBan (xray-autoban)
  • Службы: xray, nginx, telemt и все прочие

Точка входа из _core.py:
    from vless_installer.modules.ipban import do_manage_ipban
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

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
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN']; YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];  BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE']; NC     = _C['NC']


# ── Константы ─────────────────────────────────────────────────────────────────
_STATE_FILE    = Path("/var/lib/xray-installer/ipban.json")
_IPSET_V4      = "xray_manual_ban"
_IPSET_V6      = "xray_manual_ban6"
_COMMENT       = "xray-manual-ban"
_IPSET_CONF    = Path("/etc/ipset.conf")

_RIPE_PREFIXES = (
    "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
)


# ── Вспомогательные принтеры ──────────────────────────────────────────────────
def _ok(msg: str)   -> None: print(f"  {GREEN}✓{NC} {msg}")
def _warn(msg: str) -> None: print(f"  {YELLOW}⚠{NC}  {msg}")
def _info(msg: str) -> None: print(f"  {CYAN}•{NC} {msg}")
def _err(msg: str)  -> None: print(f"  {RED}✗{NC} {msg}", file=sys.stderr)


def _run(cmd: list, quiet: bool = False) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if not quiet and r.returncode != 0 and r.stderr:
        _warn(r.stderr.strip()[:200])
    return r


# ── Работа с состоянием ───────────────────────────────────────────────────────
def _state_load() -> dict:
    """Загружает состояние бана из JSON-файла."""
    try:
        if _STATE_FILE.exists():
            data = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {"entries": []}


def _state_save(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(
        json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _state_add_entry(
    display: str, cidrs: list, kind: str, comment: str = ""
) -> None:
    """Добавляет запись в state-файл (дедупликация по display)."""
    state = _state_load()
    entries = state.setdefault("entries", [])
    # не дублируем по display-имени
    entries = [e for e in entries if e.get("display") != display]
    entries.append({
        "display":  display,
        "kind":     kind,          # ip | cidr | range | asn
        "cidrs":    cidrs,
        "comment":  comment,
        "added_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    state["entries"] = entries
    _state_save(state)


def _state_remove_entry(display: str) -> bool:
    state = _state_load()
    before = len(state.get("entries", []))
    state["entries"] = [
        e for e in state.get("entries", []) if e.get("display") != display
    ]
    _state_save(state)
    return len(state["entries"]) < before


# ── ipset-хелперы ─────────────────────────────────────────────────────────────
def _ipset_available() -> bool:
    return subprocess.run(["which", "ipset"], capture_output=True).returncode == 0


def _set_exists(name: str) -> bool:
    return subprocess.run(
        ["ipset", "list", "-n", name], capture_output=True
    ).returncode == 0


def _ensure_sets() -> bool:
    """Создаёт ipset-сеты если они ещё не существуют."""
    if not _ipset_available():
        _err("ipset не установлен. Установите: apt install ipset")
        return False
    _run(["ipset", "create", _IPSET_V4, "hash:net",
          "family", "inet",  "maxelem", "65536", "-exist"], quiet=True)
    _run(["ipset", "create", _IPSET_V6, "hash:net",
          "family", "inet6", "maxelem", "65536", "-exist"], quiet=True)
    return True


def _ensure_iptables_rules() -> None:
    """
    Добавляет правила iptables DROP через _IPSET_V4 / _IPSET_V6 в цепочку INPUT,
    только если они ещё не существуют.
    Правила ставятся через -A (в конец), не -I 1 — чтобы не перекрыть
    ESTABLISHED,RELATED и lo-ACCEPT, которые уже находятся выше.
    """
    # IPv4
    _chk4 = subprocess.run(
        ["iptables", "-C", "INPUT",
         "-m", "set", "--match-set", _IPSET_V4, "src", "-j", "DROP"],
        capture_output=True
    )
    if _chk4.returncode != 0:
        _run([
            "iptables", "-A", "INPUT",
            "-m", "set", "--match-set", _IPSET_V4, "src",
            "-j", "DROP",
            "-m", "comment", "--comment", _COMMENT,
        ], quiet=True)

    # IPv6
    _chk6 = subprocess.run(
        ["ip6tables", "-C", "INPUT",
         "-m", "set", "--match-set", _IPSET_V6, "src", "-j", "DROP"],
        capture_output=True
    )
    if _chk6.returncode != 0:
        _run([
            "ip6tables", "-A", "INPUT",
            "-m", "set", "--match-set", _IPSET_V6, "src",
            "-j", "DROP",
            "-m", "comment", "--comment", _COMMENT,
        ], quiet=True)


def _remove_iptables_rules() -> None:
    """Удаляет правила iptables (все вхождения xray-manual-ban)."""
    for _ in range(10):
        r = _run([
            "iptables", "-D", "INPUT",
            "-m", "set", "--match-set", _IPSET_V4, "src", "-j", "DROP"
        ], quiet=True)
        if r.returncode != 0:
            break
    for _ in range(10):
        r = _run([
            "ip6tables", "-D", "INPUT",
            "-m", "set", "--match-set", _IPSET_V6, "src", "-j", "DROP"
        ], quiet=True)
        if r.returncode != 0:
            break


def _ipset_add_cidrs(cidrs: list) -> Tuple[int, int]:
    """
    Добавляет список CIDR в соответствующие сеты.
    Возвращает (добавлено_v4, добавлено_v6).
    """
    v4 = [c for c in cidrs if ":" not in c]
    v6 = [c for c in cidrs if ":" in c]

    added_v4 = added_v6 = 0
    for cidr in v4:
        r = _run(["ipset", "add", _IPSET_V4, cidr, "-exist"], quiet=True)
        if r.returncode == 0:
            added_v4 += 1
    for cidr in v6:
        r = _run(["ipset", "add", _IPSET_V6, cidr, "-exist"], quiet=True)
        if r.returncode == 0:
            added_v6 += 1
    return added_v4, added_v6


def _ipset_del_cidrs(cidrs: list) -> None:
    """Удаляет список CIDR из сетов (игнорирует ошибки)."""
    for cidr in cidrs:
        if ":" not in cidr:
            _run(["ipset", "del", _IPSET_V4, cidr], quiet=True)
        else:
            _run(["ipset", "del", _IPSET_V6, cidr], quiet=True)


def _ipset_flush_all() -> None:
    """Очищает оба сета полностью."""
    _run(["ipset", "flush", _IPSET_V4], quiet=True)
    _run(["ipset", "flush", _IPSET_V6], quiet=True)


def _ipset_destroy_all() -> None:
    """Уничтожает оба сета."""
    _run(["ipset", "destroy", _IPSET_V4], quiet=True)
    _run(["ipset", "destroy", _IPSET_V6], quiet=True)


def _ipset_count() -> Tuple[int, int]:
    """Возвращает количество записей в (v4, v6)."""
    def _cnt(name: str) -> int:
        if not _set_exists(name):
            return 0
        r = subprocess.run(["ipset", "list", name], capture_output=True, text=True)
        return r.stdout.count("\n") - r.stdout.find("Members:") // 1 if "Members:" in r.stdout else 0
    # точнее: grep ^[0-9]
    def _cnt2(name: str) -> int:
        if not _set_exists(name):
            return 0
        r = subprocess.run(["ipset", "list", name], capture_output=True, text=True)
        after = r.stdout.split("Members:", 1)
        if len(after) < 2:
            return 0
        return sum(1 for ln in after[1].splitlines() if ln.strip())
    return _cnt2(_IPSET_V4), _cnt2(_IPSET_V6)


# ── Сохранение ipset-состояния (персистентность) ──────────────────────────────
def _ipban_persist_save() -> None:
    """
    Сохраняет xray_manual_ban* в /etc/ipset.conf, дополняя (не заменяя)
    существующие записи из ingress_geoip / других модулей.
    """
    if not _ipset_available():
        return

    # Читаем существующий файл (может содержать xray_ru_block* и т.д.)
    existing_lines: list[str] = []
    if _IPSET_CONF.exists():
        try:
            raw = _IPSET_CONF.read_text(encoding="utf-8")
            # Удаляем старые секции xray_manual_ban*
            skip = False
            for ln in raw.splitlines():
                if ln.startswith("create xray_manual_ban"):
                    skip = True
                if skip and (ln.startswith("create ") and "xray_manual_ban" not in ln):
                    skip = False
                if not skip:
                    existing_lines.append(ln)
        except Exception:
            pass

    # Добавляем свежий дамп xray_manual_ban*
    new_parts: list[str] = []
    for name in (_IPSET_V4, _IPSET_V6):
        if _set_exists(name):
            r = subprocess.run(["ipset", "save", name], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                new_parts.append(r.stdout.strip())

    content = "\n".join(line for line in existing_lines if line) + "\n"
    if new_parts:
        content += "\n".join(new_parts) + "\n"

    try:
        _IPSET_CONF.write_text(content, encoding="utf-8")
        _IPSET_CONF.chmod(0o600)
        _info(f"ipset сохранён → {_IPSET_CONF}")
    except Exception as exc:
        _warn(f"Не удалось записать {_IPSET_CONF}: {exc}")


# ── Парсинг пользовательского ввода ───────────────────────────────────────────
def _parse_ip(raw: str) -> List[str]:
    """Одиночный IP → /32 или /128."""
    net = ipaddress.ip_address(raw)
    bits = 32 if net.version == 4 else 128
    return [f"{net}/{bits}"]


def _parse_cidr(raw: str) -> List[str]:
    """CIDR-подсеть — валидация и нормализация."""
    net = ipaddress.ip_network(raw, strict=False)
    return [str(net)]


def _parse_range(raw: str) -> List[str]:
    """
    Диапазон вида 1.2.3.4-1.2.3.255 → список CIDR.
    Работает только для IPv4 (ipaddress.summarize_address_range).
    """
    parts = raw.split("-", 1)
    if len(parts) != 2:
        raise ValueError(f"Неверный диапазон: {raw!r}")
    start = ipaddress.IPv4Address(parts[0].strip())
    end   = ipaddress.IPv4Address(parts[1].strip())
    if start > end:
        start, end = end, start
    return [str(n) for n in ipaddress.summarize_address_range(start, end)]


def _asn_normalize(raw: str) -> str:
    raw = raw.strip().upper()
    return raw if raw.startswith("AS") else f"AS{raw}"


def _fetch_asn_prefixes(asn: str) -> List[str]:
    """
    Скачивает IPv4+IPv6 префиксы ASN через RIPE Stat.
    Возвращает список CIDR или бросает RuntimeError.
    """
    url = _RIPE_PREFIXES.format(asn=asn)
    _info(f"Запрос префиксов {asn} → RIPE Stat API...")
    for attempt in range(1, 4):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "xray-installer/4.12.7",
                              "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            break
        except Exception as exc:
            if attempt == 3:
                raise RuntimeError(f"RIPE Stat недоступен: {exc}") from exc
            _warn(f"  Попытка {attempt}/3 не удалась, повтор через {2**attempt}с...")
            time.sleep(2 ** attempt)

    try:
        data = json.loads(raw)
    except Exception as exc:
        raise RuntimeError(f"Неверный JSON от RIPE Stat: {exc}") from exc

    prefixes_raw = (
        data.get("data", {}).get("prefixes", [])
    )
    result = []
    for item in prefixes_raw:
        p = item.get("prefix", "")
        try:
            net = ipaddress.ip_network(p, strict=False)
            result.append(str(net))
        except ValueError:
            continue

    if not result:
        raise RuntimeError(f"RIPE Stat вернул 0 префиксов для {asn}")

    v4 = [p for p in result if ":" not in p]
    v6 = [p for p in result if ":" in p]
    _ok(f"{asn}: {len(v4)} IPv4 + {len(v6)} IPv6 префиксов")
    return result


def _detect_input_kind(raw: str) -> str:
    """
    Определяет тип введённых данных:
      'asn'   — AS12345
      'range' — содержит дефис между двумя IP
      'cidr'  — содержит /
      'ip'    — одиночный IP
    """
    raw = raw.strip()
    up = raw.upper()
    if up.startswith("AS") or (raw.isdigit() and len(raw) <= 10):
        return "asn"
    if "/" in raw:
        return "cidr"
    if "-" in raw and ":" not in raw:
        return "range"
    return "ip"


def _resolve_to_cidrs(raw: str) -> Tuple[str, str, List[str]]:
    """
    Главный парсер. raw — пользовательский ввод (один токен).
    Возвращает (display_name, kind, [CIDR, ...]).
    Бросает ValueError/RuntimeError при ошибке.
    """
    raw = raw.strip()
    kind = _detect_input_kind(raw)

    if kind == "asn":
        asn = _asn_normalize(raw)
        cidrs = _fetch_asn_prefixes(asn)
        return asn, "asn", cidrs

    if kind == "range":
        cidrs = _parse_range(raw)
        return raw, "range", cidrs

    if kind == "cidr":
        cidrs = _parse_cidr(raw)
        return str(ipaddress.ip_network(raw, strict=False)), "cidr", cidrs

    # одиночный IP
    cidrs = _parse_ip(raw)
    return str(ipaddress.ip_address(raw)), "ip", cidrs


# ── Публичный API (применение / снятие) ───────────────────────────────────────
def ipban_add(raw: str, comment: str = "") -> bool:
    """
    Банит один IP / CIDR / диапазон / ASN.
    Возвращает True при успехе.
    """
    if not _ensure_sets():
        return False
    try:
        display, kind, cidrs = _resolve_to_cidrs(raw)
    except (ValueError, RuntimeError) as exc:
        _err(str(exc))
        return False

    _ensure_iptables_rules()
    added_v4, added_v6 = _ipset_add_cidrs(cidrs)
    total = added_v4 + added_v6
    if total == 0:
        _warn(f"Ничего не добавлено для {display!r} (уже в списке или ошибка ipset)")
    else:
        _ok(f"Заблокировано: {display}  "
            f"[{total} CIDR: {added_v4} IPv4 + {added_v6} IPv6]")

    _state_add_entry(display, cidrs, kind, comment)
    _ipban_persist_save()
    return True


def ipban_remove(display: str) -> bool:
    """
    Снимает бан по display-имени (берёт CIDR из state).
    Возвращает True при успехе.
    """
    state = _state_load()
    entry = next(
        (e for e in state.get("entries", []) if e.get("display") == display),
        None,
    )
    if not entry:
        _err(f"Запись {display!r} не найдена в state")
        return False

    _ipset_del_cidrs(entry.get("cidrs", []))
    _state_remove_entry(display)
    _ipban_persist_save()
    _ok(f"Разбанено: {display}")
    return True


def ipban_flush() -> None:
    """Снимает все баны, удаляет правила iptables и сеты."""
    _remove_iptables_rules()
    _ipset_flush_all()
    _ipset_destroy_all()
    _state_save({"entries": []})
    _ipban_persist_save()
    _ok("Все IP-баны сняты, сеты удалены")


def ipban_restore() -> None:
    """
    Восстанавливает баны из state (например, после reboot если
    xray-ipset-restore.service не установлен).
    """
    state = _state_load()
    entries = state.get("entries", [])
    if not entries:
        _info("Нет записей для восстановления")
        return
    if not _ensure_sets():
        return
    _ensure_iptables_rules()
    total = 0
    for e in entries:
        v4, v6 = _ipset_add_cidrs(e.get("cidrs", []))
        total += v4 + v6
    _ok(f"Восстановлено {total} CIDR из {len(entries)} записей")


# ── Интерактивное меню ────────────────────────────────────────────────────────
def do_manage_ipban() -> None:
    """
    Главное меню управления IP-банами на уровне iptables.
    Вызывается из _core.py → _menu_security().
    """
    from vless_installer._core import (
        _box_top, _box_row, _box_sep, _box_bottom,
        _box_item, _box_back, _box_info, _box_warn, _box_ok,
        _box_dim, _box_input, DIM as _DIM, NC as _NC,
    )

    while True:
        os.system("clear")
        state    = _state_load()
        entries  = state.get("entries", [])
        cnt_v4, cnt_v6 = _ipset_count()
        sets_ok  = _set_exists(_IPSET_V4) or _set_exists(_IPSET_V6)

        # статус iptables-правил
        chk4 = subprocess.run(
            ["iptables", "-C", "INPUT",
             "-m", "set", "--match-set", _IPSET_V4, "src", "-j", "DROP"],
            capture_output=True
        ).returncode == 0
        chk6 = subprocess.run(
            ["ip6tables", "-C", "INPUT",
             "-m", "set", "--match-set", _IPSET_V6, "src", "-j", "DROP"],
            capture_output=True
        ).returncode == 0

        rules_str = (
            f"{GREEN}активны{NC}"
            if (chk4 or chk6) else f"{DIM}не установлены{NC}"
        )
        entries_str = (
            f"{GREEN}{len(entries)} запис{'ь' if len(entries)==1 else 'и' if 2<=len(entries)<=4 else 'ей'}{NC}"
            if entries else f"{DIM}нет{NC}"
        )
        cidr_str = (
            f"{GREEN}{cnt_v4} IPv4 + {cnt_v6} IPv6{NC}"
            if sets_ok else f"{DIM}ipset не создан{NC}"
        )

        print()
        _box_top("🚫  IP-БАН  (iptables/ipset)")
        _box_row(f"  Правила iptables:   {rules_str}")
        _box_row(f"  Записей в state:    {entries_str}")
        _box_row(f"  Активных CIDR:      {cidr_str}")
        _box_sep()
        _box_item("1", f"➕  Добавить бан  {DIM}(IP / подсеть / диапазон / ASN){NC}")
        _box_item("2", f"➖  Снять бан{NC}")
        _box_item("3", f"📋  Список активных банов")
        _box_sep()
        _box_item("4", f"🔄  Восстановить из state  {DIM}(после reboot){NC}")
        _box_item("5", f"💾  Сохранить ipset → {_IPSET_CONF}")
        _box_item("X", f"{RED}🗑️   Снять ВСЕ баны{NC}  {DIM}(flush + удаление сетов){NC}")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        # ── 1. Добавить бан ───────────────────────────────────────────────────
        if ch == "1":
            os.system("clear")
            print()
            _box_top("🚫  ДОБАВИТЬ БАН")
            _box_row(f"  Форматы ввода (можно несколько через запятую или пробел):")
            _box_row()
            _box_row(f"    {CYAN}1.2.3.4{NC}              — одиночный IP")
            _box_row(f"    {CYAN}10.0.0.0/24{NC}          — подсеть (CIDR)")
            _box_row(f"    {CYAN}10.0.0.1-10.0.0.255{NC}  — диапазон IPv4")
            _box_row(f"    {CYAN}AS12345{NC}               — вся ASN (RIPE Stat)")
            _box_row(f"    {CYAN}2001:db8::/32{NC}         — IPv6 подсеть")
            _box_row()
            _box_row(f"  {DIM}Пример: 1.2.3.4, 10.0.0.0/8, AS1234{NC}")
            _box_bottom()

            try:
                raw_inp = input(f"{CYAN}Введите:{NC} ").strip()
            except (EOFError, KeyboardInterrupt):
                continue

            if not raw_inp:
                continue

            try:
                comment_inp = input(f"{CYAN}Комментарий (Enter — пропустить):{NC} ").strip()
            except (EOFError, KeyboardInterrupt):
                comment_inp = ""

            # Разбиваем по запятым и пробелам
            tokens = [t.strip() for t in raw_inp.replace(",", " ").split() if t.strip()]
            print()
            _box_top("🚫  ПРИМЕНЯЮ БАН...")
            for token in tokens:
                ipban_add(token, comment=comment_inp)
            _box_bottom()
            input(f"{CYAN}Нажмите Enter...{NC}")

        # ── 2. Снять бан ──────────────────────────────────────────────────────
        elif ch == "2":
            os.system("clear")
            state   = _state_load()
            entries = state.get("entries", [])
            if not entries:
                print()
                _box_top("🚫  СНЯТЬ БАН")
                _box_row(f"  {YELLOW}Список банов пуст.{NC}")
                _box_bottom()
                input(f"{CYAN}Нажмите Enter...{NC}")
                continue

            print()
            _box_top("🚫  СНЯТЬ БАН — выберите запись")
            for idx, e in enumerate(entries, 1):
                kind_icon = {
                    "ip":    "🔹", "cidr": "🔸",
                    "range": "🔷", "asn":  "🏢",
                }.get(e.get("kind", ""), "•")
                n_cidr = len(e.get("cidrs", []))
                added  = e.get("added_at", "")[:10]
                cmt    = f"  {DIM}{e['comment']}{NC}" if e.get("comment") else ""
                _box_row(
                    f"  {CYAN}{idx:>2}.{NC} {kind_icon}  {BOLD}{e['display']}{NC}"
                    f"  {DIM}[{n_cidr} CIDR, {added}]{NC}{cmt}"
                )
            _box_sep()
            _box_row(f"  {DIM}Введите номер или display-имя{NC}")
            _box_bottom()

            try:
                sel = input(f"{CYAN}Выбор:{NC} ").strip()
            except (EOFError, KeyboardInterrupt):
                continue

            if not sel:
                continue

            # по номеру или по имени
            target = None
            if sel.isdigit():
                idx = int(sel) - 1
                if 0 <= idx < len(entries):
                    target = entries[idx]["display"]
            else:
                # ищем по display или asn
                for e in entries:
                    if sel.upper() == e["display"].upper():
                        target = e["display"]
                        break

            if not target:
                _warn(f"Запись {sel!r} не найдена")
                time.sleep(1)
                continue

            print()
            _box_top("🚫  СНИМАЮ БАН...")
            ipban_remove(target)
            _box_bottom()
            input(f"{CYAN}Нажмите Enter...{NC}")

        # ── 3. Список ─────────────────────────────────────────────────────────
        elif ch == "3":
            os.system("clear")
            state   = _state_load()
            entries = state.get("entries", [])
            print()
            _box_top("📋  АКТИВНЫЕ IP-БАНЫ")
            if not entries:
                _box_row(f"  {DIM}Список пуст{NC}")
            else:
                _box_row(
                    f"  {'#':>3}  {'Тип':<6}  {'Запись':<30}  "
                    f"{'CIDR':>5}  {'Добавлен':<10}  Комментарий"
                )
                _box_sep()
                kind_labels = {
                    "ip": "IP", "cidr": "CIDR",
                    "range": "Range", "asn": "ASN",
                }
                for idx, e in enumerate(entries, 1):
                    kind   = kind_labels.get(e.get("kind", ""), "?")
                    n_cidr = len(e.get("cidrs", []))
                    added  = e.get("added_at", "")[:10]
                    cmt    = e.get("comment", "")[:20]
                    disp   = e.get("display", "")[:30]
                    _box_row(
                        f"  {CYAN}{idx:>3}.{NC}  {kind:<6}  {BOLD}{disp:<30}{NC}"
                        f"  {n_cidr:>5}  {DIM}{added:<10}{NC}  {DIM}{cmt}{NC}"
                    )
            _box_sep()
            cnt_v4, cnt_v6 = _ipset_count()
            _box_row(
                f"  Итого в ipset:  {GREEN}{cnt_v4}{NC} IPv4 + {GREEN}{cnt_v6}{NC} IPv6 CIDR"
            )
            _box_bottom()
            input(f"{CYAN}Нажмите Enter...{NC}")

        # ── 4. Восстановить ───────────────────────────────────────────────────
        elif ch == "4":
            print()
            _box_top("🔄  ВОССТАНОВЛЕНИЕ ИЗ STATE...")
            ipban_restore()
            _box_bottom()
            input(f"{CYAN}Нажмите Enter...{NC}")

        # ── 5. Сохранить ipset ────────────────────────────────────────────────
        elif ch == "5":
            print()
            _box_top("💾  СОХРАНЕНИЕ IPSET...")
            _ipban_persist_save()
            _box_bottom()
            input(f"{CYAN}Нажмите Enter...{NC}")

        # ── X. Сбросить всё ───────────────────────────────────────────────────
        elif ch == "x":
            print()
            _box_top(f"{RED}🗑️   СБРОС ВСЕХ БАНОВ{NC}")
            _box_row(f"  {YELLOW}Будут удалены ВСЕ правила iptables и ipset-сеты.{NC}")
            _box_row(f"  {YELLOW}State-файл будет очищен.{NC}")
            _box_bottom()
            try:
                confirm = input(
                    f"{RED}Введите{NC} {BOLD}ДА{NC} для подтверждения: "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if confirm in ("ДА", "да", "yes", "YES", "y", "Y"):
                print()
                _box_top("🗑️   ОЧИЩАЮ...")
                ipban_flush()
                _box_bottom()
            else:
                _info("Отменено")
            input(f"{CYAN}Нажмите Enter...{NC}")

        elif ch in ("q", ""):
            break
