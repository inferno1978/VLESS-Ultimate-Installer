"""
vless_installer/modules/telemt_mss_selector.py
───────────────────────────────────────────────────────────────────────────────
Выбор MSS-пресета для защиты Telemt от JA4/JA3 DPI-дактилоскопии TSPU.

Контекст
────────
С 1 апреля 2026 г. TSPU (часть АСБИ) развернул правила JA4-фингерпринтинга,
распознающие MTProxy Fake-TLS по уникальному паттерну TLS ClientHello.
Механизм обхода — объявление малого TCP MSS в SYN/ACK: клиент вынужден
фрагментировать ClientHello по нескольким сегментам, ALPN и
signature_algorithms (ключевые поля для JA4) попадают во 2-й / 3-й сегмент —
одно-пакетный экстрактор TSPU видит неверный хэш и пропускает соединение.

Параметр `client_mss` появился в telemt ≥ 3.4.15.
При установке на более ранней версии поле будет проигнорировано telemt'ом
без ошибки, поэтому добавление в конфиг безопасно при любой версии.

Пресеты
───────
  Пресеты с именем (tspu, 2in8, extreme-low) — нативные алиасы telemt.
  Числовые значения (256, 512, 1024) — сырые MSS, передаются как строки.
  Пустая строка — параметр не записывается в конфиг, ядро выбирает MSS само.

Интеграция с mtproto.py
───────────────────────
  Вызывается из _run_install_inner() через:
      from vless_installer.modules.telemt_mss_selector import (
          mss_select_interactive,
          mss_status_line,
          MSS_PRESET_NONE,
      )
  Возвращаемое значение передаётся в _write_config(client_mss=...).
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

# ── Константы ────────────────────────────────────────────────────────────────
_CONFIG_FILE = Path("/etc/telemt/telemt.toml")

MSS_PRESET_NONE = ""   # не добавлять client_mss в конфиг

# ── Цвета (self-contained, не импортируем из mtproto) ────────────────────────
def _colors() -> dict:
    if sys.stdout.isatty():
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ══════════════════════════════════════════════════════════════════════════════
#  ПРЕСЕТЫ
# ══════════════════════════════════════════════════════════════════════════════

# Каждый пресет: (key, value, mss_bytes_or_None, label, detail, recommended)
#   key          — символ для ввода пользователем
#   value        — строка, которая пойдёт в telemt.toml: client_mss = "<value>"
#                  пустая строка → параметр не пишется в конфиг
#   mss_int      — числовое значение MSS (только для отображения), None если нет
#   label        — короткое название
#   detail       — однострочное пояснение
#   recommended  — True → помечаем ★

_PRESETS: list[tuple] = [
    # key   value          mss_int  label                    detail                                            recommended
    ("1",  "tspu",         92,      "TSPU Stealth",
     "MSS 92 — нативный пресет против TSPU JA4. Дробит ClientHello на 5–7 сегментов.",
     True),

    ("2",  "2in8",         256,     "2-in-8 Split",
     "MSS 256 — умеренная фрагментация. ClientHello в 3–4 сегмента. Меньше overhead.",
     False),

    ("3",  "512",          512,     "Half-MSS",
     "MSS 512 — лёгкая фрагментация. Снижает нагрузку на CPU, слабее обходит JA4.",
     False),

    ("4",  "extreme-low",  88,      "Extreme Low",
     "MSS 88 — максимальная фрагментация. Используйте если tspu не помогает.",
     False),

    ("5",  "1024",         1024,    "Soft Split",
     "MSS 1024 — минимальная фрагментация. Для линий с высокой потерей пакетов.",
     False),

    ("6",  "768",          768,     "Balanced",
     "MSS 768 — баланс между фрагментацией и накладными расходами TCP.",
     False),

    ("7",  "336",          336,     "3-in-3 Split",
     "MSS 336 — ClientHello в ~3 сегмента. Хороший компромисс для мобильных клиентов.",
     False),

    ("8",  "176",          176,     "Deep Fragment",
     "MSS 176 — глубокая фрагментация. Эффективно против реассемблирующего DPI.",
     False),

    ("9",  "128",          128,     "Micro Segment",
     "MSS 128 — очень мелкая нарезка. Значительный overhead, высокая антидетект-надёжность.",
     False),

    ("0",  MSS_PRESET_NONE, None,  "Без изменений",
     "MSS выбирает ядро (~1460 LAN / ~1360 VPN). client_mss не пишется в конфиг.",
     False),
]

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════

_BOX_W = 66

def _plain(s: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', s)

def _wlen(s: str) -> int:
    import unicodedata as _ud
    plain = _plain(s)
    width = 0
    chars = list(plain)
    i = 0
    while i < len(chars):
        ch = chars[i]
        cp = ord(ch)
        next_cp = ord(chars[i + 1]) if i + 1 < len(chars) else 0
        if next_cp == 0xFE0F:
            width += 2; i += 2; continue
        if cp == 0x200D or (0x300 <= cp <= 0x36F) or (0xFE00 <= cp <= 0xFE0F):
            i += 1; continue
        eaw = _ud.east_asian_width(ch)
        if eaw in ('W', 'F'):
            width += 2
        elif eaw == 'N' and (0x1F300 <= cp <= 0x1FAFF or 0x2B00 <= cp <= 0x2BFF):
            width += 2
        else:
            width += 1
        i += 1
    return width

def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad  = _BOX_W - _wlen(title)
        lpad = pad // 2
        rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None:
    print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_bot() -> None:
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        acc = 0
        plain = _plain(text)
        cut = 0
        import unicodedata as _ud
        for i, ch in enumerate(plain):
            acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc > _BOX_W - 1:
                cut = i; break
        text = text[:cut] + "…"
        w = _wlen(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")

def _box_info(msg: str) -> None:
    _box_row(f"  {CYAN}→{NC}  {msg}")

def _box_ok(msg: str) -> None:
    _box_row(f"  {GREEN}✓{NC}  {msg}")

def _box_warn(msg: str) -> None:
    _box_row(f"  {YELLOW}⚠{NC}  {msg}")

class _Cancelled(Exception):
    pass

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

# ══════════════════════════════════════════════════════════════════════════════
#  ПУБЛИЧНЫЙ API
# ══════════════════════════════════════════════════════════════════════════════

def mss_select_interactive() -> str:
    """
    Интерактивный экран выбора MSS-пресета.

    Возвращает строку-значение для client_mss в telemt.toml:
      "tspu", "2in8", "extreme-low", "512", "256", ...
    или пустую строку MSS_PRESET_NONE — параметр не добавляется в конфиг.

    Бросает _Cancelled при Ctrl+C — вызывающий код должен перехватить.
    """
    import os
    os.system("clear")

    _box_top("ЗАЩИТА ОТ DPI  •  MSS ФРАГМЕНТАЦИЯ CLIENT HELLO")
    _box_row()
    _box_info("С 01.04.2026 TSPU блокирует MTProxy Fake-TLS через JA4 fingerprint.")
    _box_info("TCP MSS < MTU дробит ClientHello — DPI-экстрактор видит неверный хэш.")
    _box_info("Параметр client_mss требует telemt ≥ 3.4.15. На старых версиях")
    _box_info("он игнорируется без ошибки — конфиг останется рабочим.")
    _box_row()
    _box_sep()

    # ── Таблица пресетов ──────────────────────────────────────────────────────
    for (key, value, mss_int, label, detail, recommended) in _PRESETS:
        star = f" {GREEN}★ рекомендуется{NC}" if recommended else ""
        mss_str = f"MSS {mss_int}" if mss_int is not None else "без изменений"
        key_col = RED + BOLD if key == "0" else WHITE + BOLD
        header = (
            f"  {DIM}[{NC}{key_col}{key}{NC}{DIM}]{NC}  "
            f"{BOLD}{label}{NC}{star}"
        )
        _box_row(header)
        _box_row(f"       {DIM}{mss_str}  —  {detail[:48]}{NC}")
        _box_row()

    _box_sep()
    _box_row(f"  {DIM}[{NC}{WHITE}{BOLD}C{NC}{DIM}]{NC}  ✏️   Ввести своё значение MSS (88–4096)")
    _box_bot()
    print()

    valid_keys = {p[0] for p in _PRESETS} | {"c", "C"}

    while True:
        raw = _ask(
            f"{CYAN}Выбор MSS-пресета [0-9/C] (Enter=1): {NC}",
            default="1",
            c=True,
        ).strip()

        if raw == "":
            raw = "1"

        if raw.lower() == "c":
            # ── Ручной ввод ───────────────────────────────────────────────────
            try:
                print(f"  {CYAN}Значение MSS (88–4096): {NC}", end="", flush=True)
                custom = input().strip()
            except KeyboardInterrupt:
                print(); continue
            try:
                v = int(custom)
                if 88 <= v <= 4096:
                    return str(v)
                _box_warn("Значение вне диапазона 88–4096. Попробуйте ещё раз.")
            except ValueError:
                _box_warn("Нужно целое число. Попробуйте ещё раз.")
            continue

        for (key, value, mss_int, label, detail, recommended) in _PRESETS:
            if raw == key:
                return value

        _box_warn(f"Неверный выбор: '{raw}'. Введите цифру 0–9 или C.")


def mss_status_line(client_mss: str) -> str:
    """
    Возвращает читаемую строку для итогового бокса установки.
    Например: "tspu (MSS 92) — TSPU anti-JA4 ★"
    """
    if not client_mss:
        return f"{DIM}не задан (MSS ядра){NC}"

    for (key, value, mss_int, label, detail, recommended) in _PRESETS:
        if value == client_mss:
            star = f"  {GREEN}★{NC}" if recommended else ""
            mss_s = f"MSS {mss_int}" if mss_int else ""
            return f"{BOLD}{client_mss}{NC} ({mss_s})  {DIM}{label}{NC}{star}"

    # Числовое кастомное значение
    return f"{BOLD}{client_mss}{NC} (MSS {client_mss}, custom)"


def get_current_mss(config_file: Optional[Path] = None) -> str:
    """
    Читает текущее значение client_mss из telemt.toml.
    Возвращает строку или MSS_PRESET_NONE если параметр отсутствует.
    """
    path = config_file or _CONFIG_FILE
    if not path.exists():
        return MSS_PRESET_NONE
    try:
        m = re.search(
            r'^client_mss\s*=\s*"([^"]*)"',
            path.read_text(),
            re.MULTILINE,
        )
        return m.group(1) if m else MSS_PRESET_NONE
    except Exception:
        return MSS_PRESET_NONE
