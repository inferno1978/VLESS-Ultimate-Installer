"""
vless_installer/modules/box_renderer.py
───────────────────────────────────────────────────────────────────────────────
Box-рендеринг для интерактивных меню VLESS Ultimate Installer.

Содержит всю систему отрисовки рамок, строк, элементов меню и вспомогательных
функций форматирования, которая используется во всех модулях инсталлятора.

Точка входа из _core.py:
    from vless_installer.modules.box_renderer import (
        _get_box_width, _plain, _wcslen,
        _box_line_top, _box_line_sep, _box_line_bot,
        _box_row, _box_row_auto, _box_link, _box_top, _box_sep, _box_bottom,
        _box_item, _box_item_exit, _box_back, _box_desc,
        _box_wrap_msg, _box_info, _box_warn, _box_ok, _box_dim, _box_input,
        _submenu_header, _submenu_item, _submenu_back,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import re
import sys
import unicodedata
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


# =============================================================================
import re as _re
import unicodedata as _unicodedata

def _get_box_width() -> int:
    """
    Определяет внутреннюю ширину рамки динамически:
    - Берёт ширину терминала минус 2 (под символы ║ с обеих сторон)
    - Минимум 64 (ширина баннера), максимум 78 (безопасный лимит для SSH)
    """
    cols = 80  # безопасный дефолт
    # 1. Переменная окружения (более надёжна в браузерных SSH-клиентах)
    env_cols = os.environ.get("COLUMNS", "").strip()
    if env_cols.isdigit():
        cols = int(env_cols)
    # 2. PTY (может быть некорректна, берём только если меньше env)
    try:
        pty_cols = os.get_terminal_size().columns
        cols = min(cols, pty_cols)
    except Exception:
        pass
    return max(64, min(cols - 2, 100))

_BOX_W = _get_box_width()  # внутренняя ширина рамки (динамическая)


def _plain(s: str) -> str:
    """Возвращает строку без ANSI-кодов."""
    return _re.sub(r'\033\[[0-9;]*m', '', s)


def _wcslen(s: str) -> int:
    """
    Подсчёт видимой ширины строки в терминале с учётом:
      - ANSI escape-кодов (не видны)
      - Emoji и CJK символов (занимают 2 колонки каждый)
      - Emoji с вариационным селектором VS16 (U+FE0F) — тоже 2 колонки
      - Zero-width joiners и вариационные селекторы — ширина 0
      - Block elements (█░▓▒, U+2580-U+259F) и Box drawings (─│┌, U+2500-U+257F)
        считаются как 1 колонка (eaw='A'/'N', но в Latin терминалах = 1)
    """
    # Диапазоны символов, которые в стандартных (Latin) терминалах = 1 колонка,
    # даже если eaw='A' (Ambiguous):
    _FORCE_WIDTH1 = (
        (0x2500, 0x257F),  # Box Drawing
        (0x2580, 0x259F),  # Block Elements (█ ░ ▓ ▒ и др.)
        (0x25A0, 0x25FF),  # Geometric Shapes
        # Note: 0x2600-0x26FF (Misc Symbols) and 0x2700-0x27BF (Dingbats) removed
        # because some chars like ⚡ U+26A1 have eaw='W' and must be 2-wide
    )
    # BMP-символы, которые терминалы (особенно с emoji-шрифтом) рендерят как 2 колонки,
    # несмотря на eaw='N'/'A'. Перечисляем точечно, чтобы не сломать рамочную графику.
    _FORCE_WIDTH2_CODEPOINTS = frozenset({
        0x23F8,  # ⏸ PAUSE BUTTON
        0x23F9,  # ⏹ STOP BUTTON
        0x23FA,  # ⏺ RECORD BUTTON
        0x23CF,  # ⏏ EJECT SYMBOL
        0x23ED,  # ⏭ NEXT TRACK
        0x23EE,  # ⏮ LAST TRACK
        0x23EF,  # ⏯ PLAY OR PAUSE
        0x270F,  # ✏ PENCIL (без VS16 в некоторых терминалах = 2)
        0x2714,  # ✔ HEAVY CHECK MARK
        0x2716,  # ✖ HEAVY MULTIPLICATION X
        0x274C,  # ❌ CROSS MARK
        0x2764,  # ❤ HEAVY BLACK HEART
        0x2B50,  # ⭐ WHITE MEDIUM STAR
        0x2B55,  # ⭕ HEAVY LARGE CIRCLE
    })

    plain = _plain(s)
    width = 0
    i = 0
    while i < len(plain):
        ch = plain[i]
        cp = ord(ch)
        # Вариационный селектор (VS1-VS16, VS17-VS256) — нулевая ширина
        if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
            i += 1
            continue
        # Zero-Width Joiner и прочие невидимые объединители
        if cp in (0x200D, 0x200B, 0x200C):
            i += 1
            continue
        # Combining marks — нулевая ширина
        if _unicodedata.category(ch) in ('Mn', 'Me', 'Cf'):
            i += 1
            continue
        # Box-drawing и block-element — явно 1 колонка в Latin терминалах
        if any(lo <= cp <= hi for lo, hi in _FORCE_WIDTH1):
            # Если следует VS16, символ становится 2-wide emoji-стилем
            if i + 1 < len(plain) and ord(plain[i + 1]) == 0xFE0F:
                width += 2
                i += 2
            else:
                width += 1
                i += 1
            continue
        # BMP-emoji, которые терминалы рендерят как 2 колонки (eaw='N', но визуально wide)
        if cp in _FORCE_WIDTH2_CODEPOINTS:
            # Если за символом идёт VS16 — пропускаем его
            if i + 1 < len(plain) and ord(plain[i + 1]) == 0xFE0F:
                i += 2
            else:
                i += 1
            width += 2
            continue
        # Regional Indicator пара (флаги: 🇷🇺 = U+1F1F7 + U+1F1FA) — 2 колонки суммарно
        if 0x1F1E6 <= cp <= 0x1F1FF:
            if i + 1 < len(plain) and 0x1F1E6 <= ord(plain[i + 1]) <= 0x1F1FF:
                width += 2
                i += 2
            else:
                width += 2
                i += 1
            continue
        eaw = _unicodedata.east_asian_width(ch)
        if eaw in ('W', 'F'):
            width += 2
        elif cp >= 0x1F000:
            # Emoji вне BMP — всегда 2 колонки в современных терминалах
            width += 2
        else:
            # Базовые emoji в BMP + VS16 = 2 колонки
            if i + 1 < len(plain) and ord(plain[i + 1]) == 0xFE0F:
                width += 2
            else:
                width += 1
        i += 1
    return width


def _box_line_top() -> None:
    """Верхняя граница: ╔════╗"""
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")


def _box_line_sep() -> None:
    """Разделитель: ╠════║"""
    print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")


def _box_line_bot() -> None:
    """Нижняя граница: ╚════╝"""
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")


def _box_row(text: str = "") -> None:
    """Одна строка внутри рамки: ║ text ... ║

    Если видимая ширина текста превышает _BOX_W — автоматически переносит
    по словам с сохранением ведущего отступа. Правая граница ║ всегда ровная.
    Это единственное место где надо что-то поменять — все существующие и
    будущие вызовы _box_row() получают перенос бесплатно.
    """
    if not text:
        print(f"{CYAN}║{NC}{' ' * _BOX_W}{CYAN}║{NC}")
        return

    vis_w = _wcslen(text)
    if vis_w <= _BOX_W:
        # Обычный случай — влезает, выводим как есть
        pad = _BOX_W - vis_w
        print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")
        return

    # Текст длиннее рамки — переносим по словам.
    #
    # ВАЖНО: ведущий отступ ищем по _plain() (без ANSI), но отрезаем
    # от оригинальной строки нельзя по числовому индексу — строка может
    # начинаться с ANSI-кода (\033[1;37m...), и text[N:] разрежет его.
    # Правильный способ: пропустить ANSI-последовательности в начале строки,
    # затем отрезать ровно leading_spaces видимых пробелов.
    #
    plain = _plain(text)
    leading_spaces = len(plain) - len(plain.lstrip(' '))
    indent = ' ' * leading_spaces   # отступ для строк продолжения

    # Находим позицию в оригинальной строке, пропуская начальные ANSI-коды
    # и ровно leading_spaces видимых пробелов
    _ansi_re_strip = _re.compile(r'\033\[[0-9;]*m')
    pos = 0
    skipped_vis = 0
    while pos < len(text) and skipped_vis < leading_spaces:
        # Пропускаем ANSI-коды (нулевая видимая ширина)
        m = _ansi_re_strip.match(text, pos)
        if m:
            pos = m.end()
            continue
        # Видимый символ — должен быть пробел
        if text[pos] == ' ':
            skipped_vis += 1
            pos += 1
        else:
            break  # дошли до не-пробела раньше — не трогаем
    text_stripped = text[pos:]   # текст после ведущих пробелов (ANSI целые)
    prefix = ' ' * leading_spaces  # ведущий отступ первой строки (чистые пробелы)

    words = text_stripped.split(' ')
    lines_out: list[str] = []
    current = prefix
    current_vis = leading_spaces

    for word in words:
        if not word:
            # пустые токены от split — добавляем пробел если есть место
            if current_vis + 1 <= _BOX_W:
                current     += ' '
                current_vis += 1
            continue
        word_vis = _wcslen(word)
        sep_vis  = 1 if current.strip() else 0
        if current_vis + sep_vis + word_vis <= _BOX_W:
            current     = current + (' ' if current.strip() else '') + word
            current_vis = current_vis + sep_vis + word_vis
        else:
            if current.strip():
                lines_out.append(current)
            # Слово само по себе длиннее строки — режем жёстко по символам
            avail = max(_BOX_W - leading_spaces, 8)
            while _wcslen(word) > avail:
                piece = ''
                pw = 0
                for ch in word:
                    cw = _wcslen(ch)
                    if pw + cw > avail:
                        break
                    piece += ch
                    pw   += cw
                lines_out.append(indent + piece)
                word = word[len(piece):]
            current     = indent + word
            current_vis = leading_spaces + _wcslen(word)

    if current.strip():
        lines_out.append(current)
    elif not lines_out:
        lines_out.append(current)

    for line in lines_out:
        pad = _BOX_W - _wcslen(line)
        if pad < 0:
            pad = 0
        print(f"{CYAN}║{NC}{line}{' ' * pad}{CYAN}║{NC}")


def _box_row_auto(text: str = "", cont_indent: str = "  ") -> None:
    """Одна строка внутри рамки с автопереносом длинных строк.
    Если текст не влезает в _BOX_W — разбивает по словам на несколько строк.
    cont_indent — отступ продолжения (по умолчанию 2 пробела).
    Правая граница ║ всегда на месте."""
    if not text:
        _box_row()
        return
    # Если влезает — выводим как есть
    if _wcslen(text) <= _BOX_W:
        _box_row(text)
        return
    # Нужен перенос: определяем отступ первой строки (ведущие пробелы)
    plain_text = _plain(text)
    first_indent_len = len(plain_text) - len(plain_text.lstrip(' '))
    cont_plain_len = len(cont_indent)
    # Используем _box_wrap_msg: prefix = ведущий отступ + ANSI,
    # msg = остаток без ведущих пробелов (plain, т.к. wrap работает с plain)
    # Но нам нужно сохранить ANSI — используем собственный wrap
    max_w = _BOX_W  # полная внутренняя ширина (pad считается в _box_row)
    words = text.split(' ')
    lines_out = []
    current = ''
    current_w = 0
    for word in words:
        word_w = _wcslen(word)
        sep = ' ' if current else ''
        sep_w = len(sep)
        if current_w + sep_w + word_w <= max_w:
            current += sep + word
            current_w += sep_w + word_w
        else:
            if current:
                lines_out.append(current)
            # Слово длиннее строки — жёсткая резка
            avail = max_w - cont_plain_len
            if avail < 4:
                avail = 4
            while _wcslen(word) > avail:
                piece = ''
                pw = 0
                for ch in word:
                    cw = _wcslen(ch)
                    if pw + cw > avail:
                        break
                    piece += ch
                    pw += cw
                lines_out.append(cont_indent + piece)
                word = word[len(piece):]
            current = cont_indent + word
            current_w = cont_plain_len + _wcslen(word)
    if current:
        lines_out.append(current)
    for line in lines_out:
        _box_row(line)


def _box_link(link: str, colour: str = "") -> None:
    """Выводит ссылку внутри бокса БЕЗ боковых границ ║.
    Строки ссылки печатаются простым print без левого и правого ║,
    чтобы длинный URL никогда не сдвигал правую границу рамки.
    Никогда не разрывает метку (#флаг домен) посередине."""
    if not colour:
        colour = '\033[0;33m'  # non-bold жёлтый
    max_w = _BOX_W - 2  # 1 пробел слева, без правой границы

    # Разбиваем ссылку на часть до # и метку после #
    if "#" in link:
        url_part, label_part = link.rsplit("#", 1)
        label_part = "#" + label_part
    else:
        url_part, label_part = link, ""

    # Собираем токены из url_part, разбивая по & (безопасные точки разрыва)
    tokens = []
    buf = ""
    for ch in url_part:
        buf += ch
        if ch == "&":
            tokens.append(buf)
            buf = ""
    if buf:
        if label_part:
            tokens.append(buf + label_part)
            label_part = ""
        else:
            tokens.append(buf)
    if label_part:
        tokens.append(label_part)

    chunk = ""
    chunk_w = 0
    for token in tokens:
        tok_w = _wcslen(token)
        if chunk_w + tok_w > max_w and chunk:
            print(f" {colour}{chunk}{NC}")
            chunk = token
            chunk_w = tok_w
        else:
            chunk += token
            chunk_w += tok_w
        # Жёсткий разрыв по видимой ширине (не по индексу Python-символов)
        while chunk_w > max_w:
            cut = 0
            cut_w = 0
            for _ch in chunk:
                _cw = _wcslen(_ch)
                if cut_w + _cw > max_w:
                    break
                cut_w += _cw
                cut += 1
            print(f" {colour}{chunk[:cut]}{NC}")
            chunk = chunk[cut:]
            chunk_w = _wcslen(chunk)
    if chunk:
        print(f" {colour}{chunk}{NC}")
def _box_top(title: str = "") -> None:
    """Верхняя граница + опциональный заголовок по центру."""
    _box_line_top()
    if title:
        plain_len = _wcslen(title)
        total_pad = _BOX_W - plain_len
        lpad = total_pad // 2
        rpad = total_pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        _box_line_sep()


def _box_sep() -> None:
    """Горизонтальный разделитель внутри рамки."""
    _box_line_sep()


def _box_bottom() -> None:
    """Нижняя граница рамки."""
    _box_line_bot()


def _box_item(key: str, label: str) -> None:
    """Пункт меню: ║  [KEY]  label  ║"""
    if key in ("Q", "q"):
        text = f"  {DIM}[{NC}{RED}{BOLD}{key}{NC}{DIM}]{NC}  {label}"
    else:
        text = f"  {DIM}[{NC}{WHITE}{BOLD}{key}{NC}{DIM}]{NC}  {label}"
    _box_row(text)


def _box_item_exit(key: str, label: str) -> None:
    """Пункт выхода/назад/отмены с красным жирным ключом: ║  [KEY]  label  ║"""
    text = f"  {DIM}[{NC}{RED}{BOLD}{key}{NC}{DIM}]{NC}  {label}"
    _box_row(text)


def _box_back() -> None:
    """Строка возврата в нижней части рамки."""
    text = f"  {DIM}[{NC}{RED}{BOLD}Q{NC}{DIM}]{NC}  {DIM}← Назад в главное меню{NC}"
    _box_row(text)


def _box_desc(text: str) -> None:
    """Строка описания под пунктом меню (с отступом, приглушённый стиль)."""
    wrapped = f"     {DIM}{text}{NC}"
    # Если строка слишком длинная — перенос с отступом
    inner = _BOX_W - 5  # 5 = len("     ")
    plain_text = _plain(text)
    if _wcslen(plain_text) <= inner:
        _box_row(wrapped)
        return
    # Перенос по словам
    words = plain_text.split(' ')
    lines = []
    current = ''
    for word in words:
        candidate = (current + ' ' + word).lstrip() if current else word
        if _wcslen(candidate) <= inner:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    for i, line in enumerate(lines):
        prefix = "     " if i == 0 else "       "
        _box_row(f"{prefix}{DIM}{line}{NC}")


def _box_wrap_msg(prefix_colored: str, prefix_plain_len: int, msg: str) -> None:
    """Выводит строку внутри рамки с автопереносом длинных сообщений.
    Все строки выводятся через _box_row — единственный источник правого ║."""
    max_msg = _BOX_W - prefix_plain_len
    if max_msg < 10:
        max_msg = 10
    # Разбиваем по словам, используя _wcslen для точного подсчёта
    words = msg.split(' ')
    chunks = []
    current = ''
    for word in words:
        candidate = (current + ' ' + word).lstrip() if current else word
        if _wcslen(candidate) <= max_msg:
            current = candidate
        else:
            if current:
                chunks.append(current)
            # Слово длиннее строки — режем жёстко по _wcslen
            while _wcslen(word) > max_msg:
                piece = ''
                pw = 0
                for ch in word:
                    import unicodedata as _ud2
                    cw = 2 if _ud2.east_asian_width(ch) in ('W', 'F') else 1
                    if pw + cw > max_msg:
                        break
                    piece += ch
                    pw += cw
                chunks.append(piece)
                word = word[len(piece):]
            current = word
    if current:
        chunks.append(current)
    if not chunks:
        _box_row(prefix_colored)
        return
    # Все строки идут через _box_row — он добавляет одинаковый правый ║
    _box_row(f"{prefix_colored}{chunks[0]}")
    indent = ' ' * prefix_plain_len
    for chunk in chunks[1:]:
        _box_row(f"{indent}{chunk}")


def _box_info(msg: str) -> None:
    """Аналог info() внутри рамки: ║ [INFO]  msg ║"""
    _box_wrap_msg(f"{CYAN}[INFO]{NC}  ", 9, msg)


def _box_warn(msg: str) -> None:
    """Аналог warn() внутри рамки: ║ [WARN]  msg ║"""
    _box_wrap_msg(f"{YELLOW}[WARN]{NC}  ", 9, msg)


def _box_ok(msg: str) -> None:
    """Аналог success() внутри рамки: ║ [OK]    msg ║"""
    _box_wrap_msg(f"{GREEN}[OK]{NC}    ", 11, msg)


def _box_dim(msg: str) -> None:
    """Аналог dim() внутри рамки: ║ msg (dim) ║"""
    _box_row(f"{DIM}{msg}{NC}")


def _box_input(prompt: str, default: str = "", reopen: bool = True) -> str:
    """Ввод внутри бокса: закрывает рамку, берёт ввод, опционально рисует ╠══╣."""
    _box_bottom()
    val = input(f"  {CYAN}{prompt}: {NC}").strip()
    if reopen:
        _box_line_top()
    return val if val else default


def _submenu_header(title: str) -> None:
    """Очищает экран — рамка рисуется в самом подменю."""
    os.system("clear")


def _submenu_item(key: str, label: str) -> None:
    _box_item(key, label)
def _submenu_back() -> None:
    _box_back()


# =============================================================================
#  АВАРИЙНОЕ ВОССТАНОВЛЕНИЕ (пункт 6 подменю "Установка и система")
# =============================================================================

