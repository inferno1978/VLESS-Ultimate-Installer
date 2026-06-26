#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hybrid_addon.py — гибридная надстройка Mieru над Xray на Entry-ноде каскада.

Идея: внешний клиент подключается к Mieru (mita), Mieru расшифровывает
и пересылает трафик через SOCKS5 на localhost в Xray, а Xray дальше
рулит исходящим (Режим B / Smart Balancer / что угодно ниже) — точно
так же, как и раньше. Меняется ТОЛЬКО внешний inbound Xray
(vless -> socks на 127.0.0.1), вся остальная логика каскада не трогается.

Не трогает _core.py. Не требует pip — только стандартная библиотека Python.

Использование:
    sudo python3 hybrid_addon.py                          # установка (с подтверждением + выбором портов)
    sudo python3 hybrid_addon.py --dry-run                # только диагностика, без изменений
    sudo python3 hybrid_addon.py --port 8443               # если внешний VLESS-порт не 443
    sudo python3 hybrid_addon.py --mieru-udp-port 51820     # если 444 уже занят чем-то
    sudo python3 hybrid_addon.py --transport tcp            # только TCP-вариант Mieru
    sudo python3 hybrid_addon.py --yes                      # без вопросов, дефолтные порты
    sudo python3 hybrid_addon.py --rollback                 # откатить всё назад
"""

import argparse
import json
import os
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

# ───────────────────────── Стиль вывода (как в основном проекте) ─────────────────────────
# Самостоятельный (без импорта) порт алгоритмов рисования рамок и переноса строк
# из vless_installer/modules/box_renderer.py — ТОЧНО так же, как modules/mieru.py
# держит свою копию того же самого рисунка рамок, а не импортирует общий модуль.
# Причина та же: hybrid_addon.py — самостоятельный CLI (см. докстринг выше,
# "Не требует pip"), а box_renderer.py — часть пакета vless_installer. Импорт
# его в шапке файла сломал бы "sudo python3 hybrid_addon.py" точно так же, как
# уже один раз сломал бы лишний импорт mieru.py (см. _show_mieru_client_links —
# там поэтому лениво, внутри функции). Здесь так сделать нельзя: рамки используются
# буквально во всём файле, а не в одной функции — поэтому код продублирован, а не
# импортирован. Если в box_renderer.py поменяется алгоритм/символика — здесь нужно
# поправить отдельно, копия не синхронизируется автоматически.
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


def _get_box_width() -> int:
    """Внутренняя ширина рамки: ширина терминала минус 2, минимум 64, максимум 100
    (как в box_renderer._get_box_width — тот же диапазон, та же логика)."""
    cols = 80
    env_cols = os.environ.get("COLUMNS", "").strip()
    if env_cols.isdigit():
        cols = int(env_cols)
    try:
        pty_cols = os.get_terminal_size().columns
        cols = min(cols, pty_cols)
    except OSError:
        pass
    return max(64, min(cols - 2, 100))


_BOX_W = _get_box_width()
_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def _plain(s: str) -> str:
    """Строка без ANSI-кодов — для подсчёта реальной видимой ширины."""
    return _ANSI_RE.sub('', s)


def _wcslen(s: str) -> int:
    """Видимая ширина строки в терминале: emoji/CJK = 2 колонки, варианты/комбинирующие
    знаки = 0, обычные символы = 1. Та же логика, что в box_renderer._wcslen."""
    plain = _plain(s)
    width = 0
    i = 0
    while i < len(plain):
        ch = plain[i]
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F or cp in (0x200D, 0x200B, 0x200C):
            i += 1
            continue
        if unicodedata.category(ch) in ('Mn', 'Me', 'Cf'):
            i += 1
            continue
        if 0x1F1E6 <= cp <= 0x1F1FF:  # Regional Indicator (флаги)
            width += 2
            i += 1
            continue
        eaw = unicodedata.east_asian_width(ch)
        if eaw in ('W', 'F') or cp >= 0x1F000:
            width += 2
        elif i + 1 < len(plain) and ord(plain[i + 1]) == 0xFE0F:
            width += 2  # базовый emoji + VS16
        else:
            width += 1
        i += 1
    return width


def _box_row(text: str = "") -> None:
    """Одна строка внутри рамки: ║ text ... ║ — с автопереносом по словам,
    если строка не влезает в _BOX_W. Правая граница всегда ровная — это
    единственное место, рисующее правый ║, все остальные функции зовут его."""
    if not text:
        print(f"{CYAN}║{NC}{' ' * _BOX_W}{CYAN}║{NC}")
        return

    vis_w = _wcslen(text)
    if vis_w <= _BOX_W:
        pad = _BOX_W - vis_w
        print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")
        return

    # Не влезает — переносим по словам, сохраняя ведущий отступ.
    plain = _plain(text)
    leading_spaces = len(plain) - len(plain.lstrip(' '))
    indent = ' ' * leading_spaces

    pos, skipped_vis = 0, 0
    while pos < len(text) and skipped_vis < leading_spaces:
        m = _ANSI_RE.match(text, pos)
        if m:
            pos = m.end()
            continue
        if text[pos] == ' ':
            skipped_vis += 1
            pos += 1
        else:
            break
    text_stripped = text[pos:]
    prefix = ' ' * leading_spaces

    words = text_stripped.split(' ')
    lines_out = []
    current = prefix
    current_vis = leading_spaces

    for word in words:
        if not word:
            if current_vis + 1 <= _BOX_W:
                current += ' '
                current_vis += 1
            continue
        word_vis = _wcslen(word)
        sep_vis = 1 if current.strip() else 0
        if current_vis + sep_vis + word_vis <= _BOX_W:
            current = current + (' ' if current.strip() else '') + word
            current_vis = current_vis + sep_vis + word_vis
        else:
            if current.strip():
                lines_out.append(current)
            avail = max(_BOX_W - leading_spaces, 8)
            while _wcslen(word) > avail:
                piece, pw = '', 0
                for ch in word:
                    cw = _wcslen(ch)
                    if pw + cw > avail:
                        break
                    piece += ch
                    pw += cw
                lines_out.append(indent + piece)
                word = word[len(piece):]
            current = indent + word
            current_vis = leading_spaces + _wcslen(word)

    if current.strip() or not lines_out:
        lines_out.append(current)

    for line in lines_out:
        pad = max(0, _BOX_W - _wcslen(line))
        print(f"{CYAN}║{NC}{line}{' ' * pad}{CYAN}║{NC}")


def _box_link(link: str) -> None:
    """Длинная ссылка внутри рамки БЕЗ правого ║ (чтобы не резать URL посередине
    токена и не мешать копированию) — разрывает только по & (границы query-парам.
    Та же логика, что в box_renderer._box_link, без поддержки #label (тут не нужно)."""
    colour = YELLOW
    max_w = _BOX_W - 2
    tokens, buf = [], ""
    for ch in link:
        buf += ch
        if ch == "&":
            tokens.append(buf)
            buf = ""
    if buf:
        tokens.append(buf)

    chunk, chunk_w = "", 0
    for token in tokens:
        tok_w = _wcslen(token)
        if chunk_w + tok_w > max_w and chunk:
            print(f" {colour}{chunk}{NC}")
            chunk, chunk_w = token, tok_w
        else:
            chunk += token
            chunk_w += tok_w
        while chunk_w > max_w:
            cut, cut_w = 0, 0
            for ch in chunk:
                cw = _wcslen(ch)
                if cut_w + cw > max_w:
                    break
                cut_w += cw
                cut += 1
            print(f" {colour}{chunk[:cut]}{NC}")
            chunk = chunk[cut:]
            chunk_w = _wcslen(chunk)
    if chunk:
        print(f" {colour}{chunk}{NC}")


def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad = _BOX_W - _wcslen(title)
        lpad = pad // 2
        rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")


def _box_sep() -> None:
    print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")


def _box_bottom() -> None:
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")


def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")


def _box_kv(key: str, val: str, kw: int = 22) -> None:
    """Строка 'ключ: значение' с выровненным отступом — для статусов/сводок."""
    key_colored = f"{CYAN}{key}{NC}"
    key_pad = max(0, kw - _wcslen(key_colored))
    _box_row(f"  {key_colored}{' ' * key_pad}  {val}")


# Символика и цвет — как в mieru.py (родственный, тоже самостоятельный Mieru-модуль),
# а не [INFO]/[WARN] из box_renderer.py — это семейный стиль конкретно Mieru-модулей.
def _box_wrap_msg(prefix_colored: str, msg: str) -> None:
    """Строка с цветным префиксом-иконкой и переносом сообщения — продолжение
    выравнивается под текст (а не под иконку), как в box_renderer._box_wrap_msg.
    Понимает ручные '\\n' в msg (диагностика вида 'описание:\\n  детали') —
    каждый сегмент переносится по словам отдельно, перенос — тот же отступ."""
    prefix_plain_len = _wcslen(_plain(prefix_colored))
    max_msg = max(_BOX_W - prefix_plain_len, 10)
    indent = ' ' * prefix_plain_len

    all_lines = []
    for segment in msg.split('\n'):
        words = segment.split(' ')
        current = ''
        for word in words:
            if not word:
                continue
            candidate = (current + ' ' + word).lstrip() if current else word
            if _wcslen(candidate) <= max_msg:
                current = candidate
            else:
                if current:
                    all_lines.append(current)
                while _wcslen(word) > max_msg:
                    piece, pw = '', 0
                    for ch in word:
                        cw = _wcslen(ch)
                        if pw + cw > max_msg:
                            break
                        piece += ch
                        pw += cw
                    all_lines.append(piece)
                    word = word[len(piece):]
                current = word
        all_lines.append(current)  # пустой segment -> пустая строка (нужно для "...\n" в конце)

    if not all_lines:
        _box_row(prefix_colored)
        return
    _box_row(f"{prefix_colored}{all_lines[0]}")
    for line in all_lines[1:]:
        _box_row(f"{indent}{line}" if line else "")


def c_cyan(msg: str) -> None:
    _box_wrap_msg(f"  {CYAN}→{NC}  ", msg)


def c_green(msg: str) -> None:
    _box_wrap_msg(f"  {GREEN}✓{NC}  ", msg)


def c_red(msg: str) -> None:
    _box_wrap_msg(f"  {RED}✗{NC}  ", msg)


def c_yellow(msg: str) -> None:
    _box_wrap_msg(f"  {YELLOW}⚠{NC}  ", msg)


def box_header(title: str) -> None:
    """Открывает новую рамку с заголовком. У каждой открытой через box_header()
    секции есть парный _box_bottom() — ищи его в той же функции (через
    try/finally, чтобы рамка закрывалась и при раннем return, и при die())."""
    _box_top(title)


def die(msg: str, code: int = 1) -> None:
    c_red(msg)
    _log("ERROR", msg)
    sys.exit(code)


def confirm(prompt: str) -> bool:
    try:
        ans = input(f"  {BOLD}{prompt} [y/N]: {NC}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        _box_row()
        return False
    return ans in ("y", "yes", "д", "да")


# ───────────────────────── Логирование в общий лог проекта ─────────────────────────
INSTALL_LOG = "/var/log/vless-install.log"


def _log(level: str, msg: str) -> None:
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [hybrid_addon] [{level}] {msg}\n"
    try:
        with open(INSTALL_LOG, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass  # лог не критичен для работы скрипта


# ───────────────────────── Пути / состояние ─────────────────────────
STATE_DIR = Path("/var/lib/xray-installer")
STATE_FILE = STATE_DIR / "hybrid_mieru_state.json"

XRAY_CONFIG_CANDIDATES = [
    Path("/etc/xray/config.json"),          # путь, которым пользуется сам проект
    Path("/usr/local/etc/xray/config.json"),  # типовой дефолт community-сборок Xray
]

MITA_BIN = Path("/usr/bin/mita")
MITA_CONFIG_PATH = Path("/etc/mita/hybrid_server_config.json")

LOOPBACK_SOCKS_PORT = 1080


def ask_port(label: str, default: int, taken: set = None) -> int:
    taken = taken or set()
    while True:
        try:
            raw = input(f"{label} [{default}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            _box_row()
            return default
        if not raw:
            port = default
        elif raw.isdigit() and 1 <= int(raw) <= 65535:
            port = int(raw)
        else:
            c_yellow("Введи число от 1 до 65535 (или просто Enter для значения по умолчанию).")
            continue
        if port in taken:
            c_yellow(f"Порт {port} уже занят другим транспортом в этой установке, выбери другой.")
            continue
        return port


def check_port_listening(port: int, proto: str) -> tuple:
    """Возвращает (occupied: bool, detail: str) — занят ли порт прямо сейчас.
    Сначала пробуем ss (если есть), при любой проблеме с ним — честный bind-тест,
    который не зависит вообще ни от каких внешних утилит."""
    if shutil.which("ss"):
        flag = "-tlnp" if proto == "tcp" else "-ulnp"
        r = run(["ss", "-H", flag, "sport", "=", f":{port}"])
        if r.returncode == 0:
            out = r.stdout.strip()
            return (True, out.splitlines()[0]) if out else (False, "")
        # если синтаксис фильтра не подошёл в этой версии ss — едем на bind-тест ниже

    fam = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    s = socket.socket(socket.AF_INET, fam)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        return False, ""
    except OSError:
        return True, "(детали недоступны: ss не сработал/не установлен, но порт точно занят — bind не прошёл)"
    finally:
        s.close()


def run(cmd, **kwargs):
    """Обёртка над subprocess с единым поведением."""
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def require_root() -> None:
    if os.geteuid() != 0:
        # Обычный print, не через c_red/рамку — этот код может сработать
        # до открытия любой рамки (как и в mieru.py для того же случая).
        print(f"{RED}Запусти скрипт от root (sudo python3 hybrid_addon.py){NC}")
        _log("ERROR", "Запусти скрипт от root (sudo python3 hybrid_addon.py)")
        sys.exit(1)


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def load_state() -> dict:
    if not STATE_FILE.exists():
        die(f"Файл состояния {STATE_FILE} не найден — похоже, аддон ещё не устанавливался.")
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


# ───────────────────────── Шаг 1: поиск и анализ Xray config.json ─────────────────────────
def find_xray_config() -> Path:
    for p in XRAY_CONFIG_CANDIDATES:
        if p.exists():
            return p
    die(
        "Не нашёл config.json Xray ни по одному из известных путей: "
        + ", ".join(str(p) for p in XRAY_CONFIG_CANDIDATES)
        + ". Укажи путь вручную через --xray-config."
    )


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        die(f"Не удалось прочитать/распарсить {path}: {e}")


def describe_inbound(ib: dict) -> str:
    tag = ib.get("tag", "<без тега>")
    port = ib.get("port", "?")
    listen = ib.get("listen", "0.0.0.0")
    proto = ib.get("protocol", "?")
    ss = ib.get("streamSettings", {}) or {}
    security = ss.get("security", "none")
    network = ss.get("network", "tcp")
    return (f"tag={tag!r}  protocol={proto}  listen={listen}  port={port}  "
            f"network={network}  security={security}")


def find_vless_inbounds(config: dict) -> list:
    return [ib for ib in config.get("inbounds", []) if ib.get("protocol") == "vless"]


def pick_target_inbound(config: dict, port: int, inbound_tag: str = None) -> dict:
    """Находит ИМЕННО ОДНО подходящее vless-входящее соединение на заданном порту.
    Если совпадений 0 или больше 1 — останавливаемся, не угадываем
    (если не передан inbound_tag — тогда фильтруем явно по тегу)."""
    vless_inbounds = find_vless_inbounds(config)

    if not vless_inbounds:
        die("В config.json не найдено ни одного inbound с protocol == 'vless'. "
            "Возможно, аддон уже применён ранее, или путь к конфигу неверный.")

    c_cyan(f"Найдено vless-инбаундов всего: {len(vless_inbounds)}")
    for ib in vless_inbounds:
        _box_row(f"    {DIM}{describe_inbound(ib)}{NC}")

    if inbound_tag:
        matches = [ib for ib in vless_inbounds if ib.get("tag") == inbound_tag]
        if len(matches) != 1:
            die(f"По тегу {inbound_tag!r} найдено {len(matches)} совпадений (нужно ровно 1). "
                f"Проверь список выше и --inbound-tag.")
        return matches[0]

    matches = [ib for ib in vless_inbounds if int(ib.get("port", -1)) == port]

    if len(matches) == 0:
        die(
            f"Ни один vless-инбаунд не слушает порт {port} напрямую.\n"
            f"  Это может означать xHTTP-режим за Nginx (Xray слушает внутренний порт,\n"
            f"  а Nginx терминирует TLS снаружи на {port}). В этом случае внешний\n"
            f"  TCP/{port} останется у Nginx, конфликта с Mieru (TCP/{port}) НЕ будет,\n"
            f"  но тебе нужно вручную указать внутренний порт Xray через --port,\n"
            f"  чтобы скрипт знал, какой именно inbound переключать на SOCKS-петлю,\n"
            f"  либо указать инбаунд явно через --inbound-tag <tag> (см. список выше)."
        )
    if len(matches) > 1:
        die(
            f"На порту {port} нашлось {len(matches)} vless-инбаундов — однозначно "
            f"выбрать не могу. Уточни через --inbound-tag <tag> (см. список выше)."
        )

    target = matches[0]
    sec = (target.get("streamSettings", {}) or {}).get("security", "none")
    if sec == "reality":
        c_green(f"Режим обнаружен: REALITY напрямую на {port}/TCP — ожидаемый сценарий.")
    elif sec == "tls":
        c_yellow(
            f"Режим обнаружен: streamSettings.security = 'tls'. Похоже на TLS-режим "
            f"(возможно, xHTTP за Nginx или просто TLS напрямую). Проверь глазами, "
            f"что это действительно тот инбаунд, который нужно сделать внутренним."
        )
    else:
        c_yellow(f"streamSettings.security = {sec!r} — нестандартно, проверь конфиг глазами.")

    return target


# ───────────────────────── Шаг 2: бэкап и конвертация inbound ─────────────────────────
def _capture_owner_mode(path: Path) -> dict:
    """Снимает владельца/группу/права ДО любых модификаций — это "эталон",
    к которому нужно возвращаться после каждой записи в config.json."""
    st = path.stat()
    return {"uid": st.st_uid, "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode)}


def _restore_owner_mode(path: Path, owner_mode: dict) -> None:
    """shutil.copy2()/tempfile.mkstemp()+move НЕ восстанавливают владельца и группу —
    copy2 копирует только биты прав (через copystat), а mkstemp создаёт файл от имени
    текущего процесса (root:root). Без этого вызова Xray (User=xray Group=xray) не
    сможет прочитать config.json: пермишены 0640 без правильной группы = permission denied."""
    try:
        os.chown(str(path), owner_mode["uid"], owner_mode["gid"])
        os.chmod(str(path), owner_mode["mode"])
    except OSError as e:
        c_yellow(f"Не удалось восстановить владельца/права на {path}: {e}\n"
                 f"  Проверь руками: chown {owner_mode['uid']}:{owner_mode['gid']} '{path}' && "
                 f"chmod {oct(owner_mode['mode'])} '{path}'")


def backup_config(xray_config_path: Path) -> tuple[Path, dict]:
    owner_mode = _capture_owner_mode(xray_config_path)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = xray_config_path.with_name(f"{xray_config_path.name}.bak-{ts}")
    shutil.copy2(xray_config_path, backup_path)
    _restore_owner_mode(backup_path, owner_mode)
    # держим также "последний" бэкап под предсказуемым именем — как договорено в проекте
    latest = xray_config_path.with_name(f"{xray_config_path.name}.bak")
    shutil.copy2(xray_config_path, latest)
    _restore_owner_mode(latest, owner_mode)
    c_green(f"Бэкап сохранён: {backup_path}")
    return backup_path, owner_mode


def convert_inbound_to_socks_loopback(target: dict) -> dict:
    """Мутирует inbound in-place, возвращает ГЛУБОКУЮ копию оригинала для отката."""
    original = json.loads(json.dumps(target))  # глубокая копия

    sniffing = target.get("sniffing")  # ОБЯЗАТЕЛЬНО сохраняем — на нём может
                                        # держаться роутинг по доменам ниже по цепочке

    target.clear()
    target["tag"] = original.get("tag", "vless-in")  # тег НЕ меняем — на нём
                                                       # держатся routing.rules
    target["listen"] = "127.0.0.1"
    target["port"] = LOOPBACK_SOCKS_PORT
    target["protocol"] = "socks"
    target["settings"] = {
        "auth": "noauth",   # безопасно: слушаем только loopback, снаружи недоступно
        "udp": True,
    }
    if sniffing is not None:
        target["sniffing"] = sniffing

    return original


def validate_xray_config(path: Path) -> bool:
    xray_bin = shutil.which("xray") or "/usr/local/bin/xray"
    if not Path(xray_bin).exists():
        c_yellow(f"Не нашёл бинарник xray ({xray_bin}) — пропускаю preflight-валидацию.")
        return True
    r = run([xray_bin, "run", "-test", "-config", str(path)])
    if r.returncode != 0:
        c_red("Xray не принял новый конфиг (preflight-тест провален):")
        for line in f"{r.stdout}\n{r.stderr}".splitlines():
            if line.strip():
                _box_row(f"    {DIM}{line}{NC}")
        return False
    c_green("Preflight-валидация конфига Xray пройдена (xray run -test).")
    return True


def restart_service(name: str) -> bool:
    r = run(["systemctl", "restart", name])
    if r.returncode != 0:
        c_red(f"systemctl restart {name} завершился с ошибкой: {r.stderr.strip()}")
        return False
    time.sleep(1.5)
    r = run(["systemctl", "is-active", name])
    active = r.stdout.strip() == "active"
    if active:
        c_green(f"Служба {name} активна.")
    else:
        c_red(f"Служба {name} НЕ активна после restart (статус: {r.stdout.strip()!r}).")
    return active


def apply_xray_change(xray_config_path: Path, config: dict, backup_path: Path,
                       owner_mode: dict) -> bool:
    tmp_fd, tmp_name = tempfile.mkstemp(prefix="xray_config_", suffix=".json",
                                         dir=str(xray_config_path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    except Exception as e:
        die(f"Не удалось записать временный конфиг: {e}")

    if not validate_xray_config(tmp_path):
        tmp_path.unlink(missing_ok=True)
        c_red("Изменения НЕ применены — оригинальный config.json не тронут.")
        return False

    shutil.move(str(tmp_path), str(xray_config_path))
    # mkstemp создаёт файл от имени текущего процесса (root:root, 0600) — после move()
    # (это os.rename, целиком подменяющий inode) config.json остаётся root:root, и
    # Xray (User=xray Group=xray) не сможет его открыть. Возвращаем владельца/права.
    _restore_owner_mode(xray_config_path, owner_mode)
    c_cyan("Перезапускаю Xray с новым inbound...")
    if restart_service("xray"):
        return True

    # ── автоматический rollback, если Xray не поднялся ──
    c_yellow("Откатываю config.json из бэкапа и перезапускаю Xray...")
    shutil.copy2(backup_path, xray_config_path)
    _restore_owner_mode(xray_config_path, owner_mode)
    restart_service("xray")
    c_red("Изменения отменены автоматически — прежний VLESS-инбаунд восстановлен.")
    return False


# ───────────────────────── Шаг 3: установка Mieru (mita) через .deb ─────────────────────────
def detect_arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    die(f"Неподдерживаемая архитектура: {m} (поддерживаются amd64/arm64)")


def github_api_get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "vless-ultimate-hybrid-addon"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        die(f"Не удалось обратиться к GitHub API ({url}): {e}")


def download_file(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "vless-ultimate-hybrid-addon"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as out:
            shutil.copyfileobj(resp, out)
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        die(f"Не удалось скачать {url}: {e}")


def install_mita() -> None:
    if MITA_BIN.exists():
        c_green(f"Mieru (mita) уже установлен: {MITA_BIN} — пропускаю установку.")
        return

    c_cyan("Mieru не найден, ставлю с нуля...")
    arch = detect_arch()
    release = github_api_get("https://api.github.com/repos/enfein/mieru/releases/latest")
    tag = release.get("tag_name", "?")
    assets = release.get("assets", [])

    deb_asset = next(
        (a for a in assets if a["name"].endswith(f"_{arch}.deb") and a["name"].startswith("mita_")),
        None,
    )
    if deb_asset is None:
        die(f"Не нашёл .deb-пакет mita для архитектуры {arch} в релизе {tag}. "
            f"Доступные ассеты: {[a['name'] for a in assets]}")

    c_cyan(f"Скачиваю {deb_asset['name']} (релиз {tag})...")
    with tempfile.TemporaryDirectory() as tmpdir:
        deb_path = Path(tmpdir) / deb_asset["name"]
        download_file(deb_asset["browser_download_url"], deb_path)

        r = run(["dpkg", "-i", str(deb_path)])
        if r.returncode != 0:
            c_yellow("dpkg -i вернул ошибку, пробую дотянуть зависимости через apt-get -f...")
            run(["apt-get", "install", "-f", "-y"])
            r2 = run(["dpkg", "-i", str(deb_path)])
            if r2.returncode != 0:
                die(f"Установка mita не удалась:\n{r.stderr}\n{r2.stderr}")

    if not MITA_BIN.exists():
        die("dpkg отработал без ошибок, но /usr/bin/mita не появился — что-то нестандартное.")

    c_green(f"Mieru (mita) {tag} установлен.")
    _log("SUCCESS", f"mita {tag} установлен для {arch}")


# ───────────────────────── Шаг 4: конфиг Mieru (server.json) ─────────────────────────
def gen_credentials() -> tuple:
    login = "u_" + secrets.token_hex(4)
    password = secrets.token_urlsafe(18)
    return login, password


def build_mita_config(transport: str, tcp_port: int, udp_port: int,
                       traffic_pattern: dict = None) -> tuple:
    """Возвращает (config_dict, creds_dict) — creds для финального вывода пользователю.

    traffic_pattern — опциональный dict для серверного поля trafficPattern
    (настоящий JSON по docs/traffic-pattern.md, см. _traffic_pattern_*() и
    _ask_traffic_pattern_mode()). None (по умолчанию) — поведение не меняется,
    старые вызовы без этого параметра работают как раньше."""
    port_bindings = []
    users = []
    creds = {}

    if transport in ("tcp", "both"):
        login, pwd = gen_credentials()
        port_bindings.append({"port": tcp_port, "protocol": "TCP"})
        users.append({"name": login, "password": pwd})
        creds["tcp"] = {"port": tcp_port, "login": login, "password": pwd}

    if transport in ("udp", "both"):
        login, pwd = gen_credentials()
        port_bindings.append({"port": udp_port, "protocol": "UDP"})
        users.append({"name": login, "password": pwd})
        creds["udp"] = {"port": udp_port, "login": login, "password": pwd}

    config = {
        "portBindings": port_bindings,
        "users": users,
        "loggingLevel": "INFO",
        "egress": {
            "proxies": [
                {
                    "name": "xray-local",
                    "protocol": "SOCKS5_PROXY_PROTOCOL",
                    "host": "127.0.0.1",
                    "port": LOOPBACK_SOCKS_PORT,
                }
            ],
            "rules": [
                {
                    "ipRanges": ["*"],
                    "domainNames": ["*"],
                    "action": "PROXY",
                    "proxyNames": ["xray-local"],
                }
            ],
        },
    }
    if traffic_pattern:
        config["trafficPattern"] = traffic_pattern
    return config, creds


# ───────────────────────── Traffic Obfuscation (trafficPattern) ─────────────────────────
# Формат ниже — НАСТОЯЩИЙ JSON по docs/traffic-pattern.md (enfein/mieru), для серверного
# config.json mita. ВАЖНО: это НЕ то же самое, что значение traffic-pattern= в клиентской
# mierus://-ссылке или в sing-box JSON для Karing — там нужен base64 PROTOBUF-блок,
# который mita/mieru сами умеют выгружать командой `export traffic-pattern`, но руками
# из этого dict его не получить. Поэтому для клиентской выдачи используется
# _export_traffic_pattern_blob() — см. вызов после успешного apply_mita_config().
#
# multiplexing сюда НЕ входит — это отдельное, не вложенное поле, и оно уже корректно
# выставлено отдельно в modules/mieru.py (_gen_singbox_outbound/_gen_client_share_link).
# В серверном trafficPattern multiplexing не существует вообще.

def _traffic_pattern_basic() -> dict:
    return {
        "nonce": {"type": "NONCE_TYPE_PRINTABLE"},
    }


def _traffic_pattern_aggressive() -> dict:
    return {
        "nonce": {"type": "NONCE_TYPE_PRINTABLE"},
        # enable обязателен — по умолчанию False, без него maxSleepMs ни на что не влияет
        "tcpFragment": {"enable": True, "maxSleepMs": 5},
    }


def _read_multiline_json() -> str:
    """Читает строки, пока не встретит пустую (после хотя бы одной непустой) —
    так можно вставить и однострочный, и красиво отформатированный JSON.
    Возвращает None при EOF без единой накопленной строки (иначе при разорванном
    stdin/Ctrl+D вызывающий код мог бы уйти в бесконечный повторный запрос)."""
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            return "\n".join(lines) if lines else None
        if line.strip() == "":
            if lines:
                break
            continue  # пустые строки до начала ввода пропускаем
        lines.append(line)
    return "\n".join(lines)


def _traffic_pattern_custom() -> dict:
    while True:
        _box_row()
        c_cyan("Paste trafficPattern JSON (пустая строка — завершить ввод):")
        raw = _read_multiline_json()
        if raw is None:
            c_yellow("Ввод прервался (EOF) без JSON — беру Basic по умолчанию.")
            return _traffic_pattern_basic()
        if not raw.strip():
            c_yellow("Пустой ввод — вставь JSON-объект ещё раз.")
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            c_red(f"Невалидный JSON: {e}. Вставь ещё раз.")
            continue
        if not isinstance(parsed, dict):
            c_red("Корнем должен быть JSON-объект {...}, не список/строка/число. Вставь ещё раз.")
            continue
        c_green("JSON принят.")
        return parsed


def _ask_traffic_pattern_mode(cli_mode: str = None) -> dict:
    """Возвращает dict для trafficPattern (см. _traffic_pattern_*()) либо None — отключено.

    cli_mode — значение --traffic-pattern из argparse (только main()/CLI; для пути
    через меню установщика всегда None, там этого флага нет, только интерактив)."""
    if cli_mode == "aggressive":
        c_cyan("Traffic Obfuscation: Aggressive (флаг --traffic-pattern aggressive).")
        return _traffic_pattern_aggressive()
    if cli_mode == "basic":
        c_cyan("Traffic Obfuscation: Basic (флаг --traffic-pattern basic).")
        return _traffic_pattern_basic()
    if cli_mode == "disabled":
        c_cyan("Traffic Obfuscation: Disabled (флаг --traffic-pattern disabled).")
        return None

    _box_row()
    c_cyan("Traffic Obfuscation:")
    _box_item("1", f"Basic {DIM}(Recommended) — nonce: NONCE_TYPE_PRINTABLE, без tcpFragment{NC}")
    _box_item("2", f"Aggressive {DIM}(для строгих DPI/ТСПУ) — + tcpFragment, maxSleepMs=5{NC}")
    _box_item("3", "Custom — вставить свой JSON trafficPattern")
    _box_item("0", "Disabled (без обфускации, как было раньше)")
    _box_row()
    choice = input("  Выбор [1]: ").strip()

    if choice in ("", "1"):
        return _traffic_pattern_basic()
    if choice == "2":
        return _traffic_pattern_aggressive()
    if choice == "3":
        return _traffic_pattern_custom()
    if choice == "0":
        return None

    c_yellow(f"Неизвестный выбор {choice!r} — беру Basic по умолчанию.")
    return _traffic_pattern_basic()


def _print_traffic_pattern_snippet(traffic_pattern: dict) -> None:
    """Финальный вывод — клиентский JSON-сниппет trafficPattern (для документации/
    ручного применения через `mieru apply config`). НЕ путать с base64-блоком
    для ссылок/sing-box — тот выводится отдельно, см. _export_traffic_pattern_blob()."""
    if not traffic_pattern:
        return
    box_header("TRAFFIC OBFUSCATION — JSON-СНИППЕТ")
    try:
        snippet = {"trafficPattern": traffic_pattern}
        for line in json.dumps(snippet, indent=2, ensure_ascii=False).splitlines():
            _box_row(f"  {DIM}{line}{NC}")
    finally:
        _box_bottom()


def _export_traffic_pattern_blob() -> str:
    """Вызывает `mita export traffic-pattern` на УЖЕ применённом конфиге и
    возвращает base64-блок (значение для traffic-pattern= в ссылке и в
    sing-box JSON). Возвращает None при любой проблеме — это не критичная
    ошибка, остальная установка/выдача продолжается без этого поля."""
    mita_bin = shutil.which("mita") or str(MITA_BIN)
    if not Path(mita_bin).exists():
        c_yellow("mita не найден — пропускаю экспорт traffic-pattern для клиентских ссылок.")
        return None
    r = run([mita_bin, "export", "traffic-pattern"])
    if r.returncode != 0:
        c_yellow(f"`mita export traffic-pattern` завершился с ошибкой: "
                 f"{r.stderr.strip() or r.stdout.strip()}\n"
                 f"  Ссылки/JSON будут без поля traffic-pattern.")
        return None
    blob = r.stdout.strip()
    if not blob:
        c_yellow("`mita export traffic-pattern` вернул пустой вывод — "
                 "пропускаю поле в ссылках.")
        return None
    return blob


def apply_mita_config(config: dict) -> bool:
    MITA_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    MITA_CONFIG_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")

    # На случай свежей установки служба может быть ещё не запущена постинстом
    run(["systemctl", "start", "mita"])
    time.sleep(1)

    r = run(["mita", "apply", "config", str(MITA_CONFIG_PATH)])
    if r.returncode != 0:
        c_red(f"mita apply config упал: {r.stderr.strip() or r.stdout.strip()}")
        return False
    c_green("Конфиг Mieru применён (mita apply config).")

    c_cyan("Перезапускаю Mieru с новыми портами/пользователями...")
    return restart_service("mita")


# ───────────────────────── Шаг 5: файрвол ─────────────────────────
def detect_firewall() -> str:
    if shutil.which("ufw"):
        r = run(["ufw", "status"])
        if "Status: active" in r.stdout:
            return "ufw"
    if shutil.which("firewall-cmd"):
        r = run(["firewall-cmd", "--state"])
        if r.stdout.strip() == "running":
            return "firewalld"
    if shutil.which("iptables"):
        return "iptables"
    return "none"


def open_port(fw: str, port: int, proto: str) -> str:
    """Возвращает строку-команду отката (или '' если открывать не пришлось)."""
    if fw == "ufw":
        r = run(["ufw", "status"])
        rule = f"{port}/{proto}"
        if rule in r.stdout:
            c_green(f"ufw: {rule} уже открыт.")
            return ""
        run(["ufw", "allow", rule])
        c_green(f"ufw: открыт {rule}.")
        return f"ufw delete allow {rule}"

    if fw == "firewalld":
        check = run(["firewall-cmd", "--zone=public", "--query-port", f"{port}/{proto}"])
        if check.returncode == 0:
            c_green(f"firewalld: {port}/{proto} уже открыт.")
            return ""
        run(["firewall-cmd", "--zone=public", f"--add-port={port}/{proto}", "--permanent"])
        run(["firewall-cmd", "--reload"])
        c_green(f"firewalld: открыт {port}/{proto}.")
        return f"firewall-cmd --zone=public --remove-port={port}/{proto} --permanent && firewall-cmd --reload"

    if fw == "iptables":
        check = run(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])
        if check.returncode == 0:
            c_green(f"iptables: правило для {port}/{proto} уже есть.")
            return ""
        run(["iptables", "-I", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])
        # сохранение правил — best effort, разные дистрибутивы по-разному
        if shutil.which("netfilter-persistent"):
            run(["netfilter-persistent", "save"])
        elif shutil.which("iptables-save") and Path("/etc/iptables/rules.v4").parent.exists():
            r = run(["iptables-save"])
            try:
                Path("/etc/iptables/rules.v4").write_text(r.stdout)
            except OSError:
                c_yellow("Не удалось сохранить iptables-правила в файл — переживут только до reboot.")
        c_green(f"iptables: открыт {port}/{proto}.")
        return f"iptables -D INPUT -p {proto} --dport {port} -j ACCEPT"

    c_yellow(f"Файрвол не определён — открой {port}/{proto} вручную, если трафик не идёт.")
    return ""


# ───────────────────────── Шаг 6: самопроверка SOCKS5 (без сторонних либ) ─────────────────────────
def selftest_socks5(host="127.0.0.1", port=LOOPBACK_SOCKS_PORT, timeout=4) -> bool:
    """Минимальный SOCKS5-хендшейк + CONNECT, чтобы убедиться, что Xray-инбаунд
    на самом деле принимает соединения. Не проверяет путь до интернета целиком —
    это просто smoke-test локального моста."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(b"\x05\x01\x00")  # версия 5, 1 метод, no-auth
            resp = s.recv(2)
            if resp != b"\x05\x00":
                return False
            # CONNECT 1.1.1.1:80
            req = b"\x05\x01\x00\x01" + socket.inet_aton("1.1.1.1") + (80).to_bytes(2, "big")
            s.sendall(req)
            resp = s.recv(10)
            return len(resp) >= 2 and resp[1] == 0x00
    except OSError:
        return False


# ───────────────────────── Откат ─────────────────────────
def do_rollback() -> None:
    state = load_state()
    box_header("ОТКАТ HYBRID MIERU ADDON")
    try:
        xray_config_path = Path(state["xray_config_path"])
        backup_path = Path(state["backup_path"])
        owner_mode = state.get("config_owner_mode")

        if backup_path.exists():
            shutil.copy2(backup_path, xray_config_path)
            if owner_mode:
                _restore_owner_mode(xray_config_path, owner_mode)
            else:
                c_yellow(f"В {STATE_FILE} нет сохранённых владельца/прав config.json "
                         f"(старый state-файл?) — проверь руками: "
                         f"ls -la '{xray_config_path}' и сравни с другими файлами в той же папке.")
            c_green(f"config.json восстановлен из {backup_path}")
            restart_service("xray")
        else:
            c_red(f"Бэкап {backup_path} не найден — config.json НЕ восстановлен, проверь руками.")

        run(["systemctl", "stop", "mita"])
        run(["systemctl", "disable", "mita"])
        c_green("Mieru (mita) остановлен и снят с автозагрузки.")

        for rollback_cmd in state.get("firewall_rollback", []):
            if rollback_cmd:
                run(rollback_cmd.split())
        c_green("Правила файрвола, добавленные аддоном, удалены (если были).")

        STATE_FILE.unlink(missing_ok=True)
        c_green("Готово. Можешь проверить, что прежний VLESS-доступ снова работает.")
        _log("SUCCESS", "rollback hybrid_addon выполнен")
    finally:
        # Рамка закрывается всегда — и при успехе, и при die()/sys.exit() на
        # любом шаге внутри блока выше (finally срабатывает и для SystemExit).
        _box_bottom()


# ───────────────────────── Финальный вывод ─────────────────────────
def get_public_ip() -> str:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                ip = resp.read().decode().strip()
                if ip:
                    return ip
        except (urllib.error.URLError, urllib.error.HTTPError):
            continue
    return "<не удалось определить, посмотри сам: curl ifconfig.me>"


def print_summary(creds: dict) -> None:
    ip = get_public_ip()
    box_header("MIERU HYBRID ADDON — ГОТОВО")
    _box_kv("Сервер (IP):", ip)
    if "tcp" in creds:
        _box_row()
        _box_row(f"  {BOLD}TCP-вариант{NC}")
        _box_kv("Порт:", f"{creds['tcp']['port']}/tcp", kw=14)
        _box_kv("Логин:", creds['tcp']['login'], kw=14)
        _box_kv("Пароль:", creds['tcp']['password'], kw=14)
    if "udp" in creds:
        _box_row()
        _box_row(f"  {BOLD}UDP-вариант{NC}")
        _box_kv("Порт:", f"{creds['udp']['port']}/udp", kw=14)
        _box_kv("Логин:", creds['udp']['login'], kw=14)
        _box_kv("Пароль:", creds['udp']['password'], kw=14)
    _box_row()
    _box_row(f"  {DIM}Протокол клиента в Mieru: mieru / profile с этими данными.{NC}")
    _box_row(f"  {DIM}Откат в любой момент: sudo python3 hybrid_addon.py --rollback{NC}")
    _box_bottom()


# ───────────────────────── main ─────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="Mieru hybrid addon для VLESS-Ultimate-Installer")
    parser.add_argument("--port", type=int, default=443,
                         help="Текущий внешний порт VLESS-инбаунда, который нужно "
                              "освободить (по умолчанию 443)")
    parser.add_argument("--transport", choices=["tcp", "udp", "both"], default="both",
                         help="Какой транспорт Mieru разворачивать")
    parser.add_argument("--mieru-tcp-port", type=int, default=None,
                         help="TCP-порт Mieru снаружи (по умолчанию = --port, "
                              "т.е. займёт освободившийся от Xray)")
    parser.add_argument("--mieru-udp-port", type=int, default=None,
                         help="UDP-порт Mieru снаружи (по умолчанию = --port + 1)")
    parser.add_argument("--xray-config", type=str, default=None,
                         help="Явный путь к config.json Xray")
    parser.add_argument("--inbound-tag", type=str, default=None,
                         help="Явно указать тег инбаунда, если по порту найдено 0 или 2+ совпадений")
    parser.add_argument("--dry-run", action="store_true",
                         help="Только показать, что найдено, без изменений")
    parser.add_argument("--yes", "-y", action="store_true",
                         help="Не спрашивать подтверждение и не предлагать выбор портов интерактивно")
    parser.add_argument("--rollback", action="store_true",
                         help="Откатить ранее применённые изменения")
    parser.add_argument("--traffic-pattern", choices=["basic", "aggressive", "disabled"],
                         default=None,
                         help="Traffic Obfuscation для Mieru без интерактивного вопроса: "
                              "basic (по умолчанию при --yes), aggressive (для строгого DPI/ТСПУ), "
                              "disabled (без обфускации, как было раньше). Без флага — "
                              "интерактивный вопрос (Enter = basic). Custom-режим (вставка "
                              "своего JSON) доступен только интерактивно, без флага.")
    args = parser.parse_args()

    require_root()

    if args.rollback:
        do_rollback()
        return

    box_header("MIERU HYBRID ADDON — УСТАНОВКА")

    creds = None
    traffic_pattern = None
    try:
        xray_config_path = Path(args.xray_config) if args.xray_config else find_xray_config()
        c_cyan(f"Использую конфиг Xray: {xray_config_path}")
        config = load_json(xray_config_path)

        target = pick_target_inbound(config, args.port, args.inbound_tag)

        # ── выбор портов Mieru: явные флаги > интерактивный выбор > дефолты ──
        want_tcp = args.transport in ("tcp", "both")
        want_udp = args.transport in ("udp", "both")

        tcp_port = args.mieru_tcp_port if args.mieru_tcp_port is not None else args.port
        udp_port = args.mieru_udp_port if args.mieru_udp_port is not None else args.port + 1

        if not args.yes and not args.dry_run:
            _box_row()
            c_cyan("Выбор портов для Mieru (Enter — оставить значение по умолчанию):")
            taken = set()
            if want_tcp:
                if args.mieru_tcp_port is None:
                    tcp_port = ask_port("  TCP-порт Mieru", tcp_port, taken=taken)
                taken.add(tcp_port)
            if want_udp:
                if args.mieru_udp_port is None:
                    udp_port = ask_port("  UDP-порт Mieru", udp_port, taken=taken)
                taken.add(udp_port)

        if want_tcp and want_udp and tcp_port == udp_port:
            die(f"TCP- и UDP-порт совпадают ({tcp_port}) — это разные транспорты, "
                f"но порту всё равно нужно быть разным, чтобы не путаться. Укажи "
                f"--mieru-tcp-port / --mieru-udp-port явно.")

        # ── ранняя проверка UDP-порта: он не зависит от текущего Xray, можно
        #    проверить прямо сейчас, ДО каких-либо изменений ──
        if want_udp:
            occupied, detail = check_port_listening(udp_port, "udp")
            if occupied:
                die(f"UDP-порт {udp_port} уже занят:\n  {detail}\n"
                    f"  Выбери другой через --mieru-udp-port (ничего ещё не менялось).")

        c_cyan(f"Итоговые порты Mieru: "
               f"{f'TCP={tcp_port} ' if want_tcp else ''}{f'UDP={udp_port}' if want_udp else ''}")

        if args.dry_run:
            c_cyan("Dry-run: изменений не делаю, это была только диагностика.")
            return

        _box_row()
        c_yellow("Будет изменено: указанный inbound станет SOCKS-петлёй на 127.0.0.1:"
                 f"{LOOPBACK_SOCKS_PORT}, протокол сменится с vless на socks.")
        c_yellow("Внешний доступ по старому VLESS-линку на этом порту ПЕРЕСТАНЕТ работать "
                 "— вместо него будет доступ через Mieru.")
        if not args.yes and not confirm("Продолжить?"):
            c_cyan("Отменено пользователем, ничего не тронуто.")
            return

        backup_path, owner_mode = backup_config(xray_config_path)
        original_inbound = convert_inbound_to_socks_loopback(target)

        if not apply_xray_change(xray_config_path, config, backup_path, owner_mode):
            die("Установка прервана на шаге Xray — Mieru НЕ устанавливался, прод не тронут "
                "(или уже автоматически восстановлен).")

        # ── теперь, когда Xray уже освободил порт, проверяем TCP ещё раз:
        #    если порт всё равно занят — значит, его перехватил кто-то ещё, и
        #    нужно откатить Xray, чтобы не остаться вообще без входа ──
        if want_tcp:
            occupied, detail = check_port_listening(tcp_port, "tcp")
            if occupied:
                c_red(f"TCP-порт {tcp_port} занят чем-то ещё после освобождения Xray:\n  {detail}")
                c_yellow("Откатываю Xray обратно, чтобы не остаться без входа вообще...")
                shutil.copy2(backup_path, xray_config_path)
                _restore_owner_mode(xray_config_path, owner_mode)
                restart_service("xray")
                die("Установка прервана — старый VLESS-инбаунд восстановлен. "
                    "Разберись, что заняло порт, и попробуй снова.")

        install_mita()

        # --yes без явного --traffic-pattern означает «не спрашивать ничего
        # интерактивно» — тогда тихо берём Basic (тот же режим, что и Enter).
        effective_tp_mode = "basic" if (args.yes and args.traffic_pattern is None) else args.traffic_pattern
        traffic_pattern = _ask_traffic_pattern_mode(effective_tp_mode)

        mita_config, creds = build_mita_config(args.transport, tcp_port, udp_port,
                                                traffic_pattern=traffic_pattern)

        if not apply_mita_config(mita_config):
            c_red("Mieru не поднялся с новым конфигом. Откатываю Xray, чтобы не остаться без входа вообще.")
            shutil.copy2(backup_path, xray_config_path)
            _restore_owner_mode(xray_config_path, owner_mode)
            restart_service("xray")
            die("Установка прервана — старый VLESS-инбаунд восстановлен, Mieru не используется.")

        fw = detect_firewall()
        c_cyan(f"Файрвол: {fw}")
        firewall_rollback = []
        if want_tcp:
            firewall_rollback.append(open_port(fw, tcp_port, "tcp"))
        if want_udp:
            firewall_rollback.append(open_port(fw, udp_port, "udp"))

        c_cyan("Проверяю локальный SOCKS-мост (Xray)...")
        if selftest_socks5():
            c_green("SOCKS5-мост на 127.0.0.1:1080 отвечает корректно.")
        else:
            c_yellow("SOCKS5-мост не ответил как ожидалось — не критично для установки, "
                     "но стоит проверить логи Xray, прежде чем давать ссылку клиентам.")

        save_state({
            "xray_config_path": str(xray_config_path),
            "backup_path": str(backup_path),
            "config_owner_mode": owner_mode,
            "inbound_tag": original_inbound.get("tag"),
            "firewall_rollback": firewall_rollback,
            "transport": args.transport,
            "tcp_port": tcp_port if want_tcp else None,
            "udp_port": udp_port if want_udp else None,
            "created": datetime.now().isoformat(),
        })
    finally:
        # Рамка "УСТАНОВКА" закрывается всегда — при early return (dry-run,
        # отмена, конфликт портов), при die()/sys.exit() на любом шаге, и
        # при обычном успешном проходе — перед тем как print_summary()
        # откроет СВОЮ отдельную рамку "ГОТОВО".
        _box_bottom()

    if creds is None:
        return  # dry-run / отмена пользователем — до print_summary не дошли

    print_summary(creds)
    _print_traffic_pattern_snippet(traffic_pattern)
    _log("SUCCESS", "hybrid_addon установлен успешно")


if __name__ == "__main__":
    main()


# ───────────────────────── Точка входа из меню установщика (раздел 1) ─────────────────────────
# main() выше НЕ ТРОГАЕМ — это самостоятельный CLI (sudo python3 hybrid_addon.py),
# им можно продолжать пользоваться напрямую как раньше.
#
# Ниже — отдельная обёртка для интерактивного подменю _core.py. Повторяет тот же
# порядок шагов, что и install-ветка main(), и дёргает те же готовые функции выше
# (find_xray_config, pick_target_inbound, install_mita, build_mita_config и т.д.),
# но без argparse и с возвратом в меню (а не sys.exit) при ошибке на любом шаге —
# многие хелперы выше вызывают die(), а die() делает sys.exit(), что в контексте
# CLI нормально, а в контексте интерактивного меню убило бы весь установщик.

def _menu_status() -> dict:
    """Текущее состояние аддона для отображения в меню. Не падает, если файла нет/он битый."""
    if not STATE_FILE.exists():
        return {"installed": False}
    try:
        st = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        st["installed"] = True
        return st
    except (OSError, json.JSONDecodeError):
        return {"installed": False, "corrupt": True}


def _menu_install(default_port: int = 443) -> None:
    """Интерактивная установка для меню — те же шаги, что в main(), но без argparse
    и без падения всего процесса при die() на промежуточных шагах."""
    box_header("MIERU HYBRID ADDON — УСТАНОВКА")

    creds = None
    traffic_pattern = None
    try:
        raw = input(f"Текущий внешний порт VLESS-инбаунда, который нужно освободить [{default_port}]: ").strip()
        port = int(raw) if raw.isdigit() and 1 <= int(raw) <= 65535 else default_port

        _box_row()
        c_cyan("Транспорт Mieru: 1) both (по умолчанию)  2) tcp  3) udp")
        t_raw = input("Выбор [1]: ").strip()
        transport = {"2": "tcp", "3": "udp"}.get(t_raw, "both")

        try:
            xray_config_path = find_xray_config()
            c_cyan(f"Использую конфиг Xray: {xray_config_path}")
            config = load_json(xray_config_path)
            target = pick_target_inbound(config, port, None)
        except SystemExit:
            c_red("Установка прервана на шаге поиска конфигурации Xray (см. сообщение выше). "
                  "Ничего не изменено.")
            return

        want_tcp = transport in ("tcp", "both")
        want_udp = transport in ("udp", "both")
        tcp_port = port
        udp_port = port + 1

        _box_row()
        c_cyan("Выбор портов для Mieru (Enter — оставить значение по умолчанию):")
        taken = set()
        if want_tcp:
            tcp_port = ask_port("  TCP-порт Mieru", tcp_port, taken=taken)
            taken.add(tcp_port)
        if want_udp:
            udp_port = ask_port("  UDP-порт Mieru", udp_port, taken=taken)
            taken.add(udp_port)

        if want_tcp and want_udp and tcp_port == udp_port:
            c_red(f"TCP- и UDP-порт совпадают ({tcp_port}) — это разные транспорты, но порту "
                  f"всё равно нужно быть разным. Установка отменена, ничего не изменено.")
            return

        if want_udp:
            occupied, detail = check_port_listening(udp_port, "udp")
            if occupied:
                c_red(f"UDP-порт {udp_port} уже занят:\n  {detail}\n"
                      f"  Выбери другой при повторном запуске. Ничего не изменено.")
                return

        c_cyan(f"Итоговые порты Mieru: "
               f"{f'TCP={tcp_port} ' if want_tcp else ''}{f'UDP={udp_port}' if want_udp else ''}")

        _box_row()
        c_yellow("Будет изменено: указанный inbound станет SOCKS-петлёй на 127.0.0.1:"
                 f"{LOOPBACK_SOCKS_PORT}, протокол сменится с vless на socks.")
        c_yellow("Внешний доступ по старому VLESS-линку на этом порту ПЕРЕСТАНЕТ работать "
                 "— вместо него будет доступ через Mieru.")
        if not confirm("Продолжить?"):
            c_cyan("Отменено пользователем, ничего не тронуто.")
            return

        try:
            backup_path, owner_mode = backup_config(xray_config_path)
            original_inbound = convert_inbound_to_socks_loopback(target)

            if not apply_xray_change(xray_config_path, config, backup_path, owner_mode):
                c_red("Установка прервана на шаге Xray — Mieru НЕ устанавливался, прод не тронут "
                      "(или уже автоматически восстановлен).")
                return

            if want_tcp:
                occupied, detail = check_port_listening(tcp_port, "tcp")
                if occupied:
                    c_red(f"TCP-порт {tcp_port} занят чем-то ещё после освобождения Xray:\n  {detail}")
                    c_yellow("Откатываю Xray обратно, чтобы не остаться без входа вообще...")
                    shutil.copy2(backup_path, xray_config_path)
                    _restore_owner_mode(xray_config_path, owner_mode)
                    restart_service("xray")
                    c_red("Установка прервана — старый VLESS-инбаунд восстановлен.")
                    return

            install_mita()

            traffic_pattern = _ask_traffic_pattern_mode()  # в меню флага нет — всегда интерактив

            mita_config, mita_creds = build_mita_config(transport, tcp_port, udp_port,
                                                          traffic_pattern=traffic_pattern)

            if not apply_mita_config(mita_config):
                c_red("Mieru не поднялся с новым конфигом. Откатываю Xray, чтобы не остаться "
                      "без входа вообще.")
                shutil.copy2(backup_path, xray_config_path)
                _restore_owner_mode(xray_config_path, owner_mode)
                restart_service("xray")
                c_red("Установка прервана — старый VLESS-инбаунд восстановлен, Mieru не используется.")
                return

            fw = detect_firewall()
            c_cyan(f"Файрвол: {fw}")
            firewall_rollback = []
            if want_tcp:
                firewall_rollback.append(open_port(fw, tcp_port, "tcp"))
            if want_udp:
                firewall_rollback.append(open_port(fw, udp_port, "udp"))

            c_cyan("Проверяю локальный SOCKS-мост (Xray)...")
            if selftest_socks5():
                c_green("SOCKS5-мост на 127.0.0.1:1080 отвечает корректно.")
            else:
                c_yellow("SOCKS5-мост не ответил как ожидалось — не критично для установки, "
                         "но стоит проверить логи Xray, прежде чем давать ссылку клиентам.")

            save_state({
                "xray_config_path": str(xray_config_path),
                "backup_path": str(backup_path),
                "config_owner_mode": owner_mode,
                "inbound_tag": original_inbound.get("tag"),
                "firewall_rollback": firewall_rollback,
                "transport": transport,
                "tcp_port": tcp_port if want_tcp else None,
                "udp_port": udp_port if want_udp else None,
                "created": datetime.now().isoformat(),
            })
            creds = mita_creds  # сигнал «установка реально прошла» — для блока после finally
        except SystemExit:
            c_red("Установка прервана аддоном на одном из системных шагов (см. сообщение выше) — "
                  "проверь руками, что прод не остался без входа.")
    finally:
        # Рамка "УСТАНОВКА" закрывается всегда (early return / SystemExit /
        # обычный успех) — перед тем как print_summary() откроет СВОЮ рамку.
        _box_bottom()

    if creds is None:
        return  # отмена / ошибка на одном из шагов — до print_summary не дошли

    print_summary(creds)
    _print_traffic_pattern_snippet(traffic_pattern)
    traffic_pattern_blob = _export_traffic_pattern_blob() if traffic_pattern else None
    _show_mieru_client_links(creds, get_public_ip(), traffic_pattern_blob=traffic_pattern_blob)
    _log("SUCCESS", "hybrid_addon установлен успешно (через меню установщика)")


def _show_mieru_client_links(creds: dict, server_ip: str, traffic_pattern_blob: str = None) -> None:
    """Доп. клиентская выдача (только для пути через меню установщика):
    mierus:// для Karing/sing-box, mierus:// для Nekobox, sing-box JSON
    для Karing (mierus:// в нём не работает — только JSON-файл) и QR.

    Переиспользует уже проверенные форматы из modules/mieru.py — лениво
    импортирует их прямо здесь, а не в шапке файла. main() (CLI-режим)
    эту функцию не зовёт вообще, поэтому "sudo python3 hybrid_addon.py"
    как раньше не требует пакета vless_installer и работает чисто на
    stdlib — ломается только эта, чисто меню-шная надстройка, если
    что-то пойдёт не так, и то лишь с понятным предупреждением.

    traffic_pattern_blob — base64-протобаф из _export_traffic_pattern_blob(),
    НЕ JSON. Добавляется как есть в &traffic-pattern= (mierus://) и в поле
    "traffic_pattern" sing-box JSON — генераторы из mieru.py при этом не
    трогаем, просто дописываем параметр/поле к уже готовому результату.
    None — поведение как раньше, без этого параметра/поля вообще.
    """
    try:
        from vless_installer.modules.mieru import (
            _gen_client_share_link,
            _gen_client_share_link_nekobox,
            _gen_singbox_outbound,
            _print_qr,
        )
    except ImportError as e:
        c_yellow(f"Не удалось подгрузить генератор клиентских ссылок Mieru ({e}) — "
                 f"логин/пароль/порт выше уже выданы, настрой клиент вручную.")
        return

    for transport, data in creds.items():
        port = data["port"]
        login = data["login"]
        password = data["password"]
        proto = transport.upper()  # "TCP" / "UDP"

        share_link = _gen_client_share_link(server_ip, port, port, proto, login, password)
        share_link_neko = _gen_client_share_link_nekobox(server_ip, port, proto, login, password)

        if traffic_pattern_blob:
            tp_param = f"traffic-pattern={urllib.parse.quote(traffic_pattern_blob, safe='')}"
            share_link = f"{share_link}&{tp_param}"
            share_link_neko = f"{share_link_neko}&{tp_param}"

        outbound = _gen_singbox_outbound(server_ip, port, port, proto, login, password)
        if traffic_pattern_blob:
            # ВНИМАНИЕ: имя поля "traffic_pattern" — по конвенции именования sing-box
            # (snake_case, как server_port) и докам mihomo/sing-box ("base64 string,
            # см. официальную документацию mieru"), но НЕ проверено живьём на Karing —
            # стоит свериться на реальном клиенте при первом использовании.
            outbound["traffic_pattern"] = traffic_pattern_blob
        full_config = {
            "log": {"level": "info"},
            "dns": {
                "servers": [
                    {"tag": "google", "address": "8.8.8.8"},
                    {"tag": "local", "address": "1.1.1.1", "detour": "direct"},
                ]
            },
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"final": outbound["tag"]},
        }
        cfg_path = Path(f"/tmp/karing-mieru-hybrid-{transport}-{login}.json")

        box_header(f"КЛИЕНТСКАЯ ВЫДАЧА — {proto}")
        try:
            _box_row(f"  {BOLD}Ссылка для Karing (sing-box core):{NC}")
            _box_link(share_link)
            _box_row()
            _box_row(f"  {BOLD}Ссылка для Nekobox / Nyamebox:{NC}")
            _box_link(share_link_neko)
            _box_row()
            try:
                cfg_path.write_text(json.dumps(full_config, indent=2, ensure_ascii=False), encoding="utf-8")
                c_yellow(f"mierus:// НЕ работает в Karing — для него файл: {cfg_path}")
            except OSError as e:
                c_red(f"Не удалось сохранить JSON-конфиг для Karing: {e}")
        finally:
            _box_bottom()

        _print_qr(share_link, f"Karing / mierus:// ({proto})")


def _menu_rollback() -> None:
    try:
        do_rollback()
    except SystemExit:
        c_red("Откат прерван (см. сообщение выше) — проверь config.json и службы Xray/Mieru руками.")


def do_hybrid_addon_menu(default_port: int = 443) -> None:
    """Точка входа из _core.py: отдельный пункт в разделе 1 «Установка и Система»."""
    while True:
        os.system("clear")
        st = _menu_status()
        box_header("MIERU HYBRID ADDON")
        _box_row()
        if st.get("installed"):
            transport = st.get("transport", "?")
            tcp_p = st.get("tcp_port")
            udp_p = st.get("udp_port")
            ports = ", ".join(
                p for p in (f"TCP={tcp_p}" if tcp_p else "", f"UDP={udp_p}" if udp_p else "") if p
            )
            _box_kv("Статус:", f"{GREEN}установлен{NC}")
            _box_kv("Транспорт:", transport)
            _box_kv("Порты:", ports)
            _box_row()
            _box_item("1", f"Откатить  {DIM}(восстановить исходный VLESS-инбаунд){NC}")
        else:
            _box_kv("Статус:", f"{DIM}не установлен{NC}")
            _box_row()
            _box_item("1", "Установить")
        _box_item("0", "Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if ch == "1":
            if st.get("installed"):
                _menu_rollback()
            else:
                _menu_install(default_port=default_port)
            input(f"{BOLD}Нажмите Enter...{NC}")
        elif ch == "0" or ch == "":
            return
        else:
            # После _box_bottom() рамка уже закрыта — печатаем как обычный
            # print, не через c_red (та же конвенция, что в do_mieru_menu()).
            print(f"  {RED}✗{NC}  Неверный выбор: {ch}")
            time.sleep(1)
