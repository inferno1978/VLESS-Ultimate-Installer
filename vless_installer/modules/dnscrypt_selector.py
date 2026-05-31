"""
vless_installer/modules/dnscrypt_selector.py
───────────────────────────────────────────────────────────────────────────────
Интерактивный выбор DNSCrypt-резолверов с замером latency.

Что делает этот модуль:
  1. Запускает `dnscrypt-proxy -list -sort rtt` — получает список доступных
     резолверов, отсортированных по времени отклика с данного сервера.
  2. Показывает топ-100 резолверов постранично (по 20 на страницу).
  3. Пользователь выбирает нужные по номерам (через запятую: 1,2,3).
  4. Прописывает server_names в /etc/dnscrypt-proxy/dnscrypt-proxy.toml,
     перезапускает DNSCrypt и проверяет что сервис поднялся.
  5. Делает быстрый DNS-тест и показывает время ответа.

Почему именно так:
  server_names зависит от географии VPS. Оптимальные резолверы для Европы
  отличаются от оптимальных для Азии или Латинской Америки. Автоподбор по
  RTT даёт пользователю актуальные данные с его конкретного сервера.

ВАЖНО: модуль не трогает серверный /etc/xray/config.json.

Точка входа из _core.py:
    from vless_installer.modules.dnscrypt_selector import do_dnscrypt_selector_menu
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

# ── Цвета ─────────────────────────────────────────────────────────────────
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
RED   = _C['RED'];  GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN  = _C['CYAN']; BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM   = _C['DIM'];  WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        import re as _re
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = _re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [DNSCRYPT_SEL] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str) -> None: print(f"{CYAN}[INFO]{NC}  {msg}");   _log("INFO", msg)
def _ok(msg: str)   -> None: print(f"{GREEN}[OK]{NC}    {msg}");   _log("OK",   msg)
def _warn(msg: str) -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)

# ── Импорт box-рендерера ──────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row,
    _box_back, _box_warn, _box_desc,
)

# ── Константы ──────────────────────────────────────────────────────────────
_DNSCRYPT_BIN  = Path("/usr/local/bin/dnscrypt-proxy")
_DNSCRYPT_CONF = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
_TOP_N         = 100  # показываем топ-100 резолверов
_PAGE_SIZE     = 20   # по 20 на страницу


# ── Получение списка резолверов ────────────────────────────────────────────

def _fetch_resolver_list() -> tuple[list[str], bool]:
    """
    Получает полный список резолверов.
    Временно создаёт конфиг без server_names чтобы получить весь пул,
    затем пробует -sort rtt, при неудаче — обычный -list.
    Возвращает (список имён, sorted_by_rtt: bool).
    """
    import tempfile, shutil

    def _parse_names(stdout: str) -> list[str]:
        names = []
        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("[") and " " not in line:
                names.append(line)
        return names

    # Создаём временный конфиг без server_names — чтобы видеть весь пул
    tmp_conf = None
    try:
        content = _DNSCRYPT_CONF.read_text()
        # Убираем server_names из временного конфига
        tmp_content = re.sub(r"^server_names\s*=\s*\[.*?\]\n?", "", content, flags=re.MULTILINE)
        fd, tmp_conf = tempfile.mkstemp(suffix=".toml")
        with os.fdopen(fd, "w") as f:
            f.write(tmp_content)
    except Exception:
        tmp_conf = None

    conf = tmp_conf if tmp_conf else str(_DNSCRYPT_CONF)

    try:
        # Пробуем -sort rtt
        r = subprocess.run(
            [str(_DNSCRYPT_BIN), "-config", conf, "-list", "-sort", "rtt"],
            capture_output=True, text=True, timeout=60,
        )
        names = _parse_names(r.stdout)
        if names:
            return names, True

        # Fallback: обычный -list
        r = subprocess.run(
            [str(_DNSCRYPT_BIN), "-config", conf, "-list"],
            capture_output=True, text=True, timeout=30,
        )
        names = _parse_names(r.stdout)
        return names, False
    except Exception as e:
        _warn(f"Ошибка запуска dnscrypt-proxy -list: {e}")
        return [], False
    finally:
        if tmp_conf:
            try:
                os.unlink(tmp_conf)
            except Exception:
                pass


def _get_current_server_names() -> list[str]:
    """Читает текущий server_names из конфига."""
    if not _DNSCRYPT_CONF.exists():
        return []
    content = _DNSCRYPT_CONF.read_text()
    m = re.search(r"^server_names\s*=\s*\[([^\]]+)\]", content, re.MULTILINE)
    if not m:
        return []
    return [s.strip().strip("'\"") for s in m.group(1).split(",") if s.strip()]


def _apply_server_names(names: list[str]) -> bool:
    """
    Прописывает server_names в конфиг.
    Если строка уже есть — заменяет. Если нет — добавляет после listen_addresses.
    """
    if not _DNSCRYPT_CONF.exists():
        _warn(f"Конфиг не найден: {_DNSCRYPT_CONF}")
        return False

    content = _DNSCRYPT_CONF.read_text()
    names_str = ", ".join(f"'{n}'" for n in names)
    new_line = f"server_names = [{names_str}]"

    if re.search(r"^server_names\s*=", content, re.MULTILINE):
        content = re.sub(
            r"^server_names\s*=\s*\[.*?\]",
            new_line,
            content,
            flags=re.MULTILINE,
        )
    else:
        content = re.sub(
            r"(^listen_addresses\s*=\s*\[.*?\]\n)",
            r"\1" + new_line + "\n",
            content,
            flags=re.MULTILINE,
        )

    try:
        _DNSCRYPT_CONF.write_text(content)
        return True
    except Exception as e:
        _warn(f"Не удалось записать конфиг: {e}")
        return False


# ── Постраничный вывод ────────────────────────────────────────────────────

def _show_page(top: list[str], page: int, current: list[str], sorted_by_rtt: bool = True) -> None:
    """Выводит одну страницу списка резолверов."""
    start = page * _PAGE_SIZE
    end   = min(start + _PAGE_SIZE, len(top))
    total_pages = (len(top) + _PAGE_SIZE - 1) // _PAGE_SIZE

    os.system("clear")
    print()
    _box_top(f"🔍  ВЫБОР DNSCRYPT-РЕЗОЛВЕРОВ  —  стр. {page + 1}/{total_pages}")
    if sorted_by_rtt:
        _box_desc(f"Топ-{len(top)} резолверов по latency с этого сервера. Выберите 2–3. Номера через запятую.")
    else:
        _box_desc(f"{len(top)} резолверов (алфавитный порядок — latency будет после накопления статистики). Выберите 2–3.")
    _box_bottom()
    print()

    for i in range(start, end):
        name   = top[i]
        marker = f" {GREEN}← текущий{NC}" if name in current else ""
        num    = f"{i + 1:>3}."
        print(f"  {WHITE}{num}{NC}  {CYAN}{name}{NC}{marker}")

    print()
    nav = []
    if page > 0:
        nav.append(f"{WHITE}P{NC} — предыдущая")
    if end < len(top):
        nav.append(f"{WHITE}N{NC} — следующая")
    nav.append(f"{WHITE}Q{NC} — отмена")

    _box_top("")
    _box_row(f"  {DIM}Навигация: {('  |  '.join(nav))}{NC}")
    _box_row(f"  {DIM}Или введите номера через запятую (например: 1,3,7):{NC}")
    _box_bottom()


# ── Главное меню ──────────────────────────────────────────────────────────

def do_dnscrypt_selector_menu() -> None:
    """
    Интерактивный выбор DNSCrypt-резолверов с замером latency.
    Вызывается из сетевого меню в _core.py.
    """
    if not _DNSCRYPT_BIN.exists():
        _warn("DNSCrypt-proxy не установлен")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    if not _DNSCRYPT_CONF.exists():
        _warn(f"Конфиг не найден: {_DNSCRYPT_CONF}")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    os.system("clear")
    print()
    _box_top("🔍  ВЫБОР DNSCRYPT-РЕЗОЛВЕРОВ")
    _box_desc(
        "Замеряет latency до всех доступных резолверов с этого сервера "
        "и показывает топ-100 по скорости. Выберите 2–3 резолвера — "
        "они будут прописаны в server_names и применены немедленно."
    )
    _box_sep()
    _box_warn(
        "Выбирайте исходя из географии VPS, а не личных предпочтений — "
        "быстрее будет тот, кто физически ближе к серверу."
    )
    _box_bottom()
    print()

    current = _get_current_server_names()
    if current:
        _info(f"Текущие server_names: {', '.join(current)}")
    else:
        _info("server_names не установлен (используется весь пул)")
    print()
    _info("Получаю список резолверов (попытка сортировки по latency)...")
    print()

    resolvers, sorted_by_rtt = _fetch_resolver_list()

    if not resolvers:
        _warn("Список резолверов пуст. Возможные причины:")
        print(f"  {DIM}• DNSCrypt ещё не скачал public-resolvers.md (подождите минуту){NC}")
        print(f"  {DIM}• Нет доступа к интернету с сервера{NC}")
        print(f"  {DIM}• Версия dnscrypt-proxy не поддерживает -list{NC}")
        print()
        _info("Попробуйте вручную:")
        print(f"  {CYAN}dnscrypt-proxy -config {_DNSCRYPT_CONF} -list | head -30{NC}")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    top = resolvers[:_TOP_N]
    page = 0
    chosen_names: list[str] = []

    # ── Постраничный выбор ────────────────────────────────────────────────
    while True:
        _show_page(top, page, current, sorted_by_rtt)

        try:
            raw = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            return

        if not raw:
            continue

        rl = raw.lower()

        # Навигация
        if rl == "q":
            return
        if rl == "n":
            if (page + 1) * _PAGE_SIZE < len(top):
                page += 1
            continue
        if rl == "p":
            if page > 0:
                page -= 1
            continue

        # Парсим номера
        errors: list[str] = []
        new_chosen: list[str] = list(chosen_names)  # накапливаем выбор

        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if part.isdigit():
                idx = int(part)
                if 1 <= idx <= len(top):
                    name = top[idx - 1]
                    if name not in new_chosen:
                        new_chosen.append(name)
                else:
                    errors.append(f"{part} (нет такого номера, максимум {len(top)})")
            else:
                # Разрешаем вводить имя напрямую
                if part in resolvers and part not in new_chosen:
                    new_chosen.append(part)
                else:
                    errors.append(f"'{part}' (не найден в списке)")

        if errors:
            print(f"\n  {YELLOW}Пропущены: {', '.join(errors)}{NC}")

        if not new_chosen:
            print(f"\n  {YELLOW}Ни одного корректного резолвера{NC}")
            time.sleep(1)
            continue

        # Показываем что выбрано и просим подтвердить
        os.system("clear")
        print()
        _box_top("✅  ПОДТВЕРЖДЕНИЕ ВЫБОРА")
        _box_row()
        for i, name in enumerate(new_chosen, 1):
            print(f"  {WHITE}{i}.{NC}  {CYAN}{name}{NC}")
        _box_row()
        if len(new_chosen) == 1:
            _box_warn("Рекомендуется минимум 2 резолвера для отказоустойчивости")
        _box_bottom()
        print()

        try:
            confirm = input(
                f"{CYAN}Применить эти резолверы? [y — да / n — выбрать заново / q — отмена]:{NC} "
            ).strip().lower()
        except KeyboardInterrupt:
            return

        if confirm in ("q",):
            return
        if confirm in ("n", "нет"):
            chosen_names = []
            continue
        if confirm not in ("y", "yes", "д", "да"):
            continue

        chosen_names = new_chosen
        break

    if not chosen_names:
        return

    # ── Применяем ─────────────────────────────────────────────────────────
    print()
    if not _apply_server_names(chosen_names):
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    _ok(f"server_names = [{', '.join(chosen_names)}] записан в конфиг")

    _info("Перезапускаю dnscrypt-proxy...")
    subprocess.run(
        ["systemctl", "restart", "dnscrypt-proxy"],
        capture_output=True, text=True,
    )
    time.sleep(2)

    r2 = subprocess.run(
        ["systemctl", "is-active", "dnscrypt-proxy"],
        capture_output=True, text=True,
    )

    if r2.stdout.strip() == "active":
        _ok("DNSCrypt-proxy перезапущен успешно")
        print()

        # Читаем порт
        port = 5300
        try:
            m = re.search(
                r"listen_addresses\s*=\s*\[.*?:(\d+)",
                _DNSCRYPT_CONF.read_text(),
            )
            if m:
                port = int(m.group(1))
        except Exception:
            pass

        _info(f"Тест DNS через 127.0.0.1:{port}...")
        for domain in ("google.com", "cloudflare.com", "github.com", "youtube.com"):
            try:
                r3 = subprocess.run(
                    ["dig", f"@127.0.0.1", f"-p{port}", domain,
                     "+time=3", "+tries=1", "+noall", "+stats"],
                    capture_output=True, text=True, timeout=5,
                )
                m2 = re.search(r"Query time:\s*(\d+)\s*msec", r3.stdout)
                qt = m2.group(1) if m2 else "?"
                color = GREEN if (m2 and int(qt) < 50) else YELLOW
                print(f"    {domain:<22} {color}{qt} мс{NC}")
            except Exception:
                print(f"    {domain:<22} {YELLOW}нет ответа{NC}")
    else:
        _warn("DNSCrypt-proxy не запустился после перезапуска")
        _warn("Проверьте: journalctl -u dnscrypt-proxy -n 20")

    input(f"\n{BLUE}Нажмите Enter...{NC}")
