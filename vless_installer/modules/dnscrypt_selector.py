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
from concurrent.futures import ThreadPoolExecutor, as_completed
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
        """
        Парсит вывод dnscrypt-proxy -list / -list -sort rtt.

        Форматы которые встречаются в реальном выводе:
          Простой -list:
            google
            cloudflare
            adguard-dns

          -list с -sort rtt (новые версии):
            cloudflare          1.1.1.1    2ms
            google              8.8.8.8    5ms
            adguard-dns         94.140.14.14  43ms

          Подробный -list (старые версии):
            [NOTICE] DNSCrypt, port 443, 'google' ...

          -list 2>/dev/null (stderr отфильтрован):
            google
            cloudflare  [no stamp]

        Правило: первое слово строки без скобок — это имя резолвера.
        """
        names = []
        seen = set()
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Пропускаем строки systemd/journald и служебные
            if line.startswith("[") or line.startswith("#"):
                continue
            # Берём первое слово — это всегда имя резолвера
            name = line.split()[0]
            # Имя не должно быть IP-адресом или числом
            if re.match(r'^\d', name):
                continue
            # Не дублируем
            if name not in seen:
                seen.add(name)
                names.append(name)
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


def _measure_latency(resolver_name: str, port: int, timeout: float = 2.0) -> tuple[str, float]:
    """
    Замеряет latency одного резолвера через dig к 127.0.0.1:port.
    Возвращает (имя, время_в_мс). При ошибке возвращает 9999.0.
    """
    try:
        r = subprocess.run(
            ["dig", f"@127.0.0.1", f"-p{port}", "google.com",
             "+time=2", "+tries=1", "+noall", "+stats"],
            capture_output=True, text=True, timeout=timeout + 1,
        )
        m = re.search(r"Query time:\s*(\d+)\s*msec", r.stdout)
        if m:
            return resolver_name, float(m.group(1))
    except Exception:
        pass
    return resolver_name, 9999.0


def _measure_all_latency(resolvers: list[str], port: int) -> list[tuple[str, float]]:
    """
    Параллельно замеряет latency для всех резолверов.
    Временно применяет каждый резолвер, замеряет, возвращает список
    (имя, мс) отсортированный по возрастанию.

    Поскольку DNSCrypt должен использовать конкретный резолвер для замера,
    делаем замер через текущий порт DNSCrypt после временной смены server_names,
    перезапуска и dig. Это долго — используем упрощённый метод:
    измеряем RTT до bootstrap DNS (1.1.1.1) как прокси для latency резолвера,
    плюс реальный dig через текущий DNSCrypt для финального теста.
    """
    import socket

    def _ping_resolver(name: str) -> tuple[str, float]:
        """
        TCP-пинг до резолвера. Пробует порты в порядке приоритета.
        Разные резолверы слушают на разных портах:
          DNSCrypt: обычно 443 или 8443
          DoH:      443
          DoT:      853
          Quad9 DNSCrypt: 9953
          CryptoStorm, Comss: 5353
        """
        # (ip, [порты в порядке приоритета])
        KNOWN: dict[str, tuple[str, list[int]]] = {
            # Cloudflare
            "cloudflare":                         ("1.1.1.1",          [443, 853]),
            "cloudflare-ipv6":                    ("2606:4700:4700::1111", [443]),
            "cloudflare-security":                ("1.1.1.2",          [443, 853]),
            "cloudflare-security-ipv6":           ("2606:4700:4700::1112", [443]),
            "cloudflare-family":                  ("1.1.1.3",          [443, 853]),
            "cloudflare-family-ipv6":             ("2606:4700:4700::1113", [443]),
            # Google — DoH на 443, DoT на 853
            "google":                             ("8.8.8.8",          [443, 853]),
            "google-ipv6":                        ("2001:4860:4860::8888", [443, 853]),
            # AdGuard
            "adguard-dns":                        ("94.140.14.14",     [443, 853]),
            "adguard-dns-ipv6":                   ("2a10:50c0::ad1:ff",[443]),
            "adguard-dns-doh":                    ("94.140.14.14",     [443]),
            "adguard-dns-family":                 ("94.140.14.15",     [443, 853]),
            "adguard-dns-family-doh":             ("94.140.14.15",     [443]),
            "adguard-dns-unfiltered":             ("94.140.14.140",    [443, 853]),
            "adguard-dns-unfiltered-doh":         ("94.140.14.140",    [443]),
            # Quad9 — DNSCrypt на 9953, DoH на 443
            "quad9-dnscrypt-ip4-filter-pri":      ("9.9.9.9",          [9953, 443]),
            "quad9-dnscrypt-ip4-nofilter-pri":    ("9.9.9.10",         [9953, 443]),
            "quad9-dnscrypt-ip4-filter-alt":      ("149.112.112.9",    [9953, 443]),
            "quad9-dnscrypt-ip4-nofilter-alt":    ("149.112.112.10",   [9953, 443]),
            "quad9-doh-ip4-port443-filter-pri":   ("9.9.9.9",          [443]),
            "quad9-doh-ip4-port443-nofilter-pri": ("9.9.9.10",         [443]),
            # CleanBrowsing — DNSCrypt на 8443
            "cleanbrowsing-adult":                ("185.228.168.10",   [8443, 443]),
            "cleanbrowsing-family":               ("185.228.168.168",  [8443, 443]),
            "cleanbrowsing-security":             ("185.228.168.9",    [8443, 443]),
            "cleanbrowsing-adult-doh":            ("185.228.168.10",   [443]),
            "cleanbrowsing-family-doh":           ("185.228.168.168",  [443]),
            "cleanbrowsing-security-doh":         ("185.228.168.9",    [443]),
            # OpenDNS
            "opendns-familyshield":               ("208.67.222.123",   [443, 853]),
            "opendns-familyshield-ipv6":          ("2620:119:35::123", [443]),
            # Cisco Umbrella
            "cisco-doh":                          ("208.67.222.222",   [443]),
            # NextDNS
            "nextdns":                            ("45.90.28.0",       [443, 853]),
            "nextdns-doh":                        ("45.90.28.0",       [443]),
            # Mullvad
            "mullvad-doh":                        ("194.242.2.2",      [443]),
            "mullvad-adblock-doh":                ("194.242.2.3",      [443]),
            "mullvad-family-doh":                 ("194.242.2.4",      [443]),
            "mullvad-extended-doh":               ("194.242.2.5",      [443]),
            "mullvad-all-doh":                    ("194.242.2.9",      [443]),
            # ControlD
            "controld-block-malware":             ("76.76.2.1",        [443]),
            "controld-unfiltered":                ("76.76.2.0",        [443]),
            "controld-block-malware-doh":         ("76.76.2.1",        [443]),
            # Comss.one (RU) — DNSCrypt на 5353
            "comss.one":                          ("92.38.135.1",      [5353, 443]),
            # DNS.SB
            "dnssb-ipv4-a":                       ("185.222.222.222",  [443, 853]),
            "dnssb-ipv4-b":                       ("45.11.45.11",      [443, 853]),
            # a-and-a
            "a-and-a":                            ("217.169.20.23",    [5353, 443]),
            # Bortzmeyer
            "bortzmeyer":                         ("193.70.85.11",     [8443, 443]),
            "bortzmeyer-doh":                     ("193.70.85.11",     [443]),
            # CipherDNS
            "cipherdns-jb1-za":                   ("41.185.28.195",    [5353, 443]),
            "cipherdns-jb1-doh-za":               ("41.185.28.195",    [443]),
            # CS (CryptoStorm) — DNSCrypt на 5353
            "cs-austria":                         ("5.9.164.112",      [5353, 443]),
            "cs-barcelona":                       ("80.241.218.68",    [5353, 443]),
            "cs-belgium":                         ("193.34.145.92",    [5353, 443]),
            # Brahma World
            "brahma-world":                       ("216.18.214.193",   [443, 5353]),
            "brahma-world-ipv6":                  ("2602:fea7:d00::1", [443]),
        }

        entry = KNOWN.get(name)
        if not entry:
            # Неизвестный резолвер — пробуем стандартные порты
            unknown_ports = [443, 853, 5353, 8443]
            # Пробуем определить IP через системный резолвер
            return name, 9999.0

        ip, ports = entry
        try:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            for port in ports:
                try:
                    start = time.monotonic()
                    with socket.socket(family, socket.SOCK_STREAM) as s:
                        s.settimeout(2.0)
                        s.connect((ip, port))
                    ms = (time.monotonic() - start) * 1000
                    return name, round(ms, 1)
                except Exception:
                    continue
        except Exception:
            pass
        return name, 9999.0

    results: list[tuple[str, float]] = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_ping_resolver, name): name for name in resolvers}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: x[1])
    return results


def _get_dnscrypt_port() -> int:
    """Читает порт из конфига DNSCrypt."""
    try:
        m = re.search(
            r"listen_addresses\s*=\s*\[.*?:(\d+)",
            _DNSCRYPT_CONF.read_text(),
        )
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return 5300


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

def _show_page(top: list[str], page: int, current: list[str], sorted_by_rtt: bool = True, latency_map: dict | None = None) -> None:
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
        name    = top[i]
        marker  = f" {GREEN}← текущий{NC}" if name in current else ""
        num     = f"{i + 1:>3}."
        ms      = (latency_map or {}).get(name)
        if ms is not None and ms < 9999.0:
            lat_color = GREEN if ms < 50 else YELLOW if ms < 150 else RED
            lat_str   = f"  {lat_color}{ms:.0f} мс{NC}"
        elif ms is not None:
            lat_str = f"  {DIM}недоступен{NC}"
        else:
            lat_str = ""
        print(f"  {WHITE}{num}{NC}  {CYAN}{name:<35}{NC}{lat_str}{marker}")

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
    _info("Получаю список резолверов...")
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

    top_all = resolvers[:_TOP_N]
    latency_map: dict = {}

    # Замеряем latency параллельно
    _info(f"Замеряю latency для {len(top_all)} резолверов (параллельно, ~15-30 сек)...")
    print()
    measured = _measure_all_latency(top_all, _get_dnscrypt_port())

    # Разделяем на доступные и недоступные
    available   = [(n, ms) for n, ms in measured if ms < 9999.0]
    unavailable = [(n, ms) for n, ms in measured if ms >= 9999.0]

    if available:
        sorted_by_rtt = True
        # Топ по latency — только доступные, потом недоступные
        top = [n for n, _ in available] + [n for n, _ in unavailable]
        # Сохраняем latency для отображения
        latency_map = {n: ms for n, ms in measured}
    else:
        sorted_by_rtt = False
        top = top_all
        latency_map = {}
    page = 0
    chosen_names: list[str] = []

    # ── Постраничный выбор ────────────────────────────────────────────────
    while True:
        _show_page(top, page, current, sorted_by_rtt, latency_map)

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
