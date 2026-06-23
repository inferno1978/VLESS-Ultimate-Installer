"""
vless_installer/modules/telemt_ios_fix.py
───────────────────────────────────────────────────────────────────────────────
iOS-фикс для Telemt: MSS-clamp + redirect на отдельный порт.

Контекст
────────
`client_mss` (см. telemt_mss_selector.py) фрагментирует TLS ClientHello для
ВСЕХ клиентов через telemt.toml, чтобы DPI (TSPU) не собрал JA4-фингерпринт
целиком и не заблокировал по нему. Но если фрагментация нужна точечно —
например, у части пользователей не подключается именно iOS, а Android и
Desktop через тот же порт работают нормально (у TLS-стека iOS-приложения
Telegram другой ClientHello, и один и тот же MSS может не дробить его так
же эффективно) — общий client_mss не даёт настроить MSS только под них без
побочных эффектов (лишний оверхед фрагментации) на тех, у кого и так всё
работает.

Решение: отдельный внешний порт. Входящий SYN на нём получает TCP MSS-clamp
прямо на лету, трафик прозрачно редиректится на основной порт Telemt.
Android/Desktop продолжают использовать основной порт без изменений —
iOS-пользователям меняется только port= в ссылке, secret и IP те же.

Механизм: iptables (НЕ nftables — проект целиком на iptables, см. принцип в
telemt_syn_limiter.py).

    iptables -t mangle -A PREROUTING -p tcp --dport <EXT_PORT> \
        --tcp-flags SYN,RST SYN \
        -m comment --comment telemt-ios-mss-fix \
        -j TCPMSS --set-mss <MSS>
    iptables -t nat -A PREROUTING -p tcp --dport <EXT_PORT> \
        -m comment --comment telemt-ios-mss-fix \
        -j REDIRECT --to-port <PORT>

Первое правило (mangle/PREROUTING) клампит MSS только на SYN/SYN-ACK для
нашего внешнего порта — на установленные соединения и остальные порты не
влияет. Второе (nat/PREROUTING) прозрачно подменяет порт назначения на
основной порт Telemt до локальной доставки пакета.

Конфликт с client_mss
──────────────────────
client_mss в конфиге задаёт MSS на ВСЕ соединения сразу — если он уже
включён, два механизма будут спорить за MSS одного и того же сокета.
При включении фикса конфликт обнаруживается автоматически (читаем
telemt.toml тем же паттерном регулярки, что и telemt_mss_selector.py — не
импортируем модуль напрямую, чтобы не плодить cross-module зависимость), и
с согласия пользователя client_mss удаляется из конфига перед применением
правил, конфиг перечитывается сервисом (restart).

Проверка занятости порта
─────────────────────────
Перед применением правил проверяем, не слушает ли что-то ещё (sshd, другой
прокси) предложенный внешний порт — `nat REDIRECT` для уже занятого порта
молча отберёт у него трафик. Используем `socket.bind()`: TCPMSS/REDIRECT не
открывают сокет (переписывают пакет на уровне netfilter до локальной
доставки), так что повторное применение фикса на тот же порт не считается
занятым.

Гарантии совместимости
──────────────────────
  • Правила маркируются комментарием `--comment "telemt-ios-mss-fix"` —
    отключение модуля удаляет ТОЛЬКО их, ничего больше (не трогает
    REDIRECT-правила xray/tproxy — другая chain/match, другой тег).
  • persist — тот же best-effort паттерн, что в telemt_syn_limiter.py
    (netfilter-persistent / iptables-save в rules.v4), продублирован
    локально, а не вызван из mtproto.py.
  • Установка/удаление идемпотентны: перед apply правила с нашим тегом
    удаляются, дубликатов не плодит.

Интеграция с mtproto.py
───────────────────────
  Вызывается из mtproto_menu() через lazy-import (как telemt_syn_limiter):
      from vless_installer.modules.telemt_ios_fix import ios_fix_menu
      ios_fix_menu()

  Публичный API для отображения статуса/ссылок без захода в подменю:
      status() -> dict                — для построения iOS-ссылки в _menu_users
                                         и в финальном экране установки
      ios_fix_status_line() -> str    — однострочный статус для главного меню
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
#  ПУТИ И КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
_CONFIG_FILE  = Path("/etc/telemt/telemt.toml")
_SERVICE_NAME = "telemt"
_STATE_FILE   = Path("/var/lib/xray-installer/telemt_ios_fix.json")
_COMMENT_TAG  = "telemt-ios-mss-fix"

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА (self-contained, как в telemt_syn_limiter.py)
# ══════════════════════════════════════════════════════════════════════════════
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
#  BOX-РЕНДЕРИНГ (идентичен стилю telemt_syn_limiter.py)
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

def _box_sep() -> None: print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
def _box_bot() -> None: print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        acc = 0
        plain = _plain(text)
        cut = 0
        import unicodedata as _ud
        for i, ch in enumerate(plain):
            acc += 2 if _ud.east_asian_width(ch) in ("W", "F") else 1
            if acc > _BOX_W - 1:
                cut = i; break
        text = text[:cut] + "…"
        w = _wlen(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{chr(32) * pad}{CYAN}║{NC}")

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
    try:
        return subprocess.run(cmd, **kw)
    except Exception:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="error")

def _get_telemt_port() -> int:
    """Читает текущий порт Telemt из telemt.toml. Тот же паттерн, что _get_port() в mtproto.py."""
    if not _CONFIG_FILE.exists():
        return 0
    m = re.search(r'^port\s*=\s*(\d+)', _CONFIG_FILE.read_text(), re.MULTILINE)
    return int(m.group(1)) if m else 0

def _get_current_mss() -> str:
    """Читает client_mss из telemt.toml. Тот же паттерн, что get_current_mss() в telemt_mss_selector.py."""
    if not _CONFIG_FILE.exists():
        return ""
    try:
        m = re.search(r'^client_mss\s*=\s*"?([^"\s]+)"?', _CONFIG_FILE.read_text(), re.MULTILINE)
        return m.group(1) if m else ""
    except Exception:
        return ""

def _strip_client_mss() -> bool:
    """Убирает client_mss из telemt.toml. Возвращает True, если строка была удалена."""
    if not _CONFIG_FILE.exists():
        return False
    content = _CONFIG_FILE.read_text()
    new_content = re.sub(r'^client_mss\s*=\s*"[^"]*"\n?', '', content, flags=re.MULTILINE)
    if new_content == content:
        return False
    _CONFIG_FILE.write_text(new_content)
    _CONFIG_FILE.chmod(0o640)
    return True

def _port_in_use(port: int) -> bool:
    """
    True, если порт уже занят слушающим процессом (TCP/IPv4, любой интерфейс).

    Не путать с нашими собственными правилами REDIRECT — они не открывают
    сокет, а переписывают адрес назначения на уровне netfilter, так что
    повторное применение фикса на тот же внешний порт не считается занятым.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
    except OSError:
        return True
    except Exception:
        return False
    return False

def _pick_free_port(start: int, exclude: int) -> int:
    """Первый свободный TCP-порт начиная с start (с переносом через 65535 на 1024)."""
    port = max(1, min(start, 65535))
    for _ in range(100):
        if port != exclude and not _port_in_use(port):
            return port
        port += 1
        if port > 65535:
            port = 1024
    return 0

def _setup_ufw(port: int) -> None:
    """Открывает порт в UFW, если он активен. Дублирует _setup_ufw() из mtproto.py локально."""
    if not shutil.which("ufw"):
        return
    if "active" in _run(["ufw", "status"], capture=True).stdout.lower():
        _run(["ufw", "allow", f"{port}/tcp", "comment", "Telemt iOS-fix"])
        _box_ok(f"UFW: открыт порт {port}/tcp")

# ══════════════════════════════════════════════════════════════════════════════
#  STATE — храним применённую конфигурацию отдельно от telemt.toml
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class IosFixConfig:
    enabled: bool = False
    ext_port: int = 0
    target_port: int = 0
    mss: int = 92

def _load_state() -> IosFixConfig:
    if not _STATE_FILE.exists():
        return IosFixConfig()
    try:
        data = json.loads(_STATE_FILE.read_text())
        return IosFixConfig(**{k: data[k] for k in IosFixConfig.__dataclass_fields__ if k in data})
    except Exception:
        return IosFixConfig()

def _save_state(cfg: IosFixConfig) -> None:
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _STATE_FILE.write_text(json.dumps(asdict(cfg), ensure_ascii=False, indent=2))
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES — управление правилами
# ══════════════════════════════════════════════════════════════════════════════
def _rules_exist() -> bool:
    """Проверяет, есть ли уже правило с нашим комментарием в mangle/PREROUTING."""
    r = _run(["iptables", "-t", "mangle", "-S", "PREROUTING"], capture=True)
    return _COMMENT_TAG in (r.stdout or "")

def _remove_rules() -> int:
    """
    Удаляет ВСЕ правила mangle/nat PREROUTING с нашим тегом.
    Безопасно вызывать многократно — если правил нет, просто ничего не делает.
    Возвращает количество удалённых правил.
    """
    removed = 0
    for table in ("mangle", "nat"):
        for _ in range(20):  # защита от бесконечного цикла, если что-то пошло не так
            r = _run(["iptables", "-t", table, "-S", "PREROUTING"], capture=True)
            lines = [l for l in (r.stdout or "").splitlines() if _COMMENT_TAG in l]
            if not lines:
                break
            line = lines[0]
            if not line.startswith("-A PREROUTING"):
                break
            del_args = ["iptables", "-t", table, "-D", "PREROUTING"] + line.split()[2:]
            r2 = _run(del_args, capture=True)
            if r2.returncode != 0:
                break
            removed += 1
    return removed

def _apply_rules(cfg: IosFixConfig) -> tuple[bool, str]:
    """
    Применяет TCPMSS + REDIRECT для текущего cfg.
    Идемпотентно: сначала удаляет старые правила с нашим тегом, потом
    добавляет новые.
    """
    if cfg.ext_port <= 0 or cfg.target_port <= 0:
        return False, "Не заданы порты."

    _remove_rules()  # чистим перед применением — гарантия идемпотентности

    mss_cmd = [
        "iptables", "-t", "mangle", "-A", "PREROUTING",
        "-p", "tcp", "--dport", str(cfg.ext_port),
        "--tcp-flags", "SYN,RST", "SYN",
        "-m", "comment", "--comment", _COMMENT_TAG,
        "-j", "TCPMSS", "--set-mss", str(cfg.mss),
    ]
    redirect_cmd = [
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-p", "tcp", "--dport", str(cfg.ext_port),
        "-m", "comment", "--comment", _COMMENT_TAG,
        "-j", "REDIRECT", "--to-port", str(cfg.target_port),
    ]

    r1 = _run(mss_cmd, capture=True)
    if r1.returncode != 0:
        return False, f"Ошибка применения TCPMSS-правила: {r1.stderr.strip()[:120]}"

    r2 = _run(redirect_cmd, capture=True)
    if r2.returncode != 0:
        # откатываем TCPMSS-правило, чтобы не оставить половинчатое состояние
        _remove_rules()
        return False, f"Ошибка применения REDIRECT-правила: {r2.stderr.strip()[:120]}"

    return True, "Правила TCPMSS + REDIRECT применены."

def _persist_rules() -> None:
    """
    Сохраняет iptables-правила тем же best-effort способом, что и
    telemt_syn_limiter.py (netfilter-persistent / iptables-save в
    rules.v4, если доступно). Не падает, если механизм persist
    отсутствует — правило просто не переживёт перезагрузку (можно
    повторно включить через меню).
    """
    if shutil.which("netfilter-persistent"):
        _run(["netfilter-persistent", "save"])
        return
    rules_path = Path("/etc/iptables/rules.v4")
    if rules_path.parent.exists():
        try:
            r = _run(["iptables-save"], capture=True)
            if r.returncode == 0 and r.stdout:
                rules_path.write_text(r.stdout)
        except Exception:
            pass

# ══════════════════════════════════════════════════════════════════════════════
#  ПУБЛИЧНЫЙ API
# ══════════════════════════════════════════════════════════════════════════════
def status() -> dict:
    """Возвращает текущее состояние фикса для отображения в mtproto_menu() и при показе ссылок."""
    cfg = _load_state()
    active = _rules_exist()
    return {
        "enabled": cfg.enabled and active,
        "configured_but_inactive": cfg.enabled and not active,
        "ext_port": cfg.ext_port,
        "target_port": cfg.target_port,
        "mss": cfg.mss,
    }

def ios_fix_status_line() -> str:
    """Однострочный статус для главного меню mtproto_menu()."""
    st = status()
    if st["enabled"]:
        return f"{GREEN}● активен{NC}  {DIM}порт {st['ext_port']} → {st['target_port']}, MSS {st['mss']}{NC}"
    if st["configured_but_inactive"]:
        return f"{YELLOW}⚠ включён в конфиге, но правил нет в iptables{NC}"
    return f"{DIM}не активен{NC}"

# ══════════════════════════════════════════════════════════════════════════════
#  ИНТЕРАКТИВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def ios_fix_menu() -> None:
    """
    Точка входа — вызывается из mtproto_menu() в mtproto.py.
    """
    if not _CONFIG_FILE.exists():
        _box_err("Telemt не установлен."); _pause(); return

    while True:
        os.system("clear")
        cfg = _load_state()
        active = _rules_exist()
        target_port = _get_telemt_port()
        current_mss = _get_current_mss()

        _box_top("🍎  IOS-ФИКС  •  MSS + REDIRECT НА ОТДЕЛЬНЫЙ ПОРТ")
        _box_row()
        _box_info("Отдельный внешний порт для iOS: SYN получает TCP MSS-clamp,")
        _box_info("трафик прозрачно редиректится на основной порт Telemt.")
        _box_info("Android/Desktop продолжают работать на основном порту как есть.")
        _box_row(); _box_sep()

        status_str = (
            f"{GREEN}● активен{NC}  {DIM}порт {cfg.ext_port} → {cfg.target_port}, MSS {cfg.mss}{NC}"
            if active and cfg.enabled else
            f"{YELLOW}⚠ включён в конфиге, но правил в iptables нет{NC}"
            if cfg.enabled and not active else
            f"{DIM}не активен{NC}"
        )
        _box_kv("Статус:", status_str)
        _box_kv("Основной порт:", str(target_port) if target_port else f"{RED}не определён{NC}")
        _box_kv("client_mss в конфиге:", current_mss if current_mss else f"{DIM}не задан{NC}")
        if current_mss:
            _box_row()
            _box_warn("client_mss задан — конфликтует с MSS-clamp для iOS-порта.")
        _box_row(); _box_sep()
        _box_item("1", "🚀  Включить / изменить параметры")
        _box_item("2", f"{RED}⏹️   Выключить и удалить правила{NC}")
        _box_sep(); _box_item("Q", "← Назад в меню Telemt"); _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            if target_port <= 0:
                _box_err("Не удалось определить основной порт Telemt из telemt.toml.")
                _pause(); continue

            print()
            default_ext = _pick_free_port(target_port + 1, target_port)
            if default_ext == 0:
                default_ext = target_port + 1 if target_port < 65535 else target_port - 1
            try:
                ext_s = _ask(f"  {CYAN}Внешний порт для iOS [{default_ext}]: {NC}",
                              default=str(default_ext), c=True).strip()
                mss_s = _ask(f"  {CYAN}MSS для iOS-порта (88-4096) [92]: {NC}",
                              default="92", c=True).strip()
            except _Cancelled:
                continue

            try:
                ext_port, mss = int(ext_s), int(mss_s)
            except ValueError:
                _box_err("Нужны целые числа."); _pause(); continue

            if not (1 <= ext_port <= 65535):
                _box_err("Внешний порт вне диапазона 1-65535."); _pause(); continue
            if ext_port == target_port:
                _box_err("Внешний порт не должен совпадать с основным."); _pause(); continue
            if not (88 <= mss <= 4096):
                _box_err("MSS вне диапазона 88-4096."); _pause(); continue
            if _port_in_use(ext_port):
                suggestion = _pick_free_port(ext_port + 1, target_port)
                hint = f" Свободный рядом: {suggestion}." if suggestion else ""
                _box_err(f"Порт {ext_port} уже занят другим процессом.{hint}")
                _pause(); continue

            cur_mss = _get_current_mss()
            if cur_mss:
                print()
                _box_warn(f"В конфиге задан client_mss = \"{cur_mss}\" — он спорит")
                _box_warn("с MSS-clamp для iOS-порта (два разных MSS на один сокет).")
                try:
                    confirm = _ask(f"  {CYAN}Убрать client_mss из конфига и продолжить? [Y/n]: {NC}",
                                    default="y", c=True).strip().lower()
                except _Cancelled:
                    continue
                if confirm not in ("y", ""):
                    _box_info("Отменено."); _pause(); continue
                if _strip_client_mss():
                    _box_ok("client_mss удалён из конфига.")

            new_cfg = IosFixConfig(enabled=True, ext_port=ext_port,
                                    target_port=target_port, mss=mss)
            ok, msg = _apply_rules(new_cfg)
            if not ok:
                print(); _box_err(msg); _pause(); continue

            _persist_rules()
            _save_state(new_cfg)
            _setup_ufw(ext_port)
            _run(["systemctl", "restart", _SERVICE_NAME])

            print()
            _box_ok(f"iOS-фикс включён: порт {ext_port} → {target_port}, MSS {mss}.")
            _box_ok("Сервис перезапущен.")
            _box_info(f"Выдайте iOS-пользователям ссылку с port={ext_port} вместо {target_port}.")
            _box_info("Secret и IP остаются прежними — меняется только порт в ссылке.")
            _pause()

        elif ch == "2":
            if not active and not cfg.enabled:
                _box_info("iOS-фикс уже не активен."); _pause(); continue
            removed = _remove_rules()
            _persist_rules()
            _save_state(IosFixConfig(enabled=False))
            _run(["systemctl", "restart", _SERVICE_NAME])
            print()
            if removed:
                _box_ok(f"Удалено правил: {removed}. iOS-фикс выключен.")
            else:
                _box_info("Правил для удаления не найдено — фикс уже выключен.")
            _box_ok("Сервис перезапущен.")
            _pause()

        elif ch in ("q", ""):
            break


# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        ios_fix_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}")
