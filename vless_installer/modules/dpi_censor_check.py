"""
vless_installer/modules/dpi_censor_check.py
───────────────────────────────────────────────────────────────────────────────
Обёртка над сторонним инструментом Runnin4ik/dpi-detector — диагностика
цензуры на стороне провайдера (TLS/TCP/HTTP/DNS-блокировки, обрыв
соединений на 16-20KB, подмена DNS-ответов).

ВАЖНО — не путать с vless_installer/modules/dpi_detector.py:
    dpi_detector.py (соседний модуль) — анализирует error.log Xray НА
    СЕРВЕРЕ и банит IP при активном зондировании (server-side защита).
    dpi_censor_check.py (этот файл) — проверяет, ЧТО блокирует провайдер
    СНАРУЖИ, в сторону произвольных доменов/IP (client-side диагностика).
    Это две разные сущности с похожими названиями — разные задачи,
    разный код, объединять не нужно.

Архитектура интеграции:
    Апстрим (httpx + rich + PyYAML, пакеты core/cli/utils, ~190 КБ) вендорится
    БЕЗ ИЗМЕНЕНИЙ в _vendor/dpi_detector/ (см. там VENDOR_INFO.md) и
    запускается как ОТДЕЛЬНЫЙ процесс через subprocess. Причины:
      • Изоляция: апстрим сам ставит signal-хендлер на SIGINT и вызывает
        os._exit() — в отдельном процессе это не заденет установщик.
      • Апстрим использует относительные импорты (from utils import config,
        from core.dns_scanner import ...) и резолвит свои файлы конфигурации
        через __file__ — корректно работает только как точка входа
        интерпретатора, а не как импортируемый пакет. Подмена этого на
        нормальные пакетные импорты означала бы переписывать апстрим —
        higher risk, никакой пользы.
      • Новые pip-зависимости (httpx, rich, PyYAML) не тянутся в основной
        интерпретатор установщика. Ставятся лениво — только когда
        пользователь реально открывает этот пункт меню.
      • Обновление апстрима = просто заменить файлы в _vendor/dpi_detector/.

Точка входа из _core.py:
    from vless_installer.modules.dpi_censor_check import do_dpi_censor_check_menu
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# ── Цвета (самодостаточно, как и в остальных модулях) ───────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'], _C['BLUE'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ── box_renderer (UI меню, общий для всех модулей установщика) ─────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_item, _box_back,
    _box_info, _box_warn, _box_row, _box_desc,
)

# ── Константы ─────────────────────────────────────────────────────────────────
_VENDOR_DIR = Path(__file__).resolve().parent / "_vendor" / "dpi_detector"
_ENTRY      = _VENDOR_DIR / "dpi_detector.py"
_REQS       = _VENDOR_DIR / "requirements.txt"
_LOG_FILE   = Path("/var/log/vless-install.log")
_REPORT_DIR = Path("/var/log/xray-installer/dpi-censor-reports")

# Имена пакетов для импорта (PyYAML импортируется как "yaml")
_REQUIRED_MODULES = ("httpx", "rich", "yaml")


def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] [{level}] [dpi_censor_check] {msg}\n")
    except Exception:
        pass


# ── Проверка/установка зависимостей ─────────────────────────────────────────────
def _deps_missing() -> List[str]:
    """Список недостающих пакетов. find_spec() не импортирует модуль —
    не тратит память основного процесса установщика на httpx/rich."""
    missing = []
    for mod in _REQUIRED_MODULES:
        try:
            found = importlib.util.find_spec(mod) is not None
        except Exception:
            found = False
        if not found:
            missing.append(mod)
    return missing


def _install_deps() -> bool:
    if not _REQS.exists():
        print(f"{RED}[ERR]{NC} requirements.txt не найден: {_REQS}")
        return False
    print(f"{CYAN}Устанавливаю зависимости (httpx, rich, PyYAML)...{NC}")
    cmd = [sys.executable, "-m", "pip", "install", "--break-system-packages",
           "-r", str(_REQS)]
    try:
        r = subprocess.run(cmd, timeout=300)
    except Exception as e:
        print(f"{RED}[ERR]{NC} Не удалось запустить pip: {e}")
        _log("ERROR", f"pip install не запустился: {e}")
        return False
    if r.returncode != 0:
        print(f"{RED}[ERR]{NC} pip install завершился с ошибкой (код {r.returncode}).")
        print(f"{DIM}Если PyPI недоступен из-за блокировок — попробуйте вручную:{NC}")
        print(f"{DIM}  {sys.executable} -m pip install --break-system-packages -r {_REQS}{NC}")
        _log("ERROR", f"pip install exit code {r.returncode}")
        return False
    _log("SUCCESS", "зависимости dpi-detector установлены")
    return True


def _ensure_deps() -> bool:
    missing = _deps_missing()
    if not missing:
        return True
    print()
    print(f"{YELLOW}Для запуска нужны пакеты: {', '.join(missing)}{NC}")
    try:
        ans = input(f"{CYAN}Установить через pip сейчас? [Y/n]:{NC} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if ans in ("n", "no", "н", "нет"):
        return False
    return _install_deps()


# ── Запуск вендоренного инструмента ─────────────────────────────────────────────
def _build_args(domains: Optional[List[str]], proxy: Optional[str],
                 output: Optional[str]) -> List[str]:
    args: List[str] = []
    if domains:
        for d in domains:
            args += ["-d", d]
    if proxy:
        args += ["-p", proxy]
    if output:
        args += ["-o", output]
    return args


def _run_vendor(args: List[str]) -> int:
    """Запускает _vendor/dpi_detector/dpi_detector.py отдельным процессом.
    stdin/stdout/stderr наследуются — апстрим сам рисует свой rich-интерфейс
    и сам ловит Ctrl+C (os._exit() в СВОЁМ процессе, установщик не задевает)."""
    cmd = [sys.executable, str(_ENTRY)] + args
    _log("INFO", f"запуск: {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd)
        return r.returncode
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"{RED}[ERR]{NC} Не удалось запустить dpi-detector: {e}")
        _log("ERROR", str(e))
        return 1


# ── Публичная точка входа ────────────────────────────────────────────────────────
def do_dpi_censor_check_menu() -> None:
    """Главное меню. Вызывается из _core.py."""
    if not _ENTRY.exists():
        print()
        _box_top("🔍  ПРОВЕРКА ЦЕНЗУРЫ ПРОВАЙДЕРА")
        _box_warn(f"Вендоренный dpi-detector не найден по пути:")
        _box_row(f"  {_ENTRY}")
        _box_info("См. _vendor/dpi_detector/VENDOR_INFO.md — переустановите модуль.")
        _box_bottom()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    os.system("clear")
    print()
    _box_top("🔍  ПРОВЕРКА ЦЕНЗУРЫ ПРОВАЙДЕРА  (Runnin4ik/dpi-detector)")
    _box_desc(
        "Сторонний инструмент: определяет блокировку TLS/TCP/HTTP/DNS, обрыв "
        "соединений на 16-20KB и подмену DNS-ответов провайдером. Не путать "
        "с пунктом «D» в разделе Безопасность — там анализ ИЗВНЕ, здесь — что "
        "блокирует провайдер."
    )
    _box_sep()
    _box_warn(
        "Если на этом сервере/клиенте уже работает zapret или GoodbyeDPI — "
        "результаты будут искажены. Отключите их перед проверкой."
    )
    _box_sep()
    _box_item("1", "🚀 Запустить (интерактивный выбор тестов, как у апстрима)")
    _box_item("2", "🌐 Проверить конкретные домены")
    _box_item("3", "🧦 Запустить через proxy (socks5/http)")
    _box_back()
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return

    if ch not in ("1", "2", "3"):
        return

    if not _ensure_deps():
        print(f"{YELLOW}Зависимости не установлены — запуск отменён.{NC}")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    domains: Optional[List[str]] = None
    proxy: Optional[str] = None

    if ch == "2":
        try:
            raw = input(f"{CYAN}Домены через пробел:{NC} ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        domains = raw.split() if raw else None
    elif ch == "3":
        try:
            proxy = input(
                f"{CYAN}Proxy URL (напр. socks5://127.0.0.1:1080):{NC} "
            ).strip() or None
        except (KeyboardInterrupt, EOFError):
            return

    try:
        save = input(f"{CYAN}Сохранить отчёт в файл? [y/N]:{NC} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        save = ""

    output = None
    if save in ("y", "yes", "д", "да"):
        try:
            _REPORT_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output = str(_REPORT_DIR / f"report_{ts}.txt")
        except Exception as e:
            print(f"{YELLOW}Не удалось создать {_REPORT_DIR}: {e}{NC}")
            output = None

    args = _build_args(domains, proxy, output)

    print()
    rc = _run_vendor(args)

    if output and Path(output).exists():
        print()
        _box_top("Отчёт сохранён")
        _box_row(f"  {output}")
        _box_bottom()
    elif rc not in (0, 130):
        print(f"{YELLOW}dpi-detector завершился с кодом {rc}.{NC}")

    input(f"\n{BLUE}Нажмите Enter...{NC}")


if __name__ == "__main__":
    # Автономный запуск для отладки модуля (вне установщика).
    do_dpi_censor_check_menu()
