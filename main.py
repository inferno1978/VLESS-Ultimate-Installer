#!/usr/bin/env python3
"""
VLESS Ultimate Installer v4.11.3 — Entry Point
=============================================
Запуск: sudo python3 main.py

Этот файл — тонкая обёртка. Вся логика находится в vless_installer/_core.py.
"""

import sys
import os
import json
from pathlib import Path

# =============================================================================
#  Загружаем весь код установщика из монолита
# =============================================================================
# Используем exec чтобы _core.py выполнился в глобальном пространстве имён —
# так все его переменные, функции и monkey-patch input() работают точно так же
# как в оригинальном install.py
_core_path = Path(__file__).parent / "vless_installer" / "_core.py"
with open(_core_path, encoding="utf-8") as _f:
    _core_src = _f.read()

exec(compile(_core_src, str(_core_path), "exec"), globals())  # noqa: S102

# =============================================================================
#  Точка входа (перенесена из оригинального if __name__ == "__main__":)
# =============================================================================

# --- Headless переключение режима (вызывается из auto-fallback cron) ---
if "--switch-mode-a" in sys.argv or "--switch-mode-b" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    _init_pkg_mgr()
    target = "A" if "--switch-mode-a" in sys.argv else "B"
    if not STATE_FILE.exists():
        print("ERROR: state.json не найден", file=sys.stderr)
        sys.exit(1)
    try:
        _st = json.loads(STATE_FILE.read_text())
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    current = _st.get("install_mode", "A")
    if current == target:
        log_to_file("INFO", f"--switch-mode-{target.lower()}: режим уже {target}, пропуск.")
        sys.exit(0)
    import builtins as _builtins
    _orig_input = _builtins.input
    _builtins.input = lambda _="": "y"
    try:
        switch_mode_ab()
    finally:
        _builtins.input = _orig_input
    sys.exit(0)

# --- Режим ежесуточного обновления РФ подсетей ---
if "--update-ru-subnets" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    _ru_subnets_cli_update()
    sys.exit(0)

# --- Режим ежесуточного обновления AS-direct префиксов ---
if "--update-as-direct" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    _as_direct_cli_update()
    sys.exit(0)

# --- Сброс SQLite-кэша ASN-префиксов ---
if "--clear-asn-cache" in sys.argv:
    idx = sys.argv.index("--clear-asn-cache")
    target = sys.argv[idx + 1].strip() if idx + 1 < len(sys.argv) else "all"
    if target.lower() in ("all", ""):
        try:
            if ASN_CACHE_DB.exists():
                conn = _asn_cache_connect()
                rows = conn.execute("SELECT key FROM prefix_cache").fetchall()
                conn.execute("DELETE FROM prefix_cache")
                conn.commit()
                conn.close()
                print(f"[ASN кэш] Удалено {len(rows)} записей из {ASN_CACHE_DB}")
            else:
                print("[ASN кэш] БД не существует — нечего сбрасывать")
        except Exception as e:
            print(f"[ASN кэш] Ошибка: {e}", file=sys.stderr)
            sys.exit(1)
    elif target.lower() in ("ru", "ru_delegated"):
        _asn_cache_delete("ru_delegated")
        print("[ASN кэш] Удалена запись 'ru_delegated'")
    else:
        asn = target.upper()
        if not asn.startswith("AS"):
            asn = f"AS{asn}"
        key = f"asn:{asn}"
        _asn_cache_delete(key)
        print(f"[ASN кэш] Удалена запись '{key}'")
    sys.exit(0)

# --- DPI-детектор (из cron каждые 5 мин) ---
if "--dpi-check" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    n = _dpi_run_once()
    if n:
        print(f"[DPI] Заблокировано: {n}")
    sys.exit(0)

# --- Smart Balancer (из cron каждые N минут) ---
if "--smart-balance" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    if not _awg_guard_cron("SmartBalancer"):
        _smart_balancer_run_once()
    sys.exit(0)

# --- Pinned-нода: проверка доступности и авто-fallback (из cron) ---
if "--pinned-fallback-check" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    if _awg_guard_cron("PinnedFallback"):
        sys.exit(0)
    if STATE_FILE.exists():
        try:
            _st = json.loads(STATE_FILE.read_text())
            CHAIN_NODES             = _st.get("chain_nodes", [])
            CHAIN_PINNED_NODE_INDEX = _st.get("chain_pinned_node_index", -1)
            INSTALL_MODE            = _st.get("install_mode", "A")
            CHAIN_BALANCER_STRATEGY = _st.get("chain_balancer_strategy", "roundRobin")
        except Exception:
            pass
    switched = _pinned_node_check_and_fallback()
    if switched:
        print("[PINNED-FALLBACK] Нода заменена — см. /var/log/xray-auto-fallback.log")
    sys.exit(0)

# --- Быстрый статус без меню ---
if "--status" in sys.argv:
    _init_pkg_mgr()
    do_quick_status()
    sys.exit(0)

# --- Разовый авто-бан (из cron) ---
if "--autoban" in sys.argv:
    if os.geteuid() != 0:
        sys.exit(1)
    _autoban_run_once()
    sys.exit(0)

# --- Автоматический бэкап по расписанию (вызывается из cron) ---
if "--scheduled-backup" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    _scheduled_backup_run()
    sys.exit(0)

# --- Отправка TG-уведомления (вызывается из bash-скриптов watchdog и autoupdate) ---
if "--tg-event" in sys.argv:
    idx = sys.argv.index("--tg-event")
    if idx + 2 < len(sys.argv):
        _tg_notify_event(sys.argv[idx + 1], sys.argv[idx + 2])
    elif idx + 1 < len(sys.argv):
        _tg_notify_event(sys.argv[idx + 1])
    sys.exit(0)

# --- Проверка TTL-пользователей (из cron каждые 30 мин) ---
if "--ttl-check" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    removed = _ttl_check_and_expire()
    if removed:
        print(f"[TTL] Удалено {removed} пользователей с истёкшим сроком")
    else:
        print("[TTL] Истёкших пользователей нет")
    sys.exit(0)

# --- Обновление ingress GeoIP блокировки (из cron еженедельно) ---
if "--ingress-geoip-update" in sys.argv:
    if os.geteuid() != 0:
        print("ERROR: требуются права root", file=sys.stderr)
        sys.exit(1)
    _st = _ingress_state_load()
    if not _st.get("enabled"):
        print("[ingress-geoip] Блокировка не включена — пропуск")
        sys.exit(0)
    port = _st.get("port", 443)
    print(f"[ingress-geoip] Обновляю РФ-подсети, порт {port}...")
    _ingress_remove()
    _ingress_enable(port)
    print("[ingress-geoip] Готово")
    sys.exit(0)

# =============================================================================
#  ОСНОВНОЙ ИНТЕРАКТИВНЫЙ ЗАПУСК
# =============================================================================
import time as _time
from datetime import datetime as _datetime

_CHECKPOINT_FILE = Path("/var/lib/xray-installer/checkpoint.json")

def _checkpoint_save(stage: str) -> None:
    try:
        _CHECKPOINT_FILE.write_text(json.dumps({
            "stage": stage,
            "ts":    _datetime.now().isoformat(),
        }))
    except Exception:
        pass

def _checkpoint_load() -> dict:
    try:
        if _CHECKPOINT_FILE.exists():
            return json.loads(_CHECKPOINT_FILE.read_text())
    except Exception:
        pass
    return {}

def _checkpoint_clear() -> None:
    try:
        _CHECKPOINT_FILE.unlink(missing_ok=True)
    except Exception:
        pass

_MAX_RETRIES = 5

for _attempt in range(_MAX_RETRIES + 1):
    try:
        if _attempt == 0:
            _init_pkg_mgr()

            if os.geteuid() != 0:
                die(f"Запустите от root: sudo python3 {sys.argv[0]}")

            _checkpoint_save("ensure_startup_dependencies")
            ensure_startup_dependencies()

            print_banner()
            print()
            _cc, _cn, _flag = get_server_country_cached()
            info(f"VLESS Ultimate Installer v4.11.3 | RAM: {TOTAL_RAM}MB | CPU: {TOTAL_CPU} | {_flag} {_cn} ({_cc})")
            print()
            _time.sleep(1)

        else:
            print()
            info(f"Повторная попытка после установки пакета (попытка {_attempt}/{_MAX_RETRIES})...")
            print()

        _checkpoint_save("main_menu")
        main_menu()
        _checkpoint_clear()
        break

    except KeyboardInterrupt:
        print()
        print(f"{GREEN}До свидания! 👋{NC}")
        log_to_file("INFO", "Скрипт завершён пользователем (Ctrl+C)")
        _checkpoint_clear()
        sys.exit(0)

    except FileNotFoundError as _fnf:
        _recovered = _smart_recover(_fnf)
        if not _recovered:
            print()
            print(f"{RED}Восстановление невозможно. Скрипт остановлен.{NC}")
            print(f"{DIM}Лог: {LOG_FILE}{NC}")
            sys.exit(1)
        print()
        print(f"{CYAN}{'═'*64}{NC}")
        print(f"{CYAN}  Пакет установлен. Как продолжить?{NC}")
        print(f"{CYAN}{'═'*64}{NC}")
        print(f"  {DIM}[{NC}{WHITE}{BOLD}C{NC}{DIM}]{NC}  {GREEN}Продолжить с текущего места{NC}")
        print(f"  {DIM}[{NC}{WHITE}{BOLD}R{NC}{DIM}]{NC}  Начать установку заново (с нуля)")
        print(f"  {DIM}[{NC}{RED}{BOLD}Q{NC}{DIM}]{NC}  Выйти")
        print()
        try:
            _cont = input(f"{CYAN}  Выбор [C/R/Q]:{NC} ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            _cont = "Q"

        if _cont == "Q":
            print(f"{YELLOW}Выход.{NC}")
            sys.exit(1)
        elif _cont == "R":
            info("Перезапуск установки с нуля...")
            _checkpoint_clear()
            os.execv(sys.executable, [sys.executable] + sys.argv)
        else:
            info("Продолжаю с текущего места...")
            continue

    except SystemExit:
        raise

    except Exception as _exc:
        import traceback as _tb
        print()
        print(f"{RED}[CRITICAL]{NC} Неожиданная ошибка: {_exc}")
        print(f"{DIM}{_tb.format_exc()}{NC}")
        log_to_file("ERROR", f"Неожиданная ошибка: {_exc}\n{_tb.format_exc()}")
        print(f"{DIM}Лог: {LOG_FILE}{NC}")
        sys.exit(1)

else:
    print()
    print(f"{RED}[ERROR]{NC} Исчерпан лимит авто-восстановлений ({_MAX_RETRIES}).")
    print(f"{YELLOW}[HINT]{NC}  Запустите: ensure_startup_dependencies() вручную или")
    print(f"         проверьте лог: {LOG_FILE}")
    sys.exit(1)
