"""
vless_installer/modules/hysteria2_menu.py
───────────────────────────────────────────────────────────────────────────────
Главное меню «Управление транспортом Hysteria2».

Вызывается из _core.py одним вызовом:
    from vless_installer.modules.hysteria2_menu import do_hysteria2_menu
    do_hysteria2_menu()

Стиль меню идентичен остальным разделам _core.py (box_renderer).
Ни один существующий файл не изменяется.

Подменю:
  1  Exit-нода    (hysteria2_exit_mgr.do_h2_exit_menu)
  2  Транспорт    (hysteria2_transport.h2_select_transport)
  3  Балансировщик(hysteria2_balancer.do_h2_balancer_menu)
  4  Health Check (hysteria2_health.do_h2_health_menu)
  5  Watchdog     (hysteria2_watchdog.do_h2_watchdog_menu)
  6  Трафик       (hysteria2_traffic.do_h2_traffic_menu)
  7  Сертификаты  (hysteria2_cert_mgr.do_h2_cert_menu)
  8  Обновление   (hysteria2_auto_update.do_h2_update_menu)
  9  Кластер      (hysteria2_cluster.do_h2_cluster_menu)
  B  Бэкап        (hysteria2_backup.do_h2_backup_menu)
  D  DPI детектор (hysteria2_dpi.do_h2_dpi_menu)
  Q  Качество     (hysteria2_quality.do_h2_quality_menu)
  S  Smoke Test   (hysteria2_smoke_test.do_h2_smoke_test_menu)
  L  Логи H2
  0  ← Назад
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back, _box_desc,
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, WHITE, NC,
)
from vless_installer.modules.hysteria2_common import (
    info, success, warn, error,
    _load_h2_state, _ensure_h2_state,
    _service_active, _h2_binary_version, _h2_binary_exists,
    H2_SERVICE,
)


def _h2_status_line() -> str:
    """Возвращает однострочный статус H2 для шапки меню."""
    h2        = _load_h2_state()
    enabled   = h2.get("enabled", False)
    active    = _service_active(H2_SERVICE)
    ver       = _h2_binary_version() if _h2_binary_exists() else "—"
    nodes     = h2.get("exit_nodes", [])
    n_live    = sum(1 for n in nodes if n.get("status") == "active")
    n_total   = len(nodes)
    transport = h2.get("active_transport", "—")

    if not enabled:
        return f"{YELLOW}не установлен{NC}"

    svc_col = GREEN if active else RED
    svc_str = f"{svc_col}{'активен' if active else 'DOWN'}{NC}"
    return (
        f"v{ver}  │  Сервис: {svc_str}  │  "
        f"Ноды: {GREEN}{n_live}{NC}/{n_total}  │  "
        f"Транспорт: {CYAN}{transport}{NC}"
    )


def do_hysteria2_menu() -> None:
    """
    Главное интерактивное меню Hysteria2.
    Вызывается из _core.py → main_menu().
    """
    _ensure_h2_state()

    while True:
        os.system("clear")
        print()
        _box_top("🚀  HYSTERIA2 — УПРАВЛЕНИЕ ТРАНСПОРТОМ")
        _box_row(f"  {DIM}{_h2_status_line()}{NC}")
        _box_sep()

        # ── Конфигурация ──────────────────────────────────────────────────────
        _box_row()
        _box_item("1", f"🖥️  Exit-нода           {DIM}Установка/управление H2 сервером{NC}")
        _box_item("2", f"🔀 Выбор транспорта     {DIM}AWG / Hysteria2 / Оба + веса{NC}")
        _box_item("3", f"⚖️  Балансировщик нод    {DIM}Стратегия, веса, автопереключение{NC}")
        _box_row()
        _box_sep()

        # ── Мониторинг ────────────────────────────────────────────────────────
        _box_row()
        _box_item("4", f"🩺 Health Check         {DIM}QUIC-пинг, RTT, потери{NC}")
        _box_item("5", f"🔄 Watchdog             {DIM}Авторестарт при падении{NC}")
        _box_item("6", f"📊 Трафик               {DIM}RX/TX через iptables/ss{NC}")
        _box_item("Q", f"📈 Качество соединения  {DIM}RTT/потери/скорость + TG-отчёт{NC}")
        _box_row()
        _box_sep()

        # ── Инфраструктура ────────────────────────────────────────────────────
        _box_row()
        _box_item("7", f"🔒 Сертификаты          {DIM}certbot / самоподписанный + мониторинг{NC}")
        _box_item("8", f"⬆️  Обновление           {DIM}Автообновление бинарника H2{NC}")
        _box_item("9", f"🖧  Кластер SSH          {DIM}Управление несколькими Exit-нодами{NC}")
        _box_item("B", f"💾 Бэкап                {DIM}Резервное копирование + миграция из AWG{NC}")
        _box_row()
        _box_sep()

        # ── Диагностика ───────────────────────────────────────────────────────
        _box_row()
        _box_item("D", f"🔍 DPI Детектор         {DIM}Тест блокировки UDP + авто-фолбэк порта{NC}")
        _box_item("S", f"🔬 Smoke Test           {DIM}Полная проверка после установки{NC}")
        _box_item("L", f"📋 Логи H2              {DIM}Просмотр /var/log/hysteria.log{NC}")
        _box_row()
        _box_item_exit("0", "← Назад в главное меню")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch in ("0", ""):
            break
        elif ch == "1":
            try:
                from vless_installer.modules.hysteria2_exit_mgr import do_h2_exit_menu
                do_h2_exit_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "2":
            try:
                from vless_installer.modules.hysteria2_transport import h2_select_transport
                h2_select_transport()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "3":
            try:
                from vless_installer.modules.hysteria2_balancer import do_h2_balancer_menu
                do_h2_balancer_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "4":
            try:
                from vless_installer.modules.hysteria2_health import do_h2_health_menu
                do_h2_health_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "5":
            try:
                from vless_installer.modules.hysteria2_watchdog import do_h2_watchdog_menu
                do_h2_watchdog_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "6":
            try:
                from vless_installer.modules.hysteria2_traffic import do_h2_traffic_menu
                do_h2_traffic_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "7":
            try:
                from vless_installer.modules.hysteria2_cert_mgr import do_h2_cert_menu
                do_h2_cert_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "8":
            try:
                from vless_installer.modules.hysteria2_auto_update import do_h2_update_menu
                do_h2_update_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "9":
            try:
                from vless_installer.modules.hysteria2_cluster import do_h2_cluster_menu
                do_h2_cluster_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "B":
            try:
                from vless_installer.modules.hysteria2_backup import do_h2_backup_menu
                do_h2_backup_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "D":
            try:
                from vless_installer.modules.hysteria2_dpi import do_h2_dpi_menu
                do_h2_dpi_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "Q":
            try:
                from vless_installer.modules.hysteria2_quality import do_h2_quality_menu
                do_h2_quality_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "S":
            try:
                from vless_installer.modules.hysteria2_smoke_test import do_h2_smoke_test_menu
                do_h2_smoke_test_menu()
            except ImportError as e:
                error(f"Модуль недоступен: {e}"); time.sleep(2)
        elif ch == "L":
            _show_h2_logs()
        else:
            warn("Неверный выбор")
            time.sleep(0.8)


def _show_h2_logs() -> None:
    """Показывает последние строки логов H2."""
    log_paths = [
        Path("/var/log/hysteria.log"),
        Path("/var/log/hysteria-watchdog.log"),
        Path("/var/log/hysteria-health.log"),
    ]
    os.system("clear")
    print()
    _box_top("📋  ЛОГИ HYSTERIA2")
    found = False
    for lp in log_paths:
        if lp.exists():
            found = True
            _box_row(f"  {CYAN}{lp}{NC}")
            _box_sep()
            from vless_installer.modules.hysteria2_common import _run
            r = _run(["tail", "-n", "20", str(lp)], capture=True)
            for line in (r.stdout or "(пуст)").splitlines():
                _box_row(f"  {DIM}{line}{NC}")
            _box_row()
    if not found:
        _box_row(f"  {YELLOW}Лог-файлы не найдены{NC}")
        _box_row()
    _box_item_exit("0", "← Назад")
    _box_bottom()
    try:
        input(f"{CYAN}Нажмите Enter...{NC}")
    except KeyboardInterrupt:
        pass
