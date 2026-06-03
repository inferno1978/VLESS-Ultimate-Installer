"""
vless_installer/modules/hysteria2_auto_update.py
───────────────────────────────────────────────────────────────────────────────
Автообновление бинарника Hysteria2.

Логика:
  • Сравнивает текущую версию с latest из GitHub Releases API
  • При наличии обновления: скачивает, проверяет, заменяет атомарно
  • Перезапускает сервис только если он был активен
  • TG-уведомление об обновлении
  • Cron 1 раз в сутки

Точка входа из _core.py:
    from vless_installer.modules.hysteria2_auto_update import (
        h2_update_check, h2_update_apply, h2_autoupdate_install, do_h2_update_menu,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

from vless_installer.modules.hysteria2_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, _load_h2_state, _save_h2_state,
    _tg_h2_event, _service_active, _systemctl,
    _h2_binary_exists, _h2_binary_version,
    H2_BINARY, H2_SERVICE,
)
from vless_installer.modules.hysteria2_exit_mgr import (
    _detect_arch, _h2_latest_url,
)
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)


_UPDATE_CRON = Path("/etc/cron.d/hysteria2-autoupdate")
_TMP_BINARY  = Path("/tmp/hysteria2-update.bin")


def h2_update_check() -> dict:
    """
    Проверяет наличие новой версии бинарника.
    Возвращает {"current": "2.5.0", "latest": "2.6.0", "update_available": True}.
    """
    current = _h2_binary_version() if _h2_binary_exists() else ""
    try:
        url, latest_tag = _h2_latest_url()
        latest = latest_tag.lstrip("v")
    except Exception:
        latest = ""

    update_available = bool(latest and current != latest and latest)
    return {
        "current":          current,
        "latest":           latest,
        "update_available": update_available,
    }


def h2_update_apply(force: bool = False) -> bool:
    """
    Скачивает и устанавливает новую версию бинарника.
    Если force=False — проверяет необходимость обновления.
    """
    check = h2_update_check()
    if not check["update_available"] and not force:
        info(f"H2 уже актуален: v{check['current']}")
        return True

    was_active = _service_active(H2_SERVICE)
    info(f"Обновляю Hysteria2: {check['current'] or '—'} → {check['latest']}")

    try:
        url, tag = _h2_latest_url()
        r = _run(["curl", "-L", "--max-time", "90", "-o", str(_TMP_BINARY), url],
                 capture=True, timeout=120)
        if r.returncode != 0 or not _TMP_BINARY.exists():
            error("Не удалось скачать обновление")
            return False

        # Проверяем что скачанный файл исполняем
        _TMP_BINARY.chmod(0o755)
        v_check = _run([str(_TMP_BINARY), "version"], capture=True, timeout=10)
        if v_check.returncode != 0:
            error("Скачанный бинарник не запускается, откат")
            _TMP_BINARY.unlink(missing_ok=True)
            return False

        # Атомарная замена
        if was_active:
            _systemctl("stop", H2_SERVICE)
        shutil.move(str(_TMP_BINARY), str(H2_BINARY))
        H2_BINARY.chmod(0o755)

        if was_active:
            _systemctl("start", H2_SERVICE)
            time.sleep(2)

        new_ver = _h2_binary_version()
        success(f"Hysteria2 обновлён до v{new_ver}")
        _tg_h2_event("h2_update", f"Обновлён до v{new_ver}")
        log_to_file("INFO", f"H2 updated: {check['current']} → {new_ver}")

        # Обновляем версию в нодах
        h2    = _load_h2_state()
        nodes = h2.get("exit_nodes", [])
        for n in nodes:
            n["version"] = new_ver
        h2["exit_nodes"] = nodes
        _save_h2_state(h2)
        return True

    except Exception as e:
        error(f"Ошибка обновления: {e}")
        _TMP_BINARY.unlink(missing_ok=True)
        if was_active:
            _systemctl("start", H2_SERVICE)
        return False


def h2_autoupdate_install() -> None:
    """Устанавливает cron для ежесуточной проверки обновлений."""
    cron = "0 3 * * * root /usr/bin/python3 /opt/vless-installer/main.py --h2-autoupdate\n"
    _UPDATE_CRON.write_text(
        "# H2 AutoUpdate — VLESS Ultimate Installer\n" + cron
    )
    success(f"AutoUpdate cron → {_UPDATE_CRON}")
    log_to_file("INFO", "H2 autoupdate cron installed")


def h2_autoupdate_remove() -> None:
    if _UPDATE_CRON.exists():
        _UPDATE_CRON.unlink()
    success("AutoUpdate cron удалён")


def h2_autoupdate_cron() -> None:
    """Точка входа для cron --h2-autoupdate."""
    h2 = _load_h2_state()
    if not h2.get("auto_update", {}).get("enabled", True):
        return
    h2_update_apply(force=False)


# ── Меню ──────────────────────────────────────────────────────────────────────
def do_h2_update_menu() -> None:
    """Интерактивное меню AutoUpdate H2."""
    while True:
        os.system("clear")
        print()
        h2 = _load_h2_state()
        upd = h2.get("autoupdate", {})
        cur_ver = _h2_binary_version() if _h2_binary_exists() else "—"
        _box_top("⬆️  HYSTERIA2 — ОБНОВЛЕНИЕ БИНАРНИКА")
        _box_row(f"  Версия: {CYAN}{cur_ver}{NC}  │  Автообновление: {'вкл' if upd.get('enabled') else 'выкл'}  │  Последнее: {DIM}{upd.get('last_check','—')}{NC}")
        _box_sep()
        _box_row()

        check     = h2_update_check()
        cur_color = GREEN if not check["update_available"] else YELLOW
        print(f"  Текущая версия:  {cur_color}v{check['current'] or '—'}{NC}")
        print(f"  Последняя:       {CYAN}v{check['latest'] or '—'}{NC}")
        if check["update_available"]:
            print(f"  {GREEN}Доступно обновление!{NC}")
        else:
            print(f"  {DIM}Обновлений нет{NC}")

        h2      = _load_h2_state()
        au      = h2.get("auto_update", {})
        au_str  = f"{GREEN}включено{NC}" if au.get("enabled", True) else f"{DIM}выключено{NC}"
        cron_str = f"{GREEN}установлен{NC}" if _UPDATE_CRON.exists() else f"{RED}не установлен{NC}"
        print()
        print(f"  Автообновление: {au_str}  │  Cron: {cron_str}")
        print()
        _box_item("1", "Проверить наличие обновления")
        _box_item("2", "Обновить сейчас")
        _box_item("3", f"Принудительно переустановить  {DIM}(force){NC}")
        _box_item("4", f"Установить cron автообновления")
        _box_item("5", "Удалить cron автообновления")
        _box_item("6", "Вкл/Выкл автообновление")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "1":
            check = h2_update_check()
            if check["update_available"]:
                success(f"Доступно: v{check['latest']}")
            else:
                info("Версия актуальна")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            h2_update_apply()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            h2_update_apply(force=True)
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            h2_autoupdate_install()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            h2_autoupdate_remove()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            h2 = _load_h2_state()
            cur = h2.get("auto_update", {}).get("enabled", True)
            h2.setdefault("auto_update", {})["enabled"] = not cur
            _save_h2_state(h2)
            success(f"Автообновление {'включено' if not cur else 'выключено'}")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "Q":
            break
        else:
            time.sleep(0.5)


"""
ПРИМЕР ВЫЗОВА из _core.py / main.py:
    from vless_installer.modules.hysteria2_auto_update import (
        h2_update_check, h2_update_apply, h2_autoupdate_install,
        h2_autoupdate_cron, do_h2_update_menu,
    )

    # CLI --h2-autoupdate (из cron):
    h2_autoupdate_cron()

    # Вручную:
    check = h2_update_check()
    if check["update_available"]:
        h2_update_apply()

    # Интерактивно:
    do_h2_update_menu()
"""
