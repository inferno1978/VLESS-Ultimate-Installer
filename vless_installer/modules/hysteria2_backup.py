"""
vless_installer/modules/hysteria2_backup.py
───────────────────────────────────────────────────────────────────────────────
Бэкап конфигурации Hysteria2.

Включает в существующий бэкап проекта:
  • /etc/hysteria/config.yaml
  • /etc/xray/hysteria.crt + hysteria.key
  • Секцию hysteria2 из state.json

Также поддерживает:
  • Автономный бэкап в /var/backups/vless-installer/
  • Миграционный скрипт AWG → H2

Точка входа из _core.py:
    from vless_installer.modules.hysteria2_backup import (
        h2_backup_create, h2_backup_list, h2_backup_restore,
        do_h2_backup_menu,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tarfile
import time
from datetime import datetime
from pathlib import Path

from vless_installer.modules.hysteria2_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, _load_h2_state, _save_h2_state,
    H2_CONFIG_DIR, H2_CONFIG_FILE, H2_CERT_FILE, H2_KEY_FILE,
)
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)


_BACKUP_DIR = Path("/var/backups/vless-installer")
_BACKUP_PREFIX = "h2_backup"

# Файлы для включения в бэкап H2
_H2_FILES = [
    H2_CONFIG_FILE,
    H2_CERT_FILE,
    H2_KEY_FILE,
    Path("/etc/systemd/system/hysteria-server.service"),
    Path("/var/lib/xray-installer/state.json"),
]


def h2_backup_create(tag: str = "") -> Optional[Path]:
    """
    Создаёт tar.gz бэкап конфигов H2.
    Возвращает путь к созданному архиву или None при ошибке.
    """
    from typing import Optional
    _BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix  = f"_{tag}" if tag else ""
    archive = _BACKUP_DIR / f"{_BACKUP_PREFIX}{suffix}_{ts}.tar.gz"

    existing = [f for f in _H2_FILES if f.exists()]
    if not existing:
        warn("Нечего бэкапить — H2 конфиги не найдены")
        return None

    try:
        with tarfile.open(str(archive), "w:gz") as tar:
            for f in existing:
                tar.add(str(f), arcname=str(f).lstrip("/"))

            # Добавляем только секцию hysteria2 из state.json отдельно
            h2 = _load_h2_state()
            import tempfile, json
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                             delete=False) as tmp:
                json.dump({"hysteria2": h2}, tmp, indent=2, ensure_ascii=False)
                tmp_path = tmp.name
            tar.add(tmp_path, arcname="hysteria2_state_section.json")
            Path(tmp_path).unlink(missing_ok=True)

        archive.chmod(0o600)
        success(f"Бэкап создан → {archive}")
        log_to_file("INFO", f"H2 backup: {archive}")
        return archive
    except Exception as e:
        error(f"Ошибка создания бэкапа: {e}")
        return None


def h2_backup_list() -> list[Path]:
    """Возвращает список существующих H2-бэкапов (новые первыми)."""
    if not _BACKUP_DIR.exists():
        return []
    files = sorted(
        _BACKUP_DIR.glob(f"{_BACKUP_PREFIX}*.tar.gz"),
        key=lambda p: p.stat().st_mtime, reverse=True,
    )
    return files


def h2_backup_restore(archive: Path) -> bool:
    """Восстанавливает конфиги H2 из указанного архива."""
    if not archive.exists():
        error(f"Архив не найден: {archive}")
        return False

    try:
        with tarfile.open(str(archive), "r:gz") as tar:
            tar.extractall("/")   # пути хранятся без leading /

        # Перезапускаем сервис если он был активен
        from vless_installer.modules.hysteria2_common import _service_active, _systemctl, H2_SERVICE
        if _service_active(H2_SERVICE):
            _systemctl("restart", H2_SERVICE)

        success(f"Конфиги восстановлены из {archive.name}")
        log_to_file("INFO", f"H2 backup restored: {archive}")
        return True
    except Exception as e:
        error(f"Ошибка восстановления: {e}")
        return False


def h2_backup_cleanup(keep: int = 5) -> int:
    """Удаляет старые бэкапы, оставляет последние keep штук."""
    files   = h2_backup_list()
    to_del  = files[keep:]
    for f in to_del:
        try:
            f.unlink()
        except Exception:
            pass
    if to_del:
        info(f"Удалено {len(to_del)} старых бэкапов H2")
    return len(to_del)


def h2_backup_include_in_main() -> list[str]:
    """
    Возвращает список путей для включения в основной бэкап проекта.
    Вызывается из _core.py в do_backup() без изменения существующей логики.
    """
    paths = []
    for f in _H2_FILES:
        if f.exists():
            paths.append(str(f))
    if H2_CONFIG_DIR.exists():
        paths.append(str(H2_CONFIG_DIR))
    return paths


# ── Миграционный скрипт AWG → H2 ─────────────────────────────────────────────
def h2_migrate_from_awg() -> dict:
    """
    Копирует базовые настройки AWG как отправную точку для H2.
    AWG конфиги остаются нетронутыми — аддитивная миграция.
    Возвращает предзаполненный h2_state на основе AWG.
    """
    try:
        from vless_installer.modules.hysteria2_common import STATE_FILE
        st = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    except Exception:
        st = {}



    awg_host = st.get("awg_exit_host", "")
    awg_port = st.get("awg_exit_port", 51820)

    h2_state = _load_h2_state()
    if awg_host and awg_host not in [n.get("ip") for n in h2_state.get("exit_nodes", [])]:
        h2_state.setdefault("exit_nodes", []).append({
            "ip":     awg_host,
            "ports":  [443],
            "auth":   "",   # будет заполнен при установке H2
            "weight": 1.0,
            "status": "pending",
            "ipstack": "ipv4",
            "version": "",
            "metrics": {"rtt_ms": 0, "loss_pct": 0.0, "speed_mbps": 0},
            "_migrated_from_awg": True,
        })
        info(f"Добавлена нода из AWG конфига: {awg_host}")

    return h2_state


# ── Меню ──────────────────────────────────────────────────────────────────────
def do_h2_backup_menu() -> None:
    """Интерактивное меню бэкапа H2."""
    while True:
        os.system("clear")
        print()
        backups = _list_backups()
        _box_top("💾  HYSTERIA2 — БЭКАП КОНФИГУРАЦИИ")
        if backups:
            _box_row(f"  Бэкапов: {CYAN}{len(backups)}{NC}  │  Последний: {DIM}{backups[0].name}{NC}  ({int(backups[0].stat().st_size/1024)} KB)")
        else:
            _box_row(f"  {YELLOW}Бэкапов нет{NC}")
        _box_sep()
        _box_row()

        backups = h2_backup_list()
        print(f"  Директория бэкапов: {_BACKUP_DIR}")
        print(f"  Существующих бэкапов: {CYAN}{len(backups)}{NC}")
        if backups:
            print(f"  Последний: {DIM}{backups[0].name}{NC}  "
                  f"({_fmt_size(backups[0].stat().st_size)})")
        print()
        _box_item("1", "Создать бэкап сейчас")
        _box_item("2", "Список бэкапов")
        _box_item("3", "Восстановить из бэкапа")
        _box_item("4", f"Очистить старые  {DIM}(оставить 5){NC}")
        _box_item("5", "Миграция: перенести Exit-ноду из AWG")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "1":
            h2_backup_create()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            backups = h2_backup_list()
            print()
            if not backups:
                warn("  Бэкапов нет")
            for i, b in enumerate(backups, 1):
                ts = datetime.fromtimestamp(b.stat().st_mtime).strftime("%d.%m %H:%M")
                _box_row(f"  {CYAN}{i:>2}{NC}. {b.name}  {DIM}{ts}  {_fmt_size(b.stat().st_size)}{NC}")
            input(f"\n{CYAN}Нажмите Enter...{NC}")
        elif ch == "3":
            backups = h2_backup_list()
            if not backups:
                warn("Нет бэкапов для восстановления")
                input(f"\n{CYAN}Нажмите Enter...{NC}")
                continue
            print()
            for i, b in enumerate(backups, 1):
                _box_row(f"  {CYAN}{i}{NC}  {b.name}")
            try:
                idx = int(input(f"  {CYAN}Номер:{NC} ").strip()) - 1
            except (KeyboardInterrupt, ValueError):
                continue
            if 0 <= idx < len(backups):
                h2_backup_restore(backups[idx])
            input(f"\n{CYAN}Нажмите Enter...{NC}")
        elif ch == "4":
            n = h2_backup_cleanup()
            info(f"Удалено: {n}")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            h2 = h2_migrate_from_awg()
            _save_h2_state(h2)
            success("Миграция из AWG завершена")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "Q":
            break
        else:
            time.sleep(0.5)


def _fmt_size(b: int) -> str:
    for u in ("B", "KB", "MB"):
        if b < 1024:
            return f"{b:.1f}{u}"
        b //= 1024
    return f"{b}MB"


"""
ПРИМЕР ВЫЗОВА из _core.py:
    from vless_installer.modules.hysteria2_backup import (
        h2_backup_create, h2_backup_include_in_main,
        h2_migrate_from_awg, do_h2_backup_menu,
    )

    # Включить H2-файлы в основной бэкап (добавить в список BACKUP_FILES):
    extra = h2_backup_include_in_main()   # → ["/etc/hysteria/...", ...]

    # Автономный бэкап:
    h2_backup_create(tag="before_update")

    # Миграция AWG → H2:
    h2_migrate_from_awg()

    # Интерактивно:
    do_h2_backup_menu()
"""
