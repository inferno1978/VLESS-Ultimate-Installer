"""
vless_installer/modules/ipset_persist.py
───────────────────────────────────────────────────────────────────────────────
Персистентность ipset через save/restore при перезагрузке.

Зачем: при reboot ipset пересоздаётся через _ingress_enable, который скачивает
файл подсетей заново. Если сеть недоступна при boot или файл повреждён —
блокировка молча не восстанавливается.

Решение:
  • ipset save после каждого apply → /etc/ipset.conf
  • xray-ipset-restore.service: ExecStart=ipset restore, Before=xray.service

Только сеты xray_ru_block / xray_ru_block6 — не трогаем WARP/временные сеты.

Точки входа из _core.py:
    from vless_installer.modules.ipset_persist import (
        ipset_save, ipset_restore_unit_install, ipset_restore_unit_remove,
        do_manage_ipset_persist,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m', NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'], _C['BOLD'], _C['DIM'], _C['NC'],
)

# ── Пути и константы ──────────────────────────────────────────────────────────
_IPSET_CONF     = Path('/etc/ipset.conf')
_RESTORE_SVC    = Path('/etc/systemd/system/xray-ipset-restore.service')
_RESTORE_LOG    = Path('/var/log/xray-ipset-restore.log')
_IPSET_SETS     = ('xray_ru_block', 'xray_ru_block6')


# ── Внутренние хелперы ────────────────────────────────────────────────────────
def _ok(msg: str)   -> None: print(f'  {GREEN}✓{NC} {msg}')
def _warn(msg: str) -> None: print(f'  {YELLOW}⚠{NC}  {msg}')
def _info(msg: str) -> None: print(f'  {CYAN}•{NC} {msg}')
def _err(msg: str)  -> None: print(f'  {RED}✗{NC} {msg}', file=sys.stderr)

def _run(cmd: list, quiet: bool = False) -> int:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if not quiet and r.returncode != 0 and r.stderr:
        _warn(r.stderr.strip()[:200])
    return r.returncode

def _ipset_available() -> bool:
    return subprocess.run(['which', 'ipset'], capture_output=True).returncode == 0

def _set_exists(name: str) -> bool:
    return subprocess.run(['ipset', 'list', '-n', name],
                         capture_output=True).returncode == 0

def _is_enabled(unit: str) -> bool:
    r = subprocess.run(['systemctl', 'is-enabled', unit], capture_output=True, text=True)
    return 'enabled' in r.stdout


# ── Публичный API ─────────────────────────────────────────────────────────────
def ipset_save() -> bool:
    """
    Сохраняет xray_ru_block и xray_ru_block6 в /etc/ipset.conf.
    Вызывается автоматически после _ingress_enable / _ingress_apply_ipset.
    Возвращает True при успехе.
    """
    if not _ipset_available():
        _warn('ipset не установлен — сохранение пропущено')
        return False

    existing = [s for s in _IPSET_SETS if _set_exists(s)]
    if not existing:
        _warn('ipset-сеты xray_ru_block не найдены — нечего сохранять')
        return False

    _info(f'Сохранение ipset → {_IPSET_CONF}...')
    lines: list[str] = []
    for name in existing:
        r = subprocess.run(['ipset', 'save', name], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            lines.append(r.stdout.strip())

    if not lines:
        _warn('ipset save вернул пустой результат')
        return False

    content = '\n'.join(lines) + '\n'
    try:
        _IPSET_CONF.write_text(content, encoding='utf-8')
        _IPSET_CONF.chmod(0o600)
    except Exception as e:
        _err(f'Не удалось записать {_IPSET_CONF}: {e}')
        return False

    entry_count = content.count('\nadd ')
    _ok(f'ipset сохранён: {_IPSET_CONF} (~{entry_count} записей)')
    return True


def ipset_restore_unit_install() -> bool:
    """
    Устанавливает xray-ipset-restore.service.
    Запускается Before=xray.service при каждом boot.
    ConditionPathExists=/etc/ipset.conf — без файла юнит молча пропускается.
    """
    if not _ipset_available():
        _warn('ipset не установлен — установка юнита пропущена')
        return False

    _RESTORE_SVC.write_text(textwrap.dedent(f"""\
        [Unit]
        Description=Restore ipset rules for Xray ingress blocking (VLESS Ultimate)
        Before=xray.service
        After=network-pre.target
        ConditionPathExists={_IPSET_CONF}

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/bin/bash -c 'ipset restore -! -f {_IPSET_CONF} 2>&1 | \\
            tee -a {_RESTORE_LOG} && \\
            echo "ipset restored: $(grep -c ^add {_IPSET_CONF} 2>/dev/null || echo 0) rules" \\
            >> {_RESTORE_LOG}'
        StandardOutput=journal
        StandardError=journal

        [Install]
        WantedBy=multi-user.target
    """))

    subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
    r = subprocess.run(['systemctl', 'enable', 'xray-ipset-restore.service'],
                       capture_output=True, text=True)
    if r.returncode != 0:
        _err(f'systemctl enable failed: {r.stderr.strip()[:200]}')
        return False

    _ok('xray-ipset-restore.service установлен и включён')
    _info('ipset восстанавливается при каждом boot до старта Xray')
    return True


def ipset_restore_unit_remove() -> None:
    """Удаляет юнит восстановления ipset."""
    subprocess.run(['systemctl', 'disable', 'xray-ipset-restore.service'],
                   capture_output=True)
    _RESTORE_SVC.unlink(missing_ok=True)
    subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
    _ok('xray-ipset-restore.service удалён')


def do_manage_ipset_persist() -> None:
    """Интерактивное меню управления персистентностью ipset."""
    import os
    while True:
        os.system('clear')
        enabled     = _is_enabled('xray-ipset-restore.service')
        conf_exists = _IPSET_CONF.exists()
        conf_entries = 0
        if conf_exists:
            try:
                conf_entries = _IPSET_CONF.read_text().count('\nadd ')
            except Exception:
                pass

        status_str = f'{GREEN}установлен{NC}' if enabled else f'{YELLOW}не установлен{NC}'
        conf_str   = (f'{GREEN}{_IPSET_CONF} ({conf_entries} записей){NC}'
                      if conf_exists else f'{YELLOW}отсутствует{NC}')

        print()
        print(f'  {CYAN}{"═"*56}{NC}')
        print(f'  {CYAN}  📦 IPSET PERSISTENT (восстановление при reboot){NC}')
        print(f'  {CYAN}{"─"*56}{NC}')
        print(f'  Юнит xray-ipset-restore:  {status_str}')
        print(f'  Файл /etc/ipset.conf:      {conf_str}')
        print()
        print(f'  {CYAN}{"─"*56}{NC}')
        if enabled:
            print(f'  1. Удалить юнит')
        else:
            print(f'  1. Установить юнит (восстановление при boot)')
        print(f'  2. Сохранить текущий ipset → /etc/ipset.conf')
        print(f'  3. Показать содержимое /etc/ipset.conf (первые 30 строк)')
        print(f'  Q. Назад')
        print(f'  {CYAN}{"═"*56}{NC}')
        print()

        try:
            ch = input(f'  {CYAN}Выбор:{NC} ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if ch == '1':
            if enabled:
                ipset_restore_unit_remove()
            else:
                if not conf_exists:
                    _warn('Сначала сохраните ipset (пункт 2) — иначе при boot нечего восстанавливать')
                ipset_restore_unit_install()
            input(f'  {CYAN}Нажмите Enter...{NC}')

        elif ch == '2':
            ipset_save()
            input(f'  {CYAN}Нажмите Enter...{NC}')

        elif ch == '3':
            print()
            if conf_exists:
                lines = _IPSET_CONF.read_text(errors='replace').splitlines()[:30]
                for line in lines:
                    print(f'    {DIM}{line}{NC}')
                if conf_entries > 30:
                    print(f'    {DIM}... ещё {conf_entries - 30} записей{NC}')
            else:
                _warn('Файл /etc/ipset.conf не существует')
            input(f'  {CYAN}Нажмите Enter...{NC}')

        elif ch in ('q', ''):
            break
