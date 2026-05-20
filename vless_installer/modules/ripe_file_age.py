"""
vless_installer/modules/ripe_file_age.py
───────────────────────────────────────────────────────────────────────────────
Проверка актуальности RIPE-файла перед включением ingress-блокировки.

Зачем: при включении блокировки входящих скрипт берёт уже скачанный файл
без проверки его возраста. Если файлу 6 месяцев — блокировка работает по
устаревшим данным молча.

Точки входа из _core.py:
    from vless_installer.modules.ripe_file_age import (
        check_ripe_file_age,   # вызов перед apply — интерактивно
        ripe_file_age_banner,  # строка для вывода в меню
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

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

# ── Константы ─────────────────────────────────────────────────────────────────
DEFAULT_RIPE_PATH  = Path('/etc/xray/ru_subnets_ripe.txt')
WARN_DAYS          = 30   # предупреждение
CRITICAL_DAYS      = 90   # жёсткое предупреждение


# ── Публичный API ─────────────────────────────────────────────────────────────
def get_ripe_file_info(path: Optional[Path] = None) -> dict:
    """
    Возвращает информацию о файле RIPE-подсетей.
    dict-ключи: exists, age_days, size_bytes, stale, critical, mtime_str, path
    """
    import datetime
    p = path or DEFAULT_RIPE_PATH
    if not p.exists() or p.stat().st_size < 100:
        return dict(exists=False, age_days=None, size_bytes=p.stat().st_size
                    if p.exists() else 0, stale=True, critical=True,
                    mtime_str='—', path=str(p))
    stat      = p.stat()
    age_days  = int((time.time() - stat.st_mtime) / 86400)
    mtime_str = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
    return dict(exists=True, age_days=age_days, size_bytes=stat.st_size,
                stale=age_days > WARN_DAYS, critical=age_days > CRITICAL_DAYS,
                mtime_str=mtime_str, path=str(p))


def check_ripe_file_age(
    path: Optional[Path] = None,
    max_days: int = WARN_DAYS,
    interactive: bool = True,
) -> bool:
    """
    Проверяет актуальность RIPE-файла перед включением ingress-блокировки.

    Алгоритм:
      • Файл свежий (age ≤ max_days)        → True без вопросов
      • Файл устарел (max_days < age < 90)  → предупреждение + вопрос (interactive)
      • Файл критически устарел (age ≥ 90)  → жёсткое предупреждение + вопрос
      • Файл не существует / повреждён      → предупреждение, True (скачает сам _ingress_get_cidrs)
      • interactive=False                   → только вывод, всегда True (для cron)

    Возвращает True если можно продолжать, False если операция должна быть отменена.
    """
    info = get_ripe_file_info(path)

    if not info['exists']:
        size = info['size_bytes']
        if size > 0:
            print(f'\n  {RED}✗ RIPE-файл повреждён:{NC} {info["path"]} ({size} байт — слишком мало)')
        else:
            print(f'\n  {YELLOW}⚠  RIPE-файл не найден — будет скачан автоматически{NC}')
        return True   # _ingress_get_cidrs скачает сам

    age = info['age_days']

    if age <= max_days:
        print(f'  {GREEN}✓ RIPE-файл актуален:{NC} {info["mtime_str"]} ({age} дн.)')
        return True

    # Устаревший файл
    if info['critical']:
        level, verdict = RED, f'КРИТИЧЕСКИ устарел ({age} дней!)'
        advice = 'Данные не обновлялись более 90 дней — блокировка будет неточной.'
    else:
        level, verdict = YELLOW, f'устарел ({age} дней)'
        advice = f'Рекомендуется обновить (порог: {max_days} дней).'

    print()
    print(f'  {level}⚠  RIPE-файл {verdict}{NC}')
    print(f'  Файл:    {info["path"]}')
    print(f'  Изменён: {info["mtime_str"]}')
    print(f'  Размер:  {info["size_bytes"] // 1024} КБ')
    print(f'  {YELLOW}{advice}{NC}')
    print(f'  Обновить: выберите «Обновить список РФ подсетей» в меню.')

    if not interactive:
        return True   # не блокируем cron

    print()
    try:
        ans = input('  Продолжить с устаревшими данными? [y/N] ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = ''

    if ans in ('y', 'yes', 'д', 'да'):
        print(f'  {YELLOW}Продолжаем с устаревшими данными RIPE.{NC}')
        return True
    print(f'  {CYAN}Операция отменена. Сначала обновите RIPE-файл.{NC}')
    return False


def ripe_file_age_banner(path: Optional[Path] = None) -> str:
    """
    Однострочный баннер для вывода в меню/статусе.
    Пример: "RIPE-файл: 2025-01-15  (12 дн.)"
    """
    info = get_ripe_file_info(path)
    if not info['exists']:
        return f'{YELLOW}RIPE-файл: не найден{NC}'
    age, mtime = info['age_days'], info['mtime_str']
    if info['critical']:
        return f'{RED}RIPE: {mtime}  ({age} дней — КРИТИЧЕСКИ УСТАРЕЛ!){NC}'
    if info['stale']:
        return f'{YELLOW}RIPE: {mtime}  ({age} дней — устарел){NC}'
    return f'{GREEN}RIPE: {mtime}  ({age} дн.){NC}'
