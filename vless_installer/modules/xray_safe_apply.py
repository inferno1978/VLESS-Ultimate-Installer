"""
vless_installer/modules/xray_safe_apply.py
───────────────────────────────────────────────────────────────────────────────
Обёртка над _xray_safe_apply_config из _core.py: добавляет smoke-test
после успешного перезапуска Xray.

ВАЖНО: _core.py уже содержит полноценный _xray_safe_apply_config с:
  • xray -test барьером
  • автоматическим бэкапом
  • автооткатом при неудачном рестарте
  • ожиданием active до 15 сек

Этот модуль не дублирует эту логику — он добавляет smoke-test поверх.

Точка входа из _core.py:
    from vless_installer.modules.xray_safe_apply import xray_apply_with_smoke
    # Вызывается вместо прямого _xray_safe_apply_config() там, где нужен smoke-test
    ok = xray_apply_with_smoke(cfg_path=cfg)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, Optional

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


def xray_apply_with_smoke(
    cfg_path: Optional[Path] = None,
    *,
    service_restart: bool = True,
    _core_apply_fn: Optional[Callable] = None,
    _smoke_fn: Optional[Callable] = None,
    _emergency_restore_fn: Optional[Callable] = None,
) -> bool:
    """
    Применяет конфиг Xray через _xray_safe_apply_config (из _core.py),
    затем запускает smoke-test.

    Параметры:
        cfg_path              — путь к конфигу (None = автоопределение внутри _core)
        service_restart       — передаётся в _xray_safe_apply_config
        _core_apply_fn        — _xray_safe_apply_config из _core.py (передаётся при вызове)
        _smoke_fn             — smoke_test_xray из modules/smoke_test.py
        _emergency_restore_fn — do_emergency_restore из _core.py

    Пример вызова из _core.py:
        from vless_installer.modules.xray_safe_apply import xray_apply_with_smoke
        from vless_installer.modules.smoke_test      import smoke_test_xray
        ok = xray_apply_with_smoke(
            cfg_path=cfg,
            _core_apply_fn=_xray_safe_apply_config,
            _smoke_fn=smoke_test_xray,
            _emergency_restore_fn=do_emergency_restore,
        )
    """
    if _core_apply_fn is None:
        print(f'  {RED}xray_apply_with_smoke: _core_apply_fn не передан{NC}', file=sys.stderr)
        return False

    # Применяем конфиг через _core.py (test + backup + restart + rollback)
    kwargs: dict = {'service_restart': service_restart}
    if cfg_path is not None:
        ok = _core_apply_fn(cfg_path, **kwargs)
    else:
        ok = _core_apply_fn(**kwargs)

    if not ok:
        return False

    # Smoke-test после успешного apply
    if _smoke_fn is not None:
        _smoke_fn(_do_emergency_restore_fn=_emergency_restore_fn)

    return True
