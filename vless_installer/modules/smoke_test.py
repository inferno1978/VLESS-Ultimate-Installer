"""
vless_installer/modules/smoke_test.py
───────────────────────────────────────────────────────────────────────────────
Автоматическая диагностика после apply-операций.

Точка входа из _core.py:
    from vless_installer.modules.smoke_test import smoke_test_xray
    smoke_test_xray()

Принципы:
  • Только stdlib — socket, ssl, json, time
  • Самодостаточные цвета (как в mtproto.py)
  • Читает параметры из state.json сам
  • Не падает с исключением — все ошибки выводятся и возвращается False
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import socket
import ssl
import sys
import time
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

# ── Константы ─────────────────────────────────────────────────────────────────
_STATE_FILE = Path('/var/lib/xray-installer/state.json')


# ── Чтение state.json ─────────────────────────────────────────────────────────
def _read_state() -> dict:
    try:
        return json.loads(_STATE_FILE.read_text()) if _STATE_FILE.exists() else {}
    except Exception:
        return {}


# ── TCP connect ───────────────────────────────────────────────────────────────
def _tcp_connect(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ''
    except socket.timeout:
        return False, f'timeout {timeout}s'
    except ConnectionRefusedError:
        return False, 'connection refused — Xray не слушает порт'
    except OSError as e:
        return False, str(e)


# ── TLS handshake ─────────────────────────────────────────────────────────────
def _tls_handshake(host: str, port: int, timeout: float,
                   sni: Optional[str] = None) -> tuple[bool, str]:
    """
    Проверяет TLS handshake. Не валидирует сертификат — Reality использует
    кастомный fingerprint, сертификат может быть самоподписанным.
    SSLError типа 'alert' означает что сервер ОТВЕТИЛ — это SUCCESS.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=sni or host) as tls:
            _ = tls.version()
        return True, ''
    except socket.timeout:
        return False, f'TLS timeout {timeout}s'
    except ssl.SSLError as e:
        msg = str(e).lower()
        # Сервер ответил — handshake состоялся, Reality отбросил неверный fingerprint
        if any(x in msg for x in ('alert', 'handshake', 'certificate',
                                   'unknown ca', 'unsupported protocol')):
            return True, f'сервер ответил ({str(e)[:60]})'
        return False, f'SSLError: {e}'
    except ConnectionRefusedError:
        return False, 'connection refused'
    except OSError as e:
        return False, str(e)


# ── Публичный API ─────────────────────────────────────────────────────────────
def smoke_test_xray(
    port: Optional[int] = None,
    tls: Optional[bool] = None,
    timeout: float = 5.0,
    host: str = '127.0.0.1',
    sni: Optional[str] = None,
    _do_emergency_restore_fn: Optional[Callable] = None,
) -> bool:
    """
    Минимальный smoke-test после apply-операций.

    Параметры (все опциональны — читаются из state.json):
        port     — SERVER_PORT (default: state['server_port'] или 443)
        tls      — проверять TLS handshake (default: True для reality/tls)
        timeout  — таймаут TCP/TLS в секундах
        host     — хост для проверки (127.0.0.1)
        sni      — SNI для TLS (default: state['param_domain'])
        _do_emergency_restore_fn — callable аварийного восстановления

    Возвращает True при успехе, False при провале.
    """
    state = _read_state()
    _port = port if port is not None else int(state.get('server_port', 443))
    _sni  = sni  or state.get('param_domain') or state.get('param_sni') or host
    if tls is None:
        _tls = state.get('protocol_mode', 'reality') in ('reality', 'tls')
    else:
        _tls = tls

    print()
    print(f'  {CYAN}▶ Smoke-test Xray (порт {_port})...{NC}')

    # ── TCP connect (3 попытки — даём Xray время подняться) ──────────────────
    tcp_ok, tcp_err = False, ''
    for attempt in range(3):
        tcp_ok, tcp_err = _tcp_connect(host, _port, timeout)
        if tcp_ok:
            break
        if attempt < 2:
            time.sleep(2)

    if not tcp_ok:
        print(f'  {RED}✗ TCP connect FAILED:{NC} {tcp_err}')
        _offer_restore(_do_emergency_restore_fn, _port)
        return False
    print(f'  {GREEN}✓ TCP connect OK{NC}')

    # ── TLS handshake ─────────────────────────────────────────────────────────
    if _tls:
        tls_ok, tls_note = _tls_handshake(host, _port, timeout, sni=_sni)
        if tls_ok:
            note = f'  {DIM}({tls_note}){NC}' if tls_note else ''
            print(f'  {GREEN}✓ TLS handshake OK{NC}{note}')
        else:
            print(f'  {RED}✗ TLS handshake FAILED:{NC} {tls_note}')
            _offer_restore(_do_emergency_restore_fn, _port)
            return False
    else:
        print(f'  {DIM}  TLS-проверка пропущена (plain TCP режим){NC}')

    print(f'  {GREEN}✓ Xray доступен на порту {_port}{NC}')
    print()
    return True


def _offer_restore(fn: Optional[Callable], port: int) -> None:
    """Предлагает аварийное восстановление при провале smoke-теста."""
    print()
    print(f'  {RED}{BOLD}⚠  Xray не отвечает на порту {port}!{NC}')
    print(f'  {YELLOW}Клиенты не могут подключиться.{NC}')
    print()
    try:
        ans = input('  Запустить Аварийное восстановление? [y/N] ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = ''
    if ans in ('y', 'yes', 'д', 'да'):
        if fn is not None:
            try:
                fn()
            except Exception as e:
                print(f'  {RED}Ошибка восстановления: {e}{NC}')
        else:
            print(f'  {YELLOW}Функция восстановления не передана.{NC}')
            print(f'    journalctl -u xray -n 50')
            print(f'    systemctl restart xray')
    else:
        print(f'  {DIM}Диагностика: journalctl -u xray -n 30{NC}')
