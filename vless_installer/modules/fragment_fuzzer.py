"""
vless_installer/modules/fragment_fuzzer.py
───────────────────────────────────────────────────────────────────────────────
Автоматический подбор оптимальных параметров фрагментации (Fuzzer).

Алгоритм:
  1. Для каждой комбинации length/interval/packets запускает тестовое
     исходящее TLS-соединение через временный конфиг Xray (xray run -test
     + реальный TLS handshake через socks5-прокси).
  2. Измеряет время TLS Handshake и факт его успешного завершения.
  3. Ранжирует результаты по (success_rate DESC, avg_ttfb ASC).
  4. Выводит рекомендацию и сохраняет «победивший» конфиг.

ВАЖНО: серверный /etc/xray/config.json не затрагивается.
Fuzzer использует временный порт (10900) и тестовое соединение.

Точка входа из _core.py:
    from vless_installer.modules.fragment_fuzzer import do_fragment_fuzzer_menu
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        else:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
            )
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────
_LOG_FILE  = Path("/var/log/vless-install.log")
_FUZZ_LOG  = Path("/var/log/xray-fragment-fuzzer.log")
_STATE_FILE = Path("/var/lib/xray-installer/state.json")

def _log(level: str, msg: str) -> None:
    try:
        import re as _re
        from datetime import datetime
        for lf in (_LOG_FILE, _FUZZ_LOG):
            lf.parent.mkdir(parents=True, exist_ok=True)
            with lf.open("a") as f:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                clean = _re.sub(r'\x1b\[[0-9;]*m', '', msg)
                f.write(f"[{ts}] [FUZZER] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");    _log("INFO",    msg)
def _success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}");   _log("SUCCESS", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}");  _log("WARN",    msg)

# ── Импорт ────────────────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn, _box_desc, _get_box_width,
)
from vless_installer.modules.fragment_config import (
    build_fragment_sockopt,
    generate_fragment_client_config,
)

# ── Константы ─────────────────────────────────────────────────────────────
_XRAY_BIN             = Path("/usr/local/bin/xray")
_FUZZ_SOCKS_PORT_PREF = 10900   # предпочтительный порт (ищем свободный начиная отсюда)
_FUZZ_TIMEOUT_SEC     = 8       # таймаут одного TLS-теста
_FUZZ_REPEATS         = 3       # повторений на комбинацию для усреднения
_TEST_HOST            = "www.google.com"
_TEST_PORT            = 443

# ── Матрица параметров для перебора ──────────────────────────────────────
# Три диапазона length:
#   1-5    — агрессивные: жёсткий DPI (Иран, ТСПУ)
#   10-50  — средние: работают там, где мелкие уже фильтруются как сигнатура
#   50-200 — лёгкие: минимальный оверхед, поверхностный DPI
#
# ВНИМАНИЕ: Fuzzer тестирует с VPS, поэтому его результаты носят
# ориентировочный характер. Итоговый выбор — за пользователем на своём устройстве.
# Используйте F4 (генерация всех пресетов) для реального тестирования.
_FUZZ_MATRIX = [
    # (packets, length, interval_ms)
    # ── Агрессивные (мелкие пакеты) ──────────────────────────────────
    ("1-3", "1-1",   "5-10"),
    ("1-3", "1-3",   "5-10"),
    ("1-3", "1-5",   "10-20"),
    # ── Средние (10–50 байт) ─────────────────────────────────────────
    ("1-3", "10-20", "10-20"),
    ("1-3", "20-50", "20-40"),
    ("1-2", "20-50", "30-60"),
    # ── Лёгкие (50–200 байт) ─────────────────────────────────────────
    ("1-2", "50-100",  "10-20"),
    ("1-1", "100-200", "5-10"),
]

# ── Вспомогательные ───────────────────────────────────────────────────────

def _port_free(port: int) -> bool:
    """Проверяет, что порт свободен."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) != 0


def _find_free_port(start: int = _FUZZ_SOCKS_PORT_PREF, attempts: int = 20) -> Optional[int]:
    """Ищет свободный порт начиная с `start`. Возвращает номер или None."""
    for port in range(start, start + attempts):
        if _port_free(port):
            return port
    return None


def _wait_port_open(port: int, timeout: float = 5.0) -> bool:
    """Ждёт, пока порт откроется (сервис поднялся)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def _build_test_client_config(
    state: dict,
    packets: str,
    length: str,
    interval: str,
    socks_port: int,
) -> dict:
    """
    Строит минимальный клиентский конфиг с фрагментацией для одного теста.
    Socks5 на socks_port, outbound → VPS с fragment sockopt.
    """
    protocol_mode = state.get("protocol_mode", "reality")
    server_host   = state.get("domain", "")
    server_port   = int(state.get("server_port", 443))
    uuid_val      = state.get("uuid", "")
    pub_key       = state.get("public_key", "")
    short_id      = state.get("short_id", "")
    reality_dest  = state.get("reality_dest", "www.microsoft.com")
    xtls_flow     = state.get("xtls_flow", "xtls-rprx-vision")

    sockopt = build_fragment_sockopt(packets, length, interval)

    if protocol_mode == "xhttp":
        xhttp_path = state.get("xhttp_path", "/")
        xhttp_mode = state.get("xhttp_mode", "streamup")
        outbound = {
            "tag":      "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_host,
                    "port":    server_port,
                    "users":   [{"id": uuid_val, "encryption": "none"}],
                }],
            },
            "streamSettings": {
                "network":  "xhttp",
                "security": "tls",
                "sockopt":  sockopt,
                "tlsSettings": {
                    "serverName":    server_host,
                    "allowInsecure": False,
                },
                "xhttpSettings": {
                    "path": xhttp_path,
                    "mode": xhttp_mode,
                },
            },
        }
    else:
        sni = reality_dest.split(":")[0] if ":" in reality_dest else reality_dest
        outbound = {
            "tag":      "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_host,
                    "port":    server_port,
                    "users":   [{
                        "id":         uuid_val,
                        "encryption": "none",
                        **({"flow": xtls_flow} if xtls_flow else {}),
                    }],
                }],
            },
            "streamSettings": {
                "network":  "tcp",
                "security": "reality",
                "sockopt":  sockopt,
                "realitySettings": {
                    "show":        False,
                    "fingerprint": "chrome",
                    "serverName":  sni,
                    "publicKey":   pub_key,
                    "shortId":     short_id,
                    "spiderX":     "/",
                },
            },
        }

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag":      "socks-test",
            "protocol": "socks",
            "listen":   "127.0.0.1",
            "port":     socks_port,
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"},
        ],
    }


def _tls_handshake_via_socks5(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float = _FUZZ_TIMEOUT_SEC,
) -> Optional[float]:
    """
    Устанавливает CONNECT через socks5 и измеряет время TLS Handshake.
    Возвращает время (сек) или None при неудаче.

    Использует только stdlib (socket + ssl) — без внешних зависимостей.
    """
    import ssl
    import struct

    try:
        s = socket.create_connection((socks_host, socks_port), timeout=timeout)
        s.settimeout(timeout)

        # SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
            s.close()
            return None

        # SOCKS5 CONNECT request
        host_bytes = target_host.encode("idna")
        req = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + struct.pack("!H", target_port)
        )
        s.sendall(req)
        reply = s.recv(10)
        if len(reply) < 2 or reply[1] != 0:
            s.close()
            return None

        # TLS Handshake timing
        ctx = ssl.create_default_context()
        t0 = time.perf_counter()
        tls = ctx.wrap_socket(s, server_hostname=target_host, do_handshake_on_connect=True)
        elapsed = time.perf_counter() - t0
        tls.close()
        return elapsed

    except Exception:
        return None


def _run_one_probe(
    state: dict,
    packets: str,
    length: str,
    interval: str,
    socks_port: int,
    tmp_dir: str,
    idx: int,
) -> list[Optional[float]]:
    """
    Запускает временный xray-процесс с тестовым конфигом и делает
    _FUZZ_REPEATS попыток TLS Handshake. Возвращает список измерений.
    Временный xray-процесс завершается после теста.
    """
    if not _XRAY_BIN.exists():
        _warn("Xray не найден — пропуск теста")
        return [None] * _FUZZ_REPEATS

    if not _port_free(socks_port):
        _warn(f"Порт {socks_port} занят — пропуск")
        return [None] * _FUZZ_REPEATS

    cfg = _build_test_client_config(state, packets, length, interval, socks_port)
    cfg_path = Path(tmp_dir) / f"fuzz_{idx}.json"
    cfg_path.write_text(json.dumps(cfg))

    # Проверяем конфиг синтаксически
    r_test = subprocess.run(
        [str(_XRAY_BIN), "run", "-test", "-config", str(cfg_path)],
        capture_output=True, text=True, timeout=10,
    )
    if r_test.returncode != 0:
        _log("WARN", f"xray -test failed: {r_test.stderr.strip()[:200]}")
        return [None] * _FUZZ_REPEATS

    # Запускаем xray как фоновый процесс
    proc = subprocess.Popen(
        [str(_XRAY_BIN), "run", "-config", str(cfg_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )
    try:
        if not _wait_port_open(socks_port, timeout=6.0):
            _log("WARN", f"Socks5:{socks_port} не открылся за 6 сек")
            return [None] * _FUZZ_REPEATS

        results: list[Optional[float]] = []
        for _ in range(_FUZZ_REPEATS):
            t = _tls_handshake_via_socks5(
                "127.0.0.1", socks_port,
                _TEST_HOST, _TEST_PORT,
                timeout=_FUZZ_TIMEOUT_SEC,
            )
            results.append(t)
            time.sleep(0.5)
        return results

    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
        proc.wait(timeout=3)


# ── Основная функция Fuzzer ───────────────────────────────────────────────

def run_fragment_fuzzer(state: dict, socks_port: int = _FUZZ_SOCKS_PORT_PREF) -> Optional[dict]:
    """
    Перебирает матрицу фрагментации, измеряет TLS Handshake через каждый
    вариант и возвращает dict с лучшими параметрами:
        {
            "packets": "1-3",
            "length":  "3-7",
            "interval": "10-20",
            "avg_ttfb": 0.42,
            "success_rate": 1.0,
        }
    или None, если ни один вариант не сработал.
    """
    results = []

    with tempfile.TemporaryDirectory(prefix="vless_fuzz_") as tmp_dir:
        total = len(_FUZZ_MATRIX)
        print()
        _info(f"Начинаю перебор {total} комбинаций × {_FUZZ_REPEATS} попыток каждая")
        _info(f"Тест: TLS Handshake → {_TEST_HOST}:{_TEST_PORT} через временный socks5")
        print()

        for idx, (packets, length, interval) in enumerate(_FUZZ_MATRIX, 1):
            label = f"packets={packets} length={length} interval={interval}мс"
            print(f"  {DIM}[{idx}/{total}]{NC}  {label} ...", end="", flush=True)

            measurements = _run_one_probe(
                state, packets, length, interval,
                socks_port=socks_port,
                tmp_dir=tmp_dir,
                idx=idx,
            )

            successes = [m for m in measurements if m is not None]
            success_rate = len(successes) / len(measurements) if measurements else 0.0
            avg_ttfb     = sum(successes) / len(successes) if successes else float("inf")

            if success_rate > 0:
                print(f"  {GREEN}✓{NC} {success_rate*100:.0f}% успех, "
                      f"avg TTFB={avg_ttfb*1000:.0f} мс")
            else:
                print(f"  {RED}✗{NC} все попытки провалились")

            results.append({
                "packets":      packets,
                "length":       length,
                "interval":     interval,
                "avg_ttfb":     avg_ttfb,
                "success_rate": success_rate,
            })
            _log("INFO", f"{label} → success={success_rate:.2f} ttfb={avg_ttfb*1000:.0f}ms")

            # Небольшая пауза между итерациями
            time.sleep(1.0)

    # Сортируем: сначала по success_rate DESC, затем по avg_ttfb ASC
    ranked = sorted(
        results,
        key=lambda r: (-r["success_rate"], r["avg_ttfb"]),
    )
    if not ranked or ranked[0]["success_rate"] == 0.0:
        return None
    return ranked[0]


# ── Интерактивное меню ────────────────────────────────────────────────────

def do_fragment_fuzzer_menu() -> None:
    """
    Интерактивное меню автоматического подбора фрагментации.
    Вызывается из _menu_diagnostics() в _core.py.
    """
    os.system("clear")
    print()
    _box_top("🔬  ТЕСТ СВЯЗНОСТИ С VPS (FUZZER)")
    _box_desc(
        "Перебирает комбинации length/interval/packets и измеряет TLS Handshake. "
        "Тест идёт с VPS — результат ориентировочный. "
        "Для точного подбора используйте F4 и тестируйте "
        "конфиги на своём устройстве."
    )
    _box_sep()
    _box_info(f"Целевой хост: {_TEST_HOST}:{_TEST_PORT}")
    _box_info(f"Комбинаций в матрице: {len(_FUZZ_MATRIX)}  (агрессивные / средние / лёгкие)")
    _box_info(f"Повторений на вариант: {_FUZZ_REPEATS}")
    _box_info(f"Временный socks5-порт: авто (предпочтительно ~{_FUZZ_SOCKS_PORT_PREF})")
    _box_info(f"Ожидаемое время: ~{len(_FUZZ_MATRIX) * _FUZZ_REPEATS * (_FUZZ_TIMEOUT_SEC + 2) // 60 + 1} мин")
    _box_sep()
    _box_warn("Не затрагивает серверный /etc/xray/config.json")
    _box_bottom()
    print()

    # Проверяем наличие state.json
    if not _STATE_FILE.exists():
        _warn("state.json не найден — сначала установите VLESS-сервер")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    try:
        state = json.loads(_STATE_FILE.read_text())
    except Exception as e:
        _warn(f"Не удалось прочитать state.json: {e}")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    if not state.get("domain") or not state.get("uuid"):
        _warn("В state.json нет domain/uuid — сначала завершите установку сервера")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    if not _XRAY_BIN.exists():
        _warn(f"Xray не найден: {_XRAY_BIN}")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    # ── Выбор порта ──────────────────────────────────────────────────────
    fuzz_port = _find_free_port(_FUZZ_SOCKS_PORT_PREF)
    if fuzz_port is None:
        _warn(f"Не удалось найти свободный порт в диапазоне "
              f"{_FUZZ_SOCKS_PORT_PREF}–{_FUZZ_SOCKS_PORT_PREF + 19}")
        fuzz_port = None

    print()
    if fuzz_port:
        _info(f"Свободный порт найден автоматически: {fuzz_port}")
        try:
            port_input = input(
                f"{CYAN}Использовать порт {fuzz_port}? "
                f"(Enter — да, или введите другой):{NC} "
            ).strip()
        except KeyboardInterrupt:
            return
        if port_input:
            if port_input.isdigit() and 1024 <= int(port_input) <= 65535:
                fuzz_port = int(port_input)
                if not _port_free(fuzz_port):
                    _warn(f"Порт {fuzz_port} занят. Выберите другой.")
                    input(f"\n{BLUE}Нажмите Enter...{NC}")
                    return
            else:
                _warn("Некорректный порт. Введите число от 1024 до 65535.")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
                return
    else:
        _warn("Авто-поиск порта не дал результата.")
        try:
            port_input = input(
                f"{CYAN}Введите порт вручную (1024–65535):{NC} "
            ).strip()
        except KeyboardInterrupt:
            return
        if port_input.isdigit() and 1024 <= int(port_input) <= 65535:
            fuzz_port = int(port_input)
            if not _port_free(fuzz_port):
                _warn(f"Порт {fuzz_port} тоже занят.")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
                return
        else:
            _warn("Некорректный порт.")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            return

    _info(f"Будет использован порт: {fuzz_port}")
    print()

    try:
        confirm = input(f"{CYAN}Начать подбор? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return

    if confirm not in ("y", "yes", "д", "да"):
        return

    print()
    best = run_fragment_fuzzer(state, socks_port=fuzz_port)
    print()

    if best is None:
        print(f"{RED}{'═'*60}{NC}")
        print(f"{RED}  Ни один вариант фрагментации не прошёл тест.{NC}")
        print(f"{YELLOW}  Возможные причины:{NC}")
        print(f"  • VPS недоступен / порт закрыт")
        print(f"  • {_TEST_HOST} недоступен через VPS")
        print(f"  • Фрагментация не поддерживается версией Xray")
        print(f"{RED}{'═'*60}{NC}")
    else:
        rate_pct  = int(best["success_rate"] * 100)
        ttfb_ms   = int(best["avg_ttfb"] * 1000) if best["avg_ttfb"] != float("inf") else 9999
        label     = (f"packets={best['packets']} "
                     f"length={best['length']} "
                     f"interval={best['interval']} мс")

        print(f"{GREEN}{'═'*60}{NC}")
        print(f"{GREEN}  ✅  ОПТИМАЛЬНАЯ ФРАГМЕНТАЦИЯ НАЙДЕНА{NC}")
        print(f"{GREEN}{'═'*60}{NC}")
        print(f"  {BOLD}packets :{NC}  {best['packets']}")
        print(f"  {BOLD}length  :{NC}  {best['length']} байт")
        print(f"  {BOLD}interval:{NC}  {best['interval']} мс")
        print(f"  {DIM}Успешность: {rate_pct}%  |  Avg TTFB: {ttfb_ms} мс{NC}")
        print()
        print(f"  {YELLOW}Рекомендация:{NC}")
        print(f"  Для вашего провайдера оптимальна фрагментация ClientHello")
        print(f"  на пакеты {best['length']} байт с интервалом {best['interval']} мс")
        print(f"{GREEN}{'═'*60}{NC}")

        print()
        try:
            save = input(f"{CYAN}Сохранить рекомендованный конфиг? [Y/n]:{NC} ").strip().lower()
        except KeyboardInterrupt:
            save = "n"

        if save not in ("n", "no", "н", "нет"):
            path = generate_fragment_client_config(
                packets=best["packets"],
                length=best["length"],
                interval=best["interval"],
                label="fragment_recommended",
            )
            if path:
                _success(f"Конфиг сохранён: {path}")
                _info("Скопируйте на клиентское устройство (Xray / v2rayNG / Nekoray)")

    input(f"\n{BLUE}Нажмите Enter...{NC}")
