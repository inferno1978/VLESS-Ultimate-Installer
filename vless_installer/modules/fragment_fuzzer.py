"""
vless_installer/modules/fragment_fuzzer.py
───────────────────────────────────────────────────────────────────────────────
Автоматический подбор оптимальных параметров фрагментации.

Два режима работы:
─────────────────
  Режим A — «С VPS» (ориентировочный):
    Запускает временный Xray-процесс на VPS и делает TLS Handshake к внешнему
    хосту через него. DPI между VPS и интернетом не проверяется — результат
    показывает только базовую работоспособность конфига.

  Режим B — «С клиента» (точный, рекомендуется):
    Генерирует все конфиги из матрицы в fragment_configs/fuzz_NN_label.json.
    Опционально поднимает временный HTTP-коллектор на порту 10901.
    Клиент запускает каждый конфиг, затем отправляет результат:
        curl "http://VPS:10901/report?id=01&ttfb=420&ok=1"
    Сервер собирает ответы, строит таблицу, сохраняет победителя.

ВАЖНО:
  • /etc/xray/config.json не затрагивается ни в каком режиме.
  • Временный Xray-процесс (режим A) завершается сразу после теста.
  • HTTP-коллектор принимает только GET /report?... — никаких команд не выполняет.
  • FP берётся из state.json, а не захардкожен как chrome.
  • Принцип «одна функция — один файл» соблюдён.

Публичное API:
    do_fragment_fuzzer_menu()   → точка входа из _core.py (Меню 4 → F2)
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
import threading
import time
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
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
_LOG_FILE   = Path("/var/log/vless-install.log")
_FUZZ_LOG   = Path("/var/log/xray-fragment-fuzzer.log")
_STATE_FILE = Path("/var/lib/xray-installer/state.json")

def _log(level: str, msg: str) -> None:
    try:
        import re as _re
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
    _box_info, _box_warn, _box_desc, _box_ok, _get_box_width,
)
from vless_installer.modules.fragment_config import (
    build_fragment_sockopt,
    generate_fragment_client_config,
)

# ── Константы ─────────────────────────────────────────────────────────────
_XRAY_BIN             = Path("/usr/local/bin/xray")
_FRAGMENT_DIR         = Path("/var/lib/xray-installer/fragment_configs")
_FUZZ_SOCKS_PORT_PREF = 10900
_COLLECTOR_PORT       = 10901
_FUZZ_TIMEOUT_SEC     = 8
_FUZZ_REPEATS         = 5       # увеличено с 3 — для статистической надёжности
_COLLECTOR_TIMEOUT    = 300     # 5 минут максимум
_TEST_HOST            = "www.google.com"
_TEST_PORT            = 443

# ── Матрица параметров ────────────────────────────────────────────────────
# (packets, length, interval_ms, label)
# Три группы: агрессивные / средние / лёгкие.
_FUZZ_MATRIX: list[tuple[str, str, str, str]] = [
    ("1-3", "1-1",   "5-10",  "ultra"),
    ("1-3", "1-3",   "5-10",  "aggressive-a"),
    ("1-3", "1-5",   "10-20", "aggressive-b"),
    ("1-3", "10-20", "10-20", "medium-a"),
    ("1-3", "20-50", "20-40", "medium-b"),
    ("1-2", "20-50", "30-60", "medium-c"),
    ("1-2", "50-100",  "10-20", "light-a"),
    ("1-1", "100-200", "5-10",  "light-b"),
]


# =============================================================================
#  ОБЩИЕ УТИЛИТЫ
# =============================================================================

def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) != 0


def _find_free_port(start: int, attempts: int = 20) -> Optional[int]:
    for port in range(start, start + attempts):
        if _port_free(port):
            return port
    return None


def _wait_port_open(port: int, timeout: float = 6.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def _load_state() -> Optional[dict]:
    if not _STATE_FILE.exists():
        _warn("state.json не найден — сначала установите VLESS-сервер")
        return None
    try:
        data = json.loads(_STATE_FILE.read_text())
    except Exception as e:
        _warn(f"Не удалось прочитать state.json: {e}")
        return None
    if not data.get("domain") or not data.get("uuid"):
        _warn("В state.json нет domain/uuid — сначала завершите установку сервера")
        return None
    return data


def _get_server_ip(state: dict) -> str:
    ip = state.get("server_ip", "")
    if ip:
        return ip
    try:
        return socket.gethostbyname(state.get("domain", ""))
    except Exception:
        return state.get("domain", "?")


def _fp_from_state(state: dict) -> str:
    """Берёт fingerprint из state.json. Fallback → chrome."""
    return (
        state.get("fingerprint")
        or state.get("tls_fingerprint")
        or "chrome"
    )


def _patch_fp_in_config(path: Path, fp: str) -> None:
    """Патчит fingerprint в сгенерированном конфиге."""
    try:
        cfg = json.loads(path.read_text())
        for ob in cfg.get("outbounds", []):
            rs = ob.get("streamSettings", {}).get("realitySettings", {})
            if rs:
                rs["fingerprint"] = fp
        path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
    except Exception:
        pass


# =============================================================================
#  РЕЖИМ A — ТЕСТ С VPS
# =============================================================================

def _build_test_client_config(
    state: dict,
    packets: str,
    length: str,
    interval: str,
    socks_port: int,
) -> dict:
    """
    Строит минимальный клиентский конфиг Xray для теста с VPS.
    FP берётся из state.json — не захардкожен.
    Не затрагивает /etc/xray/config.json.
    """
    protocol_mode = state.get("protocol_mode", "reality")
    server_host   = state.get("domain", "")
    server_port   = int(state.get("server_port", 443))
    uuid_val      = state.get("uuid", "")
    pub_key       = state.get("public_key", "")
    short_id      = state.get("short_id", "")
    reality_dest  = state.get("reality_dest", "www.microsoft.com")
    xtls_flow     = state.get("xtls_flow", "xtls-rprx-vision")
    fp            = _fp_from_state(state)
    sockopt       = build_fragment_sockopt(packets, length, interval)

    if protocol_mode == "xhttp":
        outbound = {
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": server_host, "port": server_port,
                "users": [{"id": uuid_val, "encryption": "none"}]}]},
            "streamSettings": {
                "network": "xhttp", "security": "tls", "sockopt": sockopt,
                "tlsSettings": {"serverName": server_host, "allowInsecure": False},
                "xhttpSettings": {
                    "path": state.get("xhttp_path", "/"),
                    "mode": state.get("xhttp_mode", "streamup"),
                },
            },
        }
    else:
        sni = reality_dest.split(":")[0] if ":" in reality_dest else reality_dest
        outbound = {
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": server_host, "port": server_port,
                "users": [{"id": uuid_val, "encryption": "none",
                           **( {"flow": xtls_flow} if xtls_flow else {} )}]}]},
            "streamSettings": {
                "network": "tcp", "security": "reality", "sockopt": sockopt,
                "realitySettings": {
                    "show": False, "fingerprint": fp,
                    "serverName": sni, "publicKey": pub_key,
                    "shortId": short_id, "spiderX": "/",
                },
            },
        }

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"tag": "socks-test", "protocol": "socks",
                      "listen": "127.0.0.1", "port": socks_port,
                      "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }


def _tls_handshake_via_socks5(
    socks_port: int,
    target_host: str = _TEST_HOST,
    target_port: int = _TEST_PORT,
    timeout: float   = _FUZZ_TIMEOUT_SEC,
) -> Optional[float]:
    """
    TLS Handshake через socks5 на 127.0.0.1:socks_port.
    Возвращает время handshake (сек) или None при неудаче.
    Только stdlib — без внешних зависимостей.
    """
    import ssl, struct
    try:
        s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
            s.close(); return None
        host_b = target_host.encode("idna")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b
                  + struct.pack("!H", target_port))
        reply = s.recv(10)
        if len(reply) < 2 or reply[1] != 0:
            s.close(); return None
        ctx = ssl.create_default_context()
        t0  = time.perf_counter()
        tls = ctx.wrap_socket(s, server_hostname=target_host,
                              do_handshake_on_connect=True)
        elapsed = time.perf_counter() - t0
        tls.close()
        return elapsed
    except Exception:
        return None


def _run_one_probe(
    state: dict,
    packets: str, length: str, interval: str,
    socks_port: int,
    tmp_dir: str,
    idx: int,
) -> list[Optional[float]]:
    """
    Запускает временный xray-процесс и делает _FUZZ_REPEATS попыток handshake.
    Процесс завершается сразу после теста.
    """
    if not _XRAY_BIN.exists():
        return [None] * _FUZZ_REPEATS
    if not _port_free(socks_port):
        return [None] * _FUZZ_REPEATS

    cfg      = _build_test_client_config(state, packets, length, interval, socks_port)
    cfg_path = Path(tmp_dir) / f"fuzz_{idx}.json"
    cfg_path.write_text(json.dumps(cfg))

    r = subprocess.run(
        [str(_XRAY_BIN), "run", "-test", "-config", str(cfg_path)],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        _log("WARN", f"xray -test failed idx={idx}: {r.stderr.strip()[:200]}")
        return [None] * _FUZZ_REPEATS

    proc = subprocess.Popen(
        [str(_XRAY_BIN), "run", "-config", str(cfg_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )
    try:
        if not _wait_port_open(socks_port, timeout=6.0):
            return [None] * _FUZZ_REPEATS
        results: list[Optional[float]] = []
        for _ in range(_FUZZ_REPEATS):
            results.append(_tls_handshake_via_socks5(socks_port))
            time.sleep(0.5)
        return results
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            try: proc.terminate()
            except Exception: pass
        proc.wait(timeout=3)


def run_fragment_fuzzer(state: dict, socks_port: int = _FUZZ_SOCKS_PORT_PREF) -> Optional[dict]:
    """
    Режим A: перебирает матрицу, измеряет TLS Handshake, возвращает лучший вариант.
    Результат ориентировочный — DPI на пути VPS→интернет отсутствует.
    """
    results = []
    fp      = _fp_from_state(state)
    total   = len(_FUZZ_MATRIX)
    print()
    _info(f"Fingerprint: {BOLD}{fp}{NC}")
    _info(f"Перебор {total} комбинаций × {_FUZZ_REPEATS} попыток")
    _info(f"Тест: TLS Handshake → {_TEST_HOST}:{_TEST_PORT} через временный socks5")
    _warn("Результат ориентировочный — DPI на пути VPS→интернет не проверяется")
    print()

    with tempfile.TemporaryDirectory(prefix="vless_fuzz_") as tmp_dir:
        for idx, (packets, length, interval, label) in enumerate(_FUZZ_MATRIX, 1):
            desc = f"packets={packets} length={length} interval={interval}мс"
            print(f"  {DIM}[{idx:02d}/{total}]{NC}  {desc:<45}", end="", flush=True)

            meas     = _run_one_probe(state, packets, length, interval,
                                      socks_port, tmp_dir, idx)
            ok       = [m for m in meas if m is not None]
            rate     = len(ok) / len(meas) if meas else 0.0
            avg_ttfb = sum(ok) / len(ok) if ok else float("inf")

            if rate > 0:
                print(f"  {GREEN}✓{NC}  {int(rate*100):3d}%  "
                      f"{DIM}ttfb={int(avg_ttfb*1000)}мс{NC}")
            else:
                print(f"  {RED}✗{NC}  все попытки провалились")

            results.append({
                "packets": packets, "length": length, "interval": interval,
                "label": label, "avg_ttfb": avg_ttfb, "success_rate": rate,
            })
            _log("INFO", f"{desc} → ok={rate:.2f} ttfb={int(avg_ttfb*1000)}мс")
            time.sleep(1.0)

    ranked = sorted(results, key=lambda r: (-r["success_rate"], r["avg_ttfb"]))
    if not ranked or ranked[0]["success_rate"] == 0.0:
        return None
    return ranked[0]


# =============================================================================
#  РЕЖИМ B — ТЕСТ С КЛИЕНТА
# =============================================================================

_collector_results: dict[str, dict] = {}
_collector_lock    = threading.Lock()
_collector_done    = threading.Event()


class _CollectorHandler(BaseHTTPRequestHandler):
    """
    HTTP-коллектор результатов от клиентов.
    Принимает только GET /report?id=XX&ttfb=NNN&ok=0|1
    Не выполняет никаких команд — только читает query string.
    """

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/report":
                self._respond(404, "not found"); return
            params   = dict(urllib.parse.parse_qsl(parsed.query))
            rid      = params.get("id", "").strip()[:8]
            ok_str   = params.get("ok",   "0").strip()
            ttfb_str = params.get("ttfb", "").strip()

            if not rid or not rid.replace("-", "").isalnum():
                self._respond(400, "bad id"); return

            ok   = ok_str == "1"
            ttfb = int(ttfb_str) if ttfb_str.isdigit() else None

            with _collector_lock:
                _collector_results[rid] = {
                    "ok": ok, "ttfb_ms": ttfb,
                    "ts": datetime.now().isoformat(timespec="seconds"),
                }
                received = len(_collector_results)

            self._respond(200, "ok")
            _log("INFO", f"collector got id={rid} ok={ok} ttfb={ttfb}")

            if received >= len(_FUZZ_MATRIX):
                _collector_done.set()

        except Exception:
            self._respond(500, "error")

    def _respond(self, code: int, body: str) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        _log("INFO", f"collector: {fmt % args}")


def _collector_serve_loop(server: HTTPServer) -> None:
    while not _collector_done.is_set():
        try:
            server.handle_request()
        except Exception:
            break


def _generate_all_client_configs(state: dict) -> list[dict]:
    """
    Генерирует конфиги для всех комбинаций матрицы.
    Использует generate_fragment_client_config() — не дублирует логику.
    Патчит FP из state.json.
    """
    fp    = _fp_from_state(state)
    total = len(_FUZZ_MATRIX)
    _FRAGMENT_DIR.mkdir(parents=True, exist_ok=True)
    generated = []

    for idx, (packets, length, interval, label) in enumerate(_FUZZ_MATRIX, 1):
        file_label = f"fuzz_{idx:02d}_{label}"
        path = generate_fragment_client_config(
            packets=packets, length=length, interval=interval, label=file_label,
        )
        if path:
            _patch_fp_in_config(path, fp)
            generated.append({
                "id": f"{idx:02d}", "label": label,
                "packets": packets, "length": length, "interval": interval,
                "path": path,
            })
            print(f"  {DIM}[{idx:02d}/{total}]{NC}  {file_label}.json  "
                  f"{DIM}packets={packets} length={length} interval={interval}мс{NC}")
        else:
            _warn(f"Не удалось сгенерировать конфиг #{idx:02d} ({label})")

    return generated


def _print_client_instructions(server_ip: str, generated: list[dict]) -> None:
    """Инструкция для пользователя в стиле проекта."""
    _box_sep()
    _box_row(f"  {BOLD}Инструкция:{NC}")
    _box_row()
    _box_row(f"  1. Скачайте конфиги с сервера:")
    _box_row(f"     {DIM}scp root@{server_ip}:{_FRAGMENT_DIR}/fuzz_*.json ./{NC}")
    _box_row()
    _box_row(f"  2. Для каждого конфига:")
    _box_row(f"     {DIM}xray run -config fuzz_01_ultra.json{NC}")
    _box_row()
    _box_row(f"  3. В другом терминале отправьте результат на сервер:")
    if generated:
        ex = generated[0]
        _box_row(
            f"     {CYAN}curl{NC} {DIM}\"http://{server_ip}:{_COLLECTOR_PORT}"
            f"/report?id={ex['id']}&ttfb=<мс>&ok=<0|1>\"{NC}"
        )
    _box_row()
    _box_row(f"  {DIM}ok=1 — подключение прошло, ok=0 — не прошло{NC}")
    _box_row(f"  {DIM}ttfb — время подключения в миллисекундах{NC}")
    _box_row()
    _box_row(f"  {YELLOW}Коллектор ждёт результатов {_COLLECTOR_TIMEOUT//60} мин "
             f"или нажатия Enter на сервере.{NC}")


def _print_collector_table(generated: list[dict]) -> Optional[dict]:
    """Выводит таблицу результатов, возвращает победителя или None."""
    with _collector_lock:
        results = dict(_collector_results)

    if not results:
        _warn("Результатов от клиента не получено")
        return None

    _box_sep()
    _box_row(f"  {BOLD}Результаты:{NC}")
    _box_row()
    _box_row(f"  {DIM}  #   label           packets   length    interval    ttfb мс  ok{NC}")
    _box_row(f"  {DIM}{'─'*65}{NC}")

    ranked = []
    for item in generated:
        rid = item["id"]
        r   = results.get(rid)
        if r:
            ok_mark  = f"{GREEN}✓{NC}" if r["ok"] else f"{RED}✗{NC}"
            ttfb_str = str(r["ttfb_ms"]) if r["ttfb_ms"] is not None else "—"
            _box_row(
                f"  {rid:>3}   {item['label']:<14}  {item['packets']:<8}  "
                f"{item['length']:<8}  {item['interval']:<10}  "
                f"{ttfb_str:>7}  {ok_mark}"
            )
            if r["ok"]:
                ranked.append({**item,
                    "ttfb_ms": r["ttfb_ms"] if r["ttfb_ms"] is not None else 9999})
        else:
            _box_row(
                f"  {rid:>3}   {item['label']:<14}  {item['packets']:<8}  "
                f"{item['length']:<8}  {item['interval']:<10}  "
                f"{'—':>7}  {DIM}нет данных{NC}"
            )

    _box_row()
    if not ranked:
        return None

    ranked.sort(key=lambda r: r["ttfb_ms"])
    w = ranked[0]
    _box_row(
        f"  {GREEN}{BOLD}Победитель: #{w['id']} {w['label']} — "
        f"packets={w['packets']} length={w['length']} "
        f"interval={w['interval']}мс  ttfb={w['ttfb_ms']}мс{NC}"
    )
    return w


def run_client_fuzzer(state: dict) -> None:
    """Режим B: генерация конфигов + опциональный HTTP-коллектор."""
    global _collector_results, _collector_done

    server_ip = _get_server_ip(state)

    os.system("clear")
    print()
    _box_top(f"  {CYAN}FUZZER — РЕЖИМ B: ТЕСТ С КЛИЕНТА{NC}")
    _box_desc(
        "Генерируются конфиги для всех комбинаций матрицы. "
        "Клиент тестирует их со своего устройства — "
        "это единственный точный способ проверить обход DPI."
    )
    _box_sep()
    _box_row(f"  {BOLD}Генерация конфигов...{NC}")
    _box_row()

    generated = _generate_all_client_configs(state)
    if not generated:
        _box_warn("Не удалось сгенерировать ни одного конфига")
        _box_bottom()
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    _box_row()
    _box_ok(f"Сгенерировано: {len(generated)} конфигов  →  {_FRAGMENT_DIR}")
    _box_sep()
    _box_info(f"Запустить HTTP-коллектор на порту {_COLLECTOR_PORT}?")
    _box_row(f"  {DIM}Клиент отправляет результаты через curl — сервер строит таблицу.{NC}")
    _box_row(f"  {DIM}Если нет — конфиги уже сохранены, тестируйте вручную.{NC}")
    _box_bottom()
    print()

    try:
        ans = input(f"  {CYAN}Запустить коллектор? [Y/n]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return

    if ans in ("n", "no", "н", "нет"):
        os.system("clear")
        print()
        _box_top(f"  {CYAN}ИНСТРУКЦИЯ ДЛЯ РУЧНОГО ТЕСТИРОВАНИЯ{NC}")
        _print_client_instructions(server_ip, generated)
        _box_bottom()
        print()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    if not _port_free(_COLLECTOR_PORT):
        _warn(f"Порт {_COLLECTOR_PORT} занят — коллектор не запущен")
        _print_client_instructions(server_ip, generated)
        print()
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    # Сброс состояния и запуск коллектора
    with _collector_lock:
        _collector_results.clear()
    _collector_done.clear()

    server         = HTTPServer(("0.0.0.0", _COLLECTOR_PORT), _CollectorHandler)
    server.timeout = 1.0
    server_thread  = threading.Thread(target=_collector_serve_loop,
                                      args=(server,), daemon=True)
    server_thread.start()

    os.system("clear")
    print()
    _box_top(f"  {CYAN}КОЛЛЕКТОР ЗАПУЩЕН  :{_COLLECTOR_PORT}{NC}")
    _print_client_instructions(server_ip, generated)
    _box_bottom()
    print()
    _info(f"Ожидание результатов ({_COLLECTOR_TIMEOUT//60} мин). "
          f"Нажмите Enter для досрочного завершения.")

    stop_event = threading.Event()

    def _wait_enter() -> None:
        try: input()
        except Exception: pass
        stop_event.set(); _collector_done.set()

    threading.Thread(target=_wait_enter, daemon=True).start()

    deadline = time.time() + _COLLECTOR_TIMEOUT
    while time.time() < deadline:
        if _collector_done.is_set() or stop_event.is_set():
            break
        with _collector_lock:
            received = len(_collector_results)
        print(f"\r  {DIM}Получено: {received}/{len(_FUZZ_MATRIX)}{NC}   ",
              end="", flush=True)
        time.sleep(1.0)
    print()

    server.shutdown()
    server_thread.join(timeout=3)

    print()
    _box_top(f"  {CYAN}РЕЗУЛЬТАТЫ — РЕЖИМ B{NC}")
    winner = _print_collector_table(generated)
    _box_bottom()
    print()

    if winner:
        try:
            save = input(
                f"  {CYAN}Сохранить победителя как fragment_recommended.json? [Y/n]:{NC} "
            ).strip().lower()
        except KeyboardInterrupt:
            save = "n"
        if save not in ("n", "no", "н", "нет"):
            path = generate_fragment_client_config(
                packets=winner["packets"], length=winner["length"],
                interval=winner["interval"], label="fragment_recommended",
            )
            if path:
                _patch_fp_in_config(path, _fp_from_state(state))
                _success(f"Сохранено: {path}")
                _log("INFO",
                     f"fuzzer-B winner: packets={winner['packets']} "
                     f"length={winner['length']} interval={winner['interval']} "
                     f"ttfb={winner['ttfb_ms']}мс label={winner['label']}")
    else:
        _warn("Успешных результатов не получено")

    input(f"\n{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  ГЛАВНОЕ МЕНЮ (точка входа из _core.py)
# =============================================================================

def do_fragment_fuzzer_menu() -> None:
    """
    Интерактивное меню подбора фрагментации.
    Точка входа из _core.py (Меню 4 → F2): do_fragment_fuzzer_menu()
    """
    while True:
        os.system("clear")
        print()
        _box_top("🔬  FUZZER ФРАГМЕНТАЦИИ")
        _box_desc(
            "Автоматический подбор оптимальных параметров fragment: "
            "packets / length / interval."
        )
        _box_sep()
        _box_row(f"  {BOLD}[A]{NC}  Тест с VPS  {DIM}(ориентировочный, без DPI){NC}")
        _box_row(
            f"  {DIM}Запускает временный Xray на сервере, делает TLS Handshake "
            f"к {_TEST_HOST}. Быстро, но DPI на пути VPS→интернет "
            f"отсутствует.{NC}"
        )
        _box_sep()
        _box_row(f"  {BOLD}[B]{NC}  Тест с клиента  {DIM}(точный, рекомендуется){NC}")
        _box_row(
            f"  {DIM}Генерирует {len(_FUZZ_MATRIX)} конфигов. Вы тестируете со "
            f"своего устройства через реальный маршрут c DPI. "
            f"Коллектор автоматически собирает результаты.{NC}"
        )
        _box_sep()
        _box_item("A", "Тест с VPS")
        _box_item("B", f"Тест с клиента  {DIM}(конфиги + коллектор){NC}")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "a":
            _run_mode_a()
        elif ch == "b":
            _run_mode_b()
        elif ch in ("q", ""):
            break
        else:
            _warn("Неверный выбор")
            time.sleep(1)


def _run_mode_a() -> None:
    os.system("clear")
    print()
    _box_top(f"  {CYAN}FUZZER — РЕЖИМ A: ТЕСТ С VPS{NC}")
    _box_warn("Результат ориентировочный — DPI между VPS и интернетом не проверяется.")
    _box_desc(
        f"Перебирает {len(_FUZZ_MATRIX)} комбинаций × {_FUZZ_REPEATS} попыток. "
        f"FP берётся из вашего конфига. "
        f"/etc/xray/config.json не затрагивается."
    )
    _box_bottom()
    print()

    if not _XRAY_BIN.exists():
        _warn(f"Xray не найден: {_XRAY_BIN}")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    state = _load_state()
    if state is None:
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    fp = _fp_from_state(state)
    _info(f"Fingerprint: {BOLD}{fp}{NC}")
    _info(f"Сервер: {state.get('domain','?')}:{state.get('server_port',443)}")
    print()

    fuzz_port = _find_free_port(_FUZZ_SOCKS_PORT_PREF)
    if fuzz_port is None:
        _warn(f"Свободный порт не найден (начиная с {_FUZZ_SOCKS_PORT_PREF})")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    try:
        confirm = input(f"{CYAN}Начать? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return
    if confirm not in ("y", "yes", "д", "да"):
        return

    best = run_fragment_fuzzer(state, socks_port=fuzz_port)
    print()

    if best is None:
        _box_top("РЕЗУЛЬТАТ")
        _box_warn("Ни один вариант не прошёл тест.")
        _box_row(f"  {DIM}Проверьте: доступен ли сервер, открыт ли порт, работает ли Xray.{NC}")
        _box_bottom()
    else:
        rate_pct = int(best["success_rate"] * 100)
        ttfb_ms  = int(best["avg_ttfb"] * 1000) if best["avg_ttfb"] != float("inf") else 9999
        _box_top("РЕЗУЛЬТАТ — РЕЖИМ A")
        _box_ok(f"Лучший вариант  (успешность: {rate_pct}%,  ttfb: {ttfb_ms}мс)")
        _box_row()
        _box_row(f"  {BOLD}packets :{NC}  {best['packets']}")
        _box_row(f"  {BOLD}length  :{NC}  {best['length']} байт")
        _box_row(f"  {BOLD}interval:{NC}  {best['interval']} мс")
        _box_sep()
        _box_warn(
            "Для подтверждения запустите Режим B и проверьте с клиентского устройства."
        )
        _box_bottom()
        print()

        try:
            save = input(
                f"  {CYAN}Сохранить как fragment_recommended.json? [Y/n]:{NC} "
            ).strip().lower()
        except KeyboardInterrupt:
            save = "n"
        if save not in ("n", "no", "н", "нет"):
            path = generate_fragment_client_config(
                packets=best["packets"], length=best["length"],
                interval=best["interval"], label="fragment_recommended",
            )
            if path:
                _patch_fp_in_config(path, _fp_from_state(state))
                _success(f"Сохранено: {path}")
                _log("INFO",
                     f"fuzzer-A winner: packets={best['packets']} "
                     f"length={best['length']} interval={best['interval']} "
                     f"ttfb={ttfb_ms}мс")

    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _run_mode_b() -> None:
    state = _load_state()
    if state is None:
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return
    run_client_fuzzer(state)
