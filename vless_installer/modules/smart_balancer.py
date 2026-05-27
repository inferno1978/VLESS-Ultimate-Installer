"""
vless_installer/modules/smart_balancer.py
───────────────────────────────────────────────────────────────────────────────
Smart Balancer — автоматический выбор лучшей exit-ноды по latency/bandwidth/load.

  • TCP-probe и TTFB-probe каждые PROBE_INTERVAL_MIN минут (cron)
  • Взвешенный score: latency 50%, bandwidth 30%, load 20%
  • Карантин "мёртвых" нод на QUARANTINE_MINUTES минут
  • Прямой патч config.json Xray без перезаписи всего конфига

Точка входа из _core.py:
    from vless_installer.modules.smart_balancer import (
        do_manage_smart_balancer, _smart_balancer_run_once,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────────
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

# ── Логирование ────────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] {clean}\n")
    except Exception:
        pass

def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO",    msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN",   msg)
def log_to_file(level: str, msg: str) -> None: _log(level, msg)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

# ── Делегируем в _core через importlib ────────────────────────────────────────
def _tg_notify_event(event: str, detail: str = "") -> None:
    try:
        import importlib
        _core = importlib.import_module("vless_installer._core")
        _core._tg_notify_event(event, detail)
    except Exception:
        pass

# ── Импорты из других модулей ─────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_ok, _box_warn, _wcslen, _BOX_W,
    RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC,
)

# ── Константы ─────────────────────────────────────────────────────────────────
_SB_STATE_FILE  = Path("/var/lib/xray-installer/smart_balancer.json")
_SB_LOG_FILE    = Path("/var/log/xray-smart-balancer.log")
_SB_CRON_FILE   = Path("/etc/cron.d/xray-smart-balancer")
_SB_CRON_SCRIPT = Path("/usr/local/bin/xray-smart-balancer.sh")
_STATE_FILE     = Path("/var/lib/xray-installer/state.json")

PROBE_INTERVAL_MIN = 15
QUARANTINE_MINUTES = 30
DEAD_THRESHOLD     = 3
PROBE_TIMEOUT_SEC  = 5

W_LATENCY   = 0.50
W_BANDWIDTH = 0.30
W_LOAD      = 0.20

NORM_LAT_MS_WORST  = 2000
NORM_BW_MS_WORST   = 5000
NORM_LOAD_WORST    = 200


def _sb_load() -> dict:
    """Загружает состояние балансировщика из JSON."""
    try:
        if _SB_STATE_FILE.exists():
            return json.loads(_SB_STATE_FILE.read_text())
    except Exception:
        pass
    return {
        "enabled":        False,
        "strategy":       "smart",    # smart | roundrobin | leastping | leastload | random
        "active_node_idx": -1,
        "nodes_meta":     {},          # host:port → {fails, quarantine_until, last_score, last_lat_ms, last_bw_ms, last_load}
        "history":        [],          # последние 100 событий переключения
        "weights":        {
            "latency":   W_LATENCY,
            "bandwidth": W_BANDWIDTH,
            "load":      W_LOAD,
        },
        "probe_interval_min": PROBE_INTERVAL_MIN,
        "quarantine_minutes": QUARANTINE_MINUTES,
        "dead_threshold":     DEAD_THRESHOLD,
    }


def _sb_save(state: dict) -> None:
    try:
        _SB_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SB_STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        _SB_STATE_FILE.chmod(0o600)
    except Exception:
        pass


def _sb_log(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        _SB_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _SB_LOG_FILE.open("a") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Probe functions
# ---------------------------------------------------------------------------

def _probe_tcp_latency(host: str, port: int, timeout: float = PROBE_TIMEOUT_SEC) -> float:
    """
    Измеряет TCP RTT (SYN → ACK) в миллисекундах.
    Возвращает float("inf") если нода недоступна.
    """
    try:
        t0 = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return (time.monotonic() - t0) * 1000.0
    except Exception:
        return float("inf")


def _probe_bandwidth_ttfb(host: str, port: int,
                          timeout: float = PROBE_TIMEOUT_SEC) -> float:
    """
    Измеряет TTFB через curl с прокси через ноду.
    Возвращает время в мс или float("inf").

    Примечание: curl пробует соединение напрямую к ноде (TCP),
    что косвенно отражает bandwidth. Для точного измерения
    нужен http-прокси, но это усложняет конфиг; пока используем
    прямой HTTP HEAD к публичному URL с таймаутом.
    """
    try:
        r = subprocess.run(
            [
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{time_starttransfer}",
                "--connect-timeout", str(int(timeout)),
                "--max-time", str(int(timeout * 1.5)),
                "--resolve", f"{host}:{port}:{host}",
                f"http://{host}:{port}",
            ],
            capture_output=True, text=True, timeout=timeout + 3
        )
        if r.returncode == 0 and r.stdout.strip():
            return float(r.stdout.strip()) * 1000.0
    except Exception:
        pass

    # Fallback: просто TCP латентность как оценка bandwidth
    lat = _probe_tcp_latency(host, port, timeout)
    return lat * 1.5 if lat != float("inf") else float("inf")


def _probe_active_connections(host: str, port: int) -> int:
    """
    Считает количество ESTABLISHED TCP-соединений к данной ноде через ss.
    Нагрузка (load) — косвенный показатель загруженности ноды.
    """
    try:
        r = subprocess.run(
            ["ss", "-tn", "state", "established", f"dst {host}:{port}"],
            capture_output=True, text=True, timeout=3
        )
        # Вычитаем 1 (header строку)
        lines = [l for l in r.stdout.strip().splitlines() if l.strip()]
        return max(0, len(lines) - 1)
    except Exception:
        return 0


def _probe_node(host: str, port: int) -> dict:
    """
    Полный зонд одной ноды.
    Возвращает dict с метриками или {"alive": False}.
    """
    lat_ms = _probe_tcp_latency(host, port)
    if lat_ms == float("inf"):
        return {"alive": False, "lat_ms": None, "bw_ms": None, "load": None}

    bw_ms = _probe_bandwidth_ttfb(host, port)
    load  = _probe_active_connections(host, port)

    return {
        "alive":  True,
        "lat_ms": round(lat_ms, 1),
        "bw_ms":  round(bw_ms, 1) if bw_ms != float("inf") else None,
        "load":   load,
    }


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _compute_score(lat_ms: float | None,
                   bw_ms:  float | None,
                   load:   int,
                   weights: dict) -> float:
    """
    Composite score [0..1]: меньше = лучше.
    Нормализует каждую метрику и взвешивает.
    """
    w_lat = weights.get("latency",   W_LATENCY)
    w_bw  = weights.get("bandwidth", W_BANDWIDTH)
    w_ld  = weights.get("load",      W_LOAD)

    lat_norm  = min(1.0, (lat_ms or NORM_LAT_MS_WORST)  / NORM_LAT_MS_WORST)
    bw_norm   = min(1.0, (bw_ms  or NORM_BW_MS_WORST)   / NORM_BW_MS_WORST)
    load_norm = min(1.0,  load                           / NORM_LOAD_WORST)

    return round(w_lat * lat_norm + w_bw * bw_norm + w_ld * load_norm, 4)


# ---------------------------------------------------------------------------
# Quarantine helpers
# ---------------------------------------------------------------------------

def _is_quarantined(meta: dict) -> bool:
    until = meta.get("quarantine_until", 0)
    return time.time() < until


def _quarantine_node(meta: dict, minutes: int) -> None:
    meta["quarantine_until"] = time.time() + minutes * 60
    meta["quarantine_until_str"] = datetime.fromtimestamp(
        meta["quarantine_until"]
    ).strftime("%Y-%m-%d %H:%M:%S")


def _release_from_quarantine(meta: dict) -> None:
    meta["quarantine_until"] = 0
    meta.pop("quarantine_until_str", None)
    meta["fails"] = 0


# ---------------------------------------------------------------------------
# Config patching — смена активной ноды в xray config.json
# ---------------------------------------------------------------------------

def _sb_get_xray_config_path() -> Path | None:
    for p in (Path("/etc/xray/config.json"),
              Path("/usr/local/etc/xray/config.json")):
        if p.exists():
            return p
    return None


def _sb_get_nodes_from_state() -> list[dict]:
    """
    Читает список exit-нод из state.json.
    Возвращает список dict с ключами: host, port, uuid, pubkey, short_id, sni, fp.
    """
    state_file = Path("/var/lib/xray-installer/state.json")
    try:
        if state_file.exists():
            st = json.loads(state_file.read_text())
            return st.get("chain_nodes", [])
    except Exception:
        pass
    return []


def _sb_patch_xray_active_node(node: dict) -> bool:
    """
    Меняет адрес/порт exit-outbound в xray config.json.
    Патчит первый outbound с тегом 'chain-exit-*' или 'proxy'.
    Возвращает True при успехе.
    """
    cfg_path = _sb_get_xray_config_path()
    if not cfg_path:
        return False
    try:
        cfg = json.loads(cfg_path.read_text())
        outbounds = cfg.get("outbounds", [])
        patched = False

        for ob in outbounds:
            tag = ob.get("tag", "")
            # Ищем exit outbound (chain или прямой proxy)
            if not (tag.startswith("chain-exit") or tag == "proxy" or
                    tag.startswith("exit")):
                continue

            settings = ob.setdefault("settings", {})
            vnext = settings.get("vnext") or settings.get("servers")
            if not vnext:
                # Пустой список — создаём структуру
                settings["vnext"] = [{
                    "address": node["host"],
                    "port":    int(node.get("port", 443)),
                    "users":   [{"id": node.get("uuid", ""), "encryption": "none",
                                 "flow": "xtls-rprx-vision"}],
                }]
            else:
                vnext[0]["address"] = node["host"]
                vnext[0]["port"]    = int(node.get("port", 443))
                if "users" in vnext[0] and vnext[0]["users"]:
                    vnext[0]["users"][0]["id"] = node.get("uuid", vnext[0]["users"][0]["id"])

            # Обновляем SNI и fp в streamSettings
            st = ob.get("streamSettings", {})
            for tls_key in ("realitySettings", "tlsSettings"):
                if tls_key in st:
                    if node.get("sni"):
                        st[tls_key]["serverName"] = node["sni"]
                    if node.get("pubkey") and tls_key == "realitySettings":
                        st[tls_key]["publicKey"] = node["pubkey"]
                    if node.get("short_id") and tls_key == "realitySettings":
                        st[tls_key]["shortId"] = node["short_id"]
                    if node.get("fp"):
                        st[tls_key]["fingerprint"] = node["fp"]

            patched = True
            break   # патчим только первый подходящий outbound

        if not patched:
            _sb_log("WARN: подходящий exit-outbound не найден в конфиге")
            return False

        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        cfg_path.chmod(0o640)
        return True
    except Exception as e:
        _sb_log(f"ERROR patch config: {e}")
        return False


def _sb_reload_xray() -> bool:
    """
    Перезапускает xray после смены ноды Smart Balancer.

    Важно: xray.service использует ExecReload=/bin/systemctl restart xray,
    поэтому любой reload — это полный restart, обрывающий соединения клиентов.
    Чтобы минимизировать влияние:
      1. Даём клиентам 3 сек завершить текущие запросы (graceful window).
      2. Используем 'systemctl restart' напрямую.
      3. Ждём до 15 сек подъёма сервиса.
      4. После подъёма xray перезапускаем nginx — иначе при REALITY+Unix-сокет
         nginx продолжает держать старый сокет-путь и клиенты получают EOF.
    """
    _sb_log("INFO: пауза 3 сек перед restart (graceful window для клиентов)...")
    time.sleep(3)

    subprocess.run(["systemctl", "restart", "xray"],
                   capture_output=True, timeout=30)

    # Ждём подъёма до 15 сек
    xray_up = False
    for _ in range(5):
        time.sleep(3)
        r = subprocess.run(
            ["systemctl", "is-active", "xray"], capture_output=True, text=True, timeout=5
        )
        if r.stdout.strip() == "active":
            _sb_log("INFO: xray restart после смены ноды — OK")
            xray_up = True
            break

    if not xray_up:
        _sb_log("ERROR: xray не поднялся после restart Smart Balancer")
        return False

    # Перезапускаем nginx чтобы он пересоздал Unix-сокет xray.
    # ВАЖНО: нужен именно restart, не reload.
    # При REALITY+Unix-сокет xray ExecStartPre удаляет старый /dev/shm/XXXX.socket,
    # создаёт новый. nginx reload только перечитывает конфиг — сокет не пересоздаёт.
    # Без nginx restart клиенты получают EOF сразу после переключения ноды.
    rn = subprocess.run(
        ["systemctl", "is-active", "nginx"], capture_output=True, text=True, timeout=5
    )
    if rn.stdout.strip() == "active":
        subprocess.run(["systemctl", "restart", "nginx"],
                       capture_output=True, timeout=15)
        _sb_log("INFO: nginx restart после смены ноды — OK")
    else:
        _sb_log("WARN: nginx не активен — пропуск перезапуска")

    return True


# ---------------------------------------------------------------------------
# AWG guard helper для cron-задач
# ---------------------------------------------------------------------------

def _awg_guard_cron(label: str) -> bool:
    """
    Возвращает True и пишет в лог если AWG активен и cron-задача неприменима.
    Использование: if _awg_guard_cron("label"): return
    """
    try:
        if _STATE_FILE.exists():
            _st = json.loads(_STATE_FILE.read_text())
            if _st.get("awg_exit_enabled", False) and _st.get("install_mode") == "B":
                log_to_file("INFO", f"[{label}] AWG-режим активен — задача пропущена")
                return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Core: одна итерация балансировки
# ---------------------------------------------------------------------------

def _smart_balancer_run_once() -> None:
    """
    Главная функция. Запускается из cron каждые N минут.
    1. Зондирует все ноды.
    2. Обновляет метаданные (fails, quarantine).
    3. Выбирает лучшую ноду по composite score.
    4. Если текущая нода изменилась → патчит конфиг и перезагружает xray.
    """
    # ── AWG-режим: балансировщик нод не применим — тихий выход ──────────────
    if _awg_guard_cron("SmartBalancer"):
        return

    state    = _sb_load()
    if not state.get("enabled"):
        return

    nodes    = _sb_get_nodes_from_state()
    if not nodes:
        _sb_log("WARN: нет exit-нод в state.json — пропуск")
        return

    strategy       = state.get("strategy", "smart")
    weights        = state.get("weights", {})
    q_minutes      = state.get("quarantine_minutes", QUARANTINE_MINUTES)
    dead_threshold = state.get("dead_threshold",     DEAD_THRESHOLD)
    nodes_meta     = state.get("nodes_meta", {})

    # ------------------------------------------------------------------
    # 1. Зондирование
    # ------------------------------------------------------------------
    probe_results: list[dict] = []

    for i, node in enumerate(nodes):
        host = node.get("host", "")
        port = int(node.get("port", 443))
        key  = f"{host}:{port}"

        if key not in nodes_meta:
            nodes_meta[key] = {
                "fails": 0, "quarantine_until": 0,
                "last_score": None, "last_lat_ms": None,
                "last_bw_ms": None, "last_load": 0,
            }

        meta = nodes_meta[key]

        # Снимаем карантин если время вышло
        if _is_quarantined(meta):
            _sb_log(f"INFO: нода {key} в карантине до {meta.get('quarantine_until_str','?')} — пропуск")
            probe_results.append({
                "idx": i, "key": key, "node": node,
                "alive": False, "quarantined": True,
                "score": 1.0, "meta": meta,
            })
            continue
        elif meta.get("quarantine_until", 0) > 0:
            # Карантин истёк
            _sb_log(f"INFO: карантин {key} снят — возврат в пул")
            _release_from_quarantine(meta)

        # Собственно зонд
        result = _probe_node(host, port)

        if not result["alive"]:
            meta["fails"] = meta.get("fails", 0) + 1
            _sb_log(f"WARN: нода {key} недоступна (провалов подряд: {meta['fails']})")
            if meta["fails"] >= dead_threshold:
                _quarantine_node(meta, q_minutes)
                _sb_log(
                    f"ALERT: нода {key} переведена в карантин на {q_minutes} мин "
                    f"(провалов: {meta['fails']})"
                )
                # TG уведомление
                try:
                    _tg_notify_event(  # type: ignore[name-defined]
                        "xray_down",
                        f"⚠️ SmartBalancer: нода <b>{host}:{port}</b> "
                        f"недоступна {meta['fails']}×, карантин {q_minutes} мин"
                    )
                except Exception:
                    pass
            probe_results.append({
                "idx": i, "key": key, "node": node,
                "alive": False, "quarantined": False,
                "score": 1.0, "meta": meta,
            })
        else:
            # Нода жива — сбрасываем счётчик провалов
            meta["fails"] = 0
            lat_ms = result["lat_ms"]
            bw_ms  = result["bw_ms"]
            load   = result.get("load", 0)

            if strategy == "smart":
                score = _compute_score(lat_ms, bw_ms, load, weights)
            elif strategy == "leastping":
                score = _compute_score(lat_ms, None, 0,
                                       {"latency": 1.0, "bandwidth": 0.0, "load": 0.0})
            elif strategy == "leastload":
                score = _compute_score(None, None, load,
                                       {"latency": 0.0, "bandwidth": 0.0, "load": 1.0})
            elif strategy == "random":
                import random as _rnd
                score = _rnd.random()
            else:   # roundrobin — score = порядковый номер (обработаем ниже)
                score = float(i)

            meta["last_score"]  = score
            meta["last_lat_ms"] = lat_ms
            meta["last_bw_ms"]  = bw_ms
            meta["last_load"]   = load

            probe_results.append({
                "idx": i, "key": key, "node": node,
                "alive": True, "quarantined": False,
                "score": score, "meta": meta,
                "lat_ms": lat_ms, "bw_ms": bw_ms, "load": load,
            })

    state["nodes_meta"] = nodes_meta

    # ------------------------------------------------------------------
    # 2. Выбор лучшей ноды
    # ------------------------------------------------------------------
    alive = [r for r in probe_results if r["alive"]]
    if not alive:
        _sb_log("ERROR: все ноды недоступны или в карантине — нет переключения")
        _sb_save(state)
        return

    if strategy == "roundrobin":
        # Следующая живая нода по порядку
        cur_idx  = state.get("active_node_idx", -1)
        cur_keys = [r["key"] for r in alive]
        next_pos = 0
        for j, r in enumerate(alive):
            if r["idx"] > cur_idx:
                next_pos = j
                break
        best = alive[next_pos]
    else:
        best = min(alive, key=lambda r: r["score"])

    # ------------------------------------------------------------------
    # 3. Применяем если нода изменилась (с гистерезисом)
    # ------------------------------------------------------------------
    prev_idx = state.get("active_node_idx", -1)
    if best["idx"] == prev_idx:
        _sb_log(
            f"OK: нода {best['key']} остаётся активной "
            f"(score={best['score']:.4f})"
        )
        _sb_save(state)
        return

    # Гистерезис — переключаемся только если новая нода значимо лучше текущей.
    # Предотвращает лишние restart Xray при незначительных колебаниях метрик.
    # При первом запуске (prev_idx == -1) гистерезис не применяем — нужно
    # установить активную ноду.
    HYSTERESIS_THRESHOLD = state.get("hysteresis_threshold", 0.15)  # 15%
    if strategy not in ("roundrobin", "random") and 0 <= prev_idx < len(nodes):
        cur_results = [r for r in alive if r["idx"] == prev_idx]
        if cur_results:
            cur_score  = cur_results[0]["score"]
            best_score = best["score"]
            if cur_score > 0 and (cur_score - best_score) / cur_score < HYSTERESIS_THRESHOLD:
                _sb_log(
                    f"OK: нода {nodes[prev_idx]['host']}:{nodes[prev_idx].get('port',443)} "
                    f"остаётся активной (гистерезис: cur={cur_score:.4f}, "
                    f"best={best_score:.4f}, delta={((cur_score-best_score)/cur_score*100):.1f}% "
                    f"< {HYSTERESIS_THRESHOLD*100:.0f}%)"
                )
                _sb_save(state)
                return

    old_key = nodes[prev_idx]["host"] + ":" + str(nodes[prev_idx].get("port", 443)) \
              if 0 <= prev_idx < len(nodes) else "—"
    new_key = best["key"]

    _sb_log(
        f"SWITCH: {old_key} → {new_key} "
        f"(strategy={strategy}, score={best['score']:.4f}, "
        f"lat={best.get('lat_ms')}ms, bw={best.get('bw_ms')}ms, "
        f"load={best.get('load')})"
    )

    patched = _sb_patch_xray_active_node(best["node"])
    if patched:
        xray_ok = _sb_reload_xray()
        status  = "OK" if xray_ok else "XRAY_RESTART_FAIL"
    else:
        status = "PATCH_FAIL"
        xray_ok = False

    # Запись в историю
    history = state.get("history", [])
    history.append({
        "ts":        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "from":      old_key,
        "to":        new_key,
        "score":     best["score"],
        "lat_ms":    best.get("lat_ms"),
        "bw_ms":     best.get("bw_ms"),
        "load":      best.get("load"),
        "strategy":  strategy,
        "status":    status,
    })
    state["history"] = history[-100:]  # хранить последние 100

    state["active_node_idx"] = best["idx"]
    _sb_save(state)

    # TG уведомление при успешном переключении
    if xray_ok:
        try:
            _tg_notify_event(  # type: ignore[name-defined]
                "node_connect",
                f"✅ SmartBalancer: переключение <b>{old_key}</b> → <b>{new_key}</b> "
                f"(score={best['score']:.3f}, lat={best.get('lat_ms')}ms)"
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Cron installer
# ---------------------------------------------------------------------------

def _sb_install_cron(interval_min: int = PROBE_INTERVAL_MIN) -> None:
    """Устанавливает cron-скрипт для запуска Smart Balancer."""
    # Определяем путь к текущему скрипту
    try:
        script_self = Path(sys.argv[0]).resolve()
    except Exception:
        script_self = Path("/root/install_v431.py")

    sh_script = textwrap.dedent(f"""\
        #!/bin/bash
        # Smart Balancer — автоматический выбор лучшей exit-ноды
        # Установлен VLESS Ultimate Installer
        LOG="{_SB_LOG_FILE}"
        LOCK="/var/run/xray-smart-balancer.lock"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')

        # Путь к install.py — сначала оригинальный, потом fallback-поиск
        INSTALLER="{script_self}"
        if [ ! -f "$INSTALLER" ]; then
            FOUND=$(find /root -maxdepth 2 -name "install*.py" -newer /etc/cron.d/xray-smart-balancer 2>/dev/null | head -1)
            if [ -z "$FOUND" ]; then
                FOUND=$(find /root -maxdepth 2 -name "install*.py" 2>/dev/null | head -1)
            fi
            if [ -n "$FOUND" ]; then
                INSTALLER="$FOUND"
                echo "[$DATE] WARN: основной путь не найден, использую $INSTALLER" >> "$LOG"
            else
                echo "[$DATE] ERROR: install.py не найден — обновите путь в $0" >> "$LOG"
                exit 2
            fi
        fi

        # Защита от параллельных запусков (если предыдущий ещё не завершился)
        if [ -f "$LOCK" ]; then
            LOCK_PID=$(cat "$LOCK" 2>/dev/null)
            if kill -0 "$LOCK_PID" 2>/dev/null; then
                echo "[$DATE] Smart Balancer: уже запущен (PID $LOCK_PID) — пропуск" >> "$LOG"
                exit 0
            fi
            # PID мёртв — старый lock, удаляем
            rm -f "$LOCK"
        fi

        echo $$ > "$LOCK"
        trap "rm -f $LOCK" EXIT

        echo "[$DATE] Smart Balancer probe start" >> "$LOG"
        python3 "$INSTALLER" --smart-balance >> "$LOG" 2>&1
        # Перезапускаем nginx после каждого probe — гарантируем что Unix-сокет
        # /dev/shm/XXXX.socket существует. Нужен restart (не reload) т.к. только
        # restart пересоздаёт сокет после того как xray его удалил через ExecStartPre.
        systemctl restart nginx >> "$LOG" 2>&1 \
            && echo "[$DATE] nginx restart — OK" >> "$LOG" \
            || echo "[$DATE] nginx restart — FAIL" >> "$LOG"
        echo "[$DATE] Smart Balancer probe done (exit 0)" >> "$LOG"
    """)
    _SB_CRON_SCRIPT.write_text(sh_script)
    _SB_CRON_SCRIPT.chmod(0o750)

    # cron каждые N минут
    if interval_min <= 1:
        schedule = "* * * * *"
    else:
        schedule = f"*/{interval_min} * * * *"

    _SB_CRON_FILE.write_text(
        f"# Smart Balancer — каждые {interval_min} минут\n"
        f"{schedule} root {_SB_CRON_SCRIPT} >> {_SB_LOG_FILE} 2>&1\n"
    )
    _SB_CRON_FILE.chmod(0o644)


def _sb_remove_cron() -> None:
    _SB_CRON_FILE.unlink(missing_ok=True)
    _SB_CRON_SCRIPT.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# TUI — главное меню Smart Balancer
# ---------------------------------------------------------------------------

def do_manage_smart_balancer() -> None:
    """
    Интерактивное управление Smart Balancer.
    Вызывается из главного меню / меню безопасности.
    """
    # ── AWG-режим: балансировщик нод не применим ────────────────────────────
    try:
        if _STATE_FILE.exists():
            _st = json.loads(_STATE_FILE.read_text())
            if _st.get("awg_exit_enabled", False) and _st.get("install_mode") == "B":
                print()
                _box_top("⚡  SMART BALANCER")
                _box_warn("В режиме AWG 2.0 Smart Balancer недоступен.")
                _box_row(f"  {DIM}Балансировщик работает только с VLESS exit-нодами.{NC}")
                _box_row(f"  {DIM}При AWG выход осуществляется через единый туннель awg0.{NC}")
                _box_bottom()
                input(f"{BLUE}Нажмите Enter...{NC}")
                return
    except Exception:
        pass

    global _BOX_W
    while True:
        os.system("clear")
        print()

        state    = _sb_load()
        enabled  = state.get("enabled", False)
        strategy = state.get("strategy", "smart")
        weights  = state.get("weights", {"latency": W_LATENCY,
                                          "bandwidth": W_BANDWIDTH,
                                          "load": W_LOAD})
        nodes    = _sb_get_nodes_from_state()
        cur_idx  = state.get("active_node_idx", -1)
        nodes_meta = state.get("nodes_meta", {})
        q_minutes  = state.get("quarantine_minutes", QUARANTINE_MINUTES)
        dead_thr   = state.get("dead_threshold", DEAD_THRESHOLD)
        cron_on    = _SB_CRON_FILE.exists()
        history    = state.get("history", [])

        # ----------- заголовок ----------------------------------------
        _box_top("⚡  SMART BALANCER — Авто-выбор лучшей exit-ноды")  # type: ignore[name-defined]
        _box_row()  # type: ignore[name-defined]

        # Статус
        st_str = f"{GREEN}ВКЛЮЧЁН{NC}" if enabled else f"{YELLOW}ВЫКЛЮЧЕН{NC}"
        _box_row(f"  Статус:        {st_str}")  # type: ignore[name-defined]
        _box_row(f"  Стратегия:     {CYAN}{strategy}{NC}")  # type: ignore[name-defined]
        _box_row(f"  Cron ({state.get('probe_interval_min', PROBE_INTERVAL_MIN)} мин): "  # type: ignore[name-defined]
                 f"{''+GREEN+'активен'+NC if cron_on else ''+YELLOW+'выключен'+NC}")
        _box_row(f"  Карантин:      {q_minutes} мин  |  порог провалов: {dead_thr}×")  # type: ignore[name-defined]

        if strategy == "smart":
            _box_row(  # type: ignore[name-defined]
                f"  Веса:          "
                f"latency={weights.get('latency', W_LATENCY):.0%}  "
                f"bandwidth={weights.get('bandwidth', W_BANDWIDTH):.0%}  "
                f"load={weights.get('load', W_LOAD):.0%}"
            )

        # Ноды
        _box_sep()  # type: ignore[name-defined]
        if nodes:
            _box_row(f"  {BOLD}Exit-ноды ({len(nodes)}):{NC}")  # type: ignore[name-defined]
            for i, nd in enumerate(nodes):
                h = nd.get("host", "?")
                p = nd.get("port", 443)
                key = f"{h}:{p}"
                meta = nodes_meta.get(key, {})
                score    = meta.get("last_score")
                lat_ms   = meta.get("last_lat_ms")
                bw_ms    = meta.get("last_bw_ms")
                fails    = meta.get("fails", 0)
                qtime    = meta.get("quarantine_until_str", "")

                if _is_quarantined(meta):
                    status_col = f"{RED}🔴 карантин до {qtime}{NC}"
                elif i == cur_idx:
                    status_col = f"{GREEN}● активна{NC}"
                elif score is not None:
                    col = GREEN if score < 0.3 else YELLOW if score < 0.6 else RED
                    status_col = f"{col}score={score:.3f}{NC}"
                else:
                    status_col = f"{DIM}не проверялась{NC}"

                lat_str = f"lat={lat_ms}ms" if lat_ms else ""
                bw_str  = f"bw={bw_ms}ms"  if bw_ms  else ""
                extra   = "  ".join(filter(None, [lat_str, bw_str]))
                marker  = f"{CYAN}▶{NC}" if i == cur_idx else f"{DIM} {NC}"
                # Строим одну строку и проверяем влезает ли она в рамку
                line1 = f"  {marker} [{i}] {BOLD}{h}:{p}{NC}  {status_col}  {DIM}{extra}{NC}"
                if _wcslen(line1) <= _BOX_W:  # type: ignore[name-defined]
                    _box_row(line1)  # type: ignore[name-defined]
                else:
                    # Не влезает — хост на первой строке, метрики на второй
                    _box_row(f"  {marker} [{i}] {BOLD}{h}:{p}{NC}  {status_col}")  # type: ignore[name-defined]
                    if extra:
                        _box_row(f"       {DIM}{extra}{NC}")  # type: ignore[name-defined]
        else:
            _box_row(f"  {YELLOW}Нет exit-нод в state.json (нужен Режим B){NC}")  # type: ignore[name-defined]

        # Последнее переключение — разбиваем на 2 строки чтобы вписаться в рамку
        if history:
            last = history[-1]
            _box_sep()  # type: ignore[name-defined]
            _box_row(f"  {DIM}Последнее переключение: {last['ts']}{NC}")  # type: ignore[name-defined]
            _box_row(  # type: ignore[name-defined]
                f"    {DIM}{last['from']} → {last['to']}  "
                f"score={last['score']:.3f}{NC}"
            )

        # Меню
        _box_sep()  # type: ignore[name-defined]
        _box_item("1", f"{'Выключить' if enabled else 'Включить'} Smart Balancer")  # type: ignore[name-defined]
        _box_item("2", f"Сменить стратегию  {DIM}(текущая: {strategy}){NC}")  # type: ignore[name-defined]
        _box_item("3", f"Настроить веса  {DIM}(latency / bandwidth / load){NC}")  # type: ignore[name-defined]
        _box_item("4", f"Карантин и пороги провалов")  # type: ignore[name-defined]
        _box_item("5", f"{'Остановить' if cron_on else 'Запустить'} cron (автозонд каждые {state.get('probe_interval_min', PROBE_INTERVAL_MIN)} мин)")  # type: ignore[name-defined]
        _box_item("6", f"Зондировать ноды прямо сейчас")  # type: ignore[name-defined]
        _box_item("7", f"Историй переключений")  # type: ignore[name-defined]
        _box_item("8", f"Снять карантин вручную")  # type: ignore[name-defined]
        _box_row()  # type: ignore[name-defined]
        _box_back()  # type: ignore[name-defined]
        _box_bottom()  # type: ignore[name-defined]

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        # ── 1: Вкл/выкл ─────────────────────────────────────────────────
        if ch == "1":
            state["enabled"] = not enabled
            _sb_save(state)
            if state["enabled"]:
                # Спрашиваем интервал при включении
                print()
                cur_interval = state.get("probe_interval_min", PROBE_INTERVAL_MIN)
                print(f"  {CYAN}Рекомендуемый интервал зонда: 15–30 мин.{NC}")
                print(f"  {DIM}Слишком частый запуск (< 5 мин) увеличивает число restartов Xray{NC}")
                print(f"  {DIM}и вызывает разрывы соединений у клиентов.{NC}")
                print()
                raw_i = input(
                    f"  Интервал cron-зонда (мин) [{cur_interval}]: "
                ).strip()
                if raw_i.isdigit() and int(raw_i) >= 1:
                    state["probe_interval_min"] = int(raw_i)
                    _sb_save(state)
                _sb_install_cron(state.get("probe_interval_min", PROBE_INTERVAL_MIN))
                print(f"{GREEN}Smart Balancer включён. Cron: каждые {state.get('probe_interval_min', PROBE_INTERVAL_MIN)} мин.{NC}")
            else:
                _sb_remove_cron()
                print(f"{YELLOW}Smart Balancer выключен. Cron удалён.{NC}")
            time.sleep(1.5)

        # ── 2: Стратегия ────────────────────────────────────────────────
        elif ch == "2":
            print()
            _box_top("Выбор стратегии балансировки")  # type: ignore[name-defined]
            strategies = [
                ("smart",      f"Smart (latency + bandwidth + load) {GREEN}★ рекомендуется{NC}"),
                ("leastping",  "Least Ping — минимальная задержка"),
                ("leastload",  "Least Load — минимум активных соединений"),
                ("roundrobin", "Round Robin — по очереди"),
                ("random",     "Random — случайная нода"),
            ]
            for i, (k, label) in enumerate(strategies, 1):
                cur_mark = f" {CYAN}(текущая){NC}" if k == strategy else ""
                _box_item(str(i), f"{label}{cur_mark}")  # type: ignore[name-defined]
            _box_bottom()  # type: ignore[name-defined]
            try:
                s_ch = input(f"{CYAN}Выбор [1-5]:{NC} ").strip()
                if s_ch.isdigit() and 1 <= int(s_ch) <= len(strategies):
                    state["strategy"] = strategies[int(s_ch) - 1][0]
                    _sb_save(state)
                    print(f"{GREEN}Стратегия: {state['strategy']}{NC}")
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

        # ── 3: Веса ─────────────────────────────────────────────────────
        elif ch == "3":
            if state.get("strategy") != "smart":
                print(f"{YELLOW}Веса применяются только для стратегии 'smart'.{NC}")
                time.sleep(2)
                continue
            print()
            _box_top("Настройка весов composite score")  # type: ignore[name-defined]
            _box_row(f"  {DIM}Сумма весов должна = 1.0. Введите дробное число (0.0–1.0){NC}")  # type: ignore[name-defined]
            _box_row(f"  {DIM}Пустой ввод = оставить текущее значение{NC}")  # type: ignore[name-defined]
            _box_bottom()  # type: ignore[name-defined]
            new_w = dict(weights)
            try:
                for key_w, default in [("latency", W_LATENCY),
                                       ("bandwidth", W_BANDWIDTH),
                                       ("load", W_LOAD)]:
                    cur = weights.get(key_w, default)
                    raw = input(
                        f"  {key_w} [{cur:.2f}]: "
                    ).strip()
                    if raw:
                        try:
                            new_w[key_w] = float(raw)
                        except ValueError:
                            print(f"{YELLOW}Некорректное значение, оставлено {cur:.2f}{NC}")
                # Нормализуем
                total = sum(new_w.values())
                if total > 0:
                    for k2 in new_w:
                        new_w[k2] = round(new_w[k2] / total, 4)
                state["weights"] = new_w
                _sb_save(state)
                print(f"{GREEN}Веса сохранены: {new_w}{NC}")
            except KeyboardInterrupt:
                pass
            time.sleep(1)

        # ── 4: Карантин ─────────────────────────────────────────────────
        elif ch == "4":
            print()
            _box_top("Настройка карантина")  # type: ignore[name-defined]
            _box_row(f"  Текущий карантин: {q_minutes} мин")  # type: ignore[name-defined]
            _box_row(f"  Порог провалов:   {dead_thr}×")  # type: ignore[name-defined]
            _box_bottom()  # type: ignore[name-defined]
            try:
                raw_q = input(f"  Карантин (мин) [{q_minutes}]: ").strip()
                if raw_q.isdigit():
                    state["quarantine_minutes"] = int(raw_q)
                raw_d = input(f"  Порог провалов [{dead_thr}]: ").strip()
                if raw_d.isdigit():
                    state["dead_threshold"] = int(raw_d)
                _sb_save(state)
                print(f"{GREEN}Параметры карантина сохранены.{NC}")
            except KeyboardInterrupt:
                pass
            time.sleep(1)

        # ── 5: Cron ─────────────────────────────────────────────────────
        elif ch == "5":
            if cron_on:
                _sb_remove_cron()
                print(f"{YELLOW}Cron Smart Balancer остановлен.{NC}")
            else:
                raw_i = input(
                    f"  Интервал зонда (мин) [{state.get('probe_interval_min', PROBE_INTERVAL_MIN)}]: "
                ).strip()
                if raw_i.isdigit():
                    state["probe_interval_min"] = int(raw_i)
                    _sb_save(state)
                _sb_install_cron(state.get("probe_interval_min", PROBE_INTERVAL_MIN))
                print(f"{GREEN}Cron установлен (каждые {state.get('probe_interval_min', PROBE_INTERVAL_MIN)} мин).{NC}")
            time.sleep(1)

        # ── 6: Ручной зонд ──────────────────────────────────────────────
        elif ch == "6":
            os.system("clear")
            print()
            _box_top("⚡ Зондирование exit-нод")  # type: ignore[name-defined]
            if not nodes:
                _box_row(f"  {YELLOW}Нет exit-нод (нужен Режим B){NC}")  # type: ignore[name-defined]
                _box_bottom()  # type: ignore[name-defined]
                input(f"{CYAN}Нажмите Enter...{NC}")
                continue

            _box_row(  # type: ignore[name-defined]
                f"  {'Нода':<28} {'Latency':>10} {'BW(TTFB)':>10} "
                f"{'Load':>6} {'Score':>8} {'Статус'}"
            )
            _box_sep()  # type: ignore[name-defined]

            probe_data = []
            for i, nd in enumerate(nodes):
                h   = nd.get("host", "?")
                p   = int(nd.get("port", 443))
                key = f"{h}:{p}"
                _box_row(f"  Зондирую {CYAN}{h}:{p}{NC}...")  # type: ignore[name-defined]

                result = _probe_node(h, p)
                if result["alive"]:
                    lat  = result["lat_ms"]
                    bw   = result["bw_ms"] or lat * 1.5
                    load = result.get("load", 0)
                    score = _compute_score(lat, bw, load, weights)
                    col = GREEN if score < 0.3 else YELLOW if score < 0.6 else RED

                    # Обновляем meta
                    state.setdefault("nodes_meta", {})
                    state["nodes_meta"].setdefault(key, {})
                    state["nodes_meta"][key].update({
                        "fails": 0,
                        "last_score":  score,
                        "last_lat_ms": lat,
                        "last_bw_ms":  bw,
                        "last_load":   load,
                    })

                    probe_data.append((i, nd, score))
                    lat_s  = f"{lat:.0f}ms"   if lat  else "—"
                    bw_s   = f"{bw:.0f}ms"    if bw   else "—"
                    status = f"{col}OK{NC}"
                else:
                    score = 1.0
                    lat_s = bw_s = "—"
                    status = f"{RED}недоступна{NC}"
                    probe_data.append((i, nd, 2.0))  # score > 1 → не выбирать

                _box_row(  # type: ignore[name-defined]
                    f"  [{i}] {h:<25} {lat_s:>10} {bw_s:>10} "
                    f"{load if result['alive'] else '—':>6} "
                    f"{score:>8.4f} {status}"
                )

            _sb_save(state)

            # Лучшая нода — показываем внутри бокса, затем закрываем его
            _box_sep()  # type: ignore[name-defined]
            alive_probes = [(i, nd, sc) for i, nd, sc in probe_data if sc <= 1.0]
            if alive_probes:
                best_i, best_nd, best_sc = min(alive_probes, key=lambda x: x[2])
                _box_row(  # type: ignore[name-defined]
                    f"  {GREEN}★ Лучшая нода: [{best_i}] "
                    f"{best_nd['host']}:{best_nd.get('port', 443)} "
                    f"(score={best_sc:.4f}){NC}"
                )
                _box_bottom()  # type: ignore[name-defined]  ← закрываем бокс

                # Вопрос — вне рамок
                print()
                ans = input(
                    f"  {CYAN}Применить эту ноду прямо сейчас? [Y/n]:{NC} "
                ).strip().lower()
                print()

                if ans in ("y", "yes", ""):
                    if _sb_patch_xray_active_node(best_nd):
                        ok = _sb_reload_xray()
                        if ok:
                            state["active_node_idx"] = best_i
                            _sb_save(state)
                            # Результат — в рамке
                            _box_top("Результат")  # type: ignore[name-defined]
                            _box_ok(f"Нода [{best_i}] {best_nd['host']}:{best_nd.get('port', 443)} применена")  # type: ignore[name-defined]
                            _box_ok("Xray перезагружен успешно")  # type: ignore[name-defined]
                            _box_bottom()  # type: ignore[name-defined]
                        else:
                            _box_top("Результат")  # type: ignore[name-defined]
                            _box_warn("Xray не перезапустился — проверьте конфиг")  # type: ignore[name-defined]
                            _box_bottom()  # type: ignore[name-defined]
                    else:
                        _box_top("Результат")  # type: ignore[name-defined]
                        _box_warn("Не удалось патчнуть конфиг")  # type: ignore[name-defined]
                        _box_bottom()  # type: ignore[name-defined]
                else:
                    _box_top("Результат")  # type: ignore[name-defined]
                    _box_row(f"  {DIM}Нода не применена — отменено пользователем{NC}")  # type: ignore[name-defined]
                    _box_bottom()  # type: ignore[name-defined]
            else:
                _box_row(f"  {RED}Все ноды недоступны!{NC}")  # type: ignore[name-defined]
                _box_bottom()  # type: ignore[name-defined]

            print()
            input(f"{CYAN}Нажмите Enter...{NC}")

        # ── 7: История ───────────────────────────────────────────────────
        elif ch == "7":
            os.system("clear")
            print()

            # Двухстрочный формат — каждая запись занимает 2 строки:
            #   Строка 1: Время  Откуда → Куда
            #   Строка 2: (отступ)  Score  Strat  Статус
            # Это гарантирует что все данные помещаются в рамку при любой ширине терминала.
            _W_TS    = 19   # "2026-05-03 04:05:08"
            _W_ADDR  = 24   # "totalshadows.online:443"
            _W_SCORE =  6   # "0.0010"
            _W_STRAT =  7   # "smart"
            _W_INDENT = 2 + _W_TS + 1  # отступ для второй строки = выровнять под Откуда

            _box_top("История переключений Smart Balancer")  # type: ignore[name-defined]
            if not history:
                _box_row(f"  {DIM}Переключений ещё не было{NC}")  # type: ignore[name-defined]
            else:
                # Заголовок таблицы — две строки
                _box_row(  # type: ignore[name-defined]
                    f"  {BOLD}"
                    f"{'Время':<{_W_TS}} "
                    f"{'Откуда':<{_W_ADDR}} "
                    f"{'Куда'}{NC}"
                )
                _box_row(  # type: ignore[name-defined]
                    f"  {BOLD}"
                    f"{'':<{_W_TS}} "
                    f"{'Score':>{_W_SCORE}} "
                    f"{'Strat':<{_W_STRAT}} "
                    f"Статус{NC}"
                )
                _box_sep()  # type: ignore[name-defined]

                for ev in reversed(history[-30:]):
                    col    = GREEN if ev.get("status") == "OK" else RED
                    ts     = ev.get("ts", "—")
                    frm    = ev.get("from", "—")
                    to_    = ev.get("to",   "—")
                    score  = f"{ev.get('score', 0):>{_W_SCORE}.4f}"
                    strat  = ev.get("strategy", "—")
                    status = ev.get("status", "?")
                    # Строка 1: время, откуда, куда
                    _box_row(  # type: ignore[name-defined]
                        f"  {ts:<{_W_TS}} "
                        f"{frm:<{_W_ADDR}} "
                        f"{to_}"
                    )
                    # Строка 2: score, стратегия, статус (с отступом под колонку откуда)
                    _box_row(  # type: ignore[name-defined]
                        f"  {'':<{_W_TS}} "
                        f"{score} "
                        f"{strat:<{_W_STRAT}} "
                        f"{col}{status}{NC}"
                    )

            _box_bottom()  # type: ignore[name-defined]
            input(f"{CYAN}Нажмите Enter...{NC}")

        # ── 8: Снять карантин вручную ────────────────────────────────────
        elif ch == "8":
            quarantined = [
                (key, meta) for key, meta in state.get("nodes_meta", {}).items()
                if _is_quarantined(meta)
            ]
            if not quarantined:
                print(f"{GREEN}Нет нод в карантине.{NC}")
                time.sleep(2)
                continue
            print()
            _box_top("Снять карантин вручную")  # type: ignore[name-defined]
            for i, (key, meta) in enumerate(quarantined, 1):
                _box_item(str(i), f"{key}  (до {meta.get('quarantine_until_str','?')})")  # type: ignore[name-defined]
            _box_item("A", "Снять с ВСЕХ нод")  # type: ignore[name-defined]
            _box_bottom()  # type: ignore[name-defined]
            try:
                raw = input(f"{CYAN}Выбор:{NC} ").strip().lower()
                if raw == "a":
                    for key, meta in quarantined:
                        _release_from_quarantine(meta)
                    print(f"{GREEN}Карантин снят со всех нод.{NC}")
                elif raw.isdigit() and 1 <= int(raw) <= len(quarantined):
                    key, meta = quarantined[int(raw) - 1]
                    _release_from_quarantine(meta)
                    print(f"{GREEN}Карантин снят: {key}{NC}")
                _sb_save(state)
            except KeyboardInterrupt:
                pass
            time.sleep(1)

        elif ch in ("q", ""):
            break
        else:
            print(f"{YELLOW}Неверный выбор{NC}")
            time.sleep(1)


# =============================================================================
#  ФУНКЦИЯ 2: АВТО-ФОЛБЭК В РЕЖИМ A ПРИ ОТКАЗЕ ВСЕХ EXIT-НОД
# =============================================================================

_AUTO_FALLBACK_SCRIPT  = Path("/usr/local/bin/xray-auto-fallback.sh")
_AUTO_FALLBACK_CRON    = Path("/etc/cron.d/xray-auto-fallback")
_AUTO_FALLBACK_LOGFILE = Path("/var/log/xray-auto-fallback.log")

# =============================================================================
#  AWG TUNNEL WATCHDOG — мониторинг туннеля awg0 (ip rule fallback)
#  Отдельный механизм от нодового авто-фолбэка (xray-auto-fallback).
#  Управляет только ip rule fwmark без перезапуска Xray или смены режима.
# =============================================================================
_AWG_WATCHDOG_SCRIPT = Path("/usr/local/bin/awg-fallback-check.sh")
_AWG_WATCHDOG_CRON   = Path("/etc/cron.d/awg-tunnel-watchdog")
_AWG_WATCHDOG_LOG    = Path("/var/log/awg-fallback.log")
_AWG_WATCHDOG_STATE  = Path("/var/run/awg-fallback.state")


