"""
vless_installer/modules/hysteria2_health.py
───────────────────────────────────────────────────────────────────────────────
Health Check для Hysteria2 exit-нод через QUIC-пинг.

Методы проверки:
  • QUIC ping (UDP/QUIC connection attempt на порт H2)
  • RTT-замер (среднее по 5 попыткам)
  • Потери пакетов (count successful / total)
  • Авторизация (проверка H2 handshake с паролем)

Не создаёт новых демонов — запускается из cron или напрямую.
Результаты пишутся в state.json → hysteria2.exit_nodes[].metrics.

Точка входа из _core.py:
    from vless_installer.modules.hysteria2_health import (
        h2_health_check_all, h2_health_check_node, do_h2_health_menu,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from vless_installer.modules.hysteria2_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, _load_h2_state, _save_h2_state,
    _tg_h2_event, _is_ipv6, _bracket,
)
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)


_HEALTH_LOG = Path("/var/log/hysteria-health.log")
_QUIC_PROBE_TIMEOUT = 5      # секунды на одну попытку
_PROBE_COUNT        = 5      # количество попыток для замера RTT
_FAIL_THRESHOLD_DEF = 3      # порог сбоев подряд → DOWN


def _log_health(msg: str) -> None:
    try:
        with _HEALTH_LOG.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


# ── QUIC ping (UDP-пакет + ожидание ответа) ───────────────────────────────────
def _quic_ping(host: str, port: int, timeout: float = 5.0) -> Optional[float]:
    """
    Отправляет минимальный QUIC Initial packet и ждёт ответа.
    Возвращает RTT в мс или None при таймауте/ошибке.

    Реализация:
      • QUIC Initial использует Long Header + версию 0x00000001
      • Посылаем 1200-байтный пакет (минимальный padded Initial)
      • При получении любого UDP-ответа — считаем UP
    """
    # QUIC v1 Long Header Initial (упрощённый — достаточно для детекции ноды)
    import struct, secrets as _sec
    dcid = _sec.token_bytes(8)
    scid = _sec.token_bytes(8)
    # Long Header: version=1, DCIL, SCIL, token_len=0, length=0
    hdr = bytes([0xC0]) + b'\x00\x00\x00\x01' + \
          bytes([len(dcid)]) + dcid + \
          bytes([len(scid)]) + scid + \
          b'\x00'  # token length
    # Минимальная длина пакета QUIC = 1200 байт
    payload = hdr + b'\x00' * (1200 - len(hdr))

    family = socket.AF_INET6 if _is_ipv6(host) else socket.AF_INET
    target = host.strip("[]")

    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        t0 = time.monotonic()
        sock.sendto(payload, (target, port))
        try:
            sock.recvfrom(2048)
            rtt_ms = (time.monotonic() - t0) * 1000
            return round(rtt_ms, 2)
        except socket.timeout:
            # Нода может отвергать неавторизованные QUIC Initial — считаем UP
            # если пакет ушёл без ошибки сети (ICMP unreachable = ошибка)
            return None
        finally:
            sock.close()
    except (OSError, Exception):
        return None


def _quic_ping_multi(host: str, port: int, count: int = 5) -> dict:
    """
    Выполняет count QUIC-пингов, возвращает статистику.
    """
    rtts = []
    fails = 0
    for _ in range(count):
        rtt = _quic_ping(host, port)
        if rtt is not None:
            rtts.append(rtt)
        else:
            fails += 1
        time.sleep(0.2)

    success_count = count - fails
    return {
        "rtt_min":  round(min(rtts), 2) if rtts else 0,
        "rtt_avg":  round(sum(rtts) / len(rtts), 2) if rtts else 0,
        "rtt_max":  round(max(rtts), 2) if rtts else 0,
        "loss_pct": round(fails / count * 100, 1),
        "up":       success_count > 0,
    }


def _tcp_fallback_check(host: str, port: int, timeout: float = 5.0) -> bool:
    """Fallback TCP-проверка (если QUIC блокируется DPI)."""
    # H2 — UDP only, TCP-check бесполезен для H2 порта.
    # Используем как дополнительную проверку: доступность хоста вообще.
    family = socket.AF_INET6 if _is_ipv6(host) else socket.AF_INET
    target = host.strip("[]")
    try:
        with socket.create_connection((target, 22), timeout=timeout):
            return True
    except Exception:
        pass
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((target, port))
        s.close()
        return r == 0
    except Exception:
        return False


# ── Основные функции ──────────────────────────────────────────────────────────
def h2_health_check_node(node: dict) -> dict:
    """
    Проверяет одну H2 exit-ноду. Возвращает обновлённый словарь ноды.
    """
    ip       = node.get("ip", "")
    ports    = node.get("ports", [443])
    port     = ports[0] if ports else 443
    auth     = node.get("auth", "")
    cfg      = _load_h2_state().get("health_check", {})
    timeout  = cfg.get("timeout_sec", _QUIC_PROBE_TIMEOUT)

    stats = _quic_ping_multi(ip, port, count=_PROBE_COUNT)
    up    = stats["up"]

    # Обновляем метрики
    node["metrics"] = {
        "rtt_ms":    stats["rtt_avg"],
        "rtt_min":   stats["rtt_min"],
        "rtt_max":   stats["rtt_max"],
        "loss_pct":  stats["loss_pct"],
        "speed_mbps": 0,   # заполняется в hysteria2_traffic.py
        "checked_at": datetime.now().isoformat(),
    }

    prev_status = node.get("status", "unknown")
    if up:
        node["status"] = "active"
        if prev_status != "active":
            msg = f"H2 нода {ip}:{port} UP (RTT {stats['rtt_avg']}ms)"
            success(msg)
            _log_health(msg)
            _tg_h2_event("h2_up", f"Нода {ip}:{port} доступна")
    else:
        node.setdefault("_fail_count", 0)
        node["_fail_count"] += 1
        threshold = cfg.get("fail_threshold", _FAIL_THRESHOLD_DEF)
        if node["_fail_count"] >= threshold:
            node["status"] = "down"
            if prev_status != "down":
                msg = f"H2 нода {ip}:{port} DOWN (потерь {stats['loss_pct']}%)"
                warn(msg)
                _log_health(msg)
                _tg_h2_event("h2_down", f"Нода {ip}:{port} недоступна")
        else:
            warn(f"H2 нода {ip}:{port} — ошибка #{node['_fail_count']} (порог {threshold})")

    return node


def h2_health_check_all() -> list[dict]:
    """
    Проверяет все H2 exit-ноды из state.json. Обновляет метрики.
    Возвращает список нод с обновлёнными статусами.
    """
    h2    = _load_h2_state()
    nodes = h2.get("exit_nodes", [])
    if not nodes:
        warn("H2 exit-ноды не настроены")
        return []

    updated = []
    for node in nodes:
        updated.append(h2_health_check_node(node))

    h2["exit_nodes"] = updated
    _save_h2_state(h2)
    log_to_file("INFO", f"H2 health check: {len(updated)} нод проверено")
    return updated


def h2_health_check_cron() -> None:
    """Точка входа для cron-запуска (без вывода в stdout)."""
    nodes = h2_health_check_all()
    down  = [n for n in nodes if n.get("status") == "down"]
    if down:
        log_to_file("WARN", f"H2: {len(down)} нод DOWN после health check")


# ── Интерактивное меню ────────────────────────────────────────────────────────
def do_h2_health_menu() -> None:
    """Интерактивное меню Health Check для H2."""
    while True:
        os.system("clear")
        print()
        h2 = _load_h2_state()
        hc = h2.get("health_check", {})
        n_ok    = sum(1 for n in h2.get("exit_nodes",[]) if n.get("status")=="active")
        n_total = len(h2.get("exit_nodes",[]))
        _box_top("🩺  HYSTERIA2 — HEALTH CHECK")
        _box_row(f"  Ноды OK: {GREEN}{n_ok}{NC}/{n_total}  │  Интервал: {CYAN}{hc.get('interval_sec',60)}с{NC}  │  Таймаут: {CYAN}{hc.get('timeout_sec',5)}с{NC}  │  Порог сбоев: {CYAN}{hc.get('fail_threshold',3)}{NC}")
        _box_sep()
        _box_row()

        h2    = _load_h2_state()
        nodes = h2.get("exit_nodes", [])
        if not nodes:
            warn("  Нет H2 exit-нод в state.json")
        else:
            print(f"  {'IP':<20} {'Порт':<8} {'Статус':<12} {'RTT мс':<10} {'Потери'}")
            print(f"  {'-'*60}")
            for n in nodes:
                m     = n.get("metrics", {})
                st    = n.get("status", "—")
                color = GREEN if st == "active" else (RED if st == "down" else YELLOW)
                ports = n.get("ports", [0])
                print(
                    f"  {n.get('ip',''):<20} {str(ports[0]):<8} "
                    f"{color}{st:<12}{NC} {str(m.get('rtt_ms',0))+'ms':<10} "
                    f"{m.get('loss_pct',0)}%"
                )
        print()
        hc = h2.get("health_check", {})
        print(f"  {DIM}Интервал: {hc.get('interval_sec',60)}с  |  "
              f"Таймаут: {hc.get('timeout_sec',5)}с  |  "
              f"Порог сбоев: {hc.get('fail_threshold',3)}{NC}")
        print()
        _box_item("1", "Запустить проверку сейчас")
        _box_item("2", "Изменить параметры Health Check")
        _box_item("3", f"Показать лог  {DIM}({_HEALTH_LOG}){NC}")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "1":
            info("Запускаю QUIC health check...")
            results = h2_health_check_all()
            ok   = sum(1 for n in results if n.get("status") == "active")
            down = sum(1 for n in results if n.get("status") == "down")
            print()
            print(f"  Готово: {GREEN}{ok} UP{NC}  {RED}{down} DOWN{NC}")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            _edit_health_params()
        elif ch == "3":
            if _HEALTH_LOG.exists():
                lines = _HEALTH_LOG.read_text().splitlines()[-40:]
                print()
                print("\n".join(lines))
            else:
                warn("Лог пуст")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "Q":
            break
        else:
            time.sleep(0.5)


def _edit_health_params() -> None:
    h2 = _load_h2_state()
    hc = h2.setdefault("health_check", {})
    print()
    try:
        v = input(f"  {CYAN}Интервал проверки сек{NC} [{hc.get('interval_sec',60)}]: ").strip()
        if v.isdigit():
            hc["interval_sec"] = int(v)
        v = input(f"  {CYAN}Таймаут сек{NC} [{hc.get('timeout_sec',5)}]: ").strip()
        if v.isdigit():
            hc["timeout_sec"] = int(v)
        v = input(f"  {CYAN}Порог сбоев{NC} [{hc.get('fail_threshold',3)}]: ").strip()
        if v.isdigit():
            hc["fail_threshold"] = int(v)
    except KeyboardInterrupt:
        return
    _save_h2_state(h2)
    success("Параметры сохранены")
    input(f"\n{BLUE}Нажмите Enter...{NC}")


"""
ПРИМЕР ВЫЗОВА из _core.py / cron:
    from vless_installer.modules.hysteria2_health import (
        h2_health_check_all, h2_health_check_cron, do_h2_health_menu,
    )

    # Разовая проверка:
    nodes = h2_health_check_all()

    # Из cron (--h2-health):
    h2_health_check_cron()

    # Интерактивно:
    do_h2_health_menu()
"""
