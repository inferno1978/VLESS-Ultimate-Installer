"""
vless_installer/modules/hysteria2_traffic.py
───────────────────────────────────────────────────────────────────────────────
Сбор статистики трафика Hysteria2.

Источники (без новых демонов):
  • iptables -L -n -v -x  — байты/пакеты по UDP-правилам H2
  • ip6tables             — то же для IPv6
  • ss -u -s              — UDP-сокеты и буферы
  • /var/log/hysteria.log — парсинг строк с трафиком H2

Метрики:
  • rx_bytes, tx_bytes (per-node по IP)
  • connections_total
  • speed_mbps (скорость за последний интервал)

Результаты записываются в state.json → hysteria2.exit_nodes[].metrics.speed_mbps
и выводятся в интерактивном меню или --h2-traffic.

Точка входа из _core.py:
    from vless_installer.modules.hysteria2_traffic import (
        h2_traffic_collect, h2_traffic_report, do_h2_traffic_menu,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from vless_installer.modules.hysteria2_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, _load_h2_state, _save_h2_state,
    _tg_h2_event,
    H2_LOG_FILE,
)
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)


_STATS_CACHE = Path("/var/lib/xray-installer/h2_traffic_cache.json")
_PREV_BYTES_KEY = "_h2_prev_bytes"


def _parse_iptables_bytes(port: int, ipv6: bool = False) -> int:
    """Парсит байты из iptables для UDP-правила на указанный порт."""
    ipt = "ip6tables" if ipv6 else "iptables"
    try:
        r = _run([ipt, "-L", "INPUT", "-n", "-v", "-x"], capture=True, timeout=10)
        for line in r.stdout.splitlines():
            if f"udp dpt:{port}" in line or f"dport {port}" in line:
                parts = line.split()
                # Формат: pkts bytes target prot opt in out src dst
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1])
    except Exception:
        pass
    return 0


def _parse_ss_udp() -> dict:
    """Получает статистику UDP-сокетов через ss."""
    result = {"connections": 0, "recv_q": 0, "send_q": 0}
    try:
        r = _run(["ss", "-u", "-n", "-p"], capture=True, timeout=10)
        lines = r.stdout.splitlines()
        result["connections"] = max(0, len(lines) - 1)  # минус заголовок
    except Exception:
        pass
    return result


def _parse_h2_log_bytes(last_n_lines: int = 500) -> dict:
    """
    Парсит лог Hysteria2 на строки вида:
    'upload=... download=...' для получения суммарного трафика.
    """
    rx, tx = 0, 0
    if not H2_LOG_FILE.exists():
        return {"rx": 0, "tx": 0}
    try:
        # Читаем последние N строк без загрузки всего файла
        r = _run(["tail", "-n", str(last_n_lines), str(H2_LOG_FILE)],
                 capture=True, timeout=5)
        for line in r.stdout.splitlines():
            m = re.search(r'upload=(\d+).*download=(\d+)', line)
            if m:
                tx += int(m.group(1))
                rx += int(m.group(2))
    except Exception:
        pass
    return {"rx": rx, "tx": tx}


def _load_cache() -> dict:
    try:
        if _STATS_CACHE.exists():
            return json.loads(_STATS_CACHE.read_text())
    except Exception:
        pass
    return {}


def _save_cache(data: dict) -> None:
    try:
        _STATS_CACHE.parent.mkdir(parents=True, exist_ok=True)
        _STATS_CACHE.write_text(json.dumps(data))
    except Exception:
        pass


def _bytes_to_human(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


# ── Основные функции ──────────────────────────────────────────────────────────
def h2_traffic_collect() -> dict:
    """
    Собирает текущую статистику трафика по всем H2 портам.
    Вычисляет скорость (Мбит/с) между вызовами.
    Обновляет кэш и state.json.
    """
    h2    = _load_h2_state()
    ports = h2.get("firewall", {}).get("udp_ports", [443])

    now_ts = time.time()
    cache  = _load_cache()
    prev_ts = cache.get("ts", now_ts)
    elapsed = max(now_ts - prev_ts, 1.0)

    total_rx, total_tx = 0, 0
    for p in ports:
        rx = _parse_iptables_bytes(p, ipv6=False)
        tx = _parse_iptables_bytes(p, ipv6=True)
        total_rx += rx
        total_tx += tx

    # Из лога H2
    log_stats = _parse_h2_log_bytes()
    total_rx = max(total_rx, log_stats["rx"])
    total_tx = max(total_tx, log_stats["tx"])

    prev_rx = cache.get("rx", total_rx)
    prev_tx = cache.get("tx", total_tx)

    delta_rx = max(total_rx - prev_rx, 0)
    delta_tx = max(total_tx - prev_tx, 0)

    speed_rx_mbps = round(delta_rx * 8 / elapsed / 1_000_000, 2)
    speed_tx_mbps = round(delta_tx * 8 / elapsed / 1_000_000, 2)

    ss_stats = _parse_ss_udp()

    result = {
        "ts":           now_ts,
        "rx_bytes":     total_rx,
        "tx_bytes":     total_tx,
        "rx_speed_mbps": speed_rx_mbps,
        "tx_speed_mbps": speed_tx_mbps,
        "connections":  ss_stats["connections"],
        "ports":        ports,
    }

    # Обновляем кэш
    _save_cache({"ts": now_ts, "rx": total_rx, "tx": total_tx})

    # Обновляем speed_mbps в нодах (первая активная нода)
    nodes = h2.get("exit_nodes", [])
    for i, n in enumerate(nodes):
        if n.get("status") == "active":
            n.setdefault("metrics", {})["speed_mbps"] = speed_rx_mbps + speed_tx_mbps
            nodes[i] = n
            break
    h2["exit_nodes"] = nodes
    _save_h2_state(h2)

    log_to_file("INFO",
        f"H2 traffic: RX {_bytes_to_human(total_rx)} "
        f"({speed_rx_mbps}Mbps), TX {_bytes_to_human(total_tx)} ({speed_tx_mbps}Mbps)"
    )
    return result


def h2_traffic_report() -> str:
    """Формирует текстовый отчёт по трафику H2 для вывода или TG."""
    stats = h2_traffic_collect()
    lines = [
        "📊 <b>Hysteria2 Traffic Report</b>",
        f"RX: {_bytes_to_human(stats['rx_bytes'])} ({stats['rx_speed_mbps']} Mbps)",
        f"TX: {_bytes_to_human(stats['tx_bytes'])} ({stats['tx_speed_mbps']} Mbps)",
        f"Соединений: {stats['connections']}",
        f"Порты: {stats['ports']}",
        f"<i>{datetime.now().strftime('%d.%m.%Y %H:%M')}</i>",
    ]
    return "\n".join(lines)


def h2_traffic_send_tg() -> None:
    """Отправляет отчёт по трафику в Telegram."""
    report = h2_traffic_report()
    _tg_h2_event("h2_traffic", report)


# ── Меню ──────────────────────────────────────────────────────────────────────
def do_h2_traffic_menu() -> None:
    """Интерактивное меню статистики трафика H2."""
    while True:
        os.system("clear")
        print()
        _box_top("📊  HYSTERIA2 — ТРАФИК")
        _box_row()

        stats = h2_traffic_collect()
        print(f"  RX:         {GREEN}{_bytes_to_human(stats['rx_bytes'])}{NC}  "
              f"({stats['rx_speed_mbps']} Мбит/с)")
        print(f"  TX:         {GREEN}{_bytes_to_human(stats['tx_bytes'])}{NC}  "
              f"({stats['tx_speed_mbps']} Мбит/с)")
        print(f"  Соединений: {CYAN}{stats['connections']}{NC}")
        print(f"  UDP-порты:  {DIM}{stats['ports']}{NC}")
        print(f"  {DIM}Обновлено: {datetime.fromtimestamp(stats['ts']).strftime('%H:%M:%S')}{NC}")
        print()

        h2    = _load_h2_state()
        nodes = h2.get("exit_nodes", [])
        if nodes:
            print(f"  {'IP':<20} {'Скорость Мбит/с':<18} {'Статус'}")
            print(f"  {'-'*50}")
            for n in nodes:
                m = n.get("metrics", {})
                print(f"  {n.get('ip',''):<20} {m.get('speed_mbps',0):<18.2f} "
                      f"{n.get('status','—')}")

        print()
        _box_item("1", "Обновить")
        _box_item("2", "Отправить отчёт в Telegram")
        _box_item("3", f"Показать лог H2  {DIM}(tail -50){NC}")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "1":
            continue  # обновить экран
        elif ch == "2":
            h2_traffic_send_tg()
            success("Отчёт отправлен")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            r = _run(["tail", "-n", "50", str(H2_LOG_FILE)], capture=True)
            print()
            print(r.stdout or "(лог пуст)")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "Q":
            break
        else:
            time.sleep(0.5)


"""
ПРИМЕР ВЫЗОВА из _core.py:
    from vless_installer.modules.hysteria2_traffic import (
        h2_traffic_collect, h2_traffic_report, do_h2_traffic_menu,
    )

    # CLI --h2-traffic:
    print(h2_traffic_report())

    # TG-отчёт:
    h2_traffic_send_tg()

    # Интерактивно:
    do_h2_traffic_menu()
"""
