"""
vless_installer/modules/hysteria2_balancer.py
───────────────────────────────────────────────────────────────────────────────
Балансировщик нагрузки для Hysteria2 exit-нод.

Стратегии:
  • weightedRandom  — выбор ноды пропорционально весам (по умолчанию)
  • leastRtt        — всегда выбирает ноду с минимальным RTT
  • roundRobin      — поочерёдный выбор без учёта метрик

Интеграция:
  • Читает метрики из state.json → hysteria2.exit_nodes[].metrics
  • При смене активной ноды — патчит xray outbound через hysteria2_transport.py
  • Отправляет TG-уведомление при смене весов / ноды
  • Исключает ноды со статусом "down" из балансировки
  • Поддерживает IPv4 и IPv6 с раздельными весами

Точка входа из _core.py:
    from vless_installer.modules.hysteria2_balancer import (
        h2_balancer_select_node, h2_balancer_run_once, do_h2_balancer_menu,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from vless_installer.modules.hysteria2_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, _load_h2_state, _save_h2_state,
    _tg_h2_event, _is_ipv6,
)
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)


# ── Константы ─────────────────────────────────────────────────────────────────
_DEFAULT_STRATEGY = "weightedRandom"
_SWITCH_THRESHOLD = 0.5   # если текущая нода деградировала > 50% → переключить


# ── Выбор ноды ────────────────────────────────────────────────────────────────
def _live_nodes(nodes: list[dict]) -> list[dict]:
    """Возвращает только ноды со статусом != 'down'."""
    return [n for n in nodes if n.get("status", "active") != "down"]


def _weighted_random(nodes: list[dict]) -> Optional[dict]:
    """Взвешенный случайный выбор."""
    live = _live_nodes(nodes)
    if not live:
        return None
    weights = [max(float(n.get("weight", 1.0)), 0.01) for n in live]
    return random.choices(live, weights=weights, k=1)[0]


def _least_rtt(nodes: list[dict]) -> Optional[dict]:
    """Выбирает ноду с минимальным RTT (0 игнорируется если есть альтернативы)."""
    live = _live_nodes(nodes)
    if not live:
        return None
    with_rtt = [n for n in live if n.get("metrics", {}).get("rtt_ms", 0) > 0]
    if not with_rtt:
        return live[0]
    return min(with_rtt, key=lambda n: n["metrics"]["rtt_ms"])


def _round_robin(nodes: list[dict], current_idx: int) -> Optional[dict]:
    live = _live_nodes(nodes)
    if not live:
        return None
    return live[current_idx % len(live)]


def h2_balancer_select_node(prefer_ipv6: bool = False) -> Optional[dict]:
    """
    Выбирает оптимальную H2 exit-ноду согласно стратегии балансировщика.
    Возвращает словарь ноды или None если все DOWN.
    """
    h2       = _load_h2_state()
    nodes    = h2.get("exit_nodes", [])
    balancer = h2.get("balancer", {})
    strategy = balancer.get("strategy", _DEFAULT_STRATEGY)

    if not nodes:
        return None

    # Фильтрация по IP-версии если требуется
    if prefer_ipv6:
        ipv6_nodes = [n for n in nodes if _is_ipv6(n.get("ip", ""))
                      and n.get("status") != "down"]
        if ipv6_nodes:
            nodes = ipv6_nodes

    if strategy == "weightedRandom":
        return _weighted_random(nodes)
    elif strategy == "leastRtt":
        return _least_rtt(nodes)
    elif strategy == "roundRobin":
        idx = balancer.get("_rr_index", 0)
        node = _round_robin(nodes, idx)
        balancer["_rr_index"] = (idx + 1) % max(len(_live_nodes(nodes)), 1)
        h2["balancer"] = balancer
        _save_h2_state(h2)
        return node
    return _weighted_random(nodes)


def _auto_adjust_weights(nodes: list[dict]) -> list[dict]:
    """
    Автоматически корректирует веса на основе RTT и потерь.
    Формула: weight = 1 / (rtt_ms * (1 + loss_pct/100) + 1)
    Нормализуется до суммы весов = len(nodes).
    """
    scores = []
    for n in nodes:
        m      = n.get("metrics", {})
        rtt    = max(float(m.get("rtt_ms",   100)), 1.0)
        loss   = max(float(m.get("loss_pct",   0)), 0.0)
        if n.get("status") == "down":
            scores.append(0.0)
        else:
            scores.append(1.0 / (rtt * (1.0 + loss / 100.0) + 1.0))

    total = sum(scores) or 1.0
    n_live = sum(1 for s in scores if s > 0) or 1

    for i, n in enumerate(nodes):
        new_w = round(scores[i] / total * n_live, 3)
        old_w = n.get("weight", 1.0)
        nodes[i]["weight"] = new_w
        if abs(new_w - old_w) > 0.1:
            log_to_file("INFO", f"H2 balancer: {n['ip']} weight {old_w} → {new_w}")

    return nodes


# ── Основной балансировщик (из cron) ─────────────────────────────────────────
def h2_balancer_run_once() -> bool:
    """
    Однократный прогон балансировщика:
    1. Обновляет веса на основе свежих метрик
    2. Если текущая активная нода деградировала → переключает
    3. Патчит Xray outbound при смене ноды
    """
    from vless_installer.modules.hysteria2_health import h2_health_check_all
    from vless_installer.modules.hysteria2_transport import h2_transport_apply

    h2    = _load_h2_state()
    nodes = h2.get("exit_nodes", [])
    if not nodes:
        return False

    # 1) Health check
    nodes = h2_health_check_all()
    h2    = _load_h2_state()  # перечитываем после health check
    nodes = h2.get("exit_nodes", [])

    # 2) Пересчёт весов
    nodes = _auto_adjust_weights(nodes)
    h2["exit_nodes"] = nodes

    # 3) Проверяем текущую активную ноду
    active_ip = h2.get("_active_node_ip", "")
    current   = next((n for n in nodes if n.get("ip") == active_ip), None)
    threshold = h2.get("balancer", {}).get("switch_threshold", _SWITCH_THRESHOLD)

    need_switch = False
    if current:
        m    = current.get("metrics", {})
        loss = m.get("loss_pct", 0.0) / 100.0
        if current.get("status") == "down" or loss > threshold:
            need_switch = True
    elif active_ip:
        need_switch = True  # нода пропала из списка

    if need_switch:
        best = h2_balancer_select_node()
        if best and best.get("ip") != active_ip:
            info(f"H2 balancer: переключение {active_ip} → {best['ip']}")
            h2_transport_apply(
                exit_ip=best["ip"],
                exit_port=best.get("ports", [443])[0],
                auth_password=best.get("auth", ""),
            )
            h2["_active_node_ip"] = best["ip"]
            _tg_h2_event("h2_switch", f"Балансировщик → {best['ip']}")

    _save_h2_state(h2)
    log_to_file("INFO", "H2 balancer run_once complete")
    return True


# ── Интерактивное меню ────────────────────────────────────────────────────────
def do_h2_balancer_menu() -> None:
    """Интерактивное меню настройки балансировщика H2."""
    while True:
        os.system("clear")
        print()
        h2       = _load_h2_state()
        balancer = h2.get("balancer", {})
        nodes    = h2.get("exit_nodes", [])
        strategy = balancer.get("strategy", _DEFAULT_STRATEGY)
        active   = h2.get("_active_node_ip", "—")

        _box_top("⚖️  HYSTERIA2 — БАЛАНСИРОВЩИК НОД")
        _box_row(f"  Стратегия: {CYAN}{strategy}{NC}  │  Активная: {GREEN}{active}{NC}  │  Порог: {balancer.get('switch_threshold', _SWITCH_THRESHOLD)*100:.0f}% потерь")
        _box_sep()
        _box_row()
        if nodes:
            _box_row(f"  {CYAN}{'IP':<20} {'Вес':<8} {'RTT мс':<10} Статус{NC}")
            _box_row(f"  {DIM}{'─'*50}{NC}")
            for n in nodes:
                m   = n.get("metrics", {})
                st  = n.get("status", "—")
                col = GREEN if st == "active" else RED
                _box_row(f"  {n.get('ip',''):<20} {n.get('weight',1.0):<8.3f} {str(m.get('rtt_ms',0))+'ms':<10} {col}{st}{NC}")
            _box_row()
        _box_sep()
        _box_row()
        _box_item("1", "Изменить стратегию")
        _box_item("2", "Установить вес ноды вручную")
        _box_item("3", f"Автопересчёт весов  {DIM}(по RTT/потерям){NC}")
        _box_item("4", "Запустить балансировщик сейчас")
        _box_item("5", "Установить порог переключения")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "1":
            _change_strategy()
        elif ch == "2":
            _set_node_weight()
        elif ch == "3":
            h2 = _load_h2_state()
            h2["exit_nodes"] = _auto_adjust_weights(h2.get("exit_nodes", []))
            _save_h2_state(h2)
            success("Веса пересчитаны")
            _tg_h2_event("h2_weights", "Веса нод обновлены")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            info("Запускаю балансировщик...")
            h2_balancer_run_once()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            _set_threshold()
        elif ch == "Q":
            break
        else:
            time.sleep(0.5)


def _change_strategy() -> None:
    strategies = ["weightedRandom", "leastRtt", "roundRobin"]
    print()
    _box_top("⚖️  СТРАТЕГИЯ БАЛАНСИРОВКИ")
    for i, s in enumerate(strategies, 1):
        _box_item(str(i), s)
    _box_row()
    _box_item_exit("Q", "← Отмена")
    _box_bottom()
    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip()
    except KeyboardInterrupt:
        return
    if ch.isdigit() and 1 <= int(ch) <= len(strategies):
        h2 = _load_h2_state()
        h2.setdefault("balancer", {})["strategy"] = strategies[int(ch)-1]
        _save_h2_state(h2)
        success(f"Стратегия → {strategies[int(ch)-1]}")
    input(f"\n{CYAN}Нажмите Enter...{NC}")


def _set_node_weight() -> None:
    h2    = _load_h2_state()
    nodes = h2.get("exit_nodes", [])
    if not nodes:
        warn("Нет нод")
        return
    print()
    _box_top("⚖️  УСТАНОВИТЬ ВЕС НОДЫ")
    for i, n in enumerate(nodes):
        _box_item(str(i+1), f"{n['ip']}  {DIM}(текущий вес: {n.get('weight',1.0)}){NC}")
    _box_row()
    _box_bottom()
    try:
        idx  = int(input(f"  {CYAN}Номер ноды:{NC} ").strip()) - 1
        wval = float(input(f"  {CYAN}Новый вес{NC} (0.1 – 10.0): ").strip())
    except (KeyboardInterrupt, ValueError):
        return
    if 0 <= idx < len(nodes):
        nodes[idx]["weight"] = round(max(0.01, min(wval, 100.0)), 3)
        h2["exit_nodes"] = nodes
        _save_h2_state(h2)
        success(f"Вес ноды {nodes[idx]['ip']} → {nodes[idx]['weight']}")
        _tg_h2_event("h2_weights", f"Вес {nodes[idx]['ip']} → {nodes[idx]['weight']}")
    input(f"\n{CYAN}Нажмите Enter...{NC}")


def _set_threshold() -> None:
    h2 = _load_h2_state()
    print()
    try:
        v = float(input(
            f"  {CYAN}Порог потерь для смены ноды{NC} (0–100%) "
            f"[{h2.get('balancer',{}).get('switch_threshold',0.5)*100:.0f}]: "
        ).strip())
    except (KeyboardInterrupt, ValueError):
        return
    h2.setdefault("balancer", {})["switch_threshold"] = round(v / 100.0, 3)
    _save_h2_state(h2)
    success(f"Порог → {v}%")
    input(f"\n{BLUE}Нажмите Enter...{NC}")


"""
ПРИМЕР ВЫЗОВА из _core.py / cron:
    from vless_installer.modules.hysteria2_balancer import (
        h2_balancer_select_node, h2_balancer_run_once, do_h2_balancer_menu,
    )

    # Из cron (--smart-balance):
    h2_balancer_run_once()

    # Выбрать лучшую ноду:
    node = h2_balancer_select_node()
    if node:
        print(node["ip"], node["ports"])

    # Интерактивно:
    do_h2_balancer_menu()
"""
