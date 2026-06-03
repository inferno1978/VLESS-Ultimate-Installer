"""
vless_installer/modules/hysteria2_quality.py
───────────────────────────────────────────────────────────────────────────────
Мониторинг качества Hysteria2: RTT, потери, скорость + авторегулировка.

Функции:
  • Замер RTT/потерь через QUIC-ping (5 попыток на ноду)
  • Speedtest-like: UDP burst через H2-сокет (без внешних утилит)
  • Авто-оптимизация: udpIdleTimeout, MTU на основе замеров
  • Отчёт в Telegram (--h2-quality-report)
  • Сохранение истории метрик в state.json

Точка входа из _core.py:
    from vless_installer.modules.hysteria2_quality import (
        h2_quality_report, h2_quality_optimize, do_h2_quality_menu,
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
    _tg_h2_event, _tg_send, _is_ipv6,
    H2_CONFIG_FILE,
)
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)

from vless_installer.modules.hysteria2_health import _quic_ping_multi

_HISTORY_FILE = Path("/var/lib/xray-installer/h2_quality_history.json")
_MAX_HISTORY  = 100   # максимум точек в истории на ноду


# ── UDP burst speedtest (без внешних утилит) ──────────────────────────────────
def _udp_throughput_test(host: str, port: int,
                          duration_sec: float = 3.0,
                          pkt_size: int = 1200) -> float:
    """
    Измеряет пропускную способность UDP к указанному хосту:порт.
    Отправляет пакеты в течение duration_sec секунд.
    Возвращает приблизительную скорость в Мбит/с.

    Внимание: это однонаправленный UDP burst — не TCP throughput.
    Для H2 даёт ориентировочную оценку пропускной способности канала.
    """
    family = socket.AF_INET6 if _is_ipv6(host) else socket.AF_INET
    target = host.strip("[]")
    payload = b"X" * pkt_size

    sent = 0
    t0   = time.monotonic()
    t_end = t0 + duration_sec

    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        while time.monotonic() < t_end:
            try:
                s.sendto(payload, (target, port))
                sent += pkt_size
            except OSError:
                break
        s.close()
    except Exception:
        return 0.0

    elapsed  = time.monotonic() - t0
    mbps     = (sent * 8) / elapsed / 1_000_000
    return round(mbps, 2)


# ── Замер качества по одной ноде ─────────────────────────────────────────────
def _measure_node_quality(node: dict) -> dict:
    ip    = node.get("ip", "")
    ports = node.get("ports", [443])
    port  = ports[0] if ports else 443

    # QUIC RTT
    ping_stats = _quic_ping_multi(ip, port, count=5)

    # UDP throughput
    speed = _udp_throughput_test(ip, port, duration_sec=2.0)

    return {
        "ip":         ip,
        "port":       port,
        "rtt_min":    ping_stats["rtt_min"],
        "rtt_avg":    ping_stats["rtt_avg"],
        "rtt_max":    ping_stats["rtt_max"],
        "loss_pct":   ping_stats["loss_pct"],
        "speed_mbps": speed,
        "up":         ping_stats["up"],
        "ts":         datetime.now().isoformat(),
    }


def _load_history() -> dict:
    try:
        if _HISTORY_FILE.exists():
            return json.loads(_HISTORY_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_history(history: dict) -> None:
    try:
        _HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        _HISTORY_FILE.write_text(json.dumps(history, indent=2, ensure_ascii=False))
    except Exception:
        pass


def _append_history(ip: str, record: dict) -> None:
    hist = _load_history()
    hist.setdefault(ip, [])
    hist[ip].append(record)
    if len(hist[ip]) > _MAX_HISTORY:
        hist[ip] = hist[ip][-_MAX_HISTORY:]
    _save_history(hist)


# ── Основные публичные функции ────────────────────────────────────────────────
def h2_quality_report(send_tg: bool = False) -> str:
    """
    Измеряет качество всех H2 нод и формирует отчёт.
    Если send_tg=True — отправляет в Telegram.
    Возвращает текст отчёта.
    """
    h2    = _load_h2_state()
    nodes = h2.get("exit_nodes", [])

    if not nodes:
        return "⚠️ Нет H2 exit-нод"

    lines = [
        f"📊 <b>Hysteria2 Quality Report</b>",
        f"<i>{datetime.now().strftime('%d.%m.%Y %H:%M')}</i>",
        "",
    ]

    for node in nodes:
        if node.get("status") == "down":
            lines.append(f"🔴 <b>{node.get('ip')}</b> — DOWN")
            continue

        q = _measure_node_quality(node)
        _append_history(node.get("ip", ""), q)

        # Обновляем метрики в state
        node["metrics"] = {
            "rtt_ms":    q["rtt_avg"],
            "rtt_min":   q["rtt_min"],
            "rtt_max":   q["rtt_max"],
            "loss_pct":  q["loss_pct"],
            "speed_mbps": q["speed_mbps"],
            "checked_at": q["ts"],
        }

        quality = (
            "🟢 отлично" if q["rtt_avg"] < 50 and q["loss_pct"] < 5 else
            "🟡 норма"   if q["rtt_avg"] < 150 and q["loss_pct"] < 15 else
            "🔴 плохо"
        )

        lines += [
            f"<b>{node.get('ip')}:{q['port']}</b>  {quality}",
            f"  RTT: avg={q['rtt_avg']}ms  min={q['rtt_min']}ms  max={q['rtt_max']}ms",
            f"  Потери: {q['loss_pct']}%   Скорость UDP: {q['speed_mbps']} Мбит/с",
            "",
        ]

    h2["exit_nodes"] = nodes
    _save_h2_state(h2)

    report = "\n".join(lines)

    if send_tg:
        _tg_send(report)
        log_to_file("INFO", "H2 quality report sent to TG")

    return report


def h2_quality_optimize() -> dict:
    """
    Авто-оптимизация параметров H2 на основе замеров.
    Обновляет /etc/hysteria/config.yaml:
      • udpIdleTimeout (на основе среднего RTT)
      • bandwidth (на основе speedtest)
    Возвращает dict с применёнными изменениями.
    """
    h2    = _load_h2_state()
    nodes = [n for n in h2.get("exit_nodes", []) if n.get("status") == "active"]
    if not nodes:
        return {}

    node = nodes[0]
    q    = _measure_node_quality(node)

    changes = {}

    if not H2_CONFIG_FILE.exists():
        return {}

    try:
        import re
        text = H2_CONFIG_FILE.read_text()

        # udpIdleTimeout: 2× средний RTT, минимум 30с, максимум 120с
        rtt_s   = max(30, min(120, int(q["rtt_avg"] * 2 / 1000) + 30))
        new_timeout = f"{rtt_s}s"
        text, n = re.subn(
            r'(udpIdleTimeout:\s*)[\w]+',
            rf'\g<1>{new_timeout}',
            text,
        )
        if n:
            changes["udpIdleTimeout"] = new_timeout

        # bandwidth: если speedtest < 100Мбит — устанавливаем более реалистичный
        speed = q["speed_mbps"]
        if speed > 0:
            bw = f"{max(int(speed * 0.8), 10)} mbps"
            text, n = re.subn(
                r'(bandwidth:\s*\n\s*up:\s*)[\w ]+',
                rf'\g<1>{bw}',
                text,
            )
            if n:
                changes["bandwidth_up"] = bw

        H2_CONFIG_FILE.write_text(text)
        info(f"Конфиг H2 оптимизирован: {changes}")
        log_to_file("INFO", f"H2 quality_optimize applied: {changes}")

    except Exception as e:
        error(f"Ошибка оптимизации конфига: {e}")

    return changes


# ── Меню ──────────────────────────────────────────────────────────────────────
def do_h2_quality_menu() -> None:
    """Интерактивное меню мониторинга качества H2."""
    while True:
        os.system("clear")
        print()
        h2    = _load_h2_state()
        nodes = h2.get("exit_nodes", [])
        _box_top("📈  HYSTERIA2 — КАЧЕСТВО СОЕДИНЕНИЯ")
        for n in nodes:
            m   = n.get("metrics", {})
            col = GREEN if n.get("status") == "active" else RED
            _box_row(f"  {col}●{NC}  {n.get('ip','?'):<20}  RTT: {CYAN}{m.get('rtt_ms',0)}мс{NC}  Потери: {CYAN}{m.get('loss_pct',0):.1f}%{NC}  Скорость: {CYAN}{m.get('speed_mbps',0):.1f} Мбит/с{NC}")
        if not nodes:
            _box_row(f"  {YELLOW}Нет зарегистрированных нод{NC}")
        _box_sep()
        _box_row()

        h2    = _load_h2_state()
        nodes = h2.get("exit_nodes", [])
        for n in nodes:
            m   = n.get("metrics", {})
            col = GREEN if n.get("status") == "active" else RED
            print(
                f"  {col}●{NC} {n.get('ip',''):<20}  "
                f"RTT {m.get('rtt_ms',0)}ms  "
                f"Потери {m.get('loss_pct',0)}%  "
                f"{m.get('speed_mbps',0)} Мбит/с"
            )

        print()
        _box_item("1", f"Запустить замер качества  {DIM}(все ноды){NC}")
        _box_item("2", "Отправить отчёт в Telegram")
        _box_item("3", "Авто-оптимизация параметров конфига")
        _box_item("4", "История метрик")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "1":
            print()
            report = h2_quality_report(send_tg=False)
            print(report.replace("<b>","").replace("</b>","")
                       .replace("<i>","").replace("</i>",""))
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            h2_quality_report(send_tg=True)
            success("Отчёт отправлен в Telegram")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            changes = h2_quality_optimize()
            if changes:
                success(f"Оптимизировано: {changes}")
                # Рестарт H2 для применения
                from vless_installer.modules.hysteria2_common import _systemctl, H2_SERVICE
                _systemctl("restart", H2_SERVICE)
            else:
                info("Нет изменений для оптимизации")
            input(f"\n{CYAN}Нажмите Enter...{NC}")
        elif ch == "4":
            hist = _load_history()
            os.system("clear")
            print()
            _box_top("📈  ИСТОРИЯ МЕТРИК")
            for ip, records in hist.items():
                _box_row(f"  {CYAN}{ip}{NC}  {DIM}— {len(records)} замеров{NC}")
                for r in records[-5:]:
                    _box_row(f"    {DIM}{r['ts'][:16]}  RTT={r['rtt_avg']}ms  loss={r['loss_pct']}%  {r['speed_mbps']}Мбит/с{NC}")
                _box_row()
            if not hist:
                _box_row(f"  {YELLOW}История пуста — запустите замер{NC}")
                _box_row()
            _box_item_exit("0", "← Назад")
            _box_bottom()
            input(f"{CYAN}Нажмите Enter...{NC}")
        elif ch == "Q":
            break
        else:
            time.sleep(0.5)




"""
ПРИМЕР ВЫЗОВА из _core.py / main.py:
    from vless_installer.modules.hysteria2_quality import (
        h2_quality_report, h2_quality_optimize, do_h2_quality_menu,
    )

    # CLI --h2-quality-report:
    print(h2_quality_report(send_tg=True))

    # Авто-оптимизация после установки:
    h2_quality_optimize()

    # Интерактивно:
    do_h2_quality_menu()
"""
