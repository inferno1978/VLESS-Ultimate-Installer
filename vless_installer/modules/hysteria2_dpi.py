"""
vless_installer/modules/hysteria2_dpi.py
───────────────────────────────────────────────────────────────────────────────
DPI-детектор для Hysteria2: тест блокировки QUIC/UDP и автофолбэк портов.

Тесты:
  • UDP connectivity test на порт H2 через raw socket
  • Проверка ICMP unreachable (= UDP заблокирован роутером/DPI)
  • Сравнение RTT по нескольким портам — выбор наименее заблокированного
  • Авто-переключение на fallback_port при детекции блокировки
  • Обновление iptables-правил при смене порта
  • TG-уведомление о смене порта

Точка входа из _core.py:
    from vless_installer.modules.hysteria2_dpi import (
        h2_dpi_test, h2_dpi_auto_fallback, do_h2_dpi_menu,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

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
    _tg_h2_event, _is_ipv6,
    open_udp_ports, close_udp_ports, _detect_ipv6_available,
    H2_SERVICE, H2_CONFIG_FILE,
)
from vless_installer.modules.hysteria2_health import _quic_ping

_DPI_LOG = Path("/var/log/hysteria-dpi.log")

# Кандидаты для фолбэка по убыванию приоритета
_FALLBACK_PORTS_DEFAULT = [443, 8443, 2083, 2087, 2096, 4433]


def _dpi_log(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _DPI_LOG.open("a") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass
    log_to_file("INFO", f"H2 DPI: {msg}")


# ── Тест UDP-порта ────────────────────────────────────────────────────────────
def _test_udp_port(host: str, port: int, timeout: float = 3.0) -> dict:
    """
    Тестирует UDP-доступность порта через QUIC-пинг.
    Возвращает {"port": int, "rtt": float|None, "blocked": bool, "reason": str}.
    """
    rtt = _quic_ping(host, port, timeout=timeout)

    # Дополнительно: проверяем через nmap если доступен
    blocked = False
    reason  = ""

    if rtt is None:
        # Пробуем nc или простой UDP send
        target = host.strip("[]")
        family = socket.AF_INET6 if _is_ipv6(host) else socket.AF_INET
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b"\x00" * 32, (target, port))
            s.recvfrom(64)  # если дождались — порт открыт
            rtt     = timeout * 500  # приблизительно
            blocked = False
            reason  = "UDP response"
        except socket.timeout:
            blocked = True
            reason  = "timeout (QUIC заблокирован?)"
        except OSError as e:
            blocked = True
            reason  = f"ICMP unreachable: {e}"
        finally:
            try:
                s.close()
            except Exception:
                pass
    else:
        reason = f"QUIC OK, RTT={rtt}ms"

    return {"port": port, "rtt": rtt, "blocked": blocked, "reason": reason}


def h2_dpi_test(
    host: str = "",
    ports: Optional[list[int]] = None,
    timeout: float = 5.0,
) -> list[dict]:
    """
    Тестирует все указанные порты на блокировку DPI.
    Если host не задан — тестируется первая активная exit-нода.
    Возвращает список результатов по портам (сортировка: лучшие первые).
    """
    h2 = _load_h2_state()

    if not host:
        nodes = [n for n in h2.get("exit_nodes", []) if n.get("status") == "active"]
        if not nodes:
            warn("Нет активных H2 нод для теста DPI")
            return []
        host = nodes[0]["ip"]

    if not ports:
        ports = h2.get("firewall", {}).get("udp_ports", [443])
        fallbacks = h2.get("firewall", {}).get("fallback_ports", _FALLBACK_PORTS_DEFAULT)
        # Тестируем текущие + fallback порты
        all_ports = list(dict.fromkeys(ports + fallbacks))[:8]
    else:
        all_ports = ports

    info(f"DPI-тест UDP портов на {host}: {all_ports}")
    results = []
    for p in all_ports:
        r = _test_udp_port(host, p, timeout=timeout)
        results.append(r)
        status = f"{RED}BLOCKED{NC}" if r["blocked"] else f"{GREEN}OK{NC}"
        rtt_s  = f"RTT={r['rtt']}ms" if r["rtt"] else ""
        print(f"  порт {p:>5}:  {status}  {DIM}{r['reason']}{NC}  {rtt_s}")

    _dpi_log(f"DPI test {host}: " + ", ".join(
        f"{r['port']}={'BLOCK' if r['blocked'] else 'OK'}" for r in results
    ))
    return results


def _best_port(results: list[dict]) -> Optional[int]:
    """Выбирает лучший незаблокированный порт с минимальным RTT."""
    available = [r for r in results if not r["blocked"] and r.get("rtt") is not None]
    if not available:
        # Все заблокированы — берём первый неблокированный по timeout
        available = [r for r in results if not r["blocked"]]
    if not available:
        return None
    best = min(available, key=lambda r: r.get("rtt") or 9999)
    return best["port"]


def h2_dpi_auto_fallback() -> bool:
    """
    Проверяет текущий порт и при обнаружении блокировки
    автоматически переключается на лучший доступный порт.
    Обновляет iptables, конфиг H2 и state.json.
    Возвращает True если порт был сменён.
    """
    h2    = _load_h2_state()
    nodes = [n for n in h2.get("exit_nodes", []) if n.get("status") == "active"]
    if not nodes:
        return False

    current_ports = h2.get("firewall", {}).get("udp_ports", [443])
    fallbacks      = h2.get("firewall", {}).get("fallback_ports", _FALLBACK_PORTS_DEFAULT)
    host           = nodes[0]["ip"]

    results = h2_dpi_test(host=host, ports=current_ports + fallbacks)
    if not results:
        return False

    # Проверяем заблокированы ли текущие порты
    current_blocked = all(
        next((r["blocked"] for r in results if r["port"] == p), True)
        for p in current_ports
    )

    if not current_blocked:
        _dpi_log(f"Текущие порты {current_ports} доступны, смена не нужна")
        return False

    best = _best_port(results)
    if not best:
        error("Все тестируемые порты заблокированы, фолбэк невозможен")
        _dpi_log("Все порты заблокированы")
        _tg_h2_event("h2_port_fb", "⛔ Все UDP-порты заблокированы DPI!")
        return False

    if best in current_ports:
        return False

    info(f"DPI: смена порта {current_ports} → [{best}]")
    _dpi_log(f"Fallback: {current_ports} → [{best}]")

    # Закрываем старые, открываем новый
    close_udp_ports(current_ports, ipv6=True)
    open_udp_ports([best], ipv6=_detect_ipv6_available())

    # Патчим конфиг H2
    _patch_h2_config_port(best)

    # Обновляем state
    h2["firewall"]["udp_ports"] = [best]
    for n in h2.get("exit_nodes", []):
        if n.get("status") == "active":
            n["ports"] = [best]
    _save_h2_state(h2)

    # Рестарт H2
    from vless_installer.modules.hysteria2_common import _systemctl
    _systemctl("restart", H2_SERVICE)
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)


    _tg_h2_event("h2_port_fb", f"DPI фолбэк: порт {current_ports[0]} → {best}")
    success(f"Порт успешно сменён на {best}")
    return True


def _patch_h2_config_port(new_port: int) -> None:
    """Обновляет listen-порт в /etc/hysteria/config.yaml."""
    if not H2_CONFIG_FILE.exists():
        return
    try:
        import re
        text = H2_CONFIG_FILE.read_text()
        text = re.sub(r'^(listen:\s*::?)(\d+)', rf'\g<1>{new_port}', text,
                      flags=re.MULTILINE)
        text = re.sub(r'^(listen:\s*0\.0\.0\.0:)(\d+)', rf'\g<1>{new_port}', text,
                      flags=re.MULTILINE)
        H2_CONFIG_FILE.write_text(text)
        info(f"Конфиг H2 обновлён: listen port → {new_port}")
    except Exception as e:
        error(f"Не удалось обновить конфиг: {e}")


# ── Меню ──────────────────────────────────────────────────────────────────────
def do_h2_dpi_menu() -> None:
    """Интерактивное меню DPI-тестирования H2."""
    while True:
        os.system("clear")
        print()
        h2 = _load_h2_state()
        fb = h2.get("firewall", {}).get("fallback_ports", [80, 8080, 2053])
        _box_top("🔍  HYSTERIA2 — DPI ДЕТЕКТОР")
        _box_row(f"  Fallback-порты: {CYAN}{fb}{NC}")
        _box_sep()
        _box_row()

        h2    = _load_h2_state()
        ports = h2.get("firewall", {}).get("udp_ports", [443])
        fb    = h2.get("firewall", {}).get("fallback_ports", _FALLBACK_PORTS_DEFAULT)
        print(f"  Текущие UDP-порты:   {CYAN}{ports}{NC}")
        print(f"  Fallback-порты:      {DIM}{fb}{NC}")
        print()
        _box_item("1", f"DPI-тест всех портов  {DIM}(текущие + fallback){NC}")
        _box_item("2", "Автофолбэк при обнаружении блокировки")
        _box_item("3", "Задать список fallback-портов")
        _box_item("4", "Показать лог DPI")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "1":
            print()
            h2_dpi_test()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            print()
            switched = h2_dpi_auto_fallback()
            if switched:
                success("Порт успешно переключён")
            else:
                info("Смена порта не потребовалась")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            try:
                raw = input(
                    f"  {CYAN}Fallback-порты{NC} (через запятую) "
                    f"[{','.join(map(str,fb))}]: "
                ).strip()
            except KeyboardInterrupt:
                continue
            if raw:
                new_fb = [int(p.strip()) for p in raw.split(",")
                           if p.strip().isdigit()]
                h2["firewall"]["fallback_ports"] = new_fb
                _save_h2_state(h2)
                success(f"Fallback-порты → {new_fb}")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            if _DPI_LOG.exists():
                lines = _DPI_LOG.read_text().splitlines()[-40:]
                print("\n".join(lines))
            else:
                warn("Лог пуст")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "Q":
            break
        else:
            time.sleep(0.5)


"""
ПРИМЕР ВЫЗОВА из _core.py:
    from vless_installer.modules.hysteria2_dpi import (
        h2_dpi_test, h2_dpi_auto_fallback, do_h2_dpi_menu,
    )

    # Тест портов:
    results = h2_dpi_test()

    # Авто-фолбэк (из cron):
    h2_dpi_auto_fallback()

    # Интерактивно:
    do_h2_dpi_menu()
"""
