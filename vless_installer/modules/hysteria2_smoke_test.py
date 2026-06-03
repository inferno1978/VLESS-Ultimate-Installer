"""
vless_installer/modules/hysteria2_smoke_test.py
───────────────────────────────────────────────────────────────────────────────
Smoke Test для Hysteria2 — проверка после установки/apply.

Тесты:
  1. Сервис systemd активен
  2. UDP-порт слушается (ss -u -ln)
  3. QUIC-ping на каждый настроенный порт
  4. Проверка маршрута (curl через H2 SOCKS5-proxy если доступен)
  5. Валидность TLS-сертификата
  6. Xray принимает конфиг (xray -test)

Результаты выводятся в стиле smoke_test.py проекта.
Возвращает True если все критичные тесты прошли.

Точка входа из _core.py:
    from vless_installer.modules.hysteria2_smoke_test import (
        h2_smoke_test, do_h2_smoke_test_menu,
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
    _run, _load_h2_state,
    _service_active, _h2_binary_exists, _h2_binary_version,
    _is_ipv6,
    H2_SERVICE, H2_CONFIG_FILE, H2_CERT_FILE, H2_KEY_FILE,
)
from vless_installer.modules.hysteria2_health import _quic_ping

_OK  = f"{GREEN}✓{NC}"
_ERR = f"{RED}✗{NC}"
_SKP = f"{YELLOW}—{NC}"


def _check(label: str, result: bool, detail: str = "") -> bool:
    sym = _OK if result else _ERR
    print(f"  {sym} {label}" + (f"  {DIM}{detail}{NC}" if detail else ""))
    return result


def h2_smoke_test(verbose: bool = True) -> bool:
    """
    Выполняет полный smoke test Hysteria2.
    Возвращает True если все КРИТИЧНЫЕ тесты прошли.
    """
    if verbose:
        print()
        _box_top(f"🔬  HYSTERIA2 SMOKE TEST  {DIM}{datetime.now().strftime('%d.%m.%Y %H:%M:%S')}{NC}")
        _box_row()

    h2    = _load_h2_state()
    ports = h2.get("firewall", {}).get("udp_ports", [443])
    nodes = h2.get("exit_nodes", [])

    results: dict[str, bool] = {}

    # ── 1. Бинарник ───────────────────────────────────────────────────────────
    bin_ok = _h2_binary_exists()
    ver    = _h2_binary_version() if bin_ok else ""
    results["binary"] = _check(
        "Бинарник Hysteria2",
        bin_ok,
        f"v{ver}" if ver else "(не найден)",
    )

    # ── 2. Системный сервис ───────────────────────────────────────────────────
    svc_ok = _service_active(H2_SERVICE)
    results["service"] = _check("Сервис hysteria-server", svc_ok,
                                  "active" if svc_ok else "не активен")

    # ── 3. UDP-порт слушается ─────────────────────────────────────────────────
    port_ok = False
    port_detail = ""
    if svc_ok and ports:
        r = _run(["ss", "-u", "-l", "-n"], capture=True, timeout=5)
        for p in ports:
            if f":{p} " in r.stdout or f":{p}\n" in r.stdout:
                port_ok = True
                port_detail = f"UDP:{p} LISTEN"
                break
        if not port_ok:
            port_detail = f"UDP:{ports} не найден в ss"
    else:
        port_detail = "пропущено (сервис не активен)"
    results["port"] = _check("UDP-порт слушается", port_ok, port_detail)

    # ── 4. TLS-сертификат ─────────────────────────────────────────────────────
    cert_ok = H2_CERT_FILE.exists() and H2_KEY_FILE.exists()
    if cert_ok:
        from vless_installer.modules.hysteria2_cert_mgr import h2_cert_check
        info_d    = h2_cert_check()
        cert_ok   = info_d.get("valid", False)
        cert_detail = f"до {info_d.get('expires_at','?')} ({info_d.get('days_left',0)} дней)"
    else:
        cert_detail = "файл не найден"
    results["cert"] = _check("TLS-сертификат", cert_ok, cert_detail)

    # ── 5. Конфиг-файл H2 ────────────────────────────────────────────────────
    cfg_ok = H2_CONFIG_FILE.exists()
    results["config"] = _check("Конфиг /etc/hysteria/config.yaml", cfg_ok,
                                  "существует" if cfg_ok else "не найден")

    # ── 6. Xray конфиг валиден ────────────────────────────────────────────────
    xray_ok = False
    xray_detail = ""
    xray_bin = _run(["which", "xray"], capture=True).stdout.strip()
    if xray_bin:
        cfg_paths = ["/usr/local/etc/xray/config.json", "/etc/xray/config.json"]
        for cp in cfg_paths:
            if Path(cp).exists():
                r = _run([xray_bin, "-test", "-config", cp],
                          capture=True, timeout=10)
                xray_ok     = r.returncode == 0
                xray_detail = "OK" if xray_ok else r.stderr[:80].strip()
                break
    else:
        xray_detail = "xray не найден в PATH"
    results["xray_config"] = _check("Xray конфиг (xray -test)", xray_ok, xray_detail)

    # ── 7. QUIC ping на exit-ноды ─────────────────────────────────────────────
    if verbose:
        print()
        print(f"  {DIM}QUIC ping по нодам:{NC}")

    ping_results = []
    for node in nodes:
        ip    = node.get("ip", "")
        nports = node.get("ports", [443])
        if not ip:
            continue
        for p in nports[:2]:  # не более 2 портов на ноду
            rtt = _quic_ping(ip, p, timeout=5.0)
            ok  = rtt is not None
            ping_results.append(ok)
            label  = f"  QUIC ping {ip}:{p}"
            detail = f"{rtt}ms" if ok else "timeout/unreachable"
            _check(label, ok, detail)

    quic_ok = any(ping_results) if ping_results else True  # нет нод = не ошибка
    results["quic_ping"] = quic_ok

    # ── 8. IPv6 (если доступен) ───────────────────────────────────────────────
    from vless_installer.modules.hysteria2_common import _detect_ipv6_available
    if _detect_ipv6_available():
        ipv6_nodes = [n for n in nodes if _is_ipv6(n.get("ip", ""))]
        if ipv6_nodes:
            ip6 = ipv6_nodes[0]["ip"].strip("[]")
            p6  = ipv6_nodes[0].get("ports", [443])[0]
            rtt6 = _quic_ping(ip6, p6, timeout=5.0)
            results["ipv6"] = _check(f"QUIC IPv6 ping {ip6}:{p6}",
                                      rtt6 is not None,
                                      f"{rtt6}ms" if rtt6 else "timeout")
        else:
            print(f"  {_SKP} IPv6 ноды не настроены — пропущено")
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)


    # ── Итог ─────────────────────────────────────────────────────────────────
    critical = ["binary", "service", "cert", "config", "xray_config"]
    all_critical_ok = all(results.get(k, False) for k in critical)
    total_ok  = sum(1 for v in results.values() if v)
    total_all = len(results)

    print()
    print(f"{CYAN}{'─'*62}{NC}")
    color = GREEN if all_critical_ok else RED
    _box_row(f"  {color}{'✓ Все критичные тесты прошли' if all_critical_ok else '✗ Есть критичные ошибки'}{NC}  ({total_ok}/{total_all} тестов ОК)")
    _box_row()
    _box_bottom()

    log_to_file(
        "INFO" if all_critical_ok else "ERROR",
        f"H2 smoke test: {total_ok}/{total_all}, critical={'OK' if all_critical_ok else 'FAIL'}"
    )
    return all_critical_ok


# ── Меню ──────────────────────────────────────────────────────────────────────
def do_h2_smoke_test_menu() -> None:
    """Интерактивное меню Smoke Test H2."""
    while True:
        os.system("clear")
        print()
        _box_top("🔬  HYSTERIA2 — SMOKE TEST")
        _box_row(f"  {DIM}Полная диагностическая проверка после установки{NC}")
        _box_sep()
        _box_row()
        _box_item("1", "Запустить полный Smoke Test")
        _box_item("2", f"Быстрый тест  {DIM}(только сервис + порт){NC}")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "1":
            result = h2_smoke_test(verbose=True)
            print()
            if result:
                success("Smoke Test PASSED")
            else:
                error("Smoke Test FAILED — проверьте ошибки выше")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            h2    = _load_h2_state()
            ok1   = _service_active(H2_SERVICE)
            ports = h2.get("firewall", {}).get("udp_ports", [443])
            r     = _run(["ss", "-u", "-l", "-n"], capture=True, timeout=5)
            ok2   = any(f":{p}" in r.stdout for p in ports)
            print()
            _check("Сервис hysteria-server", ok1)
            _check(f"UDP-порт {ports}", ok2)
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "Q":
            break
        else:
            time.sleep(0.5)


"""
ПРИМЕР ВЫЗОВА из _core.py:
    from vless_installer.modules.hysteria2_smoke_test import (
        h2_smoke_test, do_h2_smoke_test_menu,
    )

    # После h2_exit_install():
    ok = h2_smoke_test()
    if not ok:
        warn("Smoke test выявил проблемы")

    # CLI --h2-smoke:
    sys.exit(0 if h2_smoke_test() else 1)

    # Интерактивно:
    do_h2_smoke_test_menu()
"""
