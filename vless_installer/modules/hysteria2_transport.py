"""
vless_installer/modules/hysteria2_transport.py
───────────────────────────────────────────────────────────────────────────────
Настройка транспорта Hysteria2 на Entry-ноде.

АРХИТЕКТУРА (нативный клиент):
  Клиент → Xray (VLESS inbound) → Xray (SOCKS5 outbound → 127.0.0.1:10809)
           → hysteria2-клиент (нативный бинарь /usr/local/bin/hysteria)
           → Exit-нода (hysteria2-сервер) → Интернет

Почему не Xray-built-in hysteria protocol:
  Xray-core 26.x имеет документированные баги с нативным protocol:"hysteria"
  (pinnedPeerCertSha256 + CA-сертификаты, up/down параметры, ALPN).
  Нативный hysteria2-бинарь работает корректно с официальным сервером.
  Для Xray это обычный SOCKS5-прокси — никаких специфичных зависимостей.

Для клиента (VLESS-ссылки) ничего не меняется.

Основные функции:
  • h2_transport_apply()    — применить H2 как транспорт для выбранной exit-ноды
  • h2_transport_remove()   — вернуть на AWG/VLESS транспорт
  • h2_transport_status()   — текущий активный транспорт
  • h2_select_transport()   — выбор AWG / H2 / оба (с весами)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from vless_installer.modules.hysteria2_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, _load_h2_state, _save_h2_state, _ensure_h2_state,
    _tg_h2_event, _is_ipv6, _bracket,
    H2_BINARY,
)
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)


_XRAY_CONFIG     = Path("/usr/local/etc/xray/config.json")
_XRAY_CONFIG_ALT = Path("/etc/xray/config.json")
_STATE_FILE      = Path("/var/lib/xray-installer/state.json")

# Нативный Hysteria2-клиент слушает SOCKS5 на этом адресе
_H2_CLIENT_SOCKS_HOST = "127.0.0.1"
_H2_CLIENT_SOCKS_PORT = 10809
_H2_CLIENT_CONFIG     = Path("/etc/hysteria/client.yaml")
_H2_CLIENT_SERVICE    = "hysteria-client"


# ── Xray config helpers ───────────────────────────────────────────────────────

def _find_xray_config() -> Optional[Path]:
    """
    Проверяем /etc/xray/config.json первым — это канонический путь,
    который используется в ExecStart systemd unit.
    /usr/local/etc/xray/config.json создаётся как symlink для совместимости;
    write через tmp.replace() ломает symlink — поэтому он идёт вторым.
    """
    for p in (_XRAY_CONFIG_ALT, _XRAY_CONFIG):
        if p.exists():
            return p
    return None


def _load_xray_config() -> Optional[dict]:
    p = _find_xray_config()
    if not p:
        return None
    try:
        return json.loads(p.read_text())
    except Exception as e:
        error(f"Не удалось прочитать xray config: {e}")
        return None


def _save_xray_config(cfg: dict) -> bool:
    """Атомарная запись. Если путь — symlink, пишем в target, не в symlink."""
    p = _find_xray_config()
    if not p:
        p = _XRAY_CONFIG_ALT
    target = p.resolve() if p.is_symlink() else p
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        tmp.replace(target)
        return True
    except Exception as e:
        error(f"Не удалось сохранить xray config: {e}")
        return False


def _xray_restart() -> bool:
    for svc in ("xray", "xray-core"):
        r = _run(["systemctl", "is-active", "--quiet", svc], quiet=True)
        if r.returncode == 0:
            _run(["systemctl", "restart", svc], quiet=True)
            time.sleep(2)
            return True
    return False


# ── Hysteria2 native client ───────────────────────────────────────────────────

def _write_h2_client_config(
    exit_ip: str,
    exit_port: int,
    auth_password: str,
    cert_sha256: str = "",
    sni: str = "",
) -> bool:
    """
    Генерирует /etc/hysteria/client.yaml для нативного hysteria2-клиента.
    Клиент поднимает SOCKS5 на 127.0.0.1:10809, через который Xray
    направляет исходящий трафик.
    """
    ipv6 = _is_ipv6(exit_ip)
    server_addr = f"[{exit_ip}]:{exit_port}" if ipv6 else f"{exit_ip}:{exit_port}"

    # TLS: для самоподписанных сертификатов (а они всегда таковы в этом
    # установщике) нативный hysteria2-клиент требует insecure: true, иначе
    # падает с "x509: certificate signed by unknown authority" — даже при
    # наличии pinSHA256. Безопасность обеспечивается pinSHA256, который
    # верифицирует точный отпечаток сертификата сервера.
    if cert_sha256:
        sha = cert_sha256.replace(":", "").lower()
        if sni:
            tls_block = f"""tls:
  insecure: true
  serverName: {sni}
  pinSHA256: {sha}
"""
        else:
            tls_block = f"""tls:
  insecure: true
  pinSHA256: {sha}
"""
    else:
        warn("Нет SHA256-отпечатка сертификата exit-ноды — соединение небезопасно")
        tls_block = """tls:
  insecure: true
"""

    config_yaml = f"""# Hysteria2 client config — generated by VLESS Ultimate Installer
server: {server_addr}

auth: {auth_password}

{tls_block}
socks5:
  listen: {_H2_CLIENT_SOCKS_HOST}:{_H2_CLIENT_SOCKS_PORT}

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
"""
    try:
        _H2_CLIENT_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        _H2_CLIENT_CONFIG.write_text(config_yaml)
        info(f"Hysteria2 client config → {_H2_CLIENT_CONFIG}")
        return True
    except Exception as e:
        error(f"Не удалось записать {_H2_CLIENT_CONFIG}: {e}")
        return False


def _ensure_hysteria_client_service() -> bool:
    """
    Создаёт и включает systemd-сервис hysteria-client.service.
    Использует тот же бинарь /usr/local/bin/hysteria, что и сервер,
    но в режиме client с отдельным конфигом client.yaml.
    """
    if not H2_BINARY.exists():
        # На entry-ноде hysteria-бинарь может отсутствовать (exit-нода
        # устанавливается удалённо через SSH и бинарь туда не копируется).
        # Скачиваем автоматически — тот же бинарь используется и как клиент.
        info(f"Hysteria2 бинарь не найден ({H2_BINARY}), скачиваю на entry-ноду...")
        try:
            from vless_installer.modules.hysteria2_exit_mgr import _install_h2_binary
            if not _install_h2_binary():
                error("Не удалось скачать hysteria2 на entry-ноду")
                return False
        except Exception as e:
            error(f"Ошибка при установке hysteria2 на entry-ноду: {e}")
            return False

    unit = f"""[Unit]
Description=Hysteria2 Client (VLESS Ultimate Installer)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart={H2_BINARY} client --config {_H2_CLIENT_CONFIG}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""
    unit_path = Path(f"/etc/systemd/system/{_H2_CLIENT_SERVICE}.service")
    try:
        unit_path.write_text(unit)
        _run(["systemctl", "daemon-reload"], quiet=True)
        _run(["systemctl", "enable", _H2_CLIENT_SERVICE], quiet=True)
        return True
    except Exception as e:
        error(f"Не удалось создать {_H2_CLIENT_SERVICE}.service: {e}")
        return False


def _start_hysteria_client() -> bool:
    r = _run(["systemctl", "restart", _H2_CLIENT_SERVICE], quiet=True)
    if r.returncode != 0:
        error(f"Не удалось запустить {_H2_CLIENT_SERVICE}")
        _run(["journalctl", "-u", _H2_CLIENT_SERVICE, "-n", "20",
              "--no-pager"], quiet=False)
        return False
    time.sleep(2)
    r2 = _run(["systemctl", "is-active", "--quiet", _H2_CLIENT_SERVICE],
               quiet=True)
    if r2.returncode != 0:
        error(f"{_H2_CLIENT_SERVICE} упал после запуска")
        _run(["journalctl", "-u", _H2_CLIENT_SERVICE, "-n", "20",
              "--no-pager"], quiet=False)
        return False
    success(f"hysteria-client запущен → SOCKS5 {_H2_CLIENT_SOCKS_HOST}:{_H2_CLIENT_SOCKS_PORT}")
    return True


def _stop_hysteria_client() -> None:
    _run(["systemctl", "stop", _H2_CLIENT_SERVICE], quiet=True)
    _run(["systemctl", "disable", _H2_CLIENT_SERVICE], quiet=True)


# ── Xray outbound patch ───────────────────────────────────────────────────────

def _build_socks_outbound(
    host: str = _H2_CLIENT_SOCKS_HOST,
    port: int = _H2_CLIENT_SOCKS_PORT,
    tag: str = "proxy",
) -> dict:
    """
    SOCKS5 outbound, указывающий на локальный Hysteria2-клиент.
    Xray не знает, что за ним стоит — для него это обычный SOCKS5-прокси.
    """
    return {
        "tag": tag,
        "protocol": "socks",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
            }]
        },
    }


def _find_proxy_outbound_idx(cfg: dict, tag: str = "proxy") -> int:
    for i, ob in enumerate(cfg.get("outbounds", [])):
        if ob.get("tag") == tag:
            return i
    return -1


def _find_catchall_rule(cfg: dict) -> Optional[dict]:
    """Находит catch-all routing-правило (network: tcp,udp, не BLOCK)."""
    for rule in cfg.get("routing", {}).get("rules", []):
        if rule.get("type") != "field":
            continue
        net = rule.get("network", "")
        if ("tcp" in net and "udp" in net
                and not rule.get("ip")
                and not rule.get("protocol")
                and rule.get("outboundTag") != "BLOCK"):
            return rule
    return None


def _patch_routing_to_proxy(cfg: dict, tag: str = "proxy") -> tuple[bool, str]:
    rule = _find_catchall_rule(cfg)
    if rule is None:
        return False, ""
    prev = rule.get("outboundTag", "")
    if prev == tag:
        return False, prev
    rule["outboundTag"] = tag
    return True, prev


# ── Public API ────────────────────────────────────────────────────────────────

def h2_transport_apply(
    exit_ip: str = "",
    exit_port: int = 443,
    auth_password: str = "",
    insecure: bool = True,
) -> bool:
    """
    Применяет Hysteria2 как транспорт на Entry-ноде:
      1. Записывает /etc/hysteria/client.yaml
      2. Создаёт и запускает systemd-сервис hysteria-client
      3. Патчит Xray outbound → SOCKS5 → 127.0.0.1:10809
      4. Патчит catch-all routing-правило на тег proxy
      5. Перезапускает Xray
    """
    h2 = _ensure_h2_state()

    if not exit_ip:
        nodes = [n for n in h2.get("exit_nodes", []) if n.get("status") == "active"]
        if not nodes:
            error("Нет активных H2 exit-нод в state.json. Сначала установите Exit.")
            return False
        node = nodes[0]
        exit_ip       = node["ip"]
        exit_port     = node.get("ports", [443])[0]
        auth_password = node.get("auth", "")

    if not auth_password:
        error("Не задан пароль аутентификации H2")
        return False

    cert_sha256 = ""
    for n in h2.get("exit_nodes", []):
        if n.get("ip") == exit_ip:
            cert_sha256 = n.get("cert_sha256", "")
            break

    # 1. Конфиг нативного клиента
    if not _write_h2_client_config(exit_ip, exit_port, auth_password, cert_sha256):
        return False

    # 2. Systemd-сервис
    if not _ensure_hysteria_client_service():
        return False

    # 3. Запуск клиента
    if not _start_hysteria_client():
        return False

    # 4. Патч Xray config
    cfg = _load_xray_config()
    if cfg is None:
        error("Xray config.json не найден")
        return False

    new_ob = _build_socks_outbound()
    idx = _find_proxy_outbound_idx(cfg)
    if idx >= 0:
        h2["_prev_outbound"] = cfg["outbounds"][idx]
        cfg["outbounds"][idx] = new_ob
        info("Заменяю outbound[proxy] → SOCKS5 (Hysteria2 native client)")
    else:
        cfg.setdefault("outbounds", []).insert(0, new_ob)
        info("Добавляю SOCKS5 outbound → Hysteria2 native client")

    changed, prev_tag = _patch_routing_to_proxy(cfg, tag="proxy")
    if changed:
        h2["_prev_routing_tag"] = prev_tag
        info(f"Routing catch-all: {prev_tag} → proxy")
    elif not prev_tag:
        warn("Catch-all routing-правило не найдено — проверьте config.json")

    if not _save_xray_config(cfg):
        return False

    _xray_restart()

    h2["active_transport"] = "hysteria2"
    _save_h2_state(h2)

    success(f"Hysteria2 транспорт активирован: "
            f"Xray → SOCKS5:10809 → hysteria-client → {exit_ip}:{exit_port}")
    _tg_h2_event("h2_switch", f"Транспорт → H2 native ({exit_ip}:{exit_port})")
    log_to_file("INFO", f"H2 native transport applied: {exit_ip}:{exit_port}")
    return True


def h2_transport_remove() -> bool:
    """Откатывает H2-транспорт: останавливает hysteria-client, восстанавливает Xray outbound."""
    h2 = _load_h2_state()
    cfg = _load_xray_config()
    if cfg is None:
        return False

    # Останавливаем нативный клиент
    _stop_hysteria_client()

    prev_ob = h2.pop("_prev_outbound", None)
    prev_routing_tag = h2.pop("_prev_routing_tag", None)
    idx = _find_proxy_outbound_idx(cfg)

    if idx >= 0:
        if prev_ob:
            cfg["outbounds"][idx] = prev_ob
            info("Восстановлен предыдущий outbound (AWG/VLESS)")
        else:
            cfg["outbounds"].pop(idx)
            info("SOCKS5/H2 outbound удалён")

    if prev_routing_tag:
        rule = _find_catchall_rule(cfg)
        if rule is not None:
            rule["outboundTag"] = prev_routing_tag
            info(f"Routing catch-all восстановлен: proxy → {prev_routing_tag}")

    if not _save_xray_config(cfg):
        return False

    _xray_restart()
    h2["active_transport"] = "awg"
    _save_h2_state(h2)
    success("Транспорт H2 отключён, hysteria-client остановлен")
    _tg_h2_event("h2_switch", "Транспорт → AWG/VLESS")
    return True


def h2_transport_status() -> dict:
    h2 = _load_h2_state()
    cfg = _load_xray_config()
    active = "unknown"
    exit_ip = ""
    exit_port = 0

    # Проверяем, запущен ли hysteria-client
    r = _run(["systemctl", "is-active", "--quiet", _H2_CLIENT_SERVICE], quiet=True)
    if r.returncode == 0:
        active = "hysteria2"
        # Читаем exit-параметры из client.yaml
        if _H2_CLIENT_CONFIG.exists():
            try:
                for line in _H2_CLIENT_CONFIG.read_text().splitlines():
                    if line.startswith("server:"):
                        srv = line.split(":", 1)[1].strip()
                        # srv может быть "ip:port" или "[ipv6]:port"
                        if srv.startswith("["):
                            exit_ip = srv[1:srv.index("]")]
                            exit_port = int(srv.split("]:")[-1])
                        else:
                            parts = srv.rsplit(":", 1)
                            exit_ip = parts[0]
                            exit_port = int(parts[1]) if len(parts) > 1 else 443
            except Exception:
                pass
    else:
        active = h2.get("active_transport", "awg")

    return {
        "active_transport": active,
        "exit_ip":   exit_ip,
        "exit_port": exit_port,
        "h2_nodes":  len(h2.get("exit_nodes", [])),
    }


def h2_select_transport() -> None:
    """Интерактивный выбор транспорта: AWG / Hysteria2."""
    while True:
        os.system("clear")
        print()
        st = h2_transport_status()
        active   = st["active_transport"]
        exit_ip  = st.get("exit_ip", "")
        exit_prt = st.get("exit_port", 0)
        n_nodes  = st.get("h2_nodes", 0)
        col = GREEN if active == "hysteria2" else (YELLOW if active == "awg" else CYAN)

        _box_top("🔀  HYSTERIA2 — ВЫБОР ТРАНСПОРТА ENTRY → EXIT")
        status_extra = (f"  │  {DIM}Exit: {exit_ip}:{exit_prt}{NC}"
                        if active == "hysteria2" and exit_ip else "")
        _box_row(f"  Транспорт: {col}{active}{NC}{status_extra}  │  H2 нод: {CYAN}{n_nodes}{NC}")
        _box_sep()
        _box_row()
        _box_item("1", f"AWG (AmneziaWG)         {DIM}Вернуть на AWG/VLESS транспорт{NC}")
        _box_item("2", f"Hysteria2 (нативный)    {DIM}Запустить hysteria-client + SOCKS5 outbound{NC}")
        _box_item("3", f"Оба (AWG + H2)          {DIM}Балансировка по весам{NC}")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch in ("Q", ""):
            break

        elif ch == "1":
            h2_transport_remove()
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            h2 = _load_h2_state()
            nodes = [n for n in h2.get("exit_nodes", []) if n.get("status") == "active"]
            if not nodes:
                warn("Нет активных H2 exit-нод. Сначала выполните установку (меню 1 → Exit-нода).")
                input(f"\n{BLUE}Нажмите Enter...{NC}")
                continue
            node = nodes[0]
            h2_transport_apply(
                exit_ip=node["ip"],
                exit_port=node.get("ports", [443])[0],
                auth_password=node.get("auth", ""),
            )
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            info("Режим AWG+H2 — настройте веса в меню «Балансировщик» (пункт 3)")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        else:
            warn("Неверный выбор")
            time.sleep(0.8)
