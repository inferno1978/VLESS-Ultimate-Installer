"""
vless_installer/modules/hysteria2_transport.py
───────────────────────────────────────────────────────────────────────────────
Настройка Xray outbound на Entry-ноде для транспорта Hysteria2.

Hysteria2 в контексте Xray — это транспортный уровень outbound:
  Entry → (Hysteria2/QUIC/UDP) → Exit → Интернет

Клиент подключается по обычной VLESS-ссылке, прозрачно.
Генерация VLESS-ссылок НЕ ЗАТРАГИВАЕТСЯ.

Основные функции:
  • h2_transport_apply()    — применить H2 как транспорт для выбранной exit-ноды
  • h2_transport_remove()   — вернуть на AWG/VLESS транспорт
  • h2_transport_status()   — текущий активный транспорт
  • h2_select_transport()   — выбор AWG / H2 / оба (с весами)

Xray конфиг patching использует тот же подход что xray_safe_apply.py.

ВАЖНО: не модифицирует существующие функции генерации конфигов.
Патч применяется только к outbound секции через прямую запись JSON.

Точка входа из _core.py:
    from vless_installer.modules.hysteria2_transport import (
        h2_transport_apply, h2_transport_remove, h2_select_transport,
    )
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
)
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)


_XRAY_CONFIG = Path("/usr/local/etc/xray/config.json")
_XRAY_CONFIG_ALT = Path("/etc/xray/config.json")
_STATE_FILE = Path("/var/lib/xray-installer/state.json")


def _find_xray_config() -> Optional[Path]:
    """
    BUGFIX: каноническая директория конфига в _core.py — CONFIG_DIR =
    Path("/etc/xray"); именно туда пишется config.json при генерации,
    и именно этот путь передаётся в systemd unit (ExecStart=... -config
    /etc/xray/config.json). /usr/local/etc/xray/config.json создаётся
    в generate_xray_config_chain_entry_multi()/generate_xray_config()
    лишь как СИМЛИНК на /etc/xray/config.json — для обратной совместимости.

    Раньше эта функция проверяла /usr/local/etc/xray/config.json первым.
    Поскольку симлинк "существует", он совпадал — и _save_xray_config()
    писал именно туда через tmp.replace(p), что атомарно ПОДМЕНЯЕТ сам
    симлинк обычным файлом (поведение os.rename для символьных ссылок).
    В результате патч уходил в "осиротевшую" копию конфига, а реальный
    /etc/xray/config.json, который читает запущенный Xray, не менялся
    вообще — Hysteria2-транспорт молча не применялся к живому процессу.

    Теперь проверяем /etc/xray/config.json (реальный, используемый Xray)
    первым; /usr/local/etc/xray/config.json — только как fallback для
    нестандартных инсталляций, где основной путь отличается.
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
    """
    BUGFIX: если найденный путь — символическая ссылка (например,
    /usr/local/etc/xray/config.json -> /etc/xray/config.json), пишем
    в файл, на который она указывает (p.resolve()), а не заменяем
    саму ссылку обычным файлом. Иначе при повторном запуске
    /usr/local/etc/xray/config.json и /etc/xray/config.json молча
    расходятся, и неясно, какой из них реально использует Xray.
    """
    p = _find_xray_config()
    if not p:
        p = _XRAY_CONFIG_ALT
    target = p.resolve() if p.is_symlink() else p
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # Атомарная запись через tmp
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


# ── Outbound patch ────────────────────────────────────────────────────────────
def _build_h2_outbound(
    exit_ip: str,
    exit_port: int,
    auth_password: str,
    tag: str = "proxy",
    cert_sha256: str = "",
    sni: Optional[str] = None,
    enable_mux: bool = True,
) -> dict:
    """
    Строит Xray outbound для Hysteria2.

    ВАЖНО: в Xray-core протокол называется "hysteria" (не "hysteria2"!), а
    версия 2 указывается явно полем "version" — и в settings (на уровне
    протокола), и продублирована в streamSettings.hysteriaSettings. Без
    "version": 2 Xray трактует конфиг как Hysteria v1 (полностью удалён из
    актуальных сборок Xray-core) и падает с "unknown config id" / валидацией.
    Источник схемы: infra/conf/hysteria.go в XTLS/Xray-core (network: "hysteria",
    settings.version + streamSettings.hysteriaSettings.version).

    TLS: поле "allowInsecure" с июня 2026 полностью убрано из Xray-core
    ("The feature 'allowInsecure' has been removed and migrated to
    'pinnedPeerCertSha256'"). Для самоподписанного сертификата exit-ноды
    нужно явно пиннить его SHA256-отпечаток вместо отключения проверки —
    отпечаток считается при установке H2 (см. h2_cert_sha256_local() /
    удалённую установку по SSH) и хранится в state.json у каждой exit-ноды.
    """
    ipv6 = _is_ipv6(exit_ip)
    server_addr = _bracket(exit_ip) if ipv6 else exit_ip

    tls_settings: dict = {
        "serverName": sni or exit_ip,
    }
    if cert_sha256:
        tls_settings["pinnedPeerCertSha256"] = cert_sha256
    else:
        warn("Нет сохранённого SHA256-отпечатка сертификата exit-ноды — "
             "TLS-валидация, скорее всего, провалится. Переустановите H2 "
             "на exit-ноде (меню 7 → 1/2), чтобы отпечаток сохранился.")

    outbound = {
        "tag": tag,
        "protocol": "hysteria",
        "settings": {
            "version": 2,
            "address": server_addr,
            "port": exit_port,
        },
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": tls_settings,
            "hysteriaSettings": {
                "version": 2,
                "auth": auth_password,
                "udpIdleTimeout": 60,
            },
        },
    }
    if enable_mux:
        # Мультиплексирование уменьшает накладные расходы на установление
        # новых QUIC-потоков при множестве параллельных соединений клиента.
        outbound["mux"] = {"enabled": True, "concurrency": 8}
    return outbound


def _find_proxy_outbound_idx(cfg: dict, tag: str = "proxy") -> int:
    """Возвращает индекс outbound с тегом 'proxy' или -1."""
    for i, ob in enumerate(cfg.get("outbounds", [])):
        if ob.get("tag") == tag:
            return i
    return -1


# ── BUGFIX: routing catch-all не указывал на H2-outbound ──────────────────────
# Проблема: generate_xray_config() / generate_xray_config_chain_entry_multi()
# (ветка H2_EXIT_ENABLED без VLESS exit-нод) ставят catch-all routing-правило
# {"network": "tcp,udp", "outboundTag": "direct"} или "chain-exit".
# h2_transport_apply() добавлял outbound с тегом "proxy", но НЕ трогал routing —
# в итоге весь трафик продолжал уходить через "direct"/"chain-exit" (т.е. с
# Entry-ноды напрямую или по старому транспорту), Hysteria2-outbound был
# "осиротевшим" и никогда не использовался. Снаружи это выглядело так, будто
# Hysteria2 "включился" (success-сообщение), но IP-чекеры показывали Entry IP,
# а не Exit IP — трафик реально никогда не покидал Entry-ноду через H2.
def _find_catchall_rule(cfg: dict) -> Optional[dict]:
    """
    Находит routing-правило catch-all (network: tcp,udp), которое НЕ относится
    к loopback (127.0.0.1/::1) и НЕ является BLOCK-правилом. Это правило
    определяет, куда уходит "весь остальной" трафик клиентов.
    """
    rules = cfg.get("routing", {}).get("rules", [])
    for rule in rules:
        if rule.get("type") != "field":
            continue
        net = rule.get("network", "")
        if "tcp" in net and "udp" in net and not rule.get("ip") and not rule.get("protocol"):
            if rule.get("outboundTag") != "BLOCK":
                return rule
    return None


def _patch_routing_to_proxy(cfg: dict, tag: str = "proxy") -> tuple[bool, str]:
    """
    Переключает catch-all routing-правило на outboundTag=tag (по умолчанию "proxy"),
    запоминая предыдущий тег, чтобы h2_transport_remove() мог откатить.
    Возвращает (изменено?, предыдущий_тег).
    """
    rule = _find_catchall_rule(cfg)
    if rule is None:
        return False, ""
    prev_tag = rule.get("outboundTag", "")
    if prev_tag == tag:
        return False, prev_tag
    rule["outboundTag"] = tag
    return True, prev_tag


def h2_transport_apply(
    exit_ip: str = "",
    exit_port: int = 443,
    auth_password: str = "",
    insecure: bool = True,
) -> bool:
    """
    Применяет Hysteria2 как транспорт на Entry-ноде.
    Патчит outbound в Xray конфиге без изменения inbound/routing/генерации ссылок.
    """
    h2 = _ensure_h2_state()

    # Если параметры не переданы — берём из первой активной exit_node
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

    # Находим сохранённый SHA256-отпечаток сертификата этой exit-ноды —
    # нужен для pinnedPeerCertSha256 (allowInsecure в Xray-core больше нет).
    cert_sha256 = ""
    for n in h2.get("exit_nodes", []):
        if n.get("ip") == exit_ip:
            cert_sha256 = n.get("cert_sha256", "")
            break

    cfg = _load_xray_config()
    if cfg is None:
        error("Xray config.json не найден")
        return False

    new_ob = _build_h2_outbound(exit_ip, exit_port, auth_password,
                                 cert_sha256=cert_sha256)

    idx = _find_proxy_outbound_idx(cfg)
    if idx >= 0:
        # Сохраняем старый outbound в state для возможного rollback
        old_ob = cfg["outbounds"][idx]
        h2["_prev_outbound"] = old_ob
        cfg["outbounds"][idx] = new_ob
        info(f"Заменяю outbound[{idx}] (тег=proxy) на Hysteria2")
    else:
        cfg.setdefault("outbounds", []).insert(0, new_ob)
        info("Добавляю новый Hysteria2 outbound")

    # BUGFIX: без этого catch-all routing-правило продолжало указывать на
    # "direct"/"chain-exit", и новый outbound "proxy" никогда не использовался —
    # весь трафик уходил с Entry-ноды напрямую, минуя Exit. Переключаем
    # catch-all правило на наш тег и запоминаем предыдущий для отката.
    changed, prev_tag = _patch_routing_to_proxy(cfg, tag="proxy")
    if changed:
        h2["_prev_routing_tag"] = prev_tag
        info(f"Routing catch-all переключён: {prev_tag} → proxy")
    elif prev_tag:
        info("Routing catch-all уже указывает на proxy — пропускаю")
    else:
        warn("Не найдено catch-all routing-правило (network: tcp,udp) — "
             "проверьте config.json вручную, Hysteria2-outbound может быть не задействован!")

    if not _save_xray_config(cfg):
        return False

    _xray_restart()

    h2["transport_only"] = False
    h2["active_transport"] = "hysteria2"
    _save_h2_state(h2)

    success(f"Транспорт Hysteria2 активирован → {exit_ip}:{exit_port}")
    _tg_h2_event("h2_switch", f"Транспорт → H2 ({exit_ip}:{exit_port})")
    log_to_file("INFO", f"H2 transport applied: {exit_ip}:{exit_port}")
    return True


def h2_transport_remove() -> bool:
    """
    Откатывает Hysteria2 outbound. Если был сохранён prev_outbound — восстанавливает,
    иначе удаляет H2 outbound (Xray вернётся к следующему outbound в списке).
    """
    h2 = _load_h2_state()
    cfg = _load_xray_config()
    if cfg is None:
        return False

    prev_ob = h2.pop("_prev_outbound", None)
    prev_routing_tag = h2.pop("_prev_routing_tag", None)
    idx = _find_proxy_outbound_idx(cfg)

    if idx >= 0:
        if prev_ob:
            cfg["outbounds"][idx] = prev_ob
            info("Восстановлен предыдущий outbound (AWG/VLESS)")
        else:
            cfg["outbounds"].pop(idx)
            info("Hysteria2 outbound удалён")

    # BUGFIX: откатываем catch-all routing-правило обратно на тег,
    # который был до включения H2 (обычно "direct" или "chain-exit"),
    # иначе после удаления outbound "proxy" весь трафик уйдёт в blackhole/EOF.
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
    success("Транспорт H2 отключён")
    _tg_h2_event("h2_switch", "Транспорт → AWG/VLESS")
    return True


def h2_transport_status() -> dict:
    """Возвращает информацию о текущем активном транспорте."""
    h2 = _load_h2_state()
    cfg = _load_xray_config()
    active = "unknown"
    exit_ip = ""
    exit_port = 0

    if cfg:
        idx = _find_proxy_outbound_idx(cfg)
        if idx >= 0:
            ob = cfg["outbounds"][idx]
            proto = ob.get("protocol", "")
            # ВАЖНО: правильное имя протокола в Xray-core — "hysteria"
            # (не "hysteria2"), см. _build_h2_outbound(). Раньше эта проверка
            # сверялась со старым (ошибочным) именем и никогда не срабатывала.
            if proto == "hysteria":
                active = "hysteria2"
                settings = ob.get("settings", {})
                exit_ip   = settings.get("address", "")
                exit_port = settings.get("port", 0)
            elif proto in ("vless", "vmess", "freedom"):
                active = proto
            else:
                active = proto

    return {
        "active_transport": active,
        "exit_ip":   exit_ip,
        "exit_port": exit_port,
        "h2_nodes":  len(h2.get("exit_nodes", [])),
    }


def h2_select_transport() -> None:
    """
    Интерактивный выбор транспорта: AWG / Hysteria2 / Оба (с весами балансировщика).
    Вызывается из do_hysteria2_menu().
    """
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
        status_extra = f"  │  {DIM}Exit: {exit_ip}:{exit_prt}{NC}" if active == "hysteria2" and exit_ip else ""
        _box_row(f"  Транспорт: {col}{active}{NC}{status_extra}  │  H2 нод: {CYAN}{n_nodes}{NC}")
        _box_sep()
        _box_row()
        _box_item("1", f"AWG (AmneziaWG)         {DIM}Вернуть на AWG/VLESS транспорт{NC}")
        _box_item("2", f"Hysteria2 (QUIC/UDP)    {DIM}Переключить outbound на H2{NC}")
        _box_item("3", f"Оба (AWG + H2)          {DIM}Балансировка по весам{NC}")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "Q" or ch == "":
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


"""
ПРИМЕР ВЫЗОВА из _core.py:
    from vless_installer.modules.hysteria2_transport import (
        h2_transport_apply, h2_transport_remove, h2_select_transport,
    )

    # Включить H2 транспорт:
    h2_transport_apply()          # берёт ноду из state.json

    # Явно:
    h2_transport_apply(exit_ip="1.2.3.4", exit_port=443, auth_password="secret")

    # Откатить:
    h2_transport_remove()

    # Интерактивный выбор:
    h2_select_transport()
"""
