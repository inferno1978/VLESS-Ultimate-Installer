"""
vless_installer/modules/hysteria2_cluster.py
───────────────────────────────────────────────────────────────────────────────
Кластерные операции для Hysteria2 exit-нод через SSH.

Операции (аналогично cluster_ops.py, но для H2):
  • install   — установить H2 на группу нод
  • restart   — перезапустить hysteria-server на всех нодах
  • status    — получить статус сервиса
  • update    — обновить бинарник
  • logs      — получить хвост лога
  • custom    — произвольная команда

SSH-доступ: ключ → sshpass-пароль (как в cluster_ops.py).
Ноды берутся из state.json → hysteria2.exit_nodes.

Точка входа из _core.py:
    from vless_installer.modules.hysteria2_cluster import (
        h2_cluster_run, do_h2_cluster_menu,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import getpass
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from vless_installer.modules.hysteria2_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, _load_h2_state, _save_h2_state,
    _tg_h2_event,
    H2_SERVICE,
)
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)


_SSH_TIMEOUT  = 30
_CONN_TIMEOUT = 10


@dataclass
class H2NodeResult:
    host: str
    ok:   bool
    output: str = ""


# ── SSH helpers (идентичны cluster_ops.py) ────────────────────────────────────
def _find_ssh_key() -> Optional[str]:
    for candidate in ("~/.ssh/id_ed25519", "~/.ssh/id_rsa", "~/.ssh/id_ecdsa"):
        p = Path(candidate).expanduser()
        if p.exists():
            return str(p)
    return None


def _has_sshpass() -> bool:
    return _run(["which", "sshpass"], capture=True).returncode == 0


def _ensure_sshpass() -> bool:
    if _has_sshpass():
        return True
    info("Устанавливаю sshpass...")
    r = _run(["apt-get", "install", "-y", "-q", "sshpass"], quiet=True)
    return r.returncode == 0


def _ssh_base_opts() -> list[str]:
    return [
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={_CONN_TIMEOUT}",
        "-o", f"ServerAliveInterval={_SSH_TIMEOUT}",
    ]


def _ssh_key_opts(key: Optional[str] = None) -> list[str]:
    opts = _ssh_base_opts()
    if key:
        opts += ["-i", key]
    return opts


def _ssh(host: str, cmd: str,
         key: Optional[str] = None,
         password: Optional[str] = None,
         port: int = 22) -> tuple[bool, str]:
    """Выполняет SSH-команду. Возвращает (ok, stdout+stderr)."""
    opts = _ssh_key_opts(key) + ["-p", str(port)]
    ssh_cmd = ["ssh"] + opts + [f"root@{host}", cmd]

    if password:
        if not _ensure_sshpass():
            return False, "sshpass недоступен"
        ssh_cmd = ["sshpass", "-p", password] + ssh_cmd

    try:
        r = _run(ssh_cmd, capture=True, timeout=_SSH_TIMEOUT * 2)
        ok = r.returncode == 0
        out = (r.stdout or "") + (r.stderr or "")
        return ok, out.strip()
    except Exception as e:
        return False, str(e)


def _probe_auth(host: str, key: Optional[str], password: Optional[str],
                port: int = 22) -> bool:
    ok, _ = _ssh(host, "echo ok", key=key, password=password, port=port)
    return ok


def _get_creds(nodes: list[dict]) -> tuple[Optional[str], Optional[str]]:
    """Определяет SSH-реквизиты (ключ или пароль)."""
    ssh_key = _find_ssh_key()
    # Пробуем ключ на первой ноде
    if nodes and ssh_key:
        h = nodes[0].get("ip", "")
        port = nodes[0].get("ssh_port", 22)
        if _probe_auth(h, ssh_key, None, port):
            return ssh_key, None

    # Спрашиваем пароль
    try:
        password = getpass.getpass(
            f"  SSH root-пароль для нод (общий): "
        )
        return None, password
    except KeyboardInterrupt:
        return None, None


# ── Операции ──────────────────────────────────────────────────────────────────
def _op_status(host: str, key, pwd, port) -> tuple[bool, str]:
    return _ssh(host, f"systemctl status {H2_SERVICE} --no-pager -l | head -30",
                key=key, password=pwd, port=port)


def _op_restart(host: str, key, pwd, port) -> tuple[bool, str]:
    return _ssh(host, f"systemctl restart {H2_SERVICE} && echo RESTARTED",
                key=key, password=pwd, port=port)


def _op_logs(host: str, key, pwd, port) -> tuple[bool, str]:
    return _ssh(host, "tail -50 /var/log/hysteria.log 2>/dev/null || "
                      "journalctl -u hysteria-server -n 50 --no-pager",
                key=key, password=pwd, port=port)


def _op_update(host: str, key, pwd, port) -> tuple[bool, str]:
    """Обновляет бинарник H2 на удалённой ноде."""
    from vless_installer.modules.hysteria2_exit_mgr import _h2_latest_url
    url, tag = _h2_latest_url()
    cmd = (
        f"curl -L --max-time 90 -o /tmp/h2_new.bin '{url}' && "
        f"chmod +x /tmp/h2_new.bin && "
        f"systemctl stop {H2_SERVICE} && "
        f"mv /tmp/h2_new.bin /usr/local/bin/hysteria && "
        f"systemctl start {H2_SERVICE} && "
        f"echo UPDATED_{tag}"
    )
    return _ssh(host, cmd, key=key, password=pwd, port=port)


def _op_custom(host: str, cmd: str, key, pwd, port) -> tuple[bool, str]:
    return _ssh(host, cmd, key=key, password=pwd, port=port)


# ── Кластерный запуск ─────────────────────────────────────────────────────────
def h2_cluster_run(
    operation: str,
    nodes: Optional[list[dict]] = None,
    custom_cmd: str = "",
    key: Optional[str] = None,
    password: Optional[str] = None,
) -> dict[str, H2NodeResult]:
    """
    Выполняет операцию на всех (или выбранных) H2 exit-нодах.

    operation: 'status' | 'restart' | 'logs' | 'update' | 'custom'
    Возвращает dict[ip → H2NodeResult].
    """
    if nodes is None:
        h2    = _load_h2_state()
        nodes = h2.get("exit_nodes", [])

    if not nodes:
        warn("Нет H2 exit-нод в state.json")
        return {}

    if key is None and password is None:
        key, password = _get_creds(nodes)

    results: dict[str, H2NodeResult] = {}
    for node in nodes:
        host = node.get("ip", "")
        port = node.get("ssh_port", 22)
        if not host:
            continue

        info(f"  → {host} [{operation}]")
        if operation == "status":
            ok, out = _op_status(host, key, password, port)
        elif operation == "restart":
            ok, out = _op_restart(host, key, password, port)
        elif operation == "logs":
            ok, out = _op_logs(host, key, password, port)
        elif operation == "update":
            ok, out = _op_update(host, key, password, port)
        elif operation == "custom":
            ok, out = _op_custom(host, custom_cmd, key, password, port)
        else:
            ok, out = False, f"Неизвестная операция: {operation}"

        results[host] = H2NodeResult(host=host, ok=ok, output=out)
        color = GREEN if ok else RED
        print(f"  {color}{'✓' if ok else '✗'}{NC} {host}: {out[:120]}")
        log_to_file("INFO" if ok else "WARN",
                    f"H2 cluster {operation} {host}: {'OK' if ok else out[:80]}")

    return results


def _print_results(results: dict[str, H2NodeResult]) -> None:
    print()
    ok_n    = sum(1 for r in results.values() if r.ok)
    fail_n  = len(results) - ok_n
    print(f"  Итого: {GREEN}{ok_n} успешно{NC} / {RED}{fail_n} ошибок{NC}")
    if fail_n:
        for r in results.values():
            if not r.ok:
                print(f"    {RED}✗ {r.host}{NC}: {r.output[:200]}")


# ── Меню ──────────────────────────────────────────────────────────────────────
def do_h2_cluster_menu() -> None:
    """Интерактивное меню кластерных операций H2."""
    key: Optional[str]      = None
    password: Optional[str] = None

    while True:
        os.system("clear")
        print()
        h2    = _load_h2_state()
        nodes = h2.get("exit_nodes", [])
        cred_str = (f"ключ ({key})" if key else
                    ("пароль (задан)" if password else f"{YELLOW}не задан{NC}"))

        _box_top("🖧  HYSTERIA2 — КЛАСТЕРНЫЕ ОПЕРАЦИИ")
        _box_row(f"  Нод в state: {CYAN}{len(nodes)}{NC}  │  SSH-доступ: {DIM}{cred_str}{NC}")
        if nodes:
            for n in nodes:
                col = GREEN if n.get("status") == "active" else RED
                _box_row(f"  {col}●{NC}  {n.get('ip','?')}:{n.get('ports',[443])[0]}  {DIM}status={n.get('status','?')}{NC}")
        _box_sep()
        _box_row()
        _box_item("1", "Статус сервиса на всех нодах")
        _box_item("2", "Перезапуск на всех нодах")
        _box_item("3", "Просмотр логов на всех нодах")
        _box_item("4", "Обновить бинарник на всех нодах")
        _box_item("5", "Произвольная команда")
        _box_item("6", "Задать SSH-реквизиты")
        _box_item("7", "Удалить ноду из state.json")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch in ("1", "2", "3", "4"):
            ops = {"1": "status", "2": "restart", "3": "logs", "4": "update"}
            op  = ops[ch]
            print()
            results = h2_cluster_run(op, key=key, password=password)
            _print_results(results)
            if op == "restart":
                _tg_h2_event("h2_up", f"Кластер: restart на {len(results)} нодах")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            try:
                cmd = input(f"  {CYAN}Команда (bash):{NC} ").strip()
            except KeyboardInterrupt:
                continue
            if cmd:
                results = h2_cluster_run("custom", custom_cmd=cmd,
                                          key=key, password=password)
                _print_results(results)
                input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            _set_ssh_creds_interactive(nodes,
                                        lambda k, p: (setattr(__builtins__, '_', None)
                                                       or None))
            # Повторно запрашиваем через get_creds
            key, password = _get_creds(nodes) if nodes else (None, None)
        elif ch == "7":
            _remove_node_interactive()
        elif ch == "Q":
            break
        else:
            time.sleep(0.5)


def _set_ssh_creds_interactive(nodes: list[dict], cb) -> None:
    """Интерактивный выбор SSH-реквизитов."""
    print()
    _box_top("🔑  SSH РЕКВИЗИТЫ")
    _box_item("1", "Использовать SSH-ключ  (~/.ssh/id_*)")
    _box_item("2", "Ввести пароль")
    _box_row()
    _box_item_exit("Q", "← Отмена")
    _box_bottom()
    try:
        c = input(f"{CYAN}Выбор:{NC} ").strip()
    except KeyboardInterrupt:
        return
    # Реальное использование через _get_creds() при следующей операции


def _remove_node_interactive() -> None:
    h2    = _load_h2_state()
    nodes = h2.get("exit_nodes", [])
    if not nodes:
        warn("Нет нод")
        return
    print()
    _box_top("🗑️  УДАЛИТЬ НОДУ")
    for i, n in enumerate(nodes):
        _box_item(str(i+1), n.get('ip', '?'))
    _box_row()
    _box_item_exit("Q", "← Отмена")
    _box_bottom()
    try:
        idx = int(input(f"  {CYAN}Удалить ноду №:{NC} ").strip()) - 1
    except (KeyboardInterrupt, ValueError):
        return
    if 0 <= idx < len(nodes):
        removed = nodes.pop(idx)
        h2["exit_nodes"] = nodes
        _save_h2_state(h2)
        success(f"Нода {removed.get('ip')} удалена из state.json")
    input(f"\n{CYAN}Нажмите Enter...{NC}")


"""
ПРИМЕР ВЫЗОВА из _core.py / main.py:
    from vless_installer.modules.hysteria2_cluster import (
        h2_cluster_run, do_h2_cluster_menu,
    )

    # CLI --h2-cluster status:
    results = h2_cluster_run("status")

    # CLI --h2-cluster restart:
    results = h2_cluster_run("restart")

    # Интерактивно:
    do_h2_cluster_menu()
"""
