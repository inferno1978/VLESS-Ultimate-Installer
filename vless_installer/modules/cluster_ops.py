"""
vless_installer/modules/cluster_ops.py
───────────────────────────────────────────────────────────────────────────────
Мультисерверное управление Exit Nodes из Entry Node по SSH.

Зачем: Режим B поддерживает до 10 exit-нод, но для управления каждой нодой
нужно заходить по SSH отдельно. Этот модуль позволяет с Entry Node применять
изменения на всех Exit Nodes одной командой.

Операции:
  • Диагностика  — systemctl status xray + xray -test
  • Перезапуск   — systemctl restart xray
  • Обновление   — скачать latest Xray-core с GitHub + atomically заменить
  • Ротация UUID — новый UUID → конфиг на Exit Node → restart
  • Произвольная команда

SSH-доступ по ключу (ключи есть в инфраструктуре при каскадной установке).
Ноды читаются из /var/lib/xray-installer/state.json → chain_nodes.

Точка входа из _core.py:
    from vless_installer.modules.cluster_ops import do_cluster_menu
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import uuid as _uuid_mod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m', NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'], _C['BOLD'], _C['DIM'], _C['NC'],
)

# ── Константы ─────────────────────────────────────────────────────────────────
_STATE_FILE  = Path('/var/lib/xray-installer/state.json')
_SSH_TIMEOUT = 30
_CONN_TIMEOUT = 10


# ── Типы данных ───────────────────────────────────────────────────────────────
@dataclass
class NodeResult:
    host: str
    ok: bool
    output: str = ''
    error: str = ''
    duration: float = 0.0


# ── SSH транспорт ─────────────────────────────────────────────────────────────
def _find_ssh_key() -> Optional[str]:
    for cand in ('~/.ssh/id_ed25519', '~/.ssh/id_rsa', '~/.ssh/id_ecdsa'):
        p = Path(cand).expanduser()
        if p.exists():
            return str(p)
    return None


def _ssh_opts(ssh_key: Optional[str] = None) -> list[str]:
    opts = [
        'ssh',
        '-o', 'StrictHostKeyChecking=no',
        '-o', f'ConnectTimeout={_CONN_TIMEOUT}',
        '-o', 'LogLevel=ERROR',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'BatchMode=yes',
    ]
    key = ssh_key or _find_ssh_key()
    if key:
        opts += ['-i', key]
    return opts


def _ssh(host: str, cmd: str, ssh_key: Optional[str] = None,
         timeout: int = _SSH_TIMEOUT) -> tuple[bool, str, str]:
    """Выполняет команду на хосте. Возвращает (ok, stdout, stderr)."""
    full = [*_ssh_opts(ssh_key), f'root@{host}', cmd]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, '', f'timeout {timeout}s'
    except FileNotFoundError:
        return False, '', 'ssh не найден в PATH'
    except Exception as e:
        return False, '', str(e)


# ── Операции ──────────────────────────────────────────────────────────────────
def op_diagnostics(host: str, ssh_key: Optional[str] = None) -> NodeResult:
    """Статус Xray + xray -test на удалённой ноде."""
    t0 = time.monotonic()
    lines = []
    ok_overall = True
    for cmd in (
        'systemctl is-active xray',
        'xray version 2>/dev/null | head -1',
        '/usr/local/bin/xray run -test -config /etc/xray/config.json 2>&1 | tail -2',
        'journalctl -u xray -n 3 --no-pager 2>/dev/null',
    ):
        ok, out, err = _ssh(host, cmd, ssh_key, timeout=90)
        if out:
            lines.append(out)
        if cmd.startswith('systemctl') and out != 'active':
            ok_overall = False
    return NodeResult(host=host, ok=ok_overall,
                      output='\n'.join(lines), duration=time.monotonic() - t0)


def op_restart(host: str, ssh_key: Optional[str] = None) -> NodeResult:
    """Перезапускает Xray и ждёт active."""
    t0 = time.monotonic()
    ok, out, err = _ssh(
        host,
        'systemctl restart xray && sleep 5 && systemctl is-active xray',
        ssh_key, timeout=60,
    )
    return NodeResult(host=host, ok=ok and 'active' in (out or ''),
                      output=out, error=err, duration=time.monotonic() - t0)


def op_update_xray(host: str, ssh_key: Optional[str] = None) -> NodeResult:
    """Скачивает и устанавливает latest Xray-core, откатывает при неудаче."""
    t0 = time.monotonic()
    script = (
        "bash -c '"
        "set -e; "
        "BIN=/usr/local/bin/xray; "
        "ARCH=$(uname -m); "
        "case $ARCH in x86_64) A=64;; aarch64) A=arm64-v8a;; armv7l) A=arm32-v7a;; "
        "  *) echo unsupported arch $ARCH; exit 1;; esac; "
        "LATEST=$(curl -sf https://api.github.com/repos/XTLS/Xray-core/releases/latest "
        "  | python3 -c \"import sys,json; print(json.load(sys.stdin)[\\\"tag_name\\\"])\"); "
        "[[ -z $LATEST ]] && { echo cannot fetch latest version; exit 1; }; "
        "CURRENT=$($BIN version 2>/dev/null | awk \"{print \\$2}\" | head -1); "
        "echo current=$CURRENT latest=$LATEST; "
        "[[ \"v$CURRENT\" == \"$LATEST\" ]] && { echo already up to date; exit 0; }; "
        "TMP=$(mktemp -d); "
        "URL=https://github.com/XTLS/Xray-core/releases/download/$LATEST/Xray-linux-$A.zip; "
        "curl -sL $URL -o $TMP/xray.zip; "
        "cd $TMP && unzip -q xray.zip; "
        "cp $BIN ${BIN}.bak; "
        "cp xray $BIN && chmod +x $BIN; "
        "systemctl restart xray && sleep 5; "
        "systemctl is-active xray || { cp ${BIN}.bak $BIN; systemctl restart xray; "
        "  echo ROLLBACK; exit 1; }; "
        "echo updated to $LATEST; "
        "rm -rf $TMP; "
        "'"
    )
    ok, out, err = _ssh(host, script, ssh_key, timeout=180)
    return NodeResult(host=host, ok=ok, output=out, error=err,
                      duration=time.monotonic() - t0)


def op_rotate_uuid(host: str, ssh_key: Optional[str] = None) -> NodeResult:
    """
    Ротирует UUID клиентов в конфиге на Exit Node.
    Возвращает новый UUID в output для обновления Entry Node.
    """
    t0 = time.monotonic()
    new_uuid = str(_uuid_mod.uuid4())
    # Заменяем UUID во всех inbounds[*].settings.clients[*].id
    py = (
        f"python3 -c \""
        f"import json; p='/etc/xray/config.json'; c=json.load(open(p)); "
        f"[s.update({{'id':'{new_uuid}'}}) "
        f" for ib in c.get('inbounds',[]) "
        f" for s in ib.get('settings',{{}}).get('clients',[])]; "
        f"open(p,'w').write(json.dumps(c,indent=2)); "
        f"print('uuid_updated:{new_uuid}')"
        f"\""
    )
    ok1, out1, err1 = _ssh(host, py, ssh_key, timeout=30)
    if not ok1 or 'uuid_updated' not in out1:
        return NodeResult(host=host, ok=False, output=out1,
                          error=f'UUID замена не удалась: {err1[:200]}',
                          duration=time.monotonic() - t0)
    ok2, out2, err2 = _ssh(
        host,
        'systemctl restart xray && sleep 5 && systemctl is-active xray',
        ssh_key, timeout=60,
    )
    return NodeResult(host=host, ok=ok2 and 'active' in (out2 or ''),
                      output=f'new_uuid={new_uuid}\n{out2}',
                      error=err2, duration=time.monotonic() - t0)


def op_custom(host: str, cmd: str,
              ssh_key: Optional[str] = None) -> NodeResult:
    """Произвольная команда на ноде."""
    t0 = time.monotonic()
    ok, out, err = _ssh(host, cmd, ssh_key, timeout=120)
    return NodeResult(host=host, ok=ok, output=out, error=err,
                      duration=time.monotonic() - t0)


# ── Параллельное применение ───────────────────────────────────────────────────
def cluster_run(
    nodes: list[dict],
    op_fn: Callable,
    parallel: bool = True,
    **kwargs,
) -> dict[str, NodeResult]:
    """
    Применяет op_fn(host, ssh_key, **kwargs) ко всем нодам.
    parallel=True — ThreadPoolExecutor (макс 5 воркеров).
    Возвращает {host: NodeResult}.
    """
    results: dict[str, NodeResult] = {}
    if parallel:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        futures: dict = {}
        with ThreadPoolExecutor(max_workers=min(len(nodes), 5)) as pool:
            for nd in nodes:
                h = nd.get('host', '')
                if not h:
                    continue
                key = nd.get('ssh_key') or _find_ssh_key()
                futures[pool.submit(op_fn, h, key, **kwargs)] = h
            for fut in as_completed(futures):
                h = futures[fut]
                try:
                    results[h] = fut.result()
                except Exception as e:
                    results[h] = NodeResult(host=h, ok=False, error=str(e))
    else:
        for nd in nodes:
            h = nd.get('host', '')
            if not h:
                continue
            key = nd.get('ssh_key') or _find_ssh_key()
            try:
                results[h] = op_fn(h, key, **kwargs)
            except Exception as e:
                results[h] = NodeResult(host=h, ok=False, error=str(e))
    return results


# ── Загрузка нод из state.json ────────────────────────────────────────────────
def load_exit_nodes() -> list[dict]:
    """
    Читает Exit Nodes из state.json.
    Поддерживает chain_nodes (новый) и chain_exit_host (legacy).
    """
    try:
        state = json.loads(_STATE_FILE.read_text())
    except Exception as e:
        print(f'  {RED}Не удалось прочитать state.json: {e}{NC}')
        return []
    if 'chain_nodes' in state and isinstance(state['chain_nodes'], list):
        return [n for n in state['chain_nodes'] if n.get('host')]
    host = state.get('chain_exit_host', '')
    if host:
        return [{'host': host, 'port': state.get('chain_exit_port', 443)}]
    return []


# ── Вывод результатов ─────────────────────────────────────────────────────────
def _print_results(results: dict[str, NodeResult], title: str = "РЕЗУЛЬТАТ") -> None:
    from vless_installer._core import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_item,
    )
    ok_n  = sum(1 for r in results.values() if r.ok)
    all_n = len(results)
    color = GREEN if ok_n == all_n else (YELLOW if ok_n > 0 else RED)

    _box_top(f"📊  {title}")
    _box_row(f"  {color}Итог: {ok_n}/{all_n} нод ОК{NC}")
    _box_sep()
    for host, res in sorted(results.items()):
        icon = f'{GREEN}✓{NC}' if res.ok else f'{RED}✗{NC}'
        _box_row(f"  {icon} {BOLD}{host}{NC}  {DIM}({res.duration:.1f}s){NC}")
        for line in (res.output or '').splitlines()[:6]:
            _box_row(f"    {DIM}{line[:68]}{NC}")
        if res.error:
            _box_row(f"    {RED}{res.error[:70]}{NC}")
    _box_bottom()


# ── Проверка SSH-доступа ──────────────────────────────────────────────────────
def _check_ssh(host: str, ssh_key: Optional[str] = None) -> tuple[bool, str]:
    ok, out, err = _ssh(host, 'echo ok', ssh_key, timeout=15)
    if ok and 'ok' in out:
        return True, ''
    return False, err or 'нет ответа'


# ── Публичный API — интерактивное меню ───────────────────────────────────────
def do_cluster_menu() -> None:
    """Интерактивное меню мультисерверного управления Exit Nodes."""
    import os
    from vless_installer._core import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back,
    )
    while True:
        os.system('clear')
        nodes = load_exit_nodes()

        _box_top("🌐  КЛАСТЕР — управление Exit Nodes")
        if nodes:
            _box_row(f"  Exit Nodes ({len(nodes)}):")
            for i, nd in enumerate(nodes, 1):
                _box_row(f"    {i}. {nd.get('host','?')}:{nd.get('port',443)}")
        else:
            _box_row(f"  {YELLOW}Нет Exit Nodes в state.json.{NC}")
            _box_row(f"  {DIM}Добавьте каскадный Режим B для появления нод.{NC}")
        _box_sep()
        _box_item("1", "Диагностика всех нод")
        _box_item("2", "Перезапуск Xray на всех нодах")
        _box_item("3", "Обновление Xray-core на всех нодах")
        _box_item("4", "Ротация UUID на всех нодах")
        _box_item("5", "Произвольная команда")
        _box_item("6", "Проверить SSH-доступ")
        _box_back()
        _box_bottom()

        try:
            ch = input(f'{CYAN}Выбор:{NC} ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if not nodes and ch not in ('q', ''):
            from vless_installer._core import _box_top, _box_row, _box_bottom
            _box_top("⚠️   НЕТ НОД")
            _box_row(f"  {YELLOW}Нет Exit Nodes — нечего делать{NC}")
            _box_bottom()
            time.sleep(1)
            continue

        if ch == '1':
            from vless_installer._core import _box_top, _box_row, _box_bottom
            _box_top(f"🔍  ДИАГНОСТИКА — {len(nodes)} нод")
            _box_row(f"  {CYAN}Выполняется...{NC}")
            _box_bottom()
            _print_results(cluster_run(nodes, op_diagnostics), "ДИАГНОСТИКА")

        elif ch == '2':
            from vless_installer._core import _box_top, _box_row, _box_bottom
            _box_top(f"🔄  ПЕРЕЗАПУСК XRAY — {len(nodes)} нод")
            _box_row(f"  Перезапустить Xray на всех нодах?")
            _box_bottom()
            try:
                ans = input(f'{CYAN}[y/N]:{NC} ').strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if ans in ('y', 'yes', 'д', 'да'):
                _print_results(cluster_run(nodes, op_restart), "ПЕРЕЗАПУСК")

        elif ch == '3':
            from vless_installer._core import _box_top, _box_row, _box_bottom
            _box_top(f"⬆️   ОБНОВЛЕНИЕ XRAY-CORE — {len(nodes)} нод")
            _box_row(f"  {YELLOW}Может занять 2–3 минуты на ноду.{NC}")
            _box_row(f"  Обновить Xray-core на всех нодах?")
            _box_bottom()
            try:
                ans = input(f'{CYAN}[y/N]:{NC} ').strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if ans in ('y', 'yes', 'д', 'да'):
                _print_results(cluster_run(nodes, op_update_xray), "ОБНОВЛЕНИЕ")

        elif ch == '4':
            from vless_installer._core import _box_top, _box_row, _box_bottom
            _box_top(f"🔑  РОТАЦИЯ UUID — {len(nodes)} нод")
            _box_row(f"  {YELLOW}⚠  После ротации обновите конфиг Entry Node вручную!{NC}")
            _box_row(f"  Новые UUID будут выведены в результатах.")
            _box_bottom()
            try:
                ans = input(f'{CYAN}[y/N]:{NC} ').strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if ans in ('y', 'yes', 'д', 'да'):
                _print_results(cluster_run(nodes, op_rotate_uuid, parallel=False), "РОТАЦИЯ UUID")
                from vless_installer._core import _box_top, _box_row, _box_bottom
                _box_top("ℹ️   ВАЖНО")
                _box_row(f"  {YELLOW}Скопируйте UUID выше и обновите конфиг Entry Node.{NC}")
                _box_bottom()

        elif ch == '5':
            from vless_installer._core import _box_top, _box_row, _box_bottom
            _box_top("💬  ПРОИЗВОЛЬНАЯ КОМАНДА")
            _box_row(f"  Введите команду для выполнения на всех нодах:")
            _box_bottom()
            try:
                cmd = input(f'{CYAN}Команда:{NC} ').strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if cmd:
                _print_results(cluster_run(nodes, op_custom, cmd=cmd), f"КОМАНДА: {cmd[:40]}")

        elif ch == '6':
            from vless_installer._core import _box_top, _box_row, _box_bottom
            key = _find_ssh_key()
            _box_top(f"🔐  ПРОВЕРКА SSH — {len(nodes)} нод")
            for nd in nodes:
                h = nd.get('host', '')
                ok, reason = _check_ssh(h, key)
                icon = f'{GREEN}✓{NC}' if ok else f'{RED}✗{NC}'
                extra = f'  {DIM}{reason}{NC}' if not ok else f'  {GREEN}OK{NC}'
                _box_row(f"  {icon} {BOLD}{h}{NC}{extra}")
            _box_bottom()

        elif ch in ('q', ''):
            break

        if ch not in ('q', ''):
            try:
                input(f'{CYAN}Нажмите Enter...{NC}')
            except (EOFError, KeyboardInterrupt):
                pass
