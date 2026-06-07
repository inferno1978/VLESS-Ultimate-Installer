"""
user_fp_manager.py
==================
Смена TLS Fingerprint из меню «Управление пользователями» и Telegram-бота.

Принципы
--------
* Одна функция — один файл: вся логика здесь, не в _core.py.
* Безопасность: смена FP проходит через валидацию Xray (``run -test``),
  только затем xray перезапускается.  Конфиг откатывается при ошибке.
* Универсальность: поддерживаются все режимы установки —
  A (single), B (chain/entry), B-Multi, xHTTP, REALITY.
  В режиме B меняется fingerprint как в entry-конфиге (PARAM_FINGERPRINT),
  так и, при необходимости, в chain_nodes[*].fp через state.json.
* Публичное API:
    do_change_fp_interactive()  — интерактивный выбор (вызов из меню)
    apply_fp(new_fp)            — применить без диалога (вызов из TG-бота)
    current_fp()                → str  — текущий FP из state.json/config.json

Интеграция в _core.py
---------------------
Добавить пункт «F» в do_unified_user_manager() и do_manage_users():

    elif ch == "f":
        from vless_installer.modules.user_fp_manager import do_change_fp_interactive
        do_change_fp_interactive()

Интеграция в tg_bot.py (_generate_bot_script)
----------------------------------------------
Бот-скрипт расширяется новыми командами /fp и /setfp через
patch_tg_bot_script(script_text) → str.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

__all__ = [
    "current_fp",
    "apply_fp",
    "do_change_fp_interactive",
    "patch_tg_bot_script",
    "TG_FP_COMMANDS_BLOCK",
]

# ---------------------------------------------------------------------------
#  Пути (должны совпадать с _core.py)
# ---------------------------------------------------------------------------
_STATE_FILE  = Path("/var/lib/xray-installer/state.json")
_CONFIG_DIRS = [
    Path("/etc/xray"),
    Path("/usr/local/etc/xray"),
]
_XRAY_BIN    = Path("/usr/local/bin/xray")

# ---------------------------------------------------------------------------
#  Lazy-импорт из _core.py (избегаем циклических зависимостей на верхнем уровне)
# ---------------------------------------------------------------------------

def _core_imports():
    """Возвращает словарь нужных символов из _core.py."""
    from vless_installer._core import (  # type: ignore[import]
        _box_top, _box_item, _box_bottom, _box_row, _box_sep,
        success, warn, info,
        CYAN, NC, GREEN, YELLOW, RED, BOLD, DIM, BLUE,
    )
    from vless_installer.modules.fingerprint_manager import XRAY_FP_LIST
    return dict(
        _box_top=_box_top, _box_item=_box_item, _box_bottom=_box_bottom,
        _box_row=_box_row, _box_sep=_box_sep,
        success=success, warn=warn, info=info,
        CYAN=CYAN, NC=NC, GREEN=GREEN, YELLOW=YELLOW, RED=RED,
        BOLD=BOLD, DIM=DIM, BLUE=BLUE,
        FP_LIST=XRAY_FP_LIST,
    )


# ---------------------------------------------------------------------------
#  Вспомогательные функции (без цветов — пригодны внутри бот-скрипта)
# ---------------------------------------------------------------------------

def _config_paths() -> list[Path]:
    """Возвращает все существующие config.json."""
    paths = []
    for d in _CONFIG_DIRS:
        p = d / "config.json"
        if p.exists():
            paths.append(p)
    return paths


def current_fp() -> str:
    """
    Текущий fingerprint.
    Приоритет: state.json → первый конфиг.json (realitySettings/tlsSettings) → 'chrome'.
    """
    # 1. state.json
    if _STATE_FILE.exists():
        try:
            st = json.loads(_STATE_FILE.read_text())
            fp = st.get("fingerprint") or ""
            if fp:
                return fp
        except Exception:
            pass

    # 2. config.json — первый outbound
    for cfg_path in _config_paths():
        try:
            cfg = json.loads(cfg_path.read_text())
            for ob in cfg.get("outbounds", []):
                ss = ob.get("streamSettings", {})
                for key in ("realitySettings", "tlsSettings"):
                    fp = ss.get(key, {}).get("fingerprint", "")
                    if fp:
                        return fp
            # Также проверяем inbound (некоторые конфиги ставят там)
            for ib in cfg.get("inbounds", []):
                ss = ib.get("streamSettings", {})
                for key in ("realitySettings", "tlsSettings"):
                    fp = ss.get(key, {}).get("fingerprint", "")
                    if fp:
                        return fp
        except Exception:
            pass

    return "chrome"


def _patch_config_fp(new_fp: str) -> tuple[bool, str]:
    """
    Меняет fingerprint во всех outbound/inbound во всех config.json.
    Возвращает (ok, error_message).
    """
    changed_any = False
    for cfg_path in _config_paths():
        try:
            cfg = json.loads(cfg_path.read_text())
        except Exception as e:
            return False, f"Чтение {cfg_path}: {e}"

        patched = False
        for section in ("outbounds", "inbounds"):
            for block in cfg.get(section, []):
                ss = block.get("streamSettings", {})
                for key in ("realitySettings", "tlsSettings"):
                    if key in ss and "fingerprint" in ss[key]:
                        ss[key]["fingerprint"] = new_fp
                        patched = True

        if patched:
            # Бэкап перед записью
            bak = cfg_path.with_suffix(".json.fp_bak")
            shutil.copy2(cfg_path, bak)
            try:
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                changed_any = True
            except Exception as e:
                # Откат
                shutil.copy2(bak, cfg_path)
                return False, f"Запись {cfg_path}: {e}"
        else:
            # Конфиг не использует realitySettings/tlsSettings — может быть нормой
            # (напр. inbound через Unix-сокет без TLS).  Не считаем ошибкой.
            pass

    return changed_any, ""


def _validate_and_restart() -> tuple[bool, str]:
    """Валидирует первый config.json через xray -test, перезапускает xray."""
    if not _XRAY_BIN.exists():
        return False, "xray не найден"

    cfgs = _config_paths()
    if not cfgs:
        return False, "config.json не найден"

    # Тест
    r = subprocess.run(
        [str(_XRAY_BIN), "run", "-test", "-config", str(cfgs[0])],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return False, (r.stdout + r.stderr).strip()[:300]

    # Перезапуск
    subprocess.run(["systemctl", "restart", "xray"], check=False)
    time.sleep(2)

    # Проверяем что xray поднялся
    r2 = subprocess.run(
        ["systemctl", "is-active", "xray"],
        capture_output=True, text=True,
    )
    if r2.stdout.strip() != "active":
        return False, "xray не запустился после перезапуска"

    return True, ""


def _update_state_fp(new_fp: str) -> None:
    """
    Обновляет fingerprint в state.json — как глобальный, так и в chain_nodes[*].fp.
    Не трогает остальные поля.
    """
    if not _STATE_FILE.exists():
        return
    try:
        st = json.loads(_STATE_FILE.read_text())
        st["fingerprint"] = new_fp

        # Режим B (chain): обновляем fp во всех нодах
        if "chain_nodes" in st and isinstance(st["chain_nodes"], list):
            for node in st["chain_nodes"]:
                if isinstance(node, dict) and "fp" in node:
                    node["fp"] = new_fp
        # Легаси-ключ
        if "chain_exit_fp" in st:
            st["chain_exit_fp"] = new_fp

        _STATE_FILE.write_text(json.dumps(st, indent=2, ensure_ascii=False))
    except Exception:
        pass


def apply_fp(new_fp: str) -> tuple[bool, str]:
    """
    Применить fingerprint `new_fp` без диалога.
    Используется из Telegram-бота и других скриптов.

    Возвращает (ok: bool, message: str).
    """
    from vless_installer.modules.fingerprint_manager import XRAY_FP_LIST
    if new_fp not in XRAY_FP_LIST:
        return False, f"Неизвестный fingerprint: {new_fp!r}"

    ok, err = _patch_config_fp(new_fp)
    if not ok:
        return False, f"Не удалось обновить конфиг: {err}"

    ok2, err2 = _validate_and_restart()
    if not ok2:
        return False, f"Xray не принял конфиг: {err2}"

    _update_state_fp(new_fp)
    return True, f"Fingerprint изменён на {new_fp!r}, Xray перезапущен."


# ---------------------------------------------------------------------------
#  Интерактивное меню (вызывается из do_unified_user_manager / do_manage_users)
# ---------------------------------------------------------------------------

def do_change_fp_interactive() -> None:
    """
    Интерактивная смена TLS Fingerprint.
    Показывает текущий FP, список вариантов, применяет после подтверждения.
    Вызывается из любого меню управления пользователями.
    """
    c = _core_imports()
    _box_top = c["_box_top"]
    _box_item = c["_box_item"]
    _box_bottom = c["_box_bottom"]
    _box_row = c["_box_row"]
    success = c["success"]
    warn = c["warn"]
    info = c["info"]
    CYAN = c["CYAN"]; NC = c["NC"]; GREEN = c["GREEN"]
    YELLOW = c["YELLOW"]; DIM = c["DIM"]; BLUE = c["BLUE"]
    FP_LIST = c["FP_LIST"]

    cur = current_fp()

    print()
    _box_top(f"Смена TLS Fingerprint")
    _box_row(f"  Текущий:  {CYAN}{cur}{NC}")
    _box_row()

    # Определяем режим из state.json для информационного сообщения
    install_mode = "A"
    if _STATE_FILE.exists():
        try:
            install_mode = json.loads(_STATE_FILE.read_text()).get("install_mode", "A")
        except Exception:
            pass

    if install_mode == "B":
        _box_row(f"  {YELLOW}Режим B:{NC} FP будет обновлён в config.json и во всех chain_nodes.")
    else:
        _box_row(f"  Режим A: FP обновляется в config.json.")
    _box_row()

    for i, fp in enumerate(FP_LIST, 1):
        marker = f"  {GREEN}← текущий{NC}" if fp == cur else ""
        _box_item(f"{i}", f"{fp}{marker}")
    _box_row()
    _box_bottom()

    raw = input(
        f"  {CYAN}Выбор (1–{len(FP_LIST)}) или имя, Enter = отмена: {NC}"
    ).strip()

    if not raw:
        info("Отменено.")
        return

    new_fp = ""
    if raw.isdigit() and 1 <= int(raw) <= len(FP_LIST):
        new_fp = FP_LIST[int(raw) - 1]
    elif raw in FP_LIST:
        new_fp = raw
    else:
        warn(f"Некорректный выбор: {raw!r}. Введите номер 1–{len(FP_LIST)} или имя.")
        return

    if new_fp == cur:
        info(f"Fingerprint уже установлен в {cur!r}. Ничего не изменено.")
        return

    print()
    info(f"Применяю fingerprint: {cur} → {new_fp} ...")

    ok, msg = apply_fp(new_fp)
    if ok:
        success(msg)
    else:
        warn(msg)

    input(f"{BLUE}Нажмите Enter...{NC}")


# ---------------------------------------------------------------------------
#  Патч Telegram-бот скрипта
# ---------------------------------------------------------------------------

# Блок кода, который будет вставлен в сгенерированный бот-скрипт.
# Использует двойные фигурные скобки для экранирования в f-string _core.py.
# Обратите внимание: этот блок сам является строковым литералом Python,
# который будет вставлен в строку f''' ... ''' в _generate_bot_script.
# Поэтому он не должен содержать одиночные {, } — только {{ и }}.

TG_FP_COMMANDS_BLOCK: str = r'''
# ── Fingerprint management (injected by user_fp_manager) ─────────────────────

_FP_LIST_BOT = [
    "chrome", "firefox", "safari", "ios", "android", "edge",
    "360", "qq", "random", "randomized", "none",
]

def _fp_apply_via_xray(new_fp):
    """Применяет fingerprint напрямую через xray (без импорта _core)."""
    import shutil as _shutil

    cfg_paths = [
        Path("/etc/xray/config.json"),
        Path("/usr/local/etc/xray/config.json"),
    ]
    state_file = Path("/var/lib/xray-installer/state.json")
    xray_bin   = Path("/usr/local/bin/xray")

    changed = False
    for cfg_path in cfg_paths:
        if not cfg_path.exists():
            continue
        try:
            cfg = json.loads(cfg_path.read_text())
        except Exception:
            continue
        patched = False
        for section in ("outbounds", "inbounds"):
            for block in cfg.get(section, []):
                ss = block.get("streamSettings", {})
                for key in ("realitySettings", "tlsSettings"):
                    if key in ss and "fingerprint" in ss[key]:
                        ss[key]["fingerprint"] = new_fp
                        patched = True
        if patched:
            bak = cfg_path.with_suffix(".json.tgbot_fp_bak")
            _shutil.copy2(cfg_path, bak)
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            changed = True

    if not changed:
        return False, "fingerprint не найден ни в одном config.json"

    # Валидация
    cfg_test = next((str(p) for p in cfg_paths if p.exists()), None)
    if cfg_test and xray_bin.exists():
        r = subprocess.run(
            [str(xray_bin), "run", "-test", "-config", cfg_test],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            # Откат
            for cfg_path in cfg_paths:
                bak = cfg_path.with_suffix(".json.tgbot_fp_bak")
                if bak.exists():
                    _shutil.copy2(bak, cfg_path)
            return False, (r.stdout + r.stderr).strip()[:200]

    # Перезапуск
    subprocess.run(["systemctl", "restart", "xray"], check=False)
    import time as _time
    _time.sleep(2)

    # Обновляем state.json
    if state_file.exists():
        try:
            st = json.loads(state_file.read_text())
            st["fingerprint"] = new_fp
            if "chain_nodes" in st and isinstance(st["chain_nodes"], list):
                for node in st["chain_nodes"]:
                    if isinstance(node, dict) and "fp" in node:
                        node["fp"] = new_fp
            if "chain_exit_fp" in st:
                st["chain_exit_fp"] = new_fp
            state_file.write_text(json.dumps(st, indent=2, ensure_ascii=False))
        except Exception:
            pass

    return True, f"Fingerprint изменён на {new_fp!r}"


def handle_fp(msg):
    """Показывает текущий FP и список доступных."""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    st = _state()
    cur_fp = st.get("fingerprint", "chrome") or "chrome"
    lines = [f"🔑 <b>TLS Fingerprint</b>", f"", f"Текущий: <code>{cur_fp}</code>", ""]
    for i, fp in enumerate(_FP_LIST_BOT, 1):
        mark = " ✅" if fp == cur_fp else ""
        lines.append(f"  {i}. {fp}{mark}")
    lines += ["", "Чтобы сменить: <code>/setfp имя</code>", "Например: <code>/setfp firefox</code>"]
    send(uid, "\n".join(lines))
    _log(f"Admin {uid} requested /fp")


def handle_setfp(msg, args):
    """Меняет TLS Fingerprint."""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    if not args:
        send(uid, "❓ Использование: /setfp &lt;имя&gt;\nПример: <code>/setfp firefox</code>")
        return
    new_fp = args[0].strip().lower()
    if new_fp not in _FP_LIST_BOT:
        fp_list = ", ".join(_FP_LIST_BOT)
        send(uid, f"❌ Неизвестный fingerprint: <code>{new_fp}</code>\n\nДоступные:\n{fp_list}")
        return
    send(uid, f"⏳ Применяю fingerprint <code>{new_fp}</code>...")
    ok, errmsg = _fp_apply_via_xray(new_fp)
    if ok:
        send(uid, f"✅ {errmsg}\nXray перезапущен.")
        _log(f"Admin {uid} changed fingerprint to {new_fp!r}")
    else:
        send(uid, f"❌ Не удалось изменить fingerprint:\n<code>{errmsg}</code>")
        _log(f"Admin {uid} failed to change fingerprint to {new_fp!r}: {errmsg}")

# ── END Fingerprint management ────────────────────────────────────────────────
'''


def patch_tg_bot_script(script_text: str) -> str:
    """
    Вставляет блок команд /fp и /setfp в сгенерированный бот-скрипт.

    Алгоритм:
    1. Добавляет ``TG_FP_COMMANDS_BLOCK`` перед функцией ``handle_start`` —
       там уже определены все вспомогательные символы (api, send, is_admin...).
    2. Добавляет диспатч /fp и /setfp в ``process_update``.
    3. Добавляет команды в /help и /start (раздел admin).

    Если какая-либо точка вставки не найдена — пропускает её (не ломает скрипт).
    """
    ANCHOR_HANDLE_START  = "def handle_start(msg, args):"
    ANCHOR_PROCESS_CMD   = 'elif cmd == "/help":   handle_help(msg)'
    ANCHOR_HELP_ADMIN    = '"/broadcast — рассылка всем пользователям"'
    ANCHOR_START_ADMIN   = '"/broadcast &lt;текст&gt; — разослать всем пользователям'

    # 1. Вставка блока функций перед handle_start
    if ANCHOR_HANDLE_START in script_text and "handle_fp" not in script_text:
        script_text = script_text.replace(
            ANCHOR_HANDLE_START,
            TG_FP_COMMANDS_BLOCK + "\n" + ANCHOR_HANDLE_START,
        )

    # 2. Добавить диспатч /fp и /setfp в process_update
    if ANCHOR_PROCESS_CMD in script_text and '"handle_fp"' not in script_text \
            and "handle_fp" not in script_text.split(ANCHOR_PROCESS_CMD)[-1][:200]:
        fp_dispatch = (
            '    elif cmd == "/fp":     handle_fp(msg)\n'
            '    elif cmd == "/setfp":  handle_setfp(msg, args)\n'
            '    '
        )
        script_text = script_text.replace(
            ANCHOR_PROCESS_CMD,
            ANCHOR_PROCESS_CMD + "\n" + fp_dispatch,
        )

    # 3. Добавить /fp и /setfp в /help (блок admin)
    if ANCHOR_HELP_ADMIN in script_text:
        script_text = script_text.replace(
            ANCHOR_HELP_ADMIN,
            ANCHOR_HELP_ADMIN
            + r'''
            "\n/fp        — текущий fingerprint и список вариантов\n"
            "/setfp &lt;имя&gt; — сменить TLS fingerprint\n"''',
        )

    # 4. Добавить /fp и /setfp в /start (блок admin)
    if ANCHOR_START_ADMIN in script_text:
        script_text = script_text.replace(
            ANCHOR_START_ADMIN,
            ANCHOR_START_ADMIN
            + r"""\\n"""
            + r"""/fp — fingerprint / /setfp <имя> — сменить FP"""
            + r"""\\n"""
            + r"""/broadcast &lt;текст&gt; — разослать всем пользователям""",
        ).replace(
            # Убираем дублирование оригинала /broadcast
            r"""/fp — fingerprint / /setfp <имя> — сменить FP\\n"""
            r"""/broadcast &lt;текст&gt; — разослать всем пользователям\\n"""
            r"""/broadcast &lt;текст&gt; — разослать всем пользователям""",
            r"""/fp — fingerprint / /setfp <имя> — сменить FP\\n"""
            r"""/broadcast &lt;текст&gt; — разослать всем пользователям""",
        )

    return script_text
