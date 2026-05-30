"""
vless_installer/modules/fragment_presets.py
───────────────────────────────────────────────────────────────────────────────
Генератор ВСЕХ клиентских конфигов с фрагментацией одной командой.

Что делает этот модуль:
  1. Генерирует полный набор конфигов с разными пресетами фрагментации —
     от агрессивных (мелкие пакеты, жёсткий DPI) до лёгких (крупные пакеты,
     минимальный оверхед) и одного без фрагментации (эталон).
  2. Сохраняет все файлы в /var/lib/xray-installer/fragment_configs/.
  3. Показывает пользователю чёткую инструкцию: что скачать, как импортировать,
     как выбрать лучший.

Почему именно так:
  Фрагментация работает на пути КЛИЕНТ → VPS, то есть через DPI провайдера
  пользователя. Сервер (VPS) не может протестировать это соединение за
  пользователя — у VPS другой провайдер. Единственный правильный способ
  подобрать параметры — дать пользователю несколько конфигов и попросить
  попробовать каждый на своём устройстве.

Матрица пресетов охватывает три диапазона:
  • Агрессивные  — мелкие пакеты (1–5 байт). Обходят строгий DPI,
                   но могут замедлять соединение.
  • Средние      — пакеты 10–50 байт. Часто работают там, где мелкие
                   не помогают (DPI настроен на фильтрацию крошечных
                   пакетов как известной сигнатуры обхода).
  • Лёгкие       — пакеты 50–200 байт. Минимальный оверхед, обходят
                   только поверхностный DPI.
  • Без фрагментации — эталонный конфиг для сравнения скорости.

ВАЖНО: серверный /etc/xray/config.json не затрагивается ни при каких условиях.

Точка входа из _core.py:
    from vless_installer.modules.fragment_presets import do_fragment_presets_menu
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        else:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
            )
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        import re as _re
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = _re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [PRESETS] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");    _log("INFO",    msg)
def _success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}");   _log("SUCCESS", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}");  _log("WARN",    msg)

# ── Импорт зависимостей ────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_row_auto, _box_item, _box_back,
    _box_info, _box_warn, _box_desc, _box_ok, _get_box_width,
)
from vless_installer.modules.fragment_config import generate_fragment_client_config

# ── Константы ─────────────────────────────────────────────────────────────
_FRAGMENT_DIR = Path("/var/lib/xray-installer/fragment_configs")
_STATE_FILE   = Path("/var/lib/xray-installer/state.json")

# ── Расширенная матрица пресетов ───────────────────────────────────────────
#
# Три диапазона length намеренно:
#   1-5   — агрессивные: обходят жёсткий DPI, но известны как сигнатура обхода
#  10-50  — средние: работают там, где мелкие уже фильтруются
#  50-200 — лёгкие: минимальный оверхед, обходят только поверхностный DPI
#
# Каждый пресет имеет уникальный label — имя файла при сохранении.
#
PRESET_MATRIX = [
    # ── Агрессивные (мелкие пакеты) ────────────────────────────────────
    {
        "label":    "frag_01_aggressive_ultra",
        "group":    "aggressive",
        "name":     "Агрессивная ультра",
        "hint":     "1–1 байт / 1–3 пак / 5–10 мс — жёсткий DPI (Иран, ТСПУ)",
        "packets":  "1-3",
        "length":   "1-1",
        "interval": "5-10",
    },
    {
        "label":    "frag_02_aggressive_strong",
        "group":    "aggressive",
        "name":     "Агрессивная сильная",
        "hint":     "1–3 байт / 1–3 пак / 5–10 мс — рекомендуется для Ирана",
        "packets":  "1-3",
        "length":   "1-3",
        "interval": "5-10",
    },
    {
        "label":    "frag_03_aggressive_std",
        "group":    "aggressive",
        "name":     "Агрессивная стандарт",
        "hint":     "1–5 байт / 1–3 пак / 10–20 мс — баланс обхода и скорости",
        "packets":  "1-3",
        "length":   "1-5",
        "interval": "10-20",
    },
    # ── Средние (пакеты 10–50 байт) ────────────────────────────────────
    {
        "label":    "frag_04_medium_fast",
        "group":    "medium",
        "name":     "Средняя быстрая",
        "hint":     "10–20 байт / 1–3 пак / 10–20 мс — Россия, большинство ISP",
        "packets":  "1-3",
        "length":   "10-20",
        "interval": "10-20",
    },
    {
        "label":    "frag_05_medium_std",
        "group":    "medium",
        "name":     "Средняя стандарт",
        "hint":     "20–50 байт / 1–3 пак / 20–40 мс — когда мелкие не работают",
        "packets":  "1-3",
        "length":   "20-50",
        "interval": "20-40",
    },
    {
        "label":    "frag_06_medium_slow",
        "group":    "medium",
        "name":     "Средняя медленная",
        "hint":     "20–50 байт / 1–2 пак / 30–60 мс — надёжно, но с задержкой",
        "packets":  "1-2",
        "length":   "20-50",
        "interval": "30-60",
    },
    # ── Лёгкие (пакеты 50–200 байт) ────────────────────────────────────
    {
        "label":    "frag_07_light_fast",
        "group":    "light",
        "name":     "Лёгкая быстрая",
        "hint":     "50–100 байт / 1–2 пак / 10–20 мс — минимальный оверхед",
        "packets":  "1-2",
        "length":   "50-100",
        "interval": "10-20",
    },
    {
        "label":    "frag_08_light_std",
        "group":    "light",
        "name":     "Лёгкая стандарт",
        "hint":     "100–200 байт / 1–1 пак / 5–10 мс — почти без задержки",
        "packets":  "1-1",
        "length":   "100-200",
        "interval": "5-10",
    },
    # ── Без фрагментации (эталон) ───────────────────────────────────────
    {
        "label":    "frag_00_no_fragment",
        "group":    "baseline",
        "name":     "Без фрагментации",
        "hint":     "Эталонный конфиг — сравни скорость с остальными",
        "packets":  None,   # None = не добавлять fragment в sockopt
        "length":   None,
        "interval": None,
    },
]

# Группы для отображения
_GROUP_LABELS = {
    "aggressive": f"⚡ Агрессивные  {DIM}(мелкие пакеты, жёсткий DPI){NC}",
    "medium":     f"⚖️  Средние      {DIM}(когда мелкие не работают){NC}",
    "light":      f"🔆 Лёгкие       {DIM}(минимальный оверхед){NC}",
    "baseline":   f"📋 Эталон       {DIM}(без фрагментации, для сравнения){NC}",
}


# ── Генерация одного пресета ───────────────────────────────────────────────

def _generate_one(preset: dict) -> Optional[Path]:
    """Генерирует один конфиг по пресету. None = не генерировать sockopt fragment."""
    if preset["packets"] is None:
        # Конфиг без фрагментации — generate_fragment_client_config не подходит,
        # генерируем вручную через build_fragment_sockopt с пустым fragment
        import json
        from vless_installer.modules.fragment_config import (
            build_fragment_sockopt, _STATE_FILE as SF,
        )
        if not SF.exists():
            return None
        try:
            state = json.loads(SF.read_text())
        except Exception:
            return None

        protocol_mode = state.get("protocol_mode", "reality")
        server_host   = state.get("domain", "")
        server_port   = state.get("server_port", 443)
        uuid_val      = state.get("uuid", "")
        pub_key       = state.get("public_key", "")
        short_id      = state.get("short_id", "")
        reality_dest  = state.get("reality_dest", "www.microsoft.com")
        xtls_flow     = state.get("xtls_flow", "xtls-rprx-vision")

        if not server_host or not uuid_val:
            return None

        # sockopt без fragment
        sockopt = {
            "tcpFastOpen": True,
            "tcpKeepAliveInterval": 15,
            "tcpKeepAliveIdle":     60,
            "tcpUserTimeout":       10000,
            "tcpCongestion":        "bbr",
        }

        if protocol_mode == "xhttp":
            xhttp_path = state.get("xhttp_path", "/")
            xhttp_mode = state.get("xhttp_mode", "streamup")
            outbound = {
                "tag": "proxy", "protocol": "vless",
                "settings": {"vnext": [{"address": server_host, "port": server_port,
                    "users": [{"id": uuid_val, "encryption": "none"}]}]},
                "streamSettings": {
                    "network": "xhttp", "security": "tls", "sockopt": sockopt,
                    "tlsSettings": {"serverName": server_host, "allowInsecure": False},
                    "xhttpSettings": {"path": xhttp_path, "mode": xhttp_mode},
                },
            }
        else:
            sni = reality_dest.split(":")[0] if ":" in reality_dest else reality_dest
            outbound = {
                "tag": "proxy", "protocol": "vless",
                "settings": {"vnext": [{"address": server_host, "port": server_port,
                    "users": [{"id": uuid_val, "encryption": "none",
                        **({} if not xtls_flow else {"flow": xtls_flow})}]}]},
                "streamSettings": {
                    "network": "tcp", "security": "reality", "sockopt": sockopt,
                    "realitySettings": {
                        "show": False, "fingerprint": "chrome",
                        "serverName": sni, "publicKey": pub_key,
                        "shortId": short_id, "spiderX": "/",
                    },
                },
            }

        client_cfg = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {"tag": "socks", "protocol": "socks", "listen": "127.0.0.1",
                 "port": 10808, "settings": {"auth": "noauth", "udp": True}},
                {"tag": "http", "protocol": "http", "listen": "127.0.0.1",
                 "port": 10809, "settings": {}},
            ],
            "outbounds": [
                outbound,
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "blackhole", "tag": "block"},
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {"type": "field", "ip":     ["geoip:private"],    "outboundTag": "direct"},
                    {"type": "field", "domain": ["geosite:private"],  "outboundTag": "direct"},
                ],
            },
        }
        _FRAGMENT_DIR.mkdir(parents=True, exist_ok=True)
        out_path = _FRAGMENT_DIR / f"{preset['label']}.json"
        try:
            out_path.write_text(json.dumps(client_cfg, ensure_ascii=False, indent=2))
            return out_path
        except Exception:
            return None
    else:
        return generate_fragment_client_config(
            packets=preset["packets"],
            length=preset["length"],
            interval=preset["interval"],
            label=preset["label"],
        )


# ── Генерация всех пресетов ────────────────────────────────────────────────

def generate_all_presets() -> list[dict]:
    """
    Генерирует все конфиги из PRESET_MATRIX.
    Возвращает список результатов:
        [{"preset": {...}, "path": Path | None, "ok": bool}, ...]
    """
    results = []
    for preset in PRESET_MATRIX:
        path = _generate_one(preset)
        results.append({
            "preset": preset,
            "path":   path,
            "ok":     path is not None,
        })
    return results


# ── Интерактивное меню ────────────────────────────────────────────────────

def do_fragment_presets_menu() -> None:
    """
    Меню «Сгенерировать все конфиги с фрагментацией».
    Генерирует полный набор пресетов одной командой и выводит инструкцию
    как пользователю скачать и протестировать их на своём устройстве.

    Вызывается из _menu_diagnostics() в _core.py.
    """
    os.system("clear")
    print()
    _box_top("📦  ГЕНЕРАЦИЯ ВСЕХ КОНФИГОВ С ФРАГМЕНТАЦИЕЙ")
    _box_desc(
        "Создаёт полный набор конфигов Xray с разными параметрами фрагментации. "
        "Скачайте все на устройство, попробуйте каждый "
        "и оставьте тот, где лучше скорость."
    )
    _box_sep()

    # Показываем что будет сгенерировано
    current_group = None
    for preset in PRESET_MATRIX:
        g = preset["group"]
        if g != current_group:
            _box_row()
            _box_row_auto(f"  {_GROUP_LABELS.get(g, g)}")
            current_group = g
        _box_row(f"    {DIM}• {preset['name']}{NC}")
        _box_row(f"       {DIM}{preset['hint']}{NC}")

    _box_row()
    _box_info(f"Итого: {len(PRESET_MATRIX)} конфигов")
    _box_info(f"Папка: {_FRAGMENT_DIR}")
    _box_sep()
    _box_warn(
        "Тестируйте конфиги НА СВОЁМ УСТРОЙСТВЕ — только так можно "
        "проверить обход DPI вашего провайдера."
    )
    _box_bottom()
    print()

    try:
        confirm = input(f"{CYAN}Сгенерировать все конфиги? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return

    if confirm not in ("y", "yes", "д", "да"):
        return

    print()
    _info("Генерирую конфиги...")
    print()

    results = generate_all_presets()

    ok_count  = sum(1 for r in results if r["ok"])
    err_count = len(results) - ok_count

    for r in results:
        p = r["preset"]
        if r["ok"]:
            print(f"  {GREEN}✓{NC}  {p['name']:<28} {DIM}{r['path'].name}{NC}")
        else:
            print(f"  {RED}✗{NC}  {p['name']:<28} {YELLOW}ошибка генерации{NC}")

    print()
    if ok_count > 0:
        _success(f"Готово: {ok_count} конфигов в {_FRAGMENT_DIR}")
        if err_count:
            _warn(f"Не удалось создать: {err_count} (проверьте state.json)")
    else:
        _warn("Ни одного конфига не создано — сначала установите VLESS-сервер")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    # ── Инструкция ─────────────────────────────────────────────────────
    print()
    print(f"{CYAN}{'─' * 60}{NC}")
    print(f"  {BOLD}Что делать дальше:{NC}")
    print(f"{CYAN}{'─' * 60}{NC}")
    print(f"  {WHITE}1.{NC}  Скачайте папку {CYAN}{_FRAGMENT_DIR}{NC} на своё устройство")
    print(f"       {DIM}(scp, SFTP или share через веб — см. пункт F5 в меню){NC}")
    print()
    print(f"  {WHITE}2.{NC}  Импортируйте файлы в Xray-клиент:")
    print(f"       {DIM}v2rayNG:  Импорт → Из файла{NC}")
    print(f"       {DIM}Nekoray:  File → Import → From File{NC}")
    print(f"       {DIM}Hiddify:  Добавить профиль → Из файла{NC}")
    print()
    print(f"  {WHITE}3.{NC}  Проверьте каждый конфиг:")
    print(f"       {DIM}Подключитесь → откройте speedtest.net или fast.com{NC}")
    print(f"       {DIM}Запишите пинг и скорость{NC}")
    print()
    print(f"  {WHITE}4.{NC}  {GREEN}Оставьте конфиг с лучшим результатом{NC}")
    print(f"       {DIM}Начните с frag_04 (средняя быстрая) — обычно лучший{NC}")
    print(f"       {DIM}Если не работает вообще — попробуйте frag_01 или frag_02{NC}")
    print(f"       {DIM}Если всё работает без фрагментации — оставьте frag_00{NC}")
    print(f"{CYAN}{'─' * 60}{NC}")

    input(f"\n{BLUE}Нажмите Enter...{NC}")
