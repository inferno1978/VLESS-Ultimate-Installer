"""
vless_installer/modules/fragment_config.py
───────────────────────────────────────────────────────────────────────────────
Генератор конфигов с TCP-фрагментацией ClientHello.

Фрагментация работает на уровне TCP-сегментов исходящего соединения:
Xray разбивает первые N байт TLS ClientHello на мелкие куски, что
препятствует DPI-анализу провайдера.

Параметры sockopt.fragment (на стороне outbound клиента):
  • packets  — "1-3"          (первые 1–3 TCP-сегмента)
  • length   — "1-5"          (размер каждого фрагмента в байтах)
  • interval — "10-20"        (задержка между фрагментами, мс)

ВАЖНО: фрагментация применяется ТОЛЬКО к исходящим соединениям (outbounds),
и ТОЛЬКО в клиентском конфиге (не в серверном xray/config.json на VPS).
Серверный config.json этим модулем не затрагивается ни при каких условиях.

Точка входа из _core.py / fragment_fuzzer.py:
    from vless_installer.modules.fragment_config import (
        build_fragment_sockopt,
        generate_fragment_client_config,
        do_fragment_config_menu,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

# ── Цвета (самодостаточные, как во всех других модулях) ────────────────────
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
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            from datetime import datetime
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = _re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [FRAGMENT] {clean}\n")
    except Exception:
        pass

def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");    _log("INFO",    msg)
def _success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}");   _log("SUCCESS", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}");  _log("WARN",    msg)

# ── Импорт box-рендерера ──────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn, _box_ok, _box_desc, _get_box_width,
)

# ── Константы ─────────────────────────────────────────────────────────────
_STATE_FILE       = Path("/var/lib/xray-installer/state.json")
_FRAGMENT_DIR     = Path("/var/lib/xray-installer/fragment_configs")
_FRAGMENT_PRESETS = {
    "aggressive": {
        "packets":  "1-3",
        "length":   "1-3",
        "interval": "5-10",
        "desc":     "Агрессивная (1–3 байта) — максимальный обход DPI, медленнее",
    },
    "balanced": {
        "packets":  "1-3",
        "length":   "3-7",
        "interval": "10-20",
        "desc":     "Сбалансированная (3–7 байт) — рекомендуется для большинства провайдеров",
    },
    "light": {
        "packets":  "1-2",
        "length":   "5-15",
        "interval": "20-50",
        "desc":     "Лёгкая (5–15 байт) — минимальный оверхед, базовая защита",
    },
    "custom": {
        "packets":  "",
        "length":   "",
        "interval": "",
        "desc":     "Пользовательская — ввести параметры вручную",
    },
}

# ── Публичные функции ──────────────────────────────────────────────────────

def build_fragment_sockopt(
    packets: str = "1-3",
    length: str = "3-7",
    interval: str = "10-20",
) -> dict:
    """
    Возвращает dict sockopt с секцией fragment.
    Используется fragment_fuzzer.py и do_fragment_config_menu().

    Пример результата:
        {
            "tcpFastOpen": true,
            "fragment": {
                "packets":  "1-3",
                "length":   "3-7",
                "interval": "10-20"
            }
        }
    """
    return {
        "tcpFastOpen": True,
        "tcpKeepAliveInterval": 15,
        "tcpKeepAliveIdle":   60,
        "tcpUserTimeout":     10000,
        "tcpCongestion":      "bbr",
        "fragment": {
            "packets":  packets,
            "length":   length,
            "interval": interval,
        },
    }


def generate_fragment_client_config(
    packets: str = "1-3",
    length: str = "3-7",
    interval: str = "10-20",
    label: str = "fragment",
) -> Optional[Path]:
    """
    Генерирует клиентский конфиг Xray с фрагментацией и сохраняет его
    в /var/lib/xray-installer/fragment_configs/<label>.json.

    Конфиг является КЛИЕНТСКИМ — он работает на устройстве пользователя
    и проксирует трафик через VPS. Серверный /etc/xray/config.json
    этой функцией не затрагивается.

    Возвращает Path к созданному файлу или None при ошибке.
    """
    # Читаем параметры сервера из state.json
    if not _STATE_FILE.exists():
        _warn("state.json не найден — сначала установите VLESS-сервер")
        return None

    try:
        state = json.loads(_STATE_FILE.read_text())
    except Exception as e:
        _warn(f"Не удалось прочитать state.json: {e}")
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
        _warn("В state.json нет domain/uuid — конфиг не может быть сгенерирован")
        return None

    sockopt = build_fragment_sockopt(packets, length, interval)

    # ── Строим outbound в зависимости от протокола ─────────────────────────
    if protocol_mode == "xhttp":
        xhttp_path = state.get("xhttp_path", "/")
        xhttp_mode = state.get("xhttp_mode", "streamup")
        outbound = {
            "tag":      "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_host,
                    "port":    server_port,
                    "users":   [{"id": uuid_val, "encryption": "none"}],
                }],
            },
            "streamSettings": {
                "network":  "xhttp",
                "security": "tls",
                "sockopt":  sockopt,
                "tlsSettings": {
                    "serverName":    server_host,
                    "allowInsecure": False,
                },
                "xhttpSettings": {
                    "path": xhttp_path,
                    "mode": xhttp_mode,
                },
            },
        }
    else:
        # REALITY
        sni = reality_dest.split(":")[0] if ":" in reality_dest else reality_dest
        outbound = {
            "tag":      "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_host,
                    "port":    server_port,
                    "users":   [{
                        "id":         uuid_val,
                        "encryption": "none",
                        **({"flow": xtls_flow} if xtls_flow else {}),
                    }],
                }],
            },
            "streamSettings": {
                "network":  "tcp",
                "security": "reality",
                "sockopt":  sockopt,
                "realitySettings": {
                    "show":        False,
                    "fingerprint": "chrome",
                    "serverName":  sni,
                    "publicKey":   pub_key,
                    "shortId":     short_id,
                    "spiderX":     "/",
                },
            },
        }

    client_cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag":      "socks",
                "protocol": "socks",
                "listen":   "127.0.0.1",
                "port":     10808,
                "settings": {"auth": "noauth", "udp": True},
            },
            {
                "tag":      "http",
                "protocol": "http",
                "listen":   "127.0.0.1",
                "port":     10809,
                "settings": {},
            },
        ],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "ip":     ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
            ],
        },
    }

    # ── Сохраняем файл ─────────────────────────────────────────────────────
    _FRAGMENT_DIR.mkdir(parents=True, exist_ok=True)
    safe_label = "".join(c for c in label if c.isalnum() or c in "-_")
    out_path = _FRAGMENT_DIR / f"{safe_label}.json"
    try:
        out_path.write_text(json.dumps(client_cfg, ensure_ascii=False, indent=2))
        _log("INFO", f"Клиентский конфиг с фрагментацией сохранён: {out_path}")
        return out_path
    except Exception as e:
        _warn(f"Не удалось сохранить конфиг: {e}")
        return None


def _validate_range_str(value: str, what: str) -> bool:
    """Проверяет, что строка имеет вид 'N' или 'N-M' с целыми числами > 0."""
    parts = value.strip().split("-")
    if len(parts) not in (1, 2):
        _warn(f"{what}: ожидается формат 'N' или 'N-M', например '3-7'")
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        _warn(f"{what}: значения должны быть целыми числами")
        return False
    if any(n <= 0 for n in nums):
        _warn(f"{what}: значения должны быть > 0")
        return False
    if len(nums) == 2 and nums[0] > nums[1]:
        _warn(f"{what}: нижняя граница должна быть ≤ верхней")
        return False
    return True


def do_fragment_config_menu() -> None:
    """
    Интерактивное меню генератора клиентских конфигов с фрагментацией.
    Вызывается из _menu_diagnostics() в _core.py.
    """
    while True:
        os.system("clear")
        print()
        _box_top("🔀  ГЕНЕРАТОР КОНФИГОВ С ФРАГМЕНТАЦИЕЙ")
        _box_desc(
            "Фрагментация разбивает TLS ClientHello на мелкие TCP-сегменты, "
            "обходя DPI провайдера. Применяется в клиентском конфиге Xray."
        )
        _box_sep()
        _box_row()
        _box_item("1", f"⚡ Агрессивная  {DIM}(1–3 байта, макс. обход DPI){NC}")
        _box_item("2", f"✅ Сбалансированная  {DIM}(3–7 байт, рекомендуется){NC}")
        _box_item("3", f"🔆 Лёгкая  {DIM}(5–15 байт, минимальный оверхед){NC}")
        _box_item("4", f"⚙️  Пользовательская  {DIM}(ввести length / interval / packets){NC}")
        _box_sep()
        _box_item("L", f"📂 Показать сохранённые конфиги")
        _box_row(f"       {DIM}{_FRAGMENT_DIR}{NC}")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "q" or ch == "":
            break

        # ── Выбор пресета ─────────────────────────────────────────────────
        preset_map = {"1": "aggressive", "2": "balanced", "3": "light"}
        if ch in preset_map:
            key = preset_map[ch]
            p = _FRAGMENT_PRESETS[key]
            _info(f"Пресет: {p['desc']}")
            _info(f"  packets={p['packets']}  length={p['length']}  interval={p['interval']} мс")
            print()
            path = generate_fragment_client_config(
                packets=p["packets"],
                length=p["length"],
                interval=p["interval"],
                label=f"fragment_{key}",
            )
            if path:
                _success(f"Конфиг сохранён: {path}")
                _info("Скопируйте на клиентское устройство и подключите в Xray/v2rayNG/Nekoray")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            # Пользовательский ввод
            print()
            _info("Введите параметры фрагментации (диапазон: N или N-M, например 3-7):")
            print()

            try:
                raw_packets  = input(f"  {CYAN}packets {DIM}(сегменты, напр. 1-3){NC}: ").strip() or "1-3"
                raw_length   = input(f"  {CYAN}length  {DIM}(байты,    напр. 3-7){NC}: ").strip() or "3-7"
                raw_interval = input(f"  {CYAN}interval{DIM}(мс,       напр. 10-20){NC}: ").strip() or "10-20"
            except KeyboardInterrupt:
                continue

            ok = (
                _validate_range_str(raw_packets,  "packets")
                and _validate_range_str(raw_length,   "length")
                and _validate_range_str(raw_interval, "interval")
            )
            if not ok:
                time.sleep(2)
                continue

            print()
            path = generate_fragment_client_config(
                packets=raw_packets,
                length=raw_length,
                interval=raw_interval,
                label="fragment_custom",
            )
            if path:
                _success(f"Конфиг сохранён: {path}")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "l":
            # Список сохранённых конфигов
            print()
            _box_top("📂  Сохранённые конфиги")
            if not _FRAGMENT_DIR.exists() or not list(_FRAGMENT_DIR.glob("*.json")):
                _box_info("Конфигов пока нет — создайте через пункты 1–4")
            else:
                for f in sorted(_FRAGMENT_DIR.glob("*.json")):
                    try:
                        data = json.loads(f.read_text())
                        # Извлекаем параметры fragment из outbound
                        ob = data.get("outbounds", [{}])[0]
                        frag = (ob.get("streamSettings", {})
                                  .get("sockopt", {})
                                  .get("fragment", {}))
                        tag = (f"packets={frag.get('packets','-')} "
                               f"length={frag.get('length','-')} "
                               f"interval={frag.get('interval','-')}")
                        _box_row(f"  {GREEN}•{NC} {f.name}  {DIM}{tag}{NC}")
                    except Exception:
                        _box_row(f"  {DIM}• {f.name}{NC}")
            _box_bottom()
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        else:
            _warn("Неверный выбор.")
            time.sleep(1)
