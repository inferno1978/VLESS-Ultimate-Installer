"""
vless_installer/modules/subscription.py
───────────────────────────────────────────────────────────────────────────────
Subscription — единая subscription-ссылка sub.domain.com/<tag>, объединяющая
VLESS + NaiveProxy + Mieru в один sing-box JSON-конфиг (для Nekobox / Karing /
sing-box CLI). Идея и формулировка — из обсуждения в Telegram (gr33nimax):
"sub ссылка реально отдаёт конфиги" вместо ручной вставки трёх ссылок отдельно.

Почему именно sing-box JSON, а не текстовый список ссылок:
  У VLESS есть короткая URI-схема (vless://...), а у NaiveProxy и Mieru её
  нет — клиенты получают готовый sing-box outbound (JSON), который просто
  копируется целиком ("потроха конфига"). Общий знаменатель для всех трёх —
  один сводный sing-box-конфиг с массивом outbounds, не единый список ссылок.

  ВАЖНО про формат на проводе: файл тега — это ГОЛЫЙ JSON-массив outbound'ов
  ([{...}, {...}]), формат "JSON array of outbounds" из доков NekoBox/
  NyameBox. Обёртка вида {"outbounds": [...]} здесь НЕ подходит: она не
  матчится ни под array-формат (там клиент ждёт массив на верхнем уровне),
  ни нормально под full sing-box config (не хватает inbounds/route/dns) —
  итог: "Импортировано 0 профилей" при формально успешной загрузке URL.

Архитектура:

  Админ один раз настраивает домен подписки (sub.domain.com) — отдельный
  поддомен, НЕ совпадающий с доменом Reality/NaiveProxy (чтобы не делить с
  ними порт 443, см. ниже). Модуль поднимает свой собственный stock Caddy
  (официальная сборка с caddyserver.com, без кастомных плагинов — нужен
  только file_server + автоматический HTTPS) под именем caddy-sub,
  полностью отдельно от caddy-naive из naiveproxy.py.

  Дальше админ создаёт "теги" — реестр сопоставления:
      tag → (vless_uuid?, naive_username?, mieru_username?)
  выбирая вручную существующих пользователей из списков каждого модуля
  (они независимы и не имеют общего идентификатора — отдельный реестр
  здесь единственный надёжный способ их связать).

  При создании/регенерации тега модуль:
    • тянет сервер-вайд параметры VLESS Reality/xHTTP из основного
      /var/lib/xray-installer/state.json (домен, порт, public_key,
      short_id, fingerprint, xtls_flow) + uuid выбранного пользователя
      из users.json / xray config.json — и строит vless-outbound сам
      (копия формата из _core.py do_generate_client_config);
    • для NaiveProxy/Mieru — лениво импортирует их же собственные
      _gen_singbox_outbound() из naiveproxy.py/mieru.py (тот же паттерн
      delegation, что ipban._resolve_to_cidrs() в fail2ban_manager.py) —
      не копирует чужую логику построения outbound-а;
    • пишет статический файл /etc/caddy-sub/public/<tag>.json.

  Caddy раздаёт его как обычный файл, с rewrite-правилом, чтобы URL был
  чистым: GET https://sub.domain.com/<tag> → отдаёт <tag>.json.

ВАЖНО, что нужно знать перед использованием:

  1. Домен подписки — ОТДЕЛЬНЫЙ от Reality/NaiveProxy, со своим A-record.
     Сажать caddy-sub на тот же :443, где уже сидит Xray Reality или
     caddy-naive — конфликт портов. Поэтому при установке модуль
     проверяет, свободен ли выбранный порт, и предлагает альтернативный
     (например 8443), если занят.
     TLS-сертификат получается через certbot --standalone (а не встроенным
     ACME Caddy) и подключается статически (`tls cert key`) с `auto_https
     off` — поэтому caddy-sub НИКОГДА не пытается слушать :80 и не может
     конфликтовать с nginx/другими сервисами на этом порту. На момент
     HTTP-01 challenge certbot сам останавливает nginx на пару секунд
     (--pre-hook/--post-hook) и поднимает обратно; хуки сохраняются в его
     renewal-конфиге и применяются автоматически и при будущих продлениях.
     SNI-роутер/мультиплексирование 443 между модулями этот модуль
     НЕ реализует — это отдельная большая задача, не лезу в неё без
     явного запроса.
  2. Реестр тегов — это снимок на момент создания/регенерации. Если
     пароль/uuid пользователя поменяли в самом NaiveProxy/Mieru/VLESS —
     файл тега устареет. Самолечение: список тегов автоматически
     регенерируется при каждом открытии раздела «Управление тегами».
  3. Один login/password на пользователя в каждом протоколе — это
     ограничение самих NaiveProxy/Mieru, тут ничего не добавляется
     сверху.

Точка входа из _core.py:
    from vless_installer.modules.subscription import do_subscription_menu
    do_subscription_menu()

Интеграция в _core.py (по аналогии с пунктом 14 WebDAV Tunnel):
  1. Импорт:
       from vless_installer.modules.subscription import do_subscription_menu
  2. Пункт меню (15):
       _box_row(f"  {CYAN}15{NC} 📨 {TITLE}Подписка{NC}")
       _box_row(f"     {DIM}Единая subscription-ссылка: VLESS + NaiveProxy + Mieru{NC}")
     и поднять диапазон "Выбор (1–15 / 0):"
  3. Обработчик:
       elif choice == "15":
           try:
               do_subscription_menu()
           except ImportError as _e:
               warn(f"Модуль Подписка не найден: {_e}")
               time.sleep(2)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА
# ══════════════════════════════════════════════════════════════════════════════
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BOLD='\033[1m', DIM='\033[2m',
                WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
_BIN_PATH      = Path("/usr/local/bin/caddy-sub")
_CFG_DIR       = Path("/etc/caddy-sub")
_CADDYFILE     = Path("/etc/caddy-sub/Caddyfile")
_PUBLIC_DIR    = Path("/etc/caddy-sub/public")
_SERVICE_FILE  = Path("/etc/systemd/system/caddy-sub.service")
_SERVICE_NAME  = "caddy-sub"

_MODULE_STATE      = Path("/var/lib/xray-installer/subscription.json")
_MAIN_STATE_FILE   = Path("/var/lib/xray-installer/state.json")        # VLESS, чужой, read-only
_NAIVE_STATE_FILE  = Path("/var/lib/xray-installer/naiveproxy.json")   # чужой, read-only
_MIERU_STATE_FILE  = Path("/var/lib/xray-installer/mieru.json")        # чужой, read-only
_USERS_FILE        = Path("/etc/xray/users.json")                      # чужой, read-only

_DEFAULT_PORT = 443
_FALLBACK_PORT = 8443

_TAG_RE = re.compile(r"^[a-z0-9_-]{3,32}$")

_BOX_W = 66

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ  (тот же набор хелперов, что в webdav_tunnel.py)
# ══════════════════════════════════════════════════════════════════════════════
def _plain(s: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', s)

def _wlen(s: str) -> int:
    import unicodedata as _ud
    plain = _plain(s)
    width, chars = 0, list(plain)
    i = 0
    while i < len(chars):
        ch = chars[i]
        cp = ord(ch)
        next_cp = ord(chars[i + 1]) if i + 1 < len(chars) else 0
        if next_cp == 0xFE0F:
            width += 2; i += 2; continue
        if cp == 0x200D or (0x300 <= cp <= 0x36F) or (0xFE00 <= cp <= 0xFE0F):
            i += 1; continue
        eaw = _ud.east_asian_width(ch)
        if eaw in ('W', 'F'):
            width += 2
        elif eaw == 'N' and (0x1F300 <= cp <= 0x1FAFF or 0x2B00 <= cp <= 0x2BFF):
            width += 2
        else:
            width += 1
        i += 1
    return width

def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad  = _BOX_W - _wlen(title)
        lpad = pad // 2
        rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None:
    print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_bot() -> None:
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        acc, plain = 0, _plain(text)
        cut = 0
        for i, ch in enumerate(plain):
            import unicodedata as _ud
            acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc > _BOX_W - 1:
                cut = i; break
        text = text[:cut] + "…"
        w = _wlen(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")

def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

def _box_ok(msg: str)   -> None: _box_row(f"  {GREEN}✓{NC}  {msg}")
def _box_warn(msg: str) -> None: _box_row(f"  {YELLOW}⚠{NC}  {msg}")
def _box_info(msg: str) -> None: _box_row(f"  {CYAN}→{NC}  {msg}")
def _box_err(msg: str)  -> None: _box_row(f"  {RED}✗{NC}  {msg}")

def _box_kv(key: str, val: str, kw: int = 22) -> None:
    key_colored = f"{CYAN}{key}{NC}"
    key_pad = kw - _wlen(key_colored)
    _box_row(f"  {key_colored}{' ' * max(0, key_pad)}  {val}")

def _save_link_file(link: str, filename: str) -> Path:
    try:
        _CFG_DIR.mkdir(parents=True, exist_ok=True)
        path = _CFG_DIR / filename
        path.write_text(link + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except Exception:
            pass
        return path
    except Exception:
        return _CFG_DIR / filename

def _print_link_file_path(path: Path) -> None:
    print(f"  {DIM}📄 Ссылка сохранена в файл: {NC}{CYAN}{path}{NC}")

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
class _Cancelled(Exception):
    pass

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True)
        input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

def _ask(prompt: str, default: str = "", c: bool = False) -> str:
    try:
        print(prompt, end="", flush=True)
        val = input().strip()
        return val if val else default
    except (EOFError, UnicodeDecodeError):
        print(); return default
    except KeyboardInterrupt:
        print()
        if c: raise _Cancelled()
        return default

def _run(cmd: list, capture: bool = False, check: bool = False,
         env: Optional[dict] = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if env:
        kw["env"] = env
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _get_server_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "YOUR_SERVER_IP"

def _port_in_use(port: int) -> bool:
    for fam, kind in ((socket.AF_INET, socket.SOCK_STREAM),):
        try:
            with socket.socket(fam, kind) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
        except OSError:
            return True
    return False

def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}

# ══════════════════════════════════════════════════════════════════════════════
#  СОСТОЯНИЕ МОДУЛЯ (домен подписки + реестр тегов)
# ══════════════════════════════════════════════════════════════════════════════
def _load_state() -> dict:
    data = _read_json(_MODULE_STATE)
    data.setdefault("tags", {})
    return data

def _save_state(data: dict) -> None:
    try:
        _MODULE_STATE.parent.mkdir(parents=True, exist_ok=True)
        _MODULE_STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        _MODULE_STATE.chmod(0o600)
    except Exception as e:
        print(f"  {YELLOW}⚠{NC}  Не удалось сохранить subscription.json: {e}")

def _is_installed() -> bool:
    return _BIN_PATH.exists() and _SERVICE_FILE.exists() and bool(_load_state().get("domain"))

# ══════════════════════════════════════════════════════════════════════════════
#  ИСТОЧНИКИ ПОЛЬЗОВАТЕЛЕЙ  (read-only чтение чужих состояний)
# ══════════════════════════════════════════════════════════════════════════════
def _vless_state() -> dict:
    return _read_json(_MAIN_STATE_FILE)

def _vless_users() -> list:
    """Минимальная локальная копия логики _unified_load_users() из _core.py —
    только то, что нужно здесь (uuid + имя). Чужой код не импортируется,
    т.к. _core.py импортирует модули, а не наоборот (циклический импорт)."""
    seen, merged = set(), []
    try:
        raw = json.loads(_USERS_FILE.read_text()) if _USERS_FILE.exists() else []
    except Exception:
        raw = []
    for u in raw:
        uid = u.get("uuid", "")
        if uid and uid not in seen and not u.get("disabled"):
            seen.add(uid)
            merged.append({"uuid": uid, "name": u.get("name", u.get("email", uid[:8]))})
    for cfg_path in (Path("/etc/xray/config.json"), Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        cfg = _read_json(cfg_path)
        clients = (cfg.get("inbounds", [{}]) or [{}])[0].get("settings", {}).get("clients", [])
        for cl in clients:
            uid = cl.get("id", "")
            if uid and uid not in seen:
                seen.add(uid)
                email = cl.get("email", "")
                merged.append({"uuid": uid, "name": email.split("@")[0] if email else uid[:8]})
        break
    return merged

def _vless_outbound(vuuid: str) -> Optional[dict]:
    state = _vless_state()
    domain  = state.get("domain", "")
    port    = state.get("server_port", 443)
    if not domain or not vuuid:
        return None
    proto   = state.get("protocol_mode", "reality")
    fp      = state.get("fingerprint", "chrome")
    install_mode = state.get("install_mode", "A")
    awg_exit     = state.get("awg_exit_enabled", False) and install_mode == "B"
    reality_dest = state.get("reality_dest", "")
    sni = reality_dest if (proto == "reality" and awg_exit and reality_dest) else domain
    xtls_flow = state.get("xtls_flow", "xtls-rprx-vision") or "xtls-rprx-vision"

    if proto == "reality":
        ob = {
            "type": "vless", "tag": "vless-reality",
            "server": domain, "server_port": port, "uuid": vuuid,
            "tls": {
                "enabled": True, "server_name": sni,
                "utls": {"enabled": True, "fingerprint": fp},
                "reality": {
                    "enabled": True,
                    "public_key": state.get("public_key", ""),
                    "short_id": state.get("short_id", ""),
                },
            },
        }
        if xtls_flow:
            ob["flow"] = xtls_flow
        return ob

    return {
        "type": "vless", "tag": "vless-xhttp",
        "server": domain, "server_port": port, "uuid": vuuid,
        "transport": {"type": "http", "path": state.get("xhttp_path", "/")},
        "tls": {"enabled": True, "server_name": domain,
                "utls": {"enabled": True, "fingerprint": fp}},
    }

def _naive_state() -> dict:
    return _read_json(_NAIVE_STATE_FILE)

def _naive_users() -> list:
    return _naive_state().get("users", [])

def _naive_outbound(username: str, password: str) -> Optional[dict]:
    state = _naive_state()
    domain = state.get("domain", "")
    port   = state.get("port", 443)
    if not domain:
        return None
    try:
        from vless_installer.modules.naiveproxy import _gen_singbox_outbound as _naive_gen
    except ImportError:
        return None
    return _naive_gen(domain, port, username, password)

def _mieru_state() -> dict:
    return _read_json(_MIERU_STATE_FILE)

def _mieru_users() -> list:
    return _mieru_state().get("users", [])

def _mieru_outbound(username: str, password: str) -> Optional[dict]:
    state = _mieru_state()
    port_start = state.get("port_start")
    port_end   = state.get("port_end")
    protocol   = state.get("protocol", "TCP")
    if not port_start:
        return None
    try:
        from vless_installer.modules.mieru import _gen_singbox_outbound as _mieru_gen
    except ImportError:
        return None
    server_ip = _get_server_ip()
    return _mieru_gen(server_ip, port_start, port_end, protocol, username, password)

# ══════════════════════════════════════════════════════════════════════════════
#  СБОРКА КОНФИГА ТЕГА
# ══════════════════════════════════════════════════════════════════════════════
def _build_tag_config(entry: dict) -> dict:
    outbounds = []

    vuuid = entry.get("vless_uuid")
    if vuuid:
        ob = _vless_outbound(vuuid)
        if ob:
            outbounds.append(ob)

    naive_user = entry.get("naive_username")
    if naive_user:
        pw = next((u["password"] for u in _naive_users() if u.get("username") == naive_user), None)
        if pw:
            ob = _naive_outbound(naive_user, pw)
            if ob:
                outbounds.append(ob)

    mieru_user = entry.get("mieru_username")
    if mieru_user:
        pw = next((u["password"] for u in _mieru_users() if u.get("username") == mieru_user), None)
        if pw:
            ob = _mieru_outbound(mieru_user, pw)
            if ob:
                outbounds.append(ob)

    if len(outbounds) > 1:
        outbounds.append({
            "type": "selector",
            "tag": "Подписка",
            "outbounds": [o["tag"] for o in outbounds],
            "default": outbounds[0]["tag"],
        })

    return {"outbounds": outbounds}

def _write_tag_file(tag: str, cfg: dict) -> None:
    """Пишем ГОЛЫЙ JSON-массив outbound'ов (формат "JSON array of outbounds",
    который понимают NekoBox/NyameBox/sing-box клиенты как multi-node
    subscription), а НЕ {"outbounds": [...]} — обёртка не матчится ни под
    array-формат, ни нормально под full sing-box config (не хватает других
    секций), из-за чего клиент репортил "Импортировано 0 профилей"."""
    _PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    path = _PUBLIC_DIR / f"{tag}.json"
    path.write_text(json.dumps(cfg["outbounds"], indent=2, ensure_ascii=False))
    path.chmod(0o644)

def _regenerate_all_tags(state: dict) -> int:
    count = 0
    for tag, entry in state.get("tags", {}).items():
        cfg = _build_tag_config(entry)
        if cfg["outbounds"]:
            _write_tag_file(tag, cfg)
            count += 1
    return count

# ══════════════════════════════════════════════════════════════════════════════
#  CADDY (отдельный stock-инстанс, не связан с caddy-naive из naiveproxy.py)
# ══════════════════════════════════════════════════════════════════════════════
def _caddy_arch() -> str:
    m = platform.machine().lower()
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, "amd64")

def _download_caddy() -> bool:
    """Официальная сборка с caddyserver.com — без кастомных плагинов,
    нужен только file_server + automatic HTTPS."""
    arch = _caddy_arch()
    url = f"https://caddyserver.com/api/download?os=linux&arch={arch}"
    tmp = Path("/tmp/caddy-sub-bin")
    print(f"  {CYAN}→{NC}  Скачиваю Caddy ({arch})...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VLESS-Ultimate-Installer"})
        with urllib.request.urlopen(req, timeout=120) as resp, tmp.open("wb") as f:
            f.write(resp.read())
    except Exception as e:
        print(f"  {RED}✗{NC}  Не удалось скачать Caddy: {e}")
        return False
    if not tmp.exists() or tmp.stat().st_size < 1_000_000:
        print(f"  {RED}✗{NC}  Скачанный файл подозрительно мал — обрыв загрузки?")
        return False
    import shutil
    shutil.move(str(tmp), str(_BIN_PATH))
    _BIN_PATH.chmod(0o755)
    print(f"  {GREEN}✓{NC}  Caddy установлен: {_BIN_PATH}")
    return True

def _write_caddyfile(domain: str, port: int, cert_path: Path, key_path: Path) -> None:
    """TLS берётся из готовых файлов certbot (см. _obtain_certificate), а не из
    встроенного ACME Caddy — поэтому auto_https off: этот инстанс Caddy НИКОГДА
    не пытается слушать :80 и не может конфликтовать с nginx/др. сервисами там."""
    _PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    content = (
        "{\n"
        "    auto_https off\n"
        "}\n\n"
        f"{domain}:{port} {{\n"
        f"    tls {cert_path} {key_path}\n"
        f"    root * {_PUBLIC_DIR}\n"
        f"    @notjson not path *.json\n"
        f"    rewrite @notjson {{path}}.json\n"
        f"    file_server\n"
        f"    header Content-Type \"application/json; charset=utf-8\"\n"
        f"    header Cache-Control \"no-store\"\n"
        f"    encode gzip\n"
        f"}}\n"
    )
    _CADDYFILE.write_text(content)

# ══════════════════════════════════════════════════════════════════════════════
#  CERTBOT (--standalone, временно останавливает nginx на пару секунд)
# ══════════════════════════════════════════════════════════════════════════════
_CERTBOT_LIVE_DIR = Path("/etc/letsencrypt/live")

def _ensure_certbot_installed() -> bool:
    import shutil as _shutil
    if _shutil.which("certbot"):
        return True
    print(f"  {CYAN}→{NC}  certbot не найден, устанавливаю...")
    _run(["apt-get", "update", "-qq"], capture=True)
    _run(["apt-get", "install", "-y", "-qq", "certbot"], capture=True)
    if _shutil.which("certbot"):
        print(f"  {GREEN}✓{NC}  certbot установлен.")
        return True
    print(f"  {RED}✗{NC}  Не удалось установить certbot (apt-get install certbot).")
    return False

def _obtain_certificate(domain: str, email: str) -> bool:
    """certbot --standalone сам биндит :80 только на момент HTTP-01 challenge.
    --pre-hook останавливает nginx, --post-hook сразу поднимает обратно —
    простой только эти несколько секунд, Caddy порт 80 не нужен вообще.
    Хуки сохраняются в renewal-конфиге certbot и применяются автоматически
    при будущих продлениях (systemd certbot.timer), --deploy-hook перезагружает
    caddy-sub, чтобы он подхватил обновлённый сертификат."""
    cmd = [
        "certbot", "certonly", "--standalone",
        "-d", domain,
        "--non-interactive", "--agree-tos",
        "--pre-hook", "systemctl stop nginx 2>/dev/null || true",
        "--post-hook", "systemctl start nginx 2>/dev/null || true",
        "--deploy-hook", f"systemctl reload-or-restart {_SERVICE_NAME} 2>/dev/null || true",
    ]
    cmd += ["--email", email] if email else ["--register-unsafely-without-email"]

    print(f"  {CYAN}→{NC}  Получаю сертификат: certbot --standalone -d {domain}")
    print(f"  {DIM}   (nginx будет остановлен на несколько секунд для challenge){NC}")
    r = _run(cmd, capture=True)

    live = _CERTBOT_LIVE_DIR / domain
    ok = (live / "fullchain.pem").exists() and (live / "privkey.pem").exists()
    if not ok:
        err = ((r.stderr or "") + (r.stdout or "")).strip()
        print(f"  {RED}✗{NC}  certbot не выпустил сертификат:")
        print(f"  {DIM}{err[-500:]}{NC}")
    else:
        print(f"  {GREEN}✓{NC}  Сертификат получен: {live}")
    return ok

def _install_service() -> None:
    _SERVICE_FILE.write_text(
        "[Unit]\n"
        "Description=caddy-sub — static subscription server (VLESS/NaiveProxy/Mieru)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={_BIN_PATH} run --config {_CADDYFILE} --adapter caddyfile\n"
        f"ExecReload={_BIN_PATH} reload --config {_CADDYFILE} --adapter caddyfile\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", _SERVICE_NAME])

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА / НАСТРОЙКА ДОМЕНА
# ══════════════════════════════════════════════════════════════════════════════
def _run_setup() -> None:
    try:
        _run_setup_inner()
    except _Cancelled:
        print(f"\n  {YELLOW}Настройка прервана.{NC}\n")
        _pause()

def _run_setup_inner() -> None:
    os.system("clear")
    state = _load_state()
    _box_top("📨  НАСТРОЙКА ПОДПИСКИ")
    _box_row()
    _box_warn("Нужен ОТДЕЛЬНЫЙ поддомен (НЕ домен Reality/NaiveProxy),")
    _box_warn("с уже настроенной A-записью на IP этого сервера.")
    _box_warn("Сертификат получаем через certbot --standalone: на пару")
    _box_warn("секунд nginx будет остановлен и сразу поднят обратно —")
    _box_warn("порт 80 этому Caddy-инстансу вообще не нужен.")
    _box_bot(); print()

    try:
        domain = _ask(f"  {CYAN}Домен подписки (sub.example.com): {NC}",
                       default=state.get("domain", ""), c=True)
        if not domain:
            print(f"  {RED}✗{NC}  Домен обязателен."); _pause(); return

        port = _DEFAULT_PORT
        if _port_in_use(port):
            print(f"  {YELLOW}⚠{NC}  Порт {port} уже занят на этом сервере "
                  f"(вероятно Reality или другой Caddy).")
            raw = _ask(f"  {CYAN}Укажите свободный порт [{_FALLBACK_PORT}]: {NC}",
                       default=str(_FALLBACK_PORT), c=True)
            port = int(raw) if raw.isdigit() else _FALLBACK_PORT
            if _port_in_use(port):
                print(f"  {RED}✗{NC}  Порт {port} тоже занят. Освободите порт и повторите."); _pause(); return
        else:
            raw = _ask(f"  {CYAN}TCP порт [{port}]: {NC}", default=str(port), c=True)
            port = int(raw) if raw.isdigit() else port

        email = _ask(f"  {CYAN}Email для Let's Encrypt (опционально, Enter — без email): {NC}",
                     default=state.get("email", ""), c=True)
    except _Cancelled:
        raise

    if not _BIN_PATH.exists():
        if not _download_caddy():
            _pause(); return
    else:
        print(f"  {GREEN}✓{NC}  Caddy уже установлен.")

    if not _ensure_certbot_installed():
        _pause(); return

    if not _obtain_certificate(domain, email):
        print(f"  {RED}✗{NC}  Без сертификата продолжать нет смысла — проверьте,")
        print(f"  {RED}✗{NC}  что A-запись домена указывает на IP этого сервера.")
        _pause(); return

    live = _CERTBOT_LIVE_DIR / domain
    cert_path, key_path = live / "fullchain.pem", live / "privkey.pem"

    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    _write_caddyfile(domain, port, cert_path, key_path)
    print(f"  {GREEN}✓{NC}  Caddyfile записан: {_CADDYFILE}")
    _install_service()
    print(f"  {GREEN}✓{NC}  Systemd-сервис создан.")

    _run(["systemctl", "restart", _SERVICE_NAME])
    time.sleep(2)

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"

    state.update({"domain": domain, "port": port, "email": email, "installed": True})
    _save_state(state)

    print()
    _box_top("✅  ПОДПИСКА НАСТРОЕНА" if svc_ok else "⚠️  ЕСТЬ ПРОБЛЕМЫ")
    _box_row()
    _box_kv("Сервис:", f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● не запущен{NC}")
    _box_kv("Домен:", f"{domain}:{port}")
    _box_ok("Сертификат Let's Encrypt получен (certbot --standalone).")
    if not svc_ok:
        _box_err("Сервис не стартовал — смотрите логи (пункт «Статус»).")
    _box_row()
    _box_info("Дальше: «Управление тегами» → создать тег для пользователя.")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СОЗДАНИЕ / УПРАВЛЕНИЕ ТЕГАМИ
# ══════════════════════════════════════════════════════════════════════════════
def _pick_user(label: str, users: list, display) -> Optional[dict]:
    """Показывает нумерованный список пользователей, возвращает выбранного
    или None (пропустить). display(u) -> строка для показа."""
    if not users:
        _box_info(f"{label}: пользователей не найдено — пропускаю.")
        return None
    _box_row(f"  {BOLD}{WHITE}{label}:{NC}")
    for i, u in enumerate(users, 1):
        _box_row(f"    {CYAN}{i}{NC}) {display(u)}")
    _box_row(f"    {DIM}0) пропустить{NC}")
    raw = _ask(f"  {CYAN}Выбор: {NC}", default="0", c=True)
    if not raw.isdigit() or int(raw) == 0:
        return None
    idx = int(raw) - 1
    if 0 <= idx < len(users):
        return users[idx]
    return None

def _create_tag() -> None:
    os.system("clear")
    _box_top("➕  НОВЫЙ ТЕГ ПОДПИСКИ")
    _box_row()
    try:
        tag = _ask(f"  {CYAN}Имя тега (латиница/цифры, 3-32 симв.): {NC}", c=True).strip().lower()
    except _Cancelled:
        return
    if not _TAG_RE.match(tag):
        print(f"  {RED}✗{NC}  Недопустимое имя (только a-z 0-9 _ -, 3-32 символа)."); _pause(); return

    state = _load_state()
    if tag in state.get("tags", {}):
        print(f"  {YELLOW}⚠{NC}  Тег уже существует — выберите другое имя."); _pause(); return

    print()
    entry: dict = {}
    try:
        vu = _pick_user("VLESS", _vless_users(), lambda u: f"{u['name']}  ({u['uuid'][:8]}…)")
        if vu:
            entry["vless_uuid"] = vu["uuid"]
        print()
        nu = _pick_user("NaiveProxy", _naive_users(), lambda u: u["username"])
        if nu:
            entry["naive_username"] = nu["username"]
        print()
        mu = _pick_user("Mieru", _mieru_users(), lambda u: u["username"])
        if mu:
            entry["mieru_username"] = mu["username"]
    except _Cancelled:
        return

    if not entry:
        print(f"  {RED}✗{NC}  Ни один протокол не выбран — тег не создан."); _pause(); return

    cfg = _build_tag_config(entry)
    if not cfg["outbounds"]:
        print(f"  {RED}✗{NC}  Не удалось собрать ни одного outbound-а "
              f"(модуль не установлен или нет данных сервера)."); _pause(); return

    _write_tag_file(tag, cfg)
    state["tags"][tag] = entry
    _save_state(state)

    domain = state.get("domain", "")
    port = state.get("port", _DEFAULT_PORT)
    link = f"https://{domain}{'' if port == 443 else ':' + str(port)}/{tag}"

    print()
    _box_top("✅  ТЕГ СОЗДАН")
    _box_row()
    _box_ok(f"Тег: {tag}  ({len(cfg['outbounds']) - (1 if len(cfg['outbounds']) > 1 else 0)} протокол(а))")
    _box_row(f"  {YELLOW}{link}{NC}")
    _box_bot()
    _save_link_file(link, f"{tag}.link.txt")
    _pause()

def _delete_tag() -> None:
    os.system("clear")
    state = _load_state()
    tags = state.get("tags", {})
    if not tags:
        print(f"  {YELLOW}Тегов пока нет.{NC}"); _pause(); return
    _box_top("🗑️  УДАЛИТЬ ТЕГ")
    _box_row()
    for i, t in enumerate(tags.keys(), 1):
        _box_row(f"  {CYAN}{i}{NC}) {t}")
    _box_item("Q", "← Отмена")
    _box_bot(); print()
    try:
        raw = _ask(f"{CYAN}Выбор: {NC}", c=True)
    except _Cancelled:
        return
    if not raw.isdigit():
        return
    keys = list(tags.keys())
    idx = int(raw) - 1
    if not (0 <= idx < len(keys)):
        return
    tag = keys[idx]
    del state["tags"][tag]
    _save_state(state)
    path = _PUBLIC_DIR / f"{tag}.json"
    if path.exists():
        path.unlink()
    print(f"  {GREEN}✓{NC}  Тег «{tag}» удалён.")
    _pause()

def _show_tag_link() -> None:
    os.system("clear")
    state = _load_state()
    tags = state.get("tags", {})
    if not tags:
        print(f"  {YELLOW}Тегов пока нет.{NC}"); _pause(); return
    _box_top("🔗  ССЫЛКИ ПОДПИСКИ")
    _box_row()
    domain = state.get("domain", "")
    port = state.get("port", _DEFAULT_PORT)
    port_sfx = '' if port == 443 else f':{port}'
    for tag, entry in tags.items():
        protos = []
        if entry.get("vless_uuid"): protos.append("VLESS")
        if entry.get("naive_username"): protos.append("Naive")
        if entry.get("mieru_username"): protos.append("Mieru")
        _box_row(f"  {BOLD}{WHITE}{tag}{NC}  {DIM}({'+'.join(protos)}){NC}")
        _box_row(f"    {YELLOW}https://{domain}{port_sfx}/{tag}{NC}")
        _box_row()
    _box_bot()
    _pause()

def _tags_menu() -> None:
    while True:
        os.system("clear")
        state = _load_state()
        regenerated = _regenerate_all_tags(state)  # самолечение от устаревших паролей/uuid

        _box_top("🏷️  УПРАВЛЕНИЕ ТЕГАМИ")
        _box_row()
        _box_kv("Тегов:", str(len(state.get("tags", {}))))
        _box_kv("Обновлено файлов:", str(regenerated))
        _box_row(); _box_sep()
        _box_item("1", "➕  Создать тег")
        _box_item("2", "🔗  Показать ссылки")
        _box_item("3", "🗑️   Удалить тег")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()
        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break
        if ch == "1":
            _create_tag()
        elif ch == "2":
            _show_tag_link()
        elif ch == "3":
            _delete_tag()
        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС / УДАЛЕНИЕ / ГАЙД
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    state = _load_state()
    _box_top("📊  СТАТУС  •  Подписка")
    _box_row()
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    _box_kv("Сервис:", f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")
    _box_kv("Домен:", f"{state.get('domain','—')}:{state.get('port', _DEFAULT_PORT)}")
    _box_kv("Тегов:", str(len(state.get("tags", {}))))
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Последние 25 строк журнала:{NC}")
    _box_row()
    r2 = subprocess.run(
        ["journalctl", "-u", _SERVICE_NAME, "-n", "25", "--no-pager", "--output=short-monotonic"],
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "LANG": "C.UTF-8"},
    )
    for line in (r2.stdout or r2.stderr or "Нет записей").splitlines():
        _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")
    _box_row(); _box_bot()
    _pause()

def _full_uninstall() -> None:
    os.system("clear")
    _box_top("🗑️  УДАЛЕНИЕ  •  Подписка")
    _box_row()
    _box_warn("Будет удалено: сервис caddy-sub, Caddy-бинарник, конфиги,")
    _box_warn("все теги и реестр сопоставлений. Пользователи VLESS/")
    _box_warn("NaiveProxy/Mieru — НЕ затрагиваются, они в других модулях.")
    _box_row()
    _box_item("Y", f"{RED}Да, удалить{NC}")
    _box_item("N", "Нет, отмена")
    _box_bot(); print()
    try:
        ans = _ask(f"{CYAN}Подтверждение [y/N]: {NC}", c=True).strip().lower()
    except _Cancelled:
        return
    if ans != "y":
        print(f"  {DIM}Отменено.{NC}"); _pause(); return

    _run(["systemctl", "stop", _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    if _SERVICE_FILE.exists():
        _SERVICE_FILE.unlink()
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"], capture=True)
    if _BIN_PATH.exists():
        _BIN_PATH.unlink()
    if _CFG_DIR.exists():
        import shutil
        shutil.rmtree(_CFG_DIR, ignore_errors=True)
    if _MODULE_STATE.exists():
        _MODULE_STATE.unlink()
    print(f"  {GREEN}✓{NC}  Подписка удалена.")
    _pause()

def _show_guide() -> None:
    os.system("clear")
    _box_top("📖  ГАЙД  •  Подписка")
    _box_row()
    _box_info("Что это: одна ссылка sub.domain.com/<tag> отдаёт sing-box")
    _box_info("JSON со всеми протоколами тега (VLESS/Naive/Mieru сразу).")
    _box_info("Вставляется в Nekobox как подписка вместо ручного импорта")
    _box_info("каждой ссылки отдельно.")
    _box_row()
    _box_warn("Тег — это РУЧНОЕ сопоставление, не автосинхронизация.")
    _box_warn("Если смените пароль/uuid пользователя в самом модуле —")
    _box_warn("файл тега обновится сам при следующем открытии раздела")
    _box_warn("«Управление тегами» (авто-регенерация при входе).")
    _box_row()
    _box_warn("Домен подписки — ОТДЕЛЬНЫЙ от Reality/NaiveProxy, иначе")
    _box_warn("конфликт порта 443. SNI-роутинг между ними не реализован.")
    _box_row()
    _box_info("Сертификат получаем через certbot --standalone и подключаем")
    _box_info("к Caddy статически — порт 80 этому сервису не нужен вообще,")
    _box_info("nginx останавливается только на пару секунд при выпуске/")
    _box_info("продлении сертификата (автоматически, через хуки certbot).")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def do_subscription_menu() -> None:
    """Точка входа из _core.py. Ctrl+C → возврат в главное меню VLESS."""
    while True:
        os.system("clear")
        installed = _is_installed()
        state = _load_state()

        r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
        svc_ok = r.stdout.strip() == "active"
        svc_str = (
            f"{GREEN}● настроен{NC}"   if installed and svc_ok else
            f"{RED}● ошибка{NC}"       if installed else
            f"{YELLOW}● не настроен{NC}"
        )

        _box_top("📨  ПОДПИСКА  •  Единая раздача конфигов")
        _box_row()
        _box_kv("[INFO] Статус:", svc_str)
        _box_info("Объединяет VLESS + NaiveProxy + Mieru в одну subscription-ссылку.")
        if installed:
            _box_kv("Домен:", f"{state.get('domain','—')}:{state.get('port', _DEFAULT_PORT)}")
            _box_kv("Тегов:", str(len(state.get("tags", {}))))
        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🔧  Настроить подписку (поддомен + TLS)")
        else:
            _box_item("1", "🔧  Перенастроить домен/порт")
            _box_item("2", "🏷️   Управление тегами")
            _box_item("3", "📊  Статус / логи")
            _box_sep()
            _box_item("8", f"{RED}🗑️   Удалить подписку{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: как работает подписка")
        _box_sep()
        _box_item("Q", "← Назад в главное меню VLESS")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _run_setup()
        elif ch == "2" and installed:
            _tags_menu()
        elif ch == "3" and installed:
            _show_status()
        elif ch == "8" and installed:
            _full_uninstall()
        elif ch == "g":
            _show_guide()
        elif ch in ("q", ""):
            break
