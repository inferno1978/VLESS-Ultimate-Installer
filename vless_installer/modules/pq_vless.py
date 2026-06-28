"""
vless_installer/modules/pq_vless.py
───────────────────────────────────────────────────────────────────────────────
Экспериментальный, полностью изолированный VLESS+REALITY инбаунд с
постквантовым VLESS Encryption (mlkem768x25519plus, через `xray vlessenc`)
и опциональной постквантовой подписью REALITY (ML-DSA-65, через `xray mldsa65`).

ИЗОЛЯЦИЯ — модуль НЕ трогает существующие места генерации REALITY-конфига:
  • Слушает на ОТДЕЛЬНОМ TCP-порту, напрямую (без Nginx / unix-socket /
    proxy_protocol / AWG-fwmark) — независимо от Режима A/B и состояния AWG.
    Исходящий трафик при этом всё равно идёт через существующие outbounds
    конфига (включая AWG fwmark, если он настроен) — это общий для всех
    инбаундов механизм xray, отдельно настраивать не нужно.
  • Переиспользует существующий REALITY-identity (dest/serverNames/
    privateKey/publicKey) с ДРУГИМ shortId — ровно по документированному
    назначению shortId («differentiation» инбаундов на одном REALITY-сайте).
  • Тех же пользователей (USERS_FILE) — отдельных учёток не создаёт. После
    первого включения автоматически продолжает получать изменения через
    уже существующий `_users_patch_config_no_restart()` (он патчит ЛЮБОЙ
    инбаунд с ключом "clients" в settings — наш в их числе).
  • Полностью опционален, по умолчанию выключен, ничего не меняет в уже
    работающих 5 местах генерации REALITY-конфига в _core.py.

КЛЮЧИ ГЕНЕРИРУЮТСЯ ОДНОКРАТНО И ПЕРСИСТЕНТНЫ. При восстановлении после
полной перегенерации config.json (см. restore_pq_vless_if_enabled) НИКОГДА
не генерируются заново — иначе уже выданные клиентам ссылки сломаются.
Пересоздание — только явным действием в меню, с явным предупреждением.

АРХИТЕКТУРА МОДУЛЯ — по образцу vless_installer/modules/mtproto.py:
полностью автономен (свои _run/_info/_warn/_log, никаких импортов из
_core.py на уровне модуля). _core.py обращается к этому модулю ИСКЛЮЧИТЕЛЬНО
отложенным (внутри тела функции) импортом, в двух местах:
  1. _rebuild_and_restart_xray() — восстановление инбаунда после полной
     перегенерации config.json (по аналогии с telemt_tproxy_emergency_restore,
     тем же приёмом: переинжекция ДО финального рестарта).
  2. _menu_network() — пункт меню [P].
Все нужные значения (домен, ключи REALITY, флаг XTLS, IP сервера и т.п.)
ПЕРЕДАЮТСЯ ЯВНО аргументами функций — модуль не читает глобали _core.py сам,
поэтому циклический импорт (как у warp.py) здесь в принципе не возникает.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import socket
import subprocess
import time
import urllib.parse
from pathlib import Path
from typing import Optional

from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back,
    RED, GREEN, BLUE, CYAN, YELLOW, DIM, NC,
)


# =============================================================================
#  ЛОКАЛЬНЫЕ ХЕЛПЕРЫ — без зависимости от _core.py (см. шапку файла)
# =============================================================================
LOG_FILE = Path("/var/log/vless-install.log")


def _log(line: str) -> None:
    try:
        with LOG_FILE.open("a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")
    except Exception:
        pass


def _info(msg: str) -> None:
    print(f"  {CYAN}→{NC}  {msg}")
    _log(f"[INFO] [pq_vless] {msg}")


def _warn(msg: str) -> None:
    print(f"  {YELLOW}⚠{NC}  {msg}")
    _log(f"[WARN] [pq_vless] {msg}")


def _success(msg: str) -> None:
    print(f"  {GREEN}✓{NC}  {msg}")
    _log(f"[OK] [pq_vless] {msg}")


def _run(cmd: list[str], capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return subprocess.run(cmd, **kw)
    except FileNotFoundError:
        if check:
            raise
        return subprocess.CompletedProcess(cmd, 127, stdout="", stderr=f"command not found: {cmd[0]}")


# =============================================================================
#  КОНСТАНТЫ — те же реальные пути, что используются по всему проекту
#  (vless_installer/_core.py: CONFIG_DIR, USERS_FILE; modules/mtproto.py:
#  XRAY_CONFIG_PATHS) — продублированы локально, чтобы модуль был полностью
#  автономен и не зависел от порядка импортов.
# =============================================================================
PQ_TAG            = "vless-pq-experimental"
PQ_DEFAULT_PORT   = 8443
STATE_FILE        = Path("/var/lib/xray-installer/state.json")
CONFIG_DIR        = Path("/etc/xray")
XRAY_CONFIG_PATHS = [CONFIG_DIR / "config.json", Path("/usr/local/etc/xray/config.json")]
USERS_FILE        = CONFIG_DIR / "users.json"

_PQ_STATE_KEYS = (
    "pq_vless_enabled", "pq_vless_port", "pq_vless_shortid",
    "pq_vless_decryption", "pq_vless_encryption",
    "pq_vless_mldsa65_enabled", "pq_vless_mldsa65_seed", "pq_vless_mldsa65_verify",
)


# =============================================================================
#  СОСТОЯНИЕ — общий state.json проекта, свои ключи, read-modify-write с flock
# =============================================================================
def pq_state_load() -> dict:
    """Возвращает только pq_vless_*-ключи из общего state.json (если есть)."""
    if not STATE_FILE.exists():
        return {}
    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception:
        return {}
    return {k: state.get(k) for k in _PQ_STATE_KEYS if k in state}


def pq_state_save(values: dict) -> None:
    """Атомарно обновляет ТОЛЬКО pq_vless_*-ключи в общем state.json.

    Перечитывает файл под эксклюзивной fcntl-блокировкой непосредственно
    перед записью — не затирает UUID пользователей Xray и любые другие
    ключи ядра, изменённые конкурентно."""
    if not STATE_FILE.exists():
        _warn(f"{STATE_FILE} не найден — состояние не сохранено")
        return
    try:
        with STATE_FILE.open("r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                content = f.read()
                state = json.loads(content) if content else {}
                for k in _PQ_STATE_KEYS:
                    if k in values:
                        state[k] = values[k]
                f.seek(0)
                f.truncate()
                f.write(json.dumps(state, indent=2, ensure_ascii=False))
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        _warn(f"Не удалось сохранить состояние: {e}")


# =============================================================================
#  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ: xray-бинарник, config.json, users.json, порт
# =============================================================================
def _find_xray_bin() -> Optional[str]:
    for candidate in ("/usr/local/bin/xray", "/usr/bin/xray"):
        if Path(candidate).exists():
            return candidate
    import shutil
    return shutil.which("xray")


def _xray_config_path() -> Optional[Path]:
    for p in XRAY_CONFIG_PATHS:
        if p.exists():
            return p
    return None


def _read_users(primary_uuid: str = "") -> list[dict]:
    """Список пользователей из USERS_FILE. Если файла нет/пуст, но передан
    primary_uuid (старые однопользовательские установки без users.json) —
    возвращает единственного пользователя с этим UUID."""
    if USERS_FILE.exists():
        try:
            data = json.loads(USERS_FILE.read_text())
            if isinstance(data, list) and data:
                return data
        except Exception:
            pass
    if primary_uuid:
        return [{"uuid": primary_uuid}]
    return []


def _port_is_free(port: int) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        s = socket.socket(family, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", port))
        except OSError:
            s.close()
            return False
        s.close()
    return True


def find_unused_port(preferred: int = PQ_DEFAULT_PORT) -> int:
    """preferred, если свободен, иначе следующий свободный (до +50)."""
    for candidate in range(preferred, preferred + 50):
        if _port_is_free(candidate):
            return candidate
    return preferred  # не нашли свободный — xray сам сообщит об ошибке на -test


def _gen_shortid(existing: str = "") -> str:
    """8-символьный (4 байта) hex shortId, отличный от existing."""
    while True:
        candidate = os.urandom(4).hex()
        if candidate != existing:
            return candidate


# =============================================================================
#  ГЕНЕРАЦИЯ КЛЮЧЕЙ — через сами xray vlessenc / xray mldsa65, без
#  самостоятельной сборки base64/строк (см. обоснование в обсуждении с
#  заказчиком: ручная сборка форматов вроде wgcf URL уже однажды привела
#  к багам — здесь используется только то, что реально печатает бинарник).
# =============================================================================
def generate_vlessenc_pair(xray_bin: str) -> tuple[Optional[str], Optional[str]]:
    """Запускает `xray vlessenc` (без аргументов; команда НЕинтерактивна —
    печатает оба варианта, X25519 и ML-KEM-768, без ожидания ввода) и
    извлекает decryption/encryption именно из блока
    'Authentication: ML-KEM-768, Post-Quantum' (не из классического X25519)."""
    r = _run([xray_bin, "vlessenc"], capture=True, check=False)
    if r.returncode != 0 or not r.stdout:
        _warn(f"xray vlessenc вернул ошибку: {(r.stderr or '').strip()[:200]}")
        return None, None

    parts = re.split(r'(?m)^Authentication:\s*(.+)$', r.stdout)
    pq_section: Optional[str] = None
    for i in range(1, len(parts), 2):
        # Ищем строго "ML-KEM-768" — заголовок X25519-блока тоже содержит
        # подстроку "Post-Quantum" (из "X25519, NOT Post-Quantum"), поэтому
        # проверка по "Post-Quantum" ловила бы неверный, классический блок.
        if "ML-KEM-768" in parts[i]:
            pq_section = parts[i + 1] if i + 1 < len(parts) else ""
            break
    if pq_section is None:
        _warn("Не нашёл секцию 'ML-KEM-768, Post-Quantum' в выводе xray vlessenc")
        return None, None

    dec_m = re.search(r'"decryption"\s*:\s*"([^"]+)"', pq_section)
    enc_m = re.search(r'"encryption"\s*:\s*"([^"]+)"', pq_section)
    if not dec_m or not enc_m:
        _warn("Не нашёл decryption/encryption в секции ML-KEM-768 вывода xray vlessenc")
        return None, None
    return dec_m.group(1), enc_m.group(1)


def generate_mldsa65_pair(xray_bin: str) -> tuple[Optional[str], Optional[str]]:
    """Запускает `xray mldsa65`, извлекает Seed (на сервер) / Verify (клиенту)."""
    r = _run([xray_bin, "mldsa65"], capture=True, check=False)
    if r.returncode != 0 or not r.stdout:
        _warn(f"xray mldsa65 вернул ошибку: {(r.stderr or '').strip()[:200]}")
        return None, None
    seed_m   = re.search(r'^Seed:\s*(\S+)', r.stdout, re.MULTILINE)
    verify_m = re.search(r'^Verify:\s*(\S+)', r.stdout, re.MULTILINE)
    if not seed_m or not verify_m:
        _warn("Не нашёл Seed/Verify в выводе xray mldsa65")
        return None, None
    return seed_m.group(1), verify_m.group(1)


# =============================================================================
#  ИНБАУНД — чистые функции над dict-конфигом, без I/O
# =============================================================================
def inject_pq_inbound(
    cfg: dict,
    *,
    port: int,
    decryption: str,
    shortid: str,
    reality_dest: str,
    domain: str,
    private_key: str,
    public_key: str,
    spiderx: str,
    users: list[dict],
    xtls_flow: str = "",
    mldsa65_seed: str = "",
) -> bool:
    """Добавляет/обновляет изолированный PQ VLESS+REALITY инбаунд в cfg
    (мутирует cfg на месте). Возвращает True, если конфиг изменён.

    Полностью независим от существующих инбаундов: отдельный порт, тот же
    REALITY dest/ключи (другой shortId), без Nginx/unix-socket/AWG-fwmark —
    эти механизмы общие на уровне outbounds/routing и наш инбаунд их
    автоматически использует, отдельно настраивать не нужно."""
    clients: list[dict] = []
    for u in users:
        client: dict = {"id": u["uuid"]}
        if u.get("email"):
            client["email"] = u["email"]
        if xtls_flow:
            client["flow"] = xtls_flow
        clients.append(client)
    if not clients:
        # Xray падает с пустым clients — невалидный placeholder держит
        # инбаунд валидным конфигом, но реально подключиться никто не сможет.
        clients = [{"id": "00000000-0000-0000-0000-000000000000"}]

    reality_settings: dict = {
        "show":        False,
        "dest":        f"{reality_dest or domain}:443",
        "xver":        0,
        "spiderX":     spiderx,
        "serverNames": [reality_dest or domain],
        "privateKey":  private_key,
        "publicKey":   public_key,
        "shortIds":    [shortid],
    }
    if mldsa65_seed:
        reality_settings["mldsa65Seed"] = mldsa65_seed

    new_inbound = {
        "tag":      PQ_TAG,
        "port":     port,
        "listen":   "::",
        "protocol": "vless",
        "settings": {
            "clients":    clients,
            "decryption": decryption,
        },
        "sniffing": {
            "enabled":      True,
            "destOverride": ["http", "tls"],
            "metadataOnly": False,
            "routeOnly":    False,
        },
        "streamSettings": {
            "network":         "tcp",
            "security":        "reality",
            "realitySettings": reality_settings,
        },
    }

    inbounds = cfg.setdefault("inbounds", [])
    for i, ib in enumerate(inbounds):
        if ib.get("tag") == PQ_TAG:
            if ib == new_inbound:
                return False
            inbounds[i] = new_inbound
            return True
    inbounds.append(new_inbound)
    return True


def remove_pq_inbound(cfg: dict) -> bool:
    """Убирает PQ-инбаунд из cfg (мутирует на месте). True, если был."""
    inbounds = cfg.get("inbounds", [])
    new_ib = [ib for ib in inbounds if ib.get("tag") != PQ_TAG]
    if len(new_ib) != len(inbounds):
        cfg["inbounds"] = new_ib
        return True
    return False


def has_pq_inbound(cfg: dict) -> bool:
    return any(ib.get("tag") == PQ_TAG for ib in cfg.get("inbounds", []))


# =============================================================================
#  ЗАПИСЬ С ПРОВЕРКОЙ — xray -test ПЕРЕД тем, как конфиг попадёт в реально
#  запущенный сервис (тот же приём, что _xray_write_and_test в mtproto.py)
# =============================================================================
def _write_and_test(cfg_path: Path, cfg: dict) -> Optional[str]:
    """Пишет конфиг и проверяет синтаксис через `xray run -test`.
    При провале — откатывает файл к прежнему содержимому. None = успех."""
    backup = cfg_path.read_text() if cfg_path.exists() else None
    try:
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    except Exception as e:
        return f"Не удалось записать {cfg_path}: {e}"

    xray_bin = _find_xray_bin()
    if xray_bin:
        r = _run([xray_bin, "run", "-test", "-config", str(cfg_path)], capture=True, check=False)
        if r.returncode != 0:
            if backup is not None:
                cfg_path.write_text(backup)
            return f"xray -test провалился: {(r.stderr or r.stdout).strip()[:300]}"
    return None


# =============================================================================
#  ПУБЛИЧНЫЙ API ВКЛЮЧЕНИЯ/ОТКЛЮЧЕНИЯ/ВОССТАНОВЛЕНИЯ
# =============================================================================
def enable_pq_vless(
    *,
    domain: str,
    reality_dest: str,
    private_key: str,
    public_key: str,
    spiderx: str,
    xtls_flow: str = "",
    with_mldsa65: bool = False,
    primary_uuid: str = "",
    port: Optional[int] = None,
) -> tuple[bool, str]:
    """Полная активация. Идемпотентна: повторный вызов с уже существующими
    ключами в state.json их не перегенерирует — переиспользует."""
    cfg_path = _xray_config_path()
    if not cfg_path:
        return False, "config.json Xray не найден — Xray не установлен"

    xray_bin = _find_xray_bin()
    if not xray_bin:
        return False, "Бинарник xray не найден"

    state = pq_state_load()
    users = _read_users(primary_uuid)
    if not users:
        return False, "Не найдено ни одного пользователя VLESS (users.json пуст/отсутствует)"

    decryption = state.get("pq_vless_decryption")
    encryption = state.get("pq_vless_encryption")
    if not decryption or not encryption:
        _info("Генерация постквантовой пары VLESS Encryption (xray vlessenc)...")
        decryption, encryption = generate_vlessenc_pair(xray_bin)
        if not decryption:
            return False, "Не удалось сгенерировать VLESS Encryption (см. предупреждения выше)"

    shortid = state.get("pq_vless_shortid") or _gen_shortid()
    pq_port = port or state.get("pq_vless_port") or find_unused_port()

    mldsa65_seed   = state.get("pq_vless_mldsa65_seed", "") or ""
    mldsa65_verify = state.get("pq_vless_mldsa65_verify", "") or ""
    if with_mldsa65 and not mldsa65_seed:
        _info("Генерация постквантовой подписи REALITY (xray mldsa65)...")
        mldsa65_seed, mldsa65_verify = generate_mldsa65_pair(xray_bin)
        if not mldsa65_seed:
            _warn("mldsa65 не сгенерирован — инбаунд будет без постквантовой подписи REALITY")
            with_mldsa65 = False

    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        return False, f"Не удалось прочитать {cfg_path}: {e}"

    changed = inject_pq_inbound(
        cfg, port=pq_port, decryption=decryption, shortid=shortid,
        reality_dest=reality_dest, domain=domain,
        private_key=private_key, public_key=public_key, spiderx=spiderx,
        users=users, xtls_flow=xtls_flow,
        mldsa65_seed=mldsa65_seed if with_mldsa65 else "",
    )

    if changed:
        err = _write_and_test(cfg_path, cfg)
        if err:
            return False, err
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        time.sleep(2)
        rs = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
        if (rs.stdout or "").strip() != "active":
            return False, "Xray не запустился после добавления PQ-инбаунда — проверьте: journalctl -u xray -n 30"

    pq_state_save({
        "pq_vless_enabled":         True,
        "pq_vless_port":            pq_port,
        "pq_vless_shortid":         shortid,
        "pq_vless_decryption":      decryption,
        "pq_vless_encryption":      encryption,
        "pq_vless_mldsa65_enabled": with_mldsa65,
        "pq_vless_mldsa65_seed":    mldsa65_seed if with_mldsa65 else "",
        "pq_vless_mldsa65_verify":  mldsa65_verify if with_mldsa65 else "",
    })
    return True, f"PQ VLESS-инбаунд активен на порту {pq_port}"


def disable_pq_vless() -> tuple[bool, str]:
    """Полное отключение. Идемпотентна. Ключи в state.json НЕ стираются —
    повторное включение восстановит ту же ссылку (если не запрошена
    явная перегенерация)."""
    cfg_path = _xray_config_path()
    if not cfg_path:
        pq_state_save({"pq_vless_enabled": False})
        return True, "config.json не найден — состояние сброшено"
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        return False, f"Не удалось прочитать {cfg_path}: {e}"

    changed = remove_pq_inbound(cfg)
    if changed:
        err = _write_and_test(cfg_path, cfg)
        if err:
            return False, err
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)

    pq_state_save({"pq_vless_enabled": False})
    return True, ("PQ VLESS-инбаунд отключён" if changed else "PQ-инбаунд не был активен")


def restore_pq_vless_if_enabled(
    *,
    domain: str,
    reality_dest: str,
    private_key: str,
    public_key: str,
    spiderx: str,
    xtls_flow: str = "",
    primary_uuid: str = "",
) -> Optional[tuple[bool, str]]:
    """Вызывается из _rebuild_and_restart_xray() ПОСЛЕ полной перегенерации
    config.json — generate_xray_config*() пишет конфиг с нуля и стирает
    любые дополнительные инбаунды (тот же случай, что и у Telemt tproxy).

    Если PQ-фича не была включена — возвращает None (не ошибка, просто
    неприменимо). Если была — восстанавливает её СОХРАНЁННЫМИ ключами,
    НИКОГДА не генерирует новые (иначе уже выданные клиентам ссылки
    сломаются)."""
    state = pq_state_load()
    if not state.get("pq_vless_enabled"):
        return None

    cfg_path = _xray_config_path()
    if not cfg_path:
        return False, "config.json не найден"
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        return False, f"Не удалось прочитать {cfg_path}: {e}"

    if has_pq_inbound(cfg):
        return True, "PQ-инбаунд уже на месте"

    decryption = state.get("pq_vless_decryption")
    shortid    = state.get("pq_vless_shortid")
    port       = state.get("pq_vless_port")
    if not (decryption and shortid and port):
        return False, "Сохранённое состояние PQ-инбаунда повреждено — отключите и включите заново"

    changed = inject_pq_inbound(
        cfg, port=port, decryption=decryption, shortid=shortid,
        reality_dest=reality_dest, domain=domain,
        private_key=private_key, public_key=public_key, spiderx=spiderx,
        users=_read_users(primary_uuid), xtls_flow=xtls_flow,
        mldsa65_seed=(state.get("pq_vless_mldsa65_seed", "") or "")
                     if state.get("pq_vless_mldsa65_enabled") else "",
    )
    if not changed:
        return True, "PQ-инбаунд не требовал изменений"

    err = _write_and_test(cfg_path, cfg)
    if err:
        return False, f"Восстановление PQ-инбаунда: {err}"
    return True, f"PQ-инбаунд восстановлен на порту {port}"


# =============================================================================
#  ССЫЛКА ДЛЯ КЛИЕНТА
# =============================================================================
def _build_pq_link(
    state: dict, *, server_ip: str, domain: str, public_key: str,
    fingerprint: str = "chrome", xtls_flow: str = "", country_flag: str = "",
    primary_uuid: str = "",
) -> Optional[str]:
    users = _read_users(primary_uuid)
    if not users:
        return None
    uuid_str   = users[0]["uuid"]
    encryption = state.get("pq_vless_encryption", "")
    port       = state.get("pq_vless_port", PQ_DEFAULT_PORT)
    shortid    = state.get("pq_vless_shortid", "")
    host       = server_ip or domain
    flag_prefix = f"{country_flag} " if country_flag and country_flag != "🌐" else ""
    label = urllib.parse.quote(f"{flag_prefix}{domain} [PQ]")

    mldsa_verify = state.get("pq_vless_mldsa65_verify", "") if state.get("pq_vless_mldsa65_enabled") else ""
    extra = f"&mldsa65Verify={mldsa_verify}" if mldsa_verify else ""
    flow_part = f"&flow={xtls_flow}" if xtls_flow else ""

    return (f"vless://{uuid_str}@{host}:{port}"
            f"?type=tcp&security=reality&pbk={public_key}&fp={fingerprint}"
            f"&sni={domain}&sid={shortid}&encryption={encryption}{flow_part}{extra}"
            f"#{label}")


# =============================================================================
#  ИНТЕРАКТИВНОЕ МЕНЮ — вызывается из _core.py с явно переданными параметрами
# =============================================================================
def do_manage_pq_vless(
    *,
    domain: str,
    reality_dest: str,
    private_key: str,
    public_key: str,
    spiderx: str,
    xtls_flow: str = "",
    server_ip: str = "",
    country_flag: str = "",
    fingerprint: str = "chrome",
    primary_uuid: str = "",
) -> None:
    """Меню управления экспериментальным постквантовым VLESS-инбаундом.
    Ничего не делает с существующими инбаундами/ссылками пользователя —
    полностью отдельная, опциональная функциональность."""
    while True:
        os.system("clear")
        state   = pq_state_load()
        enabled = bool(state.get("pq_vless_enabled"))
        port    = state.get("pq_vless_port", PQ_DEFAULT_PORT)
        mldsa   = bool(state.get("pq_vless_mldsa65_enabled"))

        print()
        _box_top("🧪  Постквантовый VLESS  (ЭКСПЕРИМЕНТАЛЬНО)")
        _box_row()
        _box_row(f"  Статус:   {GREEN+'включён'+NC if enabled else DIM+'выключен'+NC}")
        if enabled:
            _box_row(f"  Порт:     {CYAN}{port}{NC}")
            _box_row(f"  PQ-подпись REALITY (mldsa65): "
                      f"{GREEN+'да'+NC if mldsa else DIM+'нет'+NC}")
        _box_row()
        _box_sep()
        _box_row(f"  {YELLOW}⚠  Не все клиенты понимают VLESS Encryption / mldsa65 —{NC}")
        _box_row(f"  {YELLOW}   известны случаи отказа подключения у части клиентов.{NC}")
        _box_row(f"  {YELLOW}   Основная (текущая) ссылка продолжает работать как прежде.{NC}")
        _box_sep()
        if not enabled:
            _box_item("1", "Включить (сгенерировать ключи, поднять отдельный порт)")
        else:
            _box_item("1", "Показать ссылку для клиента")
            _box_item("2", "Отключить")
            _box_item("3", "Перегенерировать ключи (старая PQ-ссылка перестанет работать)")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            print()
            break

        if ch in ("0", "q", "Q", ""):
            break

        elif ch == "1" and not enabled:
            ans = input(f"{YELLOW}Включить также постквантовую подпись REALITY (mldsa65)? "
                        f"На некоторых сборках Xray известны баги с этим полем. [y/N]:{NC} ").strip().lower()
            ok, msg = enable_pq_vless(
                domain=domain, reality_dest=reality_dest,
                private_key=private_key, public_key=public_key, spiderx=spiderx,
                xtls_flow=xtls_flow, with_mldsa65=(ans == "y"), primary_uuid=primary_uuid,
            )
            (_success if ok else _warn)(msg)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "1" and enabled:
            link = _build_pq_link(
                state, server_ip=server_ip, domain=domain, public_key=public_key,
                fingerprint=fingerprint, xtls_flow=xtls_flow,
                country_flag=country_flag, primary_uuid=primary_uuid,
            )
            print()
            if link:
                _box_row(f"{GREEN}Постквантовая ссылка (ЭКСПЕРИМЕНТАЛЬНАЯ):{NC}")
                _box_row(link)
            else:
                _warn("Не удалось собрать ссылку — нет пользователей.")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2" and enabled:
            ans = input(f"{YELLOW}Отключить постквантовый инбаунд? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                ok, msg = disable_pq_vless()
                (_success if ok else _warn)(msg)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3" and enabled:
            ans = input(f"{RED}Старая постквантовая ссылка перестанет работать у всех, "
                        f"кому вы её уже выдали. Продолжить? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                pq_state_save({
                    "pq_vless_decryption": "", "pq_vless_encryption": "",
                    "pq_vless_mldsa65_seed": "", "pq_vless_mldsa65_verify": "",
                })
                ok, msg = enable_pq_vless(
                    domain=domain, reality_dest=reality_dest,
                    private_key=private_key, public_key=public_key, spiderx=spiderx,
                    xtls_flow=xtls_flow, with_mldsa65=mldsa, primary_uuid=primary_uuid,
                )
                (_success if ok else _warn)(msg)
            input(f"{BLUE}Нажмите Enter...{NC}")

        else:
            _warn("Неверный выбор.")
            time.sleep(1)
