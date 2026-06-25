#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hybrid_addon.py — гибридная надстройка Mieru над Xray на Entry-ноде каскада.

Идея: внешний клиент подключается к Mieru (mita), Mieru расшифровывает
и пересылает трафик через SOCKS5 на localhost в Xray, а Xray дальше
рулит исходящим (Режим B / Smart Balancer / что угодно ниже) — точно
так же, как и раньше. Меняется ТОЛЬКО внешний inbound Xray
(vless -> socks на 127.0.0.1), вся остальная логика каскада не трогается.

Не трогает _core.py. Не требует pip — только стандартная библиотека Python.

Использование:
    sudo python3 hybrid_addon.py                          # установка (с подтверждением + выбором портов)
    sudo python3 hybrid_addon.py --dry-run                # только диагностика, без изменений
    sudo python3 hybrid_addon.py --port 8443               # если внешний VLESS-порт не 443
    sudo python3 hybrid_addon.py --mieru-udp-port 51820     # если 444 уже занят чем-то
    sudo python3 hybrid_addon.py --transport tcp            # только TCP-вариант Mieru
    sudo python3 hybrid_addon.py --yes                      # без вопросов, дефолтные порты
    sudo python3 hybrid_addon.py --rollback                 # откатить всё назад
"""

import argparse
import json
import os
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

# ───────────────────────── Стиль вывода (как в основном проекте) ─────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
NC = "\033[0m"

OK = f"{GREEN}✓{NC}"
ERR = f"{RED}✗{NC}"
ARROW = f"{CYAN}→{NC}"
WARN = f"{YELLOW}⚠{NC}"


def c_cyan(msg: str) -> None:
    print(f"{ARROW} {msg}")


def c_green(msg: str) -> None:
    print(f"{OK} {msg}")


def c_red(msg: str) -> None:
    print(f"{ERR} {msg}")


def c_yellow(msg: str) -> None:
    print(f"{WARN} {msg}")


def box_header(title: str) -> None:
    width = 64
    print(f"{CYAN}{'═' * width}{NC}")
    print(f"{CYAN}║{NC} {BOLD}{title.center(width - 4)}{NC} {CYAN}║{NC}")
    print(f"{CYAN}{'═' * width}{NC}")


def die(msg: str, code: int = 1) -> None:
    c_red(msg)
    _log("ERROR", msg)
    sys.exit(code)


def confirm(prompt: str) -> bool:
    try:
        ans = input(f"{BOLD}{prompt} [y/N]: {NC}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans in ("y", "yes", "д", "да")


# ───────────────────────── Логирование в общий лог проекта ─────────────────────────
INSTALL_LOG = "/var/log/vless-install.log"


def _log(level: str, msg: str) -> None:
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [hybrid_addon] [{level}] {msg}\n"
    try:
        with open(INSTALL_LOG, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass  # лог не критичен для работы скрипта


# ───────────────────────── Пути / состояние ─────────────────────────
STATE_DIR = Path("/var/lib/xray-installer")
STATE_FILE = STATE_DIR / "hybrid_mieru_state.json"

XRAY_CONFIG_CANDIDATES = [
    Path("/etc/xray/config.json"),          # путь, которым пользуется сам проект
    Path("/usr/local/etc/xray/config.json"),  # типовой дефолт community-сборок Xray
]

MITA_BIN = Path("/usr/bin/mita")
MITA_CONFIG_PATH = Path("/etc/mita/hybrid_server_config.json")

LOOPBACK_SOCKS_PORT = 1080


def ask_port(label: str, default: int, taken: set = None) -> int:
    taken = taken or set()
    while True:
        try:
            raw = input(f"{label} [{default}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not raw:
            port = default
        elif raw.isdigit() and 1 <= int(raw) <= 65535:
            port = int(raw)
        else:
            print("  Введи число от 1 до 65535 (или просто Enter для значения по умолчанию).")
            continue
        if port in taken:
            print(f"  Порт {port} уже занят другим транспортом в этой установке, выбери другой.")
            continue
        return port


def check_port_listening(port: int, proto: str) -> tuple:
    """Возвращает (occupied: bool, detail: str) — занят ли порт прямо сейчас.
    Сначала пробуем ss (если есть), при любой проблеме с ним — честный bind-тест,
    который не зависит вообще ни от каких внешних утилит."""
    if shutil.which("ss"):
        flag = "-tlnp" if proto == "tcp" else "-ulnp"
        r = run(["ss", "-H", flag, "sport", "=", f":{port}"])
        if r.returncode == 0:
            out = r.stdout.strip()
            return (True, out.splitlines()[0]) if out else (False, "")
        # если синтаксис фильтра не подошёл в этой версии ss — едем на bind-тест ниже

    fam = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    s = socket.socket(socket.AF_INET, fam)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        return False, ""
    except OSError:
        return True, "(детали недоступны: ss не сработал/не установлен, но порт точно занят — bind не прошёл)"
    finally:
        s.close()


def run(cmd, **kwargs):
    """Обёртка над subprocess с единым поведением."""
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def require_root() -> None:
    if os.geteuid() != 0:
        die("Запусти скрипт от root (sudo python3 hybrid_addon.py)")


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def load_state() -> dict:
    if not STATE_FILE.exists():
        die(f"Файл состояния {STATE_FILE} не найден — похоже, аддон ещё не устанавливался.")
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


# ───────────────────────── Шаг 1: поиск и анализ Xray config.json ─────────────────────────
def find_xray_config() -> Path:
    for p in XRAY_CONFIG_CANDIDATES:
        if p.exists():
            return p
    die(
        "Не нашёл config.json Xray ни по одному из известных путей: "
        + ", ".join(str(p) for p in XRAY_CONFIG_CANDIDATES)
        + ". Укажи путь вручную через --xray-config."
    )


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        die(f"Не удалось прочитать/распарсить {path}: {e}")


def describe_inbound(ib: dict) -> str:
    tag = ib.get("tag", "<без тега>")
    port = ib.get("port", "?")
    listen = ib.get("listen", "0.0.0.0")
    proto = ib.get("protocol", "?")
    ss = ib.get("streamSettings", {}) or {}
    security = ss.get("security", "none")
    network = ss.get("network", "tcp")
    return (f"tag={tag!r}  protocol={proto}  listen={listen}  port={port}  "
            f"network={network}  security={security}")


def find_vless_inbounds(config: dict) -> list:
    return [ib for ib in config.get("inbounds", []) if ib.get("protocol") == "vless"]


def pick_target_inbound(config: dict, port: int, inbound_tag: str = None) -> dict:
    """Находит ИМЕННО ОДНО подходящее vless-входящее соединение на заданном порту.
    Если совпадений 0 или больше 1 — останавливаемся, не угадываем
    (если не передан inbound_tag — тогда фильтруем явно по тегу)."""
    vless_inbounds = find_vless_inbounds(config)

    if not vless_inbounds:
        die("В config.json не найдено ни одного inbound с protocol == 'vless'. "
            "Возможно, аддон уже применён ранее, или путь к конфигу неверный.")

    c_cyan(f"Найдено vless-инбаундов всего: {len(vless_inbounds)}")
    for ib in vless_inbounds:
        print(f"    {DIM}{describe_inbound(ib)}{NC}")

    if inbound_tag:
        matches = [ib for ib in vless_inbounds if ib.get("tag") == inbound_tag]
        if len(matches) != 1:
            die(f"По тегу {inbound_tag!r} найдено {len(matches)} совпадений (нужно ровно 1). "
                f"Проверь список выше и --inbound-tag.")
        return matches[0]

    matches = [ib for ib in vless_inbounds if int(ib.get("port", -1)) == port]

    if len(matches) == 0:
        die(
            f"Ни один vless-инбаунд не слушает порт {port} напрямую.\n"
            f"  Это может означать xHTTP-режим за Nginx (Xray слушает внутренний порт,\n"
            f"  а Nginx терминирует TLS снаружи на {port}). В этом случае внешний\n"
            f"  TCP/{port} останется у Nginx, конфликта с Mieru (TCP/{port}) НЕ будет,\n"
            f"  но тебе нужно вручную указать внутренний порт Xray через --port,\n"
            f"  чтобы скрипт знал, какой именно inbound переключать на SOCKS-петлю,\n"
            f"  либо указать инбаунд явно через --inbound-tag <tag> (см. список выше)."
        )
    if len(matches) > 1:
        die(
            f"На порту {port} нашлось {len(matches)} vless-инбаундов — однозначно "
            f"выбрать не могу. Уточни через --inbound-tag <tag> (см. список выше)."
        )

    target = matches[0]
    sec = (target.get("streamSettings", {}) or {}).get("security", "none")
    if sec == "reality":
        c_green(f"Режим обнаружен: REALITY напрямую на {port}/TCP — ожидаемый сценарий.")
    elif sec == "tls":
        c_yellow(
            f"Режим обнаружен: streamSettings.security = 'tls'. Похоже на TLS-режим "
            f"(возможно, xHTTP за Nginx или просто TLS напрямую). Проверь глазами, "
            f"что это действительно тот инбаунд, который нужно сделать внутренним."
        )
    else:
        c_yellow(f"streamSettings.security = {sec!r} — нестандартно, проверь конфиг глазами.")

    return target


# ───────────────────────── Шаг 2: бэкап и конвертация inbound ─────────────────────────
def backup_config(xray_config_path: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = xray_config_path.with_name(f"{xray_config_path.name}.bak-{ts}")
    shutil.copy2(xray_config_path, backup_path)
    # держим также "последний" бэкап под предсказуемым именем — как договорено в проекте
    latest = xray_config_path.with_name(f"{xray_config_path.name}.bak")
    shutil.copy2(xray_config_path, latest)
    c_green(f"Бэкап сохранён: {backup_path}")
    return backup_path


def convert_inbound_to_socks_loopback(target: dict) -> dict:
    """Мутирует inbound in-place, возвращает ГЛУБОКУЮ копию оригинала для отката."""
    original = json.loads(json.dumps(target))  # глубокая копия

    sniffing = target.get("sniffing")  # ОБЯЗАТЕЛЬНО сохраняем — на нём может
                                        # держаться роутинг по доменам ниже по цепочке

    target.clear()
    target["tag"] = original.get("tag", "vless-in")  # тег НЕ меняем — на нём
                                                       # держатся routing.rules
    target["listen"] = "127.0.0.1"
    target["port"] = LOOPBACK_SOCKS_PORT
    target["protocol"] = "socks"
    target["settings"] = {
        "auth": "noauth",   # безопасно: слушаем только loopback, снаружи недоступно
        "udp": True,
    }
    if sniffing is not None:
        target["sniffing"] = sniffing

    return original


def validate_xray_config(path: Path) -> bool:
    xray_bin = shutil.which("xray") or "/usr/local/bin/xray"
    if not Path(xray_bin).exists():
        c_yellow(f"Не нашёл бинарник xray ({xray_bin}) — пропускаю preflight-валидацию.")
        return True
    r = run([xray_bin, "run", "-test", "-config", str(path)])
    if r.returncode != 0:
        c_red("Xray не принял новый конфиг (preflight-тест провален):")
        print(f"{DIM}{r.stdout}\n{r.stderr}{NC}")
        return False
    c_green("Preflight-валидация конфига Xray пройдена (xray run -test).")
    return True


def restart_service(name: str) -> bool:
    r = run(["systemctl", "restart", name])
    if r.returncode != 0:
        c_red(f"systemctl restart {name} завершился с ошибкой: {r.stderr.strip()}")
        return False
    time.sleep(1.5)
    r = run(["systemctl", "is-active", name])
    active = r.stdout.strip() == "active"
    if active:
        c_green(f"Служба {name} активна.")
    else:
        c_red(f"Служба {name} НЕ активна после restart (статус: {r.stdout.strip()!r}).")
    return active


def apply_xray_change(xray_config_path: Path, config: dict, backup_path: Path) -> bool:
    tmp_fd, tmp_name = tempfile.mkstemp(prefix="xray_config_", suffix=".json",
                                         dir=str(xray_config_path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    except Exception as e:
        die(f"Не удалось записать временный конфиг: {e}")

    if not validate_xray_config(tmp_path):
        tmp_path.unlink(missing_ok=True)
        c_red("Изменения НЕ применены — оригинальный config.json не тронут.")
        return False

    shutil.move(str(tmp_path), str(xray_config_path))
    c_cyan("Перезапускаю Xray с новым inbound...")
    if restart_service("xray"):
        return True

    # ── автоматический rollback, если Xray не поднялся ──
    c_yellow("Откатываю config.json из бэкапа и перезапускаю Xray...")
    shutil.copy2(backup_path, xray_config_path)
    restart_service("xray")
    c_red("Изменения отменены автоматически — прежний VLESS-инбаунд восстановлен.")
    return False


# ───────────────────────── Шаг 3: установка Mieru (mita) через .deb ─────────────────────────
def detect_arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    die(f"Неподдерживаемая архитектура: {m} (поддерживаются amd64/arm64)")


def github_api_get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "vless-ultimate-hybrid-addon"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        die(f"Не удалось обратиться к GitHub API ({url}): {e}")


def download_file(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "vless-ultimate-hybrid-addon"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as out:
            shutil.copyfileobj(resp, out)
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        die(f"Не удалось скачать {url}: {e}")


def install_mita() -> None:
    if MITA_BIN.exists():
        c_green(f"Mieru (mita) уже установлен: {MITA_BIN} — пропускаю установку.")
        return

    c_cyan("Mieru не найден, ставлю с нуля...")
    arch = detect_arch()
    release = github_api_get("https://api.github.com/repos/enfein/mieru/releases/latest")
    tag = release.get("tag_name", "?")
    assets = release.get("assets", [])

    deb_asset = next(
        (a for a in assets if a["name"].endswith(f"_{arch}.deb") and a["name"].startswith("mita_")),
        None,
    )
    if deb_asset is None:
        die(f"Не нашёл .deb-пакет mita для архитектуры {arch} в релизе {tag}. "
            f"Доступные ассеты: {[a['name'] for a in assets]}")

    c_cyan(f"Скачиваю {deb_asset['name']} (релиз {tag})...")
    with tempfile.TemporaryDirectory() as tmpdir:
        deb_path = Path(tmpdir) / deb_asset["name"]
        download_file(deb_asset["browser_download_url"], deb_path)

        r = run(["dpkg", "-i", str(deb_path)])
        if r.returncode != 0:
            c_yellow("dpkg -i вернул ошибку, пробую дотянуть зависимости через apt-get -f...")
            run(["apt-get", "install", "-f", "-y"])
            r2 = run(["dpkg", "-i", str(deb_path)])
            if r2.returncode != 0:
                die(f"Установка mita не удалась:\n{r.stderr}\n{r2.stderr}")

    if not MITA_BIN.exists():
        die("dpkg отработал без ошибок, но /usr/bin/mita не появился — что-то нестандартное.")

    c_green(f"Mieru (mita) {tag} установлен.")
    _log("SUCCESS", f"mita {tag} установлен для {arch}")


# ───────────────────────── Шаг 4: конфиг Mieru (server.json) ─────────────────────────
def gen_credentials() -> tuple:
    login = "u_" + secrets.token_hex(4)
    password = secrets.token_urlsafe(18)
    return login, password


def build_mita_config(transport: str, tcp_port: int, udp_port: int) -> tuple:
    """Возвращает (config_dict, creds_dict) — creds для финального вывода пользователю."""
    port_bindings = []
    users = []
    creds = {}

    if transport in ("tcp", "both"):
        login, pwd = gen_credentials()
        port_bindings.append({"port": tcp_port, "protocol": "TCP"})
        users.append({"name": login, "password": pwd})
        creds["tcp"] = {"port": tcp_port, "login": login, "password": pwd}

    if transport in ("udp", "both"):
        login, pwd = gen_credentials()
        port_bindings.append({"port": udp_port, "protocol": "UDP"})
        users.append({"name": login, "password": pwd})
        creds["udp"] = {"port": udp_port, "login": login, "password": pwd}

    config = {
        "portBindings": port_bindings,
        "users": users,
        "loggingLevel": "INFO",
        "egress": {
            "proxies": [
                {
                    "name": "xray-local",
                    "protocol": "SOCKS5_PROXY_PROTOCOL",
                    "host": "127.0.0.1",
                    "port": LOOPBACK_SOCKS_PORT,
                }
            ],
            "rules": [
                {
                    "ipRanges": ["*"],
                    "domainNames": ["*"],
                    "action": "PROXY",
                    "proxyNames": ["xray-local"],
                }
            ],
        },
    }
    return config, creds


def apply_mita_config(config: dict) -> bool:
    MITA_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    MITA_CONFIG_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")

    # На случай свежей установки служба может быть ещё не запущена постинстом
    run(["systemctl", "start", "mita"])
    time.sleep(1)

    r = run(["mita", "apply", "config", str(MITA_CONFIG_PATH)])
    if r.returncode != 0:
        c_red(f"mita apply config упал: {r.stderr.strip() or r.stdout.strip()}")
        return False
    c_green("Конфиг Mieru применён (mita apply config).")

    c_cyan("Перезапускаю Mieru с новыми портами/пользователями...")
    return restart_service("mita")


# ───────────────────────── Шаг 5: файрвол ─────────────────────────
def detect_firewall() -> str:
    if shutil.which("ufw"):
        r = run(["ufw", "status"])
        if "Status: active" in r.stdout:
            return "ufw"
    if shutil.which("firewall-cmd"):
        r = run(["firewall-cmd", "--state"])
        if r.stdout.strip() == "running":
            return "firewalld"
    if shutil.which("iptables"):
        return "iptables"
    return "none"


def open_port(fw: str, port: int, proto: str) -> str:
    """Возвращает строку-команду отката (или '' если открывать не пришлось)."""
    if fw == "ufw":
        r = run(["ufw", "status"])
        rule = f"{port}/{proto}"
        if rule in r.stdout:
            c_green(f"ufw: {rule} уже открыт.")
            return ""
        run(["ufw", "allow", rule])
        c_green(f"ufw: открыт {rule}.")
        return f"ufw delete allow {rule}"

    if fw == "firewalld":
        check = run(["firewall-cmd", "--zone=public", "--query-port", f"{port}/{proto}"])
        if check.returncode == 0:
            c_green(f"firewalld: {port}/{proto} уже открыт.")
            return ""
        run(["firewall-cmd", "--zone=public", f"--add-port={port}/{proto}", "--permanent"])
        run(["firewall-cmd", "--reload"])
        c_green(f"firewalld: открыт {port}/{proto}.")
        return f"firewall-cmd --zone=public --remove-port={port}/{proto} --permanent && firewall-cmd --reload"

    if fw == "iptables":
        check = run(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])
        if check.returncode == 0:
            c_green(f"iptables: правило для {port}/{proto} уже есть.")
            return ""
        run(["iptables", "-I", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"])
        # сохранение правил — best effort, разные дистрибутивы по-разному
        if shutil.which("netfilter-persistent"):
            run(["netfilter-persistent", "save"])
        elif shutil.which("iptables-save") and Path("/etc/iptables/rules.v4").parent.exists():
            r = run(["iptables-save"])
            try:
                Path("/etc/iptables/rules.v4").write_text(r.stdout)
            except OSError:
                c_yellow("Не удалось сохранить iptables-правила в файл — переживут только до reboot.")
        c_green(f"iptables: открыт {port}/{proto}.")
        return f"iptables -D INPUT -p {proto} --dport {port} -j ACCEPT"

    c_yellow(f"Файрвол не определён — открой {port}/{proto} вручную, если трафик не идёт.")
    return ""


# ───────────────────────── Шаг 6: самопроверка SOCKS5 (без сторонних либ) ─────────────────────────
def selftest_socks5(host="127.0.0.1", port=LOOPBACK_SOCKS_PORT, timeout=4) -> bool:
    """Минимальный SOCKS5-хендшейк + CONNECT, чтобы убедиться, что Xray-инбаунд
    на самом деле принимает соединения. Не проверяет путь до интернета целиком —
    это просто smoke-test локального моста."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(b"\x05\x01\x00")  # версия 5, 1 метод, no-auth
            resp = s.recv(2)
            if resp != b"\x05\x00":
                return False
            # CONNECT 1.1.1.1:80
            req = b"\x05\x01\x00\x01" + socket.inet_aton("1.1.1.1") + (80).to_bytes(2, "big")
            s.sendall(req)
            resp = s.recv(10)
            return len(resp) >= 2 and resp[1] == 0x00
    except OSError:
        return False


# ───────────────────────── Откат ─────────────────────────
def do_rollback() -> None:
    state = load_state()
    box_header("ОТКАТ HYBRID MIERU ADDON")

    xray_config_path = Path(state["xray_config_path"])
    backup_path = Path(state["backup_path"])

    if backup_path.exists():
        shutil.copy2(backup_path, xray_config_path)
        c_green(f"config.json восстановлен из {backup_path}")
        restart_service("xray")
    else:
        c_red(f"Бэкап {backup_path} не найден — config.json НЕ восстановлен, проверь руками.")

    run(["systemctl", "stop", "mita"])
    run(["systemctl", "disable", "mita"])
    c_green("Mieru (mita) остановлен и снят с автозагрузки.")

    for rollback_cmd in state.get("firewall_rollback", []):
        if rollback_cmd:
            run(rollback_cmd.split())
    c_green("Правила файрвола, добавленные аддоном, удалены (если были).")

    STATE_FILE.unlink(missing_ok=True)
    c_green("Готово. Можешь проверить, что прежний VLESS-доступ снова работает.")
    _log("SUCCESS", "rollback hybrid_addon выполнен")


# ───────────────────────── Финальный вывод ─────────────────────────
def get_public_ip() -> str:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                ip = resp.read().decode().strip()
                if ip:
                    return ip
        except (urllib.error.URLError, urllib.error.HTTPError):
            continue
    return "<не удалось определить, посмотри сам: curl ifconfig.me>"


def print_summary(creds: dict) -> None:
    ip = get_public_ip()
    box_header("MIERU HYBRID ADDON — ГОТОВО")
    print(f"  {BOLD}Сервер (IP):{NC} {ip}")
    if "tcp" in creds:
        print(f"\n  {BOLD}TCP-вариант{NC}")
        print(f"    Порт:     {creds['tcp']['port']}/tcp")
        print(f"    Логин:    {creds['tcp']['login']}")
        print(f"    Пароль:   {creds['tcp']['password']}")
    if "udp" in creds:
        print(f"\n  {BOLD}UDP-вариант{NC}")
        print(f"    Порт:     {creds['udp']['port']}/udp")
        print(f"    Логин:    {creds['udp']['login']}")
        print(f"    Пароль:   {creds['udp']['password']}")
    print(f"\n  {DIM}Протокол клиента в Mieru: mieru / profile с этими данными.{NC}")
    print(f"  {DIM}Откат в любой момент: sudo python3 hybrid_addon.py --rollback{NC}\n")


# ───────────────────────── main ─────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="Mieru hybrid addon для VLESS-Ultimate-Installer")
    parser.add_argument("--port", type=int, default=443,
                         help="Текущий внешний порт VLESS-инбаунда, который нужно "
                              "освободить (по умолчанию 443)")
    parser.add_argument("--transport", choices=["tcp", "udp", "both"], default="both",
                         help="Какой транспорт Mieru разворачивать")
    parser.add_argument("--mieru-tcp-port", type=int, default=None,
                         help="TCP-порт Mieru снаружи (по умолчанию = --port, "
                              "т.е. займёт освободившийся от Xray)")
    parser.add_argument("--mieru-udp-port", type=int, default=None,
                         help="UDP-порт Mieru снаружи (по умолчанию = --port + 1)")
    parser.add_argument("--xray-config", type=str, default=None,
                         help="Явный путь к config.json Xray")
    parser.add_argument("--inbound-tag", type=str, default=None,
                         help="Явно указать тег инбаунда, если по порту найдено 0 или 2+ совпадений")
    parser.add_argument("--dry-run", action="store_true",
                         help="Только показать, что найдено, без изменений")
    parser.add_argument("--yes", "-y", action="store_true",
                         help="Не спрашивать подтверждение и не предлагать выбор портов интерактивно")
    parser.add_argument("--rollback", action="store_true",
                         help="Откатить ранее применённые изменения")
    args = parser.parse_args()

    require_root()

    if args.rollback:
        do_rollback()
        return

    box_header("MIERU HYBRID ADDON — УСТАНОВКА")

    xray_config_path = Path(args.xray_config) if args.xray_config else find_xray_config()
    c_cyan(f"Использую конфиг Xray: {xray_config_path}")
    config = load_json(xray_config_path)

    target = pick_target_inbound(config, args.port, args.inbound_tag)

    # ── выбор портов Mieru: явные флаги > интерактивный выбор > дефолты ──
    want_tcp = args.transport in ("tcp", "both")
    want_udp = args.transport in ("udp", "both")

    tcp_port = args.mieru_tcp_port if args.mieru_tcp_port is not None else args.port
    udp_port = args.mieru_udp_port if args.mieru_udp_port is not None else args.port + 1

    if not args.yes and not args.dry_run:
        print()
        c_cyan("Выбор портов для Mieru (Enter — оставить значение по умолчанию):")
        taken = set()
        if want_tcp:
            if args.mieru_tcp_port is None:
                tcp_port = ask_port("  TCP-порт Mieru", tcp_port, taken=taken)
            taken.add(tcp_port)
        if want_udp:
            if args.mieru_udp_port is None:
                udp_port = ask_port("  UDP-порт Mieru", udp_port, taken=taken)
            taken.add(udp_port)

    if want_tcp and want_udp and tcp_port == udp_port:
        die(f"TCP- и UDP-порт совпадают ({tcp_port}) — это разные транспорты, "
            f"но порту всё равно нужно быть разным, чтобы не путаться. Укажи "
            f"--mieru-tcp-port / --mieru-udp-port явно.")

    # ── ранняя проверка UDP-порта: он не зависит от текущего Xray, можно
    #    проверить прямо сейчас, ДО каких-либо изменений ──
    if want_udp:
        occupied, detail = check_port_listening(udp_port, "udp")
        if occupied:
            die(f"UDP-порт {udp_port} уже занят:\n  {detail}\n"
                f"  Выбери другой через --mieru-udp-port (ничего ещё не менялось).")

    c_cyan(f"Итоговые порты Mieru: "
           f"{f'TCP={tcp_port} ' if want_tcp else ''}{f'UDP={udp_port}' if want_udp else ''}")

    if args.dry_run:
        c_cyan("Dry-run: изменений не делаю, это была только диагностика.")
        return

    print()
    c_yellow("Будет изменено: указанный inbound станет SOCKS-петлёй на 127.0.0.1:"
             f"{LOOPBACK_SOCKS_PORT}, протокол сменится с vless на socks.")
    c_yellow("Внешний доступ по старому VLESS-линку на этом порту ПЕРЕСТАНЕТ работать "
             "— вместо него будет доступ через Mieru.")
    if not args.yes and not confirm("Продолжить?"):
        c_cyan("Отменено пользователем, ничего не тронуто.")
        return

    backup_path = backup_config(xray_config_path)
    original_inbound = convert_inbound_to_socks_loopback(target)

    if not apply_xray_change(xray_config_path, config, backup_path):
        die("Установка прервана на шаге Xray — Mieru НЕ устанавливался, прод не тронут "
            "(или уже автоматически восстановлен).")

    # ── теперь, когда Xray уже освободил порт, проверяем TCP ещё раз:
    #    если порт всё равно занят — значит, его перехватил кто-то ещё, и
    #    нужно откатить Xray, чтобы не остаться вообще без входа ──
    if want_tcp:
        occupied, detail = check_port_listening(tcp_port, "tcp")
        if occupied:
            c_red(f"TCP-порт {tcp_port} занят чем-то ещё после освобождения Xray:\n  {detail}")
            c_yellow("Откатываю Xray обратно, чтобы не остаться без входа вообще...")
            shutil.copy2(backup_path, xray_config_path)
            restart_service("xray")
            die("Установка прервана — старый VLESS-инбаунд восстановлен. "
                "Разберись, что заняло порт, и попробуй снова.")

    install_mita()

    mita_config, creds = build_mita_config(args.transport, tcp_port, udp_port)

    if not apply_mita_config(mita_config):
        c_red("Mieru не поднялся с новым конфигом. Откатываю Xray, чтобы не остаться без входа вообще.")
        shutil.copy2(backup_path, xray_config_path)
        restart_service("xray")
        die("Установка прервана — старый VLESS-инбаунд восстановлен, Mieru не используется.")

    fw = detect_firewall()
    c_cyan(f"Файрвол: {fw}")
    firewall_rollback = []
    if want_tcp:
        firewall_rollback.append(open_port(fw, tcp_port, "tcp"))
    if want_udp:
        firewall_rollback.append(open_port(fw, udp_port, "udp"))

    c_cyan("Проверяю локальный SOCKS-мост (Xray)...")
    if selftest_socks5():
        c_green("SOCKS5-мост на 127.0.0.1:1080 отвечает корректно.")
    else:
        c_yellow("SOCKS5-мост не ответил как ожидалось — не критично для установки, "
                 "но стоит проверить логи Xray, прежде чем давать ссылку клиентам.")

    save_state({
        "xray_config_path": str(xray_config_path),
        "backup_path": str(backup_path),
        "inbound_tag": original_inbound.get("tag"),
        "firewall_rollback": firewall_rollback,
        "transport": args.transport,
        "tcp_port": tcp_port if want_tcp else None,
        "udp_port": udp_port if want_udp else None,
        "created": datetime.now().isoformat(),
    })

    print_summary(creds)
    _log("SUCCESS", "hybrid_addon установлен успешно")


if __name__ == "__main__":
    main()


# ───────────────────────── Точка входа из меню установщика (раздел 1) ─────────────────────────
# main() выше НЕ ТРОГАЕМ — это самостоятельный CLI (sudo python3 hybrid_addon.py),
# им можно продолжать пользоваться напрямую как раньше.
#
# Ниже — отдельная обёртка для интерактивного подменю _core.py. Повторяет тот же
# порядок шагов, что и install-ветка main(), и дёргает те же готовые функции выше
# (find_xray_config, pick_target_inbound, install_mita, build_mita_config и т.д.),
# но без argparse и с возвратом в меню (а не sys.exit) при ошибке на любом шаге —
# многие хелперы выше вызывают die(), а die() делает sys.exit(), что в контексте
# CLI нормально, а в контексте интерактивного меню убило бы весь установщик.

def _menu_status() -> dict:
    """Текущее состояние аддона для отображения в меню. Не падает, если файла нет/он битый."""
    if not STATE_FILE.exists():
        return {"installed": False}
    try:
        st = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        st["installed"] = True
        return st
    except (OSError, json.JSONDecodeError):
        return {"installed": False, "corrupt": True}


def _menu_install(default_port: int = 443) -> None:
    """Интерактивная установка для меню — те же шаги, что в main(), но без argparse
    и без падения всего процесса при die() на промежуточных шагах."""
    box_header("MIERU HYBRID ADDON — УСТАНОВКА")

    raw = input(f"Текущий внешний порт VLESS-инбаунда, который нужно освободить [{default_port}]: ").strip()
    port = int(raw) if raw.isdigit() and 1 <= int(raw) <= 65535 else default_port

    print()
    c_cyan("Транспорт Mieru: 1) both (по умолчанию)  2) tcp  3) udp")
    t_raw = input("Выбор [1]: ").strip()
    transport = {"2": "tcp", "3": "udp"}.get(t_raw, "both")

    try:
        xray_config_path = find_xray_config()
        c_cyan(f"Использую конфиг Xray: {xray_config_path}")
        config = load_json(xray_config_path)
        target = pick_target_inbound(config, port, None)
    except SystemExit:
        c_red("Установка прервана на шаге поиска конфигурации Xray (см. сообщение выше). "
              "Ничего не изменено.")
        return

    want_tcp = transport in ("tcp", "both")
    want_udp = transport in ("udp", "both")
    tcp_port = port
    udp_port = port + 1

    print()
    c_cyan("Выбор портов для Mieru (Enter — оставить значение по умолчанию):")
    taken = set()
    if want_tcp:
        tcp_port = ask_port("  TCP-порт Mieru", tcp_port, taken=taken)
        taken.add(tcp_port)
    if want_udp:
        udp_port = ask_port("  UDP-порт Mieru", udp_port, taken=taken)
        taken.add(udp_port)

    if want_tcp and want_udp and tcp_port == udp_port:
        c_red(f"TCP- и UDP-порт совпадают ({tcp_port}) — это разные транспорты, но порту "
              f"всё равно нужно быть разным. Установка отменена, ничего не изменено.")
        return

    if want_udp:
        occupied, detail = check_port_listening(udp_port, "udp")
        if occupied:
            c_red(f"UDP-порт {udp_port} уже занят:\n  {detail}\n"
                  f"  Выбери другой при повторном запуске. Ничего не изменено.")
            return

    c_cyan(f"Итоговые порты Mieru: "
           f"{f'TCP={tcp_port} ' if want_tcp else ''}{f'UDP={udp_port}' if want_udp else ''}")

    print()
    c_yellow("Будет изменено: указанный inbound станет SOCKS-петлёй на 127.0.0.1:"
             f"{LOOPBACK_SOCKS_PORT}, протокол сменится с vless на socks.")
    c_yellow("Внешний доступ по старому VLESS-линку на этом порту ПЕРЕСТАНЕТ работать "
             "— вместо него будет доступ через Mieru.")
    if not confirm("Продолжить?"):
        c_cyan("Отменено пользователем, ничего не тронуто.")
        return

    try:
        backup_path = backup_config(xray_config_path)
        original_inbound = convert_inbound_to_socks_loopback(target)

        if not apply_xray_change(xray_config_path, config, backup_path):
            c_red("Установка прервана на шаге Xray — Mieru НЕ устанавливался, прод не тронут "
                  "(или уже автоматически восстановлен).")
            return

        if want_tcp:
            occupied, detail = check_port_listening(tcp_port, "tcp")
            if occupied:
                c_red(f"TCP-порт {tcp_port} занят чем-то ещё после освобождения Xray:\n  {detail}")
                c_yellow("Откатываю Xray обратно, чтобы не остаться без входа вообще...")
                shutil.copy2(backup_path, xray_config_path)
                restart_service("xray")
                c_red("Установка прервана — старый VLESS-инбаунд восстановлен.")
                return

        install_mita()

        mita_config, creds = build_mita_config(transport, tcp_port, udp_port)

        if not apply_mita_config(mita_config):
            c_red("Mieru не поднялся с новым конфигом. Откатываю Xray, чтобы не остаться "
                  "без входа вообще.")
            shutil.copy2(backup_path, xray_config_path)
            restart_service("xray")
            c_red("Установка прервана — старый VLESS-инбаунд восстановлен, Mieru не используется.")
            return

        fw = detect_firewall()
        c_cyan(f"Файрвол: {fw}")
        firewall_rollback = []
        if want_tcp:
            firewall_rollback.append(open_port(fw, tcp_port, "tcp"))
        if want_udp:
            firewall_rollback.append(open_port(fw, udp_port, "udp"))

        c_cyan("Проверяю локальный SOCKS-мост (Xray)...")
        if selftest_socks5():
            c_green("SOCKS5-мост на 127.0.0.1:1080 отвечает корректно.")
        else:
            c_yellow("SOCKS5-мост не ответил как ожидалось — не критично для установки, "
                     "но стоит проверить логи Xray, прежде чем давать ссылку клиентам.")

        save_state({
            "xray_config_path": str(xray_config_path),
            "backup_path": str(backup_path),
            "inbound_tag": original_inbound.get("tag"),
            "firewall_rollback": firewall_rollback,
            "transport": transport,
            "tcp_port": tcp_port if want_tcp else None,
            "udp_port": udp_port if want_udp else None,
            "created": datetime.now().isoformat(),
        })

        print_summary(creds)
        _log("SUCCESS", "hybrid_addon установлен успешно (через меню установщика)")
    except SystemExit:
        c_red("Установка прервана аддоном на одном из системных шагов (см. сообщение выше) — "
              "проверь руками, что прод не остался без входа.")


def _menu_rollback() -> None:
    try:
        do_rollback()
    except SystemExit:
        c_red("Откат прерван (см. сообщение выше) — проверь config.json и службы Xray/Mieru руками.")


def do_hybrid_addon_menu(default_port: int = 443) -> None:
    """Точка входа из _core.py: отдельный пункт в разделе 1 «Установка и Система»."""
    while True:
        os.system("clear")
        st = _menu_status()
        box_header("MIERU HYBRID ADDON")
        print()
        if st.get("installed"):
            transport = st.get("transport", "?")
            tcp_p = st.get("tcp_port")
            udp_p = st.get("udp_port")
            ports = ", ".join(
                p for p in (f"TCP={tcp_p}" if tcp_p else "", f"UDP={udp_p}" if udp_p else "") if p
            )
            print(f"  {BOLD}Статус:{NC} {GREEN}установлен{NC}")
            print(f"  Транспорт: {transport}   Порты: {ports}")
            print()
            print(f"  {CYAN}1{NC}  Откатить  {DIM}(восстановить исходный VLESS-инбаунд){NC}")
        else:
            print(f"  {BOLD}Статус:{NC} {DIM}не установлен{NC}")
            print()
            print(f"  {CYAN}1{NC}  Установить")
        print(f"  {DIM}0  Назад{NC}")
        print()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if ch == "1":
            if st.get("installed"):
                _menu_rollback()
            else:
                _menu_install(default_port=default_port)
            input(f"{BOLD}Нажмите Enter...{NC}")
        elif ch == "0" or ch == "":
            return
        else:
            c_red(f"Неверный выбор: {ch}")
            time.sleep(1)
