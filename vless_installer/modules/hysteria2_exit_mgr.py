"""
vless_installer/modules/hysteria2_exit_mgr.py
───────────────────────────────────────────────────────────────────────────────
Установка и управление сервером Hysteria2 на Exit-ноде.

Операции:
  • Скачивание/установка бинарника с github.com/apernet/hysteria
  • Генерация конфига /etc/hysteria/config.yaml (TLS, auth, QUIC)
  • Создание systemd-юнита hysteria-server
  • Открытие UDP-портов (iptables + ip6tables)
  • Поддержка DualStack (IPv4 + IPv6)
  • Удалённая установка через SSH (вызов _awg_ssh-style)

Точка входа из _core.py (вызов по имени):
    h2_exit_install()          — установка через меню
    h2_exit_remove()           — удаление с Exit-ноды
    h2_exit_status()           — статус сервиса
    do_h2_exit_menu()          — интерактивное меню

Пример вызова в _core.py:
    # В _menu_network() или do_hysteria2_menu():
    from vless_installer.modules.hysteria2_exit_mgr import do_h2_exit_menu
    do_h2_exit_menu()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import getpass
import json
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from vless_installer.modules.hysteria2_common import (
    _C, RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, _load_h2_state, _save_h2_state, _ensure_h2_state,
    _tg_h2_event, _is_ipv6, _bracket, _detect_ipv6_available,
    open_udp_ports, close_udp_ports,
    _systemctl, _service_active, _h2_binary_exists, _h2_binary_version,
    H2_CONFIG_DIR, H2_CONFIG_FILE, H2_BINARY, H2_SERVICE, H2_LOG_FILE,
    H2_CERT_FILE, H2_KEY_FILE, h2_cert_sha256_local,
)
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)

# ── GitHub releases ───────────────────────────────────────────────────────────
_GH_API = "https://api.github.com/repos/apernet/hysteria/releases/latest"
_ARCH_MAP = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "arm"}


def _detect_arch() -> str:
    r = _run(["uname", "-m"], capture=True)
    return _ARCH_MAP.get(r.stdout.strip(), "amd64")


def _h2_latest_url() -> str:
    arch = _detect_arch()
    try:
        r = _run(["curl", "-s", "--max-time", "15", _GH_API], capture=True)
        data = json.loads(r.stdout)
        wanted = f"hysteria-linux-{arch}"
        for asset in data.get("assets", []):
            n = asset.get("name", "")
            # Актуальные релизы Hysteria2 называют линуксовые бинарники без
            # расширения (например "hysteria-linux-amd64"), .exe есть только
            # у Windows-сборок. Сравниваем точное имя, а не подстроку,
            # чтобы не зацепить "hysteria-linux-amd64-avx".
            if n == wanted:
                return asset["browser_download_url"], data.get("tag_name", "")
        # Точного совпадения не нашли (например, поменялась схема имён) —
        # берём первый ассет, содержащий нужную архитектуру, но НЕ являющийся
        # Windows/исходниками.
        for asset in data.get("assets", []):
            n = asset.get("name", "")
            if f"linux-{arch}" in n and not n.endswith((".exe", ".txt", ".sha256")):
                return asset["browser_download_url"], data.get("tag_name", "")
    except Exception:
        pass
    # Фоллбэк используется только если GitHub API недоступен (rate-limit,
    # сеть). Актуальный тег релиза имеет вид "app/vX.Y.Z", а линуксовые
    # бинарники начиная с 2.9.x не имеют расширения ".bin".
    tag = "app/v2.9.3"
    return (
        f"https://github.com/apernet/hysteria/releases/download/{tag}/"
        f"hysteria-linux-{arch}",
        tag,
    )


# ── Установка бинарника ───────────────────────────────────────────────────────
def _install_h2_binary() -> bool:
    info("Скачиваю бинарник Hysteria2...")
    url, tag = _h2_latest_url()
    tmp = Path("/tmp/hysteria.bin")
    r = _run(["curl", "-fsSL", "--max-time", "60", "-o", str(tmp), url],
             capture=True)
    if r.returncode != 0 or not tmp.exists() or tmp.stat().st_size < 1024 * 1024:
        error(f"Не удалось скачать: {url} (код {r.returncode})")
        tmp.unlink(missing_ok=True)
        return False
    # Проверяем, что скачали настоящий ELF-бинарник, а не HTML/JSON с ошибкой
    magic = tmp.read_bytes()[:4]
    if magic != b"\x7fELF":
        error(
            f"Скачанный файл не является ELF-бинарником (магия: {magic!r}). "
            "Возможно, GitHub недоступен или отдал страницу с ошибкой."
        )
        tmp.unlink(missing_ok=True)
        return False
    H2_BINARY.parent.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.move(str(tmp), str(H2_BINARY))
    H2_BINARY.chmod(0o755)
    success(f"Hysteria2 {tag} установлен → {H2_BINARY}")
    log_to_file("INFO", f"H2 binary installed: {tag}")
    return True


# ── Генерация конфига ─────────────────────────────────────────────────────────
def _generate_h2_config(
    listen_host: str,
    ports: list[int],
    auth_password: str,
    cert_path: str,
    key_path: str,
    ipv6: bool = False,
) -> str:
    """Генерирует YAML-конфиг Hysteria2-сервера."""
    # listen: поддерживаем несколько портов через portHopping синтаксис
    if len(ports) == 1:
        port_str = str(ports[0])
    else:
        lo, hi = min(ports), max(ports)
        port_str = f"{lo}-{hi}" if hi - lo < 50 else str(ports[0])

    host = _bracket(listen_host) if ipv6 else listen_host
    # ВАЖНО: для IPv6 host нужно явно подставлять в строку листена в
    # квадратных скобках — например "[::]:443". Раньше здесь стоял
    # хардкод "::{port}" (без скобок и разделителя), из-за чего Hysteria2
    # не мог распарсить адрес ("too many colons in address").
    listen_line = f"{host}:{port_str}"

    config = f"""# Hysteria2 server config — generated by VLESS Ultimate Installer
listen: "{listen_line}"

tls:
  cert: {cert_path}
  key: {key_path}

auth:
  type: password
  password: {auth_password}

masquerade:
  type: proxy
  proxy:
    url: https://news.ycombinator.com
    rewriteHost: true

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

bandwidth:
  up: 1 gbps
  down: 1 gbps

ignoreClientBandwidth: true

speedTest: false

udpIdleTimeout: 60s
"""
    return config


# ── systemd unit ──────────────────────────────────────────────────────────────
_SYSTEMD_UNIT = """\
[Unit]
Description=Hysteria2 Server (VLESS Ultimate Installer)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
StandardOutput=append:/var/log/hysteria.log
StandardError=append:/var/log/hysteria.log

[Install]
WantedBy=multi-user.target
"""


def _install_systemd_unit() -> None:
    unit = Path(f"/etc/systemd/system/{H2_SERVICE}.service")
    unit.write_text(_SYSTEMD_UNIT)
    _run(["systemctl", "daemon-reload"], quiet=True)
    _run(["systemctl", "enable", H2_SERVICE], quiet=True)


# ── Сертификаты ───────────────────────────────────────────────────────────────
def _ensure_h2_cert(domain: str = "", ip: str = "") -> tuple[str, str]:
    """
    Возвращает (cert_path, key_path).
    Если certbot есть и domain задан — получает TLS-сертификат.
    Иначе — генерирует самоподписанный leaf-сертификат с корректными SAN.

    ВАЖНО: нативный hysteria2-клиент (в отличие от Xray-core) проверяет
    SubjectAltName при TLS-верификации. Если сертификат не содержит SAN с
    IP или DNS-именем сервера — клиент падает с ошибкой
    "x509: cannot validate certificate for X because it doesn't contain any IP SANs".
    Поэтому обязательно передавайте ip= (для IP-адресов) или domain=.
    """
    if H2_CERT_FILE.exists() and H2_KEY_FILE.exists():
        return str(H2_CERT_FILE), str(H2_KEY_FILE)

    H2_CERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    if domain and _run(["which", "certbot"], capture=True).returncode == 0:
        info(f"Получаю TLS-сертификат для {domain} через certbot...")
        r = _run([
            "certbot", "certonly", "--standalone", "--non-interactive",
            "--agree-tos", "--register-unsafely-without-email",
            "-d", domain,
            "--cert-path", str(H2_CERT_FILE),
            "--key-path",  str(H2_KEY_FILE),
        ], capture=True)
        if r.returncode == 0:
            success("TLS-сертификат получен через certbot")
            return str(H2_CERT_FILE), str(H2_KEY_FILE)
        warn("certbot не смог получить сертификат, генерирую самоподписанный")

    # Строим CN и SAN
    cn = domain or ip or "hysteria2.local"
    if ip and domain:
        san = f"IP:{ip},DNS:{domain}"
    elif ip:
        san = f"IP:{ip}"
    elif domain:
        san = f"DNS:{domain}"
    else:
        san = "DNS:hysteria2.local"

    info(f"Генерирую самоподписанный TLS-сертификат (leaf, CA:FALSE, SAN={san})...")
    r = _run([
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", str(H2_KEY_FILE),
        "-out", str(H2_CERT_FILE),
        "-days", "3650", "-nodes",
        "-subj", f"/CN={cn}",
        "-addext", "basicConstraints=CA:FALSE",
        "-addext", "keyUsage=digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
        "-addext", f"subjectAltName={san}",
    ], quiet=True, check=False)
    if r.returncode != 0:
        # Фоллбэк для OpenSSL < 1.1.1 (без поддержки -addext)
        warn("openssl не поддерживает -addext, генерирую через extfile...")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ext", delete=False) as f:
            f.write("basicConstraints=CA:FALSE\n"
                    "keyUsage=digitalSignature,keyEncipherment\n"
                    "extendedKeyUsage=serverAuth\n"
                    f"subjectAltName={san}\n")
            ext_path = f.name
        _run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", str(H2_KEY_FILE),
            "-out", str(H2_CERT_FILE),
            "-days", "3650", "-nodes",
            "-subj", f"/CN={cn}",
            "-extensions", "v3_req",
            "-extfile", ext_path,
        ], quiet=True)
        Path(ext_path).unlink(missing_ok=True)
    H2_CERT_FILE.chmod(0o644)
    H2_KEY_FILE.chmod(0o600)
    _check = _run(["openssl", "x509", "-in", str(H2_CERT_FILE),
                   "-noout", "-text"], capture=True, quiet=True, check=False)
    if "CA:TRUE" in _check.stdout:
        warn("Сертификат имеет CA:TRUE — обновите OpenSSL до 1.1.1+")
    elif "IP Address" not in _check.stdout and "DNS:" not in _check.stdout:
        warn("Сертификат не содержит SAN — нативный hysteria2-клиент может "
             "отклонить соединение (передайте ip= или domain= в _ensure_h2_cert)")
    else:
        success(f"Leaf-сертификат (CA:FALSE, SAN={san}) → {H2_CERT_FILE}")
    return str(H2_CERT_FILE), str(H2_KEY_FILE)


# ── Основная установка (локальная — Exit Node) ────────────────────────────────
def h2_exit_install(
    ports: Optional[list[int]] = None,
    auth_password: str = "",
    domain: str = "",
    listen_host: str = "",
) -> bool:
    """
    Устанавливает Hysteria2-сервер на текущей (Exit) ноде.
    Вызывается интерактивно из do_h2_exit_menu() или напрямую из CLI.
    """
    info("=== Установка Hysteria2 на Exit-ноде ===")

    if not _h2_binary_exists():
        if not _install_h2_binary():
            return False

    if not ports:
        ports = [443]
    if not auth_password:
        auth_password = secrets.token_urlsafe(24)

    ipv6_avail = _detect_ipv6_available()
    if not listen_host:
        listen_host = "::" if ipv6_avail else "0.0.0.0"

    # Определяем локальный IP заранее — нужен для SAN в сертификате.
    # Нативный hysteria2-клиент требует subjectAltName=IP:X в сертификате,
    # иначе падает с "no IP SANs" даже при наличии pinSHA256.
    _ip_r = _run(["hostname", "-I"], capture=True, check=False)
    local_ip = _ip_r.stdout.strip().split()[0] \
        if _ip_r.returncode == 0 and _ip_r.stdout.strip() else ""

    cert_path, key_path = _ensure_h2_cert(domain=domain, ip=local_ip)

    H2_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cfg_yaml = _generate_h2_config(
        listen_host, ports, auth_password,
        cert_path, key_path, ipv6=ipv6_avail,
    )
    H2_CONFIG_FILE.write_text(cfg_yaml)
    H2_CONFIG_FILE.chmod(0o600)
    success(f"Конфиг записан → {H2_CONFIG_FILE}")

    _install_systemd_unit()
    open_udp_ports(ports, ipv6=ipv6_avail)

    _systemctl("restart", H2_SERVICE)
    time.sleep(2)
    if not _service_active(H2_SERVICE):
        error("Сервис не запустился. Проверьте: journalctl -u hysteria-server -n 50")
        return False

    # Обновляем state.json
    h2 = _ensure_h2_state()
    h2["enabled"] = True

    # Добавляем/обновляем локальную запись в exit_nodes
    local_ip = _run(["hostname", "-I"], capture=True).stdout.split()[0] \
        if _run(["hostname", "-I"], capture=True).returncode == 0 else "127.0.0.1"

    node_entry = {
        "ip": local_ip,
        "ports": ports,
        "auth": auth_password,
        "weight": 1.0,
        "status": "active",
        "ipstack": "dual" if ipv6_avail else "ipv4",
        "version": _h2_binary_version(),
        "cert_sha256": h2_cert_sha256_local(cert_path),
        "metrics": {"rtt_ms": 0, "loss_pct": 0.0, "speed_mbps": 0},
    }
    existing = [n for n in h2.get("exit_nodes", []) if n.get("ip") != local_ip]
    existing.append(node_entry)
    h2["exit_nodes"] = existing

    h2["cert"]["crt"] = cert_path
    h2["cert"]["key"] = key_path
    h2["firewall"]["udp_ports"] = ports
    _save_h2_state(h2)

    success(f"Hysteria2 установлен! Порты UDP: {ports}, пароль: {auth_password}")
    _tg_h2_event("h2_up", f"Exit установлен. Порты: {ports}")
    return True


def h2_exit_remove() -> None:
    """Останавливает и удаляет Hysteria2 с текущей ноды."""
    h2 = _load_h2_state()
    ports = h2.get("firewall", {}).get("udp_ports", [443])

    _systemctl("stop", H2_SERVICE)
    _systemctl("disable", H2_SERVICE)

    unit = Path(f"/etc/systemd/system/{H2_SERVICE}.service")
    if unit.exists():
        unit.unlink()
    _run(["systemctl", "daemon-reload"], quiet=True)

    close_udp_ports(ports, ipv6=True)

    if H2_CONFIG_FILE.exists():
        H2_CONFIG_FILE.unlink()

    h2["enabled"] = False
    _save_h2_state(h2)
    success("Hysteria2 удалён с Exit-ноды")
    _tg_h2_event("h2_down", "Exit-нода остановлена")


def h2_exit_status() -> dict:
    """Возвращает словарь со статусом Hysteria2 на текущей ноде."""
    active = _service_active(H2_SERVICE)
    ver = _h2_binary_version()
    h2  = _load_h2_state()
    return {
        "active": active,
        "version": ver,
        "ports": h2.get("firewall", {}).get("udp_ports", []),
        "nodes": len(h2.get("exit_nodes", [])),
    }


# ── Remote install через SSH ──────────────────────────────────────────────────
# ── SSH-пароль: проверка/установка sshpass ────────────────────────────────────
def _h2_has_sshpass() -> bool:
    return _run(["which", "sshpass"], capture=True).returncode == 0


def _h2_ensure_sshpass() -> bool:
    """
    Проверяет наличие sshpass и при отсутствии пытается установить его через
    apt-get. Тот же паттерн, что в cluster_ops._ensure_sshpass_installed()
    и hysteria2_cluster._ensure_sshpass() — нужен, чтобы парольный SSH-доступ
    к удалённой Exit-ноде не валился необработанным FileNotFoundError.
    """
    if _h2_has_sshpass():
        return True
    info("sshpass не найден, устанавливаю...")
    r = _run(["apt-get", "install", "-y", "-q", "sshpass"], capture=True)
    if r.returncode == 0 and _h2_has_sshpass():
        success("sshpass установлен")
        return True
    error("Не удалось установить sshpass автоматически. "
          "Установите вручную: apt-get install -y sshpass")
    return False


def h2_exit_remote_install(
    host: str,
    ssh_key: Optional[str] = None,
    ssh_pass: Optional[str] = None,
    ports: Optional[list[int]] = None,
    auth_password: str = "",
    ssh_port: int = 22,
) -> bool:
    """
    Устанавливает Hysteria2 на удалённую Exit-ноду через SSH.
    Использует тот же SSH-паттерн что cluster_ops.
    ssh_port — SSH-порт удалённой ноды (по умолчанию 22).
    """
    info(f"Удалённая установка H2 → {host}:{ssh_port}")
    if not ports:
        ports = [443]
    if not auth_password:
        auth_password = secrets.token_urlsafe(24)

    # Если выбрана парольная аутентификация — sshpass обязателен.
    # Проверяем/доустанавливаем его ДО первого вызова, иначе при отсутствии
    # пакета упадём с необработанным FileNotFoundError (как раньше).
    if ssh_pass and not _h2_ensure_sshpass():
        return False

    # Определяем архитектуру удалённой машины, а не локальной
    ssh_opts_pre = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15",
                    "-p", str(ssh_port)]
    if ssh_key:
        ssh_opts_pre += ["-i", ssh_key]
    _arch_cmd = ["ssh"] + ssh_opts_pre + [f"root@{host}", "uname -m"]
    if ssh_pass:
        _arch_cmd = ["sshpass", "-p", ssh_pass] + _arch_cmd
    _arch_r = _run(_arch_cmd, capture=True, timeout=15, check=False)
    _remote_arch_raw = _arch_r.stdout.strip() if _arch_r.returncode == 0 else ""
    arch = _ARCH_MAP.get(_remote_arch_raw, None)
    if not arch:
        warn(f"Не удалось определить архитектуру удалённой машины "
             f"(uname -m вернул: {_remote_arch_raw!r}), использую amd64")
        arch = "amd64"
    else:
        info(f"Архитектура удалённой ноды: {_remote_arch_raw} -> {arch}")

    # Определяем, есть ли IPv6 на удалённой ноде — раньше ipv6=True было
    # захардкожено, и на VPS без IPv6 (частый случай) Hysteria не мог
    # забиндиться на [::]:port, сервис не стартовал.
    _ipv6_cmd = ["ssh"] + ssh_opts_pre + [
        f"root@{host}", "ip -6 addr show 2>/dev/null | grep -q inet6 && echo yes || echo no"
    ]
    if ssh_pass:
        _ipv6_cmd = ["sshpass", "-p", ssh_pass] + _ipv6_cmd
    _ipv6_r = _run(_ipv6_cmd, capture=True, timeout=15, check=False)
    remote_ipv6 = _ipv6_r.returncode == 0 and "yes" in _ipv6_r.stdout
    info(f"IPv6 на удалённой ноде: {'есть' if remote_ipv6 else 'нет'}")

    # Строим URL под архитектуру удалённой машины
    try:
        _gr = _run(["curl", "-s", "--max-time", "15", _GH_API], capture=True)
        _gdata = json.loads(_gr.stdout)
        tag = _gdata.get("tag_name", "app/v2.9.3")
        _wanted = f"hysteria-linux-{arch}"
        _assets = _gdata.get("assets", [])
        url = next(
            (a["browser_download_url"] for a in _assets if a.get("name") == _wanted),
            None,
        ) or next(
            (a["browser_download_url"] for a in _assets
             if f"linux-{arch}" in a.get("name", "")
             and not a["name"].endswith((".exe", ".txt", ".sha256"))),
            f"https://github.com/apernet/hysteria/releases/download/{tag}/hysteria-linux-{arch}",
        )
    except Exception:
        tag = "app/v2.9.3"
        url = (f"https://github.com/apernet/hysteria/releases/download/{tag}/"
               f"hysteria-linux-{arch}")

    commands = [
        # -f: curl вернёт ошибку при HTTP >= 400; xxd проверяет ELF magic
        f"curl -fsSL --max-time 60 -o /tmp/hysteria.bin '{url}' && "
        f"[ \"$(head -c4 /tmp/hysteria.bin | xxd -p)\" = '7f454c46' ] && "
        f"mv /tmp/hysteria.bin /usr/local/bin/hysteria && chmod +x /usr/local/bin/hysteria || "
        f"{{ echo 'ERROR: hysteria binary is not ELF (wrong arch or GitHub unreachable)'; "
        f"rm -f /tmp/hysteria.bin; exit 1; }}",
        "mkdir -p /etc/hysteria /etc/xray",
        # Генерируем leaf-сертификат (CA:FALSE) с subjectAltName=IP:{host}.
        # CA:FALSE обязателен для Xray-core 26.x (issue #5904).
        # subjectAltName=IP:{host} обязателен для нативного hysteria2-клиента:
        # без него клиент падает с "no IP SANs" даже при наличии pinSHA256.
        f"openssl req -x509 -newkey rsa:4096 -keyout /etc/xray/hysteria.key "
        f"-out /etc/xray/hysteria.crt -days 3650 -nodes -subj '/CN={host}' "
        f"-addext 'basicConstraints=CA:FALSE' "
        f"-addext 'keyUsage=digitalSignature,keyEncipherment' "
        f"-addext 'extendedKeyUsage=serverAuth' "
        f"-addext 'subjectAltName=IP:{host}' 2>/dev/null || "
        # Фоллбэк для OpenSSL < 1.1.1 (без -addext) — без SAN, с предупреждением
        f"openssl req -x509 -newkey rsa:4096 -keyout /etc/xray/hysteria.key "
        f"-out /etc/xray/hysteria.crt -days 3650 -nodes -subj '/CN={host}' "
        f"|| echo 'ERROR: openssl не смог создать сертификат'",
        _generate_systemd_remote(),
        f"systemctl daemon-reload && systemctl enable --now {H2_SERVICE}",
    ] + [f"iptables -I INPUT -p udp --dport {p} -j ACCEPT" for p in ports]

    # Пишем конфиг через SSH heredoc
    _remote_listen_host = "::" if remote_ipv6 else "0.0.0.0"
    cfg = _generate_h2_config(_remote_listen_host, ports, auth_password,
                               "/etc/xray/hysteria.crt", "/etc/xray/hysteria.key",
                               ipv6=remote_ipv6)
    cfg_cmd = f"cat > /etc/hysteria/config.yaml << 'EOFH2'\n{cfg}\nEOFH2"
    commands.insert(2, cfg_cmd)

    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15"]
    if ssh_key:
        ssh_opts += ["-i", ssh_key]

    _had_errors = False
    for cmd in commands:
        ssh_cmd = ["ssh"] + ssh_opts + [f"root@{host}", cmd]
        if ssh_pass:
            ssh_cmd = ["sshpass", "-p", ssh_pass] + ssh_cmd
        r = _run(ssh_cmd, capture=True, timeout=90)
        if r.returncode != 0:
            warn(f"SSH команда завершилась с ошибкой: {r.stderr[:200]}")
            _had_errors = True

    # Не верим на слово команде "systemctl enable --now" — реально
    # проверяем статус сервиса на удалённой ноде, иначе можно отрапортовать
    # "H2 установлен" даже когда сервис не запустился (см. ipv6-баг выше).
    _status_cmd = ["ssh"] + ssh_opts + [
        f"root@{host}", f"systemctl is-active {H2_SERVICE}"
    ]
    if ssh_pass:
        _status_cmd = ["sshpass", "-p", ssh_pass] + _status_cmd
    _status_r = _run(_status_cmd, capture=True, timeout=15, check=False)
    _remote_active = _status_r.stdout.strip() == "active"

    if not _remote_active:
        error(
            f"Hysteria2 на {host} НЕ запустился (systemctl is-active вернул "
            f"{_status_r.stdout.strip()!r}). Проверьте на ноде: "
            f"journalctl -u {H2_SERVICE} -n 50 и /var/log/hysteria.log"
        )
        return False
    if _had_errors:
        warn("Установка завершилась с предупреждениями, но сервис активен — "
             "проверьте конфиг при необходимости.")

    # Забираем SHA256-отпечаток сертификата удалённой ноды — нужен для
    # streamSettings.tlsSettings.pinnedPeerCertSha256 на Entry-ноде (с июня
    # 2026 это единственный способ доверять самоподписанному сертификату,
    # allowInsecure из Xray-core убран).
    _fp_cmd = ["ssh"] + ssh_opts + [
        f"root@{host}",
        "openssl x509 -noout -fingerprint -sha256 -in /etc/xray/hysteria.crt 2>/dev/null"
    ]
    if ssh_pass:
        _fp_cmd = ["sshpass", "-p", ssh_pass] + _fp_cmd
    _fp_r = _run(_fp_cmd, capture=True, timeout=15, check=False)
    _cert_sha256 = _fp_r.stdout.split("=", 1)[-1].strip().replace(":", "").lower()
    if not _cert_sha256:
        warn("Не удалось получить SHA256-отпечаток сертификата удалённой ноды — "
             "транспорт H2 не сможет валидировать TLS (pinnedPeerCertSha256 будет пуст)")

    # Добавляем ноду в state
    h2 = _ensure_h2_state()
    existing = [n for n in h2.get("exit_nodes", []) if n.get("ip") != host]
    existing.append({
        "ip": host,
        "ports": ports,
        "auth": auth_password,
        "weight": 1.0,
        "status": "active",
        "ipstack": "dual" if remote_ipv6 else "v4",
        "version": tag.lstrip("v"),
        "cert_sha256": _cert_sha256,
        "metrics": {"rtt_ms": 0, "loss_pct": 0.0, "speed_mbps": 0},
    })
    h2["exit_nodes"] = existing
    h2["enabled"] = True
    _save_h2_state(h2)

    success(f"H2 установлен на {host}, порты: {ports}, пароль: {auth_password}")
    _tg_h2_event("h2_up", f"Удалённая Exit-нода {host} установлена")
    return True


def _generate_systemd_remote() -> str:
    return (
        f"cat > /etc/systemd/system/{H2_SERVICE}.service << 'EOFSVC'\n"
        + _SYSTEMD_UNIT
        + "\nEOFSVC"
    )


# ── Интерактивное меню ────────────────────────────────────────────────────────
def _h2_remote_status(host: str, ssh_key: Optional[str], ssh_pass: Optional[str],
                      ssh_port: int = 22) -> dict:
    """
    Реальная проверка статуса H2 на удалённой ноде по SSH — в отличие от
    h2_exit_status(), которая всегда смотрит только на ЭТУ (локальную) ноду.
    """
    if ssh_pass and not _h2_ensure_sshpass():
        return {"error": "sshpass недоступен"}
    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
                "-p", str(ssh_port)]
    if ssh_key:
        ssh_opts += ["-i", ssh_key]
    remote_cmd = (
        f"systemctl is-active {H2_SERVICE} 2>/dev/null; "
        f"echo '---'; "
        f"/usr/local/bin/hysteria version 2>&1; "
        f"echo '---'; "
        f"tail -n 5 /var/log/hysteria.log 2>/dev/null"
    )
    ssh_cmd = ["ssh"] + ssh_opts + [f"root@{host}", remote_cmd]
    if ssh_pass:
        ssh_cmd = ["sshpass", "-p", ssh_pass] + ssh_cmd
    r = _run(ssh_cmd, capture=True, timeout=20, check=False)
    if r.returncode != 0 and not r.stdout:
        return {"error": f"SSH недоступен: {r.stderr[:200]}"}
    parts = r.stdout.split("---")
    _ver_raw = parts[1].strip() if len(parts) > 1 else ""
    _ver_match = re.search(r"v?(\d+\.\d+\.\d+)", _ver_raw)
    return {
        "active": (parts[0].strip() if len(parts) > 0 else ""),
        "version": (_ver_match.group(1) if _ver_match else ""),
        "log_tail": (parts[2].strip() if len(parts) > 2 else ""),
    }


def _interactive_remote_status() -> None:
    h2 = _load_h2_state()
    nodes = h2.get("exit_nodes", [])
    default_host = nodes[0]["ip"] if nodes else ""
    host = input(f"  IP/домен удалённой Exit-ноды [{default_host}]: ").strip() or default_host
    if not host:
        warn("IP не указан")
        time.sleep(1)
        return
    _sp_raw = input(f"  SSH-порт [22]: ").strip()
    ssh_port = int(_sp_raw) if _sp_raw.isdigit() else 22
    ssh_key = input("  Путь к SSH-ключу (пусто = пароль): ").strip() or None
    ssh_pass = None
    if not ssh_key:
        ssh_pass = getpass.getpass("  SSH-пароль: ").strip() or None
    st = _h2_remote_status(host, ssh_key, ssh_pass, ssh_port=ssh_port)
    os.system("clear")
    print()
    _box_top(f"📊  СТАТУС УДАЛЁННОЙ EXIT-НОДЫ {host}")
    if "error" in st:
        _box_row(f"  {RED}{st['error']}{NC}")
    else:
        active_col = GREEN if st["active"] == "active" else RED
        _box_row(f"  {CYAN}active:{NC}  {active_col}{st['active'] or '—'}{NC}")
        _box_row(f"  {CYAN}version:{NC}  {st['version'] or '—'}")
        _box_row()
        _box_row(f"  {CYAN}последние строки лога:{NC}")
        for line in (st["log_tail"] or "(пусто)").splitlines():
            _box_row(f"  {DIM}{line}{NC}")
    _box_row()
    _box_item_exit("0", "← Назад")
    _box_bottom()
    try:
        input(f"{CYAN}Нажмите Enter...{NC}")
    except KeyboardInterrupt:
        pass


def do_h2_exit_menu() -> None:
    """
    Интерактивное меню управления Exit-нодой Hysteria2.
    Вызывается из do_hysteria2_menu().
    """
    while True:
        os.system("clear")
        print()
        st = h2_exit_status()
        status_str = f"{GREEN}активен{NC}" if st["active"] else f"{RED}остановлен{NC}"

        _box_top("💻  HYSTERIA2 — EXIT-НОДА")
        _box_row(f"  Сервис: {status_str}  │  Версия: {DIM}{st['version'] or '—'}{NC}  │  Порты UDP: {CYAN}{st['ports']}{NC}")
        _box_sep()
        _box_row()
        _box_item("1", "Установить H2 (локально — эта нода)")
        _box_item("2", "Установить H2 на удалённую Exit-ноду (SSH)")
        _box_item("3", f"Статус сервиса  {DIM}(локально, эта нода){NC}")
        _box_item("4", f"Перезапустить сервис  {DIM}(локально, эта нода){NC}")
        _box_item("5", f"Показать конфиг  {DIM}(локально: {H2_CONFIG_FILE}){NC}")
        _box_item("6", f"Удалить H2 с этой ноды  {DIM}(⚠️  необратимо, локально){NC}")
        _box_item("7", f"Статус удалённой Exit-ноды  {DIM}(SSH){NC}")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "1":
            _interactive_local_install()
        elif ch == "2":
            _interactive_remote_install()
        elif ch == "3":
            st = h2_exit_status()
            os.system("clear")
            print()
            _box_top("📊  СТАТУС EXIT-НОДЫ")
            for k, v in st.items():
                _box_row(f"  {CYAN}{k}:{NC}  {v}")
            _box_row()
            _box_item_exit("0", "← Назад")
            _box_bottom()
            try:
                input(f"{CYAN}Нажмите Enter...{NC}")
            except KeyboardInterrupt:
                pass
        elif ch == "4":
            _systemctl("restart", H2_SERVICE)
            time.sleep(1)
            ok = _service_active(H2_SERVICE)
            success("Перезапущен") if ok else error("Не запустился")
            input(f"\n{CYAN}Нажмите Enter...{NC}")
        elif ch == "5":
            os.system("clear")
            print()
            _box_top(f"📄  КОНФИГ  {H2_CONFIG_FILE}")
            if H2_CONFIG_FILE.exists():
                for line in H2_CONFIG_FILE.read_text().splitlines():
                    _box_row(f"  {DIM}{line}{NC}")
            else:
                _box_row(f"  {YELLOW}Конфиг не найден{NC}")
            _box_row()
            _box_item_exit("0", "← Назад")
            _box_bottom()
            try:
                input(f"{CYAN}Нажмите Enter...{NC}")
            except KeyboardInterrupt:
                pass
        elif ch == "6":
            try:
                confirm = input(f"{YELLOW}Удалить Hysteria2? [y/N]:{NC} ").strip().lower()
            except KeyboardInterrupt:
                continue
            if confirm == "y":
                h2_exit_remove()
                input(f"\n{CYAN}Нажмите Enter...{NC}")
        elif ch == "7":
            _interactive_remote_status()
        elif ch in ("Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


def _interactive_local_install() -> None:
    print()
    try:
        raw_ports = input(
            f"  UDP-порт(ы) [{CYAN}443{NC}] (несколько через запятую): "
        ).strip()
        ports = [int(p.strip()) for p in raw_ports.split(",") if p.strip().isdigit()] \
            if raw_ports else [443]

        domain = input(f"  {CYAN}Домен для TLS-сертификата{NC} (пусто = самоподписанный): ").strip()
        raw_pass = input(f"  {CYAN}Пароль аутентификации{NC} (пусто = авто): ").strip()
    except KeyboardInterrupt:
        return

    auth = raw_pass or secrets.token_urlsafe(24)
    h2_exit_install(ports=ports, auth_password=auth, domain=domain)
    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _interactive_remote_install() -> None:
    print()
    try:
        host = input(f"  {CYAN}IP/домен удалённой Exit-ноды:{NC} ").strip()
        if not host:
            return
        raw_ports = input(f"  {CYAN}UDP-порт(ы){NC} [{CYAN}443{NC}]: ").strip()
        ports = [int(p.strip()) for p in raw_ports.split(",") if p.strip().isdigit()] \
            if raw_ports else [443]
        ssh_key = input(f"  {CYAN}Путь к SSH-ключу{NC} (пусто = пароль): ").strip() or None
        _sp_raw = input(f"  {CYAN}SSH-порт{NC} [{CYAN}22{NC}]: ").strip()
        ssh_port = int(_sp_raw) if _sp_raw.isdigit() else 22
        ssh_pass = getpass.getpass(f"  {CYAN}SSH-пароль{NC} (пусто = ключ): ") if not ssh_key else None
        raw_pass = input(f"  {CYAN}Пароль H2{NC} (пусто = авто): ").strip()
    except KeyboardInterrupt:
        return

    auth = raw_pass or secrets.token_urlsafe(24)
    h2_exit_remote_install(host, ssh_key=ssh_key, ssh_pass=ssh_pass,
                            ports=ports, auth_password=auth, ssh_port=ssh_port)
    input(f"\n{BLUE}Нажмите Enter...{NC}")


"""
ПРИМЕР ВЫЗОВА из _core.py / main.py:
    from vless_installer.modules.hysteria2_exit_mgr import (
        do_h2_exit_menu, h2_exit_install, h2_exit_status,
    )

    # В меню (например _menu_network → do_hysteria2_menu):
    do_h2_exit_menu()

    # CLI --h2-install-exit:
    h2_exit_install(ports=[443, 8443], auth_password="secret")

    # Получить статус:
    st = h2_exit_status()   # {"active": True, "version": "2.6.0", ...}
"""
