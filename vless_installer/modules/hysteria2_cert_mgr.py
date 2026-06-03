"""
vless_installer/modules/hysteria2_cert_mgr.py
───────────────────────────────────────────────────────────────────────────────
Управление TLS-сертификатами для Hysteria2.

Возможности:
  • Получение сертификата через certbot (Let's Encrypt)
  • Генерация самоподписанного сертификата (openssl)
  • Проверка срока действия сертификата
  • Автопродление (cron hook)
  • Поддержка IPv6 / DualStack доменов
  • TG-уведомление за 30/7 дней до истечения

Пути:
  /etc/xray/hysteria.crt  — сертификат
  /etc/xray/hysteria.key  — приватный ключ

Точка входа из _core.py:
    from vless_installer.modules.hysteria2_cert_mgr import (
        h2_cert_ensure, h2_cert_check, h2_cert_renew, do_h2_cert_menu,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from vless_installer.modules.hysteria2_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    _run, _load_h2_state, _save_h2_state,
    _tg_h2_event,
    H2_CERT_FILE, H2_KEY_FILE,
)
from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back,
)


_RENEW_CRON = Path("/etc/cron.d/hysteria2-cert-renew")


# ── Проверка срока сертификата ────────────────────────────────────────────────
def h2_cert_check(cert_path: Optional[str] = None) -> dict:
    """
    Проверяет TLS-сертификат. Возвращает:
      {"exists": bool, "expires_at": str, "days_left": int, "valid": bool}
    """
    path = Path(cert_path) if cert_path else H2_CERT_FILE
    if not path.exists():
        return {"exists": False, "expires_at": "", "days_left": 0, "valid": False}

    try:
        r = _run(["openssl", "x509", "-noout", "-dates",
                  "-in", str(path)], capture=True, timeout=10)
        expires_line = ""
        for line in r.stdout.splitlines():
            if "notAfter" in line:
                expires_line = line.split("=", 1)[-1].strip()
                break

        if not expires_line:
            return {"exists": True, "expires_at": "", "days_left": 0, "valid": False}

        # Парсим формат: Sep 28 12:00:00 2025 GMT
        try:
            exp_dt = datetime.strptime(expires_line, "%b %d %H:%M:%S %Y %Z")
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            exp_dt = datetime.strptime(expires_line, "%b  %d %H:%M:%S %Y %Z")
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)

        now       = datetime.now(timezone.utc)
        days_left = (exp_dt - now).days

        return {
            "exists":     True,
            "expires_at": exp_dt.strftime("%d.%m.%Y"),
            "days_left":  days_left,
            "valid":      days_left > 0,
        }
    except Exception as e:
        return {"exists": True, "expires_at": "", "days_left": 0,
                "valid": False, "error": str(e)}


# ── Генерация самоподписанного ────────────────────────────────────────────────
def _gen_selfsigned(domain: str = "hysteria2.local") -> bool:
    H2_CERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    r = _run([
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", str(H2_KEY_FILE),
        "-out",    str(H2_CERT_FILE),
        "-days",   "3650", "-nodes",
        "-subj",   f"/CN={domain}",
    ], quiet=True, timeout=30)
    if r.returncode != 0:
        error("openssl не смог создать сертификат")
        return False
    H2_CERT_FILE.chmod(0o644)
    H2_KEY_FILE.chmod(0o600)
    success(f"Самоподписанный сертификат → {H2_CERT_FILE}")
    return True


# ── certbot ───────────────────────────────────────────────────────────────────
def _certbot_obtain(domain: str) -> bool:
    if not _run(["which", "certbot"], capture=True).returncode == 0:
        warn("certbot не установлен, пробую apt install...")
        _run(["apt-get", "install", "-y", "-q", "certbot"], quiet=True)

    info(f"Получаю Let's Encrypt сертификат для {domain}...")
    r = _run([
        "certbot", "certonly",
        "--standalone",
        "--non-interactive",
        "--agree-tos",
        "--register-unsafely-without-email",
        "-d", domain,
        "--cert-path",  str(H2_CERT_FILE),
        "--key-path",   str(H2_KEY_FILE),
        "--force-renewal",
    ], capture=True, timeout=120)

    if r.returncode == 0:
        success(f"Let's Encrypt сертификат получен для {domain}")
        return True

    warn(f"certbot вернул ошибку:\n{r.stderr[:300]}")
    warn("Использую самоподписанный сертификат как резерв")
    return False


def h2_cert_ensure(domain: str = "") -> bool:
    """
    Гарантирует наличие валидного TLS-сертификата.
    Если domain задан — пробует certbot, затем self-signed как резерв.
    Если domain пуст — генерирует self-signed немедленно.
    """
    info = _check_if_need_renew()
    if info["valid"] and info["days_left"] > 30:
        success(f"Сертификат действителен до {info['expires_at']} "
                f"({info['days_left']} дней)")
        return True

    if domain:
        if _certbot_obtain(domain):
            _update_state_cert()
            return True

    return _gen_selfsigned(domain or "hysteria2.local") and \
           bool(_update_state_cert())


def _check_if_need_renew() -> dict:
    return h2_cert_check()


def _update_state_cert() -> dict:
    h2 = _load_h2_state()
    info_d = h2_cert_check()
    h2.setdefault("cert", {}).update({
        "crt":         str(H2_CERT_FILE),
        "key":         str(H2_KEY_FILE),
        "expire_date": info_d.get("expires_at", ""),
    })
    _save_h2_state(h2)
    return info_d


def h2_cert_renew() -> bool:
    """Принудительное продление сертификата."""
    h2     = _load_h2_state()
    domain = h2.get("cert", {}).get("domain", "")
    result = h2_cert_ensure(domain)
    if result:
        _tg_h2_event("h2_cert", "Сертификат обновлён")
    return result


def h2_cert_monitor() -> None:
    """
    Проверяет срок и отправляет TG-уведомление если < 30 дней.
    Вызывается из cron (напр. еженедельно).
    """
    info_d = h2_cert_check()
    if not info_d.get("exists"):
        return
    days = info_d.get("days_left", 999)
    if days < 7:
        _tg_h2_event("h2_cert", f"🚨 Сертификат H2 истекает через {days} дней!")
    elif days < 30:
        _tg_h2_event("h2_cert", f"⚠️ Сертификат H2 истекает через {days} дней")
    log_to_file("INFO", f"H2 cert monitor: {days} дней до истечения")


def h2_cert_install_cron() -> None:
    """Устанавливает еженедельный мониторинг сертификата."""
    cron = "0 8 * * 1 root /usr/bin/python3 /opt/vless-installer/main.py --h2-cert-monitor\n"
    _RENEW_CRON.write_text(f"# H2 cert monitor — VLESS Ultimate Installer\n{cron}")
    success(f"Cron мониторинга сертификата → {_RENEW_CRON}")


# ── Меню ──────────────────────────────────────────────────────────────────────
def do_h2_cert_menu() -> None:
    """Интерактивное меню управления сертификатами H2."""
    while True:
        os.system("clear")
        print()
        h2   = _load_h2_state()
        cert = h2.get("cert", {})
        _box_top("🔒  HYSTERIA2 — УПРАВЛЕНИЕ СЕРТИФИКАТАМИ")
        _box_row(f"  Домен: {CYAN}{cert.get('domain','—')}{NC}  │  Тип: {CYAN}{cert.get('type','—')}{NC}  │  Истекает: {CYAN}{cert.get('expires','—')}{NC}")
        _box_sep()
        _box_row()

        info_d = h2_cert_check()
        if info_d["exists"]:
            days   = info_d["days_left"]
            color  = GREEN if days > 30 else (YELLOW if days > 7 else RED)
            print(f"  Сертификат:  {H2_CERT_FILE}")
            print(f"  Действителен до: {color}{info_d['expires_at']}{NC} "
                  f"({days} дней)")
        else:
            print(f"  {RED}Сертификат не найден{NC}")

        h2_state = _load_h2_state()
        domain   = h2_state.get("cert", {}).get("domain", "—")
        print(f"  Домен:       {CYAN}{domain}{NC}")
        print()
        _box_item("1", "Получить Let's Encrypt  (certbot)")
        _box_item("2", f"Создать самоподписанный  {DIM}(3650 дней){NC}")
        _box_item("3", "Принудительное продление")
        _box_item("4", "Проверить срок")
        _box_item("5", f"Установить мониторинг  {DIM}(cron){NC}")
        _box_item("6", "Задать домен")
        _box_row()
        _box_item_exit("Q", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch == "1":
            try:
                domain_input = input(f"  {CYAN}Домен{NC} (например: myvpn.example.com): ").strip()
            except KeyboardInterrupt:
                continue
            if domain_input:
                _certbot_obtain(domain_input)
                _update_state_cert()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            try:
                dom = input(f"  {CYAN}CN{NC} (домен/IP, пусто = hysteria2.local): ").strip()
            except KeyboardInterrupt:
                continue
            _gen_selfsigned(dom or "hysteria2.local")
            _update_state_cert()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            h2_cert_renew()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            info_d = h2_cert_check()
            print()
            for k, v in info_d.items():
                print(f"  {k}: {v}")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            h2_cert_install_cron()
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            try:
                d = input(f"  {CYAN}Новый домен:{NC} ").strip()
            except KeyboardInterrupt:
                continue
            if d:
                h2 = _load_h2_state()
                h2.setdefault("cert", {})["domain"] = d
                _save_h2_state(h2)
                success(f"Домен сохранён: {d}")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "Q":
            break
        else:
            time.sleep(0.5)


"""
ПРИМЕР ВЫЗОВА из _core.py:
    from vless_installer.modules.hysteria2_cert_mgr import (
        h2_cert_ensure, h2_cert_check, h2_cert_renew, do_h2_cert_menu,
    )

    # Убедиться что сертификат есть (при установке):
    h2_cert_ensure(domain="vpn.example.com")

    # Проверить срок:
    info = h2_cert_check()   # {"days_left": 120, ...}

    # Из cron --h2-cert-monitor:
    h2_cert_monitor()

    # Интерактивно:
    do_h2_cert_menu()
"""
