# VLESS Ultimate Installer v4.11.1

[![Version](https://img.shields.io/badge/version-4.11.1-blue.svg)](https://github.com/inferno1978/VLESS-Ultimate-Installer)
[![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](https://github.com/inferno1978/VLESS-Ultimate-Installer/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg)](https://ubuntu.com)

Профессиональный установщик VLESS-сервера с поддержкой REALITY и xHTTP TLS. Полная автоматизация: от установки до мониторинга, с поддержкой обхода DPI, каскадных конфигураций и AmneziaWG.

```
██╗   ██╗██╗     ███████╗███████╗███████╗
██║   ██║██║     ██╔════╝██╔════╝██╔════╝
██║   ██║██║     █████╗  ███████╗███████╗
╚██╗ ██╔╝██║     ██╔══╝  ╚════██║╚════██║
 ╚████╔╝ ███████╗███████╗███████║███████║
  ╚═══╝  ╚══════╝╚══════╝╚══════╝╚══════╝
  Ultimate Installer v4.11.1
```

## ⚡ Быстрый старт

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/inferno1978/VLESS-Ultimate-Installer/main/bootstrap.sh)
```

Или с `wget`:

```bash
wget -O bootstrap.sh https://raw.githubusercontent.com/inferno1978/VLESS-Ultimate-Installer/main/bootstrap.sh
chmod +x bootstrap.sh
bash bootstrap.sh
```

## 🎯 Возможности

| Категория        | Функции                                                              |
| ---------------- | -------------------------------------------------------------------- |
| **Протоколы**    | VLESS + TCP + REALITY, VLESS + xHTTP + TLS                           |
| **Режимы**       | Одиночный (A), Каскад Россия→Зарубеж (B), Мульти-каскад (до 10 нод) |
| **Транспорт**    | AmneziaWG (AWG 2.0) с multi-node балансировкой                       |
| **Маскировка**   | XTLS Vision/Splice, сайты-заглушки (TechHub, Nextcloud, custom)      |
| **DNS**          | DNSCrypt-proxy, кастомные DNS-правила, DNS Leak Test                 |
| **Анти-цензура** | Split Tunneling, РФ-подсети (RIPE NCC), AS-direct routing            |
| **CloudFlare**   | WARP full / selective / runet-only                                   |
| **Безопасность** | AutoBan, DPI Detector, Honeypot, SSH Hardening                       |
| **Мониторинг**   | Smart Balancer, Watchdog, Health Reports, Failover A↔B               |
| **Пользователи** | Добавление/удаление, QR-коды, ссылки, TTL, лимиты трафика            |
| **Диагностика**  | Health Check, MTU Tracepath, Speed Test, TLS Cert Check              |
| **Интеграции**   | Telegram-уведомления, Clash Meta / Sing-box конфиги                  |
| **Обслуживание** | Авторестарт, автообновление xray/geo, миграция конфигов              |
| **v4.11 NEW**    | Smoke-test, nginx Watchdog, ipset Persist, кластерное управление     |

## 📋 Требования

| Параметр | Минимум          | Рекомендуется            |
| -------- | ---------------- | ------------------------ |
| ОС       | Ubuntu 20.04 LTS | Ubuntu 22.04 / 24.04 LTS |
| Python   | 3.10+            | 3.12                     |
| RAM      | 512 МБ           | 1 ГБ+                    |
| Права    | root             | root                     |
| Сеть     | Публичный IP     | Публичный IP + домен     |

**Поддерживаемые ОС:** Ubuntu 20.04 / 22.04 / 24.04, Debian 11 / 12 / 13

## 🔧 Ручная установка

```bash
git clone https://github.com/inferno1978/VLESS-Ultimate-Installer /opt/vless-ultimate
cd /opt/vless-ultimate
sudo python3 main.py
```

## 🗂️ Структура проекта

```
VLESS-Ultimate-Installer/
├── main.py                      # Точка входа
├── bootstrap.sh                 # Установка одной командой
├── verify.py                    # Проверка целостности
├── README.md
├── TROUBLESHOOTING.md           # Решение частых проблем
├── INSTALL.md                   # Детальная инструкция
├── CHANGELOG.md                 # История изменений
├── LICENSE
└── vless_installer/
    ├── __init__.py
    ├── _core.py                 # Основной код установщика (~37 000 строк)
    └── modules/
        ├── mtproto.py           # MTProto-прокси
        ├── mtproto_stats.py     # Статистика MTProto
        ├── smoke_test.py        # [v4.11] Автодиагностика после apply
        ├── xray_safe_apply.py   # [v4.11] Атомарное применение конфига
        ├── nginx_watchdog.py    # [v4.11] Watchdog для nginx
        ├── ipset_persist.py     # [v4.11] Persistent ipset при reboot
        ├── ripe_file_age.py     # [v4.11] Проверка возраста RIPE-файла
        └── cluster_ops.py      # [v4.11] Управление кластером Exit Nodes
```

## 🏗️ Архитектура

### Режимы развёртывания

**Режим A — одиночный сервер**

```
Клиент ──VLESS/REALITY──► VPS (любая страна) ──► Интернет
```

**Режим B — каскад Россия → Зарубеж**

```
Клиент ──VLESS/REALITY──► Entry VPS (RU) ──AWG──► Exit VPS (EU/US) ──► Интернет
```

**Режим B Multi — мульти-каскад с балансировкой**

```
                              ┌──► Exit VPS 1 (EU) ──►┐
Клиент ──► Entry VPS (RU) ───┼──► Exit VPS 2 (US) ──►├──► Интернет
                              └──► Exit VPS 3 (AS) ──►┘
```

### Компоненты

```
┌─────────────────────────────────────────────────────────────┐
│                        VLESS Ultimate                       │
│                                                             │
│  bootstrap.sh ──► main.py ──exec──► _core.py                │
│                                         │                   │
│                               modules/ (v4.11)              │
│                                         │                   │
│         Xray-core              Nginx (TLS)                  │
│         /etc/xray/             /etc/nginx/                  │
│         config.json            sites-enabled/               │
│              │                      │                       │
│         iptables/ipset         Certbot (ACME)               │
│         (ingress block)                                     │
│              │                                              │
│         AmneziaWG (AWG)                                     │
│         /etc/amnezia/awg0.conf                              │
└─────────────────────────────────────────────────────────────┘
```

| Компонент            | Роль                                            |
| -------------------- | ----------------------------------------------- |
| **Xray-core**        | VLESS REALITY / xHTTP TLS, routing, outbounds   |
| **Nginx**            | TLS termination, маскировочный сайт-заглушка    |
| **AmneziaWG**        | Зашифрованный туннель Entry→Exit (Режим B)      |
| **DNSCrypt-proxy**   | Зашифрованный DNS, защита от leak               |
| **ipset + iptables** | Ingress-блокировка РФ подсетей (опционально)    |
| **Certbot**          | TLS-сертификаты Let's Encrypt (xHTTP режим)     |

### Хранение состояния

```
/etc/xray/
├── config.json              # Конфиг Xray
├── ru_subnets_ripe.txt      # РФ подсети (split tunneling)
├── geosite.dat / geoip.dat  # GeoData (runetfreedom)
└── config.json.pre-apply    # Авто-бэкап перед каждым apply

/var/lib/xray-installer/
├── state.json               # Состояние установщика (UUID, ключи, настройки)
├── ingress_geoip.json       # Состояние ingress-блокировки
└── backups/                 # Резервные копии конфигов

/etc/ipset.conf              # [v4.11] Дамп ipset для восстановления при reboot
/var/log/
├── vless-install.log        # Лог установщика
├── nginx-watchdog.log       # [v4.11] Лог nginx watchdog
└── xray-ipset-restore.log   # [v4.11] Лог восстановления ipset
```

## 🖥️ Управление сервисами

```bash
systemctl status xray nginx
systemctl restart xray nginx
journalctl -u xray -f
```

## 🖥️ CLI-флаги

```bash
sudo python3 /opt/vless-ultimate/main.py                   # Меню
sudo python3 /opt/vless-ultimate/main.py --status          # Быстрый статус
sudo python3 /opt/vless-ultimate/main.py --scheduled-backup
sudo python3 /opt/vless-ultimate/main.py --switch-mode-a
sudo python3 /opt/vless-ultimate/main.py --switch-mode-b
sudo python3 /opt/vless-ultimate/main.py --autoban
sudo python3 /opt/vless-ultimate/main.py --ttl-check
sudo python3 /opt/vless-ultimate/main.py --smart-balance
sudo python3 /opt/vless-ultimate/main.py --dpi-check
sudo python3 /opt/vless-ultimate/main.py --update-ru-subnets
sudo python3 /opt/vless-ultimate/main.py --update-as-direct
sudo python3 /opt/vless-ultimate/main.py --ingress-geoip-update
sudo python3 /opt/vless-ultimate/main.py --pinned-fallback-check
sudo python3 /opt/vless-ultimate/main.py --tg-event EVENT MSG
sudo python3 /opt/vless-ultimate/main.py --clear-asn-cache
```

## 🔍 Диагностика

```bash
# Полная диагностика через меню
sudo python3 /opt/vless-ultimate/main.py
# → Диагностика и Мониторинг → Полная диагностика

sudo python3 /opt/vless-ultimate/main.py --status
/usr/local/bin/xray run -test -config /etc/xray/config.json
tail -100 /var/log/vless-install.log
```

## 🔄 Обслуживание

```bash
python3 /opt/vless-ultimate/verify.py
cd /opt/vless-ultimate && git pull
sudo python3 /opt/vless-ultimate/main.py --scheduled-backup
```

## ❓ Решение проблем

Смотри [TROUBLESHOOTING.md](https://github.com/inferno1978/VLESS-Ultimate-Installer/blob/main/TROUBLESHOOTING.md).

## 📄 Лицензия

MIT — см. [LICENSE](https://github.com/inferno1978/VLESS-Ultimate-Installer/blob/main/LICENSE)

## ✍️ Автор

inferno1978 · [GitHub](https://github.com/inferno1978)
