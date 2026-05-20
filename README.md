# VLESS Ultimate Installer v4.10

[![Version](https://img.shields.io/badge/version-4.10-blue.svg)](https://github.com/inferno1978/VLESS-Ultimate)
[![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-lightgrey.svg)](https://ubuntu.com)

Профессиональный установщик VLESS-сервера с поддержкой REALITY и xHTTP TLS. Полная автоматизация: от установки до мониторинга, с поддержкой обхода DPI, каскадных конфигураций и AmneziaWG.

```
 ██╗   ██╗██╗     ███████╗███████╗███████╗
 ██║   ██║██║     ██╔════╝██╔════╝██╔════╝
 ██║   ██║██║     █████╗  ███████╗███████╗
 ╚██╗ ██╔╝██║     ██╔══╝  ╚════██║╚════██║
  ╚████╔╝ ███████╗███████╗███████║███████║
   ╚═══╝  ╚══════╝╚══════╝╚══════╝╚══════╝
   Ultimate Installer v4.10
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

| Категория | Функции |
|-----------|---------|
| **Протоколы** | VLESS + TCP + REALITY, VLESS + xHTTP + TLS |
| **Режимы** | Одиночный (A), Каскад Россия→Зарубеж (B), Мульти-каскад (до 10 нод) |
| **Транспорт** | AmneziaWG (AWG 2.0) с multi-node балансировкой |
| **Маскировка** | XTLS Vision/Splice, сайты-заглушки (TechHub, Nextcloud, custom) |
| **DNS** | DNSCrypt-proxy, кастомные DNS-правила, DNS Leak Test |
| **Анти-цензура** | Split Tunneling, РФ-подсети (RIPE NCC), AS-direct routing |
| **CloudFlare** | WARP full / selective / runet-only |
| **Безопасность** | AutoBan, DPI Detector, Honeypot, SSH Hardening |
| **Мониторинг** | Smart Balancer, Watchdog, Health Reports, Failover A↔B |
| **Пользователи** | Добавление/удаление, QR-коды, ссылки, TTL, лимиты трафика |
| **Диагностика** | Health Check, MTU Tracepath, Speed Test, TLS Cert Check |
| **Интеграции** | Telegram-уведомления, Clash Meta / Sing-box конфиги |
| **Обслуживание** | Авторестарт, автообновление xray/geo, миграция конфигов |

## 📋 Требования

| Параметр | Минимум | Рекомендуется |
|----------|---------|---------------|
| ОС | Ubuntu 20.04 LTS | Ubuntu 22.04 / 24.04 LTS |
| Python | 3.10+ | 3.12 |
| RAM | 512 МБ | 1 ГБ+ |
| Права | root | root |
| Сеть | Публичный IP | Публичный IP + домен |

**Поддерживаемые ОС:** Ubuntu 20.04 / 22.04 / 24.04, Debian 11 / 12 / 13

## 🔧 Ручная установка

```bash
git clone https://github.com/inferno1978/VLESS-Ultimate /opt/vless-ultimate
cd /opt/vless-ultimate
sudo python3 main.py
```

## 🗂️ Структура проекта

```
VLESS-Ultimate/
├── main.py                  # Точка входа
├── bootstrap.sh             # Установка одной командой
├── verify.py                # Проверка целостности
├── README.md
├── TROUBLESHOOTING.md       # Решение частых проблем
├── INSTALL.md               # Детальная инструкция
├── CHANGELOG.md             # История изменений
├── LICENSE
└── vless_installer/
    ├── __init__.py
    └── _core.py             # Весь код установщика (~37 000 строк)
```

## 🏗️ Архитектура

### Режимы развёртывания

**Режим A — одиночный сервер**
```
Клиент ──VLESS/REALITY──► VPS (любая страна) ──► Интернет
```
Простейшая схема. Один VPS, минимальная задержка.

**Режим B — каскад Россия → Зарубеж**
```
Клиент ──VLESS/REALITY──► Entry VPS (RU) ──AWG──► Exit VPS (EU/US) ──► Интернет
```
Entry-нода принимает трафик, Exit-нода выходит в интернет. Клиент видит только RU-адрес. Трафик между нодами зашифрован через AmneziaWG.

**Режим B Multi — мульти-каскад с балансировкой**
```
                              ┌──► Exit VPS 1 (EU) ──►┐
Клиент ──► Entry VPS (RU) ─── ┼──► Exit VPS 2 (US) ──►├──► Интернет
                              └──► Exit VPS 3 (AS) ──►┘
```
Smart Balancer выбирает лучшую Exit-ноду по latency/доступности. При отказе ноды — автоматический failover.

---

### Компоненты и их взаимодействие

```
┌─────────────────────────────────────────────────────────────┐
│                        VLESS Ultimate                       │
│                                                             │
│  bootstrap.sh ──► main.py ──exec──► _core.py                │
│                                         │                   │
│              ┌──────────────────────────┤                   │
│              │                          │                   │
│         Xray-core                  Nginx (TLS)              │
│         /etc/xray/                 /etc/nginx/              │
│         config.json                sites-enabled/           │
│              │                          │                   │
│         iptables/ipset            Certbot (ACME)            │
│         (ingress block)                                     │
│              │                                              │
│         AmneziaWG (AWG)                                     │
│         /etc/amnezia/                                       │
│         awg0.conf                                           │
└─────────────────────────────────────────────────────────────┘
```

| Компонент | Роль |
|-----------|------|
| **Xray-core** | VLESS REALITY / xHTTP TLS, routing, outbounds |
| **Nginx** | TLS termination, маскировочный сайт-заглушка |
| **AmneziaWG** | Зашифрованный туннель Entry→Exit (Режим B) |
| **DNSCrypt-proxy** | Зашифрованный DNS, защита от leak |
| **ipset + iptables** | Ingress-блокировка РФ подсетей (опционально) |
| **Certbot** | TLS-сертификаты Let's Encrypt (xHTTP режим) |
| **Cron / Systemd timers** | Автообновление GeoIP, ru-subnets, health checks |

---

### Хранение состояния

```
/etc/xray/
├── config.json              # Конфиг Xray (генерируется установщиком)
├── state.json               # Состояние установщика (UUID, ключи, настройки)
├── ru_subnets_ripe.txt      # РФ подсети от RIPE NCC (split tunneling)
├── geosite.dat              # GeoSite (runetfreedom)
└── geoip.dat                # GeoIP  (runetfreedom)

/var/lib/xray-installer/
├── ingress_geoip.json       # Состояние ingress-блокировки (ipset/whitelist)
└── backups/                 # Резервные копии конфигов

/var/log/
└── vless-install.log        # Лог всех действий установщика
```

---

### Безопасность: порядок правил iptables

При включённой ingress-блокировке РФ цепочка `INPUT` выглядит так:

```
INPUT chain (порядок обработки):
  1. lo → ACCEPT            (loopback, всегда первым)
  2. ESTABLISHED,RELATED → ACCEPT  (уже установленные соединения)
  3. whitelist IP → ACCEPT  (SSH, доверенные клиенты — выше DROP)
  4. tcp --dport PORT -m set xray_ru_block → DROP   (ipset РФ)
  5. tcp --dport 22/80/PORT NEW → ACCEPT            (разрешённые порты)
```

Порядок критичен: правила ESTABLISHED/RELATED и whitelist стоят **выше** DROP, что исключает обрыв уже установленных соединений.

## 🖥️ Управление сервисами

```bash
# Статус сервисов
systemctl status xray nginx

# Перезапуск
systemctl restart xray nginx

# Логи Xray в реальном времени
journalctl -u xray -f
```

## 🖥️ CLI-флаги (для cron и автоматизации)

```bash
# Интерактивное меню
sudo python3 /opt/vless-ultimate/main.py

# Быстрый статус без меню
sudo python3 /opt/vless-ultimate/main.py --status

# Backup вручную
sudo python3 /opt/vless-ultimate/main.py --scheduled-backup

# Rollback (откат конфигурации)
# Меню → Установка и Система → Откатить конфигурацию

# Переключение режима A↔B (из cron)
sudo python3 /opt/vless-ultimate/main.py --switch-mode-a
sudo python3 /opt/vless-ultimate/main.py --switch-mode-b

# Проверки по расписанию
sudo python3 /opt/vless-ultimate/main.py --autoban
sudo python3 /opt/vless-ultimate/main.py --ttl-check
sudo python3 /opt/vless-ultimate/main.py --smart-balance
sudo python3 /opt/vless-ultimate/main.py --dpi-check
sudo python3 /opt/vless-ultimate/main.py --scheduled-backup
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

# Быстрый статус
sudo python3 /opt/vless-ultimate/main.py --status

# Проверка конфига Xray
/usr/local/bin/xray run -test -config /etc/xray/config.json

# Логи установки
tail -100 /var/log/vless-install.log
```

## 🔄 Обслуживание

```bash
# Проверка целостности проекта
python3 /opt/vless-ultimate/verify.py

# Обновление до последней версии
cd /opt/vless-ultimate && git pull

# Резервная копия вручную
sudo python3 /opt/vless-ultimate/main.py --scheduled-backup
```

## ❓ Решение проблем

Смотри [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — там собраны решения для всех частых проблем:
- Xray не стартует
- Nginx не стартует
- Certbot не получил сертификат
- Нет IPv6
- APT lock
- Потерян доступ по SSH
- и другие

## 📄 Лицензия

MIT — см. [LICENSE](LICENSE)

## ✍️ Автор

inferno1978 · [GitHub](https://github.com/inferno1978)
