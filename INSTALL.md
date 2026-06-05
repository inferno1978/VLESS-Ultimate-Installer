# Инструкция по установке — VLESS Ultimate Installer v4.12.5

## Быстрый старт (рекомендуется)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/inferno1978/VLESS-Ultimate-Installer/main/bootstrap.sh)
```

Bootstrap скрипт автоматически:
1. Проверяет права root
2. Устанавливает `python3`, `curl`, `git` если отсутствуют
3. Клонирует репозиторий в `/opt/vless-ultimate`
4. Запускает установщик

---

## Ручная установка

```bash
# 1. Клонировать репозиторий
git clone https://github.com/inferno1978/VLESS-Ultimate-Installer /opt/vless-ultimate
cd /opt/vless-ultimate

# 2. Проверить целостность
python3 verify.py

# 3. Запустить
sudo python3 main.py
```

---

## Требования

| Параметр | Значение |
|----------|----------|
| ОС | Ubuntu 20.04 / 22.04 / 24.04 LTS, Debian 11 / 12 / 13 |
| Python | 3.10+ (рекомендуется 3.12) |
| RAM | минимум 512 МБ |
| Диск | минимум 2 ГБ |
| Права | root |
| Сеть | публичный IP, домен с A-записью |

### Предустановка Python 3.12 (если нужно)

```bash
# Ubuntu 20.04 / 22.04
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.12

# Ubuntu 24.04 / Debian 12+
sudo apt-get install -y python3
```

---

## Режимы установки

### Режим A — Одиночный сервер

Клиент → Ваш сервер → Интернет

Выбор протокола при установке:
- **VLESS + TCP + REALITY** — максимальная скорость, имитирует TLS 1.3
- **VLESS + xHTTP + TLS** — для сред с жёстким DPI

### Режим B — Каскад (Россия → Зарубеж)

Клиент → RU-сервер → Зарубежный сервер → Интернет

Нужно два VPS: один в России, один за рубежом. SSH-доступ к зарубежному серверу — для автонастройки.

### Мульти-каскад

До 10 зарубежных нод с балансировкой (`roundRobin`, `leastPing`, `pinned`).

---

## После установки

```bash
# Проверить статус сервисов
systemctl status xray nginx

# Посмотреть сгенерированные ссылки
sudo python3 /opt/vless-ultimate/main.py
# → Управление пользователями → Показать ссылки

# Лог установки
tail -50 /var/log/vless-install.log
```

---

## Обновление

```bash
cd /opt/vless-ultimate
git pull
sudo python3 main.py
# → Установка и Система → Обновить Xray
```

---

## Удаление

```bash
# Через меню
sudo python3 /opt/vless-ultimate/main.py
# → Управление пользователями → Полное удаление

# Или вручную
systemctl stop xray nginx
systemctl disable xray nginx
apt-get remove --purge nginx certbot
rm -rf /etc/xray /var/lib/xray-installer /opt/vless-ultimate
```

---

## Проблемы при установке?

Смотри [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
