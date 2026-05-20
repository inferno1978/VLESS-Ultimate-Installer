## [4.11] — 2026-05-20

### Добавлено
- **Smoke-test после apply** — TCP connect + TLS handshake к своему порту после каждого применения конфига; при провале — предложение аварийного восстановления
- **nginx Watchdog** — systemd timer каждые 2 мин проверяет nginx; перезапускает + Telegram-уведомление; для Reality-режима делает `systemctl reload xray` (меню: `NW`)
- **ipset Persistent** — `ipset save` после каждого apply ingress-блокировки + `xray-ipset-restore.service` (Before=xray.service) для восстановления при reboot (меню: `IP`)
- **Проверка возраста RIPE-файла** — предупреждение (30 дней) и жёсткое предупреждение (90 дней) перед включением ingress-блокировки; баннер в меню статуса
- **Кластерное управление Exit Nodes** — диагностика, перезапуск, обновление Xray-core, ротация UUID на всех Exit Nodes по SSH параллельно с Entry Node (меню: `CL`)
- **Атомарное применение конфига** — модуль `xray_safe_apply` добавляет smoke-test поверх существующего `_xray_safe_apply_config` (backup + xray -test + rollback)
- Архитектура **«один файл → одна ответственность»**: все новые функции в `vless_installer/modules/`
- `nginx-watchdog.timer` добавлен в `_repair_timer` процедуру аварийного восстановления

### Исправлено
- Все ссылки в документации приведены к корректному репозиторию `inferno1978/VLESS-Ultimate-Installer` (ветка `main`)
- `bootstrap.sh`: исправлены `REPO_URL`, `BRANCH`, имя директории архива при fallback-загрузке
- `verify.py`: исправлены URL репозитория и ветка `master` → `main`

# Changelog

## v4.10 (2025-05-19)

### Исправлено

- **[CRITICAL] Отвал клиентов (EOF) после применения RIPE-подсетей при включённой блокировке входящих из РФ**

  **Симптом:** после нажатия «РФ подсети RIPE NCC → Скачать/обновить» при одновременно
  включённой «Блокировке входящих из РФ» все клиенты переставали подключаться с ошибкой
  `outbound/vless[proxy]: EOF`. Помогало только Аварийное восстановление.

  **Причина — deadlock в `_nginx_restart_if_reality`:**
  В режиме REALITY unix-сокет (`/dev/shm/XXXX.socket`) создаётся и принадлежит **nginx**.
  Xray при старте выполнял `ExecStartPre: rm -f /dev/shm/XXXX.socket`, удаляя сокет nginx.
  Функция восстановления ждала появления сокета *до* перезапуска nginx — deadlock,
  потому что сокет появляется только *после* запуска nginx. Цикл ждал 20 секунд,
  не дожидался, делал `return` — nginx не перезапускался, клиенты получали EOF бессрочно.

  **Исправления:**
  - `_nginx_restart_if_reality`: порядок инвертирован — сначала `restart nginx`
    (он создаёт сокет), затем ждём подтверждения появления сокета. Добавлена
    защита для AWG-режима (там unix-сокет не используется).
  - `create_xray_service`: убрана строка `ExecStartPre: rm -f socket` из шаблона
    `xray.service`. Xray не является сервером на этом сокете и не должен его удалять.
  - `_ru_subnets_apply_to_xray`: добавлен патч существующего `xray.service` на лету
    перед каждым рестартом (исправляет установленные системы без переустановки).
    Таймаут ожидания `xray active` увеличен с 15 до 90 секунд
    (конфиг с 13 000+ RIPE-правил поднимается 30–60 сек).
    nginx перезапускается в любом случае даже при истечении таймаута.
  - `_rebuild_and_restart_xray`, `_as_direct_apply_to_xray`: та же логика
    «nginx первым», таймауты 90 сек.


## v4.06

### Добавлено
- AmneziaWG (AWG 2.0) multi-node поддержка с балансировкой
- Smart Balancer: автовыбор лучшей ноды (roundRobin / leastPing / pinned)
- Failover A↔B: автопереключение при отказе exit-нод
- DPI Detector: обнаружение активного зондирования
- Honeypot-порт: ловушка для сканеров
- AutoBan: автоматический бан по TLS-ошибкам
- Telegram-уведомления для всех ключевых событий
- Traffic Limits: лимиты трафика на пользователя
- TTL-пользователи: автоудаление по сроку
- Health Report: ежедневный отчёт на Telegram
- Config Changelog: лог изменений конфигурации
- GeoIP блокировка входящих (для Режима B)
- AS-direct routing: маршрутизация по номеру ASN
- Migration wizard: смена домена без переустановки
- Clash Meta / Sing-box конфиг-генератор
- xHTTP `streamup` режим с xmux поддержкой
- Certbot мониторинг с авто-обновлением

### Улучшено
- Мульти-каскад до 10 exit-нод
- MTU/MSS автотюнинг
- DNSCrypt-proxy оптимизация
- Watchdog для xray и AWG-туннелей

## v3.99

### Добавлено
- Базовая поддержка AmneziaWG
- CloudFlare WARP (full / selective / runet)
- Split Tunneling с geosite/geoip
- РФ-подсети из RIPE NCC
- Scheduled Backup

## v3.x

- Базовая установка VLESS + REALITY
- Режим B (каскад)
- Управление пользователями
- Диагностика
