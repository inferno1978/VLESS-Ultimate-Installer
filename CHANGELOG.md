# Changelog

---

## v4.12.8-patch5 — 14 июня 2026 — NaiveProxy + Mieru: HTTPS/mTLS маскировка трафика

### Контекст

Два новых протокола для обхода DPI-фильтрации. Оба модуля написаны
в едином стиле проекта — без сторонних зависимостей, чистое удаление,
встроенный гайд, QR-коды для клиентов.

### NaiveProxy (`naiveproxy.py`)

**Принцип:** HTTPS/HTTP2 с Chromium fingerprint + probe resistance.
DPI видит легитимный HTTPS трафик к домену. Зонды РКН видят фейковый сайт.

**Схема:**
```
Клиент (Karing/NekoBox/ShadowRocket)
  │  HTTPS/HTTP2 + Chromium fingerprint
  ▼
caddy-forwardproxy-naive :443
  │  probe resistance → фейковый сайт для незнакомых клиентов
  ▼
Интернет
```

**Каскад Entry→Exit:**
```
Клиент → caddy-naive Entry (RU) → upstream → caddy-naive Exit (EU) → Интернет
```

**Что делает модуль:**
- Скачивает caddy-forwardproxy-naive (prebuilt amd64)
- Генерирует Caddyfile с probe resistance и basicauth
- Создаёт фейковый HTML-сайт для незнакомых клиентов
- Systemd-сервис с `CAP_NET_BIND_SERVICE` (без root)
- Открывает TCP 443 в iptables
- Управление пользователями с bcrypt хешированием паролей
- Каскад Entry→Exit через upstream в Caddyfile
- Генерация `naive+https://` ссылок и QR-кодов
- Встроенный гайд: DNS, probe resistance, каскад, клиенты

**Требования:** домен с A-записью на VPS, порт 443/tcp

**Клиенты:** Karing, NekoBox (Android), ShadowRocket (iOS), naiveproxy CLI

---

### Mieru (`mieru.py`)

**Принцип:** mTLS + рандомный padding — трафик без паттернов.
Не требует домена. Временная метка защищает от replay-атак.

**Схема:**
```
Клиент (Karing / Nekobox / sing-box)
  │  mTLS + random padding + timestamp
  ▼
mita :2012-2022 (диапазон портов)
  │  проверка ±30 сек, встроенный SOCKS5
  ▼
Интернет
```

**Что делает модуль:**
- Скачивает mita (сервер) и mieru (CLI) с GitHub (amd64/arm64)
- Устанавливает chrony если нет NTP-синхронизации
- Применяет конфиг через `mita apply config`
- Systemd-сервис `mita`
- Открывает диапазон TCP/UDP портов в iptables
- Управление пользователями с hot-reload конфига
- Проверка NTP-синхронизации в статусе
- Генерация `mieru://` ссылок, sing-box JSON outbound и QR-кодов
- Встроенный гайд: как работает, синхронизация времени, TCP vs UDP

**Требования:** только IP и порт, домен не нужен

**Клиенты:** Karing, Nekobox (Android), sing-box CLI

---

### Интеграция в `_core.py`

- Пункт **11** в главном меню: `🔐 NaiveProxy`
- Пункт **12** в главном меню: `🔒 Mieru`
- Промпт выбора обновлён до `1–12 / 0`
- Импорты `do_naiveproxy_menu`, `do_mieru_menu`

### Что не затрагивается

- Xray `config.json` и VLESS-inbound
- `state.json` инсталлера
- iptables-правила других модулей
- Любые другие службы

### NaiveProxy vs Mieru — когда что выбрать

| | NaiveProxy | Mieru |
|---|---|---|
| Маскировка | HTTPS/H2 Chromium | mTLS + random padding |
| Домен | Обязателен | Не нужен |
| Probe resistance | ✓ | — |
| Синхронизация времени | — | ±30 сек обязательно |
| Клиенты | Karing, NekoBox, ShadowRocket | Karing, NekoBox, sing-box |

---

---

## v4.12.8-patch2 — 12 июня 2026 — VK Turn Tunnel: два клиента, два модуля

### Контекст

Предыдущая реализация `turntunnel.py` запускала `vk-turn-proxy` с флагом
`-vless`, который предназначен для работы в паре с CLI-клиентом (`client -vless`)
а не с мобильным приложением WireTurn. Xray inbound добавлялся, но к нему
никто не подключался. Одновременно WireTurn ожидает сервер Turnable, а не
vk-turn-proxy. Патч разделяет схемы на два независимых модуля.

### Новое

#### Модуль `vkturn_menu.py` — диспетчер пункта 8

- Новая точка входа `do_vkturn_menu()` вместо `do_turntunnel_menu()`
- Показывает выбор между двумя подсистемами с текущим статусом каждой
- Оба модуля могут быть установлены и работать одновременно (разные порты,
  разные сервисы, не конфликтуют)

#### Модуль `turntunnel.py` — рефакторинг под FreeTurn

- Убран флаг `-vless` из systemd ExecStart
- Удалён весь Xray-блок:
  `_xray_inject_turn_inbound`, `_xray_remove_turn_inbound`,
  `_xray_write_and_test`, `_xray_has_turn_inbound`, `_xray_get_turn_inbound`
- Удалён перезапуск Xray после установки/удаления
- Добавлен QR-код адреса сервера (`IP:порт`) для сканирования в FreeTurn
- Обновлена инструкция: вкладка «Сервер» и вкладка «Клиент» в FreeTurn
- Целевой сервис — WireGuard (UDP 51820) или Hysteria2, выбирается при установке
- Клиент: **FreeTurn** (samosvalishe/turn-proxy-android)

#### Модуль `turnable.py` — новый, под WireTurn

- Скачивает бинарник **Turnable** (TheAirBlow/Turnable, v0.4.1, linux-amd64)
- Генерирует пару ключей через `turnable keygen` (priv_key / pub_key)
- Запрашивает Call ID ВК-звонка (принимает полную ссылку или только ID)
- Создаёт `/opt/turnable/config.json` и `store.json` с маршрутом VLESS
- Добавляет VLESS-inbound в `config.json` Xray:
  `127.0.0.1:12767`, plain TCP, тег `vless-turnable-inbound`;
  проверка через `xray -test` перед применением; откат при ошибке
- Создаёт systemd-сервис `turnable` с `After=xray.service`
- Открывает UDP 56001 в iptables (56000 зарезервирован для FreeTurn)
- Генерирует `turnable://` ссылку через `turnable config generate`
- Показывает два QR-кода: turnable:// ссылка + VLESS-ссылка для Xray
- Хранит состояние в `/var/lib/xray-installer/turnable.json`
- При удалении: сервис, бинарник, inbound из Xray, iptables, turnable.json
- Клиент: **WireTurn** (spkprsnts/WireTurn)

### Схемы трафика

```
FreeTurn (Android)
  │  DTLS 1.2 / STUN ChannelData
  ▼
TURN-серверы ВКонтакте
  │  UDP → VPS :56000
  ▼
vk-turn-proxy server (UDP relay)
  │  UDP → WireGuard / Hysteria2
  ▼
Интернет
```

```
WireTurn + встроенный Xray (Android)
  │  WebRTC DTLS / TURN
  ▼
TURN-серверы ВКонтакте
  │  UDP → VPS :56001
  ▼
Turnable server
  │  TCP → Xray inbound :12767
  ▼
Xray (VLESS plain TCP, только localhost)
  │
  ▼
Интернет
```

### Изменения в `_core.py`

- Импорт заменён: `do_turntunnel_menu` → `do_vkturn_menu` из `vkturn_menu`
- Вызов пункта 8 обновлён соответственно
- Подпись пункта 8: `FreeTurn (vk-turn-proxy) · WireTurn (Turnable)`

### Что не затрагивается

- Основной VLESS/REALITY inbound и его пользователи
- Hysteria2, MTProxy, SlipGate, qWDTT и все прочие модули
- iptables-правила других модулей (ipban, autoban, geoip, telemt)
- `state.json`

---

## v4.12.8-patch4 — 11 июня 2026 — qWDTT: WireGuard через TURN ВКонтакте

### Контекст

Альтернатива vk-turn-proxy для пользователей которым нужна парольная модель
доступа, временные пароли с TTL, лимиты устройств и управление через
Telegram без SSH. Использует WireGuard как внутренний протокол вместо VLESS,
ключи WRAP выводятся из пароля через HKDF — не хранятся в APK.

### Схема трафика

```
Android (qWDTT APK)
  │  WRAP RTP AEAD/ChaCha20-Poly1305 поверх DTLS 1.2
  ▼
TURN-серверы ВКонтакте  (трафик = медиа-поток звонка)
  │  UDP → VPS :56000
  ▼
wdtt-server  (:56000/udp DTLS)
  │  WireGuard  (:56001/udp внутренний)
  ▼
WireGuard tun: wdtt0  (10.66.66.0/16)
  │  NAT MASQUERADE
  ▼
Интернет
```

### Новое

#### Модуль `wdtt.py` — установка и управление qWDTT

- Сборка `wdtt-server` из исходников Go (github.com/SpaceNeuroX/proxy-turn-vk-android)
  с автоустановкой Go через apt если отсутствует
- Systemd-сервис с `After=network-online.target`
- iptables: UDP порт 56000, MASQUERADE для подсети `10.66.66.0/16`
- IP forwarding (`net.ipv4.ip_forward=1`) через `/etc/sysctl.d/99-wdtt.conf`
- **Парольная модель:**
  - Главный пароль — бессрочный (для администратора)
  - До 10 временных паролей с TTL (1–365 дней) и лимитом устройств
  - Ключи WRAP выводятся через HKDF — не хранятся в клиентском APK
- **Hot reload** через SIGHUP — смена паролей без перезапуска службы
  и разрыва активных соединений
- **Telegram-бот** (опционально): `/new`, `/list`, деактивация,
  отвязка устройств, удаление паролей — всё без SSH
- Генерация `qwdtt://` ссылок и `.conf` файлов для клиента
- Состояние в `/var/lib/xray-installer/wdtt.json`,
  пароли в `/etc/wdtt/passwords.json`
- При удалении чисто убирает всё: сервис, бинарник, конфиги,
  iptables-правила, sysctl

#### Встроенный гайд (пункт [G])

- Скачать qWDTT APK (github.com/SpaceNeuroX/proxy-turn-vk-android/releases)
- Получить VK-хеш звонка (часть ссылки после /join/)
- Подключение по `qwdtt://` ссылке — формат и импорт в приложение
- Telegram-бот — создание бота, команды, возможности
- Сравнение с vk-turn-proxy — когда что выбрать

#### Интеграция в `_core.py`

- Новый пункт **10** в главном меню: `🔒 qWDTT (WireGuard/TURN)`
- Импорт `do_wdtt_menu` на уровне модуля
- Промпт выбора обновлён до `1–10 / 0`

### Отличия от vk-turn-proxy (turntunnel.py)

| | vk-turn-proxy | qWDTT |
|---|---|---|
| Протокол | VLESS (Xray) | WireGuard |
| Аутентификация | UUID | Пароль + HKDF |
| Клиент | WireTurn | qWDTT APK |
| Временные пароли | turntunnel_links.py | Встроено (TTL, лимит) |
| Telegram-бот | — | ✓ |
| Hot reload | — | ✓ SIGHUP |

### Что не затрагивается

- `config.json` Xray и VLESS-inbound
- `state.json` инсталлера
- iptables-правила других модулей (ipban, turntunnel, autoban)
- Любые другие службы

---

---

## v4.12.8-patch3 — 11 июня 2026 — SlipGate/SlipNet: DNS-туннели для обхода полных блокировок

### Контекст

Когда все прямые соединения заблокированы — VLESS, WireGuard, TURN —
DNS-туннель работает потому что операторы не могут заблокировать DNS
не нарушив работу всего интернета.
Трафик прячется внутри DNS-запросов и выглядит как обычная DNS-активность.
Данный патч интегрирует SlipGate (github.com/anonvector/slipgate) —
серверный компонент для DNS-туннелей — в VLESS Ultimate Installer.

### Схема трафика

```
Android / CLI (SlipNet)
  │  DNS-запросы (UDP/53) с данными внутри
  ▼
DNS-сервер оператора / публичный резолвер
  │  NS-делегирование на поддомен
  ▼
VPS :53/udp — SlipGate (DNSTT/NoizDNS/Slipstream/VayDNS)
  │  расшифровка, Curve25519
  ▼
SOCKS5 :1080 / SSH :22 → Интернет
```

### Поддерживаемые протоколы

| Протокол    | Транспорт         | Домен нужен | Порт    |
|-------------|-------------------|-------------|---------|
| DNSTT       | DNS (UDP)         | Да (NS)     | 53/udp  |
| NoizDNS     | DNS + DPI-obfs    | Да (NS)     | 53/udp  |
| Slipstream  | QUIC over DNS     | Да (NS)     | 53/udp  |
| VayDNS      | KCP + Curve25519  | Да (NS)     | 53/udp  |
| StunTLS     | SSH over TLS+WS   | Нет         | 443/tcp |
| NaiveProxy  | HTTPS Chromium FP | Да (A)      | 443/tcp |

### Новое

#### Модуль `slipgate.py` — установка и управление SlipGate

- Установка через официальный `install.sh` от авторов (AGPL-3.0)
- Управление туннелями через SlipGate TUI (`slipgate` без аргументов)
- Генерация `slipnet://` URI для импорта в клиент (пункт [3])
- Статус всех туннелей и systemd-сервисов
- Диагностика (`slipgate diag`)
- Просмотр логов по туннелям и общих
- Обновление (`slipgate update`)
- Удаление (`slipgate uninstall`) — чисто убирает всё
- Хранит флаг установки в `/var/lib/xray-installer/slipgate.json`

#### Встроенный гайд (пункт [G])

Полная документация прямо в TUI без выхода в браузер:

- **DNS-настройка** — A-запись для NS-сервера, NS-записи для каждого
  туннеля, A-запись для NaiveProxy; команда проверки (`dig NS`)
- **Android-клиент** — где скачать SlipNet APK, как импортировать
  `slipnet://` профиль, порядок подключения
- **CLI-клиент** — скачивание `slipnet-linux-amd64`, использование
  с SOCKS5 прокси, кастомный порт
- **Добавить туннель** — пошагово через TUI и через CLI
- **Типы туннелей** — что выбрать под конкретную ситуацию

#### Интеграция в `_core.py`

- Новый пункт **9** в главном меню: `🌐 SlipGate / SlipNet`
- Импорт `do_slipgate_menu` на уровне модуля
- Промпт выбора обновлён до `1–9 / 0`

### Клиентская часть

- **Android**: SlipNet APK — `github.com/anonvector/SlipNet/releases`
- **Linux/macOS/Windows**: `slipnet-linux-amd64` из тех же релизов
- Импорт через `slipnet://BASE64...` URI (генерируется пунктом [3])

### Что не затрагивается

- `config.json` Xray и основной VLESS/REALITY inbound
- `state.json` инсталлера
- iptables-правила других модулей
- Пользователи и UUID VLESS
- Любые другие службы

### Примечание по лицензии

SlipNet (клиент, APK) — закрытая лицензия, запрещающая распространение
через app stores. Модуль инсталлера не распространяет клиент —
только скачивает серверный компонент (SlipGate, AGPL-3.0) и показывает
ссылку на официальный GitHub для загрузки клиента.

---

---

## v4.12.8-patch1 — 8 июня 2026 — Fragment Fuzzer: режим тестирования с клиента

### Контекст

Режим A фаззера (тест с VPS) давал ориентировочные результаты, поскольку DPI
между VPS и интернетом отсутствует — все 8 комбинаций показывали 100% успех,
а победитель выбирался лишь по минимальному TTFB. Реальный DPI находится
на маршруте **клиент → VPS**, и единственный способ его проверить — тестировать
с клиентского устройства. Кроме того, fingerprint был захардкожен как `chrome`
вместо чтения из `state.json`.

### Изменения в `fragment_fuzzer.py`

#### Режим B — тест с клиента (новый)

- Генерирует все 8 конфигов из матрицы в `fragment_configs/fuzz_NN_label.json`
- Опциональный HTTP-коллектор на порту `:10901`: клиент запускает каждый конфиг
  и отправляет результат одной командой:
  ```
  curl "http://VPS:10901/report?id=01&ttfb=420&ok=1"
  ```
- Сервер собирает ответы в реальном времени, строит таблицу с рейтингом
- По завершении предлагает сохранить победителя как `fragment_recommended.json`
- Коллектор завершается автоматически (5 мин таймаут, все ответы получены,
  или Enter на сервере)
- HTTP-коллектор принимает только `GET /report?...` — никаких команд не выполняет

#### Исправления режима A

- FP больше не захардкожен как `chrome` — читается из `state.json`
  через `_fp_from_state()` с fallback на `chrome`
- `_FUZZ_REPEATS` увеличен с 3 до 5 для статистической надёжности
- Добавлены метки (`label`) в матрицу для читаемости таблиц

#### Прочее

- `_patch_fp_in_config()` — патчит FP во всех сгенерированных конфигах
- Меню стало двухуровневым: `[A]` Тест с VPS / `[B]` Тест с клиента
- Публичное API не изменилось: `do_fragment_fuzzer_menu()` — точка входа та же
- `/etc/xray/config.json` не затрагивается ни в каком режиме

### Совместимость

- Обратная совместимость полная: `run_fragment_fuzzer()` сохранено с прежней сигнатурой
- Интеграция в `_core.py` (F2) не изменялась

---

## ✨ v4.12.8 — 8 июня 2026 — Telemt: MSS-фрагментация против TSPU JA4 DPI

### Контекст

С 1 апреля 2026 г. TSPU (часть АСБИ) развернул правила JA4/JA3-дактилоскопии,
распознающие MTProxy Fake-TLS по уникальному паттерну TLS ClientHello.
Объявление малого TCP MSS в SYN/ACK вынуждает клиентское ядро дробить
ClientHello по нескольким сегментам — поля ALPN и signature_algorithms,
необходимые для JA4, попадают во 2-й/3-й сегмент, одно-пакетный
экстрактор TSPU видит неверный хэш и пропускает соединение.

### Новое

#### Модуль `telemt_mss_selector.py` — интерактивный выбор MSS-пресета

- **10 пресетов** с подробным описанием и рекомендацией по умолчанию:
  - `tspu` (MSS 92) ★ — нативный пресет telemt против TSPU JA4, рекомендуется
  - `2in8` (MSS 256) — умеренная фрагментация, меньше overhead
  - `512` (MSS 512) — лёгкая фрагментация для линий с потерями пакетов
  - `extreme-low` (MSS 88) — максимальная фрагментация
  - `1024` / `768` / `336` / `176` / `128` — градации для тонкой настройки
  - Без изменений — MSS ядра, `client_mss` не пишется в конфиг
- **Ручной ввод** произвольного значения MSS (88–4096) через пункт `C`
- Полностью self-contained: свои цвета, box-рендеринг в стиле проекта
- Lazy-import через `_get_mss_module()` — ошибка импорта не прерывает установку

#### Обновления `mtproto.py`

- Новый шаг выбора MSS вставлен в `_run_install_inner()` сразу после выбора домена
- `_write_config()` получил параметр `client_mss: str = ""` — обратная совместимость
  сохранена: при пустом значении поле не пишется в `telemt.toml`
- Итоговый бокс установки отображает выбранный пресет и MSS в байтах
- Lazy-import `_get_mss_module()` добавлен по тому же паттерну, что `_get_fallback_module()`

### Совместимость

- `client_mss` поддерживается в telemt ≥ 3.4.15; на более ранних версиях
  параметр игнорируется без ошибки — конфиг остаётся рабочим
- Все существующие функции (`_write_config`, установка, iptables, xray-интеграция,
  fallback, статистика) работают без изменений
- Вызовы `_write_config()` без аргумента `client_mss` продолжают работать

---

## v4.12.7 — 7 июня 2026 — IP-Бан: ручная блокировка на уровне iptables/ipset

### Новое

#### Модуль IP-Бан (`ipban.py`) — ручная блокировка на уровне iptables

Новый модуль `vless_installer/modules/ipban.py` реализует ручной бан IP-адресов
на уровне iptables через ipset — независимо от Xray и GeoIP-блокировки.

**Доступ:** меню «🛡️ Безопасность» → `[IB] IP-Бан`

**Поддерживаемые форматы ввода** (можно несколько через запятую или пробел):

| Формат | Пример | Описание |
|---|---|---|
| Одиночный IP | `1.2.3.4`, `::1` | IPv4 или IPv6 |
| Подсеть CIDR | `10.0.0.0/24`, `2001:db8::/32` | IPv4 и IPv6 |
| Диапазон IPv4 | `10.0.0.1-10.0.0.255` | суммируется в список CIDR |
| ASN | `AS209334`, `12345` | все префиксы через RIPE Stat API |

**Реализация:**
- `ipset hash:net xray_manual_ban` (IPv4) + `xray_manual_ban6` (IPv6)
- Правила `iptables`/`ip6tables` INPUT DROP через `-A` (в конец цепочки) — не нарушают ESTABLISHED/RELATED правила
- State в `/var/lib/xray-installer/ipban.json` — сохраняет все записи с типом, CIDR и датой
- Персистентность: при каждом бане/разбане обновляет `/etc/ipset.conf`, дополняя секции GeoIP-блокировки

**Операции в меню:**
- `[1]` Добавить бан
- `[2]` Снять бан — нумерованный список с выбором по номеру или имени
- `[3]` Список активных банов с типом, количеством CIDR, датой и комментарием
- `[4]` Восстановить из state (после reboot, если `xray-ipset-restore.service` не установлен)
- `[5]` Сохранить ipset → `/etc/ipset.conf`
- `[X]` Снять все баны (flush + удаление сетов, с подтверждением)

**Изолированность:** модуль не затрагивает Xray-конфиг, GeoIP-блокировку (`xray_ru_block*`), AutoBan и никакие службы.

---

## v4.12.7 — 7 июня 2026 — TG-бот: управление Fingerprint; фикс FP при добавлении пользователя

### Новое

#### Telegram-бот: команды `/fp` и `/setfp`

Новый модуль `user_fp_manager.py` расширяет сгенерированный бот-скрипт двумя
admin-only командами, позволяя менять TLS Fingerprint без SSH на сервер:

- `/fp` — показывает текущий FP и полный список доступных вариантов (все 11: chrome, firefox, safari, ios, android, edge, 360, qq, random, randomized, none)
- `/setfp <имя>` — меняет FP немедленно: патчит `config.json`, валидирует через `xray run -test`, перезапускает Xray, обновляет `state.json` (включая `chain_nodes[*].fp` в режиме B)

Смена FP поддерживает все режимы установки: A, B, B-Multi, xHTTP, REALITY.
При ошибке валидации конфиг автоматически откатывается из бэкапа.

Чтобы команды появились в боте — пересоздать бот-скрипт через меню
`Security → [TB] Telegram Config Bot → перезапустить бота`.

### Исправлено

#### Неверный FP в ссылке при добавлении пользователя после установки

**Симптом:** при добавлении нового пользователя через «Менеджер пользователей»
сгенерированная ссылка всегда содержала `fp=chrome`, независимо от того,
какой Fingerprint был выбран при установке. У пользователей с заблокированным
`chrome` соединение не устанавливалось.

**Причина:** в `_unified_show_links()` FP был захардкожен строкой `"chrome"`
вместо чтения из `state.json`.

**Исправление:** `st.get("fingerprint", "chrome") or "chrome"` — теперь ссылка
всегда использует реально сконфигурированный Fingerprint.

---

## ✨ v4.12.7 — 7 июня 2026 — Telemt: гибридный fallback Middle Proxy → Direct Mode

### Новое

#### Telemt: автоматический fallback из Middle Proxy в Direct Mode

Новый модуль `telemt_fallback.py` реализует гибридный режим работы Telemt:
при деградации ME-серверов Telegram сервис автоматически переключается в
Direct Mode без перезапуска и разрыва активных соединений.

**Новые параметры в секции `[middle_proxy]` в `telemt.toml`** (все опциональны,
старые конфиги работают без изменений):

```toml
[middle_proxy]
fallback_to_direct      = true   # разрешить автоматический fallback
fallback_after_attempts = 3      # попыток инициализации ME-пула до признания недоступным
fallback_after_seconds  = 45     # максимальное время warmup (секунд)
auto_revert_to_middle   = false  # автовозврат в Middle после восстановления (каркас)
```

**Логика работы:**
- После старта Telemt выполняется TCP-проверка ME-серверов (DC1–DC5, кворум ≥34%)
- При неудаче после `fallback_after_attempts` попыток или по истечении `fallback_after_seconds` — runtime-переключение в Direct Mode
- Переключение затрагивает только транспорт до Telegram DC; порты, iptables и xray-интеграция не изменяются
- Защита от restart-loop: повторная попытка инициализации Middle Proxy только при `systemctl reload` или через `auto_revert_to_middle`

**Новые пункты в меню Telemt:**
- `[F]` Hybrid Fallback — просмотр состояния, изменение параметров, ручное переключение режима, ME-проба, hot-reload
- Строка статуса `Fallback:` в шапке меню

**Логирование:**
```
WARN  Middle Proxy warmup timeout exceeded (45s)
WARN  ME pool initialization failed after 3 attempts
WARN  ME pool initialization failed for too long → falling back to Direct DC mode for stability
INFO  Runtime transport mode switched: Middle Proxy -> Direct
INFO  Configuration reload requested Middle Proxy mode, starting ME pool initialization
```

**Встроенные тесты:** `python telemt_fallback.py --test` (24 теста)

---

### Исправлено

#### Telemt: дублирование ключа `use_middle_proxy` в `telemt.toml`

**Симптом:** После срабатывания fallback Telemt не запускался:
```
TOML parse error at line 7, column 1
use_middle_proxy = false
^^^^^^^^^^^^^^^^
duplicate key
```

**Причина:** `_patch_config_middle_proxy()` определяла отсутствие ключа по сравнению
строк `new_text == text`. При повторном вызове с тем же значением (`false → false`)
regex заменял успешно, но строки оставались идентичными — функция уходила в ветку
вставки и добавляла второй экземпляр ключа.

**Исправление:** Наличие ключа теперь проверяется отдельным `re.search` до любых
замен. Добавлен проход по строкам, удаляющий дубликаты даже из уже повреждённых
конфигов. Функция идемпотентна: N последовательных вызовов гарантируют ровно одно
вхождение ключа.

---

#### Telemt: неполный список `[dc_overrides]` в Direct Mode

**Симптом:** При fallback в Direct Mode часть Telegram DC могла не резолвиться —
в конфиг добавлялся только DC203, тогда как Telemt обслуживает группы
`[-203, -3, -2, -1, 1, 2, 3, 203, -5, -4, 5]`.

**Исправление:** `[dc_overrides]` теперь содержит все 12 записей:
DC1–DC5, их зеркала (-1..-5), DC203 и -DC203.

---

## 🛠 v4.12.7 — 6 июня 2026 — Хотфиксы Ubuntu 22.04

### Исправлено

---

#### nginx: default server без сертификатов при `return 444` (nginx < 1.19.4)

**Симптом:** На Ubuntu 22.04 (nginx 1.18.0) nginx не запускался после установки:
```
nginx: [emerg] no ssl configured for the server
```

**Причина:** Предыдущий фикс (`ssl_reject_handshake` → `return 444`) был неполным.
Директива `listen ... ssl` **всегда** требует `ssl_certificate` и `ssl_certificate_key` —
кроме случая когда присутствует `ssl_reject_handshake on;`, которая специально снимает
это требование. Без неё nginx падал даже с `return 444`.

**Исправление:** Для nginx < 1.19.4 в default server блок теперь добавляются те же
сертификаты что и в основном блоке:
- nginx ≥ 1.19.4 → `ssl_reject_handshake on;` (как раньше)
- nginx < 1.19.4 → `ssl_certificate` + `ssl_certificate_key` + `return 444;`

---

#### xray: `config.json` создавался без прав для пользователя `xray`

**Симптом:** На Ubuntu 22.04 xray не запускался сразу после установки:
```
xray[...]: Failed to start: failed to load config files: ... failed to read config: open /usr/local/etc/xray/config.json
```
Помогал только ручной `chown xray:xray /etc/xray/*`.

**Причина:** В двух функциях генерации конфига (`generate_xray_config_chain_entry`,
`generate_xray_config_chain_entry_multi`) `chown` после записи `config.json` не вызывался
вообще. В двух других (`generate_xray_config`, `generate_xray_config_xhttp`) использовался
`_run(["chown", "root:xray", ...], check=False)` — тихо падал без предупреждения если
группа `xray` ещё не была создана в нужный момент.

**Исправление:** Во всех 4 функциях сразу после `cfg_file.write_text(...)` вызывается
`_set_config_owner(cfg_file)` — надёжная функция через `grp.getgrnam` + `os.chown`,
с fallback на `644` при отсутствии группы `xray`.

---

## 🚀 v4.12.7 — 6 июня 2026 — Интерактивный выбор TLS Fingerprint

### Добавлено

---

#### Новый модуль `fingerprint_manager.py`

Централизованный модуль управления TLS/uTLS Fingerprint. Единый источник
правды для всего проекта — список FP, интерактивный выбор, валидация, fallback.

**Полный список поддерживаемых FP (11 вариантов):**
`chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`,
`random`, `randomized`, `none`

Ранее в проекте было захардкожено только 4 варианта (`chrome`, `firefox`,
`safari`, `edge`), и выбора при установке не было — всегда применялся `chrome`.

---

#### Шаг `[11/11]` в мастере установки

В `prompt_parameters()` добавлен интерактивный шаг выбора FP. Пользователь
видит все 11 вариантов с текущим значением по умолчанию, может ввести номер
или имя FP напрямую. При нажатии Enter применяется `chrome` (безопасный
fallback).

Шаг DNSCrypt-proxy переименован из `[10/10]` в `[10/11]`.

---

#### FP для exit-нод в Режиме B

В `prompt_chain_params()` и `_prompt_one_node_manual()` старый локальный
словарь `fp_opts` (4 варианта) заменён вызовом `_fm_prompt_fingerprint()`.
Каждая exit-нода теперь получает полный список из 11 вариантов.

---

#### Сохранение FP в `state.json`

Выбранный fingerprint записывается в `state.json` под ключом `"fingerprint"`.
Это позволяет постустановочным операциям (добавление пользователей, вывод
ссылок) использовать корректный FP без повторного ввода.

---

#### Вспомогательная функция `_fp_from_state()`

Читает FP из `state.json` с fallback на `PARAM_FINGERPRINT` и затем на
`"chrome"`. Используется в `_users_gen_link()` при генерации ссылок
постфактум.

---

### Изменено

- `_FP_LIST` в `do_manage_fingerprint()` теперь импортируется из
  `fingerprint_manager.py` — единый список, нет дублирования.
- Ротационный cron-скрипт исключает мета-варианты (`random`, `randomized`,
  `none`) из пула случайного выбора — только реальные браузерные отпечатки.
- Все хардкоды `&fp=chrome` в URI-ссылках заменены на динамическое значение
  из `PARAM_FINGERPRINT` / `state.json`.

---

### Покрытие режимов

| Режим | FP применяется |
|---|---|
| A (одиночный) | ✅ шаг 11/11 при установке |
| B (chain entry+exit) | ✅ шаг 11/11 + отдельный выбор для каждой exit-ноды |
| AWG | ✅ через те же функции генерации ссылок |
| WARP | ✅ через те же функции генерации ссылок |
| Постустановка (пользователи) | ✅ через `_fp_from_state()` из state.json |

---

## 🐛 v4.12.6 — 5 июня 2026 — Совместимость nginx с Ubuntu 22.04

### Исправлено

---

#### nginx: unknown directive "ssl_reject_handshake" на Ubuntu 22.04

**Симптом:** На Ubuntu 22.04 установщик падал с ошибкой:
```
nginx: [emerg] unknown directive "ssl_reject_handshake"
```

**Причина:** Директива `ssl_reject_handshake` появилась в nginx 1.19.4.
На Ubuntu 22.04 из стандартного репо устанавливается nginx 1.18.0 — директива
не поддерживается.

**Исправление:** Добавлена проверка версии nginx при генерации конфига:
- nginx ≥ 1.19.4 → `ssl_reject_handshake on;` (как раньше)
- nginx < 1.19.4 → `ssl_certificate` + `ssl_certificate_key` + `return 444;`
  (сертификаты обязательны при `listen ... ssl` без `ssl_reject_handshake`, иначе nginx не запустится)

---

#### nginx: конфиг из sites-enabled не загружался при установке из nginx.org репо

**Симптом:** При установке nginx из официального репо nginx.org конфиг сайта
не применялся — nginx игнорировал `/etc/nginx/sites-enabled/`.

**Причина:** nginx из репо nginx.org использует только `conf.d/` и не включает
`sites-enabled/` в `nginx.conf` по умолчанию (в отличие от пакета из Ubuntu репо).

**Исправление:** Добавлена функция `_ensure_nginx_sites_enabled_include()` которая
при каждой настройке nginx проверяет `/etc/nginx/nginx.conf` и добавляет строку
`include /etc/nginx/sites-enabled/*;` после `include conf.d/` если она отсутствует.

---

## 🐛 v4.12.6 — 5 июня 2026 — Фикс IPv6 через прокси (routeOnly: False)

### Исправлено

---

#### IPv6 не работал через прокси несмотря на выбор UseIPv6v4

**Симптом:** После установки и выбора стратегии `UseIPv6v4` IPv6 через прокси не появлялся.
Помогал только ручной патч конфига с последующим рестартом xray.

**Причина:** Во всех VLESS inbound-блоках стояло `routeOnly: True`. Это означает что xray
применял роутинг на основе снифинга, но **не переписывал destination** при передаче в outbound.
В результате freedom outbound получал уже резолвленный IPv4-адрес вместо доменного имени,
и `domainStrategy: UseIPv6v4` не мог сделать свою работу — домен резолвить не нужно,
IP уже есть, и он IPv4.

**Исправление:** `routeOnly: False` во всех 6 VLESS/REALITY inbound-блоках:
- `generate_xray_config()` — Режим A, REALITY
- `generate_xray_config_xhttp()` — Режим A, xHTTP
- `generate_xray_config_chain_entry()` — Режим B, entry нода
- `generate_xray_config_chain_entry_multi()` — Режим B, multi-entry

**Совместимость:** AWG не затронут (`metadataOnly: True` для AWG сохранён).
Telemt tproxy (dokodemo-door) не затронут — у него `sniffing: disabled`.

---

## 🐛 v4.12.5 — 5 июня 2026 — IPv6 не работал через прокси (metadataOnly: True)

### Исправлено

---

#### IPv6 недоступен при подключении через VLESS REALITY (test-ipv6.com показывал 0/10)

**Симптом:** При подключении через прокси сайты с IPv6 открывались по IPv4,
test-ipv6.com показывал `0/10`, хотя на сервере IPv6-связность была (`curl -6` работал),
и в конфиге была выбрана стратегия `UseIPv6v4`.

**Причина:** В трёх функциях генерации конфига Xray параметр `metadataOnly` был
выставлен в `True` для базового сценария (без AWG, без split tunnel):

```python
# Было (неправильно для базового случая):
"metadataOnly": True if AWG_EXIT_ENABLED else (False if SPLIT_TUNNEL_ENABLED else True)
#                                                                              ^^^^ баг
```

При `metadataOnly: True` Xray не читает SNI/Host из трафика клиента.
В результате outbound `freedom` получает уже готовый IPv4-адрес вместо доменного имени,
`domainStrategy: UseIPv6v4` не применяется, и соединение устанавливается по IPv4.

**Затронутые функции:**
- `generate_xray_config()` — Режим A (основная установка)
- `generate_xray_config_chain_entry()` — Режим A/B, xHTTP транспорт
- `generate_xray_config_chain_entry_multi()` — Режим B, VLESS каскад

**Исправление:** Условие упрощено — `metadataOnly: True` только при AWG
(AWG использует маршрутизацию ядра и не зависит от sniffing доменов),
во всех остальных случаях — `False`:

```python
# Стало:
"metadataOnly": True if AWG_EXIT_ENABLED else False
```

**Как исправить на существующей установке** (без переустановки):

```bash
cd /opt/vless-ultimate && git pull

python3 - <<'EOF'
import json
path = "/etc/xray/config.json"
with open(path) as f:
    d = json.load(f)
for ib in d.get("inbounds", []):
    sn = ib.get("sniffing", {})
    if sn.get("metadataOnly") == True:
        sn["metadataOnly"] = False
        print(f"inbound [{ib.get('tag')}] metadataOnly -> False")
    if sn.get("routeOnly") == True:
        sn["routeOnly"] = False
        print(f"inbound [{ib.get('tag')}] routeOnly -> False")
with open(path, "w") as f:
    json.dump(d, f, indent=2, ensure_ascii=False)
print("Готово.")
EOF

systemctl restart xray
```

---

## 🐛 v4.12.4 — 4 июня 2026 — Совместимость с Python 3.10 (Ubuntu 22.04)

### Исправлено

---

#### SyntaxError: f-string expression part cannot include a backslash / unmatched '('

**Симптом:** На Ubuntu 22.04 (Python 3.10) установщик падал с ошибкой:

```
SyntaxError: f-string expression part cannot include a backslash
SyntaxError: f-string: unmatched '('
```

**Причина:** В Python 3.12 (Ubuntu 24.04) был переписан парсер f-строк ([PEP 701](https://peps.python.org/pep-0701/)),
который снял ограничения на использование `\` и одинаковых кавычек внутри `{}` выражений.
Код, написанный и протестированный на 3.12, падал на Python 3.10/3.11.

**Исправлено 13 мест в трёх файлах:**

- `vless_installer/_core.py` — 5 f-строк (включая внутри `f"""..."""` блока конфига DNSCrypt)
- `vless_installer/modules/warp.py` — 8 f-строк с вызовами `_get_warp("KEY", "")`
- `vless_installer/modules/health.py` — 1 f-строка с `_get_state_value("domain", "")`

---

#### Устаревший _core.py при повторном запуске на существующей установке

**Симптом:** После выхода фикса пользователь повторно запускал `bootstrap.sh`,
видел `✓ Обновлено до последней версии`, но ошибка оставалась.

**Причина:** `bootstrap.sh` принудительно перезаписывал с GitHub только `tg_nets.py`.
Если `git pull` тихо завершался с ошибкой — `_core.py` оставался старым.

**Исправление:** Теперь при каждом запуске принудительно обновляются
`_core.py` и `main.py` напрямую с GitHub.

---

### Улучшено

#### Предупреждение о версии Python при запуске

На Python < 3.12 установщик теперь показывает явное предупреждение вместо
молчаливого продолжения, с названиями возможных ошибок и ссылкой на
[deadsnakes PPA](https://launchpad.net/~deadsnakes/+archive/ubuntu/ppa).

---

## 🐛 v4.12.3 — 4 июня 2026 — Три бага в [7] Отключить / Восстановить пользователя

### Исправлено

---

#### 1. После отключения пользователь снова показывается как `[акт]`

**Симптом:** Отключил пользователя — в консоли появляется `ОТКЛЮЧЁН`. Повторно
заходишь в пункт [7] — пользователь снова помечен `[акт]`, хотя должен быть `[ОТКЛ]`.

**Причина:** `_unified_load_users()` при чтении `users.json` полностью игнорировала
поле `disabled` — оно не попадало в словарь пользователя, и статус всегда отображался
как активный.

**Исправление:** При загрузке из `users.json` явно переносим поля `disabled` и
`disabled_at` в результирующий словарь.

---

#### 2. После перезапуска скрипта отключённый пользователь снова получает доступ

**Симптом:** Отключил пользователя — доступ остался (VPN работает). При перезапуске
скрипта состояние полностью сбрасывается.

**Причина:** `_unified_save_users()` записывала в `users.json` словарь **без** поля
`disabled` — флаг существовал только в памяти текущего сеанса. После перезапуска
все пользователи снова оказывались активными и попадали в конфиг Xray.

**Исправление:** `_unified_save_users()` теперь явно включает `disabled` /
`disabled_at` в запись на диск.

---

#### 3. `failed to build inbound config` при отключении последнего / всех пользователей

**Симптом:** После отключения пользователя (особенно если он единственный) в консоль
выводится:

```
[WARN]  Конфиг невалиден — пользователи не применены!
Failed to start: main: failed to load config files: [/etc/xray/config.json]
> infra/Conf: failed to build inbound config with tag inbound-vless
```

**Причина:** Xray не принимает пустой массив `clients: []` в inbound —
это считается невалидным конфигом и Xray отказывается запускаться.

**Исправление:** В `_users_apply_to_config()` добавлена защита: если список активных
пользователей пуст, в `clients` помещается placeholder-запись с нулевым UUID
(`00000000-0000-0000-0000-000000000000`). Inbound остаётся валидным, но реально
подключиться через него невозможно.

---

## 🐛 v4.12.3 — 4 июня 2026 — Фикс импорта незашифрованного архива миграции

### Исправлено

---

#### Миграция: ошибка дешифрования при импорте обычного `.tar.gz`

**Симптом:** При выборе пункта **[2] Импорт** в меню «Миграция конфигурации» и передаче
обычного (незашифрованного) архива `.tar.gz` появлялась ошибка:

```
[WARN]  Ошибка дешифрования — неверный пароль или повреждённый файл
```

**Причина:** Функция `do_full_migration_import()` **всегда** прогоняла архив через
`openssl enc -d`, независимо от того, зашифрован он или нет. Обычный `.tar.gz` через
дешифратор не проходил → ошибка, импорт невозможен.

**Исправление** (`vless_installer/_core.py`):
- Добавлена проверка расширения файла: если суффикс `.enc` — запускается расшифровка,
  иначе — архив используется напрямую
- Запрос пароля теперь появляется **только** для зашифрованных архивов; для `.tar.gz`
  выводится сообщение «пароль не требуется»
- Уточнены подсказки в строке ввода пути и в пункте меню [2]

---

## 🐛 v4.12.3 — 4 июня 2026 — Три фикса: Hysteria2, DNS в Режиме B, Telemt tproxy

### Исправлено

---

#### 1. Hysteria2: `Exec format error` при запуске сервиса

**Симптом:** `hysteria-server.service: Failed to execute /usr/local/bin/hysteria: Exec format error`

**Причина (локальная установка):** `curl -L` скачивал файл и сохранял его даже если GitHub
был недоступен или отдавал HTML-страницу с ошибкой. Xray пытался запустить HTML как
исполняемый файл → `Exec format error`.

**Причина (удалённая установка через SSH):** `_detect_arch()` запускала `uname -m` **локально**
(на entry-node), а URL для скачивания использовался на **удалённой** exit-ноде. При разных
архитектурах скачивался бинарник не той платформы → тот же `Exec format error`.

**Исправление** (`hysteria2_exit_mgr.py`):
- `_install_h2_binary()`: флаг `-fsSL` вместо `-L` (curl возвращает ошибку при HTTP ≥ 400),
  проверка размера файла (< 1 МБ = не бинарник), проверка ELF magic bytes (`\x7fELF`)
  перед установкой — при несовпадении файл удаляется с внятной ошибкой
- `h2_exit_remote_install()`: `uname -m` теперь выполняется через SSH на удалённой машине;
  та же ELF-проверка через `xxd` встроена в remote-команду

---

#### 2. Режим B: DNS-ошибки `exchange failed … IN A: read response: EOF`

**Симптом:** в логах xray массово появлялись ошибки вида:
```
dns: exchange failed for <домен> IN A: read response: EOF
```
Проявлялось только при подключении через entry-ноду с балансировкой (2+ exit-ноды),
при прямом подключении к exit-нодам ошибок не было. Интернет при этом работал.

**Причина:** Xray резолвит домены клиентов через встроенный DNS (`domainStrategy = IPIfNonMatch`).
Запросы идут UDP к `127.0.0.1:5300` (DNSCrypt-proxy). Без AWG не создавался `direct` outbound
и не добавлялось правило `127.0.0.1 → direct`. DNS-запросы попадали в `chain-balancer`
(VLESS TCP), который не может передать UDP к loopback → `read response: EOF`.
При балансировщике активируется `observatory` (зонды каждые 30 сек) — нагрузка на DNS растёт
и ошибки становятся систематическими.

**Исправление** (`_core.py`):
- `direct` outbound создаётся **всегда** (не только при AWG); при AWG fwmark сохраняется
- Правило `127.0.0.1/8 → direct` добавляется **всегда** (`/8` вместо `/32` — весь loopback)
- Исправлено в обоих генераторах: `generate_xray_config_chain_entry()` (1 нода)
  и `generate_xray_config_chain_entry_multi()` (1+ нод, балансировщик)

---

#### 3. Telemt tproxy слетал после пересборки конфига (пункт R в меню нод)

**Симптом:** после нажатия **R** («Пересобрать конфиг Xray и перезапустить») в меню
управления exit-нодами Telegram-клиент переставал подключаться через прокси.
В Telemt → Xray-интеграция отображалось «tproxy не настроен».

**Причина:** `_rebuild_and_restart_xray()` вызывает `generate_*`, которая перезаписывает
`config.json` целиком. Теряются dokodemo-door inbound и iptables-правила Telemt.
Восстановление tproxy существовало, но вызывалось только из `do_emergency_repair()` —
при обычной пересборке конфига не выполнялось.

**Исправление** (`_core.py`):
- В `_rebuild_and_restart_xray()` добавлен вызов `telemt_tproxy_emergency_restore()`
  **перед** финальным `systemctl restart xray` — inbound уже вшит в новый конфиг к моменту запуска
- Если Telemt не установлен — вызов молча пропускается (None-результат)

---

## 🐛 v4.12.3 — 3 июня 2026 — Фикс Mode B + xHTTP + AWG (Xray не стартовал)

### Исправлено

**Xray не запускался при установке в режиме B (каскад) с xHTTP + AmneziaWG** — с ошибкой:
```
failed to build inbound config with tag inbound-vless >
infra/conf: Failed to build REALITY config. >
infra/conf: invalid "privateKey": n/a
```

**Причина:** в `generate_xray_config_chain_entry_multi()` при `AWG_EXIT_ENABLED=True`
безусловно вызывалась `generate_xray_config()`, которая всегда генерирует `inbound`
с `realitySettings`. Но для xHTTP REALITY-ключи не создаются — в конфиг попадали
заглушки `"privateKey": "n/a"`, и Xray падал при старте.

В режиме A проблема не воспроизводилась, потому что там
`generate_xray_config_xhttp()` вызывается напрямую.

**Исправление в двух местах:**

1. `generate_xray_config_chain_entry_multi()` — добавлена проверка `PROTOCOL_MODE`:
   - `xhttp` → вызывается `generate_xray_config_xhttp()` (TLS Let's Encrypt, без `realitySettings`)
   - остальные режимы → `generate_xray_config()` как прежде

2. `generate_xray_config_xhttp()` — в outbound `direct` добавлен `sockopt.mark = AWG_FWMARK`
   при `AWG_EXIT_ENABLED=True`, чтобы исходящий трафик Xray маршрутизировался
   через AWG-туннель (policy routing по fwmark).

**Не затронуто:** Mode A, Mode B + VLESS, Mode B + VLESS + AWG, Mode B + xHTTP без AWG.

---

## 🆕 v4.12.3 — 3 июня 2026 — Hysteria2 транспорт

### Добавлено

- **Меню 7 — Hysteria2 транспорт**: полностью переработан в стиль box_renderer (рамки ╔═╗),
  единый с остальными разделами установщика
- **Выбор Hysteria2 при установке Режима B**: новый пункт `3 — Hysteria2 (QUIC/UDP)`
  в `prompt_awg_exit_mode()` — альтернатива VLESS и AWG 2.0
- **H2_EXIT_ENABLED**: новый глобальный флаг, сохраняется в `state.json`,
  взаимоисключающий с `AWG_EXIT_ENABLED`
- **Балансировщик нод** (hysteria2_balancer): стратегии weightedRandom / leastRtt / roundRobin
- **Health Check, Watchdog, DPI Детектор, Smoke Test, Кластер SSH**: меню приведены к
  единому стилю box_renderer

### Исправлено

- Импорты `box_renderer` вставлялись внутрь незакрытых `from ... import (` блоков → NameError
- `_list_backups` → `h2_backup_list` в меню бэкапа
- Проблемные emoji (`🖧` `🖥️` `⬆️` `⚖️`) ломали правую границу рамки — заменены

---

## 🐛 v4.12.3 — 3 июня 2026 — Фикс статистики трафика пользователей

### Исправлено

**Статистика трафика по пользователям не отображалась** в разделе
«История трафика по дням» (меню 4 → 2) — показывало 0 Б для всех пользователей,
даже при активном трафике.

**Причина:** Xray требует два условия одновременно для подсчёта трафика по пользователям:
- `policy.system.statsUserUplink/Downlink: true` — было ✅
- `policy.levels."0".statsUserUplink/Downlink: true` — **отсутствовало** ❌

Все входящие соединения xray проходят через policy level `0`. Без явного включения
счётчиков на этом уровне — `policy.system` игнорируется и трафик не считается.

**Исправление:** добавлен блок `policy.levels."0"` в трёх местах кода:
- `_xray_stats_blocks()` — шаблон для новых установок
- `_apply_stats_to_config()` — патч конфига на лету
- `do_patch_stats_api()` — ручной патч через меню `4 → P`

### Как применить на существующем сервере

Зайти в меню: **4 (Диагностика и Мониторинг) → P (Патч Stats API)**

Патч идемпотентен — безопасно запускать повторно, ничего не сломает.

### Благодарности

Спасибо **@mkssrk** за обнаружение бага и метод его исправления 🙏

---


## 🚀 v4.12.0-beta — 2 июня 2026 — Hysteria2 транспорт + фиксы Debian 13

> ⚠️ **Beta.** Hysteria2-модули добавлены и интегрированы, но автором
> ещё не тестировались на живом сервере. Используйте с осторожностью,
> сообщайте о проблемах через Issues.

---

### Новое: Hysteria2 как альтернативный транспорт (Режим B)

Добавлена поддержка **Hysteria2** как транспортного уровня между
Entry и Exit нодами. Клиенты подключаются по обычным VLESS-ссылкам
и не замечают смены транспорта — прозрачно.

```
Клиент ──VLESS──► Entry VPS ──Hysteria2/QUIC/UDP──► Exit VPS ──► Интернет
       (ссылка не меняется)   (скрытый транспорт)
```

AWG и Hysteria2 работают параллельно. Переключение через меню в любой момент
без переустановки.

#### Меню

- Главное меню: новый пункт **7 — 🚀 Hysteria2 транспорт**
- Настройки сети: новый пункт **H — 🚀 Hysteria2 транспорт**

#### Подменю Hysteria2

| Пункт | Назначение |
|-------|-----------|
| **1 — Exit-нода** | Установка H2-сервера локально или на удалённую ноду по SSH |
| **2 — Выбор транспорта** | Переключение AWG / Hysteria2 / оба |
| **3 — Балансировщик** | Стратегии weightedRandom, leastRtt, roundRobin |
| **4 — Health Check** | QUIC-пинг, RTT, потери (не TCP) |
| **5 — Watchdog** | Авторестарт через cron каждые 2 мин |
| **6 — Трафик** | RX/TX через iptables/ip6tables/ss, без новых демонов |
| **7 — Сертификаты** | certbot (Let's Encrypt) или самоподписанный |
| **8 — Обновление** | Автообновление бинарника с GitHub Releases |
| **9 — Кластер SSH** | status / restart / logs / update на группе нод |
| **B — Бэкап** | Резервное копирование конфигов + миграция из AWG |
| **D — DPI детектор** | Тест блокировки QUIC/UDP, авто-фолбэк на другой порт |
| **Q — Качество** | RTT/потери/скорость + Telegram-отчёт + авто-оптимизация |
| **S — Smoke Test** | Полная проверка после установки |
| **L — Логи** | Просмотр /var/log/hysteria*.log |

#### CLI-флаги

```bash
sudo python3 main.py --h2-install-exit [--h2-port 443,8443]
sudo python3 main.py --h2-transport h2|awg
sudo python3 main.py --h2-status
sudo python3 main.py --h2-health
sudo python3 main.py --h2-traffic
sudo python3 main.py --h2-quality-report [--tg]
sudo python3 main.py --h2-logs
sudo python3 main.py --h2-cluster status|restart|logs|update
sudo python3 main.py --h2-smoke
sudo python3 main.py --h2-weights 1.2.3.4:1.5,5.6.7.8:0.5
sudo python3 main.py --h2-autoupdate        # из cron
sudo python3 main.py --h2-watchdog-run      # из cron
sudo python3 main.py --h2-cert-monitor      # из cron
sudo python3 main.py --h2-dpi-check         # из cron
```

#### Особенности реализации

- **Zero-breakage** — ни одна существующая функция не изменена.
  VLESS/xHTTP TLS, AWG, генерация ссылок и конфигов работают штатно
- **15 новых модулей** в `vless_installer/modules/hysteria2_*.py`
- **Только +15 строк** в `_core.py` (импорт + 2 пункта меню)
- **DualStack** — полная поддержка IPv4 и IPv6 на всех этапах
- **Health Check через QUIC**, не TCP
- **Статистика** через iptables/ip6tables/ss — без новых демонов
- **Автофолбэк порта** при детекции блокировки DPI
- **Миграция** из AWG: `python3 migrate_awg_to_h2.py`

---

### Фикс: Debian 13 / Python 3.13 — `SyntaxError: "(" unexpected` в cron

**Затронуто:** `xray-traffic-snapshot.sh` и `xray-autoban.sh`

**Проблема:** оба скрипта генерировались через `textwrap.dedent(f"""...""")`
с Python-кодом внутри `python3 -c "..."`. Из-за смешанных отступов
`dedent` не убирал пробелы перед `#!/bin/bash`, получался невалидный
shebang. На Debian 13 (`/bin/sh` = dash вместо bash) скрипты
запускались через dash и падали с `Syntax error: "(" unexpected`
примерно на строке 25 — там, где в Python-коде встречается кортеж
`('uplink', 'downlink')`.

**Исправление:** оба скрипта переписаны на heredoc:
```bash
#!/bin/bash
python3 - <<'PYEOF'
... Python-код без проблем с кавычками и shebang ...
PYEOF
```

На Ubuntu 24.04 поведение не меняется.

---

### Фикс: Debian 13 — `FileNotFoundError: 'ufw'` в AutoBan

**Проблема:** `ufw` не установлен на Debian 13 по умолчанию
(система использует чистый nftables/iptables). AutoBan вызывал `ufw`
напрямую без проверки наличия — `subprocess` падал с `FileNotFoundError`.

**Исправление:** добавлены хелперы `_fw_ban()` / `_fw_unban()`:
```
ufw доступен  → ufw deny from IP to any
ufw отсутствует → iptables -I INPUT -s IP -j DROP
```

Работает на Ubuntu 24.04 (ufw) и Debian 13 (iptables) без изменения
поведения на каждой системе.

---

### Фикс: Python 3.13 — `SyntaxWarning` → `SyntaxError` на escape-последовательностях

**Проблема:** escape-последовательности `\d`, `\.`, `\s` внутри
обычных (не raw) f-строк вызывали `SyntaxWarning` в Python 3.12
и стали `SyntaxError` в Python 3.13.

**Исправление:** все regex-паттерны внутри генерируемых скриптов
приведены к корректному виду с двойным экранированием.

---

### Фикс: Python 3.13 — `NameError` в cron-обработчиках `main.py`

Исправлено в предыдущем коммите, документируется здесь для полноты.

**Затронуто:** `--dpi-check`, `--smart-balance`, `--pinned-fallback-check`,
`--ingress-geoip-update`

**Проблема:** `main.py` загружает `_core.py` через `exec(..., globals())`.
Функции из модулей, которые не были явно импортированы в `_core.py`
(например `_dpi_run_once` из `dpi_detector.py`), не попадали в
`globals()` при cron-запуске. На Python 3.13 поведение `exec` в части
изоляции пространств имён стало строже — `NameError` начал
воспроизводиться стабильно.

**Исправление:** в каждый cron-обработчик добавлен явный `import`
нужной функции прямо перед вызовом.

---

## 🔧 v4.11.5 — 2 июня 2026 (дополнение)

### Массовый разбан в AutoBan — больше не по одному

Раньше разбанить можно было только один IP за раз. Если после ночи
нестабильного интернета в бан попало несколько своих пользователей —
приходилось заходить в меню и чистить каждого вручную по очереди.

Теперь в пункте **[3] Разбанить IP** поддерживаются четыре способа ввода:

```
3        — разбанить один IP по номеру из списка
1,3,5    — разбанить несколько через запятую
2-6      — разбанить диапазон номеров
all      — разбанить всех сразу
1.2.3.4  — разбанить по IP напрямую (как раньше)
```

Список теперь показывает не просто IP, но и количество ошибок и время бана —
чтобы было проще понять кого именно разбанить. История банов обновляется
корректно для всех разбаненных за один раз.

---

## 🔧 v4.11.5 — 2 июня 2026 (дополнение)

### Аварийное восстановление больше не сбрасывает интеграцию Telemt

Небольшое, но заметное улучшение для тех, кто использует Telemt MTProxy
вместе с каскадом (Режим B).

**Что было:** после запуска аварийного восстановления (Меню 1 → пункт 6)
установщик пересобирал `config.json` из сохранённой конфигурации — и при этом
терял правила маршрутизации Xray для Telemt. Telemt продолжал работать,
но трафик Telegram снова шёл напрямую, а не через exit-ноду. Приходилось
заходить в меню Telemt и вручную переприменять интеграцию.

**Что стало:** аварийное восстановление теперь автоматически обнаруживает
установленный Telemt и восстанавливает интеграцию без каких-либо действий
с вашей стороны. В выводе появится строка:

```
✓  Telemt tproxy: dokodemo-door добавлен (:10811), iptables REDIRECT активен [N подсетей], транспорт: VLESS
```

или при AWG:

```
✓  Telemt tproxy: dokodemo-door добавлен (:10811), iptables REDIRECT активен [N подсетей], транспорт: AWG 2.0
```

Если конфиг выжил без пересборки и интеграция уже активна — восстановление
это тоже увидит и просто пропустит шаг без лишних действий.

Работает для всех вариантов каскада: одна VLESS exit-нода, мульти-каскад
до 10 нод и AmneziaWG 2.0.

---

## 🔧 v4.11.5 — 2 июня 2026 (дополнение)

### [CRITICAL] Исправлена ошибка генерации конфигурации DNSCrypt-proxy

**Проблема:** при установке dnscrypt-proxy падал с ошибкой:
```
FATAL: expected value but found "p" instead
```
Служба не могла стартовать и циклично перезапускалась. Причина — параметр
`lb_strategy` записывался в конфиг без кавычек:
```toml
lb_strategy = p2   # неверно — TOML не принимает голые строки
```

**Причина:** в `_core.py` значение `lb_strategy` генерировалось без учёта
требований синтаксиса TOML. Функция `apply_dnscrypt_tuning()` перезаписывала
конфиг, дополнительно убирая кавычки.

**Решение:** исправлено в двух местах — шаблон генерации конфига (~строка 5791)
и словарь `TOP_PARAMS` в `apply_dnscrypt_tuning()` (~строка 5960).
Теперь параметр записывается корректно:
```toml
lb_strategy = 'p2'
```

**Влияние:**
- ✅ Все новые установки работают без ошибок
- ✅ Существующие установки не затронуты
- ✅ Обновление требуется только при первой установке DNSCrypt

Спасибо пользователям, которые помогли найти и воспроизвести баг! 🙏

---

## 🆕 v4.11.5 — 1 июня 2026 (дополнение)

### Новые инструменты обхода: Noise, Mux, Watchdog, Stats, Share

Фрагментация — это первый рубеж. Но некоторые DPI-системы (особенно ТСПУ)
со временем обучаются и начинают распознавать даже фрагментированные паттерны.
Это обновление добавляет следующий уровень защиты — и делает работу с конфигами
значительно удобнее.

---

### 🔊 Фрагментация + Noise — Меню 4 → F6

Noise добавляет случайные байты перед TLS ClientHello. Если DPI уже научился
узнавать фрагментацию — noise делает начало соединения полностью случайным,
непохожим ни на что известное. Провайдер видит «мусор» и пропускает.

Работает поверх фрагментации — выбираете пресет фрагментации, затем
интенсивность шума. Генерирует готовый JSON для Xray и Sing-box.

---

### 🔀 Фрагментация + Mux — Меню 4 → F7

Mux (мультиплексирование) объединяет несколько запросов в один долгий
TCP-туннель. Вместо множества коротких соединений — один непрерывный поток.
DPI сложнее классифицировать такой трафик и принять решение о блокировке.

Особенно эффективно в связке с фрагментацией: fragment скрывает начало,
mux снижает количество новых «точек входа» для анализа.

---

### 🔄 Автопереключение пресетов — Меню 4 → F8

Watchdog работает в фоне как системный сервис. Если за последние 5 минут
число сброшенных соединений (RST) превышает порог — он автоматически
переключает пресет на более агрессивный:

**Лёгкая → Средняя → Агрессивная → Ультра-агрессивная**

Провайдер «закрутил гайки» ночью — утром уже стоит нужный пресет.
Всё без вашего участия.

---

### 📈 Статистика эффективности — Меню 4 → F9

Показывает за любой период (час / 3 часа / сутки):
- Процент успешных соединений
- Количество RST-сбросов
- Тренд: улучшается / ухудшается / стабильно
- ASCII-гистограмма по 10-минутным интервалам

Если RST растёт — сигнал сменить пресет. Если стабильно зелёный —
текущая фрагментация работает.

---

### 📲 Поделиться конфигом без scp — Меню 2 → G

Самое удобное новое: теперь не нужен компьютер чтобы передать конфиг
пользователю на телефон. Установщик поднимает временный защищённый
сервер на 10 минут, показывает QR-код — пользователь сканирует
и файл скачивается прямо на устройство.

После скачивания сервер гаснет автоматически. Ссылка одноразовая.

---

### Полная карта меню фрагментации

**Меню 2 — Управление пользователями:**

| Пункт | Назначение |
|---|---|
| **F** | Ссылки + QR для Happ / Incy / Nekoray / v2rayNG — с фрагментацией |
| **G** | Временный QR-сервер — скачать конфиг на телефон без scp |

**Меню 4 — Диагностика:**

| Пункт | Назначение |
|---|---|
| **F1** | Один конфиг с выбором пресета фрагментации |
| **F2** | Тест связности VPS (ориентировочно) |
| **F3** | Живая визуализация в логах Xray |
| **F4** | Сгенерировать все 9 конфигов сразу ← начать здесь |
| **F5** | Гайд: как правильно тестировать на своём устройстве |
| **F6** | Фрагментация + Noise (шум) |
| **F7** | Фрагментация + Mux (мультиплексирование) |
| **F8** | Watchdog — автопереключение при деградации |
| **F9** | Статистика: RST / успех / тренд / гистограмма |

---

## 📖 Гайд: с чего начать и как использовать

### Шаг 1 — Сгенерировать конфиги (Меню 4 → F4)

Нажмите F4 и подтвердите. Установщик создаст 9 конфигов с разными
параметрами фрагментации и сохранит их в `/var/lib/xray-installer/fragment_configs/`.

### Шаг 2 — Передать конфиг пользователю (Меню 2 → G)

Перейдите в Меню 2, нажмите G. Выберите нужный конфиг из списка.
Покажите QR-код пользователю — он сканирует телефоном и скачивает файл.

Или используйте F для генерации ссылок под конкретный клиент:
- **Happ, Incy, Nekoray** — QR сразу с фрагментацией, больше ничего не нужно
- **v2rayNG, Hiddify** — нужно импортировать скачанный JSON-файл

### Шаг 3 — Попробовать разные конфиги

Нет универсального «лучшего» пресета — он зависит от вашего провайдера.
Скачайте несколько конфигов через G и попробуйте каждый.
Тот, где выше скорость и нет обрывов — оставьте.

Ориентир для начала:
- **Ростелеком, МТС** → Средняя (10–50 байт)
- **Билайн, Мегафон** → Сбалансированная (3–7 байт)
- **Жёсткая блокировка, ТСПУ** → Агрессивная (1–3 байт) или F6 (Noise)

### Шаг 4 — Смотреть что происходит (Меню 4 → F9)

Откройте F9 и посмотрите на гистограмму. Если красных столбцов (RST) много —
текущий пресет не справляется, попробуйте более агрессивный или включите Noise (F6).

### Шаг 5 — Включить автопереключение (Меню 4 → F8)

Если не хотите следить вручную — включите Watchdog (F8 → пункт 1).
Он сам переключится на более агрессивный пресет если начнутся проблемы.

### Когда что использовать

| Ситуация | Что делать |
|---|---|
| Всё работает, хочу попробовать | F4 → скачать конфиги → G → передать |
| Соединение нестабильно | F9 → посмотреть статистику |
| Фрагментация не помогает | F6 (Noise) или F7 (Mux) |
| Не хочу следить вручную | F8 (Watchdog) |
| Нужно передать конфиг без компьютера | Меню 2 → G |

---

### Что нового: обход блокировок через фрагментацию

Провайдеры в России, Иране и других странах используют DPI-оборудование,
которое анализирует первый пакет вашего соединения и блокирует его, если
видит признаки VPN. Фрагментация решает эту проблему: она разбивает этот
первый пакет на мелкие кусочки, которые DPI не успевает собрать и опознать.

В этом обновлении мы добавили всё необходимое прямо в установщик.

---

### 🔀 Подключение с фрагментацией — Меню 2 → F

Самый простой способ раздать конфиги с фрагментацией своим пользователям.

Выбираете пресет → установщик генерирует готовые ссылки и QR-коды
для каждого клиента отдельно:

- **Happ, Incy, Nekoray / Nekobox** — достаточно отсканировать QR или
  скопировать ссылку. Фрагментация включится автоматически.
- **v2rayNG, Hiddify, NyameBox, Xray** — установщик создаёт готовый
  JSON-файл, который нужно скачать с сервера и импортировать в клиент.

После показа ссылок и QR-кодов появляется пошаговая инструкция —
что делать в каждом конкретном приложении.

---

### 📦 Сгенерировать все конфиги сразу — Меню 4 → F4

Если не знаете, какая фрагментация подойдёт — создайте все 9 вариантов
одной командой и попробуйте каждый:

| Группа | Для кого |
|---|---|
| **Агрессивные** (1–5 байт) | Жёсткий DPI, Иран, ТСПУ |
| **Средние** (10–50 байт) | Россия, большинство провайдеров |
| **Лёгкие** (50–200 байт) | Когда соединение работает, но нестабильно |
| **Эталон** (без фрагментации) | Для сравнения скорости |

Скачайте все файлы на устройство, попробуйте каждый и оставьте тот,
где лучше скорость и стабильность.

---

### 🔬 Тест связности VPS — Меню 4 → F2

Проверяет, работает ли вообще соединение через ваш VPS с фрагментацией.
Перебирает несколько вариантов, измеряет скорость подключения и подсказывает,
что попробовать в первую очередь.

*Важно: тест работает прямо на сервере. Для точного результата лучше
тестировать конфиги на своём устройстве через F4.*

---

### 📊 Что происходит в реальном времени — Меню 4 → F3

Показывает в терминале живую картину соединений через ваш сервер:
какие подключения проходят успешно, какие сбрасываются провайдером,
есть ли признаки блокировки. Удобно для диагностики.

---

### 🛠️ Исправления

- **MTProto / Telegram-прокси (Режим B):** ссылка `tg://` теперь всегда
  содержит IP вашей российской entry-ноды, а не IP зарубежной exit-ноды.
  Раньше пользователи получали ссылку с неправильным адресом и не могли
  подключиться.

---

#### Новые модули

- **`fragment_config.py`** — Генератор клиентских конфигов с фрагментацией.
- **`fragment_fuzzer.py`** — Автоматический подбор параметров (Fuzzer).
- **`fragment_log_viewer.py`** — Визуализация фрагментации в логах Xray.
- **`fragment_presets.py`** — Генерация полного набора из 9 конфигов одной командой.
- **`fragment_link.py`** — Ссылки и QR-коды для конкретных клиентов.
- **`fragment_guide.py`** — Интерактивный гайд по тестированию.

#### Поддержка клиентов

| Клиент | Платформы | Fragment из QR/ссылки |
|---|---|---|
| **Happ** | iOS / Android / macOS / Windows / Linux / TV | ✅ сразу |
| **Incy** | iOS / Android / macOS / Windows / Linux / TV | ✅ сразу |
| **Nekoray / Nekobox** | Windows / Linux / macOS | ✅ сразу |
| **NyameBox** | Windows / Linux | ⚠️ нестабильно, рекомендуется JSON |
| **v2rayNG** | Android | ❌ нужен JSON-файл |
| **Hiddify** | Android / iOS / Desktop | ❌ нужен JSON-файл |
| **Xray** | Linux / macOS / Windows | ❌ нужен JSON-файл |

---

## 🔧 v4.11.4 — 28 мая 2026

### Исправления AWG 2.0 (Режим B)

- **fix:** корректный SNI в клиентских ссылках при AWG-транспорте — теперь используется `reality_dest` (домен маскировки) вместо собственного домена ноды
- **fix:** DNS-таймауты в Режиме B + AWG — добавлен `direct` outbound с AWG fwmark и правило `127.0.0.1 → direct` чтобы DNS-запросы Xray не уходили в `chain-exit`
- **fix:** конфликт `awg-quick@awg0.service` и `amneziawg-awg0.service` на exit-ноде — старый сервис теперь останавливается перед запуском нового, устраняя проблему "awg show пустой" и черепашьей скорости (~3 КБ/с). В одной из конфигураций серверов так же была замечена проблема - хостер резал UDP пакеты. Это, к счастью, не проблема скрипта, а проблема конкретного хостера, и фикса тут может быть два - пробовать менять роли серверов (Entry<->Exit) либо менять хостера(ов).
- **fix:** импорт `_AUTO_FALLBACK_CRON`, `_AUTO_FALLBACK_SCRIPT`, `_AUTO_FALLBACK_LOGFILE` в `_core.py` — планировщик задач больше не падает с `NameError`
- **fix:** `ListenPort` отсутствовал в клиентском конфиге AWG — порт был случайным при каждом перезапуске, exit-нода не могла отправить ответ. Теперь фиксированный порт 11100
- **fix:** входящий UDP порт AWG не открывался на entry-ноде — провайдеры с `INPUT policy DROP` (например AEZA) блокировали ответные пакеты от exit-ноды. Скрипт теперь добавляет правило `iptables -A INPUT -p udp --dport 11100 -j ACCEPT` автоматически

---

## 🔧 v4.11.3 — 24 мая 2026

### Исправления (`tg_nets.py`)
- Убраны нерабочие источники (bgp.tools, RADB/IRR, RIPE WHOIS REST)
- Единственный источник: RIPE NCC stat.ripe.net (announced-prefixes)
- Добавлен whitelist-фильтр: принимаются только префиксы внутри
  официального IP-пространства Telegram (точные /22-/24 блоки)
- Результат: 19 подсетей (14 IPv4 + 5 IPv6) вместо 51

---
## 🆕 v4.11.3 — 23 мая 2026

### Telegram через заблокированную entry-ноду — теперь работает

Это обновление решает задачу, с которой сталкивается каждый, кто разворачивает
каскад в России: **Telemt MTProto Proxy на entry-ноде физически не мог подключиться
к серверам Telegram**, потому что они заблокированы на уровне провайдера.
Раньше нужно было либо мириться с этим, либо вручную городить обходные пути.

Теперь установщик делает всё сам.

---

#### Что изменилось для вас

Если у вас настроен **каскад (Режим B)** — одна или несколько exit-нод за рубежом —
и вы устанавливаете Telemt на entry-ноду в России, установщик обнаружит каскад и
предложит включить интеграцию. После согласия Telemt начнёт отправлять трафик
Telegram через ваши же exit-ноды. Никаких дополнительных действий не требуется.

Работает со всеми вариантами каскада:

- **Одна exit-нода** через VLESS + REALITY
- **Несколько exit-нод** (до 10) с автоматической балансировкой нагрузки
- **AmneziaWG 2.0** — зашифрованный туннель между нодами

После установки в меню Telemt появляется новый пункт **[X] Xray-интеграция**,
где можно в любой момент проверить состояние, включить или отключить обход.

---

#### Почему не через SOCKS5

Первое, что приходит в голову — настроить Telemt так, чтобы он сам ходил
через локальный прокси xray. Это чистое и элегантное решение. Мы его попробовали.

Оказалось, что **Telemt v3.x не поддерживает SOCKS5 в секции `[[upstreams]]`**.
При попытке запустить с таким конфигом сервис падает сразу после старта с ошибкой
`Error: Con... in 'upstreams'`. Поддерживаются только `direct` и `middle`
(собственный протокол Telegram). Middle-серверы Telegram тоже недоступны из России —
круг замкнулся.

---

#### Как это работает на самом деле

Решение прозрачное — Telemt об этом вообще не знает.

Когда Telemt пытается подключиться к серверу Telegram (а их IP-диапазоны
хорошо известны и не меняются), операционная система перехватывает это соединение
и перенаправляет его в xray. Xray уже знает, как добраться до Telegram —
через вашу exit-ноду. Telemt получает ответ как будто подключился напрямую.

Правила перехвата прописываются в systemd-юнит Telemt и живут ровно столько,
сколько работает сервис. При остановке или удалении Telemt они убираются
автоматически — никакого мусора в системе не остаётся.

---

#### Итог

| | До v4.11.3 | v4.11.3 |
|---|---|---|
| Telemt на entry-ноде в РФ | ❌ Не работает | ✅ Работает |
| Требует ручной настройки | — | ❌ Нет |
| Совместимость с AWG 2.0 | — | ✅ Да |
| Совместимость с мульти-каскадом | — | ✅ До 10 нод |
| Влияет на остальной трафик | — | ❌ Нет |

---

## v4.11.1 — 20 мая 2026

### Исправлено

**Кластерное управление `[CL]` — аутентификация по паролю SSH**

Все операции кластера (диагностика, перезапуск, обновление, ротация UUID,
произвольная команда) завершались ошибкой `Permission denied` на нодах, где
не настроен SSH-ключ. Теперь при отсутствии ключа установщик запрашивает пароль
root один раз за сессию и использует его для всех нод. Новый пункт меню
**[P] Сменить пароль сессии** позволяет обновить пароль без выхода из меню.

**nginx Watchdog `[NW]` и ipset Persist `[IP]` — длинные строки в меню**

Несколько пунктов этих подменю выходили за рамки TUI-интерфейса. Исправлено
разбиением на две строки.

**Кластер `[CL]` — ошибки SSH с длинным текстом выходили за рамки**

Причина ошибки (`Permission denied (publickey,password)`) теперь отображается
на отдельной строке с отступом.

---

## v4.11 — 20 мая 2026

### Добавлено

- **Smoke-test после apply** — автопроверка подключения после каждого изменения конфига;
  при провале предлагается аварийное восстановление
- **nginx Watchdog `[NW]`** — systemd-таймер каждые 2 минуты; при падении nginx
  перезапускает его и отправляет уведомление в Telegram
- **ipset Persistent `[IP]`** — правила ingress-блокировки переживают перезагрузку сервера
- **Проверка возраста RIPE-файла** — предупреждение при устаревших данных подсетей (30/90 дней)
- **Кластерное управление `[CL]`** — управление всеми exit-нодами из одного меню:
  диагностика, перезапуск, обновление xray-core, ротация UUID, произвольная команда

---

## v4.06

### Добавлено

- AmneziaWG 2.0 с поддержкой нескольких нод и балансировкой
- Smart Balancer: автовыбор лучшей ноды (roundRobin / leastPing / pinned)
- Failover A↔B: автопереключение при отказе exit-нод
- DPI Detector и Honeypot-порт
- AutoBan по TLS-ошибкам
- Telegram-уведомления
- Traffic Limits и TTL-пользователи
- Health Report: ежедневный отчёт
- GeoIP-блокировка входящих, AS-direct routing
- Clash Meta / Sing-box конфиг-генератор
- xHTTP streamup + xmux
- Мульти-каскад до 10 exit-нод

---

## v3.99

- CloudFlare WARP (full / selective / runet)
- Split Tunneling с geosite/geoip
- РФ-подсети из RIPE NCC
- Scheduled Backup

## v3.x

- Базовая установка VLESS + REALITY
- Режим B (каскад)
- Управление пользователями, диагностика
