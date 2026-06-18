# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 4.12.9  | ✅ Активно |
| 4.12.8  | ✅ Активно |
| 4.11.1  | ⚠️ Обновитесь (нет Telemt-интеграции) |
| < 4.11.1 | ❌ Не поддерживается |

## Reporting a Vulnerability

Если вы обнаружили уязвимость — **не публикуйте её в Issues**.

Напишите напрямую: откройте **приватное Security Advisory** на GitHub:
`https://github.com/inferno1978/VLESS-Ultimate-Installer/security/advisories/new`

Либо свяжитесь через контакты в профиле. Ответ — в течение 72 часов.

**Пожалуйста, укажите:**
- Версию (`main.py` выводит версию при запуске)
- Шаги для воспроизведения
- Потенциальный impact
- Предложение по фиксу (если есть)

## Scope

В зону ответственности входят:

- `bootstrap.sh` — загрузка и запуск инсталлятора
- `vless_installer/_core.py` — основная логика
- Генерация конфигов Xray, iptables/ipset правила
- Логика хранения секретов (UUID, ключи AWG)

**Вне scope:** уязвимости в самом Xray-core (репортите в [XTLS/Xray-core](https://github.com/XTLS/Xray-core)).

## Security Design Notes

### bootstrap.sh и SHA256

Начиная с v4.12.8 bootstrap.sh поддерживает опциональную SHA256-проверку
архива при fallback-загрузке (когда `git clone` недоступен). Переменная
`EXPECTED_SHA256` в начале блока fallback должна обновляться при каждом релизе:

```bash
# Пересчитать после финальной сборки:
sha256sum vless-master.tar.gz
```

Приоритетный способ загрузки — `git clone` по HTTPS, который верифицирует
TLS-сертификат GitHub.

### Секреты и STATE_FILE

- UUID клиентов и ключи AmneziaWG хранятся в `/etc/xray/state.json` (chmod 600)
- Telegram-токен бота хранится там же, не попадает в логи
- Логи (`/var/log/vless-install.log`) не содержат приватных ключей

### iptables / ipset

Правила ingress-блокировки (РФ подсети) вставляются **после** правил
`ESTABLISHED,RELATED → ACCEPT` и `loopback → ACCEPT`, чтобы не обрывать
уже установленные легитимные соединения. Whitelist IP (SSH, доверенные клиенты)
получают `ACCEPT` явно, выше DROP-правил.

### Автоматические обновления GeoIP

Cron-задача еженедельно обновляет списки CIDR (RIPE NCC).
При обновлении старые правила удаляются (`-D`) перед применением новых,
чтобы исключить дубли.
