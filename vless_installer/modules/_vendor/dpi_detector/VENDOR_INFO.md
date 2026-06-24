# Вендоринг: Runnin4ik/dpi-detector

Этот каталог — копия стороннего проекта **без изменений в коде**.
Используется как внешний инструмент, запускаемый через `subprocess`
из `vless_installer/modules/dpi_censor_check.py`.

| Поле              | Значение |
|-------------------|----------|
| Источник          | https://github.com/Runnin4ik/dpi-detector |
| Версия            | v3.3.0 |
| Commit            | `173d3af5cd0385f0db6113af86e3438931dd92f4` |
| Дата коммита      | 2026-05-11 |
| Лицензия          | MIT (см. `LICENSE` в этой папке) |

## Что исключено из апстрима

- `images/` — логотип и скриншот (~2 MB, не нужны для работы)
- `Dockerfile` — не используется, ставим зависимости через pip
- `.github/` — CI/CD апстрима, не нужен

## Как обновить до новой версии

```bash
git clone --depth 1 https://github.com/Runnin4ik/dpi-detector.git /tmp/dpi-detector-new
rm -rf vless_installer/modules/_vendor/dpi_detector/{cli,core,utils}
cp -r /tmp/dpi-detector-new/{cli,core,utils} vless_installer/modules/_vendor/dpi_detector/
cp /tmp/dpi-detector-new/{dpi_detector.py,config.yml,domains.txt,tcp16.json,whitelist_sni.txt,requirements.txt,LICENSE,README.md} \
   vless_installer/modules/_vendor/dpi_detector/
```

Обновите commit/версию в этом файле. Если апстрим поменял имена аргументов
CLI (`-t/-p/-d/-c/-o/--batch`) или способ резолва путей в `utils/files.py` —
проверьте `dpi_censor_check.py`, он опирается именно на этот контракт.

## Важно

Не редактировать файлы в этом каталоге вручную — любые правки потеряются
при следующем обновлении апстрима. Вся кастомизация (UI меню, установка
зависимостей, логирование) — в `dpi_censor_check.py` снаружи.
