"""
telemt_self_route.py
====================
Маршрутизация исходящего трафика самого процесса Telemt через xray.

Проблема
--------
Telemt запускается под root и сам инициирует соединения к Telegram DC
для инициализации DC/ME. Эти соединения идут напрямую с entry-ноды,
минуя xray туннель — потому что:

  1. Telemt стартует раньше xray (нет After=xray.service)
  2. iptables REDIRECT применяются в ExecStartPost xray-cold-boot-restore.sh
  3. К моменту появления правил соединение Telemt уже ESTABLISHED

Решение
-------
1. Добавить ``After=xray.service`` в telemt.service — гарантирует что
   iptables правила уже применены когда Telemt стартует.
2. Добавить ``--uid-owner xray`` RETURN rule на позицию 1 в nat OUTPUT —
   xray не попадает в петлю редиректа.

Оба изменения идемпотентны и безопасны:
- Если xray не установлен — After= игнорируется systemd (wants, not requires)
- RETURN rule для xray uid не мешает работе без xray
- При удалении модуля всё откатывается через disable()

Принципы
--------
* Одна функция — один файл: вся логика здесь.
* Безопасность: изменения минимальны, откатываемы, не трогают конфиг xray.
* Универсальность: работает для всех режимов (A, B, AWG).

Публичное API
-------------
    enable()   -> tuple[bool, str]   — применить
    disable()  -> tuple[bool, str]   — откатить
    status()   -> dict               — текущее состояние
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

__all__ = ["enable", "disable", "status"]

# ---------------------------------------------------------------------------
#  Константы
# ---------------------------------------------------------------------------
_TELEMT_SERVICE   = Path("/etc/systemd/system/telemt.service")
_XRAY_SERVICE     = "xray.service"
_AFTER_MARKER     = "After=xray.service"          # строка которую добавляем
_XRAY_USER        = "xray"                         # под каким uid работает xray
_IPT              = "iptables"


# ---------------------------------------------------------------------------
#  Вспомогательные функции
# ---------------------------------------------------------------------------

def _run(cmd: list) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def _xray_uid() -> int | None:
    """Возвращает uid пользователя xray или None если не существует."""
    import pwd
    try:
        return pwd.getpwnam(_XRAY_USER).pw_uid
    except KeyError:
        return None


def _return_rule_exists() -> bool:
    """Проверяет наличие RETURN правила для uid xray в nat OUTPUT."""
    uid = _xray_uid()
    if uid is None:
        return False
    r = _run([_IPT, "-t", "nat", "-C", "OUTPUT",
              "-m", "owner", "--uid-owner", str(uid),
              "-j", "RETURN"])
    return r.returncode == 0


def _add_return_rule() -> bool:
    """Вставляет RETURN правило для uid xray на позицию 1 в nat OUTPUT."""
    if _return_rule_exists():
        return True
    uid = _xray_uid()
    if uid is None:
        return False
    r = _run([_IPT, "-t", "nat", "-I", "OUTPUT", "1",
              "-m", "owner", "--uid-owner", str(uid),
              "-j", "RETURN"])
    return r.returncode == 0


def _del_return_rule() -> None:
    """Удаляет RETURN правило для uid xray из nat OUTPUT (все копии)."""
    uid = _xray_uid()
    if uid is None:
        return
    for _ in range(5):
        if not _return_rule_exists():
            break
        _run([_IPT, "-t", "nat", "-D", "OUTPUT",
              "-m", "owner", "--uid-owner", str(uid),
              "-j", "RETURN"])


def _service_has_after() -> bool:
    """Проверяет наличие After=xray.service в telemt.service."""
    if not _TELEMT_SERVICE.exists():
        return False
    return _AFTER_MARKER in _TELEMT_SERVICE.read_text()


def _add_after_to_service() -> bool:
    """Добавляет After=xray.service в секцию [Unit] telemt.service."""
    if not _TELEMT_SERVICE.exists():
        return False
    if _service_has_after():
        return True

    text = _TELEMT_SERVICE.read_text()

    # Ищем строку After= в секции [Unit] и дописываем xray.service
    lines = text.splitlines()
    new_lines = []
    inserted = False
    for line in lines:
        new_lines.append(line)
        if not inserted and line.startswith("After="):
            # Дописываем xray.service к существующей строке After=
            new_lines[-1] = line.rstrip() + " xray.service"
            inserted = True

    if not inserted:
        # Нет строки After= — вставляем после [Unit]
        final = []
        for line in new_lines:
            final.append(line)
            if line.strip() == "[Unit]":
                final.append(_AFTER_MARKER)
                inserted = True
        new_lines = final

    if not inserted:
        return False

    _TELEMT_SERVICE.write_text("\n".join(new_lines) + "\n")
    return True


def _remove_after_from_service() -> bool:
    """Убирает xray.service из After= в telemt.service."""
    if not _TELEMT_SERVICE.exists():
        return True
    text = _TELEMT_SERVICE.read_text()
    if _AFTER_MARKER not in text and "xray.service" not in text:
        return True

    lines = text.splitlines()
    new_lines = []
    for line in lines:
        if line.startswith("After=") and "xray.service" in line:
            # Убираем xray.service из строки
            parts = line.split()
            parts = [p for p in parts if p != "xray.service"]
            line = " ".join(parts)
            # Если After= стала пустой — пропускаем
            if line.strip() == "After=":
                continue
        new_lines.append(line)

    _TELEMT_SERVICE.write_text("\n".join(new_lines) + "\n")
    return True


def _systemd_reload() -> None:
    _run(["systemctl", "daemon-reload"])


def _iptables_persist() -> None:
    """Сохраняет iptables правила для выживания после ребута."""
    if shutil.which("netfilter-persistent"):
        r = _run(["netfilter-persistent", "save"])
        if r.returncode == 0:
            return
    # Fallback: сохраняем напрямую в файл
    _run(["bash", "-c",
          "mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4 2>/dev/null || true"])


# ---------------------------------------------------------------------------
#  Публичное API
# ---------------------------------------------------------------------------

def enable() -> tuple[bool, str]:
    """
    Активирует маршрутизацию трафика telemt через xray:
      1. Вставляет RETURN rule для uid xray перед REDIRECT правилами
      2. Добавляет After=xray.service в telemt.service
      3. Перезагружает systemd daemon

    Безопасно вызывать повторно (идемпотентно).
    """
    uid = _xray_uid()
    if uid is None:
        return False, (
            "Пользователь xray не найден. "
            "Убедитесь что xray установлен корректно."
        )

    # 1. RETURN rule
    if not _add_return_rule():
        return False, "Не удалось добавить iptables RETURN rule для uid xray"

    # 2. After=xray.service
    if not _TELEMT_SERVICE.exists():
        return False, "telemt.service не найден — Telemt не установлен"

    if not _add_after_to_service():
        return False, "Не удалось обновить telemt.service"

    # 3. Перезагрузка systemd
    _systemd_reload()

    # 4. Сохранить iptables
    _iptables_persist()

    return True, (
        f"Готово: RETURN rule для uid {_XRAY_USER}({uid}) добавлен на позицию 1, "
        f"telemt.service теперь стартует после xray.service. "
        f"Перезапустите telemt: systemctl restart telemt"
    )


def disable() -> tuple[bool, str]:
    """
    Откатывает изменения:
      1. Удаляет RETURN rule для uid xray
      2. Убирает After=xray.service из telemt.service
      3. Перезагружает systemd daemon
    """
    _del_return_rule()
    _remove_after_from_service()
    _systemd_reload()
    _iptables_persist()
    return True, "Маршрутизация трафика telemt через xray отключена"


def status() -> dict:
    """
    Возвращает текущее состояние:
      {
        "return_rule": bool,   — RETURN rule для xray uid активен
        "after_xray":  bool,   — After=xray.service в telemt.service
        "xray_uid":    int|None
      }
    """
    return {
        "return_rule": _return_rule_exists(),
        "after_xray":  _service_has_after(),
        "xray_uid":    _xray_uid(),
    }
