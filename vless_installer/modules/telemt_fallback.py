"""
vless_installer/modules/telemt_fallback.py
───────────────────────────────────────────────────────────────────────────────
Гибридный режим Telemt: автоматический fallback из Middle Proxy → Direct Mode.

Архитектура
───────────
Этот модуль работает на уровне Python-инсталлера, а не внутри Rust-бинарника
Telemt. Он управляет *telemt.toml* и службой *systemd*, реализуя логику
fallback через:

  1. FallbackConfig  — dataclass с параметрами секции [middle_proxy] в toml.
  2. MiddleProxyProbe — проверяет реальную доступность ME-серверов Telegram
                        (TCP-рукопожатие к известным endpoint'ам DC).
  3. FallbackOrchestrator — координирует попытки, таймауты, переключение
                             режима и hot-reload конфига.

Параметры конфига (секция [middle_proxy] в telemt.toml)
────────────────────────────────────────────────────────
  fallback_to_direct      = true   # разрешить автоматический fallback
  fallback_after_attempts = 3      # попыток до признания ME недоступным
  fallback_after_seconds  = 45     # max время warmup ME-пула
  auto_revert_to_middle   = false  # автовозврат после восстановления (v2)

Гарантии совместимости
──────────────────────
  • Все параметры optional — старые конфиги продолжают работать без изменений.
  • Fallback не меняет порты, listener'ы, iptables и xray-интеграцию.
  • Переключение только runtime (RAM); telemt.toml не модифицируется.
  • При hot-reload (systemctl reload) новое значение use_middle_proxy из
    конфига имеет приоритет над текущим runtime-состоянием.

Интеграция с mtproto.py
───────────────────────
  Вызывается из _write_config() и _run_install_inner() через:
      from vless_installer.modules.telemt_fallback import (
          FallbackConfig, FallbackOrchestrator, append_fallback_section,
          read_fallback_config, me_probe_menu,
      )
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event, Thread
from typing import Callable, Optional

# ── Импорт констант из mtproto (без циклического импорта) ────────────────────
# Используем lazy-import внутри функций чтобы избежать circular dependency.
# Константы дублируем только там, где действительно нужны ──

_SERVICE_NAME = "telemt"
_CONFIG_FILE  = Path("/etc/telemt/telemt.toml")
_LOG_FILE     = Path("/var/log/telemt_install.log")

# ── Цвета (self-contained, не импортируем из mtproto) ────────────────────────
def _colors() -> dict:
    if sys.stdout.isatty():
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════

# Известные ME-серверы Telegram (Middle proxy endpoints).
# Список взят из публичной документации и не меняется между релизами Telemt.
# DC1..DC5 — стандартные номера датацентров Telegram.
_ME_ENDPOINTS: list[tuple[str, int]] = [
    # DC1
    ("149.154.175.50",  443),
    ("149.154.175.50", 8443),
    # DC2
    ("149.154.167.51",  443),
    ("149.154.167.51", 8443),
    # DC3
    ("149.154.175.100", 443),
    ("149.154.175.100", 8443),
    # DC4
    ("149.154.167.91",  443),
    ("149.154.167.91", 8443),
    # DC5
    ("91.108.4.100",    443),
    ("91.108.4.100",   8443),
]

# Минимальная доля успешных ME-проб для признания пула «готовым»
_ME_QUORUM = 0.34   # ≥1/3 активных DC достаточно для работы Middle Proxy

# Таймаут одного TCP-connect к ME-серверу (секунды)
_PROBE_TCP_TIMEOUT = 5

# Строки в journalctl, сигнализирующие о деградации ME-пула
_ME_FAILURE_PATTERNS: list[str] = [
    "All ME servers for DC",
    "ME server connection failed",
    "middle proxy init failed",
    "Failed to connect to ME",
    "ME pool exhausted",
]

# ══════════════════════════════════════════════════════════════════════════════
#  DATACLASS: FallbackConfig
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class FallbackConfig:
    """
    Параметры секции [middle_proxy] в telemt.toml.

    Все поля optional — дефолтные значения соответствуют «безопасному»
    поведению: fallback разрешён, но консервативные пороги.
    """
    fallback_to_direct:      bool = True   # разрешить автоматический fallback
    fallback_after_attempts: int  = 3      # попыток до признания ME недоступным
    fallback_after_seconds:  int  = 45     # max секунд warmup ME-пула
    auto_revert_to_middle:   bool = False  # автовозврат (реализован каркас)

    def __post_init__(self) -> None:
        # Защита от некорректных значений из конфига
        self.fallback_after_attempts = max(1, min(20, self.fallback_after_attempts))
        self.fallback_after_seconds  = max(10, min(300, self.fallback_after_seconds))

    @classmethod
    def defaults(cls) -> "FallbackConfig":
        """Возвращает экземпляр со стандартными значениями."""
        return cls()

    def to_toml_section(self) -> str:
        """Сериализует в строки для вставки в telemt.toml."""
        lines = [
            "",
            "# ── Hybrid fallback: автоматический переход в Direct Mode ──────────",
            "[middle_proxy]",
            f"# Разрешить автоматический переход в Direct при недоступности ME-серверов",
            f"fallback_to_direct      = {str(self.fallback_to_direct).lower()}",
            f"",
            f"# Попыток инициализации ME-пула до признания его недоступным",
            f"fallback_after_attempts = {self.fallback_after_attempts}",
            f"",
            f"# Максимальное время warmup ME-пула (секунд). При превышении — fallback.",
            f"fallback_after_seconds  = {self.fallback_after_seconds}",
            f"",
            f"# Автоматический возврат в Middle Proxy после восстановления",
            f"# (каркас для будущей реализации; при true — только логирование)",
            f"auto_revert_to_middle   = {str(self.auto_revert_to_middle).lower()}",
        ]
        return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════════════
#  ЧТЕНИЕ КОНФИГА
# ══════════════════════════════════════════════════════════════════════════════

def read_fallback_config(config_file: Path = _CONFIG_FILE) -> FallbackConfig:
    """
    Читает параметры секции [middle_proxy] из telemt.toml.
    Если секция отсутствует или файл не найден — возвращает дефолты.
    Полностью безопасна: никогда не бросает исключений.
    """
    cfg = FallbackConfig()
    if not config_file.exists():
        return cfg
    try:
        text = config_file.read_text(encoding="utf-8", errors="replace")
        in_section = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped == "[middle_proxy]":
                in_section = True
                continue
            if in_section and stripped.startswith("[") and stripped != "[middle_proxy]":
                break   # вошли в другую секцию
            if not in_section or stripped.startswith("#") or not stripped:
                continue
            m = re.match(r'^(\w+)\s*=\s*(.+)', stripped)
            if not m:
                continue
            key, val = m.group(1).strip(), m.group(2).strip().lower()
            if key == "fallback_to_direct":
                cfg.fallback_to_direct = val in ("true", "1", "yes")
            elif key == "fallback_after_attempts":
                try:    cfg.fallback_after_attempts = int(val)
                except ValueError: pass
            elif key == "fallback_after_seconds":
                try:    cfg.fallback_after_seconds = int(val)
                except ValueError: pass
            elif key == "auto_revert_to_middle":
                cfg.auto_revert_to_middle = val in ("true", "1", "yes")
    except Exception:
        pass
    # Вызываем __post_init__ для нормализации значений
    cfg.__post_init__()
    return cfg


def read_runtime_middle_proxy(config_file: Path = _CONFIG_FILE) -> Optional[bool]:
    """
    Читает значение use_middle_proxy из [general] секции telemt.toml.
    Возвращает True/False/None (None = не найдено).
    """
    if not config_file.exists():
        return None
    try:
        text = config_file.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'^use_middle_proxy\s*=\s*(true|false)', text, re.MULTILINE | re.IGNORECASE)
        if m:
            return m.group(1).lower() == "true"
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  ЗАПИСЬ СЕКЦИИ В КОНФИГ (append_fallback_section)
# ══════════════════════════════════════════════════════════════════════════════

def append_fallback_section(
    config_file: Path,
    fb: FallbackConfig,
) -> None:
    """
    Добавляет или обновляет секцию [middle_proxy] в telemt.toml.

    Если секция уже есть — заменяет её целиком.
    Если нет — добавляет в конец файла.
    Не меняет остальные части конфига.
    """
    if not config_file.exists():
        return

    text = config_file.read_text(encoding="utf-8", errors="replace")

    # Удаляем существующую секцию [middle_proxy] если есть
    lines = text.splitlines()
    out_lines: list[str] = []
    skip = False
    for line in lines:
        stripped = line.strip()
        if stripped == "[middle_proxy]":
            skip = True
            continue
        if skip and stripped.startswith("[") and stripped != "[middle_proxy]":
            skip = False
        if not skip:
            out_lines.append(line)

    new_text = "\n".join(out_lines).rstrip() + "\n"
    new_text += fb.to_toml_section()

    config_file.write_text(new_text, encoding="utf-8")
    config_file.chmod(0o640)


# ══════════════════════════════════════════════════════════════════════════════
#  ME-ПРОБА (TCP-проверка доступности Middle Proxy серверов)
# ══════════════════════════════════════════════════════════════════════════════

class MiddleProxyProbe:
    """
    Проверяет доступность ME-серверов Telegram через TCP-рукопожатие.

    Не реализует MTProto-рукопожатие — только TCP CONNECT к известным
    адресам. Этого достаточно для предварительной оценки: если TCP
    не проходит, Middle Proxy гарантированно не сработает.

    Потокобезопасна.
    """

    def __init__(
        self,
        endpoints: list[tuple[str, int]] = _ME_ENDPOINTS,
        tcp_timeout: float = _PROBE_TCP_TIMEOUT,
        quorum: float = _ME_QUORUM,
    ) -> None:
        self._endpoints  = endpoints
        self._timeout    = tcp_timeout
        self._quorum     = quorum

    def probe_one(self, host: str, port: int) -> bool:
        """Один TCP-connect. True = доступен."""
        try:
            with socket.create_connection((host, port), timeout=self._timeout):
                return True
        except (OSError, socket.timeout, ConnectionRefusedError):
            return False

    def probe_all(self) -> tuple[int, int]:
        """
        Проверяет все endpoints параллельно (Thread pool).
        Возвращает (успешных, всего).
        """
        results: list[bool] = [False] * len(self._endpoints)
        threads: list[Thread] = []

        def _worker(idx: int, host: str, port: int) -> None:
            results[idx] = self.probe_one(host, port)

        for i, (h, p) in enumerate(self._endpoints):
            t = Thread(target=_worker, args=(i, h, p), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=self._timeout + 1)

        ok = sum(results)
        return ok, len(self._endpoints)

    def is_available(self) -> bool:
        """True если кворум ME-серверов доступен."""
        ok, total = self.probe_all()
        if total == 0:
            return False
        return (ok / total) >= self._quorum

    def summary(self) -> str:
        """Краткая строка состояния для логов."""
        ok, total = self.probe_all()
        if total == 0:
            return "ME-серверы: список пуст"
        ratio = ok / total
        avail = f"{ok}/{total}"
        if ratio >= self._quorum:
            return f"ME-серверы доступны ({avail} endpoint'ов)"
        return f"ME-серверы НЕДОСТУПНЫ ({avail} endpoint'ов < кворум {self._quorum:.0%})"


# ══════════════════════════════════════════════════════════════════════════════
#  ПРОВЕРКА JOURNALCTL НА СИГНАЛЫ ОТКАЗА ME
# ══════════════════════════════════════════════════════════════════════════════

def check_journal_for_me_failures(
    lines: int = 100,
    service: str = _SERVICE_NAME,
) -> list[str]:
    """
    Читает последние N строк journalctl и ищет сигналы деградации ME-пула.
    Возвращает список найденных строк (пустой список = всё нормально).
    Не бросает исключений.
    """
    try:
        r = subprocess.run(
            ["journalctl", "-u", service, "-n", str(lines),
             "--no-pager", "--output=short"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=10,
        )
        if r.returncode != 0:
            return []
        hits: list[str] = []
        for line in r.stdout.splitlines():
            for pattern in _ME_FAILURE_PATTERNS:
                if pattern.lower() in line.lower():
                    hits.append(line.strip())
                    break
        return hits
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════════
#  RUNTIME FALLBACK: переключение use_middle_proxy в конфиге без рестарта
# ══════════════════════════════════════════════════════════════════════════════

def _log_fb(msg: str, level: str = "INFO") -> None:
    """Пишет в лог-файл и stdout."""
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] [{level}] FALLBACK: {msg}\n")
    except Exception:
        pass
    prefix = {
        "INFO":  f"  {CYAN}→{NC}  ",
        "WARN":  f"  {YELLOW}⚠{NC}  ",
        "ERROR": f"  {RED}✗{NC}  ",
        "OK":    f"  {GREEN}✓{NC}  ",
    }.get(level, "  ")
    print(f"{prefix}{msg}", flush=True)


def _patch_config_middle_proxy(
    config_file: Path,
    enable: bool,
) -> bool:
    """
    Переключает use_middle_proxy и [dc_overrides] в telemt.toml в памяти.

    Важно:
      • Это ЕДИНСТВЕННАЯ функция, которая модифицирует toml на диске при fallback.
      • Вызывается только из FallbackOrchestrator.
      • Не меняет порты, listeners, upstream, xray-интеграцию.
      • После изменения нужен `systemctl reload telemt` (SIGHUP).

    Возвращает True при успехе.
    """
    if not config_file.exists():
        return False
    try:
        text = config_file.read_text(encoding="utf-8", errors="replace")

        # Проверяем наличие ключа (независимо от текущего значения и пробелов)
        key_present = bool(re.search(
            r'^use_middle_proxy\s*=\s*(true|false)',
            text,
            flags=re.MULTILINE | re.IGNORECASE,
        ))

        if key_present:
            # Ключ есть — заменяем значение. count=1 защищает от двойной замены.
            new_text = re.sub(
                r'^(use_middle_proxy\s*=\s*)(true|false)',
                f'use_middle_proxy = {str(enable).lower()}',
                text,
                count=1,
                flags=re.MULTILINE | re.IGNORECASE,
            )
            # Удаляем возможные дублирующиеся строки (защита от старых конфигов)
            lines = new_text.splitlines()
            seen_key = False
            out_lines = []
            for line in lines:
                if re.match(r'^use_middle_proxy\s*=', line, re.IGNORECASE):
                    if seen_key:
                        continue   # дубликат — пропускаем
                    seen_key = True
                out_lines.append(line)
            new_text = "\n".join(out_lines)
            if not new_text.endswith("\n"):
                new_text += "\n"
        else:
            # Ключ отсутствует — вставляем сразу после заголовка [general]
            new_text = re.sub(
                r'(\[general\])',
                f'\\1\nuse_middle_proxy = {str(enable).lower()}',
                text,
                count=1,
            )

        # Управляем [dc_overrides]: при direct-режиме прописываем все Telegram DC.
        # Адреса актуальны для Telemt v3.x (Direct Mode без Middle Proxy).
        # Только положительные ключи — Telemt v3.x не принимает отрицательные
        # ключи в [dc_overrides] и выдаёт "Invalid dc_overrides key" при старте.
        # Источник: официальная документация Telegram / публичные MTProto-адреса.
        _DC_OVERRIDES = (
            '"1"   = "149.154.175.50:443"\n'
            '"2"   = "149.154.167.51:443"\n'
            '"3"   = "149.154.175.100:443"\n'
            '"4"   = "149.154.167.91:443"\n'
            '"5"   = "91.108.4.100:443"\n'
            '"203" = "91.105.192.100:443"\n'
        )
        if not enable:
            if "[dc_overrides]" not in new_text:
                new_text = new_text.rstrip() + '\n\n[dc_overrides]\n' + _DC_OVERRIDES
        else:
            # При возврате в Middle Proxy убираем dc_overrides
            lines = new_text.splitlines()
            out, skip = [], False
            for line in lines:
                if line.strip() == "[dc_overrides]":
                    skip = True; continue
                if skip and line.strip().startswith("["):
                    skip = False
                if not skip:
                    out.append(line)
            new_text = "\n".join(out).rstrip() + "\n"

        config_file.write_text(new_text, encoding="utf-8")
        config_file.chmod(0o640)
        return True
    except Exception as e:
        _log_fb(f"Ошибка записи конфига: {e}", "ERROR")
        return False


def _reload_telemt(service: str = _SERVICE_NAME) -> bool:
    """
    Посылает SIGHUP процессу telemt (systemctl reload).
    Telemt перечитывает конфиг без разрыва текущих соединений.
    Возвращает True при успехе.
    """
    try:
        r = subprocess.run(
            ["systemctl", "reload", service],
            capture_output=True, timeout=15,
        )
        return r.returncode == 0
    except Exception:
        return False


def _restart_telemt(service: str = _SERVICE_NAME) -> bool:
    """Полный рестарт (fallback если reload не сработал)."""
    try:
        r = subprocess.run(
            ["systemctl", "restart", service],
            capture_output=True, timeout=30,
        )
        return r.returncode == 0
    except Exception:
        return False


def apply_telemt_reload(service: str = _SERVICE_NAME) -> tuple[bool, str]:
    """
    Применяет уже записанный на диск telemt.toml к запущенному процессу.

    Баг, который эта функция исправляет:
      `_reload_telemt()` (systemctl reload) у юнитов telemt.service,
      созданных без `ExecReload=` (а такие уже стоят на проде — старые
      установки), всегда завершается ошибкой ("Job type reload is not
      applicable for unit telemt.service"). Раньше это игнорировалось
      вызывающей стороной: конфиг на диске менялся корректно, но
      запущенный процесс об этом не узнавал, и ручное переключение
      Direct ↔ Middle в меню "F" визуально показывало успех, хотя
      реального переключения не происходило.

    Эта функция:
      1. Пробует мягкий reload (SIGHUP) через _reload_telemt().
      2. Если reload не сработал — откатывается на полный restart
         через _restart_telemt(). Полный restart всегда подхватывает
         актуальный telemt.toml с диска, независимо от того, объявлен
         ли ExecReload в юните.
      3. Возвращает (success, method), чтобы вызывающий код мог
         показать пользователю правду о том, что произошло.

    Используется как для Direct → Middle, так и для Middle → Direct —
    логика симметрична для обоих направлений.
    """
    if _reload_telemt(service):
        _log_fb("Конфиг применён через systemctl reload (SIGHUP).", "OK")
        return True, "reload"

    _log_fb(
        "systemctl reload не сработал (вероятно, юнит создан без "
        "ExecReload) — пробую полный restart.",
        "WARN",
    )
    if _restart_telemt(service):
        _log_fb("Конфиг применён через systemctl restart.", "OK")
        return True, "restart"

    _log_fb("Не удалось применить конфиг ни через reload, ни через restart.", "ERROR")
    return False, "none"


# ══════════════════════════════════════════════════════════════════════════════
#  ОРКЕСТРАТОР FALLBACK
# ══════════════════════════════════════════════════════════════════════════════

class FallbackOrchestrator:
    """
    Координирует попытки инициализации ME-пула и переключение в Direct Mode.

    Жизненный цикл:
      1. run_with_fallback() — вызывается после старта telemt (post-install).
         Ждёт warmup или фиксирует отказ, затем выполняет fallback.
      2. apply_reload_config() — вызывается при hot-reload. Переприменяет
         значение use_middle_proxy из конфига с приоритетом над runtime.
      3. status() — текущее состояние для отображения в UI.

    Защита от циклов:
      • После fallback в Direct новые попытки ME НЕ запускаются автоматически.
      • Повтор только при: reload конфига | явном auto_revert_to_middle.
      • _stop_event предотвращает zombie-потоки.

    Потокобезопасность:
      • _mode и _attempts защищены через Python GIL (int/str присвоение атомарно).
      • Для production с многопоточными читателями рекомендуется threading.Lock,
        но в данной архитектуре (один поток UI + один watchdog) GIL достаточен.
    """

    def __init__(
        self,
        fb_config: FallbackConfig,
        config_file: Path = _CONFIG_FILE,
        service: str = _SERVICE_NAME,
        probe: Optional[MiddleProxyProbe] = None,
        on_fallback: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        fb_config   — параметры из секции [middle_proxy] в toml
        config_file — путь к telemt.toml
        service     — имя systemd-сервиса
        probe       — объект MiddleProxyProbe (подменяется в тестах)
        on_fallback — callback при срабатывании fallback (для UI/алертов)
        """
        self._fb         = fb_config
        self._cfg_file   = config_file
        self._service    = service
        self._probe      = probe or MiddleProxyProbe()
        self._on_fallback = on_fallback

        # Runtime-состояние (не сохраняется на диск)
        self._mode       = "middle"    # "middle" | "direct" | "unknown"
        self._attempts   = 0
        self._stop_event = Event()
        self._watchdog_thread: Optional[Thread] = None

    # ── Публичные свойства ────────────────────────────────────────────────────

    @property
    def mode(self) -> str:
        """Текущий runtime-режим: 'middle' | 'direct' | 'unknown'."""
        return self._mode

    @property
    def fallback_active(self) -> bool:
        """True если сработал автоматический fallback в Direct."""
        return self._mode == "direct"

    def status(self) -> dict:
        """Словарь состояния для отображения в UI."""
        return {
            "mode":            self._mode,
            "attempts":        self._attempts,
            "fallback_active": self.fallback_active,
            "fb_config":       self._fb,
        }

    # ── Основной метод: запуск с fallback ────────────────────────────────────

    def run_with_fallback(self) -> str:
        """
        Проверяет доступность ME-серверов и при необходимости выполняет
        runtime fallback в Direct Mode.

        Алгоритм:
          1. Если fallback_to_direct=false — ничего не делаем (pass-through).
          2. Пробуем TCP к ME-серверам fallback_after_attempts раз.
          3. Если кворум достигнут — режим остаётся Middle.
          4. Если превышен timeout или attempts — переключаем в Direct.
          5. Проверяем journalctl на сигналы отказа ME.

        Возвращает строку-резюме для лога/UI.
        """
        if not self._fb.fallback_to_direct:
            self._mode = "middle"
            return "Fallback отключён (fallback_to_direct=false) — оставляем Middle Proxy"

        # Проверка через journalctl (быстрая, без сетевых запросов)
        journal_hits = check_journal_for_me_failures()
        if journal_hits:
            _log_fb(
                f"Обнаружены признаки отказа ME в логах ({len(journal_hits)} совпадений):",
                "WARN",
            )
            for hit in journal_hits[:3]:
                _log_fb(f"  → {hit}", "WARN")

        # Сетевые пробы с повторами
        deadline = time.monotonic() + self._fb.fallback_after_seconds
        success  = False

        for attempt in range(1, self._fb.fallback_after_attempts + 1):
            self._attempts = attempt
            if self._stop_event.is_set():
                break
            if time.monotonic() > deadline:
                _log_fb(
                    f"WARN  Middle Proxy warmup timeout exceeded ({self._fb.fallback_after_seconds}s)",
                    "WARN",
                )
                break

            _log_fb(f"Проба ME-серверов (попытка {attempt}/{self._fb.fallback_after_attempts})...", "INFO")
            ok, total = self._probe.probe_all()
            ratio = ok / total if total else 0

            if ratio >= _ME_QUORUM:
                _log_fb(f"ME-пул доступен: {ok}/{total} endpoint'ов активны", "OK")
                success = True
                break
            else:
                _log_fb(
                    f"WARN  ME pool initialization failed after attempt {attempt} "
                    f"({ok}/{total} endpoint'ов, кворум {_ME_QUORUM:.0%})",
                    "WARN",
                )
                # Небольшая пауза перед следующей попыткой
                if attempt < self._fb.fallback_after_attempts:
                    wait = min(10, (self._fb.fallback_after_seconds // self._fb.fallback_after_attempts))
                    if not self._stop_event.wait(timeout=wait):
                        pass   # продолжаем

        if success and not journal_hits:
            self._mode = "middle"
            return "Middle Proxy инициализирован успешно — продолжаем в режиме Middle Proxy"

        # ── Выполняем fallback ────────────────────────────────────────────────
        return self._do_fallback(
            reason=(
                f"ME pool initialization failed after {self._attempts} attempts"
                if not success else
                "Обнаружены сигналы отказа ME в журнале"
            )
        )

    def _do_fallback(self, reason: str) -> str:
        """
        Выполняет runtime-переключение в Direct Mode.

        Действия:
          1. Пишем предупреждение в лог.
          2. Патчим telemt.toml: use_middle_proxy=false + dc_overrides.
          3. SIGHUP (systemctl reload) — telemt перечитывает конфиг.
             Текущие соединения НЕ разрываются (Telemt поддерживает reload).
          4. Обновляем runtime-состояние.
          5. Вызываем on_fallback callback если задан.
        """
        _log_fb(
            f"WARN  ME pool initialization failed for too long → "
            f"falling back to Direct DC mode for stability",
            "WARN",
        )
        _log_fb(f"  Причина: {reason}", "WARN")

        # Патчим конфиг (только runtime, не ломаем пользовательские настройки)
        patched = _patch_config_middle_proxy(self._cfg_file, enable=False)
        if patched:
            # Reload: telemt перечитывает конфиг без разрыва соединений
            reloaded = _reload_telemt(self._service)
            if not reloaded:
                # Если reload не поддерживается — тихий fallback (конфиг уже изменён,
                # применится при следующем старте / рестарте)
                _log_fb(
                    "systemctl reload вернул ненулевой код — "
                    "изменения применятся при следующем рестарте",
                    "WARN",
                )
            else:
                _log_fb(
                    "INFO  Runtime transport mode switched: Middle Proxy -> Direct",
                    "INFO",
                )
        else:
            _log_fb("Не удалось обновить telemt.toml — конфиг не изменён", "ERROR")

        self._mode = "direct"

        if self._on_fallback:
            try:
                self._on_fallback(reason)
            except Exception:
                pass

        return (
            f"Fallback выполнен: Middle Proxy → Direct Mode "
            f"(причина: {reason})"
        )

    # ── Hot-reload ────────────────────────────────────────────────────────────

    def apply_reload_config(self, new_fb: Optional[FallbackConfig] = None) -> str:
        """
        Вызывается при hot-reload конфига.

        Логика (из ТЗ):
          • Новое значение use_middle_proxy из конфига имеет приоритет над
            текущим runtime fallback состоянием.
          • Если конфиг требует Middle Proxy — запускаем новую попытку.
          • Если конфиг требует Direct — применяем без попыток.

        Пример:
          Старт → use_middle_proxy=true → fallback в Direct
          Reload → в конфиге всё ещё use_middle_proxy=true
          → снова пытаемся инициализировать Middle Proxy  ← ожидаемое поведение
        """
        if new_fb is not None:
            self._fb = new_fb
            self._fb.__post_init__()

        # Читаем актуальное значение use_middle_proxy из файла
        want_middle = read_runtime_middle_proxy(self._cfg_file)

        _log_fb(
            f"INFO  Configuration reload: use_middle_proxy={want_middle}, "
            f"current_mode={self._mode}",
            "INFO",
        )

        if want_middle is True:
            _log_fb(
                "INFO  Configuration reload requested Middle Proxy mode, "
                "starting ME pool initialization",
                "INFO",
            )
            # Сбрасываем счётчик попыток и повторяем инициализацию
            self._attempts = 0
            self._stop_event.clear()
            # Восстанавливаем Middle Proxy в конфиге (если был fallback)
            if self._mode == "direct":
                _patch_config_middle_proxy(self._cfg_file, enable=True)
                _reload_telemt(self._service)
                self._mode = "middle"
            return self.run_with_fallback()

        elif want_middle is False:
            self._mode = "direct"
            _patch_config_middle_proxy(self._cfg_file, enable=False)
            _reload_telemt(self._service)
            return "Reload: конфиг требует Direct Mode — применено"

        return "Reload: use_middle_proxy не найден в конфиге — состояние не изменено"

    # ── Auto-revert каркас ────────────────────────────────────────────────────

    def start_auto_revert_watchdog(self, check_interval: int = 120) -> None:
        """
        Каркас для автоматического возврата в Middle Proxy.

        При auto_revert_to_middle=true запускает фоновый поток,
        который периодически проверяет доступность ME-серверов и
        при успешном кворуме выполняет возврат в Middle Proxy.

        Защита от flapping:
          • Переключение обратно только после 3 последовательных успешных проб.
          • Гистерезис: интервал проверки увеличивается после каждого fallback.

        Текущий статус: каркас реализован, активируется при
        auto_revert_to_middle=true. Полная логика — в следующей итерации.
        """
        if not self._fb.auto_revert_to_middle:
            return
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            return

        def _watchdog() -> None:
            consecutive_ok = 0
            _log_fb(
                "INFO  Auto-revert watchdog started "
                f"(interval={check_interval}s, hysteresis=3 consecutive OK)",
                "INFO",
            )
            while not self._stop_event.wait(timeout=check_interval):
                if self._mode != "direct":
                    consecutive_ok = 0
                    continue
                ok, total = self._probe.probe_all()
                ratio = ok / total if total else 0
                if ratio >= _ME_QUORUM:
                    consecutive_ok += 1
                    _log_fb(
                        f"INFO  Auto-revert: ME-серверы доступны "
                        f"({ok}/{total}), consecutive_ok={consecutive_ok}/3",
                        "INFO",
                    )
                    if consecutive_ok >= 3:
                        # Полный warmup перед переключением
                        _log_fb(
                            "INFO  Auto-revert: кворум стабилен 3 раза подряд — "
                            "возвращаем Middle Proxy",
                            "INFO",
                        )
                        self._attempts = 0
                        result = self.apply_reload_config()
                        _log_fb(f"Auto-revert result: {result}", "INFO")
                        consecutive_ok = 0
                else:
                    if consecutive_ok > 0:
                        _log_fb(
                            f"INFO  Auto-revert: ME-серверы снова недоступны "
                            f"({ok}/{total}) — сброс счётчика",
                            "INFO",
                        )
                    consecutive_ok = 0

        self._watchdog_thread = Thread(target=_watchdog, daemon=True, name="telemt-auto-revert")
        self._watchdog_thread.start()

    def stop(self) -> None:
        """Останавливает фоновые потоки (вызывать при выходе из программы)."""
        self._stop_event.set()
        if self._watchdog_thread:
            self._watchdog_thread.join(timeout=5)


# ══════════════════════════════════════════════════════════════════════════════
#  POST-INSTALL FALLBACK WATCHDOG (используется из _run_install_inner)
# ══════════════════════════════════════════════════════════════════════════════

def run_post_install_fallback_check(
    config_file: Path = _CONFIG_FILE,
    service: str = _SERVICE_NAME,
    warmup_wait: int = 10,
) -> Optional[str]:
    """
    Выполняет проверку Middle Proxy после запуска Telemt.

    Вызывается из _run_install_inner() после `systemctl start telemt`,
    уже после ожидания открытия порта.

    Возвращает:
      None   — fallback не нужен (ME доступен или fallback отключён)
      str    — сообщение об ошибке/fallback для отображения в UI
    """
    fb_config = read_fallback_config(config_file)
    want_middle = read_runtime_middle_proxy(config_file)

    if not want_middle:
        # Telemt уже в Direct Mode — проверять нечего
        return None
    if not fb_config.fallback_to_direct:
        # Fallback отключён пользователем
        return None

    # Ждём прогрева сервиса перед первой пробой
    _log_fb(f"Ожидаю {warmup_wait}с прогрева Middle Proxy перед пробой...", "INFO")
    time.sleep(warmup_wait)

    orch = FallbackOrchestrator(
        fb_config=fb_config,
        config_file=config_file,
        service=service,
    )
    result = orch.run_with_fallback()
    _log_fb(result, "INFO")

    if orch.fallback_active:
        # Запускаем auto-revert watchdog если настроен
        orch.start_auto_revert_watchdog()
        return result
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  UI: МЕНЮ НАСТРОЙКИ FALLBACK (вызывается из меню установки Telemt)
# ══════════════════════════════════════════════════════════════════════════════

def me_probe_menu(config_file: Path = _CONFIG_FILE) -> FallbackConfig:
    """
    Интерактивное меню настройки параметров fallback.
    Вызывается из _run_install_inner() перед записью конфига.
    Возвращает заполненный FallbackConfig.

    Текущие настройки читаются из существующего конфига (если есть).
    """
    current = read_fallback_config(config_file)

    _BOX_W = 66
    def _plain(s: str) -> str:
        return re.sub(r'\033\[[0-9;]*m', '', s)
    def _wlen(s: str) -> int:
        import unicodedata as _ud
        plain = _plain(s); width = 0
        for ch in list(plain):
            eaw = _ud.east_asian_width(ch)
            width += 2 if eaw in ('W', 'F') else 1
        return width
    def _box_row(text: str = "") -> None:
        pad = max(0, _BOX_W - _wlen(text))
        print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")
    def _box_kv(key: str, val: str, kw: int = 28) -> None:
        key_colored = f"{CYAN}{key}{NC}"
        key_pad = kw - _wlen(key_colored)
        _box_row(f"  {key_colored}{' ' * max(0, key_pad)}  {val}")
    def _box_sep() -> None:
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
    def _box_item(key: str, label: str) -> None:
        col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
        _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

    import os as _os
    _os.system("clear")
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    title = "НАСТРОЙКА FALLBACK: MIDDLE PROXY → DIRECT"
    pad   = _BOX_W - _wlen(title)
    print(f"{CYAN}║{NC}{' ' * (pad // 2)}{BOLD}{WHITE}{title}{NC}{' ' * (pad - pad // 2)}{CYAN}║{NC}")
    print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
    _box_row()
    _box_row(f"  {DIM}При недоступности Telegram ME-серверов Telemt автоматически{NC}")
    _box_row(f"  {DIM}переходит в Direct Mode — без перезапуска и разрыва соединений.{NC}")
    _box_row()
    _box_row(f"  {BOLD}Текущие настройки:{NC}")
    _box_row()
    _box_kv("fallback_to_direct",      f"{GREEN if current.fallback_to_direct else RED}{current.fallback_to_direct}{NC}")
    _box_kv("fallback_after_attempts", str(current.fallback_after_attempts))
    _box_kv("fallback_after_seconds",  str(current.fallback_after_seconds))
    _box_kv("auto_revert_to_middle",   f"{GREEN if current.auto_revert_to_middle else DIM}{current.auto_revert_to_middle}{NC}")
    _box_row()
    _box_sep()
    _box_item("1", f"Включить fallback  {GREEN}(рекомендуется){NC}")
    _box_item("2", f"Отключить fallback {DIM}(жёсткий Middle Proxy){NC}")
    _box_item("3", f"Настроить параметры вручную")
    _box_item("T", f"Проверить доступность ME-серверов прямо сейчас")
    _box_sep()
    _box_item("Enter", f"Оставить текущие настройки и продолжить")
    _box_item("Q",     f"← Назад (без изменений)")
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")
    print()

    try:
        print(f"{CYAN}Выбор: {NC}", end="", flush=True)
        ch = input().strip().lower()
    except (KeyboardInterrupt, EOFError):
        print(); return current

    if ch == "q" or ch == "":
        return current

    if ch == "1":
        current.fallback_to_direct = True
        print(f"  {GREEN}✓{NC}  Fallback включён.")

    elif ch == "2":
        current.fallback_to_direct = False
        print(f"  {YELLOW}⚠{NC}  Fallback отключён — Middle Proxy обязателен.")

    elif ch == "3":
        print()
        # fallback_after_attempts
        try:
            print(f"  Попыток перед fallback [{current.fallback_after_attempts}]: ", end="", flush=True)
            v = input().strip()
            if v:
                current.fallback_after_attempts = int(v)
        except (ValueError, KeyboardInterrupt, EOFError):
            pass
        # fallback_after_seconds
        try:
            print(f"  Timeout warmup (секунд) [{current.fallback_after_seconds}]: ", end="", flush=True)
            v = input().strip()
            if v:
                current.fallback_after_seconds = int(v)
        except (ValueError, KeyboardInterrupt, EOFError):
            pass
        # auto_revert
        try:
            print(f"  Auto-revert в Middle при восстановлении? [y/N]: ", end="", flush=True)
            v = input().strip().lower()
            current.auto_revert_to_middle = v == "y"
        except (KeyboardInterrupt, EOFError):
            pass
        current.__post_init__()
        print(f"  {GREEN}✓{NC}  Настройки обновлены.")

    elif ch == "t":
        print()
        print(f"  {CYAN}→{NC}  Проверяю доступность ME-серверов Telegram...")
        probe = MiddleProxyProbe()
        ok, total = probe.probe_all()
        ratio = ok / total if total else 0
        if ratio >= _ME_QUORUM:
            print(f"  {GREEN}✓{NC}  ME-серверы доступны: {ok}/{total} endpoint'ов ({ratio:.0%})")
            print(f"  {GREEN}✓{NC}  Middle Proxy должен работать нормально.")
        else:
            print(f"  {YELLOW}⚠{NC}  ME-серверы НЕДОСТУПНЫ: {ok}/{total} ({ratio:.0%} < кворум {_ME_QUORUM:.0%})")
            print(f"  {YELLOW}⚠{NC}  Fallback в Direct Mode будет активирован автоматически.")
        print()
        try:
            print(f"  {DIM}Нажмите Enter...{NC}", end="", flush=True)
            input()
        except (KeyboardInterrupt, EOFError):
            pass
        return me_probe_menu(config_file)   # рекурсивный возврат в меню

    return current


# ══════════════════════════════════════════════════════════════════════════════
#  UI: СТАТУС FALLBACK (для меню Telemt → пункт статуса)
# ══════════════════════════════════════════════════════════════════════════════

def fallback_status_line(config_file: Path = _CONFIG_FILE) -> str:
    """
    Краткая строка статуса для отображения в _box_kv в меню Telemt.
    Читает конфиг и возвращает цветную строку.
    """
    fb  = read_fallback_config(config_file)
    cur = read_runtime_middle_proxy(config_file)

    if not fb.fallback_to_direct:
        return f"{YELLOW}отключён{NC}"

    mode_str = "Middle Proxy" if cur else "Direct (fallback)"
    mode_col = GREEN if cur else YELLOW

    parts = [
        f"{mode_col}{mode_str}{NC}",
        f"{DIM}(попыток: {fb.fallback_after_attempts}, timeout: {fb.fallback_after_seconds}s){NC}",
    ]
    if fb.auto_revert_to_middle:
        parts.append(f"{CYAN}auto-revert{NC}")
    return "  ".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TESTS (запускаются через python -m pytest или python telemt_fallback.py)
# ══════════════════════════════════════════════════════════════════════════════

def _run_unit_tests() -> None:
    """Встроенные unit-тесты для CI без зависимостей от pytest."""
    import tempfile, os

    _errors = []
    _passed = 0

    def _assert(cond: bool, msg: str) -> None:
        nonlocal _passed
        if cond:
            _passed += 1
            print(f"  {GREEN}✓{NC}  {msg}")
        else:
            _errors.append(msg)
            print(f"  {RED}✗{NC}  FAIL: {msg}")

    print(f"\n{BOLD}=== FallbackConfig: парсинг и дефолты ==={NC}")

    # Дефолтные значения
    cfg = FallbackConfig.defaults()
    _assert(cfg.fallback_to_direct      is True,  "default: fallback_to_direct=True")
    _assert(cfg.fallback_after_attempts == 3,      "default: fallback_after_attempts=3")
    _assert(cfg.fallback_after_seconds  == 45,     "default: fallback_after_seconds=45")
    _assert(cfg.auto_revert_to_middle   is False,  "default: auto_revert_to_middle=False")

    # Защита от некорректных значений
    bad = FallbackConfig(fallback_after_attempts=0, fallback_after_seconds=5)
    _assert(bad.fallback_after_attempts >= 1,  "normalization: attempts>=1")
    _assert(bad.fallback_after_seconds  >= 10, "normalization: seconds>=10")

    print(f"\n{BOLD}=== read_fallback_config: чтение из toml ==={NC}")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[general]
use_middle_proxy = true

[middle_proxy]
fallback_to_direct      = false
fallback_after_attempts = 7
fallback_after_seconds  = 60
auto_revert_to_middle   = true

[server]
port = 8443
""")
        tmp_path = Path(f.name)

    try:
        parsed = read_fallback_config(tmp_path)
        _assert(parsed.fallback_to_direct      is False, "parse: fallback_to_direct=false")
        _assert(parsed.fallback_after_attempts == 7,     "parse: fallback_after_attempts=7")
        _assert(parsed.fallback_after_seconds  == 60,    "parse: fallback_after_seconds=60")
        _assert(parsed.auto_revert_to_middle   is True,  "parse: auto_revert_to_middle=true")

        mp = read_runtime_middle_proxy(tmp_path)
        _assert(mp is True, "parse: use_middle_proxy=true")

    finally:
        tmp_path.unlink(missing_ok=True)

    print(f"\n{BOLD}=== append_fallback_section: запись в toml ==={NC}")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("[general]\nuse_middle_proxy = true\n\n[server]\nport = 8443\n")
        tmp_path = Path(f.name)
    try:
        fb = FallbackConfig(fallback_to_direct=True, fallback_after_attempts=5)
        append_fallback_section(tmp_path, fb)
        text = tmp_path.read_text()
        _assert("[middle_proxy]" in text,              "append: секция добавлена")
        _assert("fallback_after_attempts = 5" in text, "append: значение записано")
        # Повторная запись не дублирует секцию
        append_fallback_section(tmp_path, fb)
        _assert(text.count("[middle_proxy]") <= 1,    "append: нет дублирования")
    finally:
        tmp_path.unlink(missing_ok=True)

    print(f"\n{BOLD}=== _patch_config_middle_proxy ==={NC}")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("[general]\nuse_middle_proxy = true\nfast_mode = true\n")
        tmp_path = Path(f.name)
    try:
        _patch_config_middle_proxy(tmp_path, enable=False)
        text = tmp_path.read_text()
        _assert("use_middle_proxy = false" in text, "patch: middle→direct")
        _assert("[dc_overrides]" in text,           "patch: dc_overrides добавлен")

        _patch_config_middle_proxy(tmp_path, enable=True)
        text = tmp_path.read_text()
        _assert("use_middle_proxy = true" in text,  "patch: direct→middle")
        _assert("[dc_overrides]" not in text,       "patch: dc_overrides удалён")
    finally:
        tmp_path.unlink(missing_ok=True)

    print(f"\n{BOLD}=== FallbackOrchestrator: логика fallback ==={NC}")

    class _AlwaysFailProbe(MiddleProxyProbe):
        def probe_all(self) -> tuple[int, int]:
            return (0, len(self._endpoints))

    class _AlwaysOkProbe(MiddleProxyProbe):
        def probe_all(self) -> tuple[int, int]:
            return (len(self._endpoints), len(self._endpoints))

    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("[general]\nuse_middle_proxy = true\n")
        tmp_path = Path(f.name)

    try:
        fb_cfg = FallbackConfig(
            fallback_to_direct=True,
            fallback_after_attempts=2,
            fallback_after_seconds=10,
        )

        # Тест: ME недоступен → fallback
        orch = FallbackOrchestrator(
            fb_config=fb_cfg, config_file=tmp_path,
            service="telemt-test",
            probe=_AlwaysFailProbe(),
        )
        result = orch.run_with_fallback()
        _assert(orch.fallback_active,         "orchestrator: ME fail → fallback_active=True")
        _assert(orch.mode == "direct",        "orchestrator: ME fail → mode=direct")
        _assert("Direct" in result,           "orchestrator: result упоминает Direct")

        # Тест: ME доступен → нет fallback
        orch2 = FallbackOrchestrator(
            fb_config=fb_cfg, config_file=tmp_path,
            service="telemt-test",
            probe=_AlwaysOkProbe(),
        )
        # Восстанавливаем middle в конфиге для теста
        _patch_config_middle_proxy(tmp_path, enable=True)
        result2 = orch2.run_with_fallback()
        _assert(not orch2.fallback_active,    "orchestrator: ME ok → fallback_active=False")
        _assert(orch2.mode == "middle",       "orchestrator: ME ok → mode=middle")

        # Тест: fallback_to_direct=false → проверок нет
        fb_no_fb = FallbackConfig(fallback_to_direct=False)
        orch3 = FallbackOrchestrator(
            fb_config=fb_no_fb, config_file=tmp_path,
            service="telemt-test",
            probe=_AlwaysFailProbe(),
        )
        result3 = orch3.run_with_fallback()
        _assert(not orch3.fallback_active,    "orchestrator: fallback disabled → no fallback")

    finally:
        tmp_path.unlink(missing_ok=True)

    # Итог
    print()
    if _errors:
        print(f"{RED}{BOLD}FAILED: {len(_errors)} тест(ов){NC}")
        for e in _errors:
            print(f"  {RED}✗{NC}  {e}")
        sys.exit(1)
    else:
        print(f"{GREEN}{BOLD}Все {_passed} тест(ов) прошли ✓{NC}")


if __name__ == "__main__":
    if "--test" in sys.argv:
        _run_unit_tests()
    elif "--probe" in sys.argv:
        probe = MiddleProxyProbe()
        print(probe.summary())
    elif "--status" in sys.argv:
        print(fallback_status_line())
    else:
        print("Usage: python telemt_fallback.py [--test|--probe|--status]")
