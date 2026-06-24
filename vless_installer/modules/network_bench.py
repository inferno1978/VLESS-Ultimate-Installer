"""
vless_installer/modules/network_bench.py
───────────────────────────────────────────────────────────────────────────────
Бенчмарк сервера: CPU/RAM/диск/виртуализация/ОС + тест дисковой I/O +
multi-thread тест скорости сети через iperf3 по серверам RU/EU/NA/APAC.

Источник: bench.py — питоновский порт tlab_merged.sh (bench.sh by Teddysun,
mod. Nikola Tesla, https://t.me/tracerlab). Адаптирован для встраивания в
VLESS-Ultimate-Installer: убраны глобальные signal-хендлеры и sys.exit() —
в оригинале они завершали бы ВЕСЬ процесс установщика, а не только это
подменю. Логика сбора метрик и тестов скорости не менялась.

Зависимости: только stdlib (Python 3.8+). Новых pip-пакетов не добавляет.
Внешние программы: ping, iperf3 (ставится сам через apt/yum/dnf/pacman/apk
или статический бинарь, как в оригинале).

Приватность: print_run_stats() обращается к https://bench.tlab.pw/stats.json
(публичный счётчик запусков оригинального скрипта). Отключается флагом
_PING_RUN_STATS ниже, если такие внешние обращения нежелательны.

Точка входа из _core.py:
    from vless_installer.modules.network_bench import do_network_bench_menu
───────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── box_renderer (UI меню) ──────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_item, _box_back,
    _box_info, _box_warn, _box_desc,
)

# Публичный счётчик запусков оригинального bench.sh — поставьте False,
# если внешние обращения к bench.tlab.pw нежелательны.
_PING_RUN_STATS = True

# --------------------------------------------------------------------------- #
# Константы / цвета
# --------------------------------------------------------------------------- #

LOCK_FILE = Path(tempfile.gettempdir()) / "iperf3_last_run"
MIN_INTERVAL = 300  # секунд, как в оригинале (комментарий "10 минут" был неточен)
THREADS = 8

RED = "\033[0;31;31m"
GREEN = "\033[0;31;32m"
YELLOW = "\033[0;31;33m"
BLUE = "\033[0;31;36m"
MAGENTA = "\033[0;35m"
CYAN = "\033[0;36m"
RESET = "\033[0m"


def _c(color: str, text: str) -> str:
    return f"{color}{text}{RESET}"


def hide_cursor() -> None:
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()


def show_cursor() -> None:
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()


def exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def next_line() -> None:
    print("-" * 70)


# --------------------------------------------------------------------------- #
# Анти-флуд лок
# --------------------------------------------------------------------------- #

def check_rate_limit() -> bool:
    """Возвращает False (и печатает причину), если запускать ещё рано."""
    if LOCK_FILE.exists():
        try:
            last_run = int(re.sub(r"[^0-9]", "", LOCK_FILE.read_text().strip()) or 0)
        except (ValueError, OSError):
            last_run = 0
        diff = int(time.time()) - last_run
        if diff < MIN_INTERVAL:
            left = MIN_INTERVAL - diff
            print(_c(YELLOW, "\u26a0 The test can be run no more than once every few minutes."))
            print(_c(YELLOW, f"\u23f3 Wait another {left // 60} min {left % 60} sec."))
            return False
    return True


def mark_success() -> None:
    LOCK_FILE.write_text(str(int(time.time())))


# --------------------------------------------------------------------------- #
# Системная информация
# --------------------------------------------------------------------------- #

@dataclass
class SystemInfo:
    cname: str = ""
    cores: int = 0
    freq: str = ""
    ccache: str = ""
    aes: bool = False
    virt_flags: bool = False
    total_ram: int = 0
    used_ram: int = 0
    total_swap: int = 0
    used_swap: int = 0
    uptime: str = ""
    load: str = ""
    opsy: str = ""
    arch: str = ""
    lbit: str = ""
    kern: str = ""
    disk_total: int = 0
    disk_used: int = 0
    tcpctrl: str = ""
    virt: str = "Dedicated"
    ipv4_online: bool = False
    ipv6_online: bool = False


def read_cpuinfo() -> dict:
    data = {"model": "", "cores": 0, "freq": "", "cache": "", "aes": False, "virt": False}
    try:
        text = Path("/proc/cpuinfo").read_text(errors="ignore")
    except OSError:
        return data
    for m in re.finditer(r"model name\s*:\s*(.+)", text):
        data["model"] = m.group(1).strip()
    data["cores"] = len(re.findall(r"^processor\s*:", text, re.MULTILINE))
    m = re.search(r"cpu MHz\s*:\s*([\d.]+)", text)
    if m:
        data["freq"] = m.group(1)
    m = re.search(r"cache size\s*:\s*(.+)", text)
    if m:
        data["cache"] = m.group(1).strip()
    data["aes"] = bool(re.search(r"(?i)\baes\b", text))
    data["virt"] = bool(re.search(r"(?i)\b(vmx|svm)\b", text))
    return data


def read_meminfo() -> tuple[int, int, int, int]:
    """Возвращает total_ram, used_ram, total_swap, used_swap в байтах (как `free -b`)."""
    info = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, val = line.partition(":")
            val = val.strip().split()[0]
            info[key] = int(val) * 1024  # /proc/meminfo в КиБ
    except OSError:
        return 0, 0, 0, 0
    total_ram = info.get("MemTotal", 0)
    free_ram = info.get("MemAvailable", info.get("MemFree", 0))
    used_ram = max(total_ram - free_ram, 0)
    total_swap = info.get("SwapTotal", 0)
    free_swap = info.get("SwapFree", 0)
    used_swap = max(total_swap - free_swap, 0)
    return total_ram, used_ram, total_swap, used_swap


def get_opsy() -> str:
    redhat = Path("/etc/redhat-release")
    if redhat.exists():
        return redhat.read_text().strip()
    os_release = Path("/etc/os-release")
    if os_release.exists():
        for line in os_release.read_text().splitlines():
            if line.startswith("PRETTY_NAME"):
                return line.split("=", 1)[1].strip().strip('"')
    lsb = Path("/etc/lsb-release")
    if lsb.exists():
        for line in lsb.read_text().splitlines():
            if "DESCRIPTION" in line:
                return line.split("=", 1)[1].strip().strip('"')
    return ""


def get_load_average() -> str:
    try:
        l1, l5, l15 = os.getloadavg()
        return f"{l1:.2f}, {l5:.2f}, {l15:.2f}"
    except (OSError, AttributeError):
        return ""


def get_uptime() -> str:
    try:
        secs = float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return ""
    days = int(secs // 86400)
    hours = int((secs % 86400) // 3600)
    mins = int((secs % 3600) // 60)
    return f"{days} days, {hours} hour {mins} min"


def calc_size(raw: int) -> str:
    if raw <= 0:
        return ""
    for limit, unit in ((1 << 40, "TB"), (1 << 30, "GB"), (1 << 20, "MB"), (1 << 10, "KB")):
        if raw >= limit:
            return f"{raw / limit:.2f} {unit}"
    return f"{raw:.2f} B"


def get_disk_usage() -> tuple[int, int]:
    """Грубый аналог `df --total` по всем смонтированным разделам обычных ФС."""
    fs_ok = {"ext2", "ext3", "ext4", "btrfs", "xfs", "vfat", "ntfs", "simfs"}
    total = used = 0
    seen = set()
    try:
        mounts = Path("/proc/mounts").read_text().splitlines()
    except OSError:
        return 0, 0
    for line in mounts:
        parts = line.split()
        if len(parts) < 3:
            continue
        _, mountpoint, fstype = parts[0], parts[1], parts[2]
        if fstype not in fs_ok or mountpoint in seen:
            continue
        seen.add(mountpoint)
        try:
            st = os.statvfs(mountpoint)
        except OSError:
            continue
        size = st.f_frsize * st.f_blocks
        free = st.f_frsize * st.f_bfree
        total += size
        used += size - free
    return total, used


def check_virt(cname: str) -> str:
    def safe_read(path: str) -> str:
        try:
            return Path(path).read_text(errors="ignore")
        except OSError:
            return ""

    cgroup = safe_read("/proc/1/cgroup")
    environ = safe_read("/proc/1/environ")
    dmesg_out = ""
    if exists("dmesg"):
        try:
            dmesg_out = subprocess.run(
                ["dmesg"], capture_output=True, text=True, timeout=5
            ).stdout
        except Exception:
            pass

    sys_manu = sys_product = sys_ver = ""
    if exists("dmidecode"):
        def dmi(key: str) -> str:
            try:
                return subprocess.run(
                    ["dmidecode", "-s", key], capture_output=True, text=True, timeout=5
                ).stdout.strip()
            except Exception:
                return ""
        sys_manu = dmi("system-manufacturer")
        sys_product = dmi("system-product-name")
        sys_ver = dmi("system-version")

    if "docker" in cgroup:
        return "Docker"
    if "lxc" in cgroup or "container=lxc" in environ:
        return "LXC"
    if Path("/proc/user_beancounters").exists():
        return "OpenVZ"
    if "kvm-clock" in dmesg_out or "KVM" in sys_product or "KVM" in cname or "QEMU" in cname:
        return "KVM"
    if "VMware Virtual Platform" in dmesg_out or "VMware Virtual Platform" in sys_product:
        return "VMware"
    if "Parallels Software International" in dmesg_out:
        return "Parallels"
    if "VirtualBox" in dmesg_out:
        return "VirtualBox"
    if Path("/proc/xen").exists():
        caps = safe_read("/proc/xen/capabilities")
        return "Xen-Dom0" if "control_d" in caps else "Xen-DomU"
    if "xen" in safe_read("/sys/hypervisor/type"):
        return "Xen"
    if "Microsoft Corporation" in sys_manu:
        if "Virtual Machine" in sys_product and ("7.0" in sys_ver or "Hyper-V" in sys_ver):
            return "Hyper-V"
        return "Microsoft Virtual Machine"
    return "Dedicated"


def http_get(url: str, timeout: float = 10) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bench.py"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode(errors="ignore").strip()
    except Exception:
        return ""


def check_connectivity() -> tuple[bool, bool]:
    def ping_ok(host: str, family: str) -> bool:
        flag = "-4" if family == "4" else "-6"
        try:
            r = subprocess.run(
                ["ping", flag, "-c", "1", "-W", "4", host],
                capture_output=True, timeout=6,
            )
            return r.returncode == 0
        except Exception:
            return False

    ipv4 = ping_ok("ipv4.google.com", "4") or bool(http_get("https://ipinfo.io/org", 4))
    ipv6 = ping_ok("ipv6.google.com", "6")
    return ipv4, ipv6


def gather_system_info() -> SystemInfo:
    info = SystemInfo()
    cpu = read_cpuinfo()
    info.cname = cpu["model"]
    info.cores = cpu["cores"]
    info.freq = cpu["freq"]
    info.ccache = cpu["cache"]
    info.aes = cpu["aes"]
    info.virt_flags = cpu["virt"]

    info.total_ram, info.used_ram, info.total_swap, info.used_swap = read_meminfo()
    info.uptime = get_uptime()
    info.load = get_load_average()
    info.opsy = get_opsy()
    info.arch = os.uname().machine
    info.lbit = "64" if "64" in info.arch else "32"
    info.kern = os.uname().release
    info.disk_total, info.disk_used = get_disk_usage()

    try:
        out = subprocess.run(
            ["sysctl", "net.ipv4.tcp_congestion_control"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        info.tcpctrl = out.strip().split("=")[-1].strip()
    except Exception:
        pass

    info.virt = check_virt(info.cname)
    info.ipv4_online, info.ipv6_online = check_connectivity()
    return info


def print_system_info(info: SystemInfo) -> None:
    print(f" CPU Model          : {_c(BLUE, info.cname or 'CPU model not detected')}")
    if info.freq:
        print(f" CPU Cores          : {_c(BLUE, f'{info.cores} @ {info.freq} MHz')}")
    else:
        print(f" CPU Cores          : {_c(BLUE, str(info.cores))}")
    if info.ccache:
        print(f" CPU Cache          : {_c(BLUE, info.ccache)}")
    print(f" AES-NI             : "
          + (_c(GREEN, "\u2713 Enabled") if info.aes else _c(RED, "\u2717 Disabled")))
    print(f" VM-x/AMD-V         : "
          + (_c(GREEN, "\u2713 Enabled") if info.virt_flags else _c(RED, "\u2717 Disabled")))
    print(f" Total Disk         : {_c(YELLOW, calc_size(info.disk_total))} "
          f"{_c(BLUE, f'({calc_size(info.disk_used)} Used)')}")
    print(f" Total Mem          : {_c(YELLOW, calc_size(info.total_ram))} "
          f"{_c(BLUE, f'({calc_size(info.used_ram)} Used)')}")
    if info.total_swap:
        print(f" Total Swap         : {_c(BLUE, f'{calc_size(info.total_swap)} ({calc_size(info.used_swap)} Used)')}")
    print(f" System uptime      : {_c(BLUE, info.uptime)}")
    print(f" Load average       : {_c(BLUE, info.load)}")
    print(f" OS                 : {_c(BLUE, info.opsy)}")
    print(f" Arch               : {_c(BLUE, f'{info.arch} ({info.lbit} Bit)')}")
    print(f" Kernel             : {_c(BLUE, info.kern)}")
    if info.tcpctrl:
        print(f" TCP CC             : {_c(YELLOW, info.tcpctrl)}")
    print(f" Virtualization     : {_c(BLUE, info.virt)}")
    online4 = _c(GREEN, "\u2713 Online") if info.ipv4_online else _c(RED, "\u2717 Offline")
    online6 = _c(GREEN, "\u2713 Online") if info.ipv6_online else _c(RED, "\u2717 Offline")
    print(f" IPv4/IPv6          : {online4} / {online6}")


def print_ipv4_info() -> None:
    org = http_get("https://ipinfo.io/org")
    city = http_get("https://ipinfo.io/city")
    country = http_get("https://ipinfo.io/country")
    region = http_get("https://ipinfo.io/region")
    if org:
        print(f" Organization       : {_c(BLUE, org)}")
    if city and country:
        print(f" Location           : {_c(BLUE, f'{city} / {country}')}")
    if region:
        print(f" Region             : {_c(YELLOW, region)}")
    if not org:
        print(f" Region             : {_c(RED, 'No ISP detected')}")


# --------------------------------------------------------------------------- #
# Тест дисковой I/O
# --------------------------------------------------------------------------- #

def io_test(write_mb: int = 2048) -> Optional[float]:
    """Возвращает скорость записи в МБ/с (последовательная запись + fsync)."""
    path = Path(tempfile.gettempdir()) / f"benchtest_{os.getpid()}_{time.time_ns()}"
    block = b"\0" * (512 * 1024)
    blocks = write_mb * 2  # 512 KiB блоки
    try:
        start = time.monotonic()
        with open(path, "wb") as f:
            for _ in range(blocks):
                f.write(block)
            f.flush()
            os.fsync(f.fileno())
        elapsed = time.monotonic() - start
    except OSError:
        return None
    finally:
        path.unlink(missing_ok=True)
    if elapsed <= 0:
        return None
    return write_mb / elapsed


def print_io_test() -> None:
    free_mb = shutil.disk_usage(".").free // (1024 * 1024)
    if free_mb <= 1024:
        print(f" {_c(RED, 'Not enough space for I/O Speed test!')}")
        return
    speeds = []
    for i in range(1, 4):
        speed = io_test(2048)
        speeds.append(speed or 0.0)
        label = f" I/O Speed({['1st', '2nd', '3rd'][i - 1]} run) : "
        print(f"{label}{_c(YELLOW, f'{speed:.1f} MB/s' if speed else 'N/A')}")
    avg = sum(speeds) / len(speeds) if speeds else 0
    print(f" I/O Speed(average) : {_c(YELLOW, f'{avg:.1f} MB/s')}")


# --------------------------------------------------------------------------- #
# iperf3: установка и тест скорости
# --------------------------------------------------------------------------- #

PKG_MANAGERS = [
    ("apt-get", ["apt-get", "update", "-qq"], ["apt-get", "install", "-y", "-qq", "iperf3"]),
    ("yum", None, ["yum", "install", "-y", "-q", "iperf3"]),
    ("dnf", None, ["dnf", "install", "-y", "-q", "iperf3"]),
    ("pacman", None, ["pacman", "-S", "--noconfirm", "--quiet", "iperf3"]),
    ("apk", None, ["apk", "add", "--quiet", "iperf3"]),
]

STATIC_IPERF3_URLS = {
    "x86_64": "https://github.com/userdocs/iperf3-static/releases/latest/download/iperf3-amd64",
    "aarch64": "https://github.com/userdocs/iperf3-static/releases/latest/download/iperf3-arm64",
    "arm64": "https://github.com/userdocs/iperf3-static/releases/latest/download/iperf3-arm64",
}


def install_iperf3() -> bool:
    if exists("iperf3"):
        return True
    print(" iperf3 not found, trying to install...")
    for mgr, update_cmd, install_cmd in PKG_MANAGERS:
        if not exists(mgr):
            continue
        try:
            if update_cmd:
                subprocess.run(update_cmd, capture_output=True, timeout=120)
            subprocess.run(install_cmd, capture_output=True, timeout=180)
        except Exception:
            pass
        if exists("iperf3"):
            return True
        break  # нашли менеджер, но не вышло — статический бинарь как фоллбек

    if exists("iperf3"):
        return True

    print(" Trying to install static binary...")
    arch = os.uname().machine
    url = STATIC_IPERF3_URLS.get(arch)
    if not url:
        print(" Failed to install iperf3. Skipping speed tests...")
        return False
    dest = Path("/tmp/iperf3")
    try:
        urllib.request.urlretrieve(url, dest)
        dest.chmod(0o755)
        subprocess.run([str(dest), "--version"], capture_output=True, timeout=10, check=True)
    except Exception:
        print(" Failed to install iperf3. Skipping speed tests...")
        return False

    target = Path("/usr/local/bin/iperf3")
    try:
        shutil.move(str(dest), str(target))
        os.environ["PATH"] = f".:{os.environ.get('PATH', '')}"
    except OSError:
        local = Path("./iperf3")
        shutil.move(str(dest), str(local))
        local.chmod(0o755)
        os.environ["PATH"] = f".:{os.environ.get('PATH', '')}"
    return exists("iperf3") or Path("./iperf3").exists()


@dataclass
class ServerEntry:
    host: str
    port: str
    name: str


SERVERS: list[ServerEntry] = [
    # ===================== Russia =====================
    ServerEntry("spd-rudp.hostkey.ru", "5201", "Moscow, Hostkey"),
    ServerEntry("mskst.st.mtsws.net", "3333", "Moscow, MTS"),
    ServerEntry("st.spb.ertelecom.ru", "5201", "SPB, Er-com (5201)"),
    ServerEntry("st.spb.ertelecom.ru", "5203", "SPB, Er-com (5203)"),
    ServerEntry("st.bryansk.ertelecom.ru", "5201", "Bryansk, Er-com"),
    ServerEntry("speedtest-kaliningrad-01.corbina.net", "5201", "Kaliningrad"),
    ServerEntry("st.ekat.ertelecom.ru", "5201", "Yekaterinburg, Er-com"),
    ServerEntry("st.chel.ertelecom.ru", "5201", "Chelyabinsk (5201)"),
    ServerEntry("st.chel.ertelecom.ru", "5203", "Chelyabinsk (5203)"),
    ServerEntry("st.omsk.ertelecom.ru", "5203", "Omsk"),
    ServerEntry("st.nn.ertelecom.ru", "5201", "N.Novgorod (5201)"),
    ServerEntry("st.nn.ertelecom.ru", "5203", "N.Novgorod (5203)"),
    ServerEntry("st.kzn.ertelecom.ru", "5201", "Kazan (5201)"),
    ServerEntry("st.kzn.ertelecom.ru", "5203", "Kazan (5203)"),
    ServerEntry("st.samara.ertelecom.ru", "5201", "Samara (5201)"),
    ServerEntry("st.samara.ertelecom.ru", "5203", "Samara (5203)"),
    ServerEntry("st.rostov.ertelecom.ru", "5201", "Rostov-on-Don (5201)"),
    ServerEntry("st.rostov.ertelecom.ru", "5203", "Rostov-on-Don (5203)"),
    ServerEntry("st.volgograd.ertelecom.ru", "5201", "Volgograd (5201)"),
    ServerEntry("st.volgograd.ertelecom.ru", "5203", "Volgograd (5203)"),
    ServerEntry("voronezh-speedtest.corbina.net", "5201", "Voronezh, Beeline (5201)"),
    ServerEntry("voronezh-speedtest.corbina.net", "5203", "Voronezh, Beeline (5203)"),
    ServerEntry("st.irkutsk.ertelecom.ru", "5201", "Irkutsk, Er-com (5201)"),
    ServerEntry("st.irkutsk.ertelecom.ru", "5203", "Irkutsk, Er-com (5203)"),
    ServerEntry("st.krsk.ertelecom.ru", "5202", "Krasnoyarsk (5202)"),
    ServerEntry("st.krsk.ertelecom.ru", "5203", "Krasnoyarsk (5203)"),
    # Far East — отключено ещё в оригинале
    # ServerEntry("yktst.st.mtsws.net", "3333", "Yakutsk, MTS"),

    # ===================== Europe =====================
    ServerEntry("iperf-ams-nl.eranium.net", "5201", "NL Amsterdam"),
    ServerEntry("iperf3.moji.fr", "5200", "FR Paris"),
    ServerEntry("a208.speedtest.wobcom.de", "5201", "DE Dusseldorf"),
    ServerEntry("speedtest.fra1.de.leaseweb.net", "5201", "DE Frankfurt"),
    ServerEntry("spd-fisrv.hostkey.com", "5201", "FI Helsinki"),

    # ===================== North America =====================
    ServerEntry("speedtest.nyc1.us.leaseweb.net", "5201", "US New York"),

    # ===================== Asia-Pacific =====================
    ServerEntry("speedtest.sin1.sg.leaseweb.net", "5201", "SG Singapore"),
    ServerEntry("speedtest.tyo11.jp.leaseweb.net", "5201", "JP Tokyo"),
    ServerEntry("speedtest.hkg12.hk.leaseweb.net", "5201", "HK Hong Kong"),
    ServerEntry("49.205.75.2", "5001", "IN Mumbai"),

    # ===================== Premium DATAPACKET =====================
    ServerEntry("185.152.67.2", "5201", "US-LA Premium"),
    ServerEntry("185.59.223.8", "5201", "US-NY Premium"),
    ServerEntry("185.102.218.1", "5201", "NL-AMS Premium"),
    ServerEntry("185.102.219.93", "5201", "DE-FRA Premium"),
    ServerEntry("89.187.162.1", "5201", "SG-SIN Premium"),
    ServerEntry("89.187.160.1", "5201", "JP-TYO Premium"),
    ServerEntry("84.17.57.129", "5201", "HK-HKG Premium"),
]


_SPINNER_FRAMES = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"


class Spinner:
    """Простой спиннер в отдельном треде, аналог bash-функции spinner()."""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _run(self) -> None:
        i = 0
        hide_cursor()
        while not self._stop.is_set():
            frame = _SPINNER_FRAMES[i % len(_SPINNER_FRAMES)]
            sys.stdout.write(f"\033[1;33m{frame}\033[0m")
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write("\b")
            i += 1
        show_cursor()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()


def ping_latency(host: str) -> Optional[str]:
    try:
        r = subprocess.run(
            ["ping", "-c", "3", host], capture_output=True, text=True, timeout=8
        )
    except Exception:
        return None
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", r.stdout)
    return f"{float(m.group(1)):.2f} ms" if m else None


def ping_ok(host: str) -> bool:
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host], capture_output=True, timeout=4
        )
        return r.returncode == 0
    except Exception:
        return False


def run_iperf3(server: str, port: str, reverse: bool) -> Optional[float]:
    """Возвращает Mbit/s или None при ошибке. Парсит JSON-вывод iperf3 (-J)."""
    import json

    cmd = ["iperf3", "-c", server, "-p", port, "-t", "10", "-O", "3", "-J", "-P", str(THREADS)]
    if reverse:
        cmd.append("--reverse")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if r.returncode != 0 or not r.stdout.strip():
            return None
        data = json.loads(r.stdout)
    except Exception:
        return None

    try:
        end = data["end"]
        if reverse:
            # при --reverse отправитель — сервер, получатель (мы) — sum_received
            bits = end["sum_received"]["bits_per_second"]
        else:
            bits = end["sum_sent"]["bits_per_second"]
        return bits / 1_000_000
    except (KeyError, TypeError):
        return None


def speed_test_one(entry: ServerEntry) -> None:
    label = f" {entry.name}"
    sys.stdout.write(f"\033[0;33m{label:<18}\033[0m ")
    sys.stdout.flush()

    spinner = Spinner()
    spinner.start()

    if not ping_ok(entry.host):
        spinner.stop()
        return

    latency = ping_latency(entry.host)
    up_speed = run_iperf3(entry.host, entry.port, reverse=False)
    time.sleep(1)
    dl_speed = run_iperf3(entry.host, entry.port, reverse=True)

    spinner.stop()

    if not up_speed or not dl_speed:
        return

    name_field = f" {entry.name}"
    print(
        f"\033[0;33m{name_field:<17}\033[0;32m{up_speed:9.2f} {'Mbit/s':<8}"
        f"\033[0;31m{dl_speed:7.2f} {'Mbit/s':<8}\033[0;36m{latency or 'N/A':>13}\033[0m"
    )


def run_speed_tests() -> None:
    print(f"{' Node Name':<15}{'Upload Speed':>19}{'Download Speed':>18}{'Latency':>11}")
    for entry in SERVERS:
        speed_test_one(entry)


# --------------------------------------------------------------------------- #
# Статистика запусков
# --------------------------------------------------------------------------- #

def print_run_stats() -> None:
    if not _PING_RUN_STATS:
        print(" Run statistics     : skipped (_PING_RUN_STATS=False)")
        return
    raw = http_get("https://bench.tlab.pw/stats.json", timeout=10)
    today = re.search(r'"day"\s*:\s*(\d+)', raw)
    total = re.search(r'"total"\s*:\s*(\d+)', raw)
    if today and total:
        print(f" Run statistics     : Today:{today.group(1)} Total:{total.group(1)} "
              f"\033[3mThanks for using the script!\033[0m")
    else:
        print("Run statistics     : Unavailable")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def print_intro() -> None:
    os.system("clear" if os.name != "nt" else "cls")
    print("\033[36m\033[0m\033[37m------------------- A Bench.sh Script By Teddysun ---------------------\033[36m\033[0m")
    print(f"\033[36m\033[0m\033[37m                      {_c(CYAN, 'Modified by Nikola Tesla')} - https://t.me/tracerlab \033[36m\033[0m")
    print("\033[36m\033[0m\033[37m      Network         MERGED servers — tlab.pw + gig.ovh, all regions     \033[36m\033[0m")
    print(f"\033[36m\033[0m\033[37m   Bench Utility      {_c(GREEN, 'v2025-11-04-merged (python port)')}                              \033[36m\033[0m")
    print(f"\033[36m\033[0m\033[37m                      {_c(RED, 'wget -qO- bench.tlab.pw | bash')} <- Usage command \033[36m\033[0m")


def _cleanup_temp_files() -> None:
    """Подчищает временные файлы бенчмарка. Вызывается при Ctrl+C —
    НЕ завершает процесс (в отличие от оригинального cleanup_and_exit),
    т.к. это подменю внутри установщика, а не самостоятельный скрипт."""
    show_cursor()
    for p in Path(tempfile.gettempdir()).glob("benchtest_*"):
        p.unlink(missing_ok=True)


def check_dependencies() -> bool:
    missing = [c for c in ("ping",) if not exists(c)]
    if missing:
        print(_c(RED, f"Error: required command(s) not found: {', '.join(missing)}\n"))
        return False
    return True


def run_bench() -> bool:
    """Выполняет полный бенчмарк. Возвращает True при успешном завершении
    тестов скорости. НЕ устанавливает глобальные signal-хендлеры и НЕ
    вызывает sys.exit() — в оригинальном bench.py это убило бы весь процесс
    установщика при Ctrl+C, а не только этот пункт меню."""
    if not check_rate_limit():
        return False
    if not check_dependencies():
        return False

    start_time = time.time()
    try:
        info = gather_system_info()

        print_intro()
        next_line()
        print_system_info(info)
        print_ipv4_info()
        next_line()
        print_io_test()
        next_line()

        test_success = False
        if install_iperf3():
            run_speed_tests()
            test_success = True
        else:
            print(" Network speed tests skipped due to missing iperf3")

        next_line()
        elapsed = int(time.time() - start_time)
        if elapsed > 60:
            print(f" Finished in        : {elapsed // 60} min {elapsed % 60} sec")
        else:
            print(f" Finished in        : {elapsed} sec")
        print(f" Timestamp          : {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        print(f" Follow             : {_c(BLUE, 'https://t.me/tracerlab')}")
        print_run_stats()
        next_line()

        if test_success:
            mark_success()
        return test_success

    except KeyboardInterrupt:
        _cleanup_temp_files()
        print(_c(YELLOW, "\nБенчмарк прерван пользователем.\n"))
        return False


# --------------------------------------------------------------------------- #
# Точка входа из меню установщика (_core.py)
# --------------------------------------------------------------------------- #

def do_network_bench_menu() -> None:
    """Главное меню. Вызывается из _core.py."""
    os.system("clear")
    print()
    _box_top("🚀  БЕНЧМАРК СЕРВЕРА  (CPU / RAM / Диск / Сеть)")
    _box_desc(
        "Информация о системе, тест дисковой I/O и multi-thread тест скорости "
        "сети через iperf3 по серверам РФ, Европы, США и Азии."
    )
    _box_sep()
    _box_info("При первом запуске может поставить iperf3 (apt/yum/dnf/pacman/apk).")
    _box_warn("Не чаще одного раза в 5 минут. Полный прогон — до нескольких минут.")
    _box_sep()
    _box_item("1", "▶ Запустить бенчмарк")
    _box_back()
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор:{RESET} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return

    if ch != "1":
        return

    print()
    run_bench()
    print()
    input(f"{BLUE}Нажмите Enter...{RESET}")


if __name__ == "__main__":
    # Автономный запуск для отладки модуля (вне установщика).
    try:
        run_bench()
    except KeyboardInterrupt:
        _cleanup_temp_files()
        print(_c(YELLOW, "\nПрервано.\n"))

