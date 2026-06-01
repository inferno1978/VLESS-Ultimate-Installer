#!/usr/bin/env bash
# ============================================================
#  VLESS Ultimate Installer v4.11.5 — Bootstrap
#  bash <(curl -fsSL https://raw.githubusercontent.com/inferno1978/VLESS-Ultimate-Installer/main/bootstrap.sh)
# ============================================================
set -euo pipefail

# Сброс системного прокси перед загрузкой — защита от сломанных окружений,
# когда в /etc/environment прописан прокси на несуществующий локальный порт.
unset ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy 2>/dev/null || true

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
err()  { echo -e "  ${RED}✗${NC} $*" >&2; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
info() { echo -e "  ${CYAN}→${NC} $*"; }

echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
 ██╗   ██╗██╗     ███████╗███████╗███████╗
 ██║   ██║██║     ██╔════╝██╔════╝██╔════╝
 ██║   ██║██║     █████╗  ███████╗███████╗
 ╚██╗ ██╔╝██║     ██╔══╝  ╚════██║╚════██║
  ╚████╔╝ ███████╗███████╗███████║███████║
   ╚═══╝  ╚══════╝╚══════╝╚══════╝╚══════╝
   Ultimate Installer v4.11.5
BANNER
echo -e "${NC}"

# [1] Root check
echo -e "${BOLD}[1/5] Проверка прав${NC}"
if [[ $EUID -ne 0 ]]; then
    err "Требуются права root"
    echo -e "     ${YELLOW}sudo bash <(curl -fsSL https://raw.githubusercontent.com/inferno1978/VLESS-Ultimate-Installer/main/bootstrap.sh)${NC}"
    exit 1
fi
ok "root: OK"

# [2] Определение пакетного менеджера
echo -e "\n${BOLD}[2/5] Система${NC}"
if   command -v apt-get &>/dev/null; then PKG_INSTALL="apt-get install -y -q"
elif command -v dnf     &>/dev/null; then PKG_INSTALL="dnf install -y -q"
elif command -v yum     &>/dev/null; then PKG_INSTALL="yum install -y -q"
else err "Не найден поддерживаемый пакетный менеджер"; exit 1; fi
OS_ID=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "unknown")
OS_VER=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "?")
ok "ОС: ${OS_ID} ${OS_VER}"

# [3] Минимальные зависимости
echo -e "\n${BOLD}[3/5] Зависимости${NC}"
MISSING=()
command -v python3 &>/dev/null || MISSING+=("python3")
command -v curl    &>/dev/null || MISSING+=("curl")
command -v git     &>/dev/null || MISSING+=("git")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Устанавливаю: ${MISSING[*]}"
    if command -v apt-get &>/dev/null; then apt-get update -qq; fi
    for pkg in "${MISSING[@]}"; do
        $PKG_INSTALL "$pkg" || { err "Не удалось установить ${pkg}"; exit 1; }
    done
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MIN_OK=$(python3 -c "import sys; print(int(sys.version_info >= (3,10)))")
if [[ "$PY_MIN_OK" != "1" ]]; then
    err "Требуется Python >= 3.10, найден ${PY_VER}"
    exit 1
fi
ok "Python ${PY_VER}: OK"

# [4] Загрузка / обновление
echo -e "\n${BOLD}[4/5] Загрузка VLESS Ultimate${NC}"
INSTALL_DIR="/opt/vless-ultimate"
REPO_URL="https://github.com/inferno1978/VLESS-Ultimate-Installer"
BRANCH="main"

# Ищем существующую установку в нестандартных местах
_found=""
for _candidate in \
    "/home/inferno1978/VLESS-Ultimate-Installer" \
    "/root/VLESS-Ultimate-Installer" \
    "/opt/VLESS-Ultimate-Installer"
do
    if [[ -f "${_candidate}/main.py" ]]; then
        _found="$_candidate"
        break
    fi
done
# Также ищем через glob в /home/*/
if [[ -z "$_found" ]]; then
    for _p in /home/*/VLESS-Ultimate-Installer/main.py; do
        [[ -f "$_p" ]] && { _found="${_p%/main.py}"; break; }
    done
fi
if [[ -n "$_found" && "$_found" != "$INSTALL_DIR" ]]; then
    warn "Найдена существующая установка: ${_found}"
    info "Обновляю её (а не ${INSTALL_DIR})..."
    INSTALL_DIR="$_found"
fi

if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Обновление существующей git-установки..."
    cd "$INSTALL_DIR"
    git pull --quiet origin "$BRANCH" 2>/dev/null \
        && ok "Обновлено до последней версии" \
        || warn "Не удалось обновить через git — принудительно обновляю файлы..."
    # Принудительно обновляем ключевые модули напрямую с GitHub
    _update_module() {
        local rel_path="$1"
        local url="https://raw.githubusercontent.com/inferno1978/VLESS-Ultimate-Installer/${BRANCH}/${rel_path}"
        curl -fsSL --connect-timeout 15 -o "${INSTALL_DIR}/${rel_path}" "$url" 2>/dev/null \
            && info "Обновлён: ${rel_path}" \
            || warn "Не удалось обновить: ${rel_path}"
    }
    _update_module "vless_installer/modules/tg_nets.py"
else
    if [[ -d "$INSTALL_DIR" ]] && [[ -f "${INSTALL_DIR}/main.py" ]]; then
        # Установка без .git — принудительно обновляем все файлы с GitHub
        info "Установка без git обнаружена — принудительное обновление файлов..."
        ARCHIVE="${REPO_URL}/archive/refs/heads/${BRANCH}.tar.gz"
        ARCHIVE_TMP="/tmp/vless_ultimate_update.tar.gz"
        ARCHIVE_DIR="VLESS-Ultimate-Installer-${BRANCH}"
        curl -fsSL --connect-timeout 30 --retry 3 -o "$ARCHIVE_TMP" "$ARCHIVE" && {
            tar -xzf "$ARCHIVE_TMP" -C /tmp/
            cp -rf "/tmp/${ARCHIVE_DIR}/." "$INSTALL_DIR/"
            rm -rf "/tmp/${ARCHIVE_DIR}" "$ARCHIVE_TMP"
            ok "Файлы обновлены до последней версии"
        } || warn "Не удалось обновить — используем текущую версию"
    else
        info "Клонирование репозитория..."
        if ! git clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>/dev/null; then
            warn "git clone не удался — загружаю архив..."
            mkdir -p "$INSTALL_DIR"
            ARCHIVE="${REPO_URL}/archive/refs/heads/${BRANCH}.tar.gz"
            ARCHIVE_TMP="/tmp/vless_ultimate.tar.gz"
            ARCHIVE_DIR="VLESS-Ultimate-Installer-${BRANCH}"
            curl -fsSL --connect-timeout 30 --retry 3 -o "$ARCHIVE_TMP" "$ARCHIVE" || {
                err "Не удалось загрузить архив. Проверьте соединение."
                exit 1
            }
            tar -xzf "$ARCHIVE_TMP" -C /tmp/
            cp -r "/tmp/${ARCHIVE_DIR}/." "$INSTALL_DIR/"
            rm -rf "/tmp/${ARCHIVE_DIR}" "$ARCHIVE_TMP"
        fi
        ok "Загружено в ${INSTALL_DIR}"
    fi
fi

[[ -f "${INSTALL_DIR}/main.py" ]] || { err "main.py не найден в ${INSTALL_DIR}"; exit 1; }

# [5] Запуск
echo -e "\n${BOLD}[5/5] Запуск${NC}"
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  Запускаю установщик...${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${DIM}Директория: ${INSTALL_DIR}${NC}"
echo -e "  ${DIM}Лог: /var/log/vless-install.log${NC}"
echo ""
cd "$INSTALL_DIR"
exec python3 main.py "$@"
