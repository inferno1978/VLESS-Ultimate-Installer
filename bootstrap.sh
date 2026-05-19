#!/usr/bin/env bash
# ============================================================
#  VLESS Ultimate Installer v4.10 — Bootstrap
#  bash <(curl -fsSL https://raw.githubusercontent.com/inferno1978/VLESS-Ultimate/master/bootstrap.sh)
# ============================================================
set -euo pipefail

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
   Ultimate Installer v4.10
BANNER
echo -e "${NC}"

# [1] Root check
echo -e "${BOLD}[1/5] Проверка прав${NC}"
if [[ $EUID -ne 0 ]]; then
    err "Требуются права root"
    echo -e "     ${YELLOW}sudo bash <(curl -fsSL https://raw.githubusercontent.com/inferno1978/VLESS-Ultimate/master/bootstrap.sh)${NC}"
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

# [4] Загрузка
echo -e "\n${BOLD}[4/5] Загрузка VLESS Ultimate${NC}"
INSTALL_DIR="/opt/vless-ultimate"
REPO_URL="https://github.com/inferno1978/VLESS-Ultimate-Installer"

if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Обновление существующей установки..."
    cd "$INSTALL_DIR"
    git pull --quiet origin main 2>/dev/null && ok "Обновлено" || warn "Не удалось обновить — используем текущую версию"
else
    info "Клонирование репозитория..."
    if ! git clone --quiet --depth 1 "$REPO_URL" "$INSTALL_DIR" 2>/dev/null; then
        warn "git clone не удался — загружаю архив..."
        mkdir -p "$INSTALL_DIR"
        ARCHIVE="${REPO_URL}/archive/refs/heads/master.tar.gz"
        ARCHIVE_TMP="/tmp/vless.tar.gz"
        EXPECTED_SHA256="PLACEHOLDER_SHA256_UPDATE_BEFORE_RELEASE"

        curl -fsSL --connect-timeout 30 --retry 3 -o "$ARCHIVE_TMP" "$ARCHIVE" || {
            err "Не удалось загрузить архив. Проверьте соединение."
            exit 1
        }

        # SHA256-проверка целостности архива
        if [[ "$EXPECTED_SHA256" != "PLACEHOLDER_SHA256_UPDATE_BEFORE_RELEASE" ]]; then
            info "Проверка SHA256..."
            ACTUAL_SHA256=$(sha256sum "$ARCHIVE_TMP" | awk '{print $1}')
            if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
                err "SHA256 не совпадает!"
                err "  Ожидалось: ${EXPECTED_SHA256}"
                err "  Получено:  ${ACTUAL_SHA256}"
                rm -f "$ARCHIVE_TMP"
                exit 1
            fi
            ok "SHA256 OK: ${ACTUAL_SHA256:0:16}..."
        else
            warn "SHA256-проверка пропущена (PLACEHOLDER не заменён)"
        fi

        tar -xzf "$ARCHIVE_TMP" -C /tmp/
        cp -r /tmp/VLESS-Ultimate-master/. "$INSTALL_DIR/"
        rm -rf /tmp/VLESS-Ultimate-master "$ARCHIVE_TMP"
    fi
    ok "Загружено в ${INSTALL_DIR}"
fi

[[ -f "${INSTALL_DIR}/main.py" ]] || { err "main.py не найден"; exit 1; }

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
