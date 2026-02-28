#!/usr/bin/env bash
# Usage: install.sh --config <json-string-or-file-path>
#
# Offline installer for OpenCanary honeypot agent.
# Must run as root on Ubuntu 22.04+ or CentOS 7/8/9.
#
# Steps:
#   1. Verify root privileges
#   2. Detect OS (Ubuntu/Debian vs CentOS/RHEL)
#   3. Check Python version >= 3.8
#   4. Check required system packages, report missing with install commands
#   5. Create /opt/opencanary/venv via python3 -m venv
#   6. Install wheels from ./wheels/ via pip install --no-index --find-links
#   7. Install OpenCanary from ./opencanary-src/ into the venv
#   8. Write config to /etc/opencanaryd/opencanary.conf
#   9. Install opencanary.service to /etc/systemd/system/
#  10. systemctl daemon-reload && systemctl enable opencanary && systemctl start opencanary
#
# Exit codes:
#   0 - Success
#   1 - Not running as root
#   2 - Python version too old
#   3 - Missing system packages
#   4 - Venv creation failed
#   5 - Pip install failed
#   6 - OpenCanary install failed
#   7 - Config write failed
#   8 - Systemd setup failed

set -euo pipefail

VENV_PATH="/opt/opencanary/venv"
CONFIG_DEST="/etc/opencanaryd/opencanary.conf"
SERVICE_DEST="/etc/systemd/system/opencanary.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log_info() {
    echo "[INFO] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

# ---------------------------------------------------------------------------
# 1. Verify root privileges
# ---------------------------------------------------------------------------

if [[ "$(id -u)" -ne 0 ]]; then
    log_error "This script must be run as root."
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Detect OS (Ubuntu/Debian vs CentOS/RHEL)
# ---------------------------------------------------------------------------

OS_FAMILY="unknown"

if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
        ubuntu|debian)
            OS_FAMILY="debian"
            ;;
        centos|rhel|rocky|alma|fedora)
            OS_FAMILY="rhel"
            ;;
    esac
fi

if [[ "${OS_FAMILY}" == "unknown" ]]; then
    # Fallback heuristic
    if command -v apt-get &>/dev/null; then
        OS_FAMILY="debian"
    elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
        OS_FAMILY="rhel"
    fi
fi

if [[ "${OS_FAMILY}" == "unknown" ]]; then
    log_error "Unsupported OS. This script supports Ubuntu/Debian and CentOS/RHEL."
    exit 1
fi

log_info "Detected OS family: ${OS_FAMILY}"

# ---------------------------------------------------------------------------
# 3. Check Python version >= 3.8
# ---------------------------------------------------------------------------

if ! command -v python3 &>/dev/null; then
    log_error "python3 is not installed."
    exit 2
fi

PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PYTHON_MAJOR="$(echo "${PYTHON_VERSION}" | cut -d. -f1)"
PYTHON_MINOR="$(echo "${PYTHON_VERSION}" | cut -d. -f2)"

if [[ "${PYTHON_MAJOR}" -lt 3 ]] || { [[ "${PYTHON_MAJOR}" -eq 3 ]] && [[ "${PYTHON_MINOR}" -lt 8 ]]; }; then
    log_error "Python ${PYTHON_VERSION} is too old. Python 3.8 or higher is required."
    if [[ "${OS_FAMILY}" == "rhel" ]]; then
        log_error "CentOS 7 ships with Python 3.6 by default. Please install Python 3.8+ from the SCL or EPEL repository, or upgrade to CentOS 8/9."
    fi
    exit 2
fi

log_info "Python version: ${PYTHON_VERSION}"

# ---------------------------------------------------------------------------
# 4. Check required system packages
# ---------------------------------------------------------------------------

MISSING_REQUIRED=()
MISSING_OPTIONAL=()

if [[ "${OS_FAMILY}" == "debian" ]]; then
    # Only python3 is truly required. python3-venv is preferred but we can
    # fall back to a manual virtualenv using get-pip.py if it's missing.
    REQUIRED_PKGS=("python3")
    OPTIONAL_PKGS=("python3-venv" "python3-pip" "python3-dev" "libffi-dev" "libssl-dev" "build-essential")

    for pkg in "${REQUIRED_PKGS[@]}"; do
        if ! dpkg -s "${pkg}" &>/dev/null; then
            MISSING_REQUIRED+=("${pkg}")
        fi
    done
    for pkg in "${OPTIONAL_PKGS[@]}"; do
        if ! dpkg -s "${pkg}" &>/dev/null; then
            MISSING_OPTIONAL+=("${pkg}")
        fi
    done

    if [[ ${#MISSING_REQUIRED[@]} -gt 0 ]]; then
        log_error "Missing required system packages: ${MISSING_REQUIRED[*]}"
        log_error "Install them with:"
        log_error "  sudo apt-get update && sudo apt-get install -y ${MISSING_REQUIRED[*]}"
        exit 3
    fi
    if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
        log_info "Optional packages not installed (not needed for pre-built wheels): ${MISSING_OPTIONAL[*]}"
    fi
else
    # RHEL/CentOS family — only python3 is truly required
    REQUIRED_PKGS=("python3")
    OPTIONAL_PKGS=("python3-libs" "python3-pip" "python3-devel" "libffi-devel" "openssl-devel" "gcc")

    for pkg in "${REQUIRED_PKGS[@]}"; do
        if ! rpm -q "${pkg}" &>/dev/null; then
            MISSING_REQUIRED+=("${pkg}")
        fi
    done
    for pkg in "${OPTIONAL_PKGS[@]}"; do
        if ! rpm -q "${pkg}" &>/dev/null; then
            MISSING_OPTIONAL+=("${pkg}")
        fi
    done

    if [[ ${#MISSING_REQUIRED[@]} -gt 0 ]]; then
        log_error "Missing required system packages: ${MISSING_REQUIRED[*]}"
        PKG_MGR="yum"
        if command -v dnf &>/dev/null; then
            PKG_MGR="dnf"
        fi
        log_error "Install them with:"
        log_error "  sudo ${PKG_MGR} install -y ${MISSING_REQUIRED[*]}"
        exit 3
    fi
    if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
        log_info "Optional packages not installed (not needed for pre-built wheels): ${MISSING_OPTIONAL[*]}"
    fi
fi

log_info "All required system packages are installed."

# ---------------------------------------------------------------------------
# 5. Create virtual environment at /opt/opencanary/venv
# ---------------------------------------------------------------------------

WHEELS_DIR="${SCRIPT_DIR}/wheels"
if [[ ! -d "${WHEELS_DIR}" ]]; then
    log_error "Wheels directory not found: ${WHEELS_DIR}"
    exit 5
fi

log_info "Creating virtual environment at ${VENV_PATH}..."
# Clean up any previous installation to avoid stale wrappers/patches
rm -rf "${VENV_PATH}"
mkdir -p "$(dirname "${VENV_PATH}")"

VENV_CREATED=false

# Method 1: Try python3 -m venv (works if python3-venv is installed)
if python3 -m venv "${VENV_PATH}" 2>/dev/null; then
    VENV_CREATED=true
    log_info "Virtual environment created via python3 -m venv."
fi

# Method 2: Manual venv + get-pip.py (no python3-venv needed)
if [[ "${VENV_CREATED}" == "false" ]]; then
    log_info "python3-venv not available, creating virtual environment manually..."

    # Clean up any partial venv left by the failed attempt
    rm -rf "${VENV_PATH}"

    PYTHON3_PATH="$(command -v python3)"
    PYTHON_VERSION_FULL="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"

    # Create the directory structure that a venv normally creates
    mkdir -p "${VENV_PATH}/bin"
    mkdir -p "${VENV_PATH}/lib/python${PYTHON_VERSION_FULL}/site-packages"
    mkdir -p "${VENV_PATH}/include"

    # Create the pyvenv.cfg file
    cat > "${VENV_PATH}/pyvenv.cfg" <<PYVENV_EOF
home = $(dirname "${PYTHON3_PATH}")
include-system-site-packages = false
version = ${PYTHON_VERSION_FULL}
PYVENV_EOF

    # COPY the python binary instead of symlinking.  When Python is a
    # symlink it resolves to the real path and can't find pyvenv.cfg,
    # which means site-packages never gets added to sys.path.  A copy
    # keeps the binary in the venv directory so pyvenv.cfg discovery works.
    # Use -L to dereference symlinks (on Ubuntu, python3 -> python3.12).
    cp -L "${PYTHON3_PATH}" "${VENV_PATH}/bin/python3"
    ln -sf "${VENV_PATH}/bin/python3" "${VENV_PATH}/bin/python"

    # Bootstrap pip using bundled get-pip.py
    GET_PIP="${SCRIPT_DIR}/get-pip.py"
    if [[ ! -f "${GET_PIP}" ]]; then
        log_error "get-pip.py not found in bundle and python3-venv is not installed."
        log_error "Either install python3-venv or rebuild the bundle with internet access."
        exit 4
    fi

    log_info "Bootstrapping pip via get-pip.py..."
    # get-pip.py bundles pip internally, so --no-index is safe even without
    # a pip wheel in the wheels dir.  We MUST use --no-index because the
    # target machine is air-gapped.
    if ! "${VENV_PATH}/bin/python3" "${GET_PIP}" --no-index --find-links "${WHEELS_DIR}" 2>/dev/null; then
        # Retry without --find-links — get-pip.py can self-extract its bundled pip
        if ! "${VENV_PATH}/bin/python3" "${GET_PIP}" --no-index 2>/dev/null; then
            # Last resort: the embedded pip in get-pip.py may be too old for --no-index
            # Try with PIP_NO_INDEX env var instead
            if ! PIP_NO_INDEX=1 "${VENV_PATH}/bin/python3" "${GET_PIP}"; then
                log_error "Failed to bootstrap pip in the virtual environment."
                exit 4
            fi
        fi
    fi

    VENV_CREATED=true
    log_info "Virtual environment created manually with get-pip.py."
fi

if [[ "${VENV_CREATED}" == "false" ]]; then
    log_error "Failed to create virtual environment at ${VENV_PATH}."
    exit 4
fi

log_info "Virtual environment ready."

# ---------------------------------------------------------------------------
# 6. Install wheels from ./wheels/ via pip
# ---------------------------------------------------------------------------

log_info "Installing Python wheel dependencies from ${WHEELS_DIR}..."
# Use --find-links so pip selects only compatible wheels for this platform/Python.
# Do NOT glob *.whl directly — the bundle contains wheels for multiple Python versions.
if ! "${VENV_PATH}/bin/pip" install --no-index --find-links "${WHEELS_DIR}" \
    Twisted pyasn1 cryptography simplejson requests zope.interface \
    PyPDF2 fpdf passlib Jinja2 ntlmlib bcrypt 'setuptools<81' urllib3 \
    hpfeeds pyOpenSSL service-identity; then
    log_error "Failed to install wheel dependencies."
    exit 5
fi

log_info "Wheel dependencies installed."

# ---------------------------------------------------------------------------
# 7. Install OpenCanary from ./opencanary-src/
# ---------------------------------------------------------------------------

OPENCANARY_SRC="${SCRIPT_DIR}/opencanary-src"
if [[ ! -d "${OPENCANARY_SRC}" ]]; then
    log_error "OpenCanary source directory not found: ${OPENCANARY_SRC}"
    exit 6
fi

log_info "Installing OpenCanary from ${OPENCANARY_SRC}..."
# Use --no-deps because all dependencies were already installed in step 6.
# This avoids version-pinning conflicts (e.g. setup.py pins Twisted==24.11.0
# but the bundle ships a newer version).
if ! "${VENV_PATH}/bin/pip" install --no-index --no-deps --find-links "${WHEELS_DIR}" "${OPENCANARY_SRC}"; then
    log_error "Failed to install OpenCanary from source."
    exit 6
fi

log_info "OpenCanary installed."

# Verify the venv can import pkg_resources (needed by opencanary.tac)
if ! "${VENV_PATH}/bin/python3" -c "import pkg_resources; print('pkg_resources OK')"; then
    log_error "pkg_resources not importable — setuptools may be too new (v82+ removed it)."
    log_error "Attempting to fix by installing setuptools<81..."
    if ! "${VENV_PATH}/bin/pip" install --no-index --find-links "${WHEELS_DIR}" 'setuptools<81'; then
        log_error "No compatible setuptools wheel found in bundle. Rebuild the bundle."
        exit 6
    fi
fi
log_info "Venv verification passed (pkg_resources importable)."

# ---------------------------------------------------------------------------
# 8. Write configuration file
# ---------------------------------------------------------------------------

CONFIG_ARG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            CONFIG_ARG="$2"
            shift 2
            ;;
        *)
            log_error "Unknown argument: $1"
            exit 7
            ;;
    esac
done

if [[ -z "${CONFIG_ARG}" ]]; then
    # Check for a config file alongside the script
    if [[ -f "${SCRIPT_DIR}/opencanary.conf" ]]; then
        CONFIG_ARG="${SCRIPT_DIR}/opencanary.conf"
    else
        log_error "No configuration provided. Use --config <json-string-or-file-path> or place opencanary.conf alongside the bundle."
        exit 7
    fi
fi

log_info "Writing configuration to ${CONFIG_DEST}..."
mkdir -p "$(dirname "${CONFIG_DEST}")"

if [[ -f "${CONFIG_ARG}" ]]; then
    # Config argument is a file path
    if ! cp "${CONFIG_ARG}" "${CONFIG_DEST}"; then
        log_error "Failed to write configuration file to ${CONFIG_DEST}."
        exit 7
    fi
else
    # Config argument is a JSON string
    if ! echo "${CONFIG_ARG}" > "${CONFIG_DEST}"; then
        log_error "Failed to write configuration file to ${CONFIG_DEST}."
        exit 7
    fi
fi

log_info "Configuration written to ${CONFIG_DEST}."

# ---------------------------------------------------------------------------
# 8b. Let the user review / edit the configuration before starting
# ---------------------------------------------------------------------------

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  OpenCanary Configuration                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
cat "${CONFIG_DEST}"
echo ""
echo "────────────────────────────────────────────────────────────────"
echo ""
echo "  Review the config above. You may want to disable services"
echo "  that conflict with existing ones (e.g. ssh.enabled: false"
echo "  if SSH is already running on port 22)."
echo ""
echo "  [Enter]  Keep this config and start the service"
echo "  [e]      Open in a text editor (nano or vi)"
echo "  [p]      Paste a replacement config"
echo "           (paste your JSON, then type EOF on its own line)"
echo ""
read -r -p "  Your choice [Enter/e/p]: " CONFIG_CHOICE

case "${CONFIG_CHOICE}" in
    e|E)
        EDITOR_CMD="nano"
        if ! command -v nano &>/dev/null; then
            EDITOR_CMD="vi"
        fi
        "${EDITOR_CMD}" "${CONFIG_DEST}"
        log_info "Configuration updated."
        ;;
    p|P)
        echo ""
        echo "  Paste your JSON config below."
        echo "  When done, type EOF on its own line and press Enter."
        echo ""
        CONFIG_PASTE=""
        while IFS= read -r line; do
            [[ "${line}" == "EOF" ]] && break
            CONFIG_PASTE="${CONFIG_PASTE}${line}
"
        done
        if [[ -n "${CONFIG_PASTE}" ]]; then
            echo "${CONFIG_PASTE}" > "${CONFIG_DEST}"
            log_info "Configuration replaced."
        else
            log_info "Empty input — keeping existing config."
        fi
        ;;
    *)
        log_info "Keeping current configuration."
        ;;
esac

# ---------------------------------------------------------------------------
# 9. Install systemd service and start OpenCanary
# ---------------------------------------------------------------------------

SERVICE_SRC="${SCRIPT_DIR}/opencanary.service"
if [[ ! -f "${SERVICE_SRC}" ]]; then
    log_error "Systemd service unit file not found: ${SERVICE_SRC}"
    exit 8
fi

log_info "Installing systemd service unit..."

# Replace the placeholder paths in the service file with actual paths
SITE_PKG_DIR="${VENV_PATH}/lib/python${PYTHON_VERSION}/site-packages"
sed -e "s|<VIRTUAL_ENV_PATH>|${VENV_PATH}|g" \
    -e "s|<SITE_PACKAGES_PATH>|${SITE_PKG_DIR}|g" \
    "${SERVICE_SRC}" > "${SERVICE_DEST}"

if [[ ! -f "${SERVICE_DEST}" ]]; then
    log_error "Failed to install systemd service unit to ${SERVICE_DEST}."
    exit 8
fi

log_info "Reloading systemd and enabling opencanary service..."
if ! systemctl daemon-reload; then
    log_error "Failed to reload systemd daemon."
    exit 8
fi

if ! systemctl enable opencanary; then
    log_error "Failed to enable opencanary service."
    exit 8
fi

if ! systemctl start opencanary; then
    log_error "Failed to start opencanary service."
    exit 8
fi

log_info "OpenCanary service is enabled and running."
log_info "Installation complete!"
