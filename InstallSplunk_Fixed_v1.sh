#!/usr/bin/env bash
set -euo pipefail

############################################
# Splunk Lab Installer (Ubuntu/Debian)
#
# Behavior:
# - Requires root (students run: sudo ./InstallSplunk.sh)
# - Blocks ARM
# - Warns if <40GB free on filesystem backing /opt
# - Installs Splunk 10.2.0 if missing (Deb package)
# - Runs Splunk as user: splunk (creates if missing)
# - Seeds admin/admin on first install (relaxes password policy for lab)
# - Downloads and ingests pokemon.csv once (index=main, sourcetype=pokedex)
# - Prints URL + creds with clean newline at end
############################################

# ---------- Config ----------
SPLUNK_USER="splunk"

SPLUNK_DEB="splunk-10.2.0-d749cb17ea65-linux-amd64.deb"
SPLUNK_URL="https://download.splunk.com/products/splunk/releases/10.2.0/linux/${SPLUNK_DEB}"
SPLUNK_DEB_PATH="/tmp/${SPLUNK_DEB}"

SPLUNK_HOME="/opt/splunk"
SPLUNK_BIN="${SPLUNK_HOME}/bin/splunk"
SPLUNK_PASSWD_FILE="${SPLUNK_HOME}/etc/passwd"

ADMIN_USER="admin"
ADMIN_PASS="admin"

POKE_URL="https://raw.githubusercontent.com/FullstackAcademy/FullstackCyberResource/refs/heads/main/pokemon.csv"
DATA_DIR="/tmp/splunk_lab_data"
POKE_FILE="${DATA_DIR}/pokemon.csv"
INGEST_MARKER="/var/tmp/.splunk_pokedex_ingested"

# ---------- Color ----------
if [[ -t 1 ]]; then
  RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"
  CYAN="$(tput setaf 6)"; BOLD="$(tput bold)"; RESET="$(tput sgr0)"
else
  RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""; RESET=""
fi

info() { echo -e "${CYAN}${BOLD}$*${RESET}"; }
ok()   { echo -e "${GREEN}OK${RESET} - $*"; }
warn() { echo -e "${YELLOW}WARN${RESET} - $*"; }
die()  { echo -e "${RED}ERROR${RESET} - $*" >&2; exit 1; }

# ---------- Core checks ----------
require_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root. Example: sudo ./InstallSplunk.sh"
}

block_arm() {
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) : ;;
    aarch64|arm64|armv7l|armv6l) die "ARM detected (${arch}). This lab will not function on ARM systems." ;;
    *) die "Unsupported architecture: ${arch}" ;;
  esac
}

warn_if_low_disk_space() {
  local check_path free_gb resp
  check_path="/opt"
  [[ -d "${SPLUNK_HOME}" ]] && check_path="${SPLUNK_HOME}"

  free_gb="$(df -BG "${check_path}" | awk 'NR==2 {gsub(/G/,"",$4); print $4}')"
  [[ -n "${free_gb}" ]] || { warn "Could not determine free disk space for ${check_path}. Continuing."; return 0; }

  if (( free_gb < 40 )); then
    warn "Only ${free_gb} GB free on filesystem backing ${check_path}."
    warn "Splunk + ingested data may exceed this and cause 'no space left on device'."
    read -r -p "Continue anyway? (y/N): " resp
    case "${resp}" in
      y|Y|yes|YES) : ;;
      *) echo "Exiting."; exit 1 ;;
    esac
  fi
}

# ---------- Helpers ----------
ensure_command() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

download_file() {
  # download_file URL OUTFILE
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --progress-bar "${url}" -o "${out}"
  elif command -v wget >/dev/null 2>&1; then
    wget --progress=bar:force:noscroll -O "${out}" "${url}"
  else
    die "Neither curl nor wget is installed."
  fi
  [[ -s "${out}" ]] || die "Download failed or file is empty: ${out}"
}

ensure_splunk_user() {
  if ! id -u "${SPLUNK_USER}" >/dev/null 2>&1; then
    useradd --system --home "${SPLUNK_HOME}" --shell /usr/sbin/nologin "${SPLUNK_USER}"
  fi

  if [[ -d "${SPLUNK_HOME}" ]]; then
    chown -R "${SPLUNK_USER}:${SPLUNK_USER}" "${SPLUNK_HOME}"
  fi
}

run_as_splunk() {
  su -s /bin/bash "${SPLUNK_USER}" -c "$(printf '%q ' "${SPLUNK_BIN}" "$@")"
}

get_lab_ip() {
  local def_if ip
  def_if="$(ip route show default 0.0.0.0/0 2>/dev/null | awk 'NR==1{print $5}')"
  if [[ -n "${def_if}" ]]; then
    ip="$(ip -4 addr show dev "${def_if}" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
    [[ -n "${ip}" ]] && { echo "${ip}"; return 0; }
  fi
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "${ip}" ]] && { echo "${ip}"; return 0; }
  echo ""
}

# ---------- Splunk setup ----------
relax_password_policy_for_lab() {
  mkdir -p "${SPLUNK_HOME}/etc/system/local"
  cat > "${SPLUNK_HOME}/etc/system/local/authentication.conf" <<EOF
[splunk_auth]
minPasswordLength = 4
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordDigit = 0
minPasswordSpecial = 0
forceWeakPasswordChange = 0
EOF
  chown "${SPLUNK_USER}:${SPLUNK_USER}" "${SPLUNK_HOME}/etc/system/local/authentication.conf"
}

write_user_seed() {
  mkdir -p "${SPLUNK_HOME}/etc/system/local"
  cat > "${SPLUNK_HOME}/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = ${ADMIN_USER}
PASSWORD = ${ADMIN_PASS}
EOF
  chown "${SPLUNK_USER}:${SPLUNK_USER}" "${SPLUNK_HOME}/etc/system/local/user-seed.conf"
}

admin_user_exists() {
  [[ -f "${SPLUNK_PASSWD_FILE}" ]] && grep -q '^admin:' "${SPLUNK_PASSWD_FILE}"
}

wait_for_admin_user() {
  local i
  for i in {1..60}; do
    admin_user_exists && return 0
    sleep 2
  done
  return 1
}

install_splunk_if_missing() {
  if [[ -x "${SPLUNK_BIN}" ]]; then
    ok "Splunk already installed at ${SPLUNK_HOME} (skipping install)."
    ensure_splunk_user
    return 0
  fi

  warn_if_low_disk_space

  info "\n[1/4] Downloading Splunk"
  download_file "${SPLUNK_URL}" "${SPLUNK_DEB_PATH}"

  info "\n[2/4] Installing Splunk (dpkg)"
  dpkg -i "${SPLUNK_DEB_PATH}"

  info "\n[3/4] Removing installer package"
  rm -f "${SPLUNK_DEB_PATH}"

  ensure_splunk_user
  relax_password_policy_for_lab
  write_user_seed

  info "\n[4/4] First start (accept license + create admin/admin)"
  run_as_splunk start --accept-license --answer-yes --no-prompt

  if wait_for_admin_user; then
    rm -f "${SPLUNK_HOME}/etc/system/local/user-seed.conf" >/dev/null 2>&1 || true
    ok "Admin user created (admin/admin)."
  else
    warn "Admin user was not created automatically."
    warn "If the web UI says 'No users exist', create admin/admin in the browser once."
  fi

  info "\nEnabling Splunk at boot"
  printf 'y\n' | "${SPLUNK_BIN}" enable boot-start -user "${SPLUNK_USER}" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
}

ensure_splunk_running() {
  if run_as_splunk status >/dev/null 2>&1; then
    return 0
  fi
  info "\nStarting Splunk"
  run_as_splunk start --answer-yes --no-prompt
  run_as_splunk status >/dev/null 2>&1 || die "Splunk is not running after start attempt."
}

ingest_pokemon_once() {
  mkdir -p "${DATA_DIR}"

  if ! admin_user_exists; then
    warn "Skipping data ingest: no admin user detected yet."
    return 0
  fi

  if [[ -f "${INGEST_MARKER}" ]]; then
    ok "pokemon.csv already ingested."
    return 0
  fi

  info "\nDownloading pokemon.csv"
  download_file "${POKE_URL}" "${POKE_FILE}"
  chown -R "${SPLUNK_USER}:${SPLUNK_USER}" "${DATA_DIR}"

  info "\nUploading pokemon.csv into Splunk (index=main, sourcetype=pokedex)"
  if run_as_splunk add oneshot "${POKE_FILE}"       -index "main"       -sourcetype "pokedex"       -source "Pokedex"       -host "Pokedex"       -auth "${ADMIN_USER}:${ADMIN_PASS}" >/dev/null 2>&1; then
    touch "${INGEST_MARKER}"
    ok "pokemon.csv uploaded."
  else
    warn "Data ingest failed (likely auth not ready yet)."
  fi
}

# ---------- Main ----------
require_root
ensure_command dpkg
ensure_command ip

info "[1/5] Architecture check"
block_arm
ok "x86_64/amd64 confirmed."

info "\n[2/5] Install or reuse existing Splunk"
install_splunk_if_missing

info "\n[3/5] Ensure Splunk is running"
ensure_splunk_running
ok "Splunk is running as user '${SPLUNK_USER}'."

info "\n[4/5] Load lab data"
ingest_pokemon_once

info "\n[5/5] Access information"
ip_addr="$(get_lab_ip)"

echo
echo "============================================================"
echo "Splunk is installed and running."
echo "URL: http://${ip_addr:-<server-ip>}:8000"
echo "Credentials: ${ADMIN_USER} / ${ADMIN_PASS}"
echo "============================================================"
echo
