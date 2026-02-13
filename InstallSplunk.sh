#!/usr/bin/env bash
set -euo pipefail

############################################
# Splunk Lab Installer (Ubuntu/Debian)
# - Must run as root
# - Blocks ARM
# - Warns if < 40GB free on filesystem backing /opt
# - Installs Splunk 10.2.0 if missing
# - Runs Splunk as user: splunk
# - Seeds admin/admin (fresh installs)
# - Ingests pokemon.csv into index=main (oneshot) once
############################################

# ---------- Config ----------
SPLUNK_USER="splunk"

SPLUNK_DEB="splunk-10.2.0-d749cb17ea65-linux-amd64.deb"
SPLUNK_URL="https://download.splunk.com/products/splunk/releases/10.2.0/linux/${SPLUNK_DEB}"
SPLUNK_DEB_PATH="/tmp/${SPLUNK_DEB}"

SPLUNK_DIR="/opt/splunk"
SPLUNK_BIN="${SPLUNK_DIR}/bin/splunk"
USERS_FILE="${SPLUNK_DIR}/etc/passwd"

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

say_step() { echo -e "\n${BOLD}${CYAN}$*${RESET}"; }
ok()       { echo -e "${GREEN}OK${RESET} - $*"; }
warn()     { echo -e "${YELLOW}WARN${RESET} - $*"; }
die()      { echo -e "${RED}ERROR${RESET} - $*" >&2; exit 1; }

# ---------- Checks ----------
need_root() {
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
  [[ -d "${SPLUNK_DIR}" ]] && check_path="${SPLUNK_DIR}"

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

# ---------- Users / Run-as ----------
ensure_splunk_user() {
  if ! id -u "${SPLUNK_USER}" >/dev/null 2>&1; then
    useradd --system --home "${SPLUNK_DIR}" --shell /usr/sbin/nologin "${SPLUNK_USER}"
  fi

  if [[ -d "${SPLUNK_DIR}" ]]; then
    chown -R "${SPLUNK_USER}:${SPLUNK_USER}" "${SPLUNK_DIR}"
  fi
}

run_as_splunk() {
  su -s /bin/bash "${SPLUNK_USER}" -c "$(printf '%q ' "${SPLUNK_BIN}" "$@")"
}

# ---------- Download ----------
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

# ---------- Splunk setup ----------
has_admin_user() {
  [[ -f "${USERS_FILE}" ]] && grep -q '^admin:' "${USERS_FILE}"
}

seed_admin_user() {
  mkdir -p "${SPLUNK_DIR}/etc/system/local"
  cat > "${SPLUNK_DIR}/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = ${ADMIN_USER}
PASSWORD = ${ADMIN_PASS}
EOF
  chown "${SPLUNK_USER}:${SPLUNK_USER}" "${SPLUNK_DIR}/etc/system/local/user-seed.conf"
}

wait_for_admin_user() {
  # Wait up to ~90s for Splunk to create users file and admin entry
  local i
  for i in {1..45}; do
    if has_admin_user; then
      return 0
    fi
    sleep 2
  done
  return 1
}

install_splunk_if_missing() {
  if [[ -x "${SPLUNK_BIN}" ]]; then
    ok "Splunk already installed at ${SPLUNK_DIR} (skipping install)."
    ensure_splunk_user
    return 0
  fi

  warn_if_low_disk_space

  say_step "[1/4] Downloading Splunk package"
  download_file "${SPLUNK_URL}" "${SPLUNK_DEB_PATH}"

  say_step "[2/4] Installing Splunk (dpkg)"
  dpkg -i "${SPLUNK_DEB_PATH}"

  say_step "[3/4] Cleaning up installer package"
  rm -f "${SPLUNK_DEB_PATH}"

  ensure_splunk_user

  say_step "[4/4] First-time setup (seed admin/admin + accept license)"
  seed_admin_user
  run_as_splunk start --accept-license --answer-yes --no-prompt >/dev/null

  if ! wait_for_admin_user; then
    warn "Admin user was not detected after startup. You may see 'No Users exist' in the UI."
    warn "If that happens, remove /opt/splunk and rerun the script on a fresh VM."
  else
    rm -f "${SPLUNK_DIR}/etc/system/local/user-seed.conf" >/dev/null 2>&1 || true
    ok "Admin user seeded (admin/admin)."
  fi

  say_step "Enabling boot-start"
  printf 'y\n' | "${SPLUNK_BIN}" enable boot-start -user "${SPLUNK_USER}" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
}

ensure_splunk_running() {
  if run_as_splunk status >/dev/null 2>&1; then
    return 0
  fi
  say_step "Starting Splunk"
  run_as_splunk start --answer-yes --no-prompt >/dev/null
  run_as_splunk status >/dev/null 2>&1 || die "Splunk is not running after start attempt."
}

ingest_pokemon_csv_once() {
  if [[ -f "${INGEST_MARKER}" ]]; then
    ok "pokemon.csv already ingested."
    return 0
  fi

  mkdir -p "${DATA_DIR}"

  say_step "Downloading pokemon.csv"
  download_file "${POKE_URL}" "${POKE_FILE}"

  say_step "Uploading pokemon.csv into Splunk (index=main, sourcetype=pokedex)"
  run_as_splunk add oneshot "${POKE_FILE}"     -index "main"     -sourcetype "pokedex"     -source "Pokedex"     -host "Pokedex"     -auth "${ADMIN_USER}:${ADMIN_PASS}" >/dev/null

  touch "${INGEST_MARKER}"
  ok "pokemon.csv uploaded."
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

# ---------- Main ----------
need_root
block_arm

say_step "Installing or validating Splunk"
install_splunk_if_missing

say_step "Ensuring Splunk is running"
ensure_splunk_running
ok "Splunk is running as user '${SPLUNK_USER}'."

say_step "Loading lab data"
ingest_pokemon_csv_once

ip_addr="$(get_lab_ip)"

echo
echo "============================================================"
echo "Splunk is installed and running."
echo "URL: http://${ip_addr:-<server-ip>}:8000"
echo "Credentials: ${ADMIN_USER} / ${ADMIN_PASS}"
echo "============================================================"
echo
