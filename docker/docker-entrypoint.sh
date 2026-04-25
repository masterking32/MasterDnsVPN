#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/masterdnsvpn}"
DATA_DIR="${DATA_DIR:-/data}"
CONFIG_FILE="${CONFIG_FILE:-server_config.toml}"
KEY_FILE="${KEY_FILE:-encrypt_key.txt}"
BIN="${APP_DIR}/masterdnsvpn"
SAMPLE_URL="https://raw.githubusercontent.com/masterking32/MasterDnsVPN/main/server_config.toml.simple"

mkdir -p "${APP_DIR}" "${DATA_DIR}"
cd "${APP_DIR}"

copy_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -f "${src}" ]]; then
    cp -f "${src}" "${dst}"
  fi
}

bootstrap_config() {
  local domain_value tmp_config

  domain_value="${DOMAIN:-}"
  if [[ -z "${domain_value}" ]]; then
    echo "ERROR: DOMAIN env is required when /data/${CONFIG_FILE} does not exist." >&2
    exit 1
  fi

  tmp_config="$(mktemp)"
  trap 'rm -f "${tmp_config}"' EXIT

  curl -fsSL --retry 3 --retry-delay 2 "${SAMPLE_URL}" -o "${tmp_config}"

  domain_value="${domain_value//&/\\&}"
  sed -E "s|^DOMAIN[[:space:]]*=.*$|DOMAIN = [\"${domain_value}\"]|" "${tmp_config}" > "${APP_DIR}/${CONFIG_FILE}"
  cp -f "${APP_DIR}/${CONFIG_FILE}" "${DATA_DIR}/${CONFIG_FILE}" 2>/dev/null || true
  rm -f "${tmp_config}"
  trap - EXIT
}

if [[ ! -x "${BIN}" ]]; then
  echo "Binary not found or not executable: ${BIN}" >&2
  exit 1
fi

# Prefer persisted config/key if present.
copy_if_exists "${DATA_DIR}/${CONFIG_FILE}" "${APP_DIR}/${CONFIG_FILE}"
copy_if_exists "${DATA_DIR}/${KEY_FILE}" "${APP_DIR}/${KEY_FILE}"

if [[ ! -f "${APP_DIR}/${CONFIG_FILE}" ]]; then
  bootstrap_config
fi

if [[ ! -s "${APP_DIR}/${KEY_FILE}" ]]; then
  tmp_log="$(mktemp)"
  if ! "${BIN}" -genkey -nowait >"${tmp_log}" 2>&1; then
    tail -n 100 "${tmp_log}" >&2 || true
    rm -f "${tmp_log}"
    exit 1
  fi
  rm -f "${tmp_log}"
fi

cp -f "${APP_DIR}/${CONFIG_FILE}" "${DATA_DIR}/${CONFIG_FILE}" 2>/dev/null || true
cp -f "${APP_DIR}/${KEY_FILE}" "${DATA_DIR}/${KEY_FILE}" 2>/dev/null || true

exec "${BIN}" -nowait "$@"
