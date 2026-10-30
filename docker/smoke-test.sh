#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:?Usage: smoke-test.sh IMAGE PLATFORM}"
PLATFORM="${2:?Usage: smoke-test.sh IMAGE PLATFORM}"
VOLUME="masterdnsvpn-smoke-${RANDOM}-${RANDOM}"
CONTAINER=""
TEST_DIR="$(mktemp -d)"

cleanup() {
  if [[ -n "${CONTAINER}" ]]; then
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
  fi
  docker volume rm "${VOLUME}" >/dev/null 2>&1 || true
  rm -f "${TEST_DIR}/first.key" "${TEST_DIR}/second.key"
  rmdir "${TEST_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

wait_until_ready() {
  for ((attempt = 0; attempt < 60; attempt++)); do
    if [[ "$(docker inspect --format '{{.State.Running}}' "${CONTAINER}")" != true ]]; then
      docker logs "${CONTAINER}"
      echo "Container exited before becoming ready on ${PLATFORM}." >&2
      return 1
    fi
    if docker logs "${CONTAINER}" 2>&1 | grep -q 'UDP Listener Ready'; then
      return 0
    fi
    sleep 1
  done
  docker logs "${CONTAINER}"
  echo "Container did not become ready on ${PLATFORM}." >&2
  return 1
}

stop_cleanly() {
  docker stop -t 10 "${CONTAINER}" >/dev/null
  if [[ "$(docker inspect --format '{{.State.ExitCode}}' "${CONTAINER}")" != 0 ]]; then
    docker logs "${CONTAINER}"
    echo "Container did not exit cleanly after SIGTERM on ${PLATFORM}." >&2
    return 1
  fi
}

docker volume create "${VOLUME}" >/dev/null
CONTAINER="$(docker run -d --platform "${PLATFORM}" --network none \
  -e DOMAIN=smoke.example.com -v "${VOLUME}:/data" "${IMAGE}" \
  -udp-host 127.0.0.1 -udp-port 15353)"
wait_until_ready
docker cp "${CONTAINER}:/data/encrypt_key.txt" "${TEST_DIR}/first.key"
stop_cleanly
docker rm "${CONTAINER}" >/dev/null
CONTAINER=""

# A fresh container must reuse /data without DOMAIN or access to GitHub.
CONTAINER="$(docker run -d --platform "${PLATFORM}" --network none \
  -v "${VOLUME}:/data" "${IMAGE}" -udp-host 127.0.0.1 -udp-port 15353)"
wait_until_ready
docker cp "${CONTAINER}:/data/encrypt_key.txt" "${TEST_DIR}/second.key"
cmp "${TEST_DIR}/first.key" "${TEST_DIR}/second.key"
stop_cleanly
echo "${PLATFORM}: offline first boot, persisted restart, key reuse and SIGTERM passed."
