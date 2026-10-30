#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# ===== Prompt for IMAGE_NAME =====
if [[ -z "${IMAGE_NAME:-}" ]]; then
  IMAGE_NAME="masterking32/masterdnsvpn"
fi

if [[ -z "${IMAGE_NAME}" ]]; then
  echo "IMAGE_NAME cannot be empty" >&2
  exit 1
fi

# ===== Defaults =====
TAG="${TAG:-latest}"
RELEASE_TAG="${RELEASE_TAG:-latest}"
RELEASE_SHA256="${RELEASE_SHA256:-}"

# ===== Build (local only) =====
docker build \
  --build-arg RELEASE_TAG="${RELEASE_TAG}" \
  --build-arg RELEASE_SHA256="${RELEASE_SHA256}" \
  -t "${IMAGE_NAME}:${TAG}" \
  -f Dockerfile \
  ..

echo "Local image built successfully: ${IMAGE_NAME}:${TAG}"
