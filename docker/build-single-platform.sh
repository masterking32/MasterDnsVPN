#!/usr/bin/env bash
set -euo pipefail

# ===== Prompt for IMAGE_NAME =====
if [[ -z "${IMAGE_NAME:-}" ]]; then
  read -rp "Enter Docker image name (example: something/masterdnsvpn): " IMAGE_NAME
fi

if [[ -z "${IMAGE_NAME}" ]]; then
  echo "IMAGE_NAME cannot be empty" >&2
  exit 1
fi

# ===== Defaults =====
TAG="${TAG:-latest}"
RELEASE_TAG="${RELEASE_TAG:-latest}"

# ===== Build (local only) =====
docker build \
  --build-arg RELEASE_TAG="${RELEASE_TAG}" \
  -t "${IMAGE_NAME}:${TAG}" \
  -f Dockerfile \
  .

echo "Local image built successfully: ${IMAGE_NAME}:${TAG}"
