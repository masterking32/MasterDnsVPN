#!/usr/bin/env bash
set -euo pipefail

RELEASE_TAG="${RELEASE_TAG:-latest}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm/v5,linux/arm/v7,linux/arm64/v8,linux/mips64le}"

if ! docker buildx version >/dev/null 2>&1; then
  echo "docker buildx is required" >&2
  exit 1
fi

echo "Choose registry:"
echo "  1) Docker Hub"
echo "  2) GHCR"
read -rp "Enter choice [1-2]: " REGISTRY_CHOICE

case "${REGISTRY_CHOICE}" in
  1)
    REGISTRY_KIND="dockerhub"
    REGISTRY_HOST=""
    ;;
  2)
    REGISTRY_KIND="ghcr"
    REGISTRY_HOST="ghcr.io"
    ;;
  *)
    echo "Invalid choice. Use 1 or 2." >&2
    exit 1
    ;;
esac

validate_image_ref() {
  local ref="$1"
  [[ "$ref" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(:[A-Za-z0-9._-][A-Za-z0-9._-]{0,127})?$ ]]
}

echo
echo "Enter image name exactly in this format:"
echo "  username/name"
echo "  username/name:tag"
echo "Examples:"
echo
echo "Invalid example:"
echo "  examplename-v2"
echo

IMAGE_REFS=()

while true; do
  read -rp "Image name: " REF

  if [[ -z "${REF}" ]]; then
    echo "Empty input. Use username/name or username/name:tag" >&2
    continue
  fi

  if [[ "${REF}" == "N" || "${REF}" == "n" ]]; then
    break
  fi

  if ! validate_image_ref "${REF}"; then
    echo "Invalid format. Use username/name or username/name:tag" >&2
    continue
  fi

  if [[ "${REF}" != *:* ]]; then
    REF="${REF}:latest"
  fi

  IMAGE_REFS+=("${REF}")

  while true; do
    read -rp "Press Enter for next image name, or N to finish: " NEXT_STEP
    case "${NEXT_STEP}" in
      "")
        break 2
        ;;
      N|n)
        break 2
        ;;
      *)
        if validate_image_ref "${NEXT_STEP}"; then
          if [[ "${NEXT_STEP}" != *:* ]]; then
            NEXT_STEP="${NEXT_STEP}:latest"
          fi
          IMAGE_REFS+=("${NEXT_STEP}")
          continue
        fi

        echo "Invalid format. Use username/name or username/name:tag" >&2
        ;;
    esac
  done
done

if [[ "${#IMAGE_REFS[@]}" -eq 0 ]]; then
  echo "At least one image name is required." >&2
  exit 1
fi

if [[ "${REGISTRY_KIND}" == "dockerhub" ]]; then
  echo
  echo "Docker Hub login required if you are not already logged in."
  read -rp "Docker Hub Username: " DOCKER_USERNAME
  read -rsp "Docker Hub Password / Access Token: " DOCKER_PASSWORD
  echo
  echo "${DOCKER_PASSWORD}" | docker login --username "${DOCKER_USERNAME}" --password-stdin
else
  echo
  echo "GHCR login required if you are not already logged in."
  echo "You can create a GitHub token here:"
  echo "https://github.com/settings/tokens"
  echo "Use a Personal Access Token (classic)."
  echo "For pushing packages, the token needs write:packages."
  echo "For deleting packages, the token needs delete:packages (GitHub docs also note read:packages is required for delete operations)."
  read -rp "GitHub Username: " GHCR_USERNAME
  read -rsp "GitHub PAT (classic): " GHCR_TOKEN
  echo
  echo "${GHCR_TOKEN}" | docker login ghcr.io --username "${GHCR_USERNAME}" --password-stdin
fi

TAG_ARGS=()
for REF in "${IMAGE_REFS[@]}"; do
  if [[ "${REGISTRY_KIND}" == "ghcr" ]]; then
    REF="${REGISTRY_HOST}/${REF}"
  fi
  TAG_ARGS+=(-t "${REF}")
done

docker buildx build \
  --platform "${PLATFORMS}" \
  --build-arg RELEASE_TAG="${RELEASE_TAG}" \
  "${TAG_ARGS[@]}" \
  -f Dockerfile \
  --push \
  .

echo
echo "Build and push completed:"
for REF in "${IMAGE_REFS[@]}"; do
  if [[ "${REGISTRY_KIND}" == "ghcr" ]]; then
    REF="ghcr.io/${REF}"
  fi
  echo "  ${REF}"
done
