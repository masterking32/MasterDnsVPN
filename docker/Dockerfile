# Download and compile on the builder's native architecture. The final image
# contains only static binaries, so it needs no target-specific distro image.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS downloader

ARG TARGETARCH
ARG TARGETVARIANT
ARG RELEASE_TAG=latest
ARG RELEASE_SHA256=

RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  binutils \
  curl \
  unzip \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /out

RUN set -eux; \
  case "${TARGETARCH}" in \
  amd64) \
  ARTIFACT="MasterDnsVPN_Server_Linux_AMD64.zip"; PREFIX="MasterDnsVPN_Server_Linux_AMD64" ;; \
  arm64) \
  ARTIFACT="MasterDnsVPN_Server_Linux_ARM64.zip"; PREFIX="MasterDnsVPN_Server_Linux_ARM64" ;; \
  arm) \
  case "${TARGETVARIANT}" in \
  v5) ARTIFACT="MasterDnsVPN_Server_Linux_ARMV5.zip"; PREFIX="MasterDnsVPN_Server_Linux_ARMV5" ;; \
  v7|"") ARTIFACT="MasterDnsVPN_Server_Linux_ARMV7.zip"; PREFIX="MasterDnsVPN_Server_Linux_ARMV7" ;; \
  *) echo "Unsupported ARM variant: ${TARGETVARIANT}" >&2; exit 1 ;; \
  esac ;; \
  mips64le) \
  ARTIFACT="MasterDnsVPN_Server_Linux_MIPS64LE.zip"; PREFIX="MasterDnsVPN_Server_Linux_MIPS64LE" ;; \
  *) \
  echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
  esac; \
  if [ "${RELEASE_TAG}" = latest ]; then \
  RELEASE_URL="https://github.com/masterking32/MasterDnsVPN/releases/latest/download"; \
  else \
  RELEASE_URL="https://github.com/masterking32/MasterDnsVPN/releases/download/${RELEASE_TAG}"; \
  fi; \
  curl -fsSL --retry 3 --retry-delay 2 \
  -o /tmp/masterdnsvpn.zip \
  "${RELEASE_URL}/${ARTIFACT}"; \
  if [ -n "${RELEASE_SHA256}" ]; then \
  echo "${RELEASE_SHA256}  /tmp/masterdnsvpn.zip" | sha256sum -c -; \
  fi; \
  unzip -q /tmp/masterdnsvpn.zip -d /out; \
  rm -f /tmp/masterdnsvpn.zip; \
  BIN="$(find /out -type f -name "${PREFIX}_v*" | sort -V | tail -n1)"; \
  if [ -z "${BIN}" ]; then echo "Could not find extracted binary for ${PREFIX}" >&2; exit 1; fi; \
  mv "${BIN}" /out/masterdnsvpn; \
  chmod 0755 /out/masterdnsvpn; \
  readelf -l /out/masterdnsvpn > /tmp/program-headers; \
  readelf -d /out/masterdnsvpn > /tmp/dynamic-section; \
  if grep -q INTERP /tmp/program-headers || grep -q NEEDED /tmp/dynamic-section; then \
  echo "The release binary must be statically linked for the scratch runtime." >&2; exit 1; \
  fi; \
  test -s /out/server_config.toml; \
  mv /out/server_config.toml /out/server_config.toml.simple; \
  find /out -type f ! -path /out/masterdnsvpn ! -path /out/server_config.toml.simple -delete

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS entrypoint-builder

ARG TARGETARCH
ARG TARGETVARIANT

WORKDIR /src
# Use the repository root as context to share the launcher's pinned TOML dependency.
COPY go.mod go.sum ./
RUN go mod download github.com/BurntSushi/toml
COPY docker/entrypoint/ ./docker/entrypoint/

RUN mkdir -p /out && \
  CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" GOARM="${TARGETVARIANT#v}" \
  GOMIPS64=softfloat \
  go build -trimpath -ldflags="-s -w" -o /out/docker-entrypoint ./docker/entrypoint && \
  readelf -l /out/docker-entrypoint > /tmp/program-headers && \
  readelf -d /out/docker-entrypoint > /tmp/dynamic-section && \
  if grep -q INTERP /tmp/program-headers || grep -q NEEDED /tmp/dynamic-section; then \
  echo "The container entrypoint must be statically linked for the scratch runtime." >&2; exit 1; \
  fi

FROM scratch

LABEL org.opencontainers.image.source=https://github.com/masterking32/MasterDnsVPN

ENV APP_DIR=/opt/masterdnsvpn \
  DATA_DIR=/data \
  CONFIG_FILE=server_config.toml

COPY --from=downloader /out/masterdnsvpn /opt/masterdnsvpn/masterdnsvpn
COPY --from=downloader /out/server_config.toml.simple /usr/share/masterdnsvpn/server_config.toml.simple
COPY --from=downloader /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=entrypoint-builder /out/docker-entrypoint /usr/local/bin/docker-entrypoint

WORKDIR /opt/masterdnsvpn

EXPOSE 53/tcp 53/udp
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["-nowait"]
