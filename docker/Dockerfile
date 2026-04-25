FROM debian:bookworm-slim AS downloader

ARG TARGETARCH
ARG TARGETVARIANT
ARG RELEASE_TAG=latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
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
    curl -fsSL --retry 3 --retry-delay 2 \
      -o /tmp/masterdnsvpn.zip \
      "https://github.com/masterking32/MasterDnsVPN/releases/${RELEASE_TAG}/download/${ARTIFACT}"; \
    unzip -q /tmp/masterdnsvpn.zip -d /out; \
    rm -f /tmp/masterdnsvpn.zip; \
    BIN="$(find /out -maxdepth 1 -type f -name "${PREFIX}_v*" | sort -V | tail -n1)"; \
    if [ -z "${BIN}" ]; then echo "Could not find extracted binary for ${PREFIX}" >&2; exit 1; fi; \
    mv "${BIN}" /out/masterdnsvpn; \
    chmod 0755 /out/masterdnsvpn; \
    find /out -maxdepth 1 -type f ! -name masterdnsvpn -delete

FROM debian:bookworm-slim

LABEL org.opencontainers.image.source=https://github.com/masterking32/MasterDnsVPN

ENV DEBIAN_FRONTEND=noninteractive \
    APP_DIR=/opt/masterdnsvpn \
    DATA_DIR=/data \
    CONFIG_FILE=server_config.toml \
    KEY_FILE=encrypt_key.txt

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    tini \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /opt/masterdnsvpn /data

COPY --from=downloader /out/masterdnsvpn /opt/masterdnsvpn/masterdnsvpn
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod 0755 /opt/masterdnsvpn/masterdnsvpn /usr/local/bin/docker-entrypoint.sh

WORKDIR /opt/masterdnsvpn

EXPOSE 53/tcp 53/udp
VOLUME ["/data"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["-nowait"]
