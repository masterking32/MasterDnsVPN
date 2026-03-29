# ---------- BUILD STAGE ----------
FROM golang:1.25-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o server ./cmd/server && \
    go build -ldflags="-s -w" -o client ./cmd/client

# ---------- RUNTIME ----------
FROM alpine:3.20

WORKDIR /app

RUN adduser -D appuser

COPY --from=builder /app/server /usr/local/bin/server
COPY --from=builder /app/client /usr/local/bin/client

USER appuser

# DNS port
EXPOSE 53/udp

# select mode: server (default) or client
ENV MODE=server

# entrypoint wrapper
ENTRYPOINT ["/bin/sh", "-c", "if [ \"$MODE\" = \"client\" ]; then exec client \"$@\"; else exec server \"$@\"; fi", "--"]

# default args
CMD ["--help"]
