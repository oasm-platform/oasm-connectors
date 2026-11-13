# connector image (SDK+katana) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY url_discovery/katana/go.mod url_discovery/katana/go.sum url_discovery/katana/
RUN cd url_discovery/katana && GOWORK=off go mod download
COPY sdk/ sdk/
COPY url_discovery/katana/ url_discovery/katana/
RUN cd url_discovery/katana && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
# katana CLI pinned v1.8.0, built from source. CGO_ENABLED=0 verified sufficient
# (static binary, functional crawl; no gcc/musl-dev needed — upstream's own
# image installing gcc is not required). The official image also bundles chromium
# and bind-tools for headless crawling; excluded here because headless is off
# (no -hl). Building from source keeps multi-arch builds and a deterministic pin.
#
# Built through a throwaway module rather than `go install katana@v1.8.0` so the
# dependency overrides in the command below can apply: `go install pkg@version`
# ignores the main module, so it cannot move a dependency of a dependency.
# katana v1.8.0 is the newest release and still pulls, with published fixes:
#   jackc/pgx/v5          5.7.2   (via projectdiscovery/dsl) CVE-2026-33815/33816
#   klauspost/compress    1.18.5
#   golang.org/x/crypto   0.55.0
#   golang.org/x/net      0.58.0
# `go get` lifts each by minimum version selection, all within their major
# version, so no API katana calls moves. Revisit when katana itself moves the
# pins and this can go back to a plain install.
RUN set -eux; \
    mkdir -p /src/katana-toolchain; \
    cd /src/katana-toolchain; \
    GOWORK=off go mod init oasm.local/katana-toolchain; \
    GOWORK=off go get github.com/projectdiscovery/katana/cmd/katana@v1.8.0 \
      github.com/jackc/pgx/v5@v5.11.0 github.com/klauspost/compress@v1.20.4 \
      golang.org/x/crypto@v0.59.0 golang.org/x/net@v0.62.0; \
    GOWORK=off CGO_ENABLED=0 go build -mod=mod -trimpath -o /out/katana github.com/projectdiscovery/katana/cmd/katana; \
    rm -rf /src/katana-toolchain
FROM alpine:3.22 AS runtime
# Named `runtime` so CI rebuilds this stage uncached (`no-cache-filters` in
# scan-and-push.yml): `apk upgrade` pulls alpine fixes published after the
# base tag, and a cached layer would keep shipping the first build's set.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates && adduser -D -u 10001 connector
# katana writes $HOME/.config/katana/{field-config,form-config}.yaml on first run;
# the image must give the non-root user a writable HOME or katana logs write errors.
ENV HOME=/home/connector
USER 10001
COPY --from=builder /out/connector /usr/local/bin/connector
COPY --from=builder /out/katana /usr/local/bin/katana
ENTRYPOINT ["/usr/local/bin/connector"]
