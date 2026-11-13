# connector image (SDK + gitleaks) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY secrets/gitleaks/go.mod secrets/gitleaks/go.sum secrets/gitleaks/
RUN cd secrets/gitleaks && GOWORK=off go mod download
COPY sdk/ sdk/
COPY secrets/gitleaks/ secrets/gitleaks/
RUN cd secrets/gitleaks && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
# gitleaks itself is rebuilt from the same pinned tag. The binary the upstream
# image ships was built with Go 1.24.13 against x/crypto 0.35, x/text 0.22,
# klauspost/compress 1.17.11, rardecode 2.1.0 and xz 0.5.12, every one with
# published fixes, and v8.30.1 is the newest release. A throwaway module lets
# `go get` lift those dependencies by minimum version selection (`go install
# pkg@version` ignores the main module), and this builder's Go 1.26 replaces
# the 1.24 standard library. The version ldflag matches upstream's Makefile so
# `gitleaks version` still reports v8.30.1. Revisit when a gitleaks release
# ships these or newer.
ARG GITLEAKS_VERSION=v8.30.1
RUN set -eux; \
    mkdir -p /src/gitleaks-toolchain; \
    cd /src/gitleaks-toolchain; \
    GOWORK=off go mod init oasm.local/gitleaks-toolchain; \
    GOWORK=off go get github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION} \
      golang.org/x/crypto@v0.59.0 golang.org/x/text@v0.44.0 \
      github.com/klauspost/compress@v1.20.4 github.com/nwaples/rardecode/v2@v2.4.6 \
      github.com/ulikunitz/xz@v0.5.17; \
    GOWORK=off CGO_ENABLED=0 go build -mod=mod -trimpath \
      -ldflags "-X=github.com/zricethezav/gitleaks/v8/version.Version=${GITLEAKS_VERSION}" \
      -o /out/gitleaks github.com/zricethezav/gitleaks/v8; \
    rm -rf /src/gitleaks-toolchain

# Final stage is the official gitleaks image, pinned by tag: it ships the git
# client sdk/gitrepo clones with. Its own gitleaks binary is overwritten by the
# rebuild above, so the two must stay on the same tag.
FROM zricethezav/gitleaks:v8.30.1 AS runtime
# The base image runs as root; package management happens first, then the
# connector drops to an unprivileged user. `apk update` first: the base image
# carries no package index. Upgrading picks up alpine security fixes released
# after the upstream tag (scan-and-push fails on unpatched CRITICALs).
#
# Named `runtime` on purpose: CI builds this stage with `no-cache-filters:
# runtime` (see .github/workflows/scan-and-push.yml). The upgrade layer's
# content depends on what the package index served at build time, which is not
# in the Dockerfile, so the layer cache would otherwise keep shipping whatever
# the first build saw long after a fix is published.
USER root
RUN apk update --no-cache && apk upgrade --no-cache \
 && adduser -D -H -u 10001 connector
COPY --from=builder /out/connector /usr/local/bin/connector
COPY --from=builder /out/gitleaks /usr/bin/gitleaks
USER connector
# The worker also pins HOME/XDG_CACHE_HOME under /tmp; git needs a writable
# HOME for its global config lookups.
ENV HOME=/tmp \
    GITLEAKS_BIN=/usr/bin/gitleaks
ENTRYPOINT ["/usr/local/bin/connector"]
