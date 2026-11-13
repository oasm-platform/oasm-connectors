# connector image (SDK+gau) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY url_discovery/gau/go.mod url_discovery/gau/go.sum url_discovery/gau/
RUN cd url_discovery/gau && GOWORK=off go mod download
COPY sdk/ sdk/
COPY url_discovery/gau/ url_discovery/gau/
RUN cd url_discovery/gau && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
# gau CLI pinned v2.2.4, built from source. The upstream Docker Hub image
# sxcurity/gau:latest is rejected: amd64-only (no multi-arch) and has no
# version tags, so it cannot be pinned or built for arm64. Building here keeps
# multi-arch builds and a deterministic v2.2.4 pin.
#
# Built through a throwaway module rather than `go install gau@v2.2.4`, because
# `go install pkg@version` ignores the main module and so cannot move a
# dependency. v2.2.4 is the newest gau release and its go.mod still pins
# x/net 0.17, x/text 0.13, fasthttp 1.31, logrus 1.8.1 and klauspost/compress
# 1.13.4, all with published fixes. `go get` lifts them by minimum version
# selection; gau's own code is untouched. Revisit when gau tags a release with
# newer pins and this can go back to a plain install.
RUN set -eux; \
    mkdir -p /src/gau-toolchain; \
    cd /src/gau-toolchain; \
    GOWORK=off go mod init oasm.local/gau-toolchain; \
    GOWORK=off go get github.com/lc/gau/v2/cmd/gau@v2.2.4 \
      golang.org/x/net@v0.62.0 golang.org/x/text@v0.44.0 \
      github.com/valyala/fasthttp@v1.78.0 github.com/sirupsen/logrus@v1.10.2 \
      github.com/klauspost/compress@v1.20.4; \
    GOWORK=off CGO_ENABLED=0 go build -mod=mod -trimpath -o /out/gau github.com/lc/gau/v2/cmd/gau; \
    rm -rf /src/gau-toolchain
FROM alpine:3.22 AS runtime
# Named `runtime` so CI rebuilds this stage uncached (`no-cache-filters` in
# scan-and-push.yml): `apk upgrade` pulls alpine fixes published after the
# base tag, and a cached layer would keep shipping the first build's set.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates && adduser -D -u 10001 connector
USER 10001
COPY --from=builder /out/connector /usr/local/bin/connector
COPY --from=builder /out/gau /usr/local/bin/gau
ENTRYPOINT ["/usr/local/bin/connector"]
