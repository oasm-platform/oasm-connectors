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
RUN GOWORK=off GOBIN=/out go install github.com/lc/gau/v2/cmd/gau@v2.2.4
FROM alpine:3.22 AS runtime
# Named `runtime` so CI rebuilds this stage uncached (`no-cache-filters` in
# scan-and-push.yml): `apk upgrade` pulls alpine fixes published after the
# base tag, and a cached layer would keep shipping the first build's set.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates && adduser -D -u 10001 connector
USER 10001
COPY --from=builder /out/connector /usr/local/bin/connector
COPY --from=builder /out/gau /usr/local/bin/gau
ENTRYPOINT ["/usr/local/bin/connector"]
