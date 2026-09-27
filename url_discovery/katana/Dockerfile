# connector image (SDK+katana) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY url_discovery/katana/go.mod url_discovery/katana/go.sum url_discovery/katana/
RUN cd url_discovery/katana && GOWORK=off go mod download
COPY sdk/ sdk/
COPY url_discovery/katana/ url_discovery/katana/
RUN cd url_discovery/katana && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
# katana CLI pinned v1.7.0, built from source. CGO_ENABLED=0 verified sufficient
# (static binary, functional crawl; no gcc/musl-dev needed — upstream's own
# image installing gcc is not required). The official image also bundles chromium
# and bind-tools for headless crawling; excluded here because headless is off
# (no -hl). Building from source keeps multi-arch builds and a deterministic pin.
#
# Built through a throwaway module rather than `go install katana@v1.7.0` so the
# pgx override in the command below can apply: `go install pkg@version` ignores
# the main module, and a replace is the only way to move a dependency of a
# dependency. katana v1.7.0 is also the newest release, so no upstream tag
# already carries the fix. pgx v5.11.0 clears CVE-2026-33815 / CVE-2026-33816
# (memory-safety, fixed in 5.9.0). It rides in via projectdiscovery/dsl rather
# than katana's own code, so moving the minor within v5 changes no API katana
# calls; the binary grows by 48 bytes. Revisit when katana itself moves the pin
# and this can be dropped.
RUN set -eux; \
    mkdir -p /src/katana-toolchain; \
    cd /src/katana-toolchain; \
    GOWORK=off go mod init oasm.local/katana-toolchain; \
    GOWORK=off go mod edit -require=github.com/projectdiscovery/katana@v1.7.0; \
    GOWORK=off go mod edit -replace=github.com/jackc/pgx/v5=github.com/jackc/pgx/v5@v5.11.0; \
    GOWORK=off CGO_ENABLED=0 go build -mod=mod -trimpath -o /out/katana github.com/projectdiscovery/katana/cmd/katana; \
    rm -rf /src/katana-toolchain
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 connector
# katana writes $HOME/.config/katana/{field-config,form-config}.yaml on first run;
# the image must give the non-root user a writable HOME or katana logs write errors.
ENV HOME=/home/connector
USER 10001
COPY --from=builder /out/connector /usr/local/bin/connector
COPY --from=builder /out/katana /usr/local/bin/katana
ENTRYPOINT ["/usr/local/bin/connector"]
