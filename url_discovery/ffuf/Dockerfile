# connector image (SDK+ffuf) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY url_discovery/ffuf/go.mod url_discovery/ffuf/go.sum url_discovery/ffuf/
RUN cd url_discovery/ffuf && GOWORK=off go mod download
COPY sdk/ sdk/
COPY url_discovery/ffuf/ url_discovery/ffuf/
RUN cd url_discovery/ffuf && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
# ffuf CLI pinned v2.3.0, built from source. The module path (not the repo root)
# is installed so the CLI lands at /out/ffuf. Upstream's Docker Hub image is
# tagless (unpinnable); building from source keeps multi-arch builds and a
# deterministic v2.3.0 pin. CGO_ENABLED=0 keeps the binary static for alpine.
#
# Built through a throwaway module rather than `go install ffuf@v2.3.0`, because
# `go install pkg@version` ignores the main module and so cannot move a
# dependency. v2.3.0 is the newest ffuf release and its go.mod still pins
# golang.org/x/net v0.7.0, which carries two dozen advisories fixed up to
# v0.62.0. `go get` lifts it by minimum version selection; ffuf's own code is
# untouched. Revisit when ffuf tags a release with a newer x/net.
RUN set -eux; \
    mkdir -p /src/ffuf-toolchain; \
    cd /src/ffuf-toolchain; \
    GOWORK=off go mod init oasm.local/ffuf-toolchain; \
    GOWORK=off go get github.com/ffuf/ffuf/v2@v2.3.0 golang.org/x/net@v0.62.0; \
    GOWORK=off CGO_ENABLED=0 go build -mod=mod -trimpath -o /out/ffuf github.com/ffuf/ffuf/v2; \
    rm -rf /src/ffuf-toolchain
RUN apk add --no-cache curl
# Bundled wordlists pinned to one SecLists commit (2026.1) so image builds are
# reproducible and no full tarball ships. `test -s` fails the build on any empty
# download (a moved file would otherwise land as a 0-byte "wordlist").
RUN mkdir -p /out/wordlists/ffuf && cd /out/wordlists/ffuf && for f in common.txt raft-small-directories.txt raft-medium-directories.txt big.txt DirBuster-2007_directory-list-2.3-small.txt DirBuster-2007_directory-list-2.3-medium.txt; do curl -fsSL -O "https://raw.githubusercontent.com/danielmiessler/SecLists/190c6f7bd58c847ceadfe57d9853592737f059e8/Discovery/Web-Content/$f"; done && for f in *.txt; do test -s "$f"; done
FROM alpine:3.24 AS runtime
# Named `runtime` so CI rebuilds this stage uncached (`no-cache-filters` in
# scan-and-push.yml): `apk upgrade` pulls alpine fixes published after the
# base tag, and a cached layer would keep shipping the first build's set.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates && adduser -D -u 10001 connector
# ffuf needs no writable HOME (unlike katana); the env only points the adapter at
# the bundled wordlists. HOME stays set for consistency across connectors.
ENV HOME=/home/connector FFUF_WORDLIST_DIR=/opt/wordlists/ffuf
USER 10001
COPY --from=builder /out/connector /usr/local/bin/connector
COPY --from=builder /out/ffuf /usr/local/bin/ffuf
COPY --from=builder /out/wordlists /opt/wordlists
ENTRYPOINT ["/usr/local/bin/connector"]
