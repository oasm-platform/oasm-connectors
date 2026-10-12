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
RUN GOWORK=off GOBIN=/out CGO_ENABLED=0 go install github.com/ffuf/ffuf/v2@v2.3.0
RUN apk add --no-cache curl
# Bundled wordlists pinned to one SecLists commit (2026.1) so image builds are
# reproducible and no full tarball ships. `test -s` fails the build on any empty
# download (a moved file would otherwise land as a 0-byte "wordlist").
RUN mkdir -p /out/wordlists/ffuf && cd /out/wordlists/ffuf && for f in common.txt raft-small-directories.txt raft-medium-directories.txt big.txt DirBuster-2007_directory-list-2.3-small.txt DirBuster-2007_directory-list-2.3-medium.txt; do curl -fsSL -O "https://raw.githubusercontent.com/danielmiessler/SecLists/190c6f7bd58c847ceadfe57d9853592737f059e8/Discovery/Web-Content/$f"; done && for f in *.txt; do test -s "$f"; done
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 connector
# ffuf needs no writable HOME (unlike katana); the env only points the adapter at
# the bundled wordlists. HOME stays set for consistency across connectors.
ENV HOME=/home/connector FFUF_WORDLIST_DIR=/opt/wordlists/ffuf
USER 10001
COPY --from=builder /out/connector /usr/local/bin/connector
COPY --from=builder /out/ffuf /usr/local/bin/ffuf
COPY --from=builder /out/wordlists /opt/wordlists
ENTRYPOINT ["/usr/local/bin/connector"]
