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
# (63 MB static binary, functional crawl; no gcc/musl-dev needed — upstream's own
# image installing gcc is not required). The official image also bundles chromium
# and bind-tools for headless crawling; excluded here because headless is off
# (no -hl). Building from source keeps multi-arch builds and a deterministic pin.
RUN GOWORK=off GOBIN=/out CGO_ENABLED=0 go install github.com/projectdiscovery/katana/cmd/katana@v1.7.0
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 connector
# katana writes $HOME/.config/katana/{field-config,form-config}.yaml on first run;
# the image must give the non-root user a writable HOME or katana logs write errors.
ENV HOME=/home/connector
USER 10001
COPY --from=builder /out/connector /usr/local/bin/connector
COPY --from=builder /out/katana /usr/local/bin/katana
ENTRYPOINT ["/usr/local/bin/connector"]
