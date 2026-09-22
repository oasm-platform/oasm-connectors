# connector image (SDK+nmap) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY ports_scanner/nmap/go.mod ports_scanner/nmap/go.sum ports_scanner/nmap/
RUN cd ports_scanner/nmap && GOWORK=off go mod download
COPY sdk/ sdk/
COPY ports_scanner/nmap/ ports_scanner/nmap/
RUN cd ports_scanner/nmap && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
FROM alpine:3.22
# nmap from the distro (7.97-r0 in alpine 3.22): pinned by the base image tag
# and far cheaper than a source build (15 MB tarball + autoconf/lua/libpcap
# toolchain). The container runs unprivileged, so the adapter never asks for a
# raw-socket scan; nmap's TCP connect fallback is what runs.
RUN apk add --no-cache ca-certificates nmap && adduser -D -u 10001 connector
# nmap writes its service-cache/config under $HOME; the non-root user needs a
# writable HOME or scans fail with write errors.
ENV HOME=/home/connector
USER 10001
COPY --from=builder /out/connector /usr/local/bin/connector
ENTRYPOINT ["/usr/local/bin/connector"]
