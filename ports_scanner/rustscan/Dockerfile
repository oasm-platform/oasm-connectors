# connector image (SDK+rustscan) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY ports_scanner/rustscan/go.mod ports_scanner/rustscan/go.sum ports_scanner/rustscan/
RUN cd ports_scanner/rustscan && GOWORK=off go mod download
COPY sdk/ sdk/
COPY ports_scanner/rustscan/ ports_scanner/rustscan/
RUN cd ports_scanner/rustscan && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .

# rustscan has no distro package, and the official image stopped at 2.3.0 (the
# 2.4.1 release dropped its Dockerfile), so the binary comes from the pinned
# GitHub release asset and its digest is verified before it is unpacked. The
# asset is a zip wrapping a tar.gz — hence unzip -p | tar -xz. The binary is
# musl-static, which is why it runs on alpine unchanged; it needs no nmap (the
# adapter stays in greppable mode, which is what disables rustscan's nmap pass).
# ponytail: x86_64 only, matching what CI builds; add the aarch64 asset
# (aarch64-linux-rustscan.zip + its digest) when an arm64 image is needed.
FROM alpine:3.22 AS rustscan
ARG RUSTSCAN_VERSION=2.4.1
ARG RUSTSCAN_SHA256=f3a4365d939e3b81f25ba8c37852ce9ac9e938c3cc882c5b3e6fff6152c740be
RUN apk add --no-cache curl unzip \
 && curl -fsSL -o /tmp/rustscan.zip "https://github.com/bee-san/RustScan/releases/download/${RUSTSCAN_VERSION}/x86_64-linux-rustscan.tar.gz.zip" \
 && echo "${RUSTSCAN_SHA256}  /tmp/rustscan.zip" | sha256sum -c - \
 && mkdir -p /out \
 && unzip -p /tmp/rustscan.zip | tar -xz -C /out \
 && curl -fsSL -o /out/LICENSE "https://raw.githubusercontent.com/bee-san/RustScan/${RUSTSCAN_VERSION}/LICENSE"

FROM alpine:3.22
# rustscan is GPL-3.0: the licence text ships with the binary the image conveys.
COPY --from=rustscan /out/rustscan /usr/local/bin/rustscan
COPY --from=rustscan /out/LICENSE /usr/share/licenses/rustscan/LICENSE
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 connector
# The connector only ever runs rustscan with -n (no config file), but a writable
# HOME keeps the tool from failing on any path that still wants $HOME.
ENV HOME=/home/connector
USER 10001
COPY --from=builder /out/connector /usr/local/bin/connector
ENTRYPOINT ["/usr/local/bin/connector"]
