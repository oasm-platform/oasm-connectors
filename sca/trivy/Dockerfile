# connector image (SDK + trivy) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY sca/trivy/go.mod sca/trivy/go.sum sca/trivy/
RUN cd sca/trivy && GOWORK=off go mod download
COPY sdk/ sdk/
COPY sca/trivy/ sca/trivy/
RUN cd sca/trivy && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .

# Final stage is the official trivy image, pinned by tag and digest (Trivy
# release tags have been hijacked before): it ships the trivy binary and the
# git client sdk/gitrepo clones with.
FROM aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa
# The base image runs as root; package management happens first, then the
# connector drops to an unprivileged user. Upgrading picks up alpine security
# fixes released after the upstream tag (scan-and-push fails on unpatched
# CRITICALs).
USER root
RUN apk update --no-cache && apk upgrade --no-cache \
 && adduser -D -H -u 10001 connector \
 && mkdir -p /var/cache/oasm-trivy && chown connector:connector /var/cache/oasm-trivy
COPY --from=builder /out/connector /usr/local/bin/connector
USER connector
# Trivy's databases (~1.5 GB unpacked) do not fit the worker's 256 MB /tmp
# tmpfs and the root filesystem is read-only, so the cache is a persisted
# volume shared by every container of this image: downloaded once, refreshed
# when stale, under a lock (see db.go). A new volume copies this directory,
# ownership included, so the unprivileged user can write it.
LABEL oasm.persist="/var/cache/oasm-trivy"
# The worker also pins HOME/XDG_CACHE_HOME under /tmp; git needs a writable
# HOME for its global config lookups.
ENV HOME=/tmp \
    TRIVY_CACHE_DIR=/var/cache/oasm-trivy \
    TRIVY_BIN=/usr/local/bin/trivy
ENTRYPOINT ["/usr/local/bin/connector"]
