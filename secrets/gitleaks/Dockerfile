# connector image (SDK + gitleaks) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY secrets/gitleaks/go.mod secrets/gitleaks/go.sum secrets/gitleaks/
RUN cd secrets/gitleaks && GOWORK=off go mod download
COPY sdk/ sdk/
COPY secrets/gitleaks/ secrets/gitleaks/
RUN cd secrets/gitleaks && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .

# Final stage is the official gitleaks image, pinned by tag: it ships the
# gitleaks binary and the git client sdk/gitrepo clones with.
FROM zricethezav/gitleaks:v8.30.1
# The base image runs as root; package management happens first, then the
# connector drops to an unprivileged user. `apk update` first: the base image
# carries no package index. Upgrading picks up alpine security fixes released
# after the upstream tag (scan-and-push fails on unpatched CRITICALs).
USER root
RUN apk update --no-cache && apk upgrade --no-cache \
 && adduser -D -H -u 10001 connector
COPY --from=builder /out/connector /usr/local/bin/connector
USER connector
# The worker also pins HOME/XDG_CACHE_HOME under /tmp; git needs a writable
# HOME for its global config lookups.
ENV HOME=/tmp \
    GITLEAKS_BIN=/usr/bin/gitleaks
ENTRYPOINT ["/usr/local/bin/connector"]
