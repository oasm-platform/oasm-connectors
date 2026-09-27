# connector image (SDK + Nikto) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY vulnerabilities/nikto/go.mod vulnerabilities/nikto/go.sum vulnerabilities/nikto/
RUN cd vulnerabilities/nikto && GOWORK=off go mod download
COPY sdk/ sdk/
COPY vulnerabilities/nikto/ vulnerabilities/nikto/
RUN cd vulnerabilities/nikto && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
# Final stage is the official Nikto image (alpine + perl + the JSON/SSL/XML
# modules Nikto needs), pinned by tag. Nikto is a Perl script whose plugins and
# databases must sit together, so inheriting the upstream /opt/nikto layout
# beats hand-rolling a Perl install. `sullo/nikto` does not exist on Docker Hub
# — this is the repository the upstream Dockerfile publishes to.
FROM hackllc/nikto:2.6.1
# The base image already runs as the non-root `nikto` user (uid 100) and puts
# /opt/nikto on PATH, so `nikto.pl` resolves by name. Package management must
# happen as root (the base image's default USER is nikto, and apk cannot write
# its log otherwise) before dropping back to nikto.
USER root
# The base image pins alpine 3.23.3, which ships openssl 3.5.5-r0 and so carries
# CVE-2026-31789 (heap overflow in X.509 parsing, fixed in 3.5.6-r0). Upstream
# publishes no newer tag — 2.6.1 is the newest, and `rolling` is the same alpine
# with the same openssl — so the patch has to be applied here. This is the one
# floating input in the build: whatever alpine has shipped as of build time.
# `.trivyignore` forbids ignoring a CRITICAL, which leaves this as the fix.
# `apk update` first: the base image carries no package index.
RUN apk update --no-cache && apk upgrade --no-cache
COPY --from=builder /out/connector /usr/local/bin/connector
USER nikto
ENV HOME=/home/nikto
ENTRYPOINT ["/usr/local/bin/connector"]
