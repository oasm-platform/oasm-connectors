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
# /opt/nikto on PATH, so `nikto.pl` resolves by name. COPY must happen as root
# (the base image's default USER is nikto) before dropping back to nikto.
USER root
COPY --from=builder /out/connector /usr/local/bin/connector
USER nikto
ENV HOME=/home/nikto
ENTRYPOINT ["/usr/local/bin/connector"]
