# connector image (SDK + ZAP) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY vulnerabilities/zap/go.mod vulnerabilities/zap/go.sum vulnerabilities/zap/
RUN cd vulnerabilities/zap && GOWORK=off go mod download
COPY sdk/ sdk/
COPY vulnerabilities/zap/ vulnerabilities/zap/
RUN cd vulnerabilities/zap && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
# Final stage is the official ZAP image: it already ships the JVM, zap.sh and
# the automation + report-generation add-ons the connector drives. Inheriting
# it (like wpscan inherits wpscanteam/wpscan) keeps ZAP version-pinned and
# avoids a hand-rolled Java install.
FROM zaproxy/zap-stable:2.17.0
# The ZAP image already runs as the non-root `zap` user (uid 1000) and ships
# /zap on PATH, so `zap.sh` resolves without extra setup. COPY must happen as
# root (the base image's default USER is zap) before dropping back to zap.
USER root
COPY --from=builder /out/connector /usr/local/bin/connector
USER zap
ENV HOME=/home/zap
ENTRYPOINT ["/usr/local/bin/connector"]
