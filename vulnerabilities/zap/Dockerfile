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
# /zap on PATH, so `zap.sh` resolves without extra setup. Package management
# must happen as root (the base image's default USER is zap, and apt cannot
# write its state otherwise) before dropping back to zap.
USER root
# ZAP 2.17.0 is the newest release and every dated rebuild of it
# (zap-stable:20260807 and later) still ships the same firefox-esr 140.13.0esr,
# so no upstream tag carries the fix for the CVEs fixed in 140.14.0esr. Upgrade
# in place instead of moving off the pinned ZAP. This is the one floating input
# in the build: whatever debian-security has published as of build time.
# `.trivyignore` forbids ignoring a CRITICAL, which leaves this as the fix.
# --only-upgrade keeps the pinned ZAP/JRE/add-on set untouched, -qq keeps the
# build log readable, and the base image ships no apt index.
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends --only-upgrade firefox-esr \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/connector /usr/local/bin/connector
USER zap
ENV HOME=/home/zap
ENTRYPOINT ["/usr/local/bin/connector"]
