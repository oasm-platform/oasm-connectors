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
#
# Named `runtime` on purpose: CI builds this stage with `no-cache-filters:
# runtime` (see .github/workflows/scan-and-push.yml). The upgrade layer below
# depends on what debian-security served at build time, not on anything in the
# repo, so a cached copy would keep shipping the first build's packages long
# after a fix is published.
FROM zaproxy/zap-stable:2.17.0 AS runtime
# The ZAP image already runs as the non-root `zap` user (uid 1000) and ships
# /zap on PATH, so `zap.sh` resolves without extra setup. Package management
# must happen as root (the base image's default USER is zap, and apt cannot
# write its state otherwise) before dropping back to zap.
USER root
# ZAP 2.17.0 is the newest release, and its dated rebuilds lag debian-security
# (firefox-esr, apt and friends), so pending Debian 12 fixes are applied in
# place rather than moving off the pinned ZAP. This is the one floating input in
# the build: whatever debian-security has published as of build time. ZAP itself
# lives under /zap and is not a Debian package, so the upgrade cannot move it.
# -qq keeps the build log readable, and the base image ships no apt index.
#
# The base image is built for interactive and scripted use: a C toolchain
# (make, autoconf, gcc, g++), the full JDK, git, Python packaging, and the
# openbox/xterm/x11vnc/xvfb desktop behind its Webswing UI. The connector only
# runs `zap.sh -cmd -autorun` on the JRE, plus firefox-esr in headless mode for
# the optional AJAX spider (ZAP's default browserId is firefox-headless, which
# needs no X server). Everything else is purged with its now-orphaned
# dependencies. That drops ~190 of ~520 packages, linux-libc-dev among them,
# whose kernel-header advisories alone were over 60% of this image's findings,
# none of them fixable by an upgrade.
#
# The JRE is a dependency of the JDK, so it is marked manual first or the
# autoremove would take it too. netbase (/etc/services, /etc/protocols) is kept
# as a precaution: it is a few KB, carries no advisories, and ZAP scripts or
# add-ons may look up service names. The pip the base image installs over Debian's
# python3-pip goes as well: it vendors setuptools/urllib3 copies the scanner
# reports, and nothing here runs pip.
#
# The trailing checks fail the build if the purge ever takes something the
# connector needs.
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq \
 && pip3 uninstall -y --break-system-packages pip \
 && apt-mark manual openjdk-17-jre-headless netbase >/dev/null \
 && DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq --auto-remove \
      make automake autoconf gcc g++ git \
      openjdk-17-jdk openjdk-17-jdk-headless openjdk-17-jre \
      openbox xterm x11vnc xvfb python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && java -version \
 && firefox-esr --version \
 && ! dpkg -s linux-libc-dev >/dev/null 2>&1
COPY --from=builder /out/connector /usr/local/bin/connector
USER zap
ENV HOME=/home/zap
ENTRYPOINT ["/usr/local/bin/connector"]
