# connector image (SDK+tool) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY vulnerabilities/wpscan/go.mod vulnerabilities/wpscan/go.sum vulnerabilities/wpscan/
RUN cd vulnerabilities/wpscan && GOWORK=off go mod download
COPY sdk/ sdk/
COPY vulnerabilities/wpscan/ vulnerabilities/wpscan/
RUN cd vulnerabilities/wpscan && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
FROM wpscanteam/wpscan:v4.2.0
# ponytail: final stage is the tool image itself — wpscan is a Ruby gem at
# /usr/local/bundle/bin/wpscan and needs the ruby runtime + gems at runtime.
# Non-root: the upstream image ships a `wpscan` user (uid 1000, home /wpscan,
# which owns its data dir) and declares User:wpscan in its config — which a
# plain FROM inherits. USER makes that explicit and robust against upstream
# config drift; no adduser/chown needed (user + data dirs already exist and
# are owned correctly).
#
# The 4.2.0 base already carries the gems the 4.1.0 base needed patched by hand,
# so this stage inherits them as published and runs no gem surgery:
#   net-imap  0.6.4.1  CVE-2026-42257 fixed in >= 0.6.4 — shipped fixed.
#   json      3.1.0    CVE-2026-33210 fixed in >= 2.19.2 — RubyGems activates
#                      3.1.0 over the interpreter's default 2.18.0. The default
#                      copy stays on disk (compiled into Ruby, not uninstallable);
#                      .trivyignore records that shadowed default with an expiry.
# Revisit when a newer base ships a Ruby whose default json is >= 2.19.2, then
# the .trivyignore entry can go.
# Behaviour note for v4: wpscan now needs a reachable WPScan API to enumerate
# plugin/theme vulnerabilities, and it reports an unreachable API or a spent
# token quota as `scan_aborted` rather than as a partial result. The adapter
# already treats scan_aborted as non-fatal (logged, run continues), so such a
# scan yields no findings instead of failing the job. apiToken is a required
# config field, so a token is always sent.
USER wpscan
COPY --from=builder /out/connector /usr/local/bin/connector
ENTRYPOINT ["/usr/local/bin/connector"]