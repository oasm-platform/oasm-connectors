# connector image (SDK+tool) — build context: repo root
FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY vulnerabilities/wpscan/go.mod vulnerabilities/wpscan/go.sum vulnerabilities/wpscan/
RUN cd vulnerabilities/wpscan && GOWORK=off go mod download
COPY sdk/ sdk/
COPY vulnerabilities/wpscan/ vulnerabilities/wpscan/
RUN cd vulnerabilities/wpscan && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
FROM wpscanteam/wpscan:v4.2.1 AS runtime
# ponytail: final stage is the tool image itself — wpscan is a Ruby gem at
# /usr/local/bundle/bin/wpscan and needs the ruby runtime + gems at runtime.
# Non-root: the upstream image ships a `wpscan` user (uid 1000, home /wpscan,
# which owns its data dir) and declares User:wpscan in its config — which a
# plain FROM inherits. USER makes that explicit and robust against upstream
# config drift; no adduser/chown needed (user + data dirs already exist and
# are owned correctly).
#
# Upstream builds the image with `bundle install` and no Gemfile.lock, so its
# gems resolve to the newest release allowed by wpscan.gemspec on the day the
# tag is built. The 4.2.1 tag (built 2026-11-19) therefore ships the fixes the
# 4.2.0 base needed swapped in by hand, and every gem is inherited as published:
#   activesupport 8.1.4.1  security release (gemspec >= 7.1, < 8.2)
#   addressable   2.9.2    (gemspec ~> 2.9)
#   net-imap      >= 0.6.4 CVE-2026-42257 — shipped fixed.
#   json          3.1.0    CVE-2026-33210 fixed in >= 2.19.2 — RubyGems activates
#                          3.1.0 over the interpreter's default copy. The default
#                          stays on disk (compiled into Ruby, not uninstallable);
#                          .trivyignore records that shadowed default with an
#                          expiry. Drop that entry once the base Ruby's default
#                          json is >= 2.19.2.
# If a later tag ships a gem behind its fix, swap it here: `gem install` the
# fixed version and `gem uninstall -x -I` the stale one (a copy left on disk
# still fails the scan), then keep the `wpscan --version` boot check.
#
# Named `runtime` so CI rebuilds this stage uncached (`no-cache-filters` in
# scan-and-push.yml): `apk upgrade` pulls alpine fixes published after the
# base tag, and a cached layer would keep shipping the first build's set.
USER root
RUN apk upgrade --no-cache \
 && su wpscan -s /bin/sh -c 'wpscan --version' >/dev/null
# Behaviour note for v4: wpscan now needs a reachable WPScan API to enumerate
# plugin/theme vulnerabilities, and it reports an unreachable API or a spent
# token quota as `scan_aborted` rather than as a partial result. The adapter
# already treats scan_aborted as non-fatal (logged, run continues), so such a
# scan yields no findings instead of failing the job. apiToken is a required
# config field, so a token is always sent.
USER wpscan
COPY --from=builder /out/connector /usr/local/bin/connector
ENTRYPOINT ["/usr/local/bin/connector"]