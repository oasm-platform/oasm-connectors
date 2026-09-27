# connector image (SDK+tool) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY vulnerabilities/wpscan/go.mod vulnerabilities/wpscan/go.sum vulnerabilities/wpscan/
RUN cd vulnerabilities/wpscan && GOWORK=off go mod download
COPY sdk/ sdk/
COPY vulnerabilities/wpscan/ vulnerabilities/wpscan/
RUN cd vulnerabilities/wpscan && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
FROM wpscanteam/wpscan:v4.1.0
# ponytail: final stage is the tool image itself — wpscan is a Ruby gem at
# /usr/local/bundle/bin/wpscan and needs the ruby runtime + gems at runtime.
# Non-root: the upstream image ships a `wpscan` user (uid 1000, home /wpscan,
# which owns its data dir) and declares User:wpscan in its config — which a
# plain FROM inherits. USER makes that explicit and robust against upstream
# config drift; no adduser/chown needed (user + data dirs already exist and
# are owned correctly).
#
# The two gems below are pinned to clear the CRITICALs left in the 4.1.0 base
# (`.trivyignore` policy: a CRITICAL is never ignorable). No published tag is
# clean — v4.1.0 is the newest, and it still carries both. Exact versions, not
# "latest", so a rebuild of this tag resolves the same way:
#   net-imap  0.6.2  -> 0.6.7    CVE-2026-42257, fixed in >= 0.6.4
#   json      2.18.0 -> 2.21.1   CVE-2026-33210, fixed in >= 2.19.2
# build-base is installed for the two native extensions and removed again, so the
# toolchain does not ship. It must run as root — the base image's default USER is
# wpscan and neither apk nor gem can write there.
USER root
# net-imap is an ordinary gem, so the vulnerable 0.6.2 is uninstalled outright
# and 0.6.7 put in its place: leaving the old copy beside the new one is enough
# for the scan to fail. It goes through the system gem path because that is where
# upstream installed it, not the bundle.
# json is different. 2.18.0 is a *default* gem compiled into this image's Ruby
# 4.0.0, and RubyGems refuses to uninstall a default gem, so the copy stays on
# disk. RubyGems activates the higher version, so 2.21.1 is what actually loads
# and the flagged 2.18.0 is unreachable — .trivyignore records that with an
# expiry rather than editing the gemspec, which would quiet the scanner while the
# loaded code stayed vulnerable.
RUN apk add --no-cache --virtual .build-deps build-base \
 && GEM_HOME=/usr/local/lib/ruby/gems/4.0.0 gem install --no-document net-imap -v 0.6.7 \
 && GEM_HOME=/usr/local/lib/ruby/gems/4.0.0 gem uninstall -x --force net-imap -v 0.6.2 \
 && gem install --no-document json -v 2.21.1 \
 && apk del .build-deps
# Behaviour note for v4: wpscan now needs a reachable WPScan API to enumerate
# plugin/theme vulnerabilities, and it reports an unreachable API or a spent
# token quota as `scan_aborted` rather than as a partial result. The adapter
# already treats scan_aborted as non-fatal (logged, run continues), so such a
# scan yields no findings instead of failing the job. apiToken is a required
# config field, so a token is always sent.
USER wpscan
COPY --from=builder /out/connector /usr/local/bin/connector
ENTRYPOINT ["/usr/local/bin/connector"]