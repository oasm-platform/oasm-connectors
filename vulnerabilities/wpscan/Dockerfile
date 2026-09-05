# connector image (SDK+tool) — build context: repo root
FROM wpscanteam/wpscan:v3.8.25 AS tool
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY vulnerabilities/wpscan/go.mod vulnerabilities/wpscan/go.sum vulnerabilities/wpscan/
RUN cd vulnerabilities/wpscan && GOWORK=off go mod download
COPY sdk/ sdk/
COPY vulnerabilities/wpscan/ vulnerabilities/wpscan/
RUN cd vulnerabilities/wpscan && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
FROM wpscanteam/wpscan:v3.8.25
# ponytail: final stage is the tool image itself — wpscan is a Ruby gem at
# /usr/local/bundle/bin/wpscan and needs the ruby runtime + gems at runtime.
# Non-root: the upstream image ships a `wpscan` user (uid 1000, home /wpscan,
# which owns its data dir) and declares User:wpscan in its config — which a
# plain FROM inherits. USER makes that explicit and robust against upstream
# config drift; no adduser/chown needed (user + data dirs already exist and
# are owned correctly).
USER wpscan
COPY --from=builder /out/connector /usr/local/bin/connector
ENTRYPOINT ["/usr/local/bin/connector"]