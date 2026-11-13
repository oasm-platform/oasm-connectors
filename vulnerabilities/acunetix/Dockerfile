# connector image (SDK + client, no bundled tool binary) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY vulnerabilities/acunetix/go.mod vulnerabilities/acunetix/go.sum vulnerabilities/acunetix/
RUN cd vulnerabilities/acunetix && GOWORK=off go mod download
COPY sdk/ sdk/
COPY vulnerabilities/acunetix/ vulnerabilities/acunetix/
RUN cd vulnerabilities/acunetix && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
FROM alpine:3.24 AS runtime
# Named `runtime` so CI rebuilds this stage uncached (`no-cache-filters` in
# scan-and-push.yml): `apk upgrade` pulls alpine fixes published after the
# base tag, and a cached layer would keep shipping the first build's set.
COPY --from=builder /out/connector /usr/local/bin/connector
RUN apk upgrade --no-cache && adduser -D -u 10001 connector
USER 10001
ENTRYPOINT ["/usr/local/bin/connector"]
