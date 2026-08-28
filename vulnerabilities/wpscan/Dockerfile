# connector image (SDK+tool) — build context: repo root
FROM wpscanteam/wpscan:3.8.25 AS tool
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY vulnerabilities/wpscan/go.mod vulnerabilities/wpscan/go.sum vulnerabilities/wpscan/
RUN cd vulnerabilities/wpscan && GOWORK=off go mod download
COPY sdk/ sdk/
COPY vulnerabilities/wpscan/ vulnerabilities/wpscan/
RUN cd vulnerabilities/wpscan && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
FROM alpine:3.20
COPY --from=tool /usr/local/bin/wpscan /usr/local/bin/wpscan
COPY --from=builder /out/connector /usr/local/bin/connector
RUN adduser -D -u 10001 connector
USER 10001
ENTRYPOINT ["/usr/local/bin/connector"]
