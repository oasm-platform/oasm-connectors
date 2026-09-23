# connector image (SDK + client, no bundled tool binary) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY vulnerabilities/openvas/go.mod vulnerabilities/openvas/go.sum vulnerabilities/openvas/
RUN cd vulnerabilities/openvas && GOWORK=off go mod download
COPY sdk/ sdk/
COPY vulnerabilities/openvas/ vulnerabilities/openvas/
RUN cd vulnerabilities/openvas && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
FROM alpine:3.20
COPY --from=builder /out/connector /usr/local/bin/connector
RUN adduser -D -u 10001 connector
USER 10001
ENTRYPOINT ["/usr/local/bin/connector"]
