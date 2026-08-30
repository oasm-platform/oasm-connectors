# connector image (SDK + client, no bundled tool binary) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY vulnerabilities/nessus/go.mod vulnerabilities/nessus/go.sum vulnerabilities/nessus/
RUN cd vulnerabilities/nessus && GOWORK=off go mod download
COPY sdk/ sdk/
COPY vulnerabilities/nessus/ vulnerabilities/nessus/
RUN cd vulnerabilities/nessus && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
FROM alpine:3.20
COPY --from=builder /out/connector /usr/local/bin/connector
RUN adduser -D -u 10001 connector
USER 10001
ENTRYPOINT ["/usr/local/bin/connector"]
