# connector image (SDK+tool) — build context: repo root
FROM projectdiscovery/nuclei:v3.4.1 AS tool
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY vulnerabilities/nuclei/go.mod vulnerabilities/nuclei/go.sum vulnerabilities/nuclei/
RUN cd vulnerabilities/nuclei && GOWORK=off go mod download
COPY sdk/ sdk/
COPY vulnerabilities/nuclei/ vulnerabilities/nuclei/
RUN cd vulnerabilities/nuclei && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
FROM alpine:3.20
COPY --from=tool /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /out/connector /usr/local/bin/connector
RUN adduser -D -u 10001 connector
USER 10001
ENTRYPOINT ["/usr/local/bin/connector"]
