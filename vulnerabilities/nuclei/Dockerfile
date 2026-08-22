# connector image (SDK+tool) — built from ./Dockerfile, not upstream image
FROM projectdiscovery/nuclei:3.3.0 AS tool
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/connector ./vulnerabilities/nuclei
FROM alpine:3.20
COPY --from=tool /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /out/connector /usr/local/bin/connector
RUN adduser -D -u 10001 connector
USER 10001
ENTRYPOINT ["/usr/local/bin/connector"]
