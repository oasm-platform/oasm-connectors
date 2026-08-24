FROM wpscanteam/wpscan:3.8.25 AS tool

FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/connector ./vulnerabilities/wpscan

FROM alpine:3.20
COPY --from=tool /usr/local/bin/wpscan /usr/local/bin/wpscan
COPY --from=builder /out/connector /usr/local/bin/connector
RUN adduser -D -u 10001 connector
USER 10001
ENTRYPOINT ["/usr/local/bin/connector"]
