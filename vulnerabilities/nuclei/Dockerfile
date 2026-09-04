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
# Offline runtime: templates are baked into /opt/nuclei-templates at build
# time. nuclei ignores the NUCLEI_TEMPLATES_DIR env var (it honors only the
# -t/-ud flags and its config file), so the adapter always passes -t
# explicitly. HOME/XDG_CACHE_HOME stay under /tmp (the worker mounts Tmpfs
# there); `nuclei -ut` defaults to HOME and would land in /tmp, hence -ud
# targets /opt before privileges drop. /tmp is world-writable so uid 10001
# can create its config/cache dirs at runtime.
ENV HOME=/tmp XDG_CACHE_HOME=/tmp/.cache
RUN mkdir -p /opt/nuclei-templates /tmp/.config/nuclei /tmp/.cache \
    && nuclei -ut -ud /opt/nuclei-templates || true \
    && chown -R 10001:10001 /opt/nuclei-templates /tmp/.config /tmp/.cache \
    && chmod 1777 /tmp \
    && chmod -R a+rX /opt/nuclei-templates
RUN adduser -D -u 10001 connector
USER 10001
ENTRYPOINT ["/usr/local/bin/connector"]
