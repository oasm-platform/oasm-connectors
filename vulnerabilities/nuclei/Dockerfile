# connector image (SDK) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY vulnerabilities/nuclei/go.mod vulnerabilities/nuclei/go.sum vulnerabilities/nuclei/
RUN cd vulnerabilities/nuclei && GOWORK=off go mod download
COPY sdk/ sdk/
COPY vulnerabilities/nuclei/ vulnerabilities/nuclei/
RUN cd vulnerabilities/nuclei && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
RUN cd vulnerabilities/nuclei && CGO_ENABLED=0 GOWORK=off go run ./cmd/templates /opt/nuclei-templates
FROM alpine:3.20
COPY --from=builder /opt/nuclei-templates /opt/nuclei-templates
COPY --from=builder /out/connector /usr/local/bin/connector
# Offline runtime: templates are baked into /opt/nuclei-templates at build
# time via the cmd/templates Go helper (nuclei installer API).
# HOME/XDG_CACHE_HOME stay under /tmp (the worker mounts Tmpfs there);
# /tmp is world-writable so uid 10001 can create config/cache dirs at runtime.
ENV HOME=/tmp XDG_CACHE_HOME=/tmp/.cache
# No oasm.persist label: templates are baked read-only into the image and the
# engine only reads them at runtime. A named volume here would shadow fresh
# baked templates with stale ones after every image rebuild.
ENV NUCLEI_TEMPLATE_DIR=/opt/nuclei-templates NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
RUN mkdir -p /tmp/.config/nuclei /tmp/.cache
RUN test -n "$(ls -A /opt/nuclei-templates)" \
    && echo "nuclei-templates baked: $(find /opt/nuclei-templates -name '*.yaml' | wc -l) templates" \
    && ls /opt/nuclei-templates | head -5
RUN chown -R 10001:10001 /opt/nuclei-templates /tmp/.config /tmp/.cache \
    && chmod 1777 /tmp \
    && chmod -R a+rX /opt/nuclei-templates
RUN adduser -D -u 10001 connector
USER 10001
ENTRYPOINT ["/usr/local/bin/connector"]
