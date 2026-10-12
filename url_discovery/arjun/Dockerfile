# connector image (SDK+arjun) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY url_discovery/arjun/go.mod url_discovery/arjun/go.sum url_discovery/arjun/
RUN cd url_discovery/arjun && GOWORK=off go mod download
COPY sdk/ sdk/
COPY url_discovery/arjun/ url_discovery/arjun/
RUN cd url_discovery/arjun && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
# Arjun 2.2.7 pinned from PyPI (not repo master). The wheel bundles its own
# wordlists under arjun/db/ (small|medium|large.txt + special.json), which the
# -w <name> shortcut resolves against the package dir — so no SecLists bundle
# and no separate wordlist volume are shipped. Installed as root into the
# system site-packages; the `arjun` console script lands in /usr/local/bin,
# which the non-root user resolves via PATH (ARJUN_BIN defaults to "arjun").
FROM python:3.13-slim
RUN pip install --no-cache-dir --break-system-packages arjun==2.2.7
RUN useradd --create-home --uid 10001 connector
COPY --from=builder /out/connector /usr/local/bin/connector
ENV HOME=/home/connector
USER 10001
ENTRYPOINT ["/usr/local/bin/connector"]
