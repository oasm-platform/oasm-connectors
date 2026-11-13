# connector image (SDK+dirsearch) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY url_discovery/dirsearch/go.mod url_discovery/dirsearch/go.sum url_discovery/dirsearch/
RUN cd url_discovery/dirsearch && GOWORK=off go mod download
COPY sdk/ sdk/
COPY url_discovery/dirsearch/ url_discovery/dirsearch/
RUN cd url_discovery/dirsearch && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
# dirsearch wordlists pinned to v0.5.0 and baked into the image so a scan never
# depends on the runtime default ($HOME/.cache/dirsearch or the pip-installed
# db). The current default wordlist is dicc.txt; the ten category presets the
# configSchema enum exposes are fetched from the same tag. `test -s` fails the
# build if any file came back empty, so a bad pin is caught at build time.
RUN apk add --no-cache curl
RUN mkdir -p /out/wordlists/dirsearch && cd /out/wordlists/dirsearch && curl -fsSL -o dicc.txt "https://raw.githubusercontent.com/maurosoria/dirsearch/v0.5.0/db/dicc.txt" && for f in common web conf extensions backups vcs db logs keys; do curl -fsSL -o "$f.txt" "https://raw.githubusercontent.com/maurosoria/dirsearch/v0.5.0/db/categories/$f.txt"; done && for f in *.txt; do test -s "$f"; done
FROM python:3.13-slim AS runtime
# Named `runtime` so CI rebuilds this stage uncached (`no-cache-filters` in
# scan-and-push.yml): the upgrade pulls debian-security fixes published after
# the base tag, and a cached layer would keep shipping the first build's set.
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq \
 && rm -rf /var/lib/apt/lists/*
# dirsearch 0.5.0 pinned from PyPI; the console script `dirsearch` lands on
# PATH (/usr/local/bin), asserted here so a broken install fails the build.
# --break-system-packages is required on Debian's externally-managed Python.
#
# dirsearch pins pyopenssl==26.1.0, which caps cryptography below 48 and so
# keeps three cryptography advisories fixed in 48.0.1-50.0.0. pyopenssl 26.4.0
# is the first release that accepts cryptography 50, and dirsearch imports
# neither package itself, so both move past the pin (pip warns about the pin
# and installs anyway). `dirsearch --version` proves it still starts.
#
# native/ is the Rust source of dirsearch's optional native backend. It needs
# Python >= 3.14 plus a Rust toolchain to compile, so on this image it can
# never be built or loaded; its Cargo.lock only feeds the scanner. pip itself
# is not needed at runtime and vendors its own urllib3/msgpack/setuptools, so
# it goes too.
RUN pip install --no-cache-dir --break-system-packages dirsearch==0.5.0 \
 && pip install --no-cache-dir --break-system-packages pyopenssl==26.4.0 cryptography==50.0.2 \
 && rm -rf /usr/local/lib/python3.13/site-packages/dirsearch/native \
 && pip uninstall -y --break-system-packages pip \
 && command -v dirsearch && dirsearch --version
# dirsearch writes per-run state (session/report cache) under $HOME; give the
# non-root user a writable HOME or those writes fail. DIRSEARCH_WORDLIST_DIR
# points the adapter's wordlist resolution at the baked wordlists.
RUN useradd --create-home --uid 10001 connector
COPY --from=builder /out/connector /usr/local/bin/connector
COPY --from=builder /out/wordlists /opt/wordlists
ENV HOME=/home/connector DIRSEARCH_WORDLIST_DIR=/opt/wordlists/dirsearch
USER 10001
ENTRYPOINT ["/usr/local/bin/connector"]
