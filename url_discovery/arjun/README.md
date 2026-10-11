# Arjun Connector

Runs [s0md3v/Arjun](https://github.com/s0md3v/Arjun) 2.2.7 via the OASM Worker gRPC bridge. Discovers hidden HTTP query parameters for a URL by probing a parameter-name wordlist against the endpoint.

## Requirements

- Go 1.26+, Docker, Worker reachable at `WORKER_GRPC_ADDR`
- Tool binary `arjun` installed in the image final stage via `pip install arjun==2.2.7` (pinned from PyPI, not repo master). The pip wheel bundles its own wordlists under the package's `arjun/db/` directory.
- **Network egress required at scan time**: Arjun probes the target endpoint directly.
- No writable `$HOME` is required (unlike katana): Arjun keeps its state in a per-run temp dir. `ENV HOME=/home/connector` is still set so the non-root user has a valid home.

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Configuration

| Parameter | env | default | mandatory | description |
|-----------|-----|---------|-----------|-------------|
| Worker address | `WORKER_GRPC_ADDR` | `localhost:50051` | yes | Worker gRPC endpoint (missing → fatal) |
| Worker token | `WORKER_TOKEN` | `` | no | Auth token if Worker requires it |
| Execution ID | `EXECUTION_ID` | — | yes | Job identity; the Worker routes `ExecuteJob` by it |
| Target | `inputs.target` | — | yes | URL to discover parameters for; a bare host is assumed `https://` |
| arjun binary | `ARJUN_BIN` | `arjun` | no | Override path to the arjun console script |
| Config profile | `OASM_CONFIG` | `` | no | JSON config profile (see below) |

`configSchema` parameters (all optional, camelCase keys in `OASM_CONFIG`):

| Key | type | default | description |
|-----|------|---------|-------------|
| `wordlist` | string (`small`\|`medium`\|`large`) | medium | Bundled parameter wordlist passed verbatim to Arjun `-w` |
| `method` | string (`GET`\|`POST`\|`XML`\|`JSON`) | GET | HTTP method used to probe parameters (`arjun -m`) |
| `threads` | integer (≥1) | 5 | Concurrent workers (`arjun -t`) |
| `chunkSize` | integer (≥1) | 250 | Parameters per request (`arjun -c`). **Ignored when `method != GET`** — upstream forces `-c 500` |
| `timeout` | integer (≥1) | 15 | Per-request timeout in seconds (`arjun -T`) |
| `delay` | number (≥0) | — | Delay between requests seconds (`arjun -d`); emitted only when > 0 |
| `stable` | boolean | false | Prefer stability over speed (`arjun --stable`); forces threads to 1 upstream |
| `rateLimit` | integer (≥1) | 9999 | Maximum requests/second (`arjun --rate-limit`) |
| `disableRedirects` | boolean | false | Do not follow redirects (`arjun --disable-redirects`) |
| `headers` | string[] | — | Extra request headers, one per entry (`arjun --headers`); omitted entirely when empty |
| `include` | string | — | Comma-separated known parameters to include in every request (`arjun --include`) |
| `maxUrls` | integer (1–100000) | 10000 | Adapter-level cap on emitted findings; on hit the run is truncated and partial results are kept |

### Bundled wordlists

The Arjun wheel ships its own parameter-name databases inside the installed package directory (`arjun/db/`): `small.txt`, `medium.txt`, `large.txt`, plus `special.json`. Arjun's `-w` shortcut resolves a bare name (`small`/`medium`/`large`) against that directory, so this image bundles **no SecLists** and needs no external wordlist volume. `medium` is the default.

### Deliberately not exposed

- **`-oB`** — replays every discovered request through an external Burp proxy; requires a Burp instance and leaks traffic to a third party.
- **`--passive`** — sends the host to `web.archive.org`, `otx.alienvault.com` and `commoncrawl.org`; an egress/opsec violation for a scan job.
- **Bare `--headers`** — an empty header list launches Arjun's `nano` editor interactively; the adapter only emits `--headers` when at least one entry is configured.
- **`-oT` / `-i` / `--casing`** — text-output, import-file and casing modes: outside the JSON-collection contract the adapter parses (`-oJ`), and `-i` would let an operator inject arbitrary file paths.

## Output contract

Arjun is file-based: it writes its JSON result to `-oJ <file>` and prints only status markers to stdout/stderr. The adapter emits one `Finding` per unique discovered parameter as **`<url>?<param>=`** (`Name` = `MatchedAt`, `Severity=info`, `Host`=target hostname). When a run discovers **no** parameters Arjun writes **no output file at all**, which the adapter treats as a clean, zero-findings success rather than an error.

## Example config profile

```yaml
# Connector profile submitted to the Worker (ExecutionCommand spec)
slug: arjun
image: ghcr.io/oasm-platform/connector-arjun:2.2.7
inputs:
  target: https://example.com/search
config:
  wordlist: medium
  method: GET
  threads: 5
```

## Deployment

### Docker

```bash
docker build -t ghcr.io/oasm-platform/connector-arjun:2.2.7 -f url_discovery/arjun/Dockerfile .
docker run --rm -e WORKER_GRPC_ADDR=worker:50051 -e EXECUTION_ID=job-1 \
  ghcr.io/oasm-platform/connector-arjun:2.2.7
```

### Manual

```bash
cd url_discovery/arjun && go run .
```

## Behavior

- `adapter.go` — `ArjunAdapter` runs Arjun, reads its `-oJ` file, and streams one `Finding` per unique discovered parameter `<url>?<param>=`; wraps Arjun in a hard 20m timeout; caps output at `maxUrls`; treats a missing output file as zero-findings success; maps Arjun's "target skipped" markers to a fatal error
- `main.go` — wires `ArjunAdapter` + SDK (`sdk/connector`, `sdk/runtime`)
- `arjun.go` — `OASM_CONFIG` parsing + `buildArjunArgs` argv assembly (fixed deterministic order; `-w`/`-m`/`-t`/`-c`/`-T`/`--rate-limit` always emitted)
- `manifest.yaml` — source of truth for `manifest.json` (capability `url_discovery`; image `ghcr.io/oasm-platform/connector-arjun:2.2.7` is the SDK+tool bundle, not upstream)
- `Dockerfile` — `golang:1.26-alpine` builder (static connector, `CGO_ENABLED=0`) → `python:3.13-slim` final stage installing `arjun==2.2.7`, non-root `connector` (uid 10001)
- `testdata/fake-arjun/` — test stub driven by `FAKE_MODE` (`default`, `empty`, `skip`, `fail`, `hang`, `many`)

### Exit policy

Arjun's own signals are unreliable and it writes no file when it finds nothing, so the adapter fails only when:

1. the parent context is cancelled → `ctx.Err()`, or
2. the 20m hard timeout elapses → `arjun: timed out after …`, or
3. the output file exists but cannot be read/parsed → `arjun: read output: …` (a **missing** file is not an error), or
4. zero findings were emitted **and** a "target skipped" marker is present in the combined output tail → fatal `arjun: target skipped: …`, or
5. the process exited nonzero **and** no findings were emitted → `arjun: <error>: <tail>`.

A nonzero exit that still produced findings, and a bare zero-findings run with no skip marker, are both clean successes.

## Testing

```bash
cd url_discovery/arjun && go test ./... -v -count=1
cd url_discovery/arjun && go vet ./...

# Real discovery against a live target with a pinned arjun 2.2.7 (build-tagged,
# writes e2e-findings.jsonl):
cd url_discovery/arjun && ARJUN_BIN=/usr/local/bin/arjun E2E_TARGET=https://example.com/ \
  go test -tags e2e -run TestArjunE2E_RealDiscovery -v -count=1
```

The E2E test fatals when `ARJUN_BIN` or `E2E_TARGET` is unset. Zero findings is a clean success (Arjun writes no file when it finds nothing), so the test asserts a clean run and validates the `<url>?<param>=` shape of any findings emitted.

## 14-step trace

Core (`manifest.json` via `ConnectorRegistry`) → `WorkerStream ExecutionCommand{spec{image, inputs}}` → Worker `ExecutionManager` → `DockerRuntime.Create(Image: spec.Image)` via `docker.sock` → Connector SDK → `ArjunAdapter.Execute` → Arjun probes the target → Core persist (`discovered_urls`).
