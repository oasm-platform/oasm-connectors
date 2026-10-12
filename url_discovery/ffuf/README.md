# ffuf Connector

Runs [ffuf/ffuf](https://github.com/ffuf/ffuf) 2.3.0 via the OASM Worker gRPC bridge. Fuzzes a target URL path base with bundled wordlists to discover directories, files, and endpoints.

## Requirements

- Go 1.26+, Docker, Worker reachable at `WORKER_GRPC_ADDR`
- Tool binary `ffuf` compiled from source and pinned to `v2.3.0` in the image builder stage
- **Network egress required at scan time**: ffuf sends requests to the target directly.
- **Bundled wordlists**: six SecLists files pinned to commit `190c6f7bd58c847ceadfe57d9853592737f059e8` (SecLists 2026.1) are copied into `/opt/wordlists/ffuf`; no full tarball ships. `FFUF_WORDLIST_DIR` overrides the directory.

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Configuration

| Parameter | env | default | mandatory | description |
|-----------|-----|---------|-----------|-------------|
| Worker address | `WORKER_GRPC_ADDR` | `localhost:50051` | yes | Worker gRPC endpoint (missing → fatal) |
| Worker token | `WORKER_TOKEN` | `` | no | Auth token if Worker requires it |
| Execution ID | `EXECUTION_ID` | — | yes | Job identity; the Worker routes `ExecuteJob` by it |
| Target | `inputs.target` | — | yes | Base URL to fuzz; missing scheme defaults to https, any path is kept as the fuzz base |
| ffuf binary | `FFUF_BIN` | `ffuf` | no | Override path to the ffuf binary |
| Wordlist dir | `FFUF_WORDLIST_DIR` | `/opt/wordlists/ffuf` | no | Directory the `wordlist` enum resolves under |
| Config profile | `OASM_CONFIG` | `` | no | JSON config profile (see below) |

`configSchema` parameters (all optional, camelCase keys in `OASM_CONFIG`):

| Key | type | default | description |
|-----|------|---------|-------------|
| `wordlist` | enum (common, raft-small-directories, raft-medium-directories, big, dirbuster-small, dirbuster-medium) | `common` | Bundled wordlist to fuzz with (`ffuf -w`); resolved under `FFUF_WORDLIST_DIR` |
| `extensions` | string[] | — | Append these extensions to each wordlist entry (`ffuf -e`) |
| `matchCodes` | string | — | Status codes to match (`ffuf -mc`) |
| `filterCodes` | string | — | Status codes to filter out (`ffuf -fc`) |
| `filterSize` | string | — | Filter responses of this size in bytes (`ffuf -fs`) |
| `recursion` | boolean | false | Recurse into matched directories (`ffuf -recursion`) |
| `recursionDepth` | integer (≥1) | — | Max recursion depth (`ffuf -recursion-depth`); only when recursion is on |
| `threads` | integer (≥1) | 40 | Concurrent threads (`ffuf -t`) |
| `rate` | integer (≥0) | — | Requests per second, 0 = unlimited (`ffuf -rate`) |
| `delay` | string | — | Delay between requests, number or range, e.g. `0.1-2.0` (`ffuf -p`) |
| `timeout` | integer (≥1) | 10 | Per-request timeout seconds (`ffuf -timeout`) |
| `followRedirects` | boolean | false | Follow HTTP redirects (`ffuf -r`) |
| `autoCalibration` | boolean | false | Auto-calibrate filtering to cut false positives (`ffuf -ac`) |
| `headers` | string[] | — | `Name: Value` header lines (`ffuf -H`) |
| `proxy` | string | — | Proxy URL, e.g. `http://127.0.0.1:8080` (`ffuf -x`) |
| `method` | string | — | HTTP method to use (`ffuf -X`) |
| `data` | string | — | POST data / request body (`ffuf -d`) |
| `maxTime` | integer (≥0, ≤1100) | — | Soft run-time budget seconds (`ffuf -maxtime`); a hard 20 min timeout always applies |
| `maxUrls` | integer (1–100000) | 10000 | Hard cap on emitted findings; on hit the scan is stopped and partial results are kept |

### Deliberately not exposed

- **Output-file flags** (`-o`, `-of`, `-od`, `-debug-log`): they swallow stdout and break the NDJSON contract the adapter parses — `ffuf -json -s` writes one JSON object per match to stdout instead.
- **Multi-target flags** (`-input-cmd`, repeated `-w`): they turn a single curl-style scan into a bulk run and break the one-target-per-job contract.
- **`-D`** (DirSearch-compatibility wordlist mode) and **`-request`** (raw request file): read local files and require a different wordlist/request shape than the assembled argv.
- `-s` is always emitted (silent banner): the adapter parses stdout as NDJSON, so any non-JSON banner line must never appear.

## Example config profile

```yaml
# Connector profile submitted to the Worker (ExecutionCommand spec)
slug: ffuf
image: ghcr.io/oasm-platform/connector-ffuf:2.3.0
inputs:
  target: example.com
config:
  wordlist: common
  extensions: [php, html]
  matchCodes: '200,204,301,302,307,401,403'
  threads: 40
```

## Deployment

### Docker

```bash
docker build -t ghcr.io/oasm-platform/connector-ffuf:2.3.0 -f url_discovery/ffuf/Dockerfile .
docker run --rm -e WORKER_GRPC_ADDR=worker:50051 -e EXECUTION_ID=job-1 \
  ghcr.io/oasm-platform/connector-ffuf:2.3.0
```

### Manual

```bash
cd url_discovery/ffuf && go run .
```

## Behavior

- `adapter.go` — `FfufAdapter` streams one `Finding` per unique matched `http(s)` URL (`Name`=`MatchedAt`=URL, `Severity=info`, `Host`=target host); parses ffuf `-json` NDJSON stdout line by line; wraps ffuf in a hard 20m timeout; caps output at `maxUrls`; fatal only when the process fails AND produced no output, otherwise partial output is success
- `main.go` — wires `FfufAdapter` + SDK (`sdk/connector`, `sdk/runtime`)
- `ffuf.go` — `OASM_CONFIG` parsing + `buildFfufArgs` argv assembly + wordlist enum resolution under `FFUF_WORDLIST_DIR`
- `manifest.yaml` — source of truth for `manifest.json` (capability `url_discovery`; image `ghcr.io/oasm-platform/connector-ffuf:2.3.0` is SDK+tool bundle, not upstream)
- `Dockerfile` — `golang:1.26-alpine` builder (connector + `ffuf@v2.3.0` from source, `CGO_ENABLED=0`, pinned SecLists wordlists) → `alpine:3.20` non-root final stage with `FFUF_WORDLIST_DIR=/opt/wordlists/ffuf`
- `testdata/fake-ffuf/` — test stub driven by `FAKE_MODE` (`default`, `empty`, `fail`, `partial-fail`, `hang`, `many`)

## Testing

```bash
cd url_discovery/ffuf && go test ./... -v -count=1
cd url_discovery/ffuf && go vet ./...

# Real scan against a pinned ffuf v2.3.0 (build-tagged, writes e2e-findings.jsonl):
cd url_discovery/ffuf && FFUF_BIN=/path/to/ffuf-v2.3.0 go test -tags e2e -run TestFfufE2E_RealScan -v -count=1
```

The E2E test fatals when `FFUF_BIN` is unset: a stale or absent PATH ffuf would exercise different flags than the pinned v2.3.0. `example.com` legitimately yields zero directory hits, so the test asserts a clean run and that every finding is an `http(s)` URL — never a minimum finding count.

## 14-step trace

Core (`manifest.json` via `ConnectorRegistry`) → `WorkerStream ExecutionCommand{spec{image, inputs}}` → Worker `ExecutionManager` → `DockerRuntime.Create(Image: spec.Image)` via `docker.sock` → Connector SDK → `FfufAdapter.Execute` → proxy → Core persist (`discovered_urls`).
