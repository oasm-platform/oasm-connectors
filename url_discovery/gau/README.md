# gau Connector

Runs [lc/gau](https://github.com/lc/gau) 2.2.4 (GetAllUrls) via the OASM Worker gRPC bridge. Discovers historical/archived URLs for a domain from public archives.

## Requirements

- Go 1.26+, Docker, Worker reachable at `WORKER_GRPC_ADDR`
- Tool binary `gau` compiled from source and pinned to `v2.2.4` in the image builder stage
- **Network egress required at scan time**: gau queries public provider APIs (Wayback Machine, Common Crawl, AlienVault OTX, urlscan.io). No API keys are needed (a urlscan.io key is optional upstream).

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Configuration

| Parameter | env | default | mandatory | description |
|-----------|-----|---------|-----------|-------------|
| Worker address | `WORKER_GRPC_ADDR` | `localhost:50051` | yes | Worker gRPC endpoint (missing → fatal) |
| Worker token | `WORKER_TOKEN` | `` | no | Auth token if Worker requires it |
| Execution ID | `EXECUTION_ID` | — | yes | Job identity; the Worker routes `ExecuteJob` by it |
| Target | `inputs.target` | — | yes | Domain (or URL): scheme/path stripped to the host |
| gau binary | `GAU_BIN` | `gau` | no | Override path to gau binary |
| Config profile | `OASM_CONFIG` | `` | no | JSON config profile (see below) |

`configSchema` parameters (all optional, camelCase keys in `OASM_CONFIG`):

| Key | type | default | description |
|-----|------|---------|-------------|
| `providers` | string[] (wayback, commoncrawl, otx, urlscan) | all four | Archive providers to query |
| `subs` | boolean | false | Query providers for `*.domain` as well (`gau --subs`) |
| `threads` | integer (min 1) | 5 | Worker threads per provider (`gau --threads`) |
| `timeout` | integer (min 1) | 45 | Per-request timeout seconds (`gau --timeout`) |
| `retries` | integer (min 0) | 5 | Provider request retries (`gau --retries`) |
| `proxy` | string | — | Proxy URL, e.g. `http://127.0.0.1:8080` |
| `from` | string | — | Start timestamp filter `YYYYMM` (`gau --from`) |
| `to` | string | — | End timestamp filter `YYYYMM` (`gau --to`) |

Deliberately not exposed (`blacklist`/`fp`/`json`/`o`): broken or unusable in gau v2.2.4 — `--json` drops URLs without an extension, `--blacklist` never matches, `--fp` is broken, and `--o` appends to a file while swallowing stdout.

## Example config profile

```yaml
# Connector profile submitted to the Worker (ExecutionCommand spec)
slug: gau
image: ghcr.io/oasm-platform/connector-gau:2.2.4
inputs:
  target: example.com
config:
  providers: [wayback, commoncrawl, otx, urlscan]
  threads: 5
  timeout: 45
```

## Deployment

### Docker

```bash
docker build -t ghcr.io/oasm-platform/connector-gau:2.2.4 -f url_discovery/gau/Dockerfile .
docker run --rm -e WORKER_GRPC_ADDR=worker:50051 -e EXECUTION_ID=job-1 \
  ghcr.io/oasm-platform/connector-gau:2.2.4
```

### Manual

```bash
cd url_discovery/gau && go run .
```

## Behavior

- `adapter.go` — `GauAdapter` streams one `Finding` per discovered URL (`Name`=`MatchedAt`=URL, `Severity=info`, `Host`=target), deduped client-side; wraps gau in a hard 10m timeout so a hung process is killed
- `main.go` — wires `GauAdapter` + SDK (`sdk/connector`, `sdk/runtime`)
- `gau.go` — `OASM_CONFIG` parsing + `buildGauArgs` argv assembly
- `manifest.yaml` — source of truth for `manifest.json` (capability `url_discovery`; image `ghcr.io/oasm-platform/connector-gau:2.2.4` is SDK+tool bundle, not upstream)
- `Dockerfile` — `golang:1.26-alpine` builder (connector + `gau@v2.2.4` from source) → `alpine:3.20` non-root final stage
- `testdata/fake-gau/` — test stub driven by `FAKE_MODE` (`default`, `empty`, `fail`, `partial-fail`, `hang`)

## Testing

```bash
cd url_discovery/gau && go test ./... -v -count=1
cd url_discovery/gau && go vet ./...
```

## 14-step trace

Core (`manifest.json` via `ConnectorRegistry`) → `WorkerStream ExecutionCommand{spec{image, inputs}}` → Worker `ExecutionManager` → `DockerRuntime.Create(Image: spec.Image)` via `docker.sock` → Connector SDK → `GauAdapter.Execute` → proxy → Core persist (`discovered_urls`).
