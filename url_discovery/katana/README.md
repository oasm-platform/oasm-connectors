# katana Connector

Runs [projectdiscovery/katana](https://github.com/projectdiscovery/katana) 1.7.0 via the OASM Worker gRPC bridge. Crawls a target website and discovers HTTP/HTTPS URLs (links, JS-derived endpoints).

## Requirements

- Go 1.26+, Docker, Worker reachable at `WORKER_URL`
- Tool binary `katana` compiled from source and pinned to `v1.7.0` in the image builder stage
- **Network egress required at scan time**: katana fetches the target site directly.
- **Writable `$HOME`**: katana writes `$HOME/.config/katana/{field-config,form-config}.yaml` on every run. The image sets `ENV HOME=/home/connector` (owned by uid 10001) for this reason; manual runs as a read-only user can log config-write errors.

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Configuration

| Parameter | env | default | mandatory | description |
|-----------|-----|---------|-----------|-------------|
| Worker URL | `WORKER_URL` | `http://localhost:50051` | yes | Worker gRPC endpoint |
| Worker token | `WORKER_TOKEN` | `` | no | Auth token if Worker requires it |
| Target | `inputs.target` | — | yes | Domain (or URL): scheme/path stripped to the host |
| katana binary | `KATANA_BIN` | `katana` | no | Override path to the katana binary |
| Config profile | `OASM_CONFIG` | `` | no | JSON config profile (see below) |

`configSchema` parameters (all optional, camelCase keys in `OASM_CONFIG`):

| Key | type | default | description |
|-----|------|---------|-------------|
| `depth` | integer (1–10) | 3 | Maximum link depth (`katana -d`) |
| `jsCrawl` | boolean | **true** | Extract endpoints from JavaScript files (`katana -jc`); no browser needed |
| `crawlDuration` | integer (≥0) | 0 | Wall-clock budget seconds; 0 = unbounded (`katana -ct`). A 10 min hard timeout always applies |
| `timeout` | integer (≥1) | 10 | Per-request timeout seconds (`katana -timeout`) |
| `concurrency` | integer (1–100) | 10 | Concurrent fetchers (`katana -c`) |
| `parallelism` | integer (1–10) | 10 | Concurrent inputs (`katana -p`) |
| `rateLimit` | integer (≥1) | 150 | Requests/second (`katana -rl`) |
| `retries` | integer (≥0) | 1 | Request retries (`katana -retry`) |
| `proxy` | string | — | Proxy URL, e.g. `http://127.0.0.1:8080` (`katana -proxy`) |
| `headers` | string[] | — | `Name: Value` header lines (`katana -H`); comma-bearing values are quoted automatically |
| `filterSimilar` | boolean | false | Collapse near-duplicate URLs (`katana -fsu`) |
| `filterSimilarThreshold` | integer (1–100) | 10 | Similarity threshold for `-fsu` (`katana -fst`) |
| `maxDomainPages` | integer (≥0) | 0 | Max pages per domain, 0 = unlimited (`katana -mdp`). Caps pages, not discovered URLs |
| `extensionMatch` | string[] | — | Only emit URLs with these extensions (`katana -em`) |
| `extensionFilter` | string[] | — | Drop URLs with these extensions (`katana -ef`) |
| `crawlScope` | string | — | In-scope URL regex (`katana -cs`) |
| `maxUrls` | integer (1–100000) | 10000 | Hard cap on emitted findings; on hit the crawl is stopped and partial results are kept |

### Deliberately not exposed

- **Headless / browser flags** (`-hl`, `-hh`, `-sc`, `-sb`, `-nos`, `-cdd`, `-xhr`, `-aff`, `-csp`, `-csk`, `-al`, `-pls`, `-dwt`, `-mfc`, `-ed`): need chromium (~hundreds of MB) and a different render path. Upgrade path: a separate headless image variant adding `apk add --no-cache chromium bind-tools` and re-exposing these flags. `jsCrawl` (`-jc`) captures static-JS endpoints without a browser.
- **Scope-escape flags** (`-ns`, `-do`, `-cos`): a job must never crawl outside the target's registered domain.
- **Output flags** (`-o`, `-ot`, `-sr`, `-or`, `-ob`, `-j`/`-jsonl`, `-sf`, `-field`): they break the URL-only stdout contract the worker's `findingToDiscoveredUrl` depends on (and file output swallows stdout).
- **Form/field extraction** (`-fx`, `-fc`, `-flc`): not URL discovery; katana writes its own defaults under `$HOME/.config/katana/`.
- **Match/filter regex/dsl and tuning flags** (`-mr`, `-fr`, `-mdc`, `-fdc`, `-iqp`, `-pc`, `-dr`, `-s`, `-kf`, `-r`, `-e`, `-td`, `-tlsi`, `-rd`, `-rlm`, `-hrl`, `-mrs`, `-time-stable`, `-duf`, `-ndef`, `-up`, `-resume`, `-health-check`, `-config`, `-v`, `-debug`, `-elog`, `-pprof-server`): outside the URL-discovery contract.
- `-fs` is never emitted: katana's default `-fs rdn` (registered domain) is the scope we want.

## Volume and limits

- **`maxUrls` (default 10000) is the only real volume bound.** `-mdp` caps *pages*, not emitted rows: a measured `-mdp 5000` run with `-fsu` still yielded 72,266 unique URLs. On hitting the cap the adapter stops scanning, kills the process, keeps the partial findings and returns success.
- Measured volume: iana.org `-d 2` produced 370,308 stdout lines / 94.5 MB / 53,520 unique URLs in 76–237 s; uncapped jobs can exceed the cap by 5×. `filterSimilar` cut the same run from 237 s to 13 s.
- `maxUrls` bounds the SDK's one-gRPC-message-per-finding cost. Upgrade path: an optional raw-data channel in the SDK.
- katana has **no global URL dedupe** (measured: 5,663 unique from 10,806 lines at depth 1) and emits non-HTTP schemes (`ftp:`, `mailto:`); the adapter dedupes and keeps only `http://`/`https://`.

## Example config profile

```yaml
# Connector profile submitted to the Worker (ExecutionCommand spec)
slug: katana
image: ghcr.io/oasm-platform/connector-katana:1.7.0
inputs:
  target: example.com
config:
  depth: 3
  jsCrawl: true
```

## Deployment

### Docker

```bash
docker build -t ghcr.io/oasm-platform/connector-katana:1.7.0 -f url_discovery/katana/Dockerfile .
docker run --rm -e WORKER_URL=http://worker:50051 ghcr.io/oasm-platform/connector-katana:1.7.0
```

### Manual

```bash
cd url_discovery/katana && go run .
```

## Behavior

- `adapter.go` — `KatanaAdapter` streams one `Finding` per unique discovered `http(s)` URL (`Name`=`MatchedAt`=URL, `Severity=info`, `Host`=target); wraps katana in a hard 10m timeout; caps output at `maxUrls`; treats the unreliable katana exit codes per the policy below
- `main.go` — wires `KatanaAdapter` + SDK (`sdk/connector`, `sdk/runtime`)
- `katana.go` — `OASM_CONFIG` parsing + `buildKatanaArgs` argv assembly (`-duc` always first)
- `manifest.yaml` — source of truth for `manifest.json` (capability `url_discovery`; image `ghcr.io/oasm-platform/connector-katana:1.7.0` is SDK+tool bundle, not upstream)
- `Dockerfile` — `golang:1.26-alpine` builder (connector + `katana@v1.7.0` from source, `CGO_ENABLED=0`) → `alpine:3.20` non-root final stage with `HOME=/home/connector`
- `testdata/fake-katana/` — test stub driven by `FAKE_MODE` (`default`, `empty`, `fail`, `partial-fail`, `runner-fail`, `hang`, `many`)

### Exit-code policy

katana's exit code is unreliable: an unreachable target exits 0, empty input exits 0, and a runner initialization failure prints `could not create runner` to stderr and **also exits 0** — only an unknown flag exits nonzero (2). The adapter therefore fails only when:

1. the process fails (nonzero exit) **and** produced no output, or
2. the `could not create runner` marker appears **and** no output was produced (the exit code cannot signal this case), or
3. the hard timeout elapses (always an error, even with partial output).

A nonzero exit **with** output is success (partial results are useful), as is a cap-truncated run.

## Testing

```bash
cd url_discovery/katana && go test ./... -v -count=1
cd url_discovery/katana && go vet ./...

# Real crawl against a pinned katana v1.7.0 (build-tagged, writes e2e-findings.jsonl):
cd url_discovery/katana && KATANA_BIN=/path/to/katana-v1.7.0 go test -tags e2e -run TestKatanaE2E_RealCrawl -v -count=1
```

The E2E test fatals when `KATANA_BIN` is unset: a stale PATH katana (e.g. v1.2.1) lacks `-duc`/`-mdp`/`-fsu` and would exit 2 rather than exercise the adapter.

## 14-step trace

Core (`manifest.json` via `ConnectorRegistry`) → `WorkerStream ExecutionCommand{spec{image, inputs}}` → Worker `ExecutionManager` → `DockerRuntime.Create(Image: spec.Image)` via `docker.sock` → Connector SDK → `KatanaAdapter.Execute` → proxy → Core persist (`discovered_urls`).
