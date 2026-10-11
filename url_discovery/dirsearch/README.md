# dirsearch Connector

Runs [maurosoria/dirsearch](https://github.com/maurosoria/dirsearch) 0.5.0 via the OASM Worker gRPC bridge. Brute-forces paths on a web target from a wordlist and discovers HTTP/HTTPS URLs (hidden files, directories, endpoints).

## Requirements

- Go 1.26+, Docker, Worker reachable at `WORKER_GRPC_ADDR`
- Tool `dirsearch==0.5.0` installed from PyPI in the image's final stage, and **Python 3.11+** (dirsearch 0.5.0's `python_requires`); the image pins `python:3.13-slim`. The console script `dirsearch` is asserted on `PATH` at build time.
- **Bundled wordlists pinned to `v0.5.0`**: `dicc.txt` (default) plus the ten `db/categories/*.txt` presets are downloaded at image build and baked into `/opt/wordlists/dirsearch`. A scan never falls back to dirsearch's runtime default wordlist.
- **Network egress required at scan time**: dirsearch sends requests to the target directly.

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Configuration

| Parameter | env | default | mandatory | description |
|-----------|-----|---------|-----------|-------------|
| Worker address | `WORKER_GRPC_ADDR` | `localhost:50051` | yes | Worker gRPC endpoint (missing → fatal) |
| Worker token | `WORKER_TOKEN` | `` | no | Auth token if Worker requires it |
| Execution ID | `EXECUTION_ID` | — | yes | Job identity; the Worker routes `ExecuteJob` by it |
| Target | `inputs.target` | — | yes | Base URL; passed to `dirsearch -u` (missing scheme defaults to `https://`) |
| dirsearch binary | `DIRSEARCH_BIN` | `dirsearch` | no | Override path to the dirsearch console script |
| Wordlist directory | `DIRSEARCH_WORDLIST_DIR` | `/opt/wordlists/dirsearch` | no | Directory the `wordlist` enum resolves against; the image sets it to the bundled wordlists |
| Config profile | `OASM_CONFIG` | `` | no | JSON config profile (see below) |

`configSchema` parameters (all optional, camelCase keys in `OASM_CONFIG`):

| Key | type | default | description |
|-----|------|---------|-------------|
| `wordlist` | string enum | `default` | Bundled preset under `DIRSEARCH_WORDLIST_DIR` (`default`, `common`, `web`, `conf`, `extensions`, `backups`, `vcs`, `db`, `logs`, `keys`). `default` selects `dicc.txt`; others select `<name>.txt` (`dirsearch -w`) |
| `extensions` | string[] | — | File extensions appended to each path (`dirsearch -e`, comma-joined) |
| `threads` | integer (≥1) | 25 | Concurrent threads (`dirsearch -t`; always emitted) |
| `recursive` | boolean | false | Recursive brute-force on discovered directories (`dirsearch -r`) |
| `maxRecursionDepth` | integer (≥1) | — | Max recursion depth; only emitted when `recursive` is true (`dirsearch -R`) |
| `includeStatus` | string | — | Only show these status codes, comma-separated (`dirsearch -i`) |
| `excludeStatus` | string | — | Exclude these status codes, comma-separated (`dirsearch -x`) |
| `excludeExtensions` | string[] | — | Extensions to exclude (`dirsearch --exclude-extensions`, comma-joined) |
| `method` | string | — | HTTP method (`dirsearch -m`) |
| `headers` | string[] | — | Extra request headers, one `-H` per entry (e.g. `X-Api-Key: abc`) |
| `proxy` | string | — | Proxy URL, e.g. `http://127.0.0.1:8080` (`dirsearch -p`) |
| `timeout` | integer (≥1) | — | Per-request timeout seconds (`dirsearch --timeout`) |
| `randomUserAgent` | boolean | false | Random User-Agent per request (`dirsearch --random-agent`) |
| `maxTime` | integer (1–1100) | — | Scan duration budget seconds (`dirsearch --max-time`). A 20 min hard timeout always applies |
| `maxUrls` | integer (≥1) | 10000 | Hard cap on emitted findings; on hit scanning stops and partial results are kept |

### Deliberately not exposed

- **DB / persistent-store flags** (`--mysql-url`, `--postgres-url`, `-O sqlite` / `--sqlite-database`): the adapter always sets `-O json`, and the connector must not assume an external database.
- **Raw-request / config / log path flags** (`--raw`, `--config`, `--log`, `--sessions-dir`, `--nmap-report`, `--proxies-file`, `--headers-file`): a job must not read or write arbitrary host paths, and raw request dumps are outside the URL-discovery contract.
- **Multi-target input flags** (`-l` / `--url-list`, `--stdin`, `--cidr`): one job scans one `inputs.target`; the adapter passes it as `-u`.
- `--exit-on-error` is never emitted: its default `False` is what makes an unreachable target exit 0, which the exit-code policy below depends on.

## Volume and limits

- **`maxUrls` (default 10000) is the only emitted-findings bound.** dirsearch writes its report to a temp file and the adapter reads it after the process exits, so the cap is applied at parse time; on hit the parse stops, partial findings are kept, and the run returns success.
- dirsearch has no global URL dedupe across wordlist hits; the adapter dedupes on URL and keeps only `http://`/`https://`.
- The adapter runs dirsearch with a hard 20 minute timeout (`dirsearchHardTimeout`); `maxTime` (≤1100 s) is the softer, user-set budget. The manifest's `resourceDefaults.timeoutSeconds` (1800 s) sits above the hard timeout so the adapter reports a clean `timed out after 20m0s` before the container is killed.

## Example config profile

```yaml
# Connector profile submitted to the Worker (ExecutionCommand spec)
slug: dirsearch
image: ghcr.io/oasm-platform/connector-dirsearch:0.5.0
inputs:
  target: https://example.com
config:
  wordlist: common
  extensions: [php, html]
```

## Deployment

### Docker

```bash
docker build -t ghcr.io/oasm-platform/connector-dirsearch:0.5.0 -f url_discovery/dirsearch/Dockerfile .
docker run --rm -e WORKER_GRPC_ADDR=worker:50051 -e EXECUTION_ID=job-1 \
  ghcr.io/oasm-platform/connector-dirsearch:0.5.0
```

### Manual

```bash
cd url_discovery/dirsearch && go run .
```

## Behavior

- `adapter.go` — `DirsearchAdapter` streams one `Finding` per unique discovered `http(s)` URL (`Name`=`MatchedAt`=URL, `Severity=info`, `Host`=host); runs dirsearch with `-O json -o <tmp>/report.json`, reads the report after exit, dedupes, caps at `maxUrls`, applies a hard 20 m timeout
- `main.go` — wires `DirsearchAdapter` + SDK (`sdk/connector`, `sdk/runtime`)
- `dirsearch.go` — `OASM_CONFIG` parsing, `resolveDirsearchWordlist` (enum → `<DIRSEARCH_WORDLIST_DIR>/<name>.txt`), and `buildDirsearchArgs` argv assembly
- `manifest.yaml` — source of truth for `manifest.json` (capability `url_discovery`; image `ghcr.io/oasm-platform/connector-dirsearch:0.5.0` is SDK+tool bundle, not upstream)
- `Dockerfile` — `golang:1.26-alpine` builder (connector + pinned v0.5.0 wordlists) → `python:3.13-slim` non-root final stage with `dirsearch==0.5.0` and `HOME=/home/connector`
- `testdata/fake-dirsearch/` — test stub driven by `FAKE_MODE` (`default`, `empty`, `fail`, `partial-fail`, `hang`, `many`)

### Exit-code policy

dirsearch exits 0 even for an unreachable target or a zero-result scan, so a nonzero exit is not the only failure signal. The **report file is the source of truth**: dirsearch creates `<tmp>/report.json` on every completed run, so a missing report is *always* an error (wrong `-o` path, or a target that never ran), regardless of exit code. The adapter fails only when:

1. the context is cancelled (returns `ctx.Err()`), or
2. the hard 20 minute timeout elapses (always an error, even with a partial report), or
3. the report file is missing (`dirsearch: missing report: <tail>`) or unreadable/unparseable (`dirsearch: read report: …`), or
4. the process exits nonzero **and** produced no findings (`dirsearch: <exit>: <tail>`).

An unreachable target therefore simply yields **zero findings and a nil error** — the caller reads the (empty) result set rather than treating the run as failed. A nonzero exit with partial report data is success (partial results are useful), and an empty `results` array is a clean zero-findings success.

## Testing

```bash
cd url_discovery/dirsearch && go test ./... -v -count=1
cd url_discovery/dirsearch && go vet ./...

# Real scan against a pinned dirsearch 0.5.0 (build-tagged, writes e2e-findings.jsonl):
cd url_discovery/dirsearch && DIRSEARCH_BIN=/path/to/dirsearch go test -tags e2e -run TestDirsearchE2E_RealScan -v -count=1
```

`e2e_test.go` is behind the `e2e` build tag and fatals when `DIRSEARCH_BIN` is unset, so `go test ./...` never runs it. It asserts a clean run (`nil` error) and that every finding is an `http(s)` URL; it deliberately does **not** assert a minimum finding count — `example.com` yields zero hits, and a zero-hit run is a valid pass.

## 14-step trace

Core (`manifest.json` via `ConnectorRegistry`) → `WorkerStream ExecutionCommand{spec{image, inputs}}` → Worker `ExecutionManager` → `DockerRuntime.Create(Image: spec.Image)` via `docker.sock` → Connector SDK → `DirsearchAdapter.Execute` → proxy → Core persist (`discovered_urls`).
