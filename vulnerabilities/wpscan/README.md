# WPScan Connector

Runs [wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) 3.8.27 via the OASM Worker gRPC bridge. Scans WordPress sites for known vulnerabilities in core, plugins, themes, and version.

## Requirements

- Go 1.26+, Docker, Worker reachable at `WORKER_URL`
- Tool binary `wpscan` bundled in image via multi-stage `COPY --from=wpscanteam/wpscan:3.8.27`

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Configuration

| Parameter | env | default | mandatory | description |
|-----------|-----|---------|-----------|-------------|
| Worker URL | `WORKER_URL` | `http://localhost:50051` | yes | Worker gRPC endpoint |
| Worker token | `WORKER_TOKEN` | `` | no | Auth token if Worker requires it |
| Target | `inputs.target` | — | yes | Scan target: `http(s)://` URL or bare domain |
| WPScan binary | `WPSCAN_BIN` | `wpscan` | no | Override path to wpscan binary |

`inputsSchema` (see `manifest.yaml`): `{target: string (uri)}`.

## Example config profile

```yaml
# Connector profile submitted to the Worker (ExecutionCommand spec)
slug: wpscan
image: ghcr.io/oasm-platform/connector-wpscan:3.8.27
inputs:
  target: https://example.com
```

## Deployment

### Docker

```bash
docker build -t ghcr.io/oasm-platform/connector-wpscan:3.8.27 -f vulnerabilities/wpscan/Dockerfile .
docker run --rm -e WORKER_URL=http://worker:50051 ghcr.io/oasm-platform/connector-wpscan:3.8.27
```

### Manual

```bash
cd vulnerabilities/wpscan && go run .
```

## Behavior

- `adapter.go` — `WpscanAdapter` (tool-specific parsing); `Validate` (no-op) + `Execute`
- `main.go` — wires `WpscanAdapter` + SDK (`sdk/connector`, `sdk/runtime`)
- `manifest.yaml` — source of truth for `manifest.json` (image `ghcr.io/oasm-platform/connector-wpscan:3.8.27` is SDK+tool bundle, not upstream)
- `Dockerfile` — `golang:1.26-alpine` builder → `wpscanteam/wpscan:3.8.27` non-root final stage
- `testdata/fake-wpscan/` — test stub that outputs canned JSON; driven by `FAKE_MODE` env

## Testing

```bash
cd vulnerabilities/wpscan && go test ./... -v -count=1
cd vulnerabilities/wpscan && go vet ./...
```

## 14-step trace

Core (`manifest.json` via `ConnectorRegistry`) → `WorkerStream ExecutionCommand{spec{image, inputs}}` → Worker `ExecutionManager` → `DockerRuntime.Create(Image: spec.Image)` via `docker.sock` → Connector SDK → `WpscanAdapter.Execute` → proxy → Core persist.
