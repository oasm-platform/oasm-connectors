# Nuclei Connector

Reference connector proving Core → Worker (docker.sock) → Connector SDK → tool → back.
Embeds [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) v3.4.1 as a Go library (`github.com/projectdiscovery/nuclei/v3/lib`) and scans in-process.

## Requirements

- Go 1.26+, Docker, Worker reachable at `WORKER_URL`
- Nuclei v3.4.1 embedded as a Go library dependency (`github.com/projectdiscovery/nuclei/v3/lib`); scans run in-process

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Configuration

| Parameter | env | default | mandatory | description |
|-----------|-----|---------|-----------|-------------|
| Worker URL | `WORKER_URL` | `http://localhost:50051` | yes | Worker gRPC endpoint |
| Worker token | `WORKER_TOKEN` | `` | no | Auth token if Worker requires it |
| Target | `inputs.target` | — | yes | Scan target: `http(s)://` URL or bare domain |

`inputsSchema` (see `manifest.yaml`): `{target: string (uri)}`.

## Example config profile

```yaml
# Connector profile submitted to the Worker (ExecutionCommand spec)
slug: nuclei
image: ghcr.io/open-asm/connector-nuclei:3.4.1
inputs:
  target: https://example.com
config: # matches configSchema in manifest.yaml
  severity: [medium, high, critical]
  tags: [cves]
  rateLimit: 150
  concurrency: 25
  followRedirects: true
```

## Deployment

### Docker

```bash
docker build -t ghcr.io/open-asm/connector-nuclei:3.4.1 -f vulnerabilities/nuclei/Dockerfile .
docker run --rm -e WORKER_URL=http://worker:50051 ghcr.io/open-asm/connector-nuclei:3.4.1
```

### Manual

```bash
cd vulnerabilities/nuclei && go run .
```

## Behavior

- `adapter.go` — `NucleiAdapter` (tool-specific parsing stub); `Validate` + `Execute`
- `main.go` — wires `NucleiAdapter` + SDK (`sdk/connector`, `sdk/runtime`)
- `manifest.yaml` — source of truth for `manifest.json` (image `ghcr.io/open-asm/connector-nuclei:3.4.1` is a single binary embedding the nuclei library)
- `Dockerfile` — `golang:1.26-alpine` builder → `alpine:3.20` non-root single-binary image; templates baked at build time via `cmd/templates` + installer API

## Testing

```bash
cd vulnerabilities/nuclei && go test ./... -v -count=1
cd vulnerabilities/nuclei && go vet ./...
```

## 14-step trace

Core (`manifest.json` via `ConnectorRegistry`) → `WorkerStream ExecutionCommand{spec{image, inputs}}` → Worker `ExecutionManager` → `DockerRuntime.Create(Image: spec.Image)` via `docker.sock` → Connector SDK → `NucleiAdapter.Execute` → proxy → Core persist.
