# Nuclei Connector

Reference connector proving Core → Worker (docker.sock) → Connector SDK → tool → back.
Runs [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) 3.3.0 via the OASM Worker gRPC bridge.

## Requirements

- Go 1.22+, Docker, Worker reachable at `WORKER_URL`
- Tool binary `nuclei` bundled in image via multi-stage `COPY --from=projectdiscovery/nuclei:3.3.0`

## Configuration

| Parameter | env | default | mandatory | description |
|-----------|-----|---------|-----------|-------------|
| Worker URL | `WORKER_URL` | `http://localhost:50051` | yes | Worker gRPC endpoint |
| Worker token | `WORKER_TOKEN` | `` | no | Auth token if Worker requires it |
| Target | `inputs.target` | — | yes | Scan target: `http(s)://` URL or bare domain |

`inputsSchema` (see `manifest.yaml`): `{target: string (uri)}`.

## Deployment

### Docker

```bash
docker build -t ghcr.io/open-asm/connector-nuclei:3.3.0 -f vulnerabilities/nuclei/Dockerfile .
docker run --rm -e WORKER_URL=http://worker:50051 ghcr.io/open-asm/connector-nuclei:3.3.0
```

### Manual

```bash
go run ./vulnerabilities/nuclei
```

## Behavior

- `adapter.go` — `NucleiAdapter` (tool-specific parsing stub); `Validate` + `Execute`
- `main.go` — wires `NucleiAdapter` + SDK (`sdk/connector`, `sdk/runtime`)
- `manifest.yaml` — source of truth for `manifest.json` (image `ghcr.io/open-asm/connector-nuclei:3.3.0` is SDK+tool bundle, not upstream)
- `Dockerfile` — `golang:1.22-alpine` builder → `alpine:3.20` non-root; multi-stage copies `/usr/local/bin/nuclei` from `projectdiscovery/nuclei:3.3.0 AS tool`

## Testing

```bash
go test ./vulnerabilities/nuclei -v
go vet ./vulnerabilities/nuclei
```

## 14-step trace

Core (`manifest.json` via `ConnectorRegistry`) → `WorkerStream ExecutionCommand{spec{image, inputs}}` → Worker `ExecutionManager` → `DockerRuntime.Create(Image: spec.Image)` via `docker.sock` → Connector SDK → `NucleiAdapter.Execute` → proxy → Core persist.
