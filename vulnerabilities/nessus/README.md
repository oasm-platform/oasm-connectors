# Nessus Connector

Runs [Tenable Nessus](https://www.tenable.com/products/nessus) scans via the OASM Worker gRPC bridge.
Authenticates, creates a scan, polls until completion, collects findings as JSONL, then cleans up.

## Requirements

- Go 1.26+, Worker reachable at `WORKER_URL`
- Nessus server (e.g. `https://nessus.example.com:8834`) with valid credentials or API keys

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Configuration

| Parameter | env | default | mandatory | description |
|-----------|-----|---------|-----------|-------------|
| Worker URL | `WORKER_URL` | `http://localhost:50051` | yes | Worker gRPC endpoint |
| Worker token | `WORKER_TOKEN` | `` | no | Auth token if Worker requires it |
| Nessus URL | `NESSUS_URL` | — | yes | Nessus server URL (e.g. `https://nessus.example.com:8834`) |
| Nessus username | `NESSUS_USERNAME` | — | yes | Authentication username |
| Nessus password | `NESSUS_PASSWORD` | — | yes | Authentication password |
| Nessus access key | `NESSUS_ACCESS_KEY` | — | no* | API access key (*set with secret key) |
| Nessus secret key | `NESSUS_SECRET_KEY` | — | no* | API secret key (*set with access key) |
| Nessus template UUID | `NESSUS_TEMPLATE_UUID` | `TemplateBasic` | no | Nessus scan template |
| Nessus policy ID | `NESSUS_POLICY_ID` | `` | no | Nessus scan policy |
| Nessus folder ID | `NESSUS_FOLDER_ID` | `0` | no | Nessus folder for scans |
| Execution ID | `EXECUTION_ID` | — | no | Scan name (auto-set by Worker) |
| Target | `inputs.target` | — | yes | Scan target URI |

`inputsSchema` (see `manifest.yaml`): `{target: string (uri)}`.

## Deployment

### Docker

```bash
docker build -t ghcr.io/open-asm/connector-nessus:0.1.0 -f vulnerabilities/nessus/Dockerfile .
docker run --rm -e WORKER_URL=http://worker:50051 \
  -e NESSUS_URL=https://nessus.example.com:8834 \
  -e NESSUS_USERNAME=admin \
  -e NESSUS_PASSWORD=changeme \
  ghcr.io/open-asm/connector-nessus:0.1.0
```

### Manual

```bash
cd vulnerabilities/nessus && go run .
```

## Behavior

1. **Authentication** — login with username/password or API access/secret key pair; session token reused for all subsequent requests.
2. **Create scan** — `POST /scans` using configured template UUID, policy, folder, and target.
3. **Launch & poll** — start the scan, then poll `/scans/{id}` until status is `completed`.
4. **Collect findings** — export scan results, parse JSONL, emit findings via SDK.
5. **Cleanup** — delete the created scan (`DELETE /scans/{id}`).

Files:
- `adapter.go` — `NessusAdapter` (tool-specific parsing); `Validate` + `Execute`
- `nessus.go` — Nessus REST API client
- `findings.go` — JSONL finding parser
- `main.go` — wires `NessusAdapter` + SDK (`sdk/connector`, `sdk/runtime`)
- `manifest.yaml` — source of truth for `manifest.json`
- `Dockerfile` — `golang:1.26-alpine` builder → `alpine:3.20` non-root; no bundled tool binary

## Testing

```bash
cd vulnerabilities/nessus && go test ./... -count=1
cd vulnerabilities/nessus && go vet ./...
```

<!-- ponytail: advanced scan settings (ScansCreateCustom) not wired yet; upgrade path via NESSUS_SCAN_SETTINGS JSON env var -->
