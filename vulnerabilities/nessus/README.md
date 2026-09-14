# Nessus Connector

Runs [Tenable Nessus](https://www.tenable.com/products/nessus) scans via the OASM Worker gRPC bridge.
Authenticates, creates a scan, polls until completion, collects findings as JSONL, then cleans up.

## Requirements

- Go 1.26+, Worker reachable at `WORKER_URL`
- Nessus server (e.g. `https://nessus.example.com:8834`) with a valid API access/secret key pair

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Configuration

The connector reads its settings from `OASM_CONFIG` — the per-job config profile
the Worker ships as JSON (camelCase keys mirroring `manifest.yaml` `configSchema`).
This is the new-SDK path that makes warm-pool reuse work: the SDK overrides
`OASM_CONFIG` per execution, so a reused container sees its own job's config.
`NESSUS_*` env vars remain as a legacy fallback for direct-runtime use.

```json
{
  "url": "https://nessus.example.com:8834",
  "accessKey": "your-access-key",
  "secretKey": "your-secret-key",
  "templateUuid": "",
  "policyId": "",
  "folderId": "0"
}
```

| Key | legacy env fallback | default | mandatory | description |
|-----|---------------------|---------|-----------|-------------|
| `url` | `NESSUS_URL` | — | yes | Nessus server URL |
| `accessKey` | `NESSUS_ACCESS_KEY` | — | yes | API access key |
| `secretKey` | `NESSUS_SECRET_KEY` | — | yes | API secret key |
| `templateUuid` | `NESSUS_TEMPLATE_UUID` | `TemplateBasic` | no | Nessus scan template |
| `policyId` | `NESSUS_POLICY_ID` | `` | no | Nessus scan policy |
| `folderId` | `NESSUS_FOLDER_ID` | `0` | no | Nessus folder for scans |

Worker connection (`WORKER_GRPC_ADDR`, `WORKER_TOKEN`) and `EXECUTION_ID` are
injected by the Worker; the scan name is derived from the target per execution.

`inputsSchema` (see `manifest.yaml`): `{target: string (uri)}`.

## Deployment

### Docker

```bash
docker build -t ghcr.io/open-asm/connector-nessus:0.1.0 -f vulnerabilities/nessus/Dockerfile .
docker run --rm -e WORKER_URL=http://worker:50051 \
  -e OASM_CONFIG='{"url":"https://nessus.example.com:8834","accessKey":"ak","secretKey":"sk"}' \
  ghcr.io/open-asm/connector-nessus:0.1.0
```

### Manual

```bash
cd vulnerabilities/nessus && go run .
```

## Behavior

1. **Authentication** — every request is sent with the configured API access/secret key pair (`X-ApiKeys` header).
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
