# Acunetix Connector

Runs [Acunetix](https://www.acunetix.com) web scans via the OASM Worker gRPC bridge.
Authenticates, finds or creates the target, schedules a scan, polls until completion,
collects every vulnerability (paginated list + per-vulnerability details) as JSONL, then cleans up.

## Requirements

- Go 1.26+, Worker reachable at `WORKER_URL`
- Acunetix instance (e.g. `https://acunetix.local:3443`) with a valid API key

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Configuration

The connector reads its settings from `OASM_CONFIG` — the per-job config profile
the Worker ships as JSON (camelCase keys mirroring `manifest.yaml` `configSchema`).
This is the new-SDK path that makes warm-pool reuse work: the SDK overrides
`OASM_CONFIG` per execution, so a reused container sees its own job's config.
`ACUNETIX_*` env vars remain as a legacy fallback for direct-runtime use.

```json
{
  "url": "https://acunetix.local:3443",
  "apiKey": "your-api-key",
  "profileId": "11111111-1111-1111-1111-111111111111",
  "criticality": 10,
  "targetDescription": "oasm-scan",
  "disableTlsChecks": false,
  "maxScanTime": 0
}
```

| Key | legacy env fallback | default | mandatory | description |
|-----|---------------------|---------|-----------|-------------|
| `url` | `ACUNETIX_URL` | — | yes | Acunetix base URL (`https://host:3443` on-premises, `https://app.invicti.com` Online). `/api/v1` is appended when absent |
| `apiKey` | `ACUNETIX_API_KEY` | — | yes | API key sent in the `X-Auth` header |
| `profileId` | `ACUNETIX_PROFILE_ID` | `11111111-1111-1111-1111-111111111111` (Full Scan) | no | Scan type (profile) UUID |
| `criticality` | `ACUNETIX_CRITICALITY` | `10` | no | Target business criticality: `30` Critical, `20` High, `10` Normal, `0` Low |
| `targetDescription` | `ACUNETIX_TARGET_DESCRIPTION` | `oasm-scan` | no | Description stored on the Acunetix target created for this scan |
| `disableTlsChecks` | `ACUNETIX_INSECURE` | `false` | no | Skip TLS certificate verification (required for the self-signed cert Acunetix ships by default) |
| `maxScanTime` | `ACUNETIX_MAX_SCAN_TIME` | `0` | no | Max scan duration in minutes; `0` uses the Acunetix default |

The `ACUNETIX_INSECURE` fallback is parsed with `strconv.ParseBool`, so it accepts
`1`, `t`, `T`, `TRUE`, `true`, `True`, `0`, `f`, `F`, `FALSE`, `false`, `False`;
any other value is a hard config error. `ACUNETIX_CRITICALITY` and
`ACUNETIX_MAX_SCAN_TIME` are parsed with `strconv.Atoi` and likewise fail loudly on
a non-integer value. A missing `url` or `apiKey` fails with
`acunetix URL required (config.url or ACUNETIX_URL)` /
`acunetix API key required (config.apiKey or ACUNETIX_API_KEY)`.

Worker connection (`WORKER_GRPC_ADDR`, `WORKER_TOKEN`) and `EXECUTION_ID` are
injected by the Worker.

`inputsSchema` (see `manifest.yaml`): `{target: string (uri)}`.

## Deployment

### Docker

```bash
docker build -t ghcr.io/oasm-platform/connector-acunetix:0.1.0 -f vulnerabilities/acunetix/Dockerfile .
docker run --rm -e WORKER_URL=http://worker:50051 \
  -e OASM_CONFIG='{"url":"https://acunetix.local:3443","apiKey":"ak","disableTlsChecks":true}' \
  ghcr.io/oasm-platform/connector-acunetix:0.1.0
```

### Manual

```bash
cd vulnerabilities/acunetix && go run .
```

## Behavior

1. **Resolve target** — canonicalize the input address (lower-cased host, default port stripped) and `GET /targets` looking for a match: first an exact canonical compare, then a strict same-host-same-path compare. A found target is **reused and never deleted**.
2. **Create target** — only when nothing matched, `POST /targets` with `targetDescription` + `criticality`; the returned id is remembered as connector-created.
3. **Schedule scan** — `POST /scans` with the target id, profile id and `schedule.disable=false` (run immediately).
4. **Poll** — `GET /scans/{id}` every 15s until `current_session.status` is `completed`; `aborted`/`failed` is a terminal error; a nil `current_session` keeps polling. The Worker's job timeout is the bound.
5. **Collect** — resolve the result id (matching the scan session, else the single result, else the newest), page through `/scans/{id}/results/{rid}/vulnerabilities` following cursors, then enrich each vulnerability with `GET .../vulnerabilities/{vuln_id}` through a bounded pool, map to findings, sort deterministically (severity desc → vuln_id asc → matched-at asc) and stream them to the Worker.
6. **Cleanup** — after findings stream: a connector-**created** target is deleted (`DELETE /targets/{id}`, which cascades its scan); a **reused** target is left untouched and its scan is deleted instead (`DELETE /scans/{id}`). On **any** failure nothing is deleted — resources are retained for inspection, and a created target orphaned this way carries the `oasm-scan` description for later operator reaping. Cleanup failures are logged, never fatal.

Files:
- `adapter.go` — `AcunetixAdapter` (`Validate` no-op + `Execute` flow); result-id resolution
- `acunetix.go` — config loader (`OASM_CONFIG` / `ACUNETIX_*`), Acunetix REST client, DTOs, cursor pagination
- `findings.go` — finding mapping, severity legend, CVE/CWE extraction, bounded-pool collection
- `main.go` — wires `AcunetixAdapter` + SDK (`sdk/connector`, `sdk/runtime`)
- `manifest.yaml` — source of truth for `manifest.json` (`inputsSchema`, `configSchema`)
- `Dockerfile` — `golang:1.26-alpine` builder → `alpine:3.20` non-root; no bundled tool binary

## Testing

```bash
cd vulnerabilities/acunetix && go test ./... -count=1
cd vulnerabilities/acunetix && go vet ./...
```

<!-- ponytail: the API client has no retry/backoff — a transient Acunetix 5xx fails the job (upgrade path: bounded retry on 429/5xx around do()). The per-vulnerability detail fetch runs through a bounded pool of ≤8 (findings.go detailWorkers); all findings are held in memory to sort (upgrade path: streaming/external sort for tens of thousands of items). -->
