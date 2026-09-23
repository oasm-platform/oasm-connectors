# OpenVAS Connector

Drives a Greenbone/OpenVAS manager — `gvmd` — over GMP (Greenbone Management Protocol) on TLS via the OASM Worker gRPC bridge.
Connects, authenticates, creates a target and task, starts the scan, polls until done, streams the findings, then cleans up.

## Requirements

- Go 1.26+, Worker reachable at `WORKER_GRPC_ADDR`
- A Greenbone/OpenVAS `gvmd` instance reachable over TLS/TCP (default port 9390) with a valid GMP username/password

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Configuration

The connector reads its settings from `OASM_CONFIG` — the per-job config profile
the Worker ships as JSON (camelCase keys mirroring `manifest.yaml` `configSchema`).
This is the new-SDK path that makes warm-pool reuse work: the SDK overrides
`OASM_CONFIG` per execution, so a reused container sees its own job's config.
`OPENVAS_*` env vars remain as a legacy fallback for direct-runtime use.

```json
{
  "host": "gvmd.example.com",
  "port": 9390,
  "username": "admin",
  "password": "your-gmp-password",
  "caCert": "",
  "clientCert": "",
  "clientKey": "",
  "disableTlsChecks": false,
  "scannerId": "",
  "configId": "",
  "portListId": ""
}
```

| Key | legacy env fallback | default | mandatory | description |
|-----|---------------------|---------|-----------|-------------|
| `host` | `OPENVAS_HOST` | — | yes | Hostname or IP of the `gvmd` management daemon |
| `username` | `OPENVAS_USERNAME` | — | yes | Greenbone user used for GMP authentication |
| `password` | `OPENVAS_PASSWORD` | — | yes | Greenbone user password |
| `port` | `OPENVAS_PORT` | `9390` | no | GMP TLS/TCP port on `gvmd` |
| `caCert` | `OPENVAS_CA_CERT` | `` (system trust store) | no | PEM CA certificate used to verify the gvmd server certificate |
| `clientCert` | `OPENVAS_CLIENT_CERT` | `` | no | PEM client certificate for mutual TLS (must be set together with `clientKey`) |
| `clientKey` | `OPENVAS_CLIENT_KEY` | `` | no | PEM private key matching `clientCert` |
| `disableTlsChecks` | `OPENVAS_INSECURE` | `false` | no | Skip server certificate verification (test/self-signed deployments only) |
| `scannerId` | `OPENVAS_SCANNER_ID` | `08b69003-5fc2-4037-a479-93b440211c73` (built-in OpenVAS scanner) | no | GMP scanner UUID |
| `configId` | `OPENVAS_CONFIG_ID` | `daba56c8-73ec-11df-a475-002264764cea` (Full and Fast) | no | GMP scan config UUID |
| `portListId` | `OPENVAS_PORT_LIST_ID` | `` (gvmd default port list) | no | GMP port list UUID |

Worker connection (`WORKER_GRPC_ADDR`, `WORKER_TOKEN`) and `EXECUTION_ID` are
injected by the Worker; the task name is derived from the target per execution.

`inputsSchema` (see `manifest.yaml`): `{target: string (uri)}`.

### Transport reality

Stock `gvmd` TCP uses TLS requiring a CA plus server **and client** certificate
(`gvm-manage-certs -a` issues both sides), so `clientCert`/`clientKey` are
effectively mandatory in production. The Greenbone Community Edition container
listens on a Unix socket only, so remote access needs
`gvmd --listen … -p 9390` or stunnel fronting the socket.

## Deployment

### Docker

```bash
docker build -f vulnerabilities/openvas/Dockerfile -t ghcr.io/oasm-platform/connector-openvas:0.1.0 .
docker run --rm -e WORKER_GRPC_ADDR=worker:50051 -e EXECUTION_ID=job-1 \
  -e OASM_CONFIG='{"host":"gvmd.example.com","port":9390,"username":"admin","password":"your-gmp-password"}' \
  ghcr.io/oasm-platform/connector-openvas:0.1.0
```

### Manual

```bash
cd vulnerabilities/openvas && go run .
```

## Behavior

1. **Connect & authenticate** — TLS-dial `gvmd` (optional CA + client cert mTLS), then GMP `authenticate` with the configured username/password.
2. **Create target & task** — `create_target` for the input target (remembered as connector-created), then `create_task` bound to the scan config, target and scanner.
3. **Start & poll** — `start_task`, then poll `get_tasks` until status `Done`; `Interrupted` is retryable, `Stopped`/`Delete Requested` are fatal.
4. **Stream findings** — `get_results` mapped to `connector.Finding` (severity table, CVE/CWE/URL refs, CVSS/QoD), deterministically sorted, streamed to the Worker.
5. **Cleanup** — on success: delete the task then the connector-created target. **Retention-on-failure**: on any non-cancellation failure nothing is deleted (resources retained for inspection); on cancellation the task is stopped and both are deleted, best effort. Cleanup failures are logged, never fatal.

Files:
- `adapter.go` — `OpenVASAdapter` (`Validate` no-op + `Execute` flow)
- `config.go` — config loader (`OASM_CONFIG` / `OPENVAS_*`)
- `gmp.go` — self-contained GMP TLS transport (framing, errors)
- `commands.go` — typed GMP command layer (target/task/start/poll/results/cleanup)
- `findings.go` — GMP `<result>` → `connector.Finding` mapper
- `main.go` — wires `OpenVASAdapter` + SDK (`sdk/connector`, `sdk/runtime`)
- `manifest.yaml` — source of truth for `manifest.json`
- `Dockerfile` — `golang:1.26-alpine` builder → `alpine:3.20` non-root; no bundled tool binary

## Testing

```bash
cd vulnerabilities/openvas && go test ./... -count=1
cd vulnerabilities/openvas && go vet ./...
```

<!-- ponytail: GMP over Unix socket and SSH transports are not implemented (upgrade path: add a socketPath or SSH transport); relies on the server exposing GMP over TLS/TCP on port 9390. -->
