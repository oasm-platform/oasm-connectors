# Nikto Connector

Runs [sullo/nikto](https://github.com/sullo/nikto) 2.6.1 via the OASM Worker gRPC bridge. Scans a web server for 7,000+ known issues — dangerous files and CGIs, outdated server software, missing security headers, and version-specific flaws — and enriches each result from nikto's own check database.

## Requirements

- Go 1.26+, Docker, Worker reachable at `WORKER_GRPC_ADDR`
- Tool binary `nikto.pl` bundled in the image via multi-stage `FROM hackllc/nikto:2.6.1`

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Configuration

| Parameter | env | default | mandatory | description |
|-----------|-----|---------|-----------|-------------|
| Worker address | `WORKER_GRPC_ADDR` | `localhost:50051` | yes | Worker gRPC endpoint (missing → fatal) |
| Worker token | `WORKER_TOKEN` | `` | no | Auth token if Worker requires it |
| Execution ID | `EXECUTION_ID` | — | yes | Job identity; the Worker routes `ExecuteJob` by it |
| Target | `inputs.target` | — | yes | Scan target: `http(s)://` URL or bare host |
| Nikto binary | `NIKTO_BIN` | `nikto.pl` | no | Override path to the nikto binary |
| Test database dir | `NIKTO_DB_DIR` | derived | no | Directory holding `db_tests`, for enrichment (see below) |
| Keep work dir | `NIKTO_KEEP_WORKDIR` | `` | no | Non-empty keeps the generated config on disk for debugging |

`inputsSchema` (see `manifest.yaml`): `{target: string (uri)}`.

Per-scan options come from the `OASM_CONFIG` JSON profile and map 1:1 onto the `configSchema` keys in `manifest.yaml` (`tuning`, `ports`, `ssl`, `root`, `vhost`, `userAgent`, `maxTime`, `timeout`, `pause`, `headers`, `noLookup`, `noCookies`, `followRedirects`, `no404`, `evasion`, `plugins`, `proxy`, `username`, `password`).

## Example config profile

```yaml
# Connector profile submitted to the Worker (ExecutionCommand spec)
slug: nikto
image: ghcr.io/oasm-platform/connector-nikto:2.6.1
inputs:
  target: https://example.com
```

## Deployment

### Docker

```bash
docker build -t ghcr.io/oasm-platform/connector-nikto:2.6.1 -f vulnerabilities/nikto/Dockerfile .
docker run --rm -e WORKER_GRPC_ADDR=worker:50051 -e EXECUTION_ID=job-1 \
  ghcr.io/oasm-platform/connector-nikto:2.6.1
```

### Manual

```bash
cd vulnerabilities/nikto && go run .
```

## Behavior

- `adapter.go` — `NiktoAdapter` (subprocess + stdout parsing); `Validate` (no-op) + `Execute`; `resolveSeverity`
- `nikto.go` — `OASM_CONFIG` → argv mapping and the generated `nikto.conf`
- `niktdb.go` — reads `db_tests` and maps a test id to its tuning category and severity
- `findings.go` — `titleFromMessage` (title/description split), keyword severity rubric (the fallback path) and shared helpers
- `main.go` — wires `NiktoAdapter` + SDK (`sdk/connector`, `sdk/runtime`)
- `manifest.yaml` — source of truth for `manifest.json` (image `ghcr.io/oasm-platform/connector-nikto:2.6.1` is an SDK+tool bundle, not upstream)
- `Dockerfile` — `golang:1.26-alpine` builder → `hackllc/nikto:2.6.1` non-root final stage
- `testdata/fake-nikto/` — test stub that prints canned stdout; driven by `FAKE_MODE`

### Generated config and interactivity

`nikto.conf.default` ships `UPDATES=yes` (Nikto prompts before submitting unidentified server banners) and leaves `PROMPTS` live. A container with no TTY would block on that prompt until the job timeout, and neither setting has a CLI flag. The adapter therefore always writes its own `nikto.conf` (`UPDATES=no`, `PROMPTS=no`) and passes it with `-config`, plus `-nointeractive` to disable the runtime keyboard toggles. `-config` replaces the default config rather than merging with it, which is why the generated file restates the shipped values it depends on.

### Exit codes and error policy

Nikto exits 0 for a completed scan (vulnerable or not) and 1 for a usage/config/database error. stdout is the source of truth:

| Condition | Result |
|-----------|--------|
| 0 findings, exit 0 | success (clean target) |
| N findings, exit 0 | success |
| N findings, exit ≠ 0 | success — partial results are kept |
| 0 findings, exit ≠ 0 | error carrying the exit code and stderr tail |
| `+ [FAIL] Unable to connect …` | not a finding — logged to stderr, zero findings, success |
| cancelled by the caller | error carrying the context error; findings already streamed were delivered, but see Time budget |

The connect-failure line matters: Nikto reports an unreachable target through the same `+ [id] message` channel as a real result, so without filtering it a host that was merely down would persist a phantom vulnerability.

### Time budget

**The connector imposes no time limit of its own.** Vulnerability scans are legitimately long — a full CGI sweep against a slow host, or a target that deliberately stalls a scanner, is a long job rather than a failure — so nothing in this adapter ends a scan early.

A scan ends in exactly three ways:

1. **Nikto finishes** — the normal case, and the only one that produces a complete result set.
2. **`maxTime` is set** — you asked for a budget, so `-maxtime` is passed through verbatim and nikto stops itself, prints its summary, and exits 0 with everything it collected. Unset means unset: the adapter does not substitute a built-in value.
3. **The caller cancels** — the Worker enforces `resourceDefaults.timeoutSeconds` and cancels the execution. Findings already streamed stay delivered; the adapter reports the cancellation faithfully.

`maxTime` accepts what nikto accepts: a duration (`30m`, `1h`, `600s`) or a bare number read as seconds.

Two consequences worth knowing before relying on this:

- **Long scans hold a container.** There is no scan-level ceiling any more, so a target that never finishes occupies a pooled container until `timeoutSeconds` fires. That value (24h) is the real backstop — it is declared in the manifest, enforced by the Worker, and invisible to the connector.
- **Cancellation still discards the job's results.** The Worker submits a connector's findings only on a clean `Done`; when the execution is cancelled the SDK stamps the error onto `Done` and the Worker reports the job failed instead of submitting. So if `timeoutSeconds` fires, findings already streamed are *not* persisted by the platform — they only reached the worker's stream. Set `maxTime` below `timeoutSeconds` if you want a long scan's partial results to survive.

### `-port` and the target URL

Nikto refuses `-port` together with a full URI (`ERROR: The -port option cannot be used with a full URI`, exit 1). When `ports` is configured the adapter therefore reduces the target to a bare host and expresses TLS with `-ssl` instead of the `https://` scheme, so `target: https://example.com` + `ports: 443` scans correctly rather than failing. Any port or path already in the URL is dropped in that case — `-port` is the authority on ports. Without `ports`, the URL is passed through untouched.

### Title and description

Nikto has one text field per check and it is written as a description, not a label: *"The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type."* Placing that whole string in `Name` made every vulnerability row a paragraph and left `Description` empty.

The adapter therefore splits it:

- `Description` always carries the **full** nikto message, unabridged.
- `Name` carries the **first sentence** — the finding itself; what follows is its consequence.

The split needs `. ` followed by a capital, so `Drupal version number 8.5.1 implies…` and `admin/phplist` are not cut. Of the 7,213 messages in `db_tests`, 630 (8.7%) contain a second sentence and get a genuinely shorter title; the other 91% are single-sentence and pass through unchanged, so `Name == Description` for them. That equality is not redundancy — it records that nikto supplied only one sentence, and no title was invented to fill the gap.

Splitting is the only place the adapter rewrites nikto's text. Note that Core computes a vulnerability's `fingerprint` as `md5(name + assetId + toolId)`, so a change to `Name` re-keys existing findings: the next scan inserts new rows instead of updating the old ones, and prior dismissals do not carry over.

### Severity and enrichment from `db_tests`

Nikto reports no severity — its stdout and its JSON report both carry only an id, a message, and references. But every result carries a test id, and the id indexes nikto's own check database at `databases/db_tests`, which ships inside the image. Each row classifies the check by *what it does* (its tuning code: `8` Command Execution, `9` SQL Injection, `2` Misconfiguration, and so on). The adapter reads that file at runtime and derives from it:

- **`category:<name>` tag** — exactly nikto's own wording for the check class (`category:SQL Injection`, `category:Denial of Service`). A check with several codes gets several tags.
- **Severity from the tuning class**, not from the wording. Multi-code checks take their worst band (`8a` = command execution + auth bypass → `critical`). Tagged `severity-source:tuning:<codes>`.
- **`CVEID` and `References`** recovered from the row's reference field.

Only when an id is absent from `db_tests` does the adapter fall back to keyword rules over the message, using the same ordered rubric the WPScan connector applies to its unscored titles. Those findings are tagged `severity-source:keyword` (a rule matched) or `severity-source:keyword-fallback` (nothing matched, so the conservative `medium` default applied).

The fallback is not an edge case: nikto defines 60 check ids in its plugins rather than in `db_tests` — including `013587`, the "Suggested security header missing" check that a default scan of any modern web server hits repeatedly. Those ids have no database row, so no category tag and a keyword-derived severity.

The database is read from disk, never copied or embedded. Its licence permits use only as part of the Nikto package (*"Database files are NOT licensed under the GPL … for use exclusively with Nikto"*, `program/COPYING`), which reading it in place satisfies and redistributing it would not. When the file cannot be found, enrichment is skipped and the scan still runs — findings then carry only keyword severities.

| Path | Result |
|------|--------|
| `NIKTO_DB_DIR` set | `<dir>/db_tests` |
| `NIKTO_BIN` set | `<dir of NIKTO_BIN>/databases/db_tests` |
| neither | `/opt/nikto/databases/db_tests` (the image layout) |

### Structured data not exposed

Nikto's JSON report also carries the HTTP request/response for each item. The adapter parses stdout instead, because driving `-Format json` requires an output file the adapter would then have to read — and the report stores the same id/message/references that stdout already provides. Reach for `-Format json` (or the `sqld` direct-database format) only if raw request/response capture is wanted; that is an SDK raw-data-channel change, not a connector-local one.

## Testing

```bash
cd vulnerabilities/nikto && go test ./... -v -count=1
cd vulnerabilities/nikto && go vet ./...
```

`testdata/fake-nikto` is built on demand by the tests; `FAKE_MODE` selects the fixture (`default`, `empty`, `unreachable`, `fail`, `partial-fail`, `hang`, `many`, `norefs`). `testdata/real-cve-stdout.txt` is stdout captured from real Nikto 2.6.1 (this connector's image scanning an `nginx:alpine` container with `-Tuning 236 -C all`) and is asserted directly, so the parser cannot drift from the upstream format. It deliberately contains both id kinds: `000024`/`007342`/`007352` resolve in `db_tests`, while `013587` does not.

The database-backed tests are skipped when `db_tests` is absent, so `go test ./...` stays green in a plain checkout. To exercise them, point `NIKTO_DB_DIR` at a copy extracted from the image:

```bash
docker run --rm -v "$PWD:/out" --entrypoint sh hackllc/nikto:2.6.1 \
  -c 'cp /opt/nikto/databases/db_tests /out/'
cd vulnerabilities/nikto && NIKTO_DB_DIR=$OLDPWD go test ./... -v -count=1
```

### E2E against the real tool

`e2e_test.go` is behind the `e2e` build tag and requires a real Nikto plus a reachable target:

```bash
docker network create oasm-nikto-e2e
docker run -d --name nikto-target --network oasm-nikto-e2e nginx:alpine
cd vulnerabilities/nikto
E2E_TARGET=http://nikto-target NIKTO_BIN=/path/to/nikto.pl \
  go test -tags e2e -run TestNiktoE2E_RealScan -v -count=1
```

The test asserts that the enrichment actually fired: every finding must carry a `severity-source:` tag, and at least one must be categorised from `db_tests`. A silent enrichment failure (database not found) is reported as a test failure rather than passing quietly.

## 14-step trace

Core (`manifest.json` via `ConnectorRegistry`) → `WorkerStream ExecutionCommand{spec{image, inputs}}` → Worker `ExecutionManager` → `DockerRuntime.Create(Image: spec.Image)` via `docker.sock` → Connector SDK → `NiktoAdapter.Execute` → proxy → Core persist.
