# OWASP ZAP Connector

Runs [OWASP ZAP](https://www.zaproxy.org/) scans via the OASM Worker gRPC bridge and streams the
discovered alerts to Core as normalized findings. ZAP is only used as a **scan engine** — its JSON
report is an internal transport, parsed and discarded, never surfaced as a user-facing report.

## How it works

```
target ─► render automation plan.yaml ─► zap.sh -cmd -silent -autorun plan.yaml
        ─► report.json (traditional-json) ─► parse alerts ─► connector.Finding stream ─► Core
```

The adapter writes a temp dir containing `plan.yaml`, a fresh ZAP home (`-dir`) and `report.json`,
runs ZAP to completion, parses `site[].alerts[]`, and streams one finding per alert. The temp dir is
removed on return so warm-pool reuse stays clean.

## Scan modes

| `scanMode` | Jobs | Safety |
|------------|------|--------|
| `baseline` (default) | spider + passive scanner | Safe: only observes |
| `full` | + active scanner | **Attacks the target** — use only with permission |

The active scanner is always opt-in. `full` raises the adapter's hard timeout from 15 to 45 minutes.

## Configuration

Settings come from `OASM_CONFIG` — the per-job config profile the Worker ships as JSON (camelCase
keys mirroring `manifest.yaml` `configSchema`). `OASM_CONFIG` is overridden per execution by the SDK
so a reused container sees its own job's config.

| Key | default | description |
|-----|---------|-------------|
| `scanMode` | `baseline` | `baseline` \| `full` |
| `maxSpiderDepth` | `5` | spider link depth |
| `maxSpiderDuration` | `5` | spider / passive-wait budget (minutes) |
| `maxScanDurationInMins` | `10` | active scanner cap (minutes, `full` only) |
| `delayInMs` | `0` | delay between active scan requests |
| `threadPerHost` | `2` | active scan threads per host |
| `policy` | `Default Policy` | active scan policy (`full` only) |
| `enableAjaxSpider` | `false` | also run the AJAX spider (needs a browser) |

`inputsSchema`: `{target: string (uri)}`. A bare host is prefixed with `https://`.

`ZAP_BIN` (default `zap.sh`) overrides the ZAP launcher path.

## Behavior

1. Render the Automation Framework plan for the selected mode.
2. Run `zap.sh -cmd -silent -nostdout -autorun <plan> -dir <tmp-home>`. `-silent` blocks ZAP's
   unsolicited startup egress (update checks); `-cmd` makes it exit when the plan finishes.
3. Read the JSON report. A parseable report wins over a nonzero exit code (ZAP exits 1 on errors,
   2 on warnings) — partial results are still useful. Only a missing/unparseable report or the hard
   timeout is fatal.
4. Map each alert to a `connector.Finding` and stream it. The JVM process group is killed on
   cancel/timeout so it cannot survive container reuse.

### Finding mapping

| Finding field | ZAP source |
|---------------|-----------|
| `Name` | `alert.name` (fallback `alert.alert`) |
| `Severity` | `riskcode` 0→info, 1→low, 2→medium, 3→high (ZAP has no critical) |
| `Host` | `site.@host` (fallback target host) |
| `MatchedAt` | first instance URI |
| `CWEID` | `cweid` (dropped when `0`) |
| `References` | `<p>` blocks in `reference`, HTML-unescaped |
| `Solution` | `solution` |
| `Tags` | `pluginid:`, `confidence:`, `instance-count:`, `affected-uri:` (first 5 instances) |

The Worker drops `MatchedAt` for the vulnerabilities pipeline, so affected URIs also travel as tags.

## Files

- `adapter.go` — `ZapAdapter` (`Validate` + `Execute`)
- `zap.go` — `OASM_CONFIG` loader + Automation Framework plan renderer
- `findings.go` — traditional-json report parser + severity mapping
- `proc_unix.go` / `proc_windows.go` — process-group kill so the JVM dies with `zap.sh`
- `main.go` — wires `ZapAdapter` + SDK
- `manifest.yaml` — source of truth for `manifest.json`
- `Dockerfile` — `golang:1.26-alpine` builder → `zaproxy/zap-stable:2.17.0`, non-root `zap`

## Testing

Unit tests build `testdata/fake-zap` at runtime; no ZAP install or network required. The fake reads
the `-autorun` plan, writes its fixture to the plan's report destination, and exits with a
mode-selected status.

```bash
cd vulnerabilities/zap && go test ./... -count=1
cd vulnerabilities/zap && go vet ./...
```

To exercise a real ZAP install end-to-end, set `ZAP_E2E_TARGET` (the test is skipped otherwise):

```bash
# zap.sh on PATH
ZAP_E2E_TARGET=https://example.com go test -run TestE2E_RealZap -v -count=1 -timeout 30m

# Windows with the ZAP installer
set ZAP_E2E_TARGET=https://example.com
set ZAP_BIN=C:\Program Files\ZAP\Zed Attack Proxy\zap.bat
go test -run TestE2E_RealZap -v -count=1 -timeout 30m
```

`OASM_CONFIG` overrides the profile (defaults to the safe `baseline`). `ZAP_KEEP_WORKDIR=1` keeps the
generated `plan.yaml`, `report.json` and stderr on disk for debugging instead of deleting them.

## Deployment

```bash
docker build -t ghcr.io/oasm-platform/connector-zap:2.17.0 -f vulnerabilities/zap/Dockerfile .
docker run --rm -e WORKER_GRPC_ADDR=worker:50051 \
  -e OASM_CONFIG='{"scanMode":"baseline"}' \
  ghcr.io/oasm-platform/connector-zap:2.17.0
```

<!-- ponytail: license note — ZAP is Apache-2.0 and is redistributed inside this image; retain the
     upstream NOTICE. No logo.png ships (combine-manifest treats it as optional). -->
