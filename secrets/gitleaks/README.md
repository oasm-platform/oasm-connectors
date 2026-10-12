# Gitleaks Connector

Runs [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 via the OASM Worker gRPC bridge. Scans one repository of a Git organization target (`targetTypes: [git_org]`) for committed credentials — API keys, tokens, private keys, passwords — and reports each as a finding with its file, line and commit. Secret values are redacted inside gitleaks (`--redact`) and never read by the adapter.

## Requirements

- Go 1.26+, Docker, Worker reachable at `WORKER_GRPC_ADDR`
- `gitleaks` and `git` bundled in the image via multi-stage `FROM zricethezav/gitleaks:v8.30.1`

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Inputs

The repository contract of `sdk/gitrepo`, filled in by the platform for every repository:

| Input | mandatory | description |
|-------|-----------|-------------|
| `repository` | yes | https clone URL |
| `ref` | no | branch, tag or commit; empty = default branch |
| `username`, `token` | no | credentials for private repositories |

The repository is shallow-cloned into a temp dir and removed after the scan. The token reaches git as an in-memory `http.extraHeader` only.

## Configuration

| Parameter | source | default | description |
|-----------|--------|---------|-------------|
| `scanHistory` | `OASM_CONFIG` | `false` | Also scan recent commits (`gitleaks git`) instead of only the checked-out tree (`gitleaks dir`) |
| `historyDepth` | `OASM_CONFIG` | `100` | Commits scanned (and clone depth) when `scanHistory` is on; capped at 5000 |
| Gitleaks binary | `GITLEAKS_BIN` | `gitleaks` | Override path to the gitleaks binary |

## Findings

| Finding field | Source |
|---------------|--------|
| `Name` | `Leaked secret: <RuleID>` |
| `Severity` | `critical` for private keys and cloud/forge access tokens, otherwise `high` |
| `FilePath`, `LineStart`, `LineEnd` | the leak's file (repository-relative) and lines |
| `Commit` | the leak's commit (history scans) or the scanned commit (tree scans) |
| `Fingerprint` | `<RuleID>:<file>:<line>` — stable while the secret stays put; the platform dedupes on it |

## Build and test

```bash
GOWORK=off go test ./...
docker build -f secrets/gitleaks/Dockerfile -t connector-gitleaks .   # from the repo root
```
