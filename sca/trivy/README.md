# Trivy Connector

Runs [Trivy](https://github.com/aquasecurity/trivy) 0.75.0 (`trivy fs`) via the OASM Worker gRPC bridge. Scans one repository of a Git organization target (`targetTypes: [git_org]`) for vulnerable dependencies and IaC misconfigurations, and optionally secrets, and reports each as a finding with its file, line and commit.

## Requirements

- Go 1.26+, Docker, Worker reachable at `WORKER_GRPC_ADDR`
- `trivy` and `git` bundled in the image via multi-stage `FROM aquasec/trivy:0.75.0` (pinned by digest)
- Outbound access to `mirror.gcr.io` for the vulnerability DB (and the Java DB, only for repositories containing `.jar`/`.war`/`.ear`/`.par` files). Misconfiguration checks use the bundle embedded in the trivy binary.

## Database cache

The vulnerability DB is ~1.5 GB unpacked: it fits neither the worker's 256 MB `/tmp` tmpfs nor the read-only root filesystem. The image declares `/var/cache/oasm-trivy` (`TRIVY_CACHE_DIR`) as an `oasm.persist` volume, which every container of the image shares, so the DB is downloaded once and then only refreshed when Trivy considers it stale.

Trivy unpacks an update in place, so containers coordinate with an `flock` on `.oasm-trivy.lock` in that volume:

1. **Update** (exclusive lock): `trivy fs --download-db-only` (+ `--download-java-db-only` when needed), with `TMPDIR` on the volume because the Java DB archive alone exceeds `/tmp`. Without a cached DB the job waits for the lock; with one, it waits at most 2 minutes for running scans, then scans with the cached copy. A failed refresh of a cached DB is logged and the cached copy is used; a failed first download fails the job.
2. **Scan** (shared lock — scans run in parallel): `--skip-db-update --skip-java-db-update --skip-check-update`, so a scan never writes the cache.

This connector is its own Go module. All dependencies, including the SDK (pulled in via a local `replace` to `../../sdk`), are declared in this directory's `go.mod`, so run build and test commands from here.

## Inputs

The repository contract of `sdk/gitrepo`, filled in by the platform for every repository:

| Input | mandatory | description |
|-------|-----------|-------------|
| `repository` | yes | https clone URL |
| `ref` | no | branch, tag or commit; empty = default branch |
| `username`, `token` | no | credentials for private repositories |

The repository is shallow-cloned (depth 1) into a temp dir and removed after the scan. The token reaches git as an in-memory `http.extraHeader` only; Trivy never sees it.

## Configuration

| Parameter | source | default | description |
|-----------|--------|---------|-------------|
| `scanners` | `OASM_CONFIG` | `[vuln, misconfig]` | Any of `vuln`, `misconfig`, `secret` (`--scanners`). Secrets are off by default: the Gitleaks job of `repository_scan` covers them |
| `severity` | `OASM_CONFIG` | all | Platform severities to report; `info` maps to Trivy's `UNKNOWN` (`--severity`) |
| `ignoreUnfixed` | `OASM_CONFIG` | `false` | Skip vulnerabilities without a fixed version (`--ignore-unfixed`) |
| `skipDirs` | `OASM_CONFIG` | `[]` | Directories or globs not scanned (`--skip-dirs`) |
| Trivy binary | `TRIVY_BIN` | `trivy` | Override path to the trivy binary |

An unknown scanner or severity is a `fatal:` configuration error, raised before the clone.

## Findings

| Kind | `Name` | `FilePath`, `LineStart`, `LineEnd` | `Fingerprint` |
|------|--------|------------------------------------|---------------|
| Vulnerability | `<advisory> in <package>` | the lockfile and the package's line in it | `<advisory>:<file>:<package>@<version>` |
| Misconfiguration | `<check ID>: <title>` | the IaC file and the offending lines (0 for file-level checks) | `<check ID>:<file>:<line>` |
| Secret | `Leaked secret: <rule>` | the file and lines | `<rule>:<file>:<line>` |

Severity maps `CRITICAL/HIGH/MEDIUM/LOW` one to one and `UNKNOWN` to `info`. Vulnerabilities also carry `PackageName`, `InstalledVersion`, `FixedVersion`, `CVEID`, `CWEID`, references, publication dates and one CVSS score — from the source Trivy took the severity from, else NVD, GHSA, Red Hat, then any; v3 before v4.0 before v2. Every finding carries the scanned `Commit`. Trivy masks secret values in its report, and the adapter does not read the masked line either.

## Build and test

```bash
GOWORK=off go test ./...
docker build -f sca/trivy/Dockerfile -t connector-trivy .   # from the repo root
```
