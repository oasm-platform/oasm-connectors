#!/usr/bin/env bash
# Test suite for detect-changed-connectors.sh
#
#   bash .github/scripts/detect-changed-connectors_test.sh
#
# Every case builds a throwaway git repository that mirrors the real layout
# (a few `<category>/<slug>/` connectors, one shared `sdk/` module, a root
# module), commits a base revision, changes one thing, and asserts on the
# detector's stdout — which is written in `$GITHUB_OUTPUT` syntax, so the
# suite reads it with `eval`, exactly as a workflow step would.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SCRIPT_DIR/detect-changed-connectors.sh"

if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "bash 4+ required (associative arrays), found ${BASH_VERSION}" >&2
  exit 1
fi

passed=0
failed=0

start() { printf '\n== %s\n' "$1"; }

check() { # name expected actual
  if [ "$2" = "$3" ]; then
    passed=$((passed + 1))
    printf '  ok   %s\n' "$1"
  else
    failed=$((failed + 1))
    printf '  FAIL %s\n       want: %s\n       got:  %s\n' "$1" "$2" "$3"
  fi
}

check_contains() { # name haystack needle
  case "$2" in
    *"$3"*)
      passed=$((passed + 1))
      printf '  ok   %s\n' "$1"
      ;;
    *)
      failed=$((failed + 1))
      printf '  FAIL %s\n       want to contain: %s\n       got: %s\n' "$1" "$3" "$2"
      ;;
  esac
}

TMPROOT="$(mktemp -d)"
trap 'rm -rf "$TMPROOT"' EXIT

OUT="$TMPROOT/detector.out"
ERR="$TMPROOT/detector.err"

# --- fixture -------------------------------------------------------------

write_connector() { # dir slug version
  local dir="$1" slug="$2" version="$3"
  mkdir -p "$REPO/$dir"
  cat >"$REPO/$dir/manifest.yaml" <<EOF
name: $slug
slug: $slug
version: $version
image: ghcr.io/oasm-platform/connector-$slug:$version
EOF
  cat >"$REPO/$dir/Dockerfile" <<EOF
# connector image (SDK) — build context: repo root
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY sdk/go.mod sdk/go.sum sdk/
COPY $dir/go.mod $dir/go.sum $dir/
RUN cd $dir && GOWORK=off go mod download
COPY sdk/ sdk/
COPY $dir/ $dir/
RUN cd $dir && CGO_ENABLED=0 GOWORK=off go build -trimpath -o /out/connector .
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/connector /usr/local/bin/connector
ENTRYPOINT ["/usr/local/bin/connector"]
EOF
  printf 'module %s\n\ngo 1.26\n' "$dir" >"$REPO/$dir/go.mod"
  printf '// checksums\n' >"$REPO/$dir/go.sum"
  printf '// placeholder\n' >"$REPO/$dir/main.go"
}

new_repo() { # -> fresh repo with a base commit, sets $REPO and $BASE_SHA
  REPO="$(mktemp -d "$TMPROOT/repo.XXXXXX")"
  local entry dir slug version
  for entry in "ports_scanner/nmap:nmap:7.97" \
    "ports_scanner/rustscan:rustscan:2.4.1" \
    "url_discovery/katana:katana:1.7.0" \
    "vulnerabilities/nuclei:nuclei:3.4.1"; do
    dir="${entry%%:*}"
    slug="${entry#*:}"
    slug="${slug%%:*}"
    version="${entry##*:}"
    write_connector "$dir" "$slug" "$version"
  done

  # katana is the multi-stage one: --from= sources are stage outputs, not
  # build-context inputs, and must never be read as shared inputs.
  cat >>"$REPO/url_discovery/katana/Dockerfile" <<'EOF'
FROM alpine:3.20
COPY --from=builder /out/katana /usr/local/bin/katana
EOF

  # rustscan uses line continuations in COPY, like the real Dockerfiles do
  # once the source list outgrows the line budget.
  cat >>"$REPO/ports_scanner/rustscan/Dockerfile" <<'EOF'
FROM alpine:3.20
COPY ports_scanner/rustscan/go.sum \
     ports_scanner/rustscan/NOTICE \
     /tmp/
EOF

  mkdir -p "$REPO/sdk/connector" "$REPO/scripts/combine-manifest" "$REPO/.github/workflows"
  printf 'module sdk\n\ngo 1.26\n' >"$REPO/sdk/go.mod"
  printf 'module github.com/oasm-platform/oasm-connectors\n\ngo 1.26\n' >"$REPO/go.mod"
  printf 'go 1.26.0\n\nuse (\n\t.\n\t./sdk\n)\n' >"$REPO/go.work"
  printf '{"generatedAt":"now","connectors":[]}\n' >"$REPO/manifest.json"
  printf '// placeholder\n' >"$REPO/sdk/connector/connector.go"
  printf '// placeholder\n' >"$REPO/scripts/combine-manifest/combine-manifest.go"
  printf '# oasm-connectors\n' >"$REPO/README.md"
  printf 'LICENSE\n' >"$REPO/LICENSE"
  printf '.git\n' >"$REPO/.dockerignore"
  printf 'CVE-0000-0000\n' >"$REPO/.trivyignore"
  printf 'version: "3"\n' >"$REPO/Taskfile.yml"
  printf 'name: ci\n' >"$REPO/.github/workflows/ci.yml"

  git -C "$REPO" init -q -b main
  git -C "$REPO" config user.email ci@example.com
  git -C "$REPO" config user.name ci
  # Keep the fixture byte-exact: the detector reads the working tree, and a
  # CRLF round-trip would rewrite the Dockerfiles it parses.
  git -C "$REPO" config core.autocrlf false
  git -C "$REPO" config core.safecrlf false
  git -C "$REPO" add -A
  git -C "$REPO" commit -qm "base"
  BASE_SHA="$(git -C "$REPO" rev-parse HEAD)"
}

# --- driver --------------------------------------------------------------

# Reads the `$GITHUB_OUTPUT` format the way the runner does: `key=value` lines
# and `key<<DELIM` heredoc blocks. `eval` cannot stand in for it — it eats the
# JSON quotes and parses `key<<DELIM` as a command — so this parser is also what
# pins the format down.
parse_outputs() { # file
  local line key value delim state=0
  MATRIX=""
  TEST_DIRS=""
  HAS_BUILD=""
  HAS_TEST=""
  BUILD_ALL=""
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$state" = 1 ]; then
      if [ "$line" = "$delim" ]; then
        value="${value%$'\n'}"
        [ "$key" = test_dirs ] && TEST_DIRS="$value"
        state=0
      else
        value="$value$line"$'\n'
      fi
      continue
    fi
    case "$line" in
      *'<<'*)
        key="${line%%<<*}"
        delim="${line#*<<}"
        value=""
        state=1
        ;;
      *=*)
        key="${line%%=*}"
        value="${line#*=}"
        case "$key" in
          matrix) MATRIX="$value" ;;
          has_build) HAS_BUILD="$value" ;;
          has_test) HAS_TEST="$value" ;;
          build_all) BUILD_ALL="$value" ;;
        esac
        ;;
    esac
  done <"$1"
}

detect() { # [script args...] -> sets MATRIX, TEST_DIRS, HAS_BUILD, ...
  DETECT_RC=0
  (cd "$REPO" && bash "$SCRIPT" "$@") >"$OUT" 2>"$ERR" || DETECT_RC=$?
  if [ "$DETECT_RC" = 0 ]; then
    parse_outputs "$OUT"
  fi
}

detect_between() { detect --root "$REPO" --base "$BASE_SHA" --head HEAD; }

test_dirs() { printf '%s\n' "$TEST_DIRS" | sed '/^$/d' | LC_ALL=C sort | tr '\n' ' '; }
stderr() { cat "$ERR"; }

entry() { printf '{"dir":"%s","slug":"%s","version":"%s","tag":"%s"}' "$1" "$2" "$3" "${4:-$3}"; }

matrix_of() {
  local out="" sep="" e
  for e in "$@"; do
    out="$out$sep$e"
    sep=", "
  done
  printf '{"include":[%s]}' "$out"
}

ALL_DIRS="ports_scanner/nmap ports_scanner/rustscan url_discovery/katana vulnerabilities/nuclei"
ALL_MATRIX="$(matrix_of \
  "$(entry ports_scanner/nmap nmap 7.97)" \
  "$(entry ports_scanner/rustscan rustscan 2.4.1)" \
  "$(entry url_discovery/katana katana 1.7.0)" \
  "$(entry vulnerabilities/nuclei nuclei 3.4.1)")"
EMPTY_MATRIX='{"include":[]}'

# --- cases ---------------------------------------------------------------

start "one connector's code changed builds only that connector"
new_repo
printf '// changed\n' >>"$REPO/vulnerabilities/nuclei/main.go"
git -C "$REPO" commit -qam "nuclei: fix finding mapping"
detect_between
check "exit 0" "0" "$DETECT_RC"
check "matrix" "$(matrix_of "$(entry vulnerabilities/nuclei nuclei 3.4.1)")" "$MATRIX"
check "test dirs" "vulnerabilities/nuclei " "$(test_dirs)"
check "has_build" "true" "$HAS_BUILD"
check "has_test" "true" "$HAS_TEST"
check "build_all" "false" "$BUILD_ALL"

start "two connectors changed build exactly those two"
new_repo
printf '// changed\n' >>"$REPO/ports_scanner/nmap/main.go"
printf '// changed\n' >>"$REPO/url_discovery/katana/main.go"
git -C "$REPO" commit -qam "nmap + katana"
detect_between
check "matrix" "$(matrix_of \
  "$(entry ports_scanner/nmap nmap 7.97)" \
  "$(entry url_discovery/katana katana 1.7.0)")" "$MATRIX"
check "test dirs" "ports_scanner/nmap url_discovery/katana " "$(test_dirs)"

start "a nested file maps to its connector, not to the category"
new_repo
mkdir -p "$REPO/vulnerabilities/nuclei/internal/parse"
printf '// package parse\n' >"$REPO/vulnerabilities/nuclei/internal/parse/parse.go"
git -C "$REPO" add -A
git -C "$REPO" commit -qm "nuclei: extract parser"
detect_between
check "matrix" "$(matrix_of "$(entry vulnerabilities/nuclei nuclei 3.4.1)")" "$MATRIX"
check "test dirs" "vulnerabilities/nuclei " "$(test_dirs)"

start "a COPY with line continuations is one instruction, and a self-COPY is not a shared input"
new_repo
printf 'module bumped\n' >>"$REPO/ports_scanner/rustscan/go.sum"
git -C "$REPO" commit -qam "rustscan: bump dep"
detect_between
check "matrix" "$(matrix_of "$(entry ports_scanner/rustscan rustscan 2.4.1)")" "$MATRIX"
check "build_all" "false" "$BUILD_ALL"

start "a --from= source is a stage output, not a build-context input"
new_repo
mkdir -p "$REPO/url_discovery/katana/bin"
printf '// changed\n' >>"$REPO/url_discovery/katana/bin/tool.go"
git -C "$REPO" add -A
git -C "$REPO" commit -qm "katana: tool"
detect_between
check "matrix" "$(matrix_of "$(entry url_discovery/katana katana 1.7.0)")" "$MATRIX"

start "sdk change rebuilds every connector and tests the sdk too"
new_repo
printf '// changed\n' >>"$REPO/sdk/connector/connector.go"
git -C "$REPO" commit -qam "sdk: add SUCCESS level"
detect_between
check "matrix" "$ALL_MATRIX" "$MATRIX"
check "test dirs" "$(printf '%s\n' $ALL_DIRS sdk | LC_ALL=C sort | tr '\n' ' ')" "$(test_dirs)"
check "build_all" "true" "$BUILD_ALL"

start ".dockerignore change rebuilds every connector (it filters every context)"
new_repo
printf '.git\n.playwright-mcp\n' >"$REPO/.dockerignore"
git -C "$REPO" commit -qam "dockerignore: exclude playwright state"
detect_between
check "matrix" "$ALL_MATRIX" "$MATRIX"
check "build_all" "true" "$BUILD_ALL"

start "a connector's go.sum change rebuilds only that connector"
new_repo
printf 'module bumped\n' >>"$REPO/vulnerabilities/nuclei/go.sum"
git -C "$REPO" commit -qam "nuclei: bump dep"
detect_between
check "matrix" "$(matrix_of "$(entry vulnerabilities/nuclei nuclei 3.4.1)")" "$MATRIX"

start "a manifest.yaml version bump publishes under the new tag"
new_repo
sed -i 's/^version: 3\.4\.1$/version: 3.4.2/' "$REPO/vulnerabilities/nuclei/manifest.yaml"
git -C "$REPO" commit -qam "nuclei: release 3.4.2"
detect_between
check "matrix" "$(matrix_of "$(entry vulnerabilities/nuclei nuclei 3.4.2)")" "$MATRIX"
check "tag follows version" "3.4.2" "$(printf '%s' "$MATRIX" | sed -n 's/.*"tag":"\([^"]*\)".*/\1/p')"
check "manifest sync gate runs too" ". vulnerabilities/nuclei " "$(test_dirs)"

start "a newly added connector is built once"
new_repo
write_connector "vulnerabilities/openvas" "openvas" "22.4.0"
git -C "$REPO" add -A
git -C "$REPO" commit -qm "openvas: first cut"
detect_between
check "matrix" "$(matrix_of "$(entry vulnerabilities/openvas openvas 22.4.0)")" "$MATRIX"

start "a deleted connector is reported, not built"
new_repo
git -C "$REPO" rm -qr url_discovery/katana
git -C "$REPO" commit -qm "katana: remove"
detect_between
check "exit 0" "0" "$DETECT_RC"
check "matrix" "$EMPTY_MATRIX" "$MATRIX"
check_contains "warns about the removal" "$(stderr)" "url_discovery/katana"

start "a renamed file inside a connector still rebuilds it"
new_repo
git -C "$REPO" mv vulnerabilities/nuclei/main.go vulnerabilities/nuclei/adapter.go
git -C "$REPO" commit -qm "nuclei: rename main.go"
detect_between
check "matrix" "$(matrix_of "$(entry vulnerabilities/nuclei nuclei 3.4.1)")" "$MATRIX"

start "root module files are gated by tests, not by image builds"
for f in go.work manifest.json Taskfile.yml; do
  new_repo
  printf '// touched\n' >>"$REPO/$f"
  git -C "$REPO" commit -qam "root: touch $f"
  detect_between
  check "$f: matrix" "$EMPTY_MATRIX" "$MATRIX"
  check "$f: has_build" "false" "$HAS_BUILD"
  check "$f: test dirs" ". " "$(test_dirs)"
done

start "scripts/ belongs to the root module"
new_repo
printf '// touched\n' >>"$REPO/scripts/combine-manifest/combine-manifest.go"
git -C "$REPO" commit -qam "scripts: touch generator"
detect_between
check "matrix" "$EMPTY_MATRIX" "$MATRIX"
check "test dirs" ". " "$(test_dirs)"

start "documentation and CI config changes build and test nothing"
for f in README.md LICENSE .trivyignore .github/workflows/ci.yml; do
  new_repo
  printf '// touched\n' >>"$REPO/$f"
  git -C "$REPO" commit -qam "docs: touch $f"
  detect_between
  check "$f: matrix" "$EMPTY_MATRIX" "$MATRIX"
  check "$f: has_build" "false" "$HAS_BUILD"
  check "$f: has_test" "false" "$HAS_TEST"
done

start "a category-level file is not mistaken for a connector"
new_repo
printf '# vulnerabilities\n' >"$REPO/vulnerabilities/README.md"
git -C "$REPO" add -A
git -C "$REPO" commit -qm "docs: describe the category"
detect_between
check "matrix" "$EMPTY_MATRIX" "$MATRIX"
check "test dirs" ". " "$(test_dirs)"

start "a first push (zero base sha) rebuilds everything"
new_repo
detect --root "$REPO" --base 0000000000000000000000000000000000000000 --head HEAD
check "exit 0" "0" "$DETECT_RC"
check "matrix" "$ALL_MATRIX" "$MATRIX"
check "build_all" "true" "$BUILD_ALL"

start "an unreachable base (force-push) rebuilds everything"
new_repo
detect --root "$REPO" --base deadbeefdeadbeefdeadbeefdeadbeefdeadbeef --head HEAD
check "exit 0" "0" "$DETECT_RC"
check "matrix" "$ALL_MATRIX" "$MATRIX"
check "build_all" "true" "$BUILD_ALL"

start "a missing base argument rebuilds everything"
new_repo
detect --root "$REPO" --head HEAD
check "matrix" "$ALL_MATRIX" "$MATRIX"

start "--force-all rebuilds everything"
new_repo
printf '// changed\n' >>"$REPO/vulnerabilities/nuclei/main.go"
git -C "$REPO" commit -qam "nuclei: fix"
detect --root "$REPO" --base "$BASE_SHA" --head HEAD --force-all
check "matrix" "$ALL_MATRIX" "$MATRIX"
check "build_all" "true" "$BUILD_ALL"

start "--tag-override replaces the tag on every entry"
new_repo
detect --root "$REPO" --force-all --tag-override sha-abc1234
check "matrix" "$(matrix_of \
  "$(entry ports_scanner/nmap nmap 7.97 sha-abc1234)" \
  "$(entry ports_scanner/rustscan rustscan 2.4.1 sha-abc1234)" \
  "$(entry url_discovery/katana katana 1.7.0 sha-abc1234)" \
  "$(entry vulnerabilities/nuclei nuclei 3.4.1 sha-abc1234)")" "$MATRIX"

start "a connector without a slug is skipped with a warning, not a failure"
new_repo
printf 'name: broken\nversion: 1.0.0\n' >"$REPO/vulnerabilities/nuclei/manifest.yaml"
git -C "$REPO" commit -qam "nuclei: drop slug"
detect_between
check "exit 0" "0" "$DETECT_RC"
check "matrix" "$EMPTY_MATRIX" "$MATRIX"
check_contains "warns about the broken manifest" "$(stderr)" "vulnerabilities/nuclei"

start "a connector without a Dockerfile is not a build target, but is still tested"
new_repo
rm "$REPO/vulnerabilities/nuclei/Dockerfile"
printf '// changed\n' >>"$REPO/vulnerabilities/nuclei/main.go"
git -C "$REPO" commit -qam "nuclei: no image"
detect_between
check "matrix" "$EMPTY_MATRIX" "$MATRIX"
check "test dirs" "vulnerabilities/nuclei " "$(test_dirs)"

start "an empty diff builds and tests nothing"
new_repo
git -C "$REPO" commit -q --allow-empty -m "chore: empty"
detect_between
check "exit 0" "0" "$DETECT_RC"
check "matrix" "$EMPTY_MATRIX" "$MATRIX"
check "has_build" "false" "$HAS_BUILD"
check "has_test" "false" "$HAS_TEST"

start 'stdout is $GITHUB_OUTPUT syntax and diagnostics go to stderr'
new_repo
printf '// changed\n' >>"$REPO/vulnerabilities/nuclei/main.go"
git -C "$REPO" commit -qam "nuclei: fix"
SUMMARY="$TMPROOT/summary.md"
: >"$SUMMARY"
GITHUB_STEP_SUMMARY="$SUMMARY" detect_between
check_contains "multi-line output uses a heredoc block" "$(cat "$OUT")" 'test_dirs<<OASM_TEST_DIRS'
check_contains "scalar output is key=value" "$(cat "$OUT")" 'has_build=true'
check "stdout carries only output keys" "build_all has_build has_test matrix test_dirs" \
  "$(grep -oE '^[a-z_]+(=|<<)' "$OUT" | sed 's/[<=]*$//' | LC_ALL=C sort -u | tr '\n' ' ' | sed 's/ $//')"
check_contains "log lines are on stderr" "$(stderr)" "nuclei"
check "no log lines on stdout" "" "$(grep -F 'rebuild' "$OUT")"
check_contains "step summary is written when asked for" "$(cat "$SUMMARY")" "vulnerabilities/nuclei"

# --- result --------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$passed" "$failed"
[ "$failed" = 0 ]
