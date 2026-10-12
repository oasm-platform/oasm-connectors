#!/usr/bin/env bash
#
# Decide which connector images a revision has to rebuild, so CI builds, scans
# and pushes those instead of the whole catalogue. Touching one tool costs one
# runner; touching the shared SDK costs the catalogue, because every
# Dockerfile COPYs `sdk/` into its build context.
#
#   ./detect-changed-connectors.sh --base "$BEFORE" --head "$SHA" >> "$GITHUB_OUTPUT"
#
# How a changed path is classified, in order:
#
#   1. inside a `<category>/<slug>/` connector  -> rebuild that connector
#   2. a build-context input of some connector  -> rebuild those connectors
#      (derived from each Dockerfile's COPY sources, minus its own tree, so a
#      new shared input is picked up without editing this script)
#   3. nothing                                  -> no image is affected
#
# Independently, every changed path is attributed to the Go module that owns it
# (nearest ancestor with a go.mod), so tests follow the same scoping. The root
# module and the SDK are therefore never tested by accident and never skipped
# when they are the thing that moved.
#
# Output (stdout, `$GITHUB_OUTPUT` syntax):
#   matrix      {"include":[{dir,slug,version,tag},...]}  connectors to build
#   test_dirs   newline-separated Go module directories to run `go test` in
#   has_build   true when matrix is non-empty
#   has_test    true when test_dirs is non-empty
#   build_all   true when every connector was selected
#
# Diagnostics go to stderr; a markdown summary is appended to
# $GITHUB_STEP_SUMMARY when that variable names a writable file.
set -euo pipefail

if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "detect-changed-connectors: bash 4+ required, found ${BASH_VERSION}" >&2
  exit 2
fi

ZERO_SHA=0000000000000000000000000000000000000000

# Root-level files that belong to the root Go module. A change to one of them
# is a test event, not an image event: the root module holds the manifest
# tooling, and no connector image is built from it — every image builds with
# GOWORK=off inside its own module. README/LICENSE/.trivyignore are excluded on
# purpose: they move no code and no manifest.
ROOT_MODULE_FILES="go.mod go.sum go.work go.work.sum manifest.json Taskfile.yml"

usage() {
  cat <<'EOF'
Usage: detect-changed-connectors.sh [options]

  --root DIR         where to start looking (default: .)
  --base REV         revision to diff against; empty or the zero sha means
                     "no baseline", which selects every connector
  --head REV         revision under test (default: HEAD)
  --force-all        select every connector regardless of the diff
  --tag-override TAG publish TAG instead of each connector's version
  -h, --help         this text
EOF
}

log() { printf '%s\n' "$*" >&2; }
die() {
  printf 'detect-changed-connectors: %s\n' "$*" >&2
  exit 2
}

ROOT="."
BASE=""
HEAD="HEAD"
FORCE_ALL=0
TAG_OVERRIDE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --root)
      [ $# -ge 2 ] || die "--root needs a value"
      ROOT="$2"
      shift 2
      ;;
    --base)
      [ $# -ge 2 ] || die "--base needs a value"
      BASE="$2"
      shift 2
      ;;
    --head)
      [ $# -ge 2 ] || die "--head needs a value"
      HEAD="$2"
      shift 2
      ;;
    --force-all)
      FORCE_ALL=1
      shift
      ;;
    --tag-override)
      [ $# -ge 2 ] || die "--tag-override needs a value"
      TAG_OVERRIDE="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done

cd "$ROOT" || die "cannot enter $ROOT"
# Every path this script resolves is repo-root relative, so work from the
# toplevel whatever --root pointed at.
TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null)" || die "$ROOT is not inside a git work tree"
cd "$TOPLEVEL"

# --- inventory -----------------------------------------------------------

# A connector is a depth-2 directory that carries both a manifest and a
# Dockerfile: the pair is what the build matrix is derived from, and the
# manifest is what the registry tag comes from.
connector_dirs() {
  local d
  for d in */*/; do
    if [ -f "${d}manifest.yaml" ] && [ -f "${d}Dockerfile" ]; then
      printf '%s\n' "${d%/}"
    fi
  done | LC_ALL=C sort
}

# Top-level path segments a connector copies into its build context, i.e. the
# inputs it shares with the rest of the repo. Sources inside the connector's own
# tree are excluded (changing them is a per-connector change), and so are
# --from= stage outputs (they are not build-context inputs at all).
shared_tops() { # connector-dir
  awk -v dir="$1" '
    function emit(src,   top) {
      if (src == "" || src == "." ) return
      if (substr(src, 1, 1) == "/") return
      gsub(/\/+$/, "", src)                            # trailing slashes are noise
      if (src == "") return
      if (src == dir || index(src, dir "/") == 1) return
      if (index(src, "/") > 0) { split(src, part, "/"); top = part[1] } else { top = src }
      if (top != "") print top
    }
    {
      line = $0
      sub(/\r$/, "", line)
      if (line ~ /^[ \t]*#/) next
      if (pending != "") { line = pending " " line; pending = "" }
      if (line ~ /\\$/) { sub(/\\$/, "", line); pending = line; next }
      if (line !~ /^[ \t]*[Cc][Oo][Pp][Yy]([ \t]|$)/) next
      sub(/^[ \t]*[Cc][Oo][Pp][Yy][ \t]*/, "", line)
      n = split(line, tok)
      if (n < 2) next
      for (i = 1; i < n; i++) {
        if (tok[i] ~ /^--/) continue                    # flags, e.g. --from=builder
        if (i == n) break                               # the destination
        emit(tok[i])
      }
    }
  ' "$1/Dockerfile" | LC_ALL=C sort -u
}

first_segment() { printf '%s\n' "${1%%/*}"; }

# Nearest ancestor that is a buildable connector, or nothing. Walks up so that
# `vulnerabilities/nuclei/internal/parse/parse.go` still resolves to
# `vulnerabilities/nuclei`; the repo root is never a connector.
connector_for_path() {
  local dir
  dir="$(dirname "$1")"
  while :; do
    if [ -f "$dir/manifest.yaml" ] && [ -f "$dir/Dockerfile" ]; then
      printf '%s\n' "$dir"
      return 0
    fi
    case "$dir" in
      . | / | '') return 0 ;;
      */*) dir="$(dirname "$dir")" ;;
      *) return 0 ;;
    esac
  done
}

# The Go module that owns a changed path, or nothing when the path belongs to
# no module at all.
module_for_path() {
  local f="$1" dir rf
  case "$(first_segment "$f")" in
    .*) return 0 ;; # .github/, .playwright-mcp/ — CI and agent state, no module
  esac
  if [ "${f#*/}" = "$f" ]; then
    for rf in $ROOT_MODULE_FILES; do
      if [ "$f" = "$rf" ]; then
        printf '.\n'
        return 0
      fi
    done
    return 0
  fi
  dir="$(dirname "$f")"
  while [ -n "$dir" ] && [ "$dir" != "." ] && [ "$dir" != "/" ]; do
    if [ -f "$dir/go.mod" ]; then
      printf '%s\n' "$dir"
      return 0
    fi
    dir="$(dirname "$dir")"
  done
  # No module claimed it, so the root module owns the rest of the tree.
  printf '.\n'
}

manifest_field() { # dir field
  sed -n "s/^$2:[[:space:]]*//p" "$1/manifest.yaml" | sed -n '1s/[[:space:]]*$//p'
}

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# --- select --------------------------------------------------------------

mapfile -t CONNECTORS < <(connector_dirs)

declare -A COPIES=() # top-level segment -> space-separated connector dirs
for d in "${CONNECTORS[@]}"; do
  while IFS= read -r top; do
    [ -n "$top" ] || continue
    if [ -n "${COPIES[$top]:-}" ]; then
      COPIES["$top"]="${COPIES[$top]} $d"
    else
      COPIES["$top"]="$d"
    fi
  done < <(shared_tops "$d")
done

declare -A build=() # connector dir -> 1
declare -A test=()  # go module dir -> 1
build_all=0
changed=""

if [ "$FORCE_ALL" = 1 ]; then
  build_all=1
  log "--force-all: selecting every connector"
elif [ -z "$BASE" ] || [ "$BASE" = "$ZERO_SHA" ]; then
  build_all=1
  log "no baseline revision given: selecting every connector"
elif ! git rev-parse --verify --quiet "${BASE}^{commit}" >/dev/null 2>&1; then
  build_all=1
  log "baseline $BASE is not in this clone (force-push or shallow fetch): selecting every connector"
fi

if [ "$build_all" = 0 ]; then
  # Three dots: the diff of what this revision introduces rather than the raw
  # tree delta, which on a pull request is computed against a moving base.
  if ! changed="$(git diff --name-only --no-renames "${BASE}...${HEAD}" 2>/dev/null)"; then
    build_all=1
    log "cannot diff ${BASE}...${HEAD}: selecting every connector"
  fi
fi

if [ "$build_all" = 0 ]; then
  while IFS= read -r f; do
    [ -n "$f" ] || continue

    if [ "$f" = ".dockerignore" ]; then
      # Filters every build context, so every image is affected even though no
      # Dockerfile names it.
      build_all=1
      log "shared: $f filters every build context"
    fi

    dir="$(connector_for_path "$f")"
    if [ -n "$dir" ]; then
      build["$dir"]=1
      log "$f -> rebuild $dir"
    else
      top="$(first_segment "$f")"
      hits="${COPIES[$top]:-}"
      if [ -n "$hits" ]; then
        n=0
        for c in $hits; do
          build["$c"]=1
          n=$((n + 1))
          log "$f -> rebuild $c (shared input $top)"
        done
        if [ "$n" -eq "${#CONNECTORS[@]}" ] && [ "$n" -gt 0 ]; then
          build_all=1
          log "shared: $f is copied by every connector"
        fi
      else
        log "$f -> no image impact"
      fi
    fi

    module="$(module_for_path "$f")"
    if [ -n "$module" ]; then
      test["$module"]=1
    fi

    # manifest.json is derived from every manifest.yaml, so a manifest change
    # has to run the root module's staleness check even though it builds
    # nothing on its own.
    case "$f" in
      */*/manifest.yaml)
        test["."]=1
        log "$f -> also gate on the manifest sync test"
        ;;
    esac
  done <<EOF
$changed
EOF
fi

if [ "$build_all" = 1 ]; then
  # Everything is being rebuilt, so everything is worth testing.
  for d in "${CONNECTORS[@]}"; do
    build["$d"]=1
    test["$d"]=1
  done
fi

# --- emit ----------------------------------------------------------------

mapfile -t build_dirs < <(
  if [ "${#build[@]}" -gt 0 ]; then printf '%s\n' "${!build[@]}" | LC_ALL=C sort; fi
)
mapfile -t test_list < <(
  if [ "${#test[@]}" -gt 0 ]; then printf '%s\n' "${!test[@]}" | LC_ALL=C sort; fi
)

entries=""
for d in "${build_dirs[@]}"; do
  slug="$(manifest_field "$d" slug)"
  version="$(manifest_field "$d" version)"
  if [ -z "$slug" ] || [ -z "$version" ]; then
    log "warning: skipping $d — manifest.yaml has no slug/version"
    continue
  fi
  entry="$(printf '{"dir":"%s","slug":"%s","version":"%s","tag":"%s"}' \
    "$(json_escape "$d")" "$(json_escape "$slug")" "$(json_escape "$version")" \
    "$(json_escape "${TAG_OVERRIDE:-$version}")")"
  if [ -z "$entries" ]; then entries="$entry"; else entries="$entries, $entry"; fi
done

has_build=false
[ -n "$entries" ] && has_build=true
has_test=false
[ "${#test_list[@]}" -gt 0 ] && has_test=true

{
  printf 'matrix={"include":[%s]}\n' "$entries"
  printf 'test_dirs<<OASM_TEST_DIRS\n'
  printf '%s\n' "${test_list[@]+"${test_list[@]}"}"
  printf 'OASM_TEST_DIRS\n'
  printf 'has_build=%s\n' "$has_build"
  printf 'has_test=%s\n' "$has_test"
  printf 'build_all=%s\n' "$([ "$build_all" = 1 ] && echo true || echo false)"
} >/dev/stdout

# --- summary -------------------------------------------------------------

# The runner points GITHUB_STEP_SUMMARY at a file it creates; a local run may
# not have one, and a path that cannot be written is never a reason to fail the
# detection step.
write_summary() {
  local summary="${GITHUB_STEP_SUMMARY:-}" sep
  [ -n "$summary" ] || return 0
  [ -e "$summary" ] || : >"$summary" 2>/dev/null || return 0
  [ -w "$summary" ] || return 0
  {
    printf '### Changed connectors\n\n'
    if [ "$build_all" = 1 ]; then
      printf 'A shared input changed, so every connector is selected.\n\n'
    fi
    if [ -z "$entries" ]; then
      printf 'No connector image needs rebuilding.\n\n'
    else
      printf '| Connector | Directory | Image |\n| --- | --- | --- |\n'
      for d in "${build_dirs[@]}"; do
        slug="$(manifest_field "$d" slug)"
        version="$(manifest_field "$d" version)"
        if [ -z "$slug" ] || [ -z "$version" ]; then continue; fi
        printf '| `%s` | `%s` | `connector-%s:%s` |\n' \
          "$slug" "$d" "$slug" "${TAG_OVERRIDE:-$version}"
      done
      printf '\n'
    fi
    if [ "${#test_list[@]}" -gt 0 ]; then
      printf 'Go modules tested: '
      sep=""
      for m in "${test_list[@]}"; do
        printf '%s`%s`' "$sep" "$m"
        sep=", "
      done
      printf '.\n'
    fi
  } >>"$summary"
}

write_summary
