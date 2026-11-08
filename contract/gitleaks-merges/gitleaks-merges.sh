#!/bin/bash
# The merge half of the gitleaks range scan, as a command of its own: the list of merges with a combined diff, and
# the scan of each merge's own content as a file tree.
#
#   gitleaks-merges.sh (--image <ref> | --binary <path>) --repo <checkout> -- <git rev-list arguments>
#   exit 0 nothing found, 1 a finding, 2 no verdict (usage, unreadable git state, a refused config or path, a scan
#   that read nothing). The rev-list arguments are joined and split on spaces again, as gitleaks.sh's --range is.
#
# gitleaks.sh runs it over a push range; a byte copy lets robotico-ci's secrets workflow run it over `--all` (INF-303).
# @see gitleaks.sh; README "Why `push` is its own mode"
#
# ⚠️ No `set -e`: every failure below is checked where it happens. Under -e a grep that finds no "own lines" ends
# the script silently with exit 1, which reads as a finding, and the "not scanned" check never runs.

# Parse data, never source shell code. Kept identical in the two standalone scripts:
# robotico-ci byte-copies the merge CLI together with this pin, without gitleaks.sh.
read_pin() {
    local line key value seen=" "
    VERSION=""; IMAGE=""; LINUX_X64_SHA256=""
    [ -f "$SCRIPT_DIR/gitleaks.pin" ] && [ -r "$SCRIPT_DIR/gitleaks.pin" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|\#*) continue ;; esac
        key=${line%%=*}; value=${line#*=}
        case "$seen" in *" $key "*) return 1 ;; esac
        case "$key" in
            version) [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1; VERSION=$value ;;
            image) [[ "$value" =~ ^[a-z0-9./-]+@sha256:[0-9a-f]{64}$ ]] || return 1; IMAGE=$value ;;
            linux_x64_sha256) [[ "$value" =~ ^[0-9a-f]{64}$ ]] || return 1; LINUX_X64_SHA256=$value ;;
            *) return 1 ;;
        esac
        seen="$seen$key "
    done < "$SCRIPT_DIR/gitleaks.pin"
    [ -n "$VERSION" ] && [ -n "$IMAGE" ] && [ -n "$LINUX_X64_SHA256" ]
}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if ! read_pin; then
    echo "gitleaks: unreadable or invalid gitleaks.pin — no verdict" >&2
    exit 2
fi
export GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0

gitleaks_merges_list() {
    # shellcheck disable=SC2086
    if ! MERGES=$(git --no-optional-locks rev-list --merges $RANGE); then
        echo -e "${RED}ERROR: die Merges in '$RANGE' sind nicht lesbar — kein Scan.${NC}" >&2
        exit 2
    fi
    MERGE_SCANS=()
    for merge in $MERGES; do
        if ! cc=$(git --no-optional-locks show --cc --no-color --format= -U0 --no-ext-diff --no-textconv "$merge"); then
            echo -e "${RED}ERROR: der kombinierte Diff von Merge $merge ist nicht lesbar — kein Scan.${NC}" >&2
            exit 2
        fi
        [ -n "$cc" ] && MERGE_SCANS+=("$merge")
    done
    return 0
}

gitleaks_merges_run() {
# ── Merges: their own content, from the combined diff ────────────────────────────
# `git log -p` shows no diff for a merge, so a line resolved into the merge itself (a token typed into a conflict
# resolution, an octopus merge's own file) was never scanned. The combined diff (`--cc`, read on the host with no
# driver) marks each line with one column per parent; a line with `+` in every column is one no parent had.
# MERGE_TREE writes those lines without marker columns under their own paths into container tmpfs or a trapped
# host directory. `gitleaks dir .` runs inside that tree: paths stay repository-relative and path-scoped rules
# and line anchors apply as in a commit. Removed lines are never scanned. The host tree is removed on every exit.
# Findings carry no commit fingerprint, so an allowance belongs in .gitleaks.toml; binary content a merge brings
# is not scanned (the patch scan's limit too).
# Positive control: when the tree holds lines, gitleaks must report more than 0 bytes scanned; a harmless sentinel
# file keeps that true when an allowlist skips every merged file.
# A path is never evaluated: awk writes flat numbered files plus a manifest ("<number> <path>"), and the shell moves each to its path
# with `mkdir -p --` / `mv --` on a read variable. A name git has to quote (control character, quote, backslash;
# non-ASCII stays literal by core.quotePath=false) stops the scan instead of being renamed, which would lose
# path-scoped rules; so does any awk failure.
MERGE_TREE=$(cat <<'SCRIPT'
set -eu
SCAN=${SCAN:-/scan}
REPO_DIR=${REPO_DIR:-/repo}
GITLEAKS=${GITLEAKS:-gitleaks}
# `gitleaks dir .` runs inside the tree, and gitleaks resolves a relative `[extend] path` against the working
# directory: such a config cannot load here. Refused with a clear message instead (no robotico repo uses one).
if [ -f "$REPO_DIR/.gitleaks.toml" ] && awk '/^\[/ { ext = ($0 ~ /^\[extend\]/) } ext && /^[ \t]*path[ \t]*=[ \t]*"[^\/]/ { found = 1 }
        END { exit !found }' "$REPO_DIR/.gitleaks.toml"; then
    echo "relative [extend] path in .gitleaks.toml: not supported by the merge scan; use an absolute path" >&2
    exit 4
fi
mkdir -p "$SCAN/flat" "$SCAN/tree"
awk -v p="$PARENTS" -v scan="$SCAN" '
    /^diff --cc / { path = substr($0, 11)
                    if (path ~ /^"/) { print "path needs quoting: " path > "/dev/stderr"; failed = 1; exit 3 }
                    # A tree may carry "..", "." or an empty name (git only warns): such a path would leave the scan
                    # tree, a host write in binary mode. No verdict instead.
                    if (("/" path "/") ~ /\/(\.\.?)?\//) {
                        print "path leaves the scan tree: " path > "/dev/stderr"; failed = 1; exit 3 }
                    hunk = 0; file = ""; next }
    /^@@/ { hunk = 1; next }
    !hunk || /^\\/ { next }
    { mark = substr($0, 1, p)
      if (length(mark) == p && mark ~ /^[+]+$/) {
          if (!(path in index_of)) { index_of[path] = ++files; print files " " path > (scan "/manifest") }
          print substr($0, p + 1) > (scan "/flat/" index_of[path]); n++ } }
    END { if (failed) exit 3; print n + 0 > (scan "/own-lines") }'
n=$(cat "$SCAN/own-lines")
echo "own lines: $n"
[ "$n" -gt 0 ] || exit 0
while IFS= read -r entry; do
    path=${entry#* }
    mkdir -p -- "$SCAN/tree/$(dirname -- "$path")"
    mv -- "$SCAN/flat/${entry%% *}" "$SCAN/tree/$path"
done < "$SCAN/manifest"
# The sentinel proves gitleaks read the tree even when every merged file is on a path allowlist (then skipped).
# A merged file may carry that very name: the sentinel takes the first name that does not exist yet.
sentinel="$SCAN/tree/.dev-hooks-merge-scan-sentinel"
while [ -e "$sentinel" ]; do sentinel="$sentinel-"; done
printf 'dev-hooks merge scan sentinel\n' > "$sentinel"
cd "$SCAN/tree"
exec "$GITLEAKS" dir . --redact --verbose --no-banner "$@"
SCRIPT
)
if [ "$GITLEAKS_MODE" = "range" ]; then
    for merge in "${MERGE_SCANS[@]}"; do
        if ! cc=$(git --no-optional-locks -c core.quotePath=false show --cc --no-color --format= -U0 --no-ext-diff --no-textconv "$merge") ||
            ! parents=$(git --no-optional-locks rev-list --parents -n 1 "$merge"); then
            echo -e "${RED}ERROR: der kombinierte Diff von Merge $merge ist nicht lesbar — kein Scan.${NC}" >&2
            exit 2
        fi
        parents=$(( $(wc -w <<< "$parents") - 1 ))
        echo -e "${BLUE}Merge $merge: gitleaks over the lines no parent had ...${NC}"
        if [ -n "$BINARY" ]; then
            # A fresh directory per merge; the parent trap also covers scan failures/signals.
            if ! SCAN=$(mktemp -d); then echo "gitleaks-merges: mktemp failed — no verdict" >&2; exit 2; fi
            MERGE_AUSGABE=$(printf '%s\n' "$cc" | env -u GITLEAKS_CONFIG -u GITLEAKS_CONFIG_TOML GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
                SCAN="$SCAN" REPO_DIR="$TOP" GITLEAKS="$BINARY" PARENTS="$parents" sh -c "$MERGE_TREE" sh "${CONFIG_ARG[@]}" 2>&1) && MERGE_EXIT=0 || MERGE_EXIT=$?
            rm -rf -- "$SCAN"
            SCAN=""
        else
            MERGE_AUSGABE=$(printf '%s\n' "$cc" | docker run -i "${DOCKER_ARGS[@]}" --tmpfs /scan --env "PARENTS=$parents" \
                --env GIT_NO_REPLACE_OBJECTS=1 --env GIT_OPTIONAL_LOCKS=0 \
                --entrypoint sh "$IMAGE" -c "$MERGE_TREE" sh "${CONFIG_ARG[@]}" 2>&1) && MERGE_EXIT=0 || MERGE_EXIT=$?
        fi
        echo "$MERGE_AUSGABE"
        OWN=$(echo "$MERGE_AUSGABE" | grep -oE '^own lines: [0-9]+' | grep -oE '[0-9]+$')
        BYTES=$(echo "$MERGE_AUSGABE" | grep -oE 'scanned ~[0-9]+ bytes' | grep -oE '[0-9]+' | tail -1)
        if [ -z "$OWN" ] || { [ "$OWN" != "0" ] && { [ -z "$BYTES" ] || [ "$BYTES" = "0" ]; }; }; then
            echo -e "${RED}ERROR: der eigene Inhalt von Merge $merge wurde nicht gescannt (${OWN:-?} Zeilen, ${BYTES:-keine} Bytes).${NC}" >&2
            exit 2
        fi
        [ "$MERGE_EXIT" -ne 0 ] && EXIT_CODE=$MERGE_EXIT
    done
fi
return 0
}

# ── Command line ─────────────────────────────────────────────────────────────────
# No file name expansion: the rev-list arguments are split on spaces (below and in the functions), never globbed,
# so a pattern cannot turn into an option such as --quiet once the scan runs from the checkout.
set -f
usage() {
    echo "usage: gitleaks-merges.sh (--image <ref> | --binary <path>) --repo <checkout> -- <git rev-list arguments>" >&2
    exit 2
}
REQUESTED_IMAGE=""
BINARY=""
RUNNER_SET=0
REPO=""
SEPARATOR=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --image) [ "$#" -ge 2 ] && [ "$RUNNER_SET" = 0 ] && [ -n "$2" ] || usage; REQUESTED_IMAGE=$2; RUNNER_SET=1; shift 2 ;;
        --binary) [ "$#" -ge 2 ] && [ "$RUNNER_SET" = 0 ] && [ -n "$2" ] || usage; BINARY=$2; RUNNER_SET=1; shift 2 ;;
        --repo) [ "$#" -ge 2 ] || usage; REPO=$2; shift 2 ;;
        --) SEPARATOR=1; shift; break ;;
        *) usage ;;
    esac
done
[ "$RUNNER_SET" = 1 ] && [ -n "$REPO" ] && [ "$SEPARATOR" = 1 ] && [ "$#" -gt 0 ] || usage
# The image argument must agree with the single pin, including for standalone CI use.
if [ -n "$REQUESTED_IMAGE" ] && [ "$REQUESTED_IMAGE" != "$IMAGE" ]; then
    echo "gitleaks-merges: image differs from gitleaks.pin — no verdict" >&2
    exit 2
fi
if [ -n "$BINARY" ]; then
    if ! BINARY=$(command -v "$BINARY") || ! ACTUAL_VERSION=$("$BINARY" version 2>/dev/null) || [ "${ACTUAL_VERSION#v}" != "$VERSION" ]; then
        echo "gitleaks-merges: binary version '${ACTUAL_VERSION:-missing}', pinned version '$VERSION' required — no verdict" >&2
        exit 2
    fi
    case "$BINARY" in /*) ;; *) BINARY="$PWD/$BINARY" ;; esac
fi
SCAN=""
trap '[ -z "$SCAN" ] || rm -rf -- "$SCAN"' EXIT
trap 'exit 2' HUP INT TERM
# Under --quiet rev-list lists no merge at all, which would read as a clean scan. Checked word by word, as the
# functions split RANGE.
# shellcheck disable=SC2048
for word in $*; do [ "$word" != --quiet ] || usage; done
# The scan runs from the checkout's top level, also for a --repo inside it: the mount and its .gitleaks.toml.
if ! cd "$REPO" 2>/dev/null || ! TOP=$(git --no-optional-locks rev-parse --show-toplevel 2>/dev/null) || ! cd "$TOP"; then
    echo "gitleaks-merges: '$REPO' is not a git checkout — no verdict" >&2
    exit 2
fi
# The functions above read these, as they did inside gitleaks.sh. The container needs the checkout only for its
# .gitleaks.toml, so a linked worktree's common git dir is not mounted.
RANGE="$*"
GITLEAKS_MODE=range
DOCKER_ARGS=(--rm --mount "type=bind,source=$(pwd),target=/repo,readonly" --workdir /repo)
CONFIG_ARG=()
if [ -f .gitleaks.toml ]; then
    if [ -n "$BINARY" ]; then CONFIG_ARG=(--config="$TOP/.gitleaks.toml")
    else CONFIG_ARG=(--config=/repo/.gitleaks.toml); fi
fi
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'
EXIT_CODE=0
gitleaks_merges_list
gitleaks_merges_run
echo "gitleaks-merges: ${#MERGE_SCANS[@]} merge(s) with a combined diff scanned"
case $EXIT_CODE in
    0|1) exit "$EXIT_CODE" ;;
    *) echo -e "${RED}ERROR: gitleaks did not complete on a merge (exit $EXIT_CODE) — no verdict.${NC}" >&2; exit 2 ;;
esac
