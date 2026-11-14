#!/bin/bash
# Shared by this action and actions/gitleaks-scan; @see README.md.
set +e -uo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 1
# Omitted selections retain all refs; explicit tips select the union of their histories.
range=${1:-}
selected=${2:-}
if [ -n "$range" ] && ! [[ "$range" =~ ^[0-9a-f]{40}\.\.[0-9a-f]{40}$ ]]; then
  echo "::error::invalid range - expected two lowercase 40-character commit SHAs separated by .."; exit 1
fi
if [ -n "$selected" ] && ! [[ "$selected" =~ ^[0-9a-f]{40}(\ [0-9a-f]{40})*$ ]]; then
  echo "::error::invalid revisions - expected space-separated lowercase 40-character commit SHAs"; exit 1
fi
if [ -n "$range" ] && [ -n "$selected" ]; then
  echo "::error::range and revisions are mutually exclusive"; exit 1
fi
revisions=(--all)
[ -z "$range" ] || revisions=("$range")
[ -z "$selected" ] || read -r -a revisions <<< "$selected"
if { [ -z "$RCI_IMAGE" ] && [ -z "$RCI_BINARY" ]; } || { [ -n "$RCI_IMAGE" ] && [ -n "$RCI_BINARY" ]; }; then
  echo "::error::exactly one of image or binary must be set - infrastructure, no scan"; exit 1
fi
if [ "$(git --no-optional-locks -C "$GITHUB_WORKSPACE" rev-parse --is-shallow-repository 2>&1)" != false ]; then
  echo "::error::the checkout is shallow or no git repository - the merge scan has no verdict; check out with fetch-depth: 0"; exit 1
fi
cd "$GITHUB_WORKSPACE" || exit 1
if [ -e "$(git --no-optional-locks rev-parse --git-path info/grafts)" ]; then
  echo "::error::the repository has info/grafts, which hide history - the merge scan has no verdict"; exit 1
fi
# A git-dir symlink may dangle here and resolve elsewhere (a fresh checkout has none); find's error counts.
if [ -n "$(find "$(git --no-optional-locks rev-parse --git-dir)" "$(git --no-optional-locks rev-parse --git-common-dir)" -type l -print -quit 2>&1)" ]; then
  echo "::error::the git directory holds a symlink - the merge scan has no verdict"; exit 1
fi
export GIT_NO_REPLACE_OBJECTS=1
if [ -n "$RCI_BINARY" ]; then
  "$SCRIPT_DIR/../../contract/gitleaks-merges/gitleaks-merges.sh" --binary "$RCI_BINARY" --repo "$GITHUB_WORKSPACE" -- "${revisions[@]}"
else
  docker pull -q "$RCI_IMAGE" > /dev/null || {
    echo "::error::scanner image not loadable - no merge scan ran; infrastructure, not a finding"; exit 1; }
  "$SCRIPT_DIR/../../contract/gitleaks-merges/gitleaks-merges.sh" --image "$RCI_IMAGE" --repo "$GITHUB_WORKSPACE" -- "${revisions[@]}"
fi
rc=$?
case $rc in
  0) ;;
  1) echo "::error::gitleaks found potential secrets that a merge brings itself (redacted above)"; exit 1 ;;
  *) echo "::error::the merge scan has no verdict (exit $rc) - not a clean scan"; exit 1 ;;
esac
