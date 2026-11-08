#!/bin/bash
# Shared by this action and actions/gitleaks-scan; @see README.md.
set -Eeuo pipefail
fail() { echo "::error::$* - infrastructure, no scan"; exit 1; }
trap 'fail "gitleaks setup failed"' ERR
if [ "${RUNNER_OS:-}" != Linux ] || [ "${RUNNER_ARCH:-}" != X64 ]; then
  fail "gitleaks-pinned supports Linux x64 only"
fi
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
read_pin() {
  local line key value seen=" "
  VERSION=""; IMAGE=""; LINUX_X64_SHA256=""
  local pin="$SCRIPT_DIR/../../contract/gitleaks-merges/gitleaks.pin"
  [ -f "$pin" ] && [ -r "$pin" ] || return 1
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
  done < "$pin"
  [ -n "$VERSION" ] && [ -n "$IMAGE" ] && [ -n "$LINUX_X64_SHA256" ]
}
read_pin || fail "unreadable or invalid gitleaks.pin"
if binary=$(command -v gitleaks) && actual=$("$binary" version 2>/dev/null) && [ "${actual#v}" = "$VERSION" ]; then
  binary="$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")"
else
  download=$(mktemp -d "$RUNNER_TEMP/gitleaks-download.XXXXXX")
  trap 'rm -rf -- "$download"' EXIT
  archive="$download/gitleaks.tar.gz"
  curl -fsSL --proto '=https' --retry 3 -o "$archive" \
    "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_linux_x64.tar.gz" ||
    fail "gitleaks $VERSION release archive not downloadable"
  printf '%s  %s\n' "$LINUX_X64_SHA256" "$archive" | sha256sum -c - ||
    fail "gitleaks release archive checksum differs from the pin"
  install_dir="$RUNNER_TEMP/gitleaks-$VERSION"
  mkdir -p "$install_dir"
  tar -xzf "$archive" -C "$install_dir" --no-same-owner gitleaks || fail "gitleaks archive not extractable"
  binary="$install_dir/gitleaks"
  actual=$("$binary" version)
  [ "${actual#v}" = "$VERSION" ] || fail "downloaded gitleaks version differs from pin"
  printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
fi
printf 'path=%s\n' "$binary" >> "$GITHUB_OUTPUT"
