#!/usr/bin/env bash

set -euo pipefail

REPO="${BLNK_WATCH_REPO:-blnkfinance/watch}"
INSTALL_DIR="${BLNK_WATCH_INSTALL_DIR:-$HOME/.local/bin}"
REQUESTED_VERSION="${1:-${BLNK_WATCH_VERSION:-}}"
USE_COLOR=0

COLOR_RESET=""
COLOR_BOLD=""
COLOR_BLUE=""
COLOR_GREEN=""
COLOR_YELLOW=""
COLOR_RED=""

fail() {
  printf "%sblnk-watch installer:%s %s\n" "$COLOR_RED" "$COLOR_RESET" "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

init_ui() {
  if [[ -t 1 ]] && [[ -t 2 ]] && command -v tput >/dev/null 2>&1; then
    local colors
    colors="$(tput colors 2>/dev/null || echo 0)"
    if [[ "$colors" -ge 8 ]]; then
      USE_COLOR=1
      COLOR_RESET="$(printf '\033[0m')"
      COLOR_BOLD="$(printf '\033[1m')"
      COLOR_BLUE="$(printf '\033[34m')"
      COLOR_GREEN="$(printf '\033[32m')"
      COLOR_YELLOW="$(printf '\033[33m')"
      COLOR_RED="$(printf '\033[31m')"
    fi
  fi
}

log_step() {
  printf "%s==>%s %s\n" "$COLOR_BLUE$COLOR_BOLD" "$COLOR_RESET" "$*"
}

log_ok() {
  printf "%sOK%s %s\n" "$COLOR_GREEN$COLOR_BOLD" "$COLOR_RESET" "$*"
}

log_note() {
  printf "%s->%s %s\n" "$COLOR_YELLOW$COLOR_BOLD" "$COLOR_RESET" "$*"
}

detect_os() {
  case "$(uname -s)" in
    Linux) echo "linux" ;;
    Darwin) echo "darwin" ;;
    *) fail "unsupported operating system: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac
}

resolve_version() {
  if [[ -n "$REQUESTED_VERSION" ]]; then
    echo "$REQUESTED_VERSION"
    return
  fi

  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1
}

verify_checksum() {
  local checksum_file="$1"
  local archive_file="$2"

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "$archive_file")" && sha256sum -c "$(basename "$checksum_file")" >/dev/null)
    return
  fi

  if command -v shasum >/dev/null 2>&1; then
    (cd "$(dirname "$archive_file")" && shasum -a 256 -c "$(basename "$checksum_file")" >/dev/null)
    return
  fi

  fail "missing sha256 verification tool: install sha256sum or shasum"
}

download_file() {
  local url="$1"
  local destination="$2"
  local show_progress="${3:-0}"

  if [[ "$show_progress" == "1" ]] && [[ -t 2 ]]; then
    curl -fL --progress-bar "$url" -o "$destination"
    return
  fi

  curl -fsSL "$url" -o "$destination"
}

main() {
  need_cmd curl
  need_cmd tar
  need_cmd mktemp
  need_cmd install
  init_ui

  local os arch version ext asset_name asset_url checksum_url tmpdir archive_file checksum_file
  log_step "[1/5] Detecting platform"
  os="$(detect_os)"
  arch="$(detect_arch)"

  log_step "[2/5] Resolving release version"
  version="$(resolve_version)"

  [[ -n "$version" ]] || fail "could not resolve a release version from GitHub"
  log_ok "Using ${version} for ${os}/${arch}"

  ext="tar.gz"
  asset_name="blnk-watch_${version}_${os}_${arch}.${ext}"
  asset_url="https://github.com/${REPO}/releases/download/${version}/${asset_name}"
  checksum_url="${asset_url}.sha256"

  tmpdir="$(mktemp -d)"
  archive_file="${tmpdir}/${asset_name}"
  checksum_file="${archive_file}.sha256"
  trap 'rm -rf -- '"$(printf '%q' "$tmpdir")" EXIT

  log_step "[3/5] Downloading ${asset_name}"
  download_file "$asset_url" "$archive_file" 1
  download_file "$checksum_url" "$checksum_file"

  log_step "[4/5] Verifying archive checksum"
  verify_checksum "$checksum_file" "$archive_file"
  log_ok "Checksum verified"

  log_step "[5/5] Installing blnk-watch to ${INSTALL_DIR}"
  mkdir -p "$INSTALL_DIR"
  tar -xzf "$archive_file" -C "$tmpdir"
  install -m 0755 "${tmpdir}/blnk-watch" "${INSTALL_DIR}/blnk-watch"

  log_ok "Installed to ${INSTALL_DIR}/blnk-watch"
  case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *) log_note "Add ${INSTALL_DIR} to your PATH to run 'blnk-watch' from any shell." ;;
  esac
}

main "$@"
