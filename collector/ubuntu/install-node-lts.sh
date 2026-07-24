#!/usr/bin/env bash
set -euo pipefail

NODE_VERSION="${NODE_VERSION:-24.18.0}"
NODE_DIST="node-v${NODE_VERSION}-linux-x64"
NODE_ARCHIVE="${NODE_DIST}.tar.xz"
NODE_BASE_URL="https://nodejs.org/download/release/v${NODE_VERSION}"
INSTALL_ROOT="/opt"
INSTALL_DIR="${INSTALL_ROOT}/${NODE_DIST}"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root: sudo bash install-node-lts.sh" >&2
  exit 1
fi

echo "[node] downloading Node.js ${NODE_VERSION} from nodejs.org"
curl -fsSLo "${TMP_DIR}/${NODE_ARCHIVE}" "${NODE_BASE_URL}/${NODE_ARCHIVE}"
curl -fsSLo "${TMP_DIR}/SHASUMS256.txt" "${NODE_BASE_URL}/SHASUMS256.txt"

echo "[node] verifying SHA-256 checksum"
(
  cd "$TMP_DIR"
  grep " ${NODE_ARCHIVE}\$" SHASUMS256.txt | sha256sum -c -
)

if [[ ! -d "$INSTALL_DIR" ]]; then
  tar -xJf "${TMP_DIR}/${NODE_ARCHIVE}" -C "$INSTALL_ROOT"
fi

for command in node npm npx corepack; do
  ln -sfn "${INSTALL_DIR}/bin/${command}" "/usr/local/bin/${command}"
done

printf '[node] installed: '
/usr/local/bin/node --version
