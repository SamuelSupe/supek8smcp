#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
VERSION="${VERSION:-0.2.0}"
VERSION="${VERSION#v}"
HELM="${HELM:-helm}"

case "${VERSION}" in
  ""|*[!0-9A-Za-z.+-]*)
    echo "VERSION must contain only letters, digits, dots, plus signs, and hyphens" >&2
    exit 2
    ;;
esac

TMP_RELEASE_DIR="$(mktemp -d)"
trap 'rm -rf -- "${TMP_RELEASE_DIR}"' EXIT HUP INT TERM

rm -rf -- "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  GOOS="${target%/*}"
  GOARCH="${target#*/}"
  ARCHIVE="supek8smcp_${VERSION}_${GOOS}_${GOARCH}"
  PACKAGE_DIR="${TMP_RELEASE_DIR}/${ARCHIVE}"
  mkdir -p "${PACKAGE_DIR}"

  echo "building ${GOOS}/${GOARCH}"
  (
    cd "${ROOT_DIR}"
    CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o "${PACKAGE_DIR}/supek8smcp" ./cmd/supek8smcp
  )
  tar -czf "${DIST_DIR}/${ARCHIVE}.tar.gz" -C "${TMP_RELEASE_DIR}" "${ARCHIVE}"
done

if ! command -v "${HELM}" >/dev/null 2>&1; then
  echo "helm is required to package the release chart" >&2
  exit 1
fi
if ! cmp -s \
  "${ROOT_DIR}/config/crd/bases/mcp.supek8smcp.io_kubernetesmcpservers.yaml" \
  "${ROOT_DIR}/charts/supek8smcp/crds/mcp.supek8smcp.io_kubernetesmcpservers.yaml"; then
  echo "Helm CRD is stale; run make manifests" >&2
  exit 1
fi
"${HELM}" lint --strict "${ROOT_DIR}/charts/supek8smcp"
"${HELM}" package "${ROOT_DIR}/charts/supek8smcp" \
  --version "${VERSION}" \
  --app-version "${VERSION}" \
  --destination "${DIST_DIR}"

(
  cd "${DIST_DIR}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum ./*.tar.gz ./*.tgz > checksums.txt
  else
    shasum -a 256 ./*.tar.gz ./*.tgz > checksums.txt
  fi
)

echo "release artifacts written to ${DIST_DIR}"
