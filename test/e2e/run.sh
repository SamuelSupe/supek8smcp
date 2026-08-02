#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"
RUN_ID="$(date -u +%Y%m%d%H%M%S)-$$"
E2E_NAMESPACE="supek8smcp-e2e-${RUN_ID}"
OPERATOR_NAMESPACE="supek8smcp-e2e-operator-${RUN_ID}"
IMAGE="supek8smcp:e2e-${RUN_ID}"
TMP_DIR="$(mktemp -d)"
CRD_NAME="kubernetesmcpservers.mcp.supek8smcp.io"
CRD_CREATED=0
TOKEN_REVIEWER_CREATED=0

cleanup() {
  set +e
  # Let the operator finalize its CR-owned resources before stopping the operator namespace.
  kubectl delete kubernetesmcpservers --all -n "${E2E_NAMESPACE}" --ignore-not-found --wait=true --timeout=90s >/dev/null 2>&1
  kubectl delete namespace "${E2E_NAMESPACE}" --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1
  if kubectl get namespace "${E2E_NAMESPACE}" >/dev/null 2>&1; then
    for server in mcp-e2e-readonly mcp-e2e-safewrite mcp-e2e-dangerous mcp-e2e-ratelimit; do
      kubectl -n "${E2E_NAMESPACE}" patch kubernetesmcpserver "${server}" --type=merge -p '{"metadata":{"finalizers":[]}}' >/dev/null 2>&1
    done
    kubectl delete namespace "${E2E_NAMESPACE}" --ignore-not-found --wait=true --timeout=30s >/dev/null 2>&1
  fi
  kubectl delete namespace "${OPERATOR_NAMESPACE}" --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1
  kubectl delete clusterrolebinding "supek8smcp-controller-manager-rolebinding-${RUN_ID}" --ignore-not-found >/dev/null 2>&1
  kubectl delete clusterrole "supek8smcp-controller-manager-role-${RUN_ID}" --ignore-not-found >/dev/null 2>&1
  if [[ "${TOKEN_REVIEWER_CREATED}" == 1 ]]; then
    kubectl delete clusterrole supek8smcp-tokenreviewer --ignore-not-found >/dev/null 2>&1
  fi
  if [[ "${CRD_CREATED}" == 1 ]]; then
    kubectl delete crd "${CRD_NAME}" --ignore-not-found >/dev/null 2>&1
  fi
  docker image rm --force "${IMAGE}" >/dev/null 2>&1 || true
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

for binary in kubectl docker go; do
  command -v "${binary}" >/dev/null 2>&1 || { echo "missing required command: ${binary}" >&2; exit 2; }
done

context="$(kubectl config current-context)"
if [[ "${context}" != "orbstack" ]]; then
  echo "refusing E2E outside OrbStack context (current: ${context})" >&2
  exit 2
fi
kubectl get nodes >/dev/null

if ! kubectl get crd "${CRD_NAME}" >/dev/null 2>&1; then
  CRD_CREATED=1
fi
if ! kubectl get clusterrole supek8smcp-tokenreviewer >/dev/null 2>&1; then
  TOKEN_REVIEWER_CREATED=1
fi

if kubectl get crd "${CRD_NAME}" >/dev/null 2>&1; then
  initial_deletion_timestamp="$(kubectl get crd "${CRD_NAME}" -o jsonpath='{.metadata.deletionTimestamp}' 2>/dev/null || true)"
  [[ -z "${initial_deletion_timestamp}" ]] || CRD_CREATED=1
  for _ in $(seq 1 60); do
    deletion_timestamp="$(kubectl get crd "${CRD_NAME}" -o jsonpath='{.metadata.deletionTimestamp}' 2>/dev/null || true)"
    [[ -z "${deletion_timestamp}" ]] && break
    sleep 1
  done
  if kubectl get crd "${CRD_NAME}" >/dev/null 2>&1; then
    deletion_timestamp="$(kubectl get crd "${CRD_NAME}" -o jsonpath='{.metadata.deletionTimestamp}' 2>/dev/null || true)"
    [[ -z "${deletion_timestamp}" ]] || { echo "CRD ${CRD_NAME} is still terminating" >&2; exit 2; }
  fi
fi

echo "building ${IMAGE}"
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -X main.version=e2e-${RUN_ID}" \
  -o "${TMP_DIR}/supek8smcp" "${ROOT_DIR}/cmd/supek8smcp"
docker build --quiet -f "${ROOT_DIR}/test/e2e/Dockerfile" -t "${IMAGE}" "${TMP_DIR}" >/dev/null

kubectl apply -f "${ROOT_DIR}/config/crd/bases/mcp.supek8smcp.io_kubernetesmcpservers.yaml" >/dev/null
kubectl wait --for=condition=Established "crd/${CRD_NAME}" --timeout=60s >/dev/null
kubectl create namespace "${OPERATOR_NAMESPACE}" >/dev/null
kubectl create namespace "${E2E_NAMESPACE}" >/dev/null

sed \
  -e "s|supek8smcp-system|${OPERATOR_NAMESPACE}|g" \
  -e "s|name: supek8smcp-controller-manager-role$|name: supek8smcp-controller-manager-role-${RUN_ID}|g" \
  -e "s|ghcr.io/samuelsupe/supek8smcp:[^[:space:]]*|${IMAGE}|g" \
  "${ROOT_DIR}/config/rbac/role.yaml" > "${TMP_DIR}/role.yaml"
sed \
  -e "s|supek8smcp-system|${OPERATOR_NAMESPACE}|g" \
  -e "s|name: supek8smcp-controller-manager-role$|name: supek8smcp-controller-manager-role-${RUN_ID}|g" \
  -e "s|name: supek8smcp-controller-manager-rolebinding$|name: supek8smcp-controller-manager-rolebinding-${RUN_ID}|g" \
  "${ROOT_DIR}/config/rbac/role_binding.yaml" > "${TMP_DIR}/role_binding.yaml"
sed \
  -e "s|supek8smcp-system|${OPERATOR_NAMESPACE}|g" \
  -e "s|ghcr.io/samuelsupe/supek8smcp:[^[:space:]]*|${IMAGE}|g" \
  "${ROOT_DIR}/config/manager/manager.yaml" > "${TMP_DIR}/manager.yaml"
sed "s|supek8smcp-system|${OPERATOR_NAMESPACE}|g" "${ROOT_DIR}/config/rbac/service_account.yaml" > "${TMP_DIR}/service_account.yaml"

kubectl apply -f "${TMP_DIR}/service_account.yaml" >/dev/null
kubectl apply -f "${TMP_DIR}/role.yaml" >/dev/null
kubectl apply -f "${TMP_DIR}/role_binding.yaml" >/dev/null
kubectl apply -f "${TMP_DIR}/manager.yaml" >/dev/null
kubectl rollout status -n "${OPERATOR_NAMESPACE}" deployment/supek8smcp-controller-manager --timeout=180s >/dev/null

echo "running Kubernetes MCP E2E in ${E2E_NAMESPACE}"
SUPEK8SMCP_E2E=1 \
SUPEK8SMCP_E2E_NAMESPACE="${E2E_NAMESPACE}" \
go test ./test/e2e -count=1 -timeout=8m -v
