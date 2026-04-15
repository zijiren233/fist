#!/usr/bin/env bash

set -euo pipefail

REPO_URL="${1:-}"
WORKDIR="${WORKDIR:-/tmp/fist-deploy}"
BRANCH="${BRANCH:-}"
IMAGE="${IMAGE:-zijiren/fist:latest}"
NAMESPACE="${NAMESPACE:-sealyun}"
AUTH_CONFIGMAP_NAME="${AUTH_CONFIGMAP_NAME:-fist-authz-webhook}"
AUTH_DEPLOYMENT_NAME="${AUTH_DEPLOYMENT_NAME:-fist}"
AUTH_SERVICE_NAME="${AUTH_SERVICE_NAME:-fist}"
AUTH_HTTPS_NODEPORT="${AUTH_HTTPS_NODEPORT:-32201}"
BLOCKED_USERNAMES="${BLOCKED_USERNAMES:-kubernetes-admin,pentest-admin}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "this script must run as root because it writes /etc/kubernetes/pki/fist and edits kube-apiserver manifests" >&2
    exit 1
  fi
}

log() {
  printf '[deploy] %s\n' "$*"
}

join_csv_as_yaml_list() {
  local input="$1"
  local first=true
  local item
  printf '['
  IFS=',' read -r -a items <<<"${input}"
  for item in "${items[@]}"; do
    item="$(echo "${item}" | xargs)"
    [[ -z "${item}" ]] && continue
    if [[ "${first}" == true ]]; then
      first=false
    else
      printf ', '
    fi
    printf '"%s"' "${item}"
  done
  printf ']'
}

prepare_workspace() {
  rm -rf "${WORKDIR}"
  mkdir -p "${WORKDIR}"
  log "cloning ${REPO_URL} into ${WORKDIR}"
  git clone "${REPO_URL}" "${WORKDIR}/repo"
  if [[ -n "${BRANCH}" ]]; then
    git -C "${WORKDIR}/repo" checkout "${BRANCH}"
  fi
}

patch_auth_manifest() {
  local repo_dir="${WORKDIR}/repo"
  local auth_yaml="${repo_dir}/auth/deploy/auth.yaml"

  log "patching auth manifest to use image ${IMAGE}"
  sed -i.bak "s|image: .*|image: ${IMAGE}|g" "${auth_yaml}"
  sed -i.bak "s|namespace: sealyun|namespace: ${NAMESPACE}|g" "${auth_yaml}"
  sed -i.bak "s|name: fist-authz-webhook|name: ${AUTH_CONFIGMAP_NAME}|g" "${auth_yaml}"
  sed -i.bak "s|name: fist$|name: ${AUTH_SERVICE_NAME}|g" "${auth_yaml}"
  sed -i.bak "s|name: fist$|name: ${AUTH_DEPLOYMENT_NAME}|g" "${auth_yaml}"
  sed -i.bak "s|nodePort: 32201|nodePort: ${AUTH_HTTPS_NODEPORT}|g" "${auth_yaml}"

  python3 - "${auth_yaml}" <<'PY'
import sys
path = sys.argv[1]
out = []
with open(path, 'r', encoding='utf-8') as f:
    for line in f:
        if line.lstrip().startswith("clusterIP:"):
            continue
        out.append(line)
with open(path, 'w', encoding='utf-8') as f:
    f.writelines(out)
PY
}

write_block_config() {
  local repo_dir="${WORKDIR}/repo"
  local config_path="${repo_dir}/auth/deploy/authz-configmap.yaml"
  local yaml_usernames

  yaml_usernames="$(join_csv_as_yaml_list "${BLOCKED_USERNAMES}")"

  cat > "${config_path}" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${AUTH_CONFIGMAP_NAME}
  namespace: ${NAMESPACE}
data:
  config.yaml: |
    apiVersion: fist.sealyun.com/v1alpha1
    kind: AuthorizationWebhookConfig
    users:
    - usernames: ${yaml_usernames}
      protectedResources:
      - apiGroups: ["*"]
        resources: ["*"]
        verbs: ["*"]
        scope: All
EOF
}

get_apiserver_advertise_address() {
  python3 - <<'PY'
from pathlib import Path
manifest = Path("/etc/kubernetes/manifests/kube-apiserver.yaml").read_text().splitlines()
for line in manifest:
    stripped = line.strip()
    if stripped.startswith("- --advertise-address="):
        print(stripped.split("=", 1)[1])
        raise SystemExit(0)
raise SystemExit("failed to find --advertise-address in kube-apiserver manifest")
PY
}

generate_certs_and_secret() {
  local advertise_address="$1"
  local ssl_dir="${WORKDIR}/repo/auth/deploy/ssl"
  mkdir -p "${ssl_dir}"

  cat > "${ssl_dir}/req.cnf" <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${AUTH_SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
DNS.2 = ${AUTH_SERVICE_NAME}.${NAMESPACE}.cluster.local
IP.1 = 127.0.0.1
IP.2 = ${advertise_address}
EOF

  openssl genrsa -out "${ssl_dir}/ca-key.pem" 2048 >/dev/null 2>&1
  openssl req -x509 -new -nodes -key "${ssl_dir}/ca-key.pem" -days 36500 -out "${ssl_dir}/ca.pem" -subj "/CN=fist-ca" >/dev/null 2>&1
  openssl genrsa -out "${ssl_dir}/key.pem" 2048 >/dev/null 2>&1
  openssl req -new -key "${ssl_dir}/key.pem" -out "${ssl_dir}/csr.pem" -subj "/CN=${AUTH_SERVICE_NAME}" -config "${ssl_dir}/req.cnf" >/dev/null 2>&1
  openssl x509 -req \
    -in "${ssl_dir}/csr.pem" \
    -CA "${ssl_dir}/ca.pem" \
    -CAkey "${ssl_dir}/ca-key.pem" \
    -CAcreateserial \
    -out "${ssl_dir}/cert.pem" \
    -days 36500 \
    -extensions v3_req \
    -extfile "${ssl_dir}/req.cnf" >/dev/null 2>&1

  kubectl -n "${NAMESPACE}" delete secret fist --ignore-not-found >/dev/null 2>&1 || true
  kubectl create secret generic fist \
    --from-file="${ssl_dir}/cert.pem" \
    --from-file="${ssl_dir}/key.pem" \
    -n "${NAMESPACE}"
}

deploy_auth() {
  local repo_dir="${WORKDIR}/repo"
  kubectl get ns "${NAMESPACE}" >/dev/null 2>&1 || kubectl create ns "${NAMESPACE}"
  kubectl apply -f "${repo_dir}/auth/deploy/authz-configmap.yaml"
  kubectl apply -f "${repo_dir}/auth/deploy/auth.yaml"
  kubectl rollout status "deployment/${AUTH_DEPLOYMENT_NAME}" -n "${NAMESPACE}" --timeout=180s
}

write_webhook_kubeconfig() {
  local advertise_address="$1"
  local kube_dir="/etc/kubernetes/pki/fist"
  mkdir -p "${kube_dir}"
  cp -f "${WORKDIR}/repo/auth/deploy/ssl/ca.pem" "${kube_dir}/ca.pem"

  cat > "${kube_dir}/authz-webhook.kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: ${kube_dir}/ca.pem
    server: https://${advertise_address}:${AUTH_HTTPS_NODEPORT}
  name: fist-authz-webhook
contexts:
- context:
    cluster: fist-authz-webhook
    user: fist-authz-webhook
  name: fist-authz-webhook
current-context: fist-authz-webhook
users:
- name: fist-authz-webhook
  user: {}
EOF
}

patch_apiserver_manifest() {
  local manifest="/etc/kubernetes/manifests/kube-apiserver.yaml"
  cp -f "${manifest}" "${manifest}.bak.$(date +%Y%m%d%H%M%S)"

  python3 - "${manifest}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text().splitlines(keepends=True)

remove_prefixes = (
    "    - --authorization-mode=",
    "    - --authorization-webhook-config-file=",
    "    - --oidc-issuer-url=",
    "    - --oidc-client-id=",
    "    - --oidc-ca-file=",
    "    - --oidc-username-claim=",
    "    - --oidc-groups-claim=",
    "    - --oidc-username-prefix=",
    "    - --oidc-groups-prefix=",
)

filtered = [line for line in lines if not line.startswith(remove_prefixes)]

insert_idx = None
for idx, line in enumerate(filtered):
    if line.strip() == "- kube-apiserver":
        insert_idx = idx + 1
        break

if insert_idx is None:
    raise SystemExit("failed to locate kube-apiserver command block in manifest")

required = [
    "    - --authorization-mode=Node,Webhook,RBAC\n",
    "    - --authorization-webhook-config-file=/etc/kubernetes/pki/fist/authz-webhook.kubeconfig\n",
]

filtered[insert_idx:insert_idx] = required
path.write_text("".join(filtered))
PY
}

wait_for_apiserver() {
  local attempts=90
  local i

  log "waiting for kube-apiserver to become ready again"
  for ((i=1; i<=attempts; i++)); do
    if kubectl --request-timeout=5s get --raw=/readyz >/dev/null 2>&1; then
      log "kube-apiserver is ready"
      return 0
    fi
    sleep 2
  done

  echo "kube-apiserver did not become ready in time" >&2
  return 1
}

print_summary() {
  cat <<EOF

deployment completed.

repo: ${REPO_URL}
workspace: ${WORKDIR}/repo
namespace: ${NAMESPACE}
image: ${IMAGE}
blocked usernames: ${BLOCKED_USERNAMES}
webhook kubeconfig: /etc/kubernetes/pki/fist/authz-webhook.kubeconfig

notes:
- only auth was deployed.
- no oidc flags were added to kube-apiserver.
- kube-apiserver authorization mode is now Node,Webhook,RBAC.
- this only blocks resource requests for ${BLOCKED_USERNAMES}.
- non-resource requests are not blocked by the current webhook implementation.
EOF
}

main() {
  local advertise_address

  if [[ -z "${REPO_URL}" ]]; then
    echo "usage: $0 <git-repo-url>" >&2
    exit 1
  fi

  need_root
  need_cmd git
  need_cmd kubectl
  need_cmd openssl
  need_cmd python3

  advertise_address="$(get_apiserver_advertise_address)"

  prepare_workspace
  patch_auth_manifest
  write_block_config
  generate_certs_and_secret "${advertise_address}"
  deploy_auth
  write_webhook_kubeconfig "${advertise_address}"
  patch_apiserver_manifest
  wait_for_apiserver

  print_summary
}

main "$@"
