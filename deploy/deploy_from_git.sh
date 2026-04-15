#!/usr/bin/env bash

set -euo pipefail

REPO_URL="${1:-}"
WORKDIR="${WORKDIR:-/tmp/fist-deploy}"
BRANCH="${BRANCH:-}"
IMAGE="${IMAGE:-zijiren/fist:latest}"
NAMESPACE="${NAMESPACE:-sealyun}"
DEPLOY_TERMINAL="${DEPLOY_TERMINAL:-true}"
DEPLOY_RBAC_APP="${DEPLOY_RBAC_APP:-false}"
AUTH_SERVICE_NAME="${AUTH_SERVICE_NAME:-fist}"
AUTH_CONFIGMAP_NAME="${AUTH_CONFIGMAP_NAME:-fist-authz-webhook}"
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

patch_manifests() {
  local repo_dir="${WORKDIR}/repo"
  local auth_yaml="${repo_dir}/auth/deploy/auth.yaml"
  local terminal_yaml="${repo_dir}/terminal/deploy/deploy.yaml"
  local rbac_yaml="${repo_dir}/rbac/deploy/deploy.yaml"
  local deploy_rbac_yaml="${repo_dir}/deploy/rbac.yaml"

  log "patching manifests to use image ${IMAGE}"
  sed -i.bak "s|image: .*|image: ${IMAGE}|g" "${auth_yaml}" "${terminal_yaml}" "${rbac_yaml}"

  log "patching deprecated apiVersions for newer Kubernetes releases"
  sed -i.bak 's|rbac.authorization.k8s.io/v1beta1|rbac.authorization.k8s.io/v1|g' "${deploy_rbac_yaml}"

  python3 - "${auth_yaml}" "${terminal_yaml}" "${rbac_yaml}" <<'PY'
import sys
for path in sys.argv[1:]:
    out = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            stripped = line.lstrip()
            if stripped.startswith('clusterIP:'):
                continue
            out.append(line)
    with open(path, 'w', encoding='utf-8') as f:
        f.writelines(out)
PY

  sed -i.bak "s/namespace: sealyun/namespace: ${NAMESPACE}/g" "${auth_yaml}" "${terminal_yaml}" "${rbac_yaml}" "${deploy_rbac_yaml}"
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

generate_certs_and_secret() {
  local repo_dir="${WORKDIR}/repo"
  pushd "${repo_dir}/auth/deploy" >/dev/null
  rm -f ssl/*
  sh gencert.sh
  kubectl -n "${NAMESPACE}" delete secret fist --ignore-not-found
  kubectl create secret generic fist \
    --from-file=ssl/cert.pem \
    --from-file=ssl/key.pem \
    -n "${NAMESPACE}"
  popd >/dev/null
}

configure_apiserver() {
  local kube_dir="/etc/kubernetes/pki/fist"
  local manifest="/etc/kubernetes/manifests/kube-apiserver.yaml"
  mkdir -p "${kube_dir}"
  cp -f "${WORKDIR}/repo/auth/deploy/ssl/ca.pem" "${kube_dir}/ca.pem"

  cat > "${kube_dir}/authz-webhook.kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: ${kube_dir}/ca.pem
    server: https://${AUTH_SERVICE_NAME}.${NAMESPACE}.svc.cluster.local:8443
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

  python3 - "${manifest}" <<EOF
import sys
path = sys.argv[1]
required = [
    "    - --authorization-mode=Node,Webhook,RBAC\n",
    "    - --authorization-webhook-config-file=/etc/kubernetes/pki/fist/authz-webhook.kubeconfig\n",
    "    - --oidc-issuer-url=https://${AUTH_SERVICE_NAME}.${NAMESPACE}.svc.cluster.local:8443\n",
    "    - --oidc-client-id=sealyun-fist\n",
    "    - --oidc-ca-file=/etc/kubernetes/pki/fist/ca.pem\n",
    "    - --oidc-username-claim=name\n",
    "    - --oidc-groups-claim=groups\n",
    "    - --oidc-username-prefix=-\n",
    "    - --oidc-groups-prefix=-\n",
]

with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

insert_idx = None
for idx, line in enumerate(lines):
    if line.strip() == "- kube-apiserver":
        insert_idx = idx + 1
        break

if insert_idx is None:
    raise SystemExit("failed to locate kube-apiserver command block in manifest")

existing = set(lines)
to_insert = [line for line in required if line not in existing]
if to_insert:
    lines[insert_idx:insert_idx] = to_insert
    with open(path, 'w', encoding='utf-8') as f:
        f.writelines(lines)
EOF
}

deploy_resources() {
  local repo_dir="${WORKDIR}/repo"
  kubectl apply -f "${repo_dir}/auth/deploy/authz-configmap.yaml"
  kubectl apply -f "${repo_dir}/auth/deploy/auth.yaml"

  if [[ "${DEPLOY_TERMINAL}" == "true" ]]; then
    kubectl apply -f "${repo_dir}/terminal/deploy/deploy.yaml"
  fi

  if [[ "${DEPLOY_RBAC_APP}" == "true" ]]; then
    kubectl apply -f "${repo_dir}/rbac/deploy/deploy.yaml"
  fi
}

print_summary() {
  cat <<EOF

deployment completed.

repo: ${REPO_URL}
workspace: ${WORKDIR}/repo
namespace: ${NAMESPACE}
image: ${IMAGE}
blocked usernames: ${BLOCKED_USERNAMES}
auth service dns: https://${AUTH_SERVICE_NAME}.${NAMESPACE}.svc.cluster.local:8443

notes:
- this policy blocks resource requests for the configured usernames by matching wildcard apiGroups/resources/verbs.
- non-resource requests are not blocked by the current webhook implementation.
- kube-apiserver static pod manifest was updated in /etc/kubernetes/manifests/kube-apiserver.yaml.
- webhook kubeconfig was written to /etc/kubernetes/pki/fist/authz-webhook.kubeconfig.
EOF
}

create_namespace_and_rbac() {
  local repo_dir="${WORKDIR}/repo"
  kubectl get ns "${NAMESPACE}" >/dev/null 2>&1 || kubectl create ns "${NAMESPACE}"
  kubectl apply -f "${repo_dir}/deploy/rbac.yaml"
}

main() {
  if [[ -z "${REPO_URL}" ]]; then
    echo "usage: $0 <git-repo-url>" >&2
    exit 1
  fi

  if [[ "${NAMESPACE}" != "sealyun" ]]; then
    echo "NAMESPACE=${NAMESPACE} is not supported by this script because auth/deploy/gencert.sh hardcodes the certificate SAN to fist.sealyun.svc.cluster.local" >&2
    exit 1
  fi

  if [[ "${AUTH_SERVICE_NAME}" != "fist" ]]; then
    echo "AUTH_SERVICE_NAME=${AUTH_SERVICE_NAME} is not supported by this script because auth/deploy/gencert.sh hardcodes the certificate SAN to fist.sealyun.svc.cluster.local" >&2
    exit 1
  fi

  need_root
  need_cmd git
  need_cmd kubectl
  need_cmd openssl
  need_cmd python3

  prepare_workspace
  patch_manifests
  write_block_config
  create_namespace_and_rbac
  generate_certs_and_secret
  deploy_resources
  configure_apiserver

  log "re-applying auth deployment after secret/config preparation"
  kubectl rollout restart deployment/fist -n "${NAMESPACE}"
  kubectl rollout status deployment/fist -n "${NAMESPACE}" --timeout=180s

  if [[ "${DEPLOY_TERMINAL}" == "true" ]]; then
    kubectl rollout status deployment/fist-terminal -n "${NAMESPACE}" --timeout=180s
  fi

  print_summary
}

main "$@"
