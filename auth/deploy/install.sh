set -e
rm ssl/*
sh gencert.sh
sleep 3
sh secret.sh
kubectl apply -f authz-configmap.yaml
kubectl create -f auth.yaml
mkdir -p /etc/kubernetes/pki/fist/ || true
cp -rf  ssl/ca.pem /etc/kubernetes/pki/fist/
cat > /etc/kubernetes/pki/fist/authz-webhook.kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: /etc/kubernetes/pki/fist/ca.pem
    server: https://fist.sealyun.svc.cluster.local:8443
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

echo "wait for auth service sleep 15s... "
sleep 15

echo '  [WARN] edit kube-apiserver.yaml and add oidc config, if auth service not ready, apiserver may start failed!'
sed '/- kube-apiserver/a\    - --oidc-username-prefix=-' -i /etc/kubernetes/manifests/kube-apiserver.yaml
sed '/- kube-apiserver/a\    - --oidc-groups-prefix=-' -i /etc/kubernetes/manifests/kube-apiserver.yaml
sed '/- kube-apiserver/a\    - --oidc-groups-claim=groups' -i /etc/kubernetes/manifests/kube-apiserver.yaml
sed '/- kube-apiserver/a\    - --oidc-username-claim=name' -i /etc/kubernetes/manifests/kube-apiserver.yaml
sed '/- kube-apiserver/a\    - --oidc-ca-file=/etc/kubernetes/pki/fist/ca.pem' -i /etc/kubernetes/manifests/kube-apiserver.yaml
sed '/- kube-apiserver/a\    - --oidc-client-id=sealyun-fist' -i /etc/kubernetes/manifests/kube-apiserver.yaml
sed '/- kube-apiserver/a\    - --oidc-issuer-url=https://fist.sealyun.svc.cluster.local:8443' -i /etc/kubernetes/manifests/kube-apiserver.yaml
echo '  [WARN] enable the authorization webhook manually:'
echo '    - set --authorization-mode=Node,Webhook,RBAC'
echo '    - add --authorization-webhook-config-file=/etc/kubernetes/pki/fist/authz-webhook.kubeconfig'
echo '    - edit the ConfigMap fist-authz-webhook in namespace sealyun to configure protected users and whitelist rules'
