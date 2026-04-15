cd ../auth/deploy && sh install.sh
echo "10.106.233.67 fist.sealyun.svc.cluster.local" >> /etc/hosts
cd - && kubectl apply -f rbac.yaml && cd ../terminal/deploy && kubectl apply -f deploy.yaml
