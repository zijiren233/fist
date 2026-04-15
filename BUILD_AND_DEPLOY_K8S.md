# Fist 构建与部署文档

本文说明如何从当前仓库构建 `fist` 二进制和镜像，并将其部署到 Kubernetes。

重点覆盖三类场景：

- 只部署 `auth` 服务
- 部署 `auth + terminal`
- 将 `auth` 接入 kube-apiserver，作为 OIDC issuer 和 authorization webhook

## 1. 前提条件

在开始之前，确认满足以下条件：

- 已安装 Go
- 已安装 Docker 或兼容的镜像构建工具
- 已安装 `kubectl`
- 当前 `kubectl` 上下文具备集群管理权限
- 如果要启用 authorization webhook，需要能修改 kube-apiserver 启动参数

注意：

- 当前仓库的 webhook 接入方式依赖修改 kube-apiserver 静态 Pod 参数，因此更适合自建 Kubernetes 控制面
- 对于 ACK、EKS、GKE 等托管集群，通常无法直接修改 kube-apiserver 参数，这种情况下只能部署 `fist auth` 服务本身，不能完整启用 webhook 链路

## 2. 仓库内相关文件

- 二进制入口：`main.go`
- Dockerfile：`deploy/Dockerfile`
- `auth` 部署清单：`auth/deploy/auth.yaml`
- `auth` 授权配置示例：`auth/deploy/authz-configmap.yaml`
- `auth` 安装脚本：`auth/deploy/install.sh`
- `terminal` 部署清单：`terminal/deploy/deploy.yaml`
- `rbac` ServiceAccount/ClusterRoleBinding：`deploy/rbac.yaml`
- 总安装入口：`deploy/init.sh`、`deploy/install.sh`

## 3. 本地构建二进制

在仓库根目录执行：

```bash
go build -o fist .
```

构建完成后会生成 `./fist`。

如果只想在本地运行，可以直接执行：

```bash
./fist auth
./fist terminal
./fist rbac
```

其中：

- `fist auth` 默认监听 `8443` 和 `8080`
- `fist terminal` 默认监听 `8080`
- `fist rbac` 默认监听 `8080`

## 4. 构建容器镜像

仓库内 Dockerfile 非常简单，只是把已经编译好的 `fist` 二进制复制进镜像：

```dockerfile
FROM centos:7.6.1810
COPY ./fist .
CMD ["./fist", "auth"]
```

因此标准构建流程是：

```bash
go build -o fist .
docker build -t <your-registry>/fist:<tag> -f deploy/Dockerfile .
docker push <your-registry>/fist:<tag>
```

示例：

```bash
go build -o fist .
docker build -t registry.example.com/fist:v0.1.0 -f deploy/Dockerfile .
docker push registry.example.com/fist:v0.1.0
```

## 5. 部署前需要修改的清单

仓库自带的 YAML 可以直接参考，但不建议原样用于生产环境。部署前至少检查以下内容：

### 5.1 镜像地址

以下文件默认镜像仍然是 `lameleg/fist:latest`，需要替换成你自己的镜像：

- `auth/deploy/auth.yaml`
- `terminal/deploy/deploy.yaml`
- `rbac/deploy/deploy.yaml`

例如改成：

```yaml
image: registry.example.com/fist:v0.1.0
imagePullPolicy: IfNotPresent
```

### 5.2 Service 的 `clusterIP` 和 `nodePort`

仓库里的多个 Service 写死了 `clusterIP` 和 `nodePort`。如果这些值和你的集群网段或现有端口冲突，应用会失败。

建议在部署前做以下处理之一：

- 删除 `clusterIP` 字段，让 Kubernetes 自动分配
- 保留或调整 `nodePort`
- 如果不需要 NodePort，直接改成 `ClusterIP`

受影响文件包括：

- `auth/deploy/auth.yaml`
- `terminal/deploy/deploy.yaml`
- `rbac/deploy/deploy.yaml`

### 5.3 webhook 域名解析

仓库默认使用：

```text
fist.sealyun.svc.cluster.local
```

这要求：

- Service 名称必须是 `fist`
- Namespace 必须是 `sealyun`
- kube-apiserver 能解析集群 DNS

如果你修改了 Service 名称或命名空间，必须同步修改：

- `auth/deploy/install.sh` 中写入的 webhook kubeconfig
- OIDC issuer URL
- 相关说明文档和访问命令

## 6. 最小部署流程

如果你只是想把服务部署到集群中，不立即接入 kube-apiserver，可以按下面步骤执行。

### 6.1 创建命名空间和高权限 ServiceAccount

```bash
kubectl create ns sealyun
kubectl apply -f deploy/rbac.yaml
```

这会创建：

- `sealyun` 命名空间下的 `admin` ServiceAccount
- 一个绑定到 `cluster-admin` 的 ClusterRoleBinding

注意：这里权限非常高，只适合测试环境或你明确接受该风险的场景。

### 6.2 生成 `auth` 证书并创建 Secret

进入 `auth/deploy`：

```bash
cd auth/deploy
sh gencert.sh
sh secret.sh
```

这两步会：

- 在 `auth/deploy/ssl` 目录生成 CA、服务证书和私钥
- 在 `sealyun` 命名空间创建名为 `fist` 的 Secret

### 6.3 创建授权配置 ConfigMap

```bash
kubectl apply -f auth/deploy/authz-configmap.yaml
```

多用户名配置示例：

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fist-authz-webhook
  namespace: sealyun
data:
  config.yaml: |
    apiVersion: fist.sealyun.com/v1alpha1
    kind: AuthorizationWebhookConfig
    users:
    - usernames: ["alice", "bob"]
      protectedResources:
      - apiGroups: [""]
        resources: ["secrets"]
        verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
        scope: Namespaced
        namespaces: ["default", "prod"]
      whitelist:
      - apiGroups: [""]
        resources: ["secrets"]
        verbs: ["get", "list"]
        scope: Namespaced
        namespaces: ["default"]
```

兼容旧格式，单用户仍可写为：

```yaml
users:
- username: alice
  protectedResources:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
```

### 6.4 部署 `auth`

确保你已经把 `auth/deploy/auth.yaml` 中的镜像改成自己的镜像，然后执行：

```bash
kubectl apply -f auth/deploy/auth.yaml
```

检查：

```bash
kubectl get pod -n sealyun
kubectl get svc -n sealyun
```

### 6.5 可选：部署 `terminal`

修改 `terminal/deploy/deploy.yaml` 中的镜像后执行：

```bash
kubectl apply -f terminal/deploy/deploy.yaml
```

### 6.6 可选：部署 `rbac`

修改 `rbac/deploy/deploy.yaml` 中的镜像后执行：

```bash
kubectl apply -f rbac/deploy/deploy.yaml
```

## 7. 使用脚本快速部署

仓库内有两层脚本：

### 7.1 初始化基础资源

```bash
cd deploy
sh init.sh
```

它做的事等价于：

```bash
kubectl create ns sealyun
kubectl create -f rbac.yaml
```

### 7.2 安装服务

```bash
cd deploy
sh install.sh
```

当前脚本行为是：

1. 进入 `auth/deploy` 执行安装
2. 把 `fist.sealyun.svc.cluster.local` 追加到本机 `/etc/hosts`
3. 应用 `deploy/rbac.yaml`
4. 应用 `terminal/deploy/deploy.yaml`

注意：

- 这个脚本不是通用生产脚本，更适合作者原始环境
- `/etc/hosts` 中写入的是固定 IP：`10.106.233.67`
- 如果你的 `auth` Service `clusterIP` 不是这个值，这一步会错误

因此更建议你按本文第 6 节手动执行，或者先改脚本再使用。

## 8. 接入 kube-apiserver

如果你要真正启用以下能力：

- `fist auth` 作为 OIDC issuer
- `fist auth` 作为 authorization webhook

还需要控制平面侧配置。

### 8.1 运行 `auth` 安装脚本

```bash
cd auth/deploy
sh install.sh
```

这个脚本会额外做几件事：

- 生成证书
- 创建 `fist` Secret
- 应用 `fist-authz-webhook` ConfigMap
- 部署 `auth`
- 将 `ssl/ca.pem` 拷贝到 `/etc/kubernetes/pki/fist/ca.pem`
- 生成 `/etc/kubernetes/pki/fist/authz-webhook.kubeconfig`
- 自动往 `/etc/kubernetes/manifests/kube-apiserver.yaml` 里插入 OIDC 参数

### 8.2 手动补充 authorization webhook 参数

当前脚本只会打印提示，不会自动写入下面两个关键参数：

```yaml
- --authorization-mode=Node,Webhook,RBAC
- --authorization-webhook-config-file=/etc/kubernetes/pki/fist/authz-webhook.kubeconfig
```

你必须手动把它们加到 kube-apiserver 启动参数中。

### 8.3 OIDC 相关参数

脚本会尝试插入以下参数：

```yaml
- --oidc-issuer-url=https://fist.sealyun.svc.cluster.local:8443
- --oidc-client-id=sealyun-fist
- --oidc-ca-file=/etc/kubernetes/pki/fist/ca.pem
- --oidc-username-claim=name
- --oidc-groups-claim=groups
- --oidc-username-prefix=-
- --oidc-groups-prefix=-
```

### 8.4 顺序要求

如果启用 webhook，`Webhook` 必须排在 `RBAC` 前面：

```yaml
--authorization-mode=Node,Webhook,RBAC
```

否则 RBAC 可能先放行，请求不会再进入这层“按用户的二次授权”逻辑。

## 9. 验证部署

### 9.1 验证 `auth` 服务

查看 Pod 和 Service：

```bash
kubectl get pods -n sealyun
kubectl get svc -n sealyun
```

### 9.2 验证 OIDC 元数据接口

```bash
curl https://fist.sealyun.svc.cluster.local:8443/.well-known/openid-configuration --cacert auth/deploy/ssl/ca.pem
```

### 9.3 验证 JWKS

```bash
curl https://fist.sealyun.svc.cluster.local:8443/keys --cacert auth/deploy/ssl/ca.pem
```

### 9.4 生成测试 token

```bash
curl "http://fist.sealyun.svc.cluster.local:8080/token?user=alice&group=dev&group=test"
```

### 9.5 验证授权策略

在 ConfigMap 中为 `alice` 配置 `protectedResources` 和 `whitelist` 后，用该 token 请求 kube-apiserver，验证是否符合预期：

- 命中 `protectedResources` 且未命中 `whitelist` 时应被拒绝
- 命中 `whitelist` 时应放行
- 未配置的用户返回 `NoOpinion`，继续由原生 RBAC 决定

## 10. 常见问题

### 10.1 `kubectl apply` 失败，提示 `provided IP is already allocated`

原因通常是 YAML 里写死的 `clusterIP` 与当前集群冲突。

处理方式：

- 删除 Service 里的 `clusterIP`
- 重新应用 YAML

### 10.2 `fist auth` Pod 启动失败，提示找不到证书

检查：

- 是否执行了 `auth/deploy/gencert.sh`
- 是否执行了 `auth/deploy/secret.sh`
- Secret `fist` 是否存在于 `sealyun` 命名空间

### 10.3 webhook 没生效

优先检查：

- kube-apiserver 是否真的启用了 `Webhook`
- `--authorization-webhook-config-file` 是否已配置
- `Webhook` 是否在 `RBAC` 前面
- kube-apiserver 是否能访问 `https://fist.sealyun.svc.cluster.local:8443`
- `fist-authz-webhook` ConfigMap 中是否存在匹配该用户的规则

### 10.4 多用户名规则怎么写

推荐：

```yaml
users:
- usernames: ["alice", "bob", "carol"]
  protectedResources:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
```

如果你只需要单用户，继续使用：

```yaml
users:
- username: alice
```

## 11. 推荐部署顺序

建议按下面的顺序执行：

1. 构建 `fist` 二进制
2. 构建并推送镜像
3. 修改 `auth.yaml`、`terminal/deploy.yaml`、`rbac/deploy.yaml` 中的镜像地址
4. 删除或调整写死的 `clusterIP`
5. 创建命名空间和 `admin` ServiceAccount
6. 生成证书并创建 Secret
7. 应用 `authz-configmap.yaml`
8. 部署 `auth`
9. 视需要部署 `terminal` 和 `rbac`
10. 如果是自建集群，再修改 kube-apiserver 启用 OIDC 与 authorization webhook

## 12. 补充说明

当前仓库已经支持一个授权策略命中多个用户名，配置方式是：

```yaml
usernames: ["alice", "bob"]
```

同时保留了旧配置：

```yaml
username: alice
```

两者可以混用，加载时会自动归一化。
