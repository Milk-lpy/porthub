# PortHub

PortHub 是一个面向家庭实验室、NAS、PVE、Docker 主机、游戏服务器和
Linux/Windows 内网设备的统一公网入口管理平台。

它把公网入口、WireGuard 隧道、TCP/UDP 端口映射、HTTP/HTTPS 反向代理、
域名/DDNS、TLS 证书、ACL、安全审计、节点状态和配置回滚放在同一个控制台
中管理。使用者可以先发现内网服务，再通过模板或表单发布服务，不需要每次
手工编写 nftables 规则。

> **重要说明**：本仓库是脱敏后的公开代码快照。仓库中的 IP、域名、证书路径
> 和 systemd 参数都是示例值，不能直接复制到真实网络。生产部署必须先做只读
> 审计、端口/网段冲突检查和备份。

## 一、项目定位

PortHub 采用控制面和数据面分离的结构：

```text
公网客户端
    |
    v
PortHub Edge  ---- 公网 TCP/UDP、轻量代理、nftables、WireGuard
    |
    |  独立 wg-porthub 隧道 + mTLS
    v
PortHub Core  ---- 用户、映射、策略、快照、审计、历史数据
    |
    v
Agent / 内网资源 / NAS / PVE / Docker / Windows / Linux
```

### Edge：公网数据面

Edge 部署在有公网 IPv4 的节点，负责低延迟转发和最后有效配置的持续运行：

- 接收 TCP、UDP 和 TCP+UDP 公网流量；
- 通过独立的 `wg-porthub` 把流量送到 Core 或指定节点；
- 只在 PortHub 自有的 `table inet porthub` 中应用规则；
- 提供轻量 HTTP/HTTPS Host/Path 反向代理；
- 保存当前和上一份有效快照，Core 暂时离线时仍继续转发；
- 通过受限 `porthub-netd` helper 执行 nftables、WireGuard 和只读连接统计；
- 不保存长期历史指标，不运行 Elasticsearch、Grafana 等重型服务。

### Core：控制面和数据中心

Core 部署在局域网或受保护的管理节点，负责：

- 用户、角色、密码、TOTP、Session、可信设备和 API Token；
- 节点、资源、服务、映射组、模板、映射和 HTTP 代理；
- WireGuard Peer、ACL、IP 集合、限速和连接数限制；
- DDNS、域名、ACME 证书、Webhook 和升级任务；
- 配置编译、Ed25519 签名、mTLS 下发、版本历史和回滚；
- 局域网扫描、Agent 状态、流量历史、公网来源 IP 审计和操作审计；
- SQLite WAL 数据库、定时备份和恢复计划。

### Agent：节点采集面

第一阶段包含 Linux Agent，并提供 Windows 构建和安装结构。Agent 负责：

- 使用一次性注册凭据向 Core 注册；
- 本地生成 ECDSA 私钥，通过 mTLS 上报心跳；
- 上报 CPU、内存、磁盘、网卡、监听端口和 Docker 容器摘要；
- 执行受签名、带时间戳、带 nonce 且在白名单内的任务校验；
- 默认不提供任意 Shell 执行接口，不上传环境变量、数据包内容或业务日志。

## 二、主要功能

| 模块 | 能力 |
| --- | --- |
| TCP/UDP 映射 | 单端口、连续端口段、TCP、UDP、TCP+UDP、批量启停、导入导出 |
| HTTP/HTTPS 代理 | Host/Path 路由、WebSocket、Header、健康检查、TLS 和强制 HTTPS |
| WireGuard | 独立 `wg-porthub`、Peer 管理、AllowedIPs 校验、握手状态和流量 |
| 资源与服务 | 局域网扫描、端口发现、服务分类、资源目录和发布草稿 |
| 模板 | Minecraft、游戏、NAS、Web、远程管理等模板，支持风险提示 |
| 安全策略 | IPv4/IPv6 CIDR、白名单、黑名单、协议/端口绑定、限速、连接限制 |
| 域名与 DDNS | Cloudflare、阿里云、腾讯 DNSPod、Webhook 和外部记录模式 |
| TLS 证书 | ACME HTTP-01、DNS-01、手工导入、续期、到期提醒和热部署 |
| 监控审计 | 实时计数、流量历史、连接摘要、公网来源 IP、操作审计和告警 |
| 快照回滚 | 签名快照、nft 语法预检、健康检查、失败回滚和历史版本 |
| 认证权限 | Argon2id、TOTP、可信设备、CSRF、安全 Cookie、RBAC 和登录限速 |
| 节点管理 | Edge、Core、Linux Agent、Windows Agent、PVE/NAS/Docker 发现 |

## 三、默认示例参数

以下全部是文档保留值，只用于开发和演示：

| 配置项 | 示例值 | 说明 |
| --- | --- | --- |
| Edge 公网地址 | `203.0.113.10` | RFC 5737 文档地址，不是真实公网地址 |
| 示例 LAN | `192.0.2.0/24` | RFC 5737 文档网段，不是真实家庭网段 |
| PortHub 隧道 | `10.255.0.0/24` | 示例隧道，必须现场检查冲突 |
| Edge 隧道地址 | `10.255.0.1/24` | 示例值 |
| Core 隧道地址 | `10.255.0.2/24` | 示例值 |
| 管理 API | `9443/tcp` | Core 和 Edge 分别监听在各自主机 |
| HTTP 代理 | `18090/tcp` | Edge 轻量 HTTP 代理示例端口 |
| HTTPS 代理 | `18443/tcp` | Edge 轻量 HTTPS 代理示例端口 |
| WireGuard | `51830/udp` | 仅是优先示例，必须扫描后再使用 |
| Agent 本地接口 | `127.0.0.1:9731` | 默认只绑定本机回环地址 |

生产环境要重新选择这些值，并确认：

1. 端口没有被 Nginx、宝塔、旧代理、Docker、Lucky 或其他服务占用；
2. 隧道网段没有与现有 WireGuard、Docker、Tailscale、PVE 或 LAN 路由重叠；
3. `AllowedIPs` 不包含未经授权的 `0.0.0.0/0` 或整个 IPv6 默认路由；
4. 云安全组已单独核对，不能把本机监听误认为公网已放行。

## 四、代码结构

```text
porthub/
├── apps/
│   ├── core/              # Core REST API、数据库、认证、快照和控制逻辑
│   ├── edge/              # Edge 数据面、代理、计数和快照应用
│   ├── netd/              # 受限 nftables/WireGuard/systemd helper
│   ├── relay/             # 跨地址族或特殊端口的轻量 relay
│   ├── agent/             # Linux/Windows Agent
│   ├── update-helper/     # root 维护窗口中的签名升级 helper
│   └── frontend/          # Vue 3 + TypeScript 管理面板
├── internal/
│   ├── auth/              # Argon2id、TOTP、Token 等
│   ├── nftables/          # 声明式规则编译和校验
│   ├── snapshots/         # Ed25519 快照、WireGuard 和证书签名
│   └── updater/           # 更新清单、哈希和原子替换
├── deploy/                # systemd、Agent 和 Windows 安装模板
├── scripts/               # 构建辅助、恢复、卸载和 relay 安装脚本
├── docs/                  # 架构、安全、API、备份和运维文档
└── tests/                 # 恢复和卸载隔离测试
```

## 五、开发环境

### 5.1 依赖

- Linux 或 macOS 开发环境；
- Go 工具链；
- Node.js 和 npm；
- SQLite CGO 所需的 C 编译器；
- nftables、WireGuard、systemd 仅在真实 Linux 部署/集成测试时需要；
- Playwright Chromium 用于前端浏览器测试。

查看版本：

```bash
go version
node --version
npm --version
```

### 5.2 编译全部 Go 组件

```bash
make build
```

产物默认在 `bin/`：

```text
bin/porthub-core
bin/porthub-edge
bin/porthub-agent
bin/porthub-netd
bin/porthub-relay
bin/porthub-update-helper
```

构建 Windows Agent：

```bash
make build-windows-agent
```

### 5.3 运行测试

```bash
make test
go test ./...
go test -race ./apps/core ./apps/edge ./apps/agent ./apps/netd ./internal/...
```

前端：

```bash
cd apps/frontend
npm ci
npm run build
npm run test:e2e
```

前端开发代理默认指向 `https://127.0.0.1:9443`。如 Core 在其他地址，使用环境变量：

```bash
PORTHUB_CORE=https://<CORE_HOST>:9443 npm run dev
```

## 六、生产部署总原则

PortHub 不是“复制二进制后直接启动”的无审计安装包。生产部署必须按以下
顺序进行：

```text
只读审计
  -> 选择不冲突的端口、接口和网段
  -> 创建 PortHub 专属备份
  -> 准备证书和 WireGuard 密钥
  -> 安装普通用户进程和受限 helper
  -> 启动 Edge/Core
  -> 初始化管理员和 TOTP
  -> 注册 Agent
  -> 添加禁用映射
  -> 预览、冲突检查、签名下发
  -> 使用临时端口进行验收
```

### 6.1 绝对不要做的事情

PortHub 部署脚本和运维人员都不能执行以下操作：

- `nft flush ruleset`；
- `iptables -F` 或清空 NAT 表；
- 删除、关闭或覆盖其他 WireGuard 接口；
- 停止已有代理、DDNS、宝塔站点、Docker 容器或 SSH；
- 重启整机网络、NetworkManager 或 networking；
- 使用已有服务正在占用的端口；
- 把 root 密码、TOTP Secret、WireGuard 私钥或 DNS 密钥写入 Git；
- 让 Web API 接受任意 Shell 字符串。

PortHub 只拥有自己的 systemd 单元、目录、`wg-porthub`、
`table inet porthub` 和 `table inet porthub_core`。

## 七、详细部署方法

下面以两台 Linux 主机为例：一台作为 Edge，一台作为 Core。命令中的
`<EDGE_HOST>`、`<CORE_HOST>`、`<LAN_CIDRS>` 等必须替换为实际值。

### 7.1 第一步：审计目标主机

在两台主机上只读检查：

- 发行版、内核、架构、CPU、内存和磁盘；
- TCP/UDP 监听端口、网卡、地址和默认路由；
- `ip rule`、全部路由表和策略路由；
- 现有 WireGuard 接口、Peer、监听端口和 AllowedIPs；
- nftables、iptables、firewalld、ufw 和 NAT；
- Nginx、Apache、Caddy、宝塔、Docker、Podman 和数据库；
- IP Forward、`rp_filter`、conntrack、DNS 和时间同步。

审计结果存放到主机外的私有位置。不要把 `ss`、`nft list ruleset`、
机器 ID、进程参数和备份清单提交到公开仓库。

### 7.2 第二步：建立 PortHub 专属目录和用户

在每台目标主机上执行。若系统已有同名用户，先确认 UID/GID 和文件归属，
不要覆盖已有账号：

```bash
sudo groupadd --system porthub 2>/dev/null || true
sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
  --gid porthub porthub 2>/dev/null || true

sudo install -d -o porthub -g porthub -m 0750 /opt/porthub/bin
sudo install -d -o porthub -g porthub -m 0750 /opt/porthub/frontend/releases
sudo install -d -o porthub -g porthub -m 0750 /var/lib/porthub
sudo install -d -o porthub -g porthub -m 0750 /var/log/porthub
sudo install -d -o porthub -g porthub -m 0750 /etc/porthub
sudo install -d -o porthub -g porthub -m 0750 /var/backups/porthub
```

Edge 的状态目录和 Core 的状态目录应分别隔离，例如：

```bash
sudo install -d -o porthub -g porthub -m 0750 /var/lib/porthub/edge
sudo install -d -o porthub -g porthub -m 0750 /var/lib/porthub/core
sudo install -d -o porthub -g porthub -m 0750 /var/lib/porthub/core/netd
```

### 7.3 第三步：构建并安装二进制

在开发机或受控构建机执行：

```bash
make build
```

将对应主机需要的二进制复制到 `/opt/porthub/bin`，并确保 root 拥有二进制、
运行服务使用 `porthub` 用户：

```bash
sudo install -o root -g root -m 0755 bin/porthub-core /opt/porthub/bin/
sudo install -o root -g root -m 0755 bin/porthub-netd /opt/porthub/bin/
sudo install -o root -g root -m 0755 bin/porthub-edge /opt/porthub/bin/
sudo install -o root -g root -m 0755 bin/porthub-agent /opt/porthub/bin/
sudo install -o root -g root -m 0755 bin/porthub-relay /opt/porthub/bin/
sudo install -o root -g root -m 0755 bin/porthub-update-helper /opt/porthub/bin/
```

不要把数据库、`*.key`、`*.pem`、`*.crt`、真实 `.env` 或备份一起复制到 Git
工作目录，更不能上传到 GitHub。

### 7.4 第四步：准备证书和密钥

PortHub 不在公开仓库保存任何生产密钥。使用自己的受信任 CA 或企业 PKI
签发证书，并按下表准备文件。文件权限建议为 `0600` 或 `0640`，目录权限
建议为 `0700` 或 `0750`。

| 主机 | 文件 | 用途 |
| --- | --- | --- |
| Edge | `/etc/porthub/edge.crt`、`edge.key` | Edge mTLS 服务端和 HTTPS 代理证书 |
| Edge | `/etc/porthub/ca.crt` | 验证 Core 的 mTLS 客户端证书 |
| Edge | `/etc/porthub/core-ed25519.pub` | 验证 Core 签名快照 |
| Core | `/var/lib/porthub/core/tls.crt`、`tls.key` | Core 管理 API 和调用 Edge 的客户端身份 |
| Core | `/var/lib/porthub/core/ca.crt` | 验证 Edge mTLS 服务端证书 |
| Core | `/var/lib/porthub/core/agent-ca.crt` | 验证和签发 Agent 证书 |
| Core | `/var/lib/porthub/core/ed25519.key` | Core 首次启动时自动生成；必须保持 `0600` |
| Core | `/var/lib/porthub/core/ed25519.pub` | 分发给 Edge 的签名公钥 |
| Agent | `/etc/porthub/agent/core-ca.crt` | 验证 Core 服务端证书 |
| Agent | `/var/lib/porthub/agent/agent.key` | Agent 首次注册时本地生成 |

Core 的 `ed25519.key` 不要复制到 Edge、前端、日志或 GitHub；Edge 只保存
公钥。Agent 私钥也只保存在 Agent 主机。

### 7.5 第五步：创建独立 WireGuard 隧道

PortHub 默认使用独立接口 `wg-porthub`。下面只展示结构，不提供真实私钥：

```ini
# Edge: /etc/wireguard/wg-porthub.conf
[Interface]
Address = 10.255.0.1/24
ListenPort = 51830
PrivateKey = <EDGE_PRIVATE_KEY>

[Peer]
PublicKey = <CORE_PUBLIC_KEY>
AllowedIPs = 10.255.0.2/32, 192.0.2.0/24
```

```ini
# Core: /etc/wireguard/wg-porthub.conf
[Interface]
Address = 10.255.0.2/24
PrivateKey = <CORE_PRIVATE_KEY>

[Peer]
PublicKey = <EDGE_PUBLIC_KEY>
Endpoint = <EDGE_HOST>:51830
AllowedIPs = 10.255.0.1/32
PersistentKeepalive = 25
```

真实配置需要根据 Core 是否位于 NAT 后方、LAN 网段和回程路由调整。不要
覆盖 `/etc/wireguard` 中其他配置，也不要使用旧接口的密钥或 Peer。

检查并启动前：

```bash
sudo chmod 600 /etc/wireguard/wg-porthub.conf
sudo wg-quick up wg-porthub
sudo wg show wg-porthub
```

确认握手正常后再继续安装 Core/Edge。若系统使用 systemd 管理：

```bash
sudo systemctl enable wg-quick@wg-porthub.service
```

### 7.6 第六步：安装 systemd 单元

先编辑 `deploy/porthub-core.service`、`deploy/porthub-edge.service` 和两个
netd 单元中的示例地址：

- `-edge-public-ipv4` 改为真实 Edge 公网地址；
- `-lan-cidrs` 改为实际需要由 Core 管理的 LAN 网段；
- `-tunnel-cidrs` 改为实际 PortHub 隧道网段；
- `-edge-url` 或其他 Core/Edge 连接地址改为真实可达地址；
- 管理端口和代理端口必须经过冲突检查。

在 **Core 主机** 安装：

```bash
sudo install -o root -g root -m 0644 deploy/porthub-netd.service \
  /etc/systemd/system/porthub-netd.service
sudo install -o root -g root -m 0644 deploy/porthub-core.service \
  /etc/systemd/system/porthub-core.service
```

在 **Edge 主机** 安装：

```bash
sudo install -o root -g root -m 0644 deploy/porthub-edge-netd.service \
  /etc/systemd/system/porthub-netd.service
sudo install -o root -g root -m 0644 deploy/porthub-edge.service \
  /etc/systemd/system/porthub-edge.service
```

注意：两个主机上的服务名都叫 `porthub-netd.service`，但使用的是不同的
单元文件。Core helper 只允许 `porthub_core` 表，Edge helper 只允许
`porthub` 表和 `wg-porthub`。

刷新 systemd：

```bash
sudo systemctl daemon-reload
```

推荐启动顺序：

```bash
# Edge
sudo systemctl enable --now porthub-netd.service
sudo systemctl enable --now porthub-edge.service

# Core
sudo systemctl enable --now porthub-netd.service
sudo systemctl enable --now porthub-core.service
```

单元已经包含网络、WireGuard 和 helper 依赖，但首次部署仍应按上述顺序
启动，方便及时观察日志。

### 7.7 第七步：部署前端

前端构建产物通过版本目录和软链接发布，不要直接覆盖正在运行的目录：

```bash
cd apps/frontend
npm ci
npm run build

RELEASE="$(date +%Y%m%d-%H%M%S)-initial"
sudo install -d -o porthub -g porthub -m 0755 \
  "/opt/porthub/frontend/releases/$RELEASE"
sudo cp -a dist/. "/opt/porthub/frontend/releases/$RELEASE/"
sudo chown -R porthub:porthub "/opt/porthub/frontend/releases/$RELEASE"
sudo chmod -R a+rX "/opt/porthub/frontend/releases/$RELEASE"
sudo ln -sfn "/opt/porthub/frontend/releases/$RELEASE" \
  /opt/porthub/frontend/current
sudo systemctl restart porthub-core.service
```

检查 Core 能读取 SPA：

```bash
sudo -u porthub test -r /opt/porthub/frontend/current/index.html
curl -k https://127.0.0.1:9443/api/health
```

`curl` 返回 Core 健康状态只说明进程存活，不代表 Edge、WireGuard、nftables
和公网入口已经可用；这些需要继续单独验证。

### 7.8 第八步：首次初始化和登录

Core 第一次创建数据库时会自动生成：

- 用户名为 `admin` 的超级管理员；
- 随机初始密码；
- 随机 TOTP Secret；
- `/var/lib/porthub/core/initial-admin.txt` 初始化文件。

该文件只用于首次取出初始化凭据，权限应保持 `0600`。登录后立即：

1. 修改初始密码；
2. 将 TOTP Secret 导入 Google Authenticator 或其他验证器；
3. 验证当前时间同步正常；
4. 创建日常使用的管理员/运维/只读账号；
5. 确认可信设备只在自己的浏览器启用；
6. 将初始化凭据放进密码管理器后删除初始化文件。

不要使用 SSH root 密码作为 PortHub 面板密码，也不要把 TOTP Secret 写进
README、Issue、截图或日志。

### 7.9 第九步：注册 Agent

在 Core 面板进入节点管理，创建一次性 Agent 注册凭据。然后在 Agent 主机：

1. 安装 Core CA 到 `server_ca_file` 指定路径；
2. 把一次性凭据写入 `enrollment_token_file`，权限设为 `0600`；
3. 复制 `deploy/porthub-agent.config.json`；
4. 修改唯一的 `node_id` 和 `core_url`；
5. 填写 Core Ed25519 公钥和证书路径；
6. 安装 `deploy/porthub-agent.service`；
7. 启动后确认一次性 token 被删除、Agent 证书已生成且心跳在线。

Linux Agent 示例配置：

```json
{
  "node_id": "lab-linux-01",
  "core_url": "https://<CORE_HOST>:9443",
  "listen": "127.0.0.1:9731",
  "server_ca_file": "/etc/porthub/agent/core-ca.crt",
  "certificate_file": "/var/lib/porthub/agent/agent.crt",
  "private_key_file": "/var/lib/porthub/agent/agent.key",
  "enrollment_token_file": "/etc/porthub/agent/enrollment.token",
  "heartbeat_seconds": 30,
  "task_public_key": "<CORE_ED25519_PUBLIC_KEY_BASE64>",
  "task_allowlist": ["wireguard_status", "service_probe", "tcp_probe", "http_probe", "docker_list"]
}
```

Windows Agent 的安装脚本位于 `deploy/windows/`。Windows Agent 使用相同的
注册和 mTLS 协议，不提供任意命令执行。

### 7.10 第十步：创建第一条映射

建议使用以下流程，不要直接把新规则设为公网启用：

1. 在“资源与服务”执行常规扫描或深度扫描；
2. 检查扫描到的 IP、端口、服务分类和风险等级；
3. 从资源或模板生成一条“禁用”状态的映射草稿；
4. 选择 Edge、协议、公网端口、目标节点和目标端口；
5. 执行冲突检测，确认同一 Edge/公网 IP/协议/端口没有重复监听；
6. 在 nft 预览中检查 DNAT、ACL、SNAT 和回程路径；
7. 先保存禁用规则，再使用批量启用或单条启用；
8. 点击下发，Core 会签名、预检、通过 mTLS 发给 Edge；
9. 检查健康状态和计数器后，再从外部网络进行 TCP/UDP 测试。

兼容模式会在 Core 侧做受控 SNAT，稳定性较高但会隐藏原始公网源 IP。保留
源 IP 模式需要局域网额外回程路由，不能为了它修改整个 LAN 默认网关。

SSH、RDP、SMB、数据库等高风险服务应默认禁用，并优先使用 IP 白名单或
WireGuard 私网访问。

## 八、部署验证

### 8.1 服务状态

在对应主机检查：

```bash
systemctl is-active porthub-core.service
systemctl is-active porthub-edge.service
systemctl is-active porthub-netd.service
systemctl is-active wg-quick@wg-porthub.service
```

查看最近日志：

```bash
journalctl -u porthub-core.service -n 100 --no-pager
journalctl -u porthub-edge.service -n 100 --no-pager
journalctl -u porthub-netd.service -n 100 --no-pager
```

### 8.2 WireGuard 和 nftables

```bash
sudo wg show wg-porthub
sudo nft list table inet porthub
sudo nft list table inet porthub_core
```

只检查 PortHub 自有表。不要使用 `nft list ruleset` 后直接重放，也不要用
flush 命令“修复”规则。

### 8.3 外部连通性

从不在同一 LAN 的测试网络验证：

- TCP 单端口；
- UDP 单端口；
- 连续端口段；
- HTTP Host/Path；
- WebSocket；
- 禁用映射是否立即停止新连接；
- Core 停止后 Edge 最后快照是否继续工作。

如果本机监听正常但公网不可达，按顺序检查云安全组、上游路由、运营商
IPv4/IPv6 入站能力和 Edge 计数器。不要声称已修改云安全组，除非确实访问
并修改了云厂商控制台。

## 九、备份、回滚和卸载

### 9.1 Core 备份

Core API 可以创建受保护的备份，内容只包括 PortHub Core 数据库和 PortHub
自有密钥/证书文件。备份目录建议保持 `0600`，不得上传 GitHub 或第三方网盘。

恢复前先做 dry-run：

```bash
/opt/porthub/bin/porthub-core-restore \
  --backup core-YYYYMMDD-HHMMSS.tar.gz
```

确认维护窗口和备份来源后才执行：

```bash
/opt/porthub/bin/porthub-core-restore \
  --execute --backup core-YYYYMMDD-HHMMSS.tar.gz
```

恢复 helper 只停止和启动 `porthub-core.service`，不重启整机网络、不操作
旧 WireGuard、不修改其他数据库。

### 9.2 配置回滚

优先在 Core 的快照历史中回滚。Core 会把历史内容重新签名为新版本，重新做
nft 语法、端口冲突和健康检查，然后下发到 Edge。Edge 自身保存最后有效快照，
Core 离线时不会自动清空已经生效的规则。

### 9.3 卸载

先预览卸载范围：

```bash
/opt/porthub/bin/porthub-uninstall
```

确认输出只包含 PortHub 资源后才执行：

```bash
/opt/porthub/bin/porthub-uninstall --execute
```

卸载脚本只针对 PortHub 自有 systemd 服务、目录、`wg-porthub`、
`table inet porthub`、`table inet porthub_core` 和 PortHub sysctl 文件。
它不应删除其他 WireGuard、代理、Docker、SSH、宝塔站点或防火墙表。

## 十、安全边界

- Edge 只接受 Core 的 mTLS 请求和 Ed25519 签名快照；
- 时间戳、nonce 和已使用 nonce 持久化用于防重放；
- Core/Edge Web 进程不以 root 运行；
- `porthub-netd` 只接受严格结构化请求、固定表名和固定接口；
- Agent 只校验白名单任务，默认不执行 Shell；
- API Token 只存哈希，原值只在创建时返回一次；
- TOTP、密码、私钥、证书私钥和 DNS 凭据不出现在普通列表接口；
- 公网来源审计只保存连接摘要，不抓包、不记录业务数据包内容；
- 只读用户看到的公网 IP 会按权限脱敏；
- DDNS、证书、Webhook 和更新任务都需要显式操作并记录审计；
- 公开仓库不包含任何生产配置或凭据。

详细说明见：

- [架构设计](docs/architecture.md)
- [安全设计](docs/security-design.md)
- [API 清单](docs/api.md)
- [部署说明](docs/deployment.md)
- [环境审计模板](docs/environment-audit.md)
- [备份与恢复](docs/backup-restore.md)
- [回滚](docs/rollback.md)
- [卸载](docs/uninstall.md)
- [升级](docs/upgrade.md)
- [测试报告模板](docs/test-report.md)
- [公开发布脱敏说明](docs/public-release.md)

## 十一、已知限制

1. 示例 systemd 单元中的地址必须人工替换，仓库不提供一键生产安装器；
2. 云厂商安全组、家庭宽带入站能力和 DNS 解析不由 PortHub 自动保证；
3. Edge 只保留轻量实时状态和最近事件，长期指标在 Core；
4. Agent 任务目前以签名校验和白名单为主，不提供任意命令执行；
5. AI 助手只生成禁用草稿，不能绕过冲突检测、预览和人工确认；
6. 保留源 IP 需要外部回程路由，不能作为默认模式；
7. Edge 直接回滚接口不替代 Core 快照回滚，正式回滚应从 Core 发起；
8. ACME DNS-01 需要提前配置受保护的 DNS Provider Secret 引用；
9. 公开部署前仍应针对目标 Linux 发行版执行完整的系统级验收。

## 十二、贡献和公开发布要求

提交代码前请执行：

```bash
go test ./...
make build
cd apps/frontend && npm run build
```

提交前检查：

- 没有真实 IP、域名、机器 ID、内部主机名和云资源标识；
- 没有密码、TOTP Secret、API Token、SSH 凭据、WireGuard 私钥或证书私钥；
- 没有数据库、日志、备份、原始审计文件和真实 `.env`；
- 没有把生产 Git 历史直接推送到公开仓库；
- 新增配置使用环境变量、外部文件或明确占位符；
- 文档明确区分“已测试”“示例”“需要现场验证”的内容。

PortHub 的公开仓库地址：

[https://github.com/Milk-lpy/porthub](https://github.com/Milk-lpy/porthub)
