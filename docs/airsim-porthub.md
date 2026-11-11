# AirSIM × PortHub：本地 Relay、VPS Edge HTTPS/WSS、公网来电

> 本文是 PortHub 的非侵入式集成指南。AirSIM 属于第三方 **PolyForm Noncommercial 1.0.0** 源码可见项目，不应把其源代码当作可自由商业再分发的 MIT/Apache 代码。本仓库不捆绑 AirSIM 二进制、不存储 APNs 凭据、短信或 PCM 数据。

## 目标架构

```text
iPhone / iOS AirSIM
  | 互联网 HTTPS + WSS       (锁屏 PushKit 经 Apple APNs)
  v
VPS: PortHub Edge 原有 HTTPS Host 入口（已有 443 或现有前置 TLS）
  | 原有 wg-porthub / 已有 VPN，不新增隧道
  v
本地服务器 VPN IP:18787（仅 Edge 可访问的 TCP socket-proxyd）
  | 转发到 127.0.0.1:8787
  v
AirSIM ECS Relay (workerd + SQLite，127.0.0.1:8787)
  + APNs Adapter (127.0.0.1:8790)
  + Maintenance (127.0.0.1:8789，不暴露)

安卓手机 Root + Shizuku + AirSIM Standalone
  |-- 连接同一 AirSIM Relay 处理推送/云端通信
  \-- 可选 iPhone -> VPN -> VoWLAN 直连控制和 PCM
```

AirSIM Relay 与 PortHub 自身 `apps/relay` **不是同一个产品**：二者名称接近，但不能相互替换。

## 0. 只读预检、隔离与备份

- 不改现有 Lucky、QX、旧 WireGuard、nftables 或 PortHub 数据库；尤其不能清空 iptables/nftables。
- 查看本地已有监听 `sudo ss -lntp`、`ip -br address` 和 `wg show`，确定可用的 VPN IP、18787 端口、Edge 的公网 HTTPS 入口和证书。
- 本地 Relay 所需监听默认绑定 `127.0.0.1:8787`、`127.0.0.1:8789`、`127.0.0.1:8790`，不要将它们映射到公网；在部署前确认无冲突。
- 提前保存 PortHub Edge/Core 的代理快照、目标主机本地服务配置及 AirSIM 状态的离线备份；执行变更前审核差异。
- 本地服务器若不是 PortHub Core 主机，需单独核对路由与访问白名单；不要照抄示例地址。
- 不依赖 root 运行 PortHub Web API 执行任意 shell 命令。

## 1. 本地 Linux 安装 AirSIM ECS Relay

上游教程：<https://github.com/kai-wu-cortex/AirSIM/blob/main/push-relay-worker/self-hosted/README.md>

按官方发布的 Linux x64 Node/workerd 和 `install-ecs.sh` 的完整校验与离线 staging 步骤安装，不要直接在线 curl | bash 或在 PortHub repo 内复制上游运行时代码。AirSIM 自带 systemd 服务：

- `airsim-relay.service`：本机 `127.0.0.1:8787`
- `airsim-apns.service`：本机 `127.0.0.1:8790`
- `airsim-relay-prune.timer`：维护与清理

`/etc/airsim-relay/config.json` 放置 APNs Key ID、Team ID、**服务端 APNs P8 私钥**和独立 Dashboard Token；仅 root/独立服务账户有权读取，禁止加入 Git/PortHub Core 数据库或 PortHub 日志。用户持有的 iOS IPA 签名 `.p12` **不等于** APNs 服务端密钥。没有可用的 Apple Developer APNs 凭据时只部署和测试前台 VoWLAN，不能声称锁屏 PushKit 可用。

健康检查：

```sh
systemctl status airsim-relay airsim-apns --no-pager
curl --fail --max-time 3 http://127.0.0.1:8787/healthz
```

仅表示 HTTP Relay 响应，并非来电/短信的端到端通过。

## 2. 使用已有 VPN 暴露一个**仅供 Edge 使用**的 TCP 入口

上游 workerd 默认绑定 loopback，因此 VPS 不能直接访问本机 `127.0.0.1:8787`。建议使用 systemd 自带 socket-proxyd 转发 TCP（可传递 WebSocket Upgrade 和二进制帧），不必再装一套 VPS Nginx。仓库的两个示例模板：

- `deploy/porthub-airsim-bridge.socket.example`
- `deploy/porthub-airsim-bridge.service.example`

审核并替换模板中的 **文档示例** `10.255.0.2`（实际 Core VPN IP）、`18787`（空闲端口）及 `systemd-socket-proxyd` 可执行路径。**不要直接启用原样示例。**

```sh
# 仅查看路径，勿改动现有 PortHub 服务
command -v systemd-socket-proxyd || ls /usr/lib/systemd/systemd-socket-proxyd /lib/systemd/systemd-socket-proxyd
# 编辑模板后另存为 /etc/systemd/system/porthub-airsim-bridge.socket/.service
sudo systemd-analyze verify /etc/systemd/system/porthub-airsim-bridge.{socket,service}
sudo systemctl daemon-reload
sudo systemctl enable --now porthub-airsim-bridge.socket
sudo ss -lntp | grep 18787
```

仅允许 **VPS Edge 的 WireGuard 源地址**连接此端口，可使用现有 PortHub 专属 ACL/安全策略；不要用开放的 `0.0.0.0:18787` 监听替代。注意 TCP 入口的健康检查 `/healthz` 仍由 Relay 提供，不会代理 APNs 适配器和维护端口。

在 Edge 主机上验证（示例 IP 必须替换）：

```sh
curl --fail --max-time 4 http://10.255.0.2:18787/healthz
```

## 3. 从 PortHub 面板发布反向代理（人工二次确认）

升级后的面板包含「系统 → AirSIM 通信」：

1. **检测 Relay**：Core 后端只读请求 `GET /api/integrations/airsim`，默认只检查 `http://127.0.0.1:8787/healthz`。Relay 若与 Core 不在同一主机，可在 PortHub Core systemd 环境中设置：
   `AIRSIM_RELAY_HEALTH_URL=http://<受信任私网IP>:<端口>/healthz`。只接受私网 IP、Tailscale 100.64.0.0/10 或 localhost，不跟随重定向，不会访问 APNs 密钥。
2. **创建代理草稿**：输入拟使用的 **专用子域名** 和 `http://<Core VPN IP>:18787`；程序生成 **默认禁用** 的 PortHub HTTP 代理记录，并启用 WebSocket、保留 Host、根路径与 `/healthz` 检查。此步骤不会自动下发。
3. 检查专用子域名的 DNS、HTTPS 证书、443 入口以及已有反代/端口占用。PortHub Edge 示例默认 HTTPS 监听 **18443**，若外部需要标准 443，必须经实际已配置的公网 HTTPS 入口转接，不能假设 443 已被 PortHub 接管。
4. 查看配置快照差异和路由冲突，人工启用代理并签名下发。回滚时只撤销这条 AirSIM Host 代理及专用 socket，无须停机/删改已有 wg-porthub、Lucky、QX 规则。
5. 外网验证 `https://<自有子域名>/healthz`；单独验证 WSS 双向二进制音频，**不能用 healthz 替代 WebSocket 验收**。

PortHub 的 Edge HTTP 代理复用 Go `httputil.ReverseProxy`，可转发 WebSocket。公开 Relay 的鉴权仍由 AirSIM 自己承担，必须按其官方安全文档设置 Dashboard Token 和设备鉴权，不要允许匿名访问管理数据；避免把 Query/媒体 Token 记入代理访问日志。

## 4. Android/iOS 与 APNs

- Android：官方 AirSIM Standalone APK + Shizuku + 电话与短信角色，Root 只是额外适配能力，不代表任何机型都能实现通话上下行 PCM。
- iOS：使用拥有正确 Bundle ID 与 provisioning profile 的 AirSIM 自签版。主 App、通知扩展与 Live Activity 的签名需要分别核对。
- Relay 允许的 App ID 和 iOS 的 Bundle ID、APNs Key ID / Team ID、`aps-environment` 必须匹配。仅有 iOS 分发证书 P12 不能签发 APNs 服务端推送。
- 首先使用 VPN 前台 VoWLAN 测试：拨号、来电、短信、两路 PCM；然后单独配置云端 Relay 与 PushKit 测试 iOS 锁屏后台来电。
- AirSIM 每通电话建立时选择本地或 Relay 传输，不保证进行中的通话能够无缝换线。若推送成功但接听无音频，要检查 CallKit 激活、音频所有权和传输锁定。
- iPhone 原生「信息」App 不会被 AirSIM 自动填入安卓短信。

## 5. 分层验收与回滚

| 层级 | 检查 | 成功不代表什么 |
|---|---|---|
| 本地 Relay | `127.0.0.1:8787/healthz` | APNs 或安卓在线 |
| VPN 路径 | VPS Edge -> 本地桥 `/healthz` | WSS 媒体成功 |
| 公网入口 | HTTPS 子域名 `/healthz` | 可收到锁屏来电 |
| Android + iOS | 前台短信与双向语音 | 后台冷启动可靠 |
| 后台 | APNs VoIP token、锁屏来电、双向音频 | 所有厂商及弱网必定成功 |

**回滚：** 禁用新 AirSIM Host 代理并重新下发 PortHub 快照；停用 `porthub-airsim-bridge.socket`；AirSIM 本体保持单独运行/按官方备份恢复。不可为了回滚删除 PortHub 原有隧道、规则、配置或其他服务。

安全边界：PortHub 只处理健康状态和代理草稿，不读取短信、来电号码、音频、APNs 私钥或完整 AirSIM Dashboard；第三方项目仅限个人非商业使用，生产/应急电话仍必须依赖正常蜂窝电话。
