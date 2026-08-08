# 公网来源 IP 审计

## 目的

PortHub Edge 通过受限的 conntrack 只读接口读取当前连接摘要。Core 每次流量采样时，将公网客户端来源地址、命中的映射、协议、公网端口、内网目标、状态、字节数和观察时间写入 `public_source_audits`。

系统不抓包、不记录业务内容，也不会从审计表反推出数据包内容。

## 记录规则

- 以“分钟 + 来源 IP + 映射 + 协议 + 公网端口”聚合，避免高并发时每个连接都膨胀成一行。
- 同一分钟重复观察会更新最后观察时间、状态、超时，并保留该分钟内最大的 conntrack 字节计数。
- `observations` 表示采样观察次数，不等同于真实连接总数。
- 只记录公网来源；内网、回环、链路本地、组播、未指定、RFC1918/ULA 和 `100.64.0.0/10` CGNAT 地址会被排除。
- 默认沿用流量统计的 30 天保留策略；可通过 Core 的 `-traffic-retention-days` 调整。

## 权限和脱敏

- 超级管理员、管理员、运维人员：可以查看精确来源 IP。
- 只读用户：来源 IPv4 默认显示前两段，IPv6 默认显示前四段，其余用掩码替代。
- `/api/edge/metrics`、实时 WebSocket 和 `/api/traffic/recent` 的来源字段也遵循相同掩码规则。
- API 返回 `exact_source_ip`，前端据此显示当前查看权限提示。

## 面板使用

进入“流量统计”，切换到“公网来源审计”页签：

1. 顶部卡片查看近期来源排行。
2. 输入公网来源 IP 或映射名称/ID进行筛选。
3. 选择 TCP/UDP后可缩小协议范围。
4. 点击“刷新”读取 Core 当前数据库；“保存当前样本”会立即向 Edge采样并刷新审计。
5. 表格中的“观察次数”是采样次数，“字节”是该来源/映射聚合桶记录的最大 conntrack 计数之和。

## 运维检查

```sql
select source_ip, mapping, protocol, public_port, last_seen_at, bytes, observations
from public_source_audits
order by last_seen_at desc
limit 20;
```

生产环境不要直接把 `core.db` 暴露给普通用户。恢复或迁移前按 `docs/backup-restore.md` 处理，并保留 Core 数据目录权限。
