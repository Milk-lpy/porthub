export type PageHelp = {
  title: string
  summary: string
  steps: string[]
  terms: Array<{ term: string; meaning: string }>
  caution?: string
}

const help: Record<string, PageHelp> = {
  '/': {
    title: '运行总览', summary: '先看节点和隧道是否正常，再观察流量与告警。',
    steps: ['确认 Edge、Core 和 WireGuard 都显示在线。', '查看上传、下载和连接数是否符合平时水平。', '有黄色或红色告警时，点击对应模块查看详情。'],
    terms: [{ term: 'Edge', meaning: '公网入口服务器，负责接收和转发公网流量。' }, { term: 'Core', meaning: '控制中心，保存配置、账号和历史数据。' }, { term: '连接跟踪', meaning: 'Linux 记录当前网络连接状态的机制。' }],
  },
  '/nodes': {
    title: '节点管理', summary: '查看每台服务器的在线情况，并生成新 Agent 的一次性接入凭据。',
    steps: ['先确认节点最后上报时间。', '新增设备时创建短时有效的接入凭据。', '在目标设备安装 Agent 后回到本页确认上线。'],
    terms: [{ term: 'Agent', meaning: '安装在受管设备上的轻量采集程序。' }, { term: '心跳', meaning: '设备定时上报“我还在线”和资源状态。' }, { term: '接入凭据', meaning: '仅用于首次注册、会自动过期的一次性凭据。' }],
  },
  '/wireguard': {
    title: 'WireGuard 隧道', summary: '管理 PortHub 自己的加密隧道节点，不会修改原有 WireGuard。',
    steps: ['新增 Peer 并填写它的公钥。', '使用自动分配的隧道地址，通常无需修改高级项。', '保存草稿后检查列表，再点击下发配置。'],
    terms: [{ term: 'Peer', meaning: '通过 WireGuard 接入的另一台设备。' }, { term: 'AllowedIPs', meaning: '允许通过该节点到达的地址范围。' }, { term: 'PersistentKeepalive', meaning: '让 NAT 后面的设备定期保持隧道可达。' }],
    caution: '不要粘贴 WireGuard 私钥；本页只需要公钥。',
  },
  '/inventory': {
    title: '资源与服务', summary: '把内网设备、监听端口和容器整理成可复用对象。',
    steps: ['从自动发现列表导入容器或监听服务。', '为对象补充容易识别的名称和说明。', '发布入口时直接选择这些对象，减少重复填写。'],
    terms: [{ term: '资源', meaning: 'NAS、主机、容器等实际设备或工作负载。' }, { term: '服务', meaning: '资源上可访问的应用和端口。' }, { term: '映射组', meaning: '需要一起启停的一组端口规则。' }],
  },
  '/publish': {
    title: '快速发布', summary: '使用模板把常见服务转换成默认禁用的映射草稿。',
    steps: ['选择与应用最接近的模板。', '填写目标内网 IP，并查看风险提示。', '创建草稿后到端口映射页检查，再启用和下发。'],
    terms: [{ term: '模板', meaning: '预先整理好的常用端口组合。' }, { term: '目标 IP', meaning: '局域网中实际运行服务的设备地址。' }, { term: '草稿', meaning: '已经保存但尚未对公网生效的规则。' }],
  },
  '/mappings': {
    title: '端口映射', summary: '决定公网端口的流量要转发到哪台内网设备。',
    steps: ['新增规则并选择 TCP、UDP 或两者。', '先运行冲突检查并预览规则差异。', '确认目标正确后启用规则，再下发到 Edge。'],
    terms: [{ term: '公网端口', meaning: '外部用户连接 VPS 时使用的端口。' }, { term: '目标端口', meaning: '内网应用实际监听的端口。' }, { term: 'DNAT', meaning: '把公网访问地址改写为内网目标地址的转发技术。' }],
    caution: 'SSH、RDP、数据库等管理端口应优先通过 WireGuard 访问，或至少绑定 IP 白名单。',
  },
  '/proxy': {
    title: '反向代理', summary: '按域名把 HTTP、HTTPS 和 WebSocket 请求送到内网网站。',
    steps: ['填写用户访问的域名和内网后端地址。', '按需要开启 WebSocket、HTTPS 跳转或多后端。', '保存后查看健康状态，再下发配置。'],
    terms: [{ term: 'Host 路由', meaning: '根据访问域名选择后端服务。' }, { term: 'WebSocket', meaning: '网页与服务器保持双向长连接的协议。' }, { term: '健康检查', meaning: '定期探测后端是否还能正常响应。' }],
  },
  '/domains': {
    title: '域名与 DDNS', summary: '维护域名解析，并在公网 IP 改变时自动更新记录。',
    steps: ['先添加 DNS 服务商，并把密钥保存在服务器密钥文件中。', '新增域名记录并选择地址来源。', '先预检查，再手动同步；稳定后开启定时同步。'],
    terms: [{ term: 'DDNS', meaning: '公网 IP 变化后自动更新域名解析。' }, { term: 'TTL', meaning: 'DNS 结果在客户端缓存的秒数。' }, { term: 'Provider', meaning: 'Cloudflare、阿里云或腾讯云等 DNS 服务商。' }],
  },
  '/certificates': {
    title: 'TLS 证书', summary: '管理 HTTPS 证书状态、导入和部署。',
    steps: ['先创建证书记录并填写完整域名。', '查看申请计划和阻断项。', '申请完成或手工导入后，再部署到对应代理。'],
    terms: [{ term: 'TLS', meaning: '为 HTTPS 提供加密和网站身份验证。' }, { term: 'ACME', meaning: '自动申请和续期证书的标准协议。' }, { term: 'DNS-01', meaning: '通过 DNS 验证域名所有权的方式。' }],
    caution: '证书私钥属于高敏感数据，不要放入备注、日志或聊天内容。',
  },
  '/ip-sets': {
    title: 'IP 集合', summary: '把一组 IP 网段整理为轻量白名单或黑名单。',
    steps: ['少量地址可直接新建集合。', '大量 GeoIP/ASN 数据使用自动数据源，并先预检查。', '同步成功后在 ACL 规则中引用，再下发配置。'],
    terms: [{ term: 'CIDR', meaning: '表示一个 IP 网段的写法，例如 192.0.2.0/24。' }, { term: 'ASN', meaning: '网络运营组织在互联网中的自治系统编号。' }, { term: 'GeoIP', meaning: '按国家或地区整理的 IP 地址范围。' }],
  },
  '/security': {
    title: 'ACL 安全', summary: '限制哪些来源、协议和时间可以访问已发布服务。',
    steps: ['优先创建允许访问的来源网段。', '按服务选择协议、端口和生效时间。', '保存后预览快照，确认没有锁住必要访问再下发。'],
    terms: [{ term: 'ACL', meaning: '访问控制列表，用规则决定允许或拒绝连接。' }, { term: '白名单', meaning: '只有列表中的来源可以访问。' }, { term: '限速', meaning: '限制单位时间可传输的数据量。' }],
  },
  '/traffic': {
    title: '流量统计', summary: '查看实时速度、当前连接、规则排行和历史告警。',
    steps: ['先看实时连接是否持续更新。', '用规则排行找出流量较大的公网入口。', '异常连接可结合 ACL 和审计记录进一步处理。'],
    terms: [{ term: 'bps', meaning: '每秒传输的字节数，这里用于显示实时速度。' }, { term: 'conntrack', meaning: 'Linux 内核维护的网络连接状态表。' }, { term: '采样', meaning: '按固定时间保存一次汇总数据，不包含业务包内容。' }],
  },
  '/audit': {
    title: '审计日志', summary: '追踪谁在什么时间执行了什么操作、影响了什么对象，以及操作是否成功。',
    steps: ['先看顶部统计和颜色，快速判断有没有失败或高风险事件。', '用关键词、操作者、类别、结果和时间范围组合筛选；按回车或点击“筛选”加载结果。', '点击一条记录打开详情，必要时把配置下发、快照和审计时间对照起来，再决定是否回滚。'],
    terms: [{ term: '审计', meaning: '记录管理操作，便于追踪和问责。' }, { term: '操作者', meaning: '执行操作的用户、API Token 或系统任务。' }, { term: '风险级别', meaning: '普通、需关注和高风险，用于帮助你先处理重要事件。' }, { term: '原始详情', meaning: '后端写入的完整附加信息，通常包含名称、编号、版本或失败原因。' }],
    caution: '审计日志只记录管理元数据，不记录网络业务包内容；公网来源 IP 审计在“流量统计”页面单独查看。',
  },
  '/snapshots': {
    title: '配置快照', summary: '查看每次下发的不可变版本，并回滚到曾经成功的规则。',
    steps: ['先确认当前生效版本。', '需要恢复时选择状态为“已应用”的旧版本。', '查看来源版本并确认回滚，系统会生成一个新的签名快照。'],
    terms: [{ term: '快照', meaning: '某一时刻的完整配置副本。' }, { term: 'SHA-256', meaning: '用于确认配置内容没有被改变的摘要。' }, { term: '回滚', meaning: '重新应用过去已验证成功的配置。' }],
  },
  '/assistant': {
    title: '命令助手', summary: '用自然语言生成结构化映射草稿，所有解析都在 Core 本机完成。',
    steps: ['描述目标 IP、端口和协议。', '检查助手列出的阻断项与风险提示。', '确认后保存为禁用草稿，再到映射页审核和下发。'],
    terms: [{ term: '结构化意图', meaning: '把一句话转换为系统能验证的字段。' }, { term: '本地解析', meaning: '内容不发送到外部 AI 服务。' }],
  },
  '/qx-services': {
    title: '本机服务', summary: '统一查看和管理 DST 网络组件与 QX 局域网工具。',
    steps: ['先看顶部 DST 隧道是否在线、最近是否有握手。', '再确认各服务显示“运行中”或“已生效”，并检查监听端口。', '只有故障排查时才重启；停止隧道前先确认当前没有设备正在使用。'],
    terms: [{ term: 'Peer', meaning: '连接到 WireGuard 隧道的另一端设备。' }, { term: '握手', meaning: 'WireGuard 两端最近一次成功确认加密连接的时间。' }, { term: 'SOCKS5', meaning: 'QX 通过它把网络请求交给局域网代理服务器。' }, { term: '配置分发', meaning: '通过局域网 HTTP 地址向设备提供 QX 配置文件。' }, { term: '开机自启', meaning: '服务器重启后，系统会自动启动该服务。' }, { term: 'PID', meaning: '当前服务进程的编号；一次性系统策略可能没有持续 PID。' }],
    caution: '重启或停止 DST 隧道会短暂中断相关游戏连接；停止 SOCKS5 会中断正在使用它的设备。',
  },
  '/tokens': {
    title: 'API Token', summary: '为自动化程序创建可撤销、权限受限的访问凭据。',
    steps: ['按自动化任务选择最低够用的角色。', '创建后立即保存一次性显示的完整 Token。', '定期查看最后使用时间并撤销闲置凭据。'],
    terms: [{ term: 'Token', meaning: '程序调用 API 时使用的访问凭据。' }, { term: 'RBAC', meaning: '按角色限制不同操作权限。' }],
    caution: 'Token 等同密码，不要提交到 Git、脚本正文或日志。',
  },
  '/webhooks': {
    title: 'Webhook', summary: '让 PortHub 在事件发生时通知其他系统。',
    steps: ['填写接收通知的 HTTPS 地址。', '选择需要发送的事件并保存。', '在接收端验证签名，避免伪造通知。'],
    terms: [{ term: 'Webhook', meaning: '事件发生时由系统主动发出的 HTTP 通知。' }, { term: 'HMAC', meaning: '使用共享密钥验证消息来源和完整性。' }],
  },
  '/users': {
    title: '用户与角色', summary: '为不同人员分配独立账号和最小权限。',
    steps: ['新建账号并选择最低够用的角色。', '让用户首次登录时修改临时密码并绑定 TOTP。', '人员离开时删除账号，并检查相关 Token。'],
    terms: [{ term: 'TOTP', meaning: '验证器应用每 30 秒生成的一次性验证码。' }, { term: '最小权限', meaning: '只授予完成工作所必需的权限。' }],
  },
  '/backups': {
    title: '备份恢复', summary: '创建 Core 数据备份，并在恢复前生成只读计划。',
    steps: ['在重要变更前创建备份。', '选择备份并查看恢复计划。', '实际恢复会停止 Core，应在维护窗口由管理员执行。'],
    terms: [{ term: 'WAL', meaning: 'SQLite 用于保证写入可靠性的预写日志。' }, { term: '维护窗口', meaning: '允许服务短暂停止的预定时间段。' }],
  },
  '/updates': {
    title: '升级管理', summary: '从可信更新源检查并暂存经过签名验证的版本。',
    steps: ['先点击检查更新并阅读发布说明。', '分别暂存 Core 或 Agent 安装包。', '确认备份和维护窗口后，再由受限安装程序应用。'],
    terms: [{ term: 'Ed25519', meaning: '用于确认更新来自可信发布者的数字签名算法。' }, { term: '暂存', meaning: '完成下载和校验，但不重启或替换当前程序。' }],
  },
}

export function helpFor(path: string) {
  return help[path] || help['/']
}
