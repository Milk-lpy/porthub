import { expect, test, type Page } from '@playwright/test'

const now = new Date().toISOString()

const fixtures: Record<string, unknown> = {
  '/api/status': { core: 'online', edge: 'online' },
  '/api/mappings': [
    { ID: 1, Name: 'NAS HTTPS', Protocol: 'tcp', PublicStart: 10443, PublicEnd: 10443, TargetIP: '192.0.2.20', TargetStart: 443, TargetEnd: 443, Enabled: true },
    { ID: 2, Name: '饥荒世界', Protocol: 'udp', PublicStart: 11001, PublicEnd: 11002, TargetIP: '192.0.2.150', TargetStart: 11001, TargetEnd: 11002, Enabled: true },
    { ID: 3, Name: '维护入口', Protocol: 'tcp', PublicStart: 22022, PublicEnd: 22022, TargetIP: '192.0.2.12', TargetStart: 22, TargetEnd: 22, Enabled: false },
  ],
  '/api/port-forwards': [
    { id: 2, name: 'openclaw · IPv4', node_id: 'local', listen_family: 'ipv4', listen_address: '0.0.0.0', listen_port_start: 18789, listen_port_end: 18789, protocol: 'both', target_family: 'ipv4', target_host: '192.0.2.150', target_port_start: 18789, target_port_end: 18789, forward_mode: 'nft', snat_mode: 'masquerade', enabled: true, last_status: 'applied' },
    { id: 3, name: 'openclaw · IPv6', node_id: 'local', listen_family: 'ipv6', listen_address: '::', listen_port_start: 18789, listen_port_end: 18789, protocol: 'both', target_family: 'ipv4', target_host: '192.0.2.150', target_port_start: 18789, target_port_end: 18789, forward_mode: 'relay', snat_mode: 'masquerade', enabled: true, last_status: 'applied' },
  ],
  '/api/port-forwards/status': { total: 2, enabled: 2, nft_rules: 1, relay_rules: 1, relay: { running: true, rules: [] }, items: [] },
  '/api/managed-services': {
    updated_at: now,
    wireguard: { interface: 'wg-dst', present: true, addresses: ['10.254.0.1/24'], listen_port: 51821, peer_count: 2, latest_handshake: Math.floor(Date.now() / 1000) - 12, rx_bytes: 493827102, tx_bytes: 193827102 },
    services: [
      { name: 'dst-wireguard', description: 'DST WireGuard', active_state: 'active', sub_state: 'exited', unit_file_state: 'enabled', main_pid: 0, started_at: now, listeners: [{ protocol: 'udp', address: '全部地址', port: 51821 }] },
      { name: 'dst-wireguard-health', description: 'DST health', active_state: 'active', sub_state: 'running', unit_file_state: 'enabled', main_pid: 1000, started_at: now, listeners: [{ protocol: 'tcp', address: '10.254.0.1', port: 18080 }] },
      { name: 'dst-wireguard-register', description: 'DST registration', active_state: 'active', sub_state: 'running', unit_file_state: 'enabled', main_pid: 1001, started_at: now, listeners: [{ protocol: 'tcp', address: '10.254.0.1', port: 18081 }, { protocol: 'tcp', address: '全部地址', port: 51822 }] },
      { name: 'prefer-real-ipv6-gateway', description: 'IPv6 gateway policy', active_state: 'active', sub_state: 'exited', unit_file_state: 'enabled', main_pid: 0, started_at: now, listeners: [] },
      { name: 'qx-lan-config-http', description: 'QX LAN config HTTP', active_state: 'active', sub_state: 'running', unit_file_state: 'enabled', main_pid: 36205, started_at: now, listeners: [{ protocol: 'tcp', address: '192.0.2.12', port: 10889 }] },
      { name: 'qx-lan-socks', description: 'QX LAN SOCKS5', active_state: 'active', sub_state: 'running', unit_file_state: 'enabled', main_pid: 14164, started_at: now, listeners: [{ protocol: 'tcp', address: '全部地址', port: 10888 }] },
    ],
  },
  '/api/edge/metrics': { packets: 184235, bytes: 938427102, rx_bytes_per_second: 34812, tx_bytes_per_second: 12941, connections: 34, cpu_percent: 2.6, memory_used_bytes: 31457280, memory_total_bytes: 2147483648, disk_used_bytes: 8589934592, disk_total_bytes: 42949672960 },
  '/api/traffic/rank?limit=8': [
    { ts: now, protocol: 'tcp', port: 10443, target: '192.0.2.20:443', packets: 38210, bytes: 493827102 },
    { ts: now, protocol: 'udp', port: 11001, target: '192.0.2.150:11001', packets: 19314, bytes: 193827102 },
  ],
  '/api/traffic/recent?limit=8': [{ ts: now, edge_version: 'v28', packets: 184235, bytes: 938427102 }],
  '/api/audit': [
    { id: 82, actor: 'boring14455', action: 'snapshot_generate', detail: '42', action_label: '生成配置快照', category: 'config', category_label: '配置下发', severity: 'info', severity_label: '普通', result: 'success', result_label: '已完成', target: '配置版本 42', summary: '生成配置快照：配置版本 42', ts: now },
    { id: 81, actor: 'boring14455', action: 'mapping_update', detail: 'NAS HTTPS', action_label: '修改映射', category: 'mapping', category_label: '映射与入口', severity: 'info', severity_label: '普通', result: 'success', result_label: '已完成', target: 'NAS HTTPS', summary: '修改映射：NAS HTTPS', ts: now },
    { id: 80, actor: 'system', action: 'lan_scan_complete', detail: 'mode=common hosts=1 open_hosts=1', action_label: '局域网扫描完成', category: 'inventory', category_label: '资源发现', severity: 'info', severity_label: '普通', result: 'success', result_label: '已完成', target: '扫描模式：common hosts=1 open_hosts=1', summary: '局域网扫描完成：扫描模式：common hosts=1 open_hosts=1', system: true, ts: now },
  ],
  '/api/http-proxies': [
    { id: 'proxy-1', name: 'NAS Web', host: 'nas.example.test', path: '/', target: 'https://192.0.2.20:443', enabled: true, force_tls: true },
    { id: 'proxy-2', name: 'Open WebUI', host: 'ai.example.test', path: '/', target: 'http://192.0.2.150:8080', enabled: true, force_tls: false },
  ],
  '/api/acl-rules': [
    { id: 'acl-home', name: '家庭公网白名单', action: 'allow', cidr: '203.0.113.0/24', enabled: true },
    { id: 'acl-block', name: '阻断扫描网段', action: 'deny', cidr: '198.51.100.0/24', enabled: true },
  ],
  '/api/domains': [],
  '/api/ddns/providers': [{ id: 4, name: '家庭 Cloudflare', type: 'cloudflare', config: { zone_id: 'zone-redacted' }, secret_ref: '/etc/porthub/secrets/cloudflare.token', enabled: true }],
  '/api/ddns/records': [],
  '/api/certificates': [{ id: 7, name: '家庭通配符', domains: ['*.example.test'], issuer: 'acme', mode: 'acme_dns_01', status: 'prepared', expires_at: '', dns_provider_id: 4, enabled: true }],
  '/api/certificates/acme/status': { email: 'admin@example.test', directory_url: 'https://acme-v02.api.letsencrypt.org/directory', ready: true },
  '/api/ip-sets': [],
  '/api/tokens': [],
  '/api/users': [],
  '/api/backups': [],
  '/api/nodes/status': [
    {
      name: 'core-linux', role: 'core', online: true, host: '192.0.2.12', os: 'Ubuntu 24.04', arch: 'amd64', load: [0.18, 0.24, 0.22],
      memory_kb: { MemTotal: 16384000, MemAvailable: 11264000 },
      disk_root_bytes: { total: 536870912000, free: 382520524800 },
      networks: [
        { name: 'enp6s18', rx_bytes: 4839275102, tx_bytes: 1839275102 },
        { name: 'wg-porthub', rx_bytes: 342927102, tx_bytes: 923827102 },
      ],
    },
    {
      name: 'edge-primary', role: 'edge', online: true, host: '203.0.113.10', os: 'Ubuntu 24.04', arch: 'amd64', load: [0.06, 0.08, 0.09],
      memory_kb: { MemTotal: 2097152, MemAvailable: 1740800 },
      disk_root_bytes: { total: 42949672960, free: 31138512896 },
      networks: [{ name: 'eth0', rx_bytes: 123839275102, tx_bytes: 98392751021 }],
    },
    {
      name: 'nas-agent', role: 'agent', online: true, host: '192.0.2.20', os: 'Linux NAS', arch: 'amd64', load: [0.42, 0.36, 0.31],
      memory_kb: { MemTotal: 33554432, MemAvailable: 23068672 },
      disk_root_bytes: { total: 1099511627776, free: 612032839680 },
      networks: [{ name: 'bond0', rx_bytes: 283839275102, tx_bytes: 188392751021 }],
    },
  ],
  '/api/nodes/discovery': { platform: 'pve', containers: [{ id: 'abc123', name: 'media-server', image: 'jellyfin/jellyfin:latest', state: 'running', status: 'Up 2 days', ports: [{ private_port: 8096, public_port: 8096, protocol: 'tcp' }] }], listeners: [
    { protocol: 'tcp', address: '0.0.0.0', port: 9443 },
    { protocol: 'tcp', address: '127.0.0.1', port: 9731 },
    { protocol: 'udp', address: '0.0.0.0', port: 51830 },
    { protocol: 'udp', address: '192.0.2.12', port: 11001 },
  ] },
  '/api/lan-scan': { status: 'completed', mode: 'common', progress: 9652, total: 9652, hosts: [{ ip: '192.0.2.20', reachable: true, classification: 'NAS', ports: [{ port: 5001, service: 'NAS HTTPS', category: 'NAS', risk: '中', protocol: 'tcp', suggested_name: 'NAS 管理 HTTPS' }, { port: 22, service: 'SSH', category: '远程管理', risk: '高', protocol: 'tcp', suggested_name: 'SSH 远程管理' }] }] },
  '/api/resources': [{ id: 1, name: '家庭 NAS', description: '存储与媒体服务', data: '{"ip":"192.0.2.20"}', enabled: true }],
  '/api/services': [{ id: 2, name: 'NAS HTTPS', description: 'DSM 管理入口', data: '{"port":443}', enabled: true }],
  '/api/groups': [{ id: 3, name: '饥荒服务器', description: 'Master 与 Caves', data: '{"ports":[11001,11002]}', enabled: true }],
  '/api/webhooks': [],
  '/api/templates/builtin': [
    { id: 'minecraft', name: 'Minecraft Java', description: 'Java 版游戏服务器', category: 'game', high_risk: false, ports: [{ name: 'Game', protocol: 'tcp', public_port: 25565, target_port: 25565 }] },
    { id: 'dst', name: '饥荒联机版', description: 'Master 与 Caves 世界', category: 'game', high_risk: false, ports: [{ name: 'Master', protocol: 'udp', public_port: 11001, target_port: 11001 }, { name: 'Caves', protocol: 'udp', public_port: 11002, target_port: 11002 }] },
    { id: 'nas-web', name: 'NAS Web', description: 'NAS 管理与文件入口', category: 'nas', high_risk: false, ports: [{ name: 'HTTPS', protocol: 'tcp', public_port: 10443, target_port: 443 }] },
    { id: 'remote', name: '远程管理', description: 'SSH 与 RDP 管理入口', category: 'remote admin', high_risk: true, warning: '建议绑定来源白名单', ports: [{ name: 'SSH', protocol: 'tcp', public_port: 22022, target_port: 22 }] },
  ],
  '/api/wireguard/peers': [],
  '/api/wireguard/status': { interface: 'wg-porthub', listen_port: 51830, protected_peers: 1, managed_peers: 0, peers: [] },
  '/api/alerts?limit=20': [],
  '/api/ip-feeds': [],
  '/api/updates/status': { enabled: true, current_version: '0.4.0', staged_version: '0.5.0', staged_component: 'core', staged_path: '/var/lib/porthub/updates/0.5.0/core' },
  '/api/snapshots?limit=50': [],
}

async function mockAPI(page: Page) {
  let signedIn = false
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url())
    if (url.pathname === '/api/login') {
      signedIn = true
      await route.fulfill({ json: { ok: true, csrf: 'visual-test-csrf', role: 'super_admin' } })
      return
    }
    if (url.pathname === '/api/session') {
      if (!signedIn) await route.fulfill({ status: 401, body: 'unauthorized' })
      else await route.fulfill({ json: { ok: true, csrf: 'visual-test-csrf', role: 'super_admin' } })
      return
    }
    if (url.pathname === '/api/traffic/trend') {
      const values = Array.from({ length: 12 }, (_, index) => ({
        ts: new Date(Date.now() - (11 - index) * 300000).toISOString(),
        protocol: 'tcp',
        port: 10443,
        target: '192.0.2.20:443',
        packets: 2000 + index * 140,
        bytes: 12000000 + index * 2300000,
      }))
      await route.fulfill({ json: values })
      return
    }
    const key = `${url.pathname}${url.search}`
    await route.fulfill({ json: fixtures[key] ?? fixtures[url.pathname] ?? [] })
  })
}

async function signIn(page: Page) {
  await page.goto('/')
  await page.getByPlaceholder('输入密码').fill('visual-test-password')
  await page.getByPlaceholder('可信设备可留空').fill('123456')
  await page.getByRole('button', { name: '进入控制台' }).click()
  await expect(page.getByText('公网入口链路运行正常')).toBeVisible()
  const closeToast = page.locator('.global-notice .n-base-close')
  if (await closeToast.isVisible()) await closeToast.click()
}

test.beforeEach(async ({ page }) => {
  await mockAPI(page)
})

test('desktop dashboard has stable layout', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'desktop-only assertion')
  await page.goto('/')
  await expect(page.getByRole('heading', { name: '登录管理面板' })).toBeVisible()
  await page.screenshot({ path: '/tmp/porthub-login-desktop.png', fullPage: true })
  await signIn(page)
  await expect(page.getByRole('heading', { name: '入口链路', exact: true })).toBeVisible()
  await page.screenshot({ path: '/tmp/porthub-dashboard-desktop.png', fullPage: true })
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  expect(overflow).toBeLessThanOrEqual(1)
})

test('mobile navigation and mapping page fit the viewport', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'mobile', 'mobile-only assertion')
  await signIn(page)
  await page.getByRole('button', { name: '打开导航' }).click()
  await expect(page.getByRole('navigation', { name: '主导航' })).toBeVisible()
  await page.getByRole('link', { name: '端口映射' }).click()
  await expect(page.getByRole('heading', { name: 'TCP / UDP 映射' })).toBeVisible()
  await page.waitForTimeout(250)
  await page.screenshot({ path: '/tmp/porthub-mappings-mobile.png', fullPage: true })
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  expect(overflow).toBeLessThanOrEqual(1)
})

test('desktop secondary pages present operational data', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'desktop-only assertion')
  await signIn(page)
  await page.getByRole('link', { name: '节点管理' }).click()
  await expect(page.getByRole('heading', { name: '节点运行中心' })).toBeVisible()
  await expect(page.getByText('nas-agent')).toBeVisible()
  await page.waitForTimeout(220)
  await page.screenshot({ path: '/tmp/porthub-nodes-desktop.png', fullPage: true })

  const destinations = [
    ['资源与服务', '内网资源'],
    ['快速发布', '发布入口'],
    ['反向代理', 'HTTP / HTTPS 代理'],
    ['ACL 安全', 'ACL 安全'],
  ]
  for (const [link, heading] of destinations) {
    await page.getByRole('link', { name: link }).click()
    await expect(page.getByRole('heading', { name: heading })).toBeVisible()
    if (link === '资源与服务') {
      await expect(page.getByText('局域网自动扫描')).toBeVisible()
      await expect(page.getByText('NAS', { exact: true }).first()).toBeVisible()
      await expect(page.getByRole('button', { name: '开始扫描' })).toBeVisible()
      await page.screenshot({ path: `/tmp/porthub-inventory-scan-${testInfo.project.name}.png`, fullPage: true })
    }
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
    expect(overflow).toBeLessThanOrEqual(1)
  }
})

test('mobile node cards and listener controls fit the viewport', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'mobile', 'mobile-only assertion')
  await signIn(page)
  await page.getByRole('button', { name: '打开导航' }).click()
  await page.getByRole('link', { name: '节点管理' }).click()
  await expect(page.getByRole('heading', { name: '节点运行中心' })).toBeVisible()
  await page.waitForTimeout(250)
  await page.screenshot({ path: '/tmp/porthub-nodes-mobile.png', fullPage: true })
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  expect(overflow).toBeLessThanOrEqual(1)
})

test('port-forward batch controls work on desktop and mobile', async ({ page }, testInfo) => {
  await signIn(page)
  if ((await page.viewportSize())!.width < 700) await page.getByRole('button', { name: '打开导航' }).click()
  await page.getByRole('link', { name: '端口转发', exact: true }).click()
  await expect(page.getByRole('heading', { name: '通用端口转发' })).toBeVisible()
  await page.getByLabel('选择 openclaw · IPv4').click()
  await expect(page.locator('.batch-toolbar')).toContainText(/1\s*条规则已选择/)
  await expect(page.getByRole('button', { name: '批量启用' })).toBeVisible()
  await expect(page.getByRole('button', { name: '批量停用' })).toBeVisible()
  await page.screenshot({ path: `/tmp/porthub-port-forward-batch-${testInfo.project.name}.png`, fullPage: true })
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1)
})

test('local service management is clear and responsive', async ({ page }, testInfo) => {
  await signIn(page)
  if ((await page.viewportSize())!.width < 700) await page.getByRole('button', { name: '打开导航' }).click()
  await page.getByRole('link', { name: '本机服务' }).click()
  await expect(page.getByRole('heading', { name: '本机服务中心' })).toBeVisible()
  await expect(page.getByText('DST 加密隧道', { exact: true }).first()).toBeVisible()
  await expect(page.locator('.tunnel-strip').getByText('wg-dst', { exact: true })).toBeVisible()
  await expect(page.getByText('51821', { exact: true })).toBeVisible()
  await expect(page.getByText('DST 设备注册')).toBeVisible()
  await expect(page.getByText('QX 局域网 SOCKS5')).toBeVisible()
  await expect(page.getByText('QX 配置分发')).toBeVisible()
  await expect(page.getByText('TCP 全部地址:10888')).toBeVisible()
  await expect(page.getByLabel('QX 局域网 SOCKS5开机自动启动')).toBeChecked()
  await expect(page.getByRole('button', { name: '重启' }).first()).toBeVisible()
  await expect(page.getByRole('button', { name: '停止' }).first()).toBeVisible()
  await page.waitForTimeout(250)
  await page.screenshot({ path: `/tmp/porthub-managed-services-${testInfo.project.name}.png`, fullPage: true })
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1)
})

test('audit timeline is readable and opens full details', async ({ page }, testInfo) => {
  await signIn(page)
  if ((await page.viewportSize())!.width < 700) await page.getByRole('button', { name: '打开导航' }).click()
  await page.getByRole('link', { name: '审计日志' }).click()
  await expect(page.getByRole('heading', { name: '操作审计' })).toBeVisible()
  await expect(page.getByText('生成配置快照', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('配置下发', { exact: true }).first()).toBeVisible()
  await page.getByRole('button', { name: '详情' }).first().click()
  await expect(page.getByRole('dialog', { name: '审计记录详情' })).toBeVisible()
  await expect(page.getByText('原始操作名', { exact: true })).toBeVisible()
  await expect(page.getByRole('dialog', { name: '审计记录详情' }).getByText('snapshot_generate', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: '关闭详情' }).click()
  await expect(page.getByRole('dialog', { name: '审计记录详情' })).toHaveCount(0)
  await page.screenshot({ path: `/tmp/porthub-audit-${testInfo.project.name}.png`, fullPage: true })
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1)
})

test('page help and new management surfaces are usable', async ({ page }, testInfo) => {
  const errors: string[] = []
  page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()) })
  page.on('pageerror', (error) => errors.push(error.message))
  await signIn(page)
  errors.length = 0
  await page.getByRole('button', { name: '本页使用说明' }).click()
  await expect(page.getByText('建议操作顺序')).toBeVisible()
  await expect(page.getByText('名词解释')).toBeVisible()
  await page.getByRole('button', { name: '关闭说明' }).click()

  if ((await page.viewportSize())!.width < 700) await page.getByRole('button', { name: '打开导航' }).click()
  await page.getByRole('link', { name: '资源与服务' }).click()
  await expect(page.getByText('media-server')).toBeVisible()
  if ((await page.viewportSize())!.width < 700) await page.getByRole('button', { name: '打开导航' }).click()
  await page.getByRole('link', { name: 'TLS 证书' }).click()
  await page.getByLabel('选择证书').selectOption('7')
  await expect(page.getByText('通过绑定的 Provider 创建临时 TXT 记录')).toBeVisible()
  await page.waitForTimeout(250)
  await page.screenshot({ path: `/tmp/porthub-certificates-${testInfo.project.name}.png`, fullPage: true })
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1)
  if ((await page.viewportSize())!.width < 700) await page.getByRole('button', { name: '打开导航' }).click()
  await page.getByRole('link', { name: '升级管理' }).click()
  await expect(page.getByText('0.5.0 已安全暂存')).toBeVisible()
  await page.locator('summary').filter({ hasText: '安装' }).click()
  await expect(page.getByText('porthub-update-helper --execute')).toBeVisible()
  await page.screenshot({ path: `/tmp/porthub-updates-${testInfo.project.name}.png`, fullPage: true })
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  expect(overflow).toBeLessThanOrEqual(1)
  expect(errors).toEqual([])
})
