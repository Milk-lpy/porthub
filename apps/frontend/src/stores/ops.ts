import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { hasRole, request } from '../api'
import type { ACMEIssueResult, ACMEStatus, CertificateItem, CertificatePlan, CertificatePrepareResult } from './ops.certificates'
import type { CoreMetrics, EdgeMetrics, PublicSourceAuditResponse, SystemAlert, TrafficRule, TrafficSample } from './ops.monitor'
import type { UpdateCheckResult, UpdateStatus } from './ops.updates'
import { createPortForwardStore, type PortForward, type PortForwardStatus } from './ops.portforward'
import { createDDNSStore } from './ops.ddns'

export type { ACMEIssueResult, ACMEStatus, CertificateItem, CertificatePlan, CertificatePrepareResult } from './ops.certificates'
export type { CoreMetrics, EdgeMetrics, PublicSourceAuditRecord, PublicSourceAuditResponse, PublicSourceSummary, SystemAlert, TrafficRule, TrafficSample } from './ops.monitor'
export type { UpdateCheckResult, UpdateStatus } from './ops.updates'
export type { PortForward, PortForwardStatus } from './ops.portforward'
export type { DDNSProvider, DDNSRecord, DDNSSyncResult, NetInterface, ProviderField, ProviderSchema } from './ops.ddns'

export type Mapping = {
  ID: string | number
  Name: string
  PublicIP?: string
  Protocol: string
  PublicStart: number
  PublicEnd: number
  TargetIP: string
  TargetStart: number
  TargetEnd: number
  Enabled: boolean
  acl_ids?: string[]
  Description?: string
  Tags?: string[]
  ResourceID?: string
  ServiceID?: string
  GroupID?: string
  EdgeID?: string
  TargetNodeID?: string
  RateLimitKbps?: number
  ConnectionLimit?: number
  LogLevel?: 'off' | 'error' | 'info' | 'verbose'
  SourceMode?: 'compat' | 'preserve'
  CreatedBy?: string
  CreatedAt?: string
  UpdatedAt?: string
}

export type MappingExport = {
  exported_at: string
  mappings: Mapping[]
}

export type AuditRecord = {
  id: number
  ts: string
  actor: string
  action: string
  detail: string
  action_label?: string
  category?: string
  category_label?: string
  severity?: 'info' | 'warning' | 'critical' | string
  severity_label?: string
  result?: 'success' | 'failure' | 'neutral' | string
  result_label?: string
  target?: string
  summary?: string
  system?: boolean
}

export type AuditFilters = {
  q?: string
  actor?: string
  category?: string
  severity?: string
  result?: string
  from?: string
  to?: string
  limit?: number
}

export type HTTPProxy = {
  id: string
  name: string
  host: string
  path?: string
  target: string
  targets?: string[]
  headers?: Record<string, string>
  health_path?: string
  load_balance?: 'round_robin'
  enabled: boolean
  force_tls?: boolean
  websocket?: boolean
  preserve_host?: boolean
}

export type ProxyBackendHealth = {
  target: string
  healthy: boolean
  status_code?: number
  last_checked: string
  error?: string
  consecutive_failures?: number
}

export type APIToken = {
  id: number
  name: string
  prefix: string
  role: string
  created_at: string
  last_used_at: string
  revoked: boolean
}

export type TokenCreateResult = {
  token: string
  prefix: string
}

export type UserItem = {
  id: number
  username: string
  role: string
  must_change: boolean
}

export type UserCreateResult = {
  id: number
  username: string
  role: string
  initial_password?: string
  temporary_password?: string
  totp_secret?: string
}

export type BackupItem = {
  name: string
  path: string
  size: number
  created_at: string
}

export type RestorePlan = {
  ok: boolean
  execute: boolean
  path: string
  steps: string[]
}

export type NodeStatus = Record<string, unknown> & {
	node_id?: string
  name?: string
  role?: string
  online?: boolean
  host?: string
  os?: string
  arch?: string
  load?: number[]
  memory_kb?: Record<string, number>
  disk_root_bytes?: Record<string, number>
  networks?: Array<{ name: string; rx_bytes: number; tx_bytes: number }>
}

export type AgentEnrollment = { id: number; token: string; expires_at: string }

export type NodeDiscovery = {
  platform?: string
  listeners: Array<{ protocol: string; address: string; port: number }>
  containers?: Array<{
    id: string
    name: string
    image: string
    state: string
    status: string
    ports: Array<{ ip?: string; private_port: number; public_port?: number; protocol: string }>
  }>
}

export type LanScanPort = { port: number; service: string; category: string; risk: string; protocol: string; suggested_name: string }
export type LanScanHost = { ip: string; reachable: boolean; classification: string; ports: LanScanPort[] }
export type LanScanState = { status: 'idle' | 'running' | 'completed' | 'failed' | 'stopped'; mode?: string; started_at?: string; finished_at?: string; progress: number; total: number; hosts: LanScanHost[]; error?: string }

export type ACLRule = {
  id: string
  name: string
  action: string
  cidr: string
  enabled: boolean
  protocols?: Array<'tcp' | 'udp'>
  port_start?: number
  port_end?: number
  node_ids?: string[]
  service_ids?: string[]
  group_ids?: string[]
  weekdays?: number[]
  start_time?: string
  end_time?: string
  timezone?: string
}

export type GenericItem = {
  id: number
  name: string
  description: string
  data: string
  enabled: boolean
  created_at?: string
  updated_at?: string
}

export type BuiltinTemplate = {
  id: string
  name: string
  description: string
  category: string
  high_risk: boolean
  warning?: string
  ports: Array<{ name: string; protocol: string; public_port: number; target_port: number }>
}

export type TemplateApplyResult = {
  ok: boolean
  created: number
  enabled: boolean
  high_risk: boolean
  warning?: string
}

export type DomainItem = {
  id: number
  name: string
  zone: string
  provider: string
  managed_by: string
  enabled: boolean
}

export type IPSet = {
  id: string
  name: string
  kind: string
  action: string
  cidrs: string[]
  enabled: boolean
}

export type IPFeed = {
  id: number
  name: string
  kind: 'geoip' | 'asn'
  action: 'allow' | 'deny'
  url: string
  expected_sha256?: string
  refresh_hours: number
  enabled: boolean
  ip_set_id: number
  last_fetch_at?: string
  last_sha256?: string
  last_error?: string
}

export type IPFeedSyncResult = {
  ok: boolean
  dry_run: boolean
  feed_id: number
  ip_set_id: number
  count: number
  sha256: string
}

export type NFTPreview = {
  version: number
  nft: string
  core_nft: string
}

export type DeployResult = {
  ok: boolean
  version: number
  edge?: Record<string, unknown>
  core?: Record<string, unknown>
}

export type SnapshotHistory = {
  version: number
  created_at: string
  operator: string
  sha256: string
  status: string
  result: string
  source_version: number
}

export type ConflictCheck = {
  ok: boolean
  error?: string
}

export type WireGuardPeer = {
  id: number
  node_id: string
  name: string
  public_key: string
  address: string
  allowed_ips: string[]
  persistent_keepalive: number
  enabled: boolean
}

export type WireGuardPeerRuntime = {
  id: number
  node_id: string
  name: string
  address: string
  online: boolean
  latest_handshake?: number
  rx_bytes: number
  tx_bytes: number
}

export type WireGuardStatus = {
  interface?: string
  public_key?: string
  listen_port?: number
  protected_peers?: number
  managed_peers?: number
  applied_sha256?: string
  peers?: WireGuardPeerRuntime[]
}

export type AIDraftResult = {
  ok: boolean
  engine: string
  group_name: string
  mappings: Mapping[]
  warnings: string[]
  blockers: string[]
  requires_confirmation: boolean
}

export const useOpsStore = defineStore('ops', () => {
  const status = ref<Record<string, string>>({})
  const mappings = ref<Mapping[]>([])
  const metrics = ref<EdgeMetrics>({})
  const coreMetrics = ref<CoreMetrics>({})
  const rank = ref<TrafficRule[]>([])
  const trend = ref<TrafficRule[]>([])
  const samples = ref<TrafficSample[]>([])
  const publicSourceAudits = ref<PublicSourceAuditResponse>({ records: [], summary: [], total: 0, retention_days: 30, exact_source_ip: false })
  const audit = ref<AuditRecord[]>([])
  const httpProxies = ref<HTTPProxy[]>([])
  const apiTokens = ref<APIToken[]>([])
  const users = ref<UserItem[]>([])
  const backups = ref<BackupItem[]>([])
  const nodeStatuses = ref<NodeStatus[]>([])
  const nodeDiscovery = ref<NodeDiscovery>({ listeners: [] })
  const lanScan = ref<LanScanState>({ status: 'idle', progress: 0, total: 0, hosts: [] })
  const snapshotHistory = ref<SnapshotHistory[]>([])
  const aclRules = ref<ACLRule[]>([])
  const resources = ref<GenericItem[]>([])
  const services = ref<GenericItem[]>([])
  const groups = ref<GenericItem[]>([])
  const webhooks = ref<GenericItem[]>([])
  const templates = ref<BuiltinTemplate[]>([])
  const domains = ref<DomainItem[]>([])
  const certificates = ref<CertificateItem[]>([])
  const ipSets = ref<IPSet[]>([])
  const ipFeeds = ref<IPFeed[]>([])
  const wireGuardPeers = ref<WireGuardPeer[]>([])
  const wireGuardStatus = ref<WireGuardStatus>({})
  // Port-forward slice lives in ops.portforward.ts; refresh is hoisted.
  const portForwardStore = createPortForwardStore(refresh)
  // DDNS slice lives in ops.ddns.ts; refresh is hoisted.
  const ddnsStore = createDDNSStore(refresh)
  const alerts = ref<SystemAlert[]>([])
  const updateStatus = ref<UpdateStatus>({ enabled: false, current_version: '--' })
  const monitorConnected = ref(false)
  const loading = ref(false)
  const error = ref('')

  const topTraffic = computed(() => rank.value[0])

  async function refresh() {
    loading.value = true
    error.value = ''
    try {
      const [nextStatus, nextMappings, nextMetrics, nextRank, nextSamples, nextPublicSourceAudits, nextAudit, nextProxies, nextAcl, nextDomains, nextProviders, nextDDNSRecords, nextCertificates, nextIPSets, nextTokens, nextUsers, nextBackups, nextNodeStatuses, nextNodeDiscovery, nextResources, nextServices, nextGroups, nextWebhooks, nextTemplates, nextSnapshotHistory, nextWireGuardPeers, nextWireGuardStatus, nextAlerts, nextIPFeeds, nextUpdateStatus, nextProviderSchemas, nextPortForwards, nextLanScan] = await Promise.all([
        request<Record<string, string>>('/api/status'),
        request<Mapping[]>('/api/mappings'),
        request<EdgeMetrics>('/api/edge/metrics'),
        request<TrafficRule[]>('/api/traffic/rank?limit=8'),
        request<TrafficSample[]>('/api/traffic/recent?limit=8'),
        request<PublicSourceAuditResponse>('/api/traffic/public-sources?limit=100'),
        request<AuditRecord[]>('/api/audit?limit=200'),
        request<HTTPProxy[]>('/api/http-proxies'),
        request<ACLRule[]>('/api/acl-rules'),
        request<DomainItem[]>('/api/domains'),
        request<import('./ops.ddns').DDNSProvider[]>('/api/ddns/providers'),
        request<import('./ops.ddns').DDNSRecord[]>('/api/ddns/records'),
        request<CertificateItem[]>('/api/certificates'),
        request<IPSet[]>('/api/ip-sets'),
        hasRole('admin') ? request<APIToken[]>('/api/tokens') : Promise.resolve([]),
        hasRole('super_admin') ? request<UserItem[]>('/api/users') : Promise.resolve([]),
        hasRole('admin') ? request<BackupItem[]>('/api/backups') : Promise.resolve([]),
        request<NodeStatus[]>('/api/nodes/status'),
        request<NodeDiscovery>('/api/nodes/discovery'),
        request<GenericItem[]>('/api/resources'),
        request<GenericItem[]>('/api/services'),
        request<GenericItem[]>('/api/groups'),
        hasRole('admin') ? request<GenericItem[]>('/api/webhooks') : Promise.resolve([]),
        request<BuiltinTemplate[]>('/api/templates/builtin'),
        request<SnapshotHistory[]>('/api/snapshots?limit=50'),
        request<WireGuardPeer[]>('/api/wireguard/peers'),
        request<WireGuardStatus>('/api/wireguard/status'),
        request<SystemAlert[]>('/api/alerts?limit=20'),
        request<IPFeed[]>('/api/ip-feeds'),
        hasRole('admin') ? request<UpdateStatus>('/api/updates/status') : Promise.resolve({ enabled: false, current_version: '--' }),
        request<import('./ops.ddns').ProviderSchema[]>('/api/ddns/provider-schema'),
        request<PortForward[]>('/api/port-forwards'),
        request<LanScanState>('/api/lan-scan'),
      ])
      status.value = nextStatus
      mappings.value = nextMappings || []
      metrics.value = nextMetrics || {}
      rank.value = nextRank || []
      samples.value = nextSamples || []
      publicSourceAudits.value = nextPublicSourceAudits || { records: [], summary: [], total: 0, retention_days: 30, exact_source_ip: false }
      audit.value = nextAudit || []
      httpProxies.value = nextProxies || []
      aclRules.value = nextAcl || []
      domains.value = nextDomains || []
      ddnsStore.applyRefresh(nextProviders, nextDDNSRecords, nextProviderSchemas)
      certificates.value = nextCertificates || []
      ipSets.value = nextIPSets || []
      apiTokens.value = nextTokens || []
      users.value = nextUsers || []
      backups.value = nextBackups || []
      nodeStatuses.value = nextNodeStatuses || []
      nodeDiscovery.value = nextNodeDiscovery || { listeners: [] }
      lanScan.value = nextLanScan || { status: 'idle', progress: 0, total: 0, hosts: [] }
      resources.value = nextResources || []
      services.value = nextServices || []
      groups.value = nextGroups || []
      webhooks.value = nextWebhooks || []
      templates.value = nextTemplates || []
      snapshotHistory.value = nextSnapshotHistory || []
      wireGuardPeers.value = nextWireGuardPeers || []
      wireGuardStatus.value = nextWireGuardStatus || {}
      portForwardStore.portForwards.value = nextPortForwards || []
      alerts.value = nextAlerts || []
      ipFeeds.value = nextIPFeeds || []
      updateStatus.value = nextUpdateStatus
      await refreshTrend()
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function collectTraffic() {
    await request<TrafficSample>('/api/traffic/snapshot', { method: 'POST', body: '{}' })
    await refresh()
  }

  async function refreshAudit(filters: AuditFilters = {}) {
    const query = new URLSearchParams({ limit: String(filters.limit || 200) })
    for (const [key, value] of Object.entries(filters)) {
      if (key === 'limit' || value === undefined || value === null || value === '' || value === 'all') continue
      query.set(key, String(value))
    }
    audit.value = await request<AuditRecord[]>(`/api/audit?${query.toString()}`)
    return audit.value
  }

  async function refreshPublicSourceAudits(filters: { source_ip?: string; mapping_id?: string; protocol?: string } = {}) {
    const query = new URLSearchParams({ limit: '100' })
    for (const [key, value] of Object.entries(filters)) {
      if (value) query.set(key, value)
    }
    publicSourceAudits.value = await request<PublicSourceAuditResponse>(`/api/traffic/public-sources?${query.toString()}`)
    return publicSourceAudits.value
  }

  async function startLanScan(input: { mode: 'common' | 'deep'; host?: string }) {
    const result = await request<{ status: string }>('/api/lan-scan', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
    return result
  }

  async function refreshLanScan() {
    lanScan.value = await request<LanScanState>('/api/lan-scan')
    return lanScan.value
  }

  async function stopLanScan() {
    await request('/api/lan-scan', { method: 'DELETE' })
    await refreshLanScan()
  }

  async function fetchCoreMetrics() {
    try {
      coreMetrics.value = await request<CoreMetrics>('/api/metrics')
    } catch (err) {
      // 静默失败: 节点页轮询场景下保留上次数据, 避免抖动报错
      if (!Object.keys(coreMetrics.value).length) {
        error.value = err instanceof Error ? err.message : String(err)
      }
    }
  }

  async function acknowledgeAlert(id: number) {
    await request('/api/alerts', { method: 'POST', body: JSON.stringify({ id }) })
    alerts.value = await request<SystemAlert[]>('/api/alerts?limit=20')
  }

  async function generateAIDraft(intent: string) {
    return request<AIDraftResult>('/api/ai/draft', { method: 'POST', body: JSON.stringify({ intent }) })
  }

  async function saveAIDraft(draft: AIDraftResult) {
    const mappings = draft.mappings.map(({ ID: _, ...mapping }) => ({ ...mapping, Enabled: false }))
    await importMappings(mappings)
  }

  async function checkUpdates() {
    const result = await request<UpdateCheckResult>('/api/updates/check', { method: 'POST', body: '{}' })
    updateStatus.value = await request<UpdateStatus>('/api/updates/status')
    return result
  }

  async function stageUpdate(component: 'core' | 'agent') {
    const result = await request<{ ok: boolean; version: string; component: string; stage_path: string; requires_install_confirmation: boolean }>('/api/updates/stage', {
      method: 'POST', body: JSON.stringify({ component }),
    })
    updateStatus.value = await request<UpdateStatus>('/api/updates/status')
    return result
  }

  let monitorSocket: WebSocket | undefined
  let monitorReconnect: number | undefined
  let monitorWanted = false

  function startLiveMonitoring() {
    monitorWanted = true
    if (monitorSocket && (monitorSocket.readyState === WebSocket.OPEN || monitorSocket.readyState === WebSocket.CONNECTING)) return
    window.clearTimeout(monitorReconnect)
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
    monitorSocket = new WebSocket(`${scheme}://${window.location.host}/api/monitor/stream`)
    monitorSocket.onopen = () => { monitorConnected.value = true }
    monitorSocket.onmessage = (event) => {
      try {
        const payload = JSON.parse(String(event.data)) as { type: string; metrics?: EdgeMetrics; alerts?: SystemAlert[] }
        if (payload.type === 'metrics' && payload.metrics) metrics.value = payload.metrics
        if (payload.alerts) alerts.value = payload.alerts
      } catch {
        monitorConnected.value = false
      }
    }
    monitorSocket.onclose = () => {
      monitorConnected.value = false
      monitorSocket = undefined
      if (monitorWanted) monitorReconnect = window.setTimeout(startLiveMonitoring, 3000)
    }
    monitorSocket.onerror = () => monitorSocket?.close()
  }

  function stopLiveMonitoring() {
    monitorWanted = false
    window.clearTimeout(monitorReconnect)
    monitorSocket?.close()
    monitorSocket = undefined
    monitorConnected.value = false
  }

  async function createDomain(input: Omit<DomainItem, 'id'>) {
    await request('/api/domains', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function updateDomain(input: DomainItem) {
    await request('/api/domains', { method: 'PUT', body: JSON.stringify(input) })
    await refresh()
  }

  async function deleteDomain(id: string | number) {
    await request(`/api/domains?id=${encodeURIComponent(String(id))}`, { method: 'DELETE' })
    await refresh()
  }

  async function createMapping(input: Omit<Mapping, 'ID'>) {
    await request('/api/mappings', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function updateMapping(input: Mapping) {
    await request('/api/mappings', { method: 'PUT', body: JSON.stringify(input) })
    await refresh()
  }

  async function deleteMapping(id: string | number) {
    await request(`/api/mappings?id=${encodeURIComponent(String(id))}`, { method: 'DELETE' })
    await refresh()
  }

  async function bulkMappings(action: 'enable' | 'disable' | 'delete', ids: Array<string | number>) {
    await request('/api/mappings/bulk', {
      method: 'POST',
      body: JSON.stringify({ action, ids: ids.map(String) }),
    })
    await refresh()
  }

  async function importMappings(mappings: Array<Omit<Mapping, 'ID'>>) {
    await request('/api/mappings/import', {
      method: 'POST',
      body: JSON.stringify({ mode: 'append', mappings }),
    })
    await refresh()
  }

  async function exportMappings() {
    return request<MappingExport>('/api/mappings/export')
  }

  async function previewNFT() {
    return request<NFTPreview>('/api/nft/preview')
  }

  async function checkMappingConflicts() {
    return request<ConflictCheck>('/api/mappings/conflicts')
  }

  async function deploySnapshot() {
    return request<DeployResult>('/api/deploy', { method: 'POST', body: '{}' })
  }

  async function rollbackSnapshot(version: number) {
    const result = await request<DeployResult>('/api/snapshots/rollback', { method: 'POST', body: JSON.stringify({ version }) })
    await refresh()
    return result
  }

  async function createAgentEnrollment(name: string, ttlMinutes = 30) {
		return request<AgentEnrollment>('/api/agents/enrollments', { method: 'POST', body: JSON.stringify({ name, ttl_minutes: ttlMinutes }) })
	}

  async function createHTTPProxy(input: Omit<HTTPProxy, 'id'>) {
    await request('/api/http-proxies', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function updateHTTPProxy(input: HTTPProxy) {
    await request('/api/http-proxies', { method: 'PUT', body: JSON.stringify(input) })
    await refresh()
  }

  async function deleteHTTPProxy(id: string | number) {
    await request(`/api/http-proxies?id=${encodeURIComponent(String(id))}`, { method: 'DELETE' })
    await refresh()
  }

  async function createToken(input: { name: string; role: string }) {
    const result = await request<TokenCreateResult>('/api/tokens', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
    return result
  }

  async function revokeToken(id: string | number) {
    await request(`/api/tokens?id=${encodeURIComponent(String(id))}`, { method: 'DELETE' })
    await refresh()
  }

  async function createUser(input: { username: string; password?: string; role: string }) {
    const result = await request<UserCreateResult>('/api/users', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
    return result
  }

  async function updateUser(input: UserItem) {
    await request('/api/users', { method: 'PUT', body: JSON.stringify(input) })
    await refresh()
  }

  async function deleteUser(id: string | number) {
    await request(`/api/users?id=${encodeURIComponent(String(id))}`, { method: 'DELETE' })
    await refresh()
  }

  async function resetUserPassword(id: string | number, password = '') {
    const result = await request<UserCreateResult>('/api/users/reset-password', {
      method: 'POST',
      body: JSON.stringify({ id: Number(id), password }),
    })
    await refresh()
    return result
  }

  async function resetUserTOTP(id: string | number) {
    const result = await request<UserCreateResult>('/api/users/reset-totp', {
      method: 'POST',
      body: JSON.stringify({ id: Number(id) }),
    })
    await refresh()
    return result
  }

  async function createBackup() {
    const result = await request<BackupItem>('/api/backups', { method: 'POST', body: '{}' })
    await refresh()
    return result
  }

  async function restorePlan(name: string) {
    return request<RestorePlan>('/api/backups/restore/plan', { method: 'POST', body: JSON.stringify({ name }) })
  }

  async function createCertificate(input: Omit<CertificateItem, 'id'>) {
    await request('/api/certificates', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function updateCertificate(input: CertificateItem) {
    await request('/api/certificates', { method: 'PUT', body: JSON.stringify(input) })
    await refresh()
  }

  async function deleteCertificate(id: string | number) {
    await request(`/api/certificates?id=${encodeURIComponent(String(id))}`, { method: 'DELETE' })
    await refresh()
  }

  async function previewCertificatePlan(certificateID: number) {
    return request<CertificatePlan>('/api/certificates/plan', {
      method: 'POST',
      body: JSON.stringify({ certificate_id: certificateID }),
    })
  }

  async function prepareCertificate(certificateID: number, dryRun = true) {
    const result = await request<CertificatePrepareResult>('/api/certificates/acme/prepare', {
      method: 'POST',
      body: JSON.stringify({ certificate_id: certificateID, dry_run: dryRun }),
    })
    if (!dryRun) await refresh()
    return result
  }

  async function getACMEStatus() {
    return request<ACMEStatus>('/api/certificates/acme/status')
  }

  async function issueCertificate(certificateID: number, email: string, deploy = true) {
    const result = await request<ACMEIssueResult>('/api/certificates/acme/issue', {
      method: 'POST', body: JSON.stringify({ certificate_id: certificateID, accept_tos: true, deploy, email }),
    })
    await refresh()
    return result
  }

  async function importCertificate(certificateID: number, certificatePEM: string, privateKeyPEM: string, deploy = true) {
    const result = await request<{ ok: boolean; certificate_id: number; expires_at: string; deployed: boolean }>('/api/certificates/import', {
      method: 'POST',
      body: JSON.stringify({ certificate_id: certificateID, certificate_pem: certificatePEM, private_key_pem: privateKeyPEM, deploy }),
    })
    await refresh()
    return result
  }

  async function deployCertificate(certificateID: number) {
    return request<{ ok: boolean; certificate_id: number }>('/api/certificates/deploy', {
      method: 'POST', body: JSON.stringify({ certificate_id: certificateID }),
    })
  }

  async function createWireGuardPeer(input: Omit<WireGuardPeer, 'id'>) {
    await request('/api/wireguard/peers', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function updateWireGuardPeer(input: WireGuardPeer) {
    await request('/api/wireguard/peers', { method: 'PUT', body: JSON.stringify(input) })
    await refresh()
  }

  async function deleteWireGuardPeer(id: number) {
    await request(`/api/wireguard/peers?id=${id}`, { method: 'DELETE' })
    await refresh()
  }

  async function deployWireGuardPeers() {
    const result = await request<{ ok: boolean; managed_peers: number; sha256: string }>('/api/wireguard/peers/deploy', { method: 'POST', body: '{}' })
    await refresh()
    return result
  }

  async function createIPSet(input: Omit<IPSet, 'id'>) {
    await request('/api/ip-sets', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function deleteIPSet(id: string | number) {
    await request(`/api/ip-sets?id=${encodeURIComponent(String(id))}`, { method: 'DELETE' })
    await refresh()
  }

  async function createIPFeed(input: Omit<IPFeed, 'id' | 'ip_set_id' | 'last_fetch_at' | 'last_sha256' | 'last_error'>) {
    await request('/api/ip-feeds', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function updateIPFeed(input: IPFeed) {
    await request('/api/ip-feeds', { method: 'PUT', body: JSON.stringify(input) })
    await refresh()
  }

  async function deleteIPFeed(id: number) {
    await request(`/api/ip-feeds?id=${id}`, { method: 'DELETE' })
    await refresh()
  }

  async function syncIPFeed(id: number, dryRun = true) {
    const result = await request<IPFeedSyncResult>('/api/ip-feeds/sync', { method: 'POST', body: JSON.stringify({ id, dry_run: dryRun }) })
    if (!dryRun) await refresh()
    return result
  }

  async function importIPSet(input: { name: string; kind: string; action: string; source: string; enabled: boolean }) {
    await request('/api/ip-sets/import', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function createACLRule(input: Omit<ACLRule, 'id'>) {
    await request('/api/acl-rules', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function updateACLRule(input: ACLRule) {
    await request('/api/acl-rules', { method: 'PUT', body: JSON.stringify(input) })
    await refresh()
  }

  async function deleteACLRule(id: string | number) {
    await request(`/api/acl-rules?id=${encodeURIComponent(String(id))}`, { method: 'DELETE' })
    await refresh()
  }

  type GenericKind = 'resources' | 'services' | 'groups' | 'webhooks'

  async function createGeneric(kind: GenericKind, input: Omit<GenericItem, 'id'>) {
    await request(`/api/${kind}`, { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function updateGeneric(kind: GenericKind, input: GenericItem) {
    await request(`/api/${kind}`, { method: 'PUT', body: JSON.stringify(input) })
    await refresh()
  }

  async function deleteGeneric(kind: GenericKind, id: string | number) {
    await request(`/api/${kind}?id=${encodeURIComponent(String(id))}`, { method: 'DELETE' })
    await refresh()
  }

  async function applyTemplate(input: { template_id: string; name: string; target_ip: string; enabled: boolean; allow_high_risk: boolean }) {
    const result = await request<TemplateApplyResult>('/api/templates/apply', {
      method: 'POST',
      body: JSON.stringify(input),
    })
    await refresh()
    return result
  }

  async function refreshTrend() {
    const top = topTraffic.value
    if (!top) {
      trend.value = []
      return
    }
    trend.value = await request<TrafficRule[]>(`/api/traffic/trend?protocol=${encodeURIComponent(top.protocol)}&port=${top.port}&limit=24`)
  }

  return {
    aclRules,
    acknowledgeAlert,
    alerts,
    apiTokens,
    applyTemplate,
    audit,
    refreshAudit,
    backups,
    bulkMappings,
    collectTraffic,
    certificates,
    checkUpdates,
    checkMappingConflicts,
    createCertificate,
    createDomain,
    createHTTPProxy,
    createIPFeed,
    createMapping,
    createToken,
    createUser,
    createBackup,
    createACLRule,
    ...portForwardStore,
    ...ddnsStore,
		createAgentEnrollment,
    createGeneric,
    deleteHTTPProxy,
    deleteIPFeed,
    deleteIPSet,
    deleteMapping,
    deleteUser,
    deleteACLRule,
    deleteCertificate,
    deleteDomain,
    deleteGeneric,
    deployCertificate,
    createWireGuardPeer,
    updateWireGuardPeer,
    deleteWireGuardPeer,
    deployWireGuardPeers,
    deploySnapshot,
    domains,
    error,
    exportMappings,
    fetchCoreMetrics,
    groups,
    getACMEStatus,
    generateAIDraft,
    httpProxies,
    importMappings,
    importCertificate,
    issueCertificate,
    ipSets,
    ipFeeds,
    wireGuardPeers,
    wireGuardStatus,
    loading,
    lanScan,
    mappings,
    metrics,
    coreMetrics,
    monitorConnected,
    nodeDiscovery,
    nodeStatuses,
    previewCertificatePlan,
    previewNFT,
    publicSourceAudits,
    refreshPublicSourceAudits,
    createIPSet,
    importIPSet,
    rank,
    refresh,
    resources,
    resetUserPassword,
    resetUserTOTP,
    rollbackSnapshot,
    restorePlan,
    revokeToken,
    samples,
    saveAIDraft,
    snapshotHistory,
    services,
    status,
    stageUpdate,
    startLiveMonitoring,
    startLanScan,
    refreshLanScan,
    stopLanScan,
    stopLiveMonitoring,
    syncIPFeed,
    topTraffic,
    trend,
    templates,
    prepareCertificate,
    updateHTTPProxy,
    updateIPFeed,
    updateACLRule,
    updateCertificate,
    updateDomain,
    updateGeneric,
    updateMapping,
    updateUser,
    updateStatus,
    users,
    webhooks,
  }
})
