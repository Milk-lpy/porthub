import { ref } from 'vue'
import { request } from '../api'

export type DDNSProvider = {
  id: number
  name: string
  type: string
  config?: Record<string, unknown>
  secret_ref?: string
  secret?: Record<string, string>
  enabled: boolean
}

export type ProviderField = {
  key: string
  label: string
  type: 'text' | 'password' | 'textarea'
  required: boolean
  secret: boolean
  default?: string
  placeholder?: string
  help?: string
}

export type ProviderSchema = {
  type: string
  label: string
  fields: ProviderField[]
  note?: string
  secret_ref_hint?: string
}

export type DDNSRecord = {
  id: number
  name: string
  fqdn: string
  provider_id: number
  record_type: string
  ip_source: string
  last_value: string
  ttl: number
  enabled: boolean
  managed_by_lucky?: boolean
  interval_seconds: number
  last_sync_at?: string
  last_error?: string
  failure_count?: number
  ip_urls?: string[]
  net_interface?: string
  ip_regex?: string
  manual_ip?: string
  force_interval_seconds?: number
  notify_webhook?: string
  verify_dns?: boolean
}

export type DDNSSyncResult = {
  ok: boolean
  dry_run: boolean
  provider: string
  record_id: number
  fqdn: string
  record_type: string
  target_value?: string
  action: string
  message: string
}

export type NetInterface = {
  name: string
  mac?: string
  up: boolean
  ipv4: string[]
  ipv6: string[]
}

// createDDNSStore owns the DDNS slice of the ops store.
// Factory pattern mirrors ops.portforward.ts: the parent store wires in refresh().
export function createDDNSStore(refresh: () => Promise<void>) {
  const ddnsProviders = ref<DDNSProvider[]>([])
  const ddnsRecords = ref<DDNSRecord[]>([])
  const ddnsInterfaces = ref<NetInterface[]>([])
  const providerSchemas = ref<ProviderSchema[]>([])

  // Called by the parent store's refresh() after the batch request completes.
  function applyRefresh(providers?: DDNSProvider[], records?: DDNSRecord[], schemas?: ProviderSchema[]) {
    ddnsProviders.value = providers || []
    ddnsRecords.value = records || []
    providerSchemas.value = schemas || []
  }

  async function fetchDDNSInterfaces() {
    try {
      ddnsInterfaces.value = await request<NetInterface[]>('/api/ddns/interfaces')
    } catch (err) {
      // 静默失败: 网卡列表拉不到时表单仍可手填, 不阻塞页面
    }
  }

  async function createDDNSProvider(input: Omit<DDNSProvider, 'id'>) {
    await request('/api/ddns/providers', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function updateDDNSProvider(input: DDNSProvider) {
    await request('/api/ddns/providers', { method: 'PUT', body: JSON.stringify(input) })
    await refresh()
  }

  async function deleteDDNSProvider(id: string | number) {
    await request(`/api/ddns/providers?id=${encodeURIComponent(String(id))}`, { method: 'DELETE' })
    await refresh()
  }

  async function createDDNSRecord(input: Omit<DDNSRecord, 'id'>) {
    await request('/api/ddns/records', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function updateDDNSRecord(input: DDNSRecord) {
    await request('/api/ddns/records', { method: 'PUT', body: JSON.stringify(input) })
    await refresh()
  }

  async function deleteDDNSRecord(id: string | number) {
    await request(`/api/ddns/records?id=${encodeURIComponent(String(id))}`, { method: 'DELETE' })
    await refresh()
  }

  async function syncDDNS(recordID: number, value = '', dryRun = true) {
    return request<DDNSSyncResult>('/api/ddns/sync', {
      method: 'POST',
      body: JSON.stringify({ record_id: recordID, dry_run: dryRun, value }),
    })
  }

  async function previewDDNSSync(recordID: number, value = '') {
    return syncDDNS(recordID, value, true)
  }

  return {
    applyRefresh,
    createDDNSProvider,
    createDDNSRecord,
    ddnsProviders,
    ddnsRecords,
    ddnsInterfaces,
    deleteDDNSProvider,
    deleteDDNSRecord,
    fetchDDNSInterfaces,
    previewDDNSSync,
    providerSchemas,
    syncDDNS,
    updateDDNSProvider,
    updateDDNSRecord,
  }
}
