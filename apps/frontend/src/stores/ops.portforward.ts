import { ref } from 'vue'
import { request } from '../api'

export type PortForward = {
  id: number
  name: string
  node_id?: string
  listen_family: 'auto' | 'ipv4' | 'ipv6'
  listen_address: string
  listen_port_start: number
  listen_port_end: number
  protocol: 'tcp' | 'udp' | 'both'
  target_family: 'auto' | 'ipv4' | 'ipv6'
  target_host: string
  target_port_start: number
  target_port_end: number
  forward_mode: 'auto' | 'nft' | 'relay'
  snat_mode: 'auto' | 'masquerade' | 'none'
  enabled: boolean
  acl_id?: number
  allowed_cidrs?: string[]
  denied_cidrs?: string[]
  rate_limit_kbps?: number
  udp_idle_timeout?: number
  health_check?: boolean
  last_status?: string
  last_error?: string
  created_at?: string
  updated_at?: string
}

export type PortForwardStatus = {
  total: number
  enabled: number
  nft_rules: number
  relay_rules: number
  relay: {
    running: boolean
    rules: Array<Record<string, unknown>>
    error?: string
  }
  items: PortForward[]
}

export type PortForwardInput = Omit<PortForward, 'id' | 'created_at' | 'updated_at' | 'last_status' | 'last_error'>

// createPortForwardStore owns the port-forward slice of the ops store.
// It is a factory so the parent store can wire in its refresh() callback.
export function createPortForwardStore(refresh: () => Promise<void>) {
  const portForwards = ref<PortForward[]>([])
  const portForwardStatus = ref<PortForwardStatus | null>(null)

  async function fetchPortForwardStatus() {
    try {
      portForwardStatus.value = await request<PortForwardStatus>('/api/port-forwards/status')
    } catch (err) {
      // 静默失败: 状态面板轮询场景下保留上次数据
    }
  }

  async function createPortForward(input: PortForwardInput) {
    await request('/api/port-forwards', { method: 'POST', body: JSON.stringify(input) })
    await refresh()
  }

  async function updatePortForward(input: PortForward) {
    await request('/api/port-forwards', { method: 'PUT', body: JSON.stringify(input) })
    await refresh()
  }

  async function deletePortForward(id: number) {
    await request(`/api/port-forwards?id=${id}`, { method: 'DELETE' })
    await refresh()
  }

  async function togglePortForward(id: number, enabled: boolean) {
    await request('/api/port-forwards/toggle', { method: 'POST', body: JSON.stringify({ id, enabled }) })
    await refresh()
  }

  async function batchTogglePortForwards(ids: number[], enabled: boolean) {
    await request('/api/port-forwards/batch', { method: 'POST', body: JSON.stringify({ ids, enabled }) })
    await refresh()
  }

  async function duplicatePortForward(id: number, name?: string) {
    await request('/api/port-forwards/duplicate', { method: 'POST', body: JSON.stringify({ id, name }) })
    await refresh()
  }

  async function applyPortForwards() {
    await request('/api/port-forwards/apply', { method: 'POST', body: '{}' })
    await refresh()
  }

  async function testPortForwardTarget(host: string, port: number, protocol: string) {
    return request<{ ok: boolean; error?: string; latency_ms?: number; note?: string }>('/api/port-forwards/test', {
      method: 'POST',
      body: JSON.stringify({ host, port, protocol }),
    })
  }

  return {
    portForwards,
    portForwardStatus,
    fetchPortForwardStatus,
    createPortForward,
    updatePortForward,
    deletePortForward,
    togglePortForward,
    batchTogglePortForwards,
    duplicatePortForward,
    applyPortForwards,
    testPortForwardTarget,
  }
}
