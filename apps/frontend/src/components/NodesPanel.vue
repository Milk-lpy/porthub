<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import {
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  Box,
  CircleDot,
  Clock,
  Cpu,
  Database,
  Gauge,
  HardDrive,
  Layers,
  MemoryStick,
  Network,
  RadioTower,
  RefreshCw,
  Search,
  Server,
	UserPlus,
} from '@lucide/vue'
import { NAlert, NButton, NInput } from 'naive-ui'
import { hasRole } from '../api'
import { useOpsStore } from '../stores/ops'
import type { CoreMetrics, NodeStatus } from '../stores/ops'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const protocol = ref<'all' | 'tcp' | 'udp'>('all')
const query = ref('')
const enrollmentOpen = ref(false)
const enrollmentName = ref('新 Linux 节点')
const enrollmentToken = ref('')
const enrollmentExpires = ref('')
const metricsLastUpdated = ref('')
let metricsTimer: number | undefined

const coreMetric = computed(() => ops.coreMetrics)

function metricPercent(used: number, total: number) {
  return percent(used, total)
}

function cpuText() {
  const value = Number(coreMetric.value.cpu_percent ?? 0)
  return `${value.toFixed(1)}%`
}

function memoryText() {
  return `${fmtBytes(Number(coreMetric.value.memory_used_bytes || 0))} / ${fmtBytes(Number(coreMetric.value.memory_total_bytes || 0))}`
}

function diskText() {
  return `${fmtBytes(Number(coreMetric.value.disk_used_bytes || 0))} / ${fmtBytes(Number(coreMetric.value.disk_total_bytes || 0))}`
}

function loadTextCore() {
  const load1 = Number(coreMetric.value.load_1 ?? 0)
  const load5 = Number(coreMetric.value.load_5 ?? 0)
  const load15 = Number(coreMetric.value.load_15 ?? 0)
  return `${load1.toFixed(2)} / ${load5.toFixed(2)} / ${load15.toFixed(2)}`
}

function uptimeText() {
  const seconds = Number(coreMetric.value.uptime_seconds || 0)
  if (!seconds) return '--'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days} 天 ${hours} 小时`
  if (hours > 0) return `${hours} 小时 ${minutes} 分`
  return `${minutes} 分`
}

async function pollCoreMetrics() {
  await ops.fetchCoreMetrics()
  if (coreMetric.value.time) {
    metricsLastUpdated.value = new Date(coreMetric.value.time as string).toLocaleTimeString('zh-CN')
  }
}

onMounted(() => {
  void pollCoreMetrics()
  metricsTimer = window.setInterval(() => void pollCoreMetrics(), 5000)
})

onUnmounted(() => {
  if (metricsTimer !== undefined) window.clearInterval(metricsTimer)
})

const listeners = computed(() => {
  const needle = query.value.trim().toLowerCase()
  return (ops.nodeDiscovery.listeners || []).filter((row) => {
    const protocolMatch = protocol.value === 'all' || row.protocol.toLowerCase().startsWith(protocol.value)
    const queryMatch = !needle || `${row.address}:${row.port}`.toLowerCase().includes(needle)
    return protocolMatch && queryMatch
  })
})

const onlineCount = computed(() => ops.nodeStatuses.filter((node) => node.online !== false).length)
const interfaceCount = computed(() => ops.nodeStatuses.reduce((sum, node) => sum + (node.networks?.length || 0), 0))
const tcpCount = computed(() => (ops.nodeDiscovery.listeners || []).filter((row) => row.protocol.toLowerCase().startsWith('tcp')).length)
const udpCount = computed(() => (ops.nodeDiscovery.listeners || []).filter((row) => row.protocol.toLowerCase().startsWith('udp')).length)

function fmtBytes(value: unknown) {
  const n = Number(value || 0)
  if (n < 1024) return `${n} B`
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KiB`
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MiB`
  if (n < 1099511627776) return `${(n / 1073741824).toFixed(1)} GiB`
  return `${(n / 1099511627776).toFixed(1)} TiB`
}

function memoryTotal(node: NodeStatus) {
  return Number(node.memory_kb?.MemTotal || 0) * 1024
}

function memoryUsed(node: NodeStatus) {
  const total = Number(node.memory_kb?.MemTotal || 0)
  const available = Number(node.memory_kb?.MemAvailable || node.memory_kb?.MemFree || 0)
  return Math.max(0, total - available) * 1024
}

function memoryPercent(node: NodeStatus) {
  return percent(memoryUsed(node), memoryTotal(node))
}

function diskTotal(node: NodeStatus) {
  return Number(node.disk_root_bytes?.total || 0)
}

function diskUsed(node: NodeStatus) {
  return Math.max(0, diskTotal(node) - Number(node.disk_root_bytes?.free || 0))
}

function diskPercent(node: NodeStatus) {
  return percent(diskUsed(node), diskTotal(node))
}

function percent(used: number, total: number) {
  if (!total) return 0
  return Math.min(100, Math.max(0, Math.round((used * 100) / total)))
}

function loadText(node: NodeStatus) {
  return Array.isArray(node.load) && node.load.length ? node.load.slice(0, 3).map((value) => Number(value).toFixed(2)).join(' / ') : '--'
}

function roleLabel(node: NodeStatus) {
  const role = String(node.role || 'agent').toLowerCase()
  if (role === 'core') return 'Core 控制节点'
  if (role === 'edge') return 'Edge 边缘节点'
  return 'Agent 子节点'
}

function roleClass(node: NodeStatus) {
  const role = String(node.role || 'agent').toLowerCase()
  return role === 'edge' ? 'cyan' : role === 'core' ? 'green' : 'blue'
}

function usageClass(value: number) {
  if (value >= 90) return 'danger'
  if (value >= 75) return 'warning'
  return 'healthy'
}

async function refresh() {
  await ops.refresh()
  emit('notify', '节点状态已刷新')
}

async function createEnrollment() {
	try {
		const result = await ops.createAgentEnrollment(enrollmentName.value.trim(), 30)
		enrollmentToken.value = result.token
		enrollmentExpires.value = result.expires_at
		emit('notify', '一次性 Agent 注册凭据已生成')
	} catch (error) {
		emit('notify', error instanceof Error ? error.message : String(error), 'error')
	}
}
</script>

<template>
  <section class="node-overview">
    <div class="node-overview-copy">
      <span class="eyebrow">NODE FLEET</span>
      <h2>节点运行中心</h2>
      <p>集中查看 Core、Edge 与 Agent 子节点的资源和网络状态。</p>
    </div>
    <div class="node-summary-grid">
      <div><span class="summary-icon green"><Server :size="18" /></span><span><small>节点总数</small><b>{{ ops.nodeStatuses.length }}</b></span></div>
      <div><span class="summary-icon cyan"><CircleDot :size="18" /></span><span><small>在线节点</small><b>{{ onlineCount }}</b></span></div>
      <div><span class="summary-icon blue"><RadioTower :size="18" /></span><span><small>监听端口</small><b>{{ ops.nodeDiscovery.listeners?.length || 0 }}</b></span></div>
      <div><span class="summary-icon amber"><Network :size="18" /></span><span><small>网络接口</small><b>{{ interfaceCount }}</b></span></div>
    </div>
	<div class="button-row">
		<n-button v-if="hasRole('admin')" secondary size="small" @click="enrollmentOpen = !enrollmentOpen"><UserPlus :size="16" />注册 Agent</n-button>
		<n-button secondary size="small" :loading="ops.loading" @click="refresh"><RefreshCw :size="16" />刷新状态</n-button>
	</div>
  </section>

	<section v-if="enrollmentOpen" class="panel enrollment-panel">
		<div class="panel-title"><div><span class="eyebrow">MTLS ENROLLMENT</span><h2>注册子节点</h2><p>凭据仅显示一次，有效期 30 分钟；Agent 本地生成私钥。</p></div></div>
		<div class="form-grid"><label>注册名称<n-input v-model:value="enrollmentName" placeholder="例如 PVE-01" /></label><n-button type="primary" class="form-action create-action" @click="createEnrollment">生成一次性凭据</n-button></div>
		<n-alert v-if="enrollmentToken" type="warning" :bordered="false" class="enrollment-result">
			<strong>注册凭据</strong><code>{{ enrollmentToken }}</code><small>到期时间：{{ new Date(enrollmentExpires).toLocaleString('zh-CN') }}</small>
		</n-alert>
	</section>

  <section class="panel core-metrics-panel">
    <div class="panel-title">
      <div><span class="eyebrow">LIVE METRICS</span><h3>Core 实时指标</h3><p>由 Core 节点本机每 5 秒采集，不依赖 Edge 上报。</p></div>
      <span class="metrics-refresh-hint"><RefreshCw :size="13" />{{ metricsLastUpdated ? `更新于 ${metricsLastUpdated}` : '采集中…' }}</span>
    </div>
    <div class="node-resource-grid">
      <div class="resource-tile">
        <div><span class="resource-icon"><Gauge :size="16" /></span><span><small>CPU 使用率</small><b>{{ cpuText() }}</b></span></div>
        <div class="usage-line"><span :class="usageClass(metricPercent(Number(coreMetric.cpu_percent || 0), 100))" :style="{ width: `${Math.min(100, Number(coreMetric.cpu_percent || 0))}%` }"></span></div>
        <p>{{ Number(coreMetric.processes || 0) }} 个进程</p>
      </div>
      <div class="resource-tile">
        <div><span class="resource-icon"><MemoryStick :size="16" /></span><span><small>内存使用</small><b>{{ memoryText() }}</b></span></div>
        <div class="usage-line"><span :class="usageClass(metricPercent(Number(coreMetric.memory_used_bytes || 0), Number(coreMetric.memory_total_bytes || 0)))" :style="{ width: `${metricPercent(Number(coreMetric.memory_used_bytes || 0), Number(coreMetric.memory_total_bytes || 0))}%` }"></span></div>
        <p>{{ metricPercent(Number(coreMetric.memory_used_bytes || 0), Number(coreMetric.memory_total_bytes || 0)) }}% 已使用</p>
      </div>
      <div class="resource-tile">
        <div><span class="resource-icon"><HardDrive :size="16" /></span><span><small>根磁盘</small><b>{{ diskText() }}</b></span></div>
        <div class="usage-line"><span :class="usageClass(metricPercent(Number(coreMetric.disk_used_bytes || 0), Number(coreMetric.disk_total_bytes || 0)))" :style="{ width: `${metricPercent(Number(coreMetric.disk_used_bytes || 0), Number(coreMetric.disk_total_bytes || 0))}%` }"></span></div>
        <p>{{ metricPercent(Number(coreMetric.disk_used_bytes || 0), Number(coreMetric.disk_total_bytes || 0)) }}% 已使用</p>
      </div>
      <div class="resource-tile">
        <div><span class="resource-icon"><Activity :size="16" /></span><span><small>系统负载</small><b>{{ loadTextCore() }}</b></span></div>
        <p>1 / 5 / 15 分钟 · <Clock :size="12" />已运行 {{ uptimeText() }}</p>
      </div>
    </div>
  </section>

  <section class="node-section">
    <div class="section-heading">
      <div><span class="eyebrow">INFRASTRUCTURE</span><h3>节点与资源</h3></div>
      <span>{{ onlineCount }}/{{ ops.nodeStatuses.length }} 在线</span>
    </div>

    <div v-if="ops.nodeStatuses.length" class="node-grid enhanced">
      <article v-for="node in ops.nodeStatuses" :key="String(node.name || node.host)" class="node-card enhanced">
        <header class="node-head enhanced">
          <div class="node-identity">
            <span :class="['node-role-icon', roleClass(node)]">
              <Database v-if="String(node.role).toLowerCase() === 'core'" :size="20" />
              <RadioTower v-else-if="String(node.role).toLowerCase() === 'edge'" :size="20" />
              <Box v-else :size="20" />
            </span>
            <span><b>{{ node.name || node.host || 'unknown' }}</b><small>{{ roleLabel(node) }}</small></span>
          </div>
          <span :class="['node-health', node.online !== false ? 'online' : 'offline']"><i></i>{{ node.online !== false ? '运行正常' : '节点离线' }}</span>
        </header>

        <div class="node-system-line">
          <span><Server :size="14" />{{ node.host || '--' }}</span>
          <span><Cpu :size="14" />{{ node.os || '--' }} · {{ node.arch || '--' }}</span>
        </div>

        <div class="node-resource-grid">
          <div class="resource-tile">
            <div><span class="resource-icon"><Activity :size="16" /></span><span><small>系统负载</small><b>{{ loadText(node) }}</b></span></div>
            <p>1 / 5 / 15 分钟</p>
          </div>
          <div class="resource-tile">
            <div><span class="resource-icon"><MemoryStick :size="16" /></span><span><small>内存使用</small><b>{{ fmtBytes(memoryUsed(node)) }} / {{ fmtBytes(memoryTotal(node)) }}</b></span></div>
            <div class="usage-line"><span :class="usageClass(memoryPercent(node))" :style="{ width: `${memoryPercent(node)}%` }"></span></div>
            <p>{{ memoryPercent(node) }}% 已使用</p>
          </div>
          <div class="resource-tile">
            <div><span class="resource-icon"><HardDrive :size="16" /></span><span><small>根磁盘</small><b>{{ fmtBytes(diskUsed(node)) }} / {{ fmtBytes(diskTotal(node)) }}</b></span></div>
            <div class="usage-line"><span :class="usageClass(diskPercent(node))" :style="{ width: `${diskPercent(node)}%` }"></span></div>
            <p>{{ diskPercent(node) }}% 已使用</p>
          </div>
        </div>

        <div class="network-block">
          <div class="network-block-title"><span><Network :size="15" />网络接口</span><small>{{ node.networks?.length || 0 }} 个</small></div>
          <div v-if="node.networks?.length" class="interface-list">
            <div v-for="net in node.networks" :key="net.name">
              <span class="interface-name"><i></i>{{ net.name }}</span>
              <span><ArrowDownToLine :size="13" />{{ fmtBytes(net.rx_bytes) }}</span>
              <span><ArrowUpFromLine :size="13" />{{ fmtBytes(net.tx_bytes) }}</span>
            </div>
          </div>
          <div v-else class="node-empty">暂无接口流量数据</div>
        </div>
      </article>
    </div>
    <div v-else class="panel node-empty large"><Server :size="24" /><span>还没有已注册的节点</span></div>
  </section>

  <section class="panel listener-panel">
    <div class="panel-title listener-title">
      <div><span class="eyebrow">SERVICE DISCOVERY</span><h2>监听端口</h2><p>Agent 以只读方式发现当前节点的 TCP 与 UDP 监听。</p></div>
      <div class="listener-controls">
        <div class="segmented">
          <button :class="{ active: protocol === 'all' }" @click="protocol = 'all'">全部 {{ tcpCount + udpCount }}</button>
          <button :class="{ active: protocol === 'tcp' }" @click="protocol = 'tcp'">TCP {{ tcpCount }}</button>
          <button :class="{ active: protocol === 'udp' }" @click="protocol = 'udp'">UDP {{ udpCount }}</button>
        </div>
        <n-input v-model:value="query" class="listener-search" clearable placeholder="搜索地址或端口">
          <template #prefix><Search :size="15" /></template>
        </n-input>
      </div>
    </div>

    <div v-if="listeners.length" class="table-wrap listener-table">
      <table>
        <thead><tr><th>协议</th><th>监听地址</th><th>端口</th><th>作用域</th></tr></thead>
        <tbody>
          <tr v-for="(row, idx) in listeners" :key="`${row.protocol}-${row.address}-${row.port}-${idx}`">
            <td><span class="protocol-pill">{{ row.protocol.toUpperCase() }}</span></td>
            <td><code>{{ row.address }}</code></td>
            <td><b>{{ row.port }}</b></td>
            <td><span class="listener-scope"><i :class="row.address.includes('127.0.0.1') || row.address === '::1' ? 'local' : 'network'"></i>{{ row.address.includes('127.0.0.1') || row.address === '::1' ? '仅本机' : '网络可达' }}</span></td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="empty-state"><Search :size="22" /><span>没有符合条件的监听端口</span></div>
  </section>
</template>
