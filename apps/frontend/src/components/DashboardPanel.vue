<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpFromLine,
  Boxes,
  CheckCircle2,
  CircleGauge,
  Clock3,
  Cpu,
  HardDrive,
  MemoryStick,
  RadioTower,
  Route,
  Send,
  Server,
  ShieldCheck,
  Waypoints,
} from '@lucide/vue'
import { NButton } from 'naive-ui'
import { useOpsStore } from '../stores/ops'

type EChartsLiteModule = typeof import('../charts')
type EChartsInstance = import('../charts').ECharts

const props = defineProps<{ dark: boolean }>()
const emit = defineEmits<{ collectTraffic: [] }>()
const ops = useOpsStore()
const topologyEl = ref<HTMLElement>()
const trendEl = ref<HTMLElement>()
let echartsModule: EChartsLiteModule | undefined
let topologyChart: EChartsInstance | undefined
let trendChart: EChartsInstance | undefined

const enabledMappings = computed(() => ops.mappings.filter((row) => row.Enabled).length)
const onlineNodes = computed(() => ops.nodeStatuses.filter((row) => row.online !== false).length)
const healthy = computed(() => Boolean(ops.status.core) && Boolean(ops.status.edge))
const recentAudit = computed(() => ops.audit.slice(0, 5))
const liveAlerts = computed(() => ops.metrics.alerts || [])

// Build an SVG polyline "points" string from the last 16 traffic samples.
// Returns '' when there is not enough data, so the sparkline is simply hidden.
function sparkPoints(key: 'rx_bytes_per_second' | 'tx_bytes_per_second') {
  const series = [...ops.samples].reverse().slice(-16).map((row) => Number(row[key] || 0))
  if (series.length < 2) return ''
  const max = Math.max(...series, 1)
  const w = 62
  const h = 24
  const step = w / (series.length - 1)
  return series
    .map((v, i) => `${(i * step).toFixed(1)},${(h - (v / max) * (h - 3) - 1).toFixed(1)}`)
    .join(' ')
}
const rxSpark = computed(() => sparkPoints('rx_bytes_per_second'))
const txSpark = computed(() => sparkPoints('tx_bytes_per_second'))

const palette = computed(() => props.dark
  ? { text: '#dce7e2', muted: '#81918b', line: 'rgba(120,210,170,.18)', split: 'rgba(120,210,170,.08)', rx: '#34e5a0', tx: '#28c8e0', rxArea: 'rgba(52,229,160,.12)', nodeFill: 'rgba(28,39,34,.9)', amber: '#e0b24a' }
  : { text: '#18221e', muted: '#6c7a75', line: '#cad5d0', split: '#e4ebe7', rx: '#2f9d68', tx: '#268ba6', rxArea: 'rgba(47,157,104,.08)', nodeFill: '#f7f9f8', amber: '#a8791e' })

async function ensureECharts() {
  echartsModule = echartsModule || await import('../charts')
  return echartsModule
}

async function renderCharts() {
  await Promise.all([renderTopology(), renderTrend()])
}

async function renderTopology() {
  if (!topologyEl.value) return
  const echarts = await ensureECharts()
  topologyChart = topologyChart || echarts.init(topologyEl.value)
  const colors = palette.value
  topologyChart.setOption({
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item' },
    series: [{
      type: 'graph',
      layout: 'none',
      roam: false,
      symbol: 'roundRect',
      symbolSize: [94, 52],
      label: { show: true, color: colors.text, fontSize: 12, fontWeight: 600 },
      edgeSymbol: ['none', 'arrow'],
      edgeSymbolSize: 7,
      edgeLineStyle: { color: colors.line, width: 2 },
      data: [
        { name: 'Internet', x: 10, y: 80, itemStyle: { color: colors.nodeFill, borderColor: colors.tx, borderWidth: 1 } },
        { name: 'VPS Edge', x: 190, y: 80, itemStyle: { color: colors.nodeFill, borderColor: colors.rx, borderWidth: 1.5, shadowColor: colors.rx, shadowBlur: 10 } },
        { name: 'WireGuard', x: 370, y: 80, itemStyle: { color: colors.nodeFill, borderColor: colors.tx, borderWidth: 1 } },
        { name: 'Core .12', x: 550, y: 80, itemStyle: { color: colors.nodeFill, borderColor: colors.rx, borderWidth: 1.5, shadowColor: colors.rx, shadowBlur: 10 } },
        { name: `${Math.max(ops.nodeStatuses.length, 1)} 个节点`, x: 730, y: 80, itemStyle: { color: colors.nodeFill, borderColor: colors.amber, borderWidth: 1 } },
      ],
      links: [
        { source: 'Internet', target: 'VPS Edge' },
        { source: 'VPS Edge', target: 'WireGuard' },
        { source: 'WireGuard', target: 'Core .12' },
        { source: 'Core .12', target: `${Math.max(ops.nodeStatuses.length, 1)} 个节点` },
      ],
    }],
  }, true)
}

async function renderTrend() {
  if (!trendEl.value) return
  const echarts = await ensureECharts()
  trendChart = trendChart || echarts.init(trendEl.value)
  const colors = palette.value
  const data = [...ops.samples].reverse()
  trendChart.setOption({
    backgroundColor: 'transparent',
    grid: { left: 54, right: 18, top: 24, bottom: 32 },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: data.map((row) => shortTime(row.ts)),
      axisLabel: { color: colors.muted },
      axisTick: { show: false },
      axisLine: { lineStyle: { color: colors.line } },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: colors.muted, formatter: (value: number) => fmtBytes(value) },
      splitLine: { lineStyle: { color: colors.split } },
    },
    tooltip: { trigger: 'axis', valueFormatter: (value: number) => fmtBytes(value) },
    series: [
      { type: 'line', smooth: true, data: data.map((row) => row.rx_bytes_per_second || 0), showSymbol: false, lineStyle: { color: colors.rx, width: 2.5 }, itemStyle: { color: colors.rx }, areaStyle: { color: colors.rxArea } },
      { type: 'line', smooth: true, data: data.map((row) => row.tx_bytes_per_second || 0), showSymbol: false, lineStyle: { color: colors.tx, width: 2 }, itemStyle: { color: colors.tx } },
    ],
  }, true)
}

function fmtBytes(value: number) {
  if (!Number.isFinite(value) || value < 1024) return `${Math.max(0, value || 0)} B`
  if (value < 1048576) return `${(value / 1024).toFixed(1)} KiB`
  if (value < 1073741824) return `${(value / 1048576).toFixed(1)} MiB`
  return `${(value / 1073741824).toFixed(1)} GiB`
}

function shortTime(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '--' : date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
}

function percent(used: unknown, total: unknown) {
  const left = Number(used || 0)
  const right = Number(total || 0)
  return right > 0 ? `${Math.round(left * 100 / right)}%` : '--'
}

function auditValue(row: Record<string, unknown>, key: string) {
  return String(row[key] ?? '--')
}

function auditDisplay(row: Record<string, unknown>, primary: string, fallback: string) {
  return String(row[primary] ?? row[fallback] ?? '--')
}

function resizeCharts() {
  topologyChart?.resize()
  trendChart?.resize()
}

watch(() => [ops.samples, ops.nodeStatuses, props.dark], () => nextTick(renderCharts), { deep: true })

onMounted(() => {
  window.addEventListener('resize', resizeCharts)
  void nextTick(renderCharts)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', resizeCharts)
  topologyChart?.dispose()
  trendChart?.dispose()
})
</script>

<template>
  <div class="dashboard">
    <section class="status-hero">
      <div class="status-main">
        <span :class="['status-orbit', { healthy }]"><CheckCircle2 :size="22" /></span>
        <div>
          <span class="eyebrow">系统运行态</span>
          <h2>{{ healthy ? '公网入口链路运行正常' : '正在确认节点状态' }}</h2>
          <p>Edge 经由 WireGuard 与 Core 保持连接，现有规则独立持续运行。</p>
        </div>
      </div>
      <div class="hero-actions">
        <RouterLink class="command-link secondary" to="/mappings"><Route :size="17" />查看映射</RouterLink>
        <RouterLink class="command-link primary" to="/publish"><Send :size="17" />发布服务</RouterLink>
      </div>
    </section>

    <section class="metric-grid">
      <article class="metric-card">
        <span class="metric-icon green"><Route :size="19" /></span>
        <div><span>生效映射</span><b>{{ enabledMappings }}</b><small>共 {{ ops.mappings.length }} 条规则</small></div>
      </article>
      <article class="metric-card">
        <span class="metric-icon cyan"><Server :size="19" /></span>
        <div><span>在线节点</span><b>{{ onlineNodes }}</b><small>已注册 {{ ops.nodeStatuses.length }} 个</small></div>
      </article>
      <article class="metric-card">
        <span class="metric-icon amber"><Activity :size="19" /></span>
        <div><span>当前连接</span><b>{{ Number(ops.metrics.connections || 0).toLocaleString() }}</b><small>连接跟踪实时摘要</small></div>
      </article>
      <article class="metric-card">
        <span class="metric-icon green"><ArrowDownToLine :size="19" /></span>
        <div><span>实时接收</span><b>{{ fmtBytes(Number(ops.metrics.rx_bytes_per_second || 0)) }}/s</b><small>{{ ops.metrics.public_interface || '公网接口' }}</small></div>
        <svg v-if="rxSpark" class="metric-spark" viewBox="0 0 62 24" preserveAspectRatio="none" aria-hidden="true"><polyline fill="none" stroke="var(--green)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" :points="rxSpark" /></svg>
      </article>
      <article class="metric-card">
        <span class="metric-icon cyan"><ArrowUpFromLine :size="19" /></span>
        <div><span>实时发送</span><b>{{ fmtBytes(Number(ops.metrics.tx_bytes_per_second || 0)) }}/s</b><small>{{ ops.monitorConnected ? '实时连接已建立' : '正在重连监控' }}</small></div>
        <svg v-if="txSpark" class="metric-spark" viewBox="0 0 62 24" preserveAspectRatio="none" aria-hidden="true"><polyline fill="none" stroke="var(--cyan)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" :points="txSpark" /></svg>
      </article>
      <article class="metric-card">
        <span class="metric-icon blue"><Cpu :size="19" /></span>
        <div><span>Edge CPU</span><b>{{ Number(ops.metrics.cpu_percent || 0).toFixed(1) }}%</b><small>负载 {{ Number(ops.metrics.load_1 || 0).toFixed(2) }}</small></div>
      </article>
      <article class="metric-card">
        <span class="metric-icon amber"><MemoryStick :size="19" /></span>
        <div><span>Edge 内存</span><b>{{ percent(ops.metrics.memory_used_bytes, ops.metrics.memory_total_bytes) }}</b><small>{{ fmtBytes(Number(ops.metrics.memory_used_bytes || 0)) }} 已用</small></div>
      </article>
      <article class="metric-card">
        <span class="metric-icon cyan"><HardDrive :size="19" /></span>
        <div><span>Edge 磁盘</span><b>{{ percent(ops.metrics.disk_used_bytes, ops.metrics.disk_total_bytes) }}</b><small>{{ fmtBytes(Number(ops.metrics.disk_used_bytes || 0)) }} 已用</small></div>
      </article>
    </section>

    <section class="dashboard-grid topology-row">
      <article class="panel topology-panel">
        <div class="panel-title">
          <div><span class="eyebrow">LIVE TOPOLOGY</span><h2>入口链路</h2></div>
          <span class="panel-status"><i class="status-dot online"></i>WireGuard 已连接</span>
        </div>
        <div ref="topologyEl" class="chart topology-chart"></div>
        <div class="topology-legend">
          <span><i class="legend-dot green"></i>正常</span>
          <span><i class="legend-dot cyan"></i>加密链路</span>
          <span><i class="legend-dot amber"></i>内网资源</span>
        </div>
      </article>

      <article class="panel system-panel">
        <div class="panel-title"><div><span class="eyebrow">CONTROL PLANE</span><h2>节点状态</h2></div><Waypoints :size="19" /></div>
        <div class="system-list">
          <div><span class="system-symbol green"><Server :size="18" /></span><span><b>Core</b><small>192.0.2.12</small></span><em><i class="status-dot online"></i>{{ ops.status.core || 'online' }}</em></div>
          <div><span class="system-symbol cyan"><RadioTower :size="18" /></span><span><b>Edge</b><small>203.0.113.10</small></span><em><i class="status-dot online"></i>{{ ops.status.edge || 'online' }}</em></div>
          <div><span class="system-symbol blue"><ShieldCheck :size="18" /></span><span><b>WireGuard</b><small>wg-porthub</small></span><em><i class="status-dot online"></i>connected</em></div>
          <div><span class="system-symbol amber"><Boxes :size="18" /></span><span><b>Agent</b><small>资源发现与状态采集</small></span><em>{{ onlineNodes }}/{{ ops.nodeStatuses.length }}</em></div>
        </div>
        <RouterLink class="text-link" to="/nodes">查看全部节点 <ArrowRight :size="15" /></RouterLink>
      </article>
    </section>

    <section class="dashboard-grid detail-row">
      <article class="panel traffic-panel">
        <div class="panel-title">
          <div><span class="eyebrow">LIVE TRAFFIC</span><h2>公网接口收发速率</h2></div>
          <n-button size="small" secondary @click="emit('collectTraffic')"><CircleGauge :size="16" />采集样本</n-button>
        </div>
        <div ref="trendEl" class="chart traffic-chart"></div>
      </article>

      <article class="panel audit-panel">
        <div class="panel-title"><div><span class="eyebrow">ALERTS & ACTIVITY</span><h2>告警与最近变更</h2></div><Clock3 :size="19" /></div>
        <div v-if="liveAlerts.length" class="dashboard-alerts">
          <div v-for="alert in liveAlerts.slice(0, 3)" :key="alert.fingerprint" :class="alert.severity"><b>{{ alert.title }}</b><span>{{ alert.detail }}</span></div>
        </div>
        <div v-if="recentAudit.length" class="audit-list">
          <div v-for="(row, index) in recentAudit" :key="String(row.id || index)">
            <span class="audit-marker"></span>
            <span><b>{{ auditDisplay(row, 'action_label', 'action') }}</b><small>{{ auditDisplay(row, 'summary', 'detail') }}</small></span>
            <time>{{ shortTime(auditValue(row, 'ts')) }}</time>
          </div>
        </div>
        <div v-else class="empty-state"><Activity :size="24" /><span>暂无配置变更</span></div>
        <RouterLink class="text-link" to="/audit">查看完整审计 <ArrowRight :size="15" /></RouterLink>
      </article>
    </section>
  </div>
</template>
