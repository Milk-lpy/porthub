<script setup lang="ts">
import { computed, ref } from 'vue'
import { Activity, ArrowDownToLine, ArrowUpFromLine, Check, CircleHelp, Filter, Gauge, Globe2, RefreshCw, ShieldAlert } from '@lucide/vue'
import { NButton, NCollapseTransition, NPopover } from 'naive-ui'
import { useOpsStore } from '../stores/ops'

const emit = defineEmits<{ collect: []; notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const tab = ref<'overview' | 'connections' | 'source-audit' | 'alerts'>('overview')
const guideOpen = ref(false)
const activeAlerts = computed(() => ops.alerts.filter((alert) => alert.active))
const connections = computed(() => ops.metrics.connection_summary || [])
const sourceAudits = computed(() => ops.publicSourceAudits.records || [])
const sourceSummary = computed(() => ops.publicSourceAudits.summary || [])
const sourceIPFilter = ref('')
const mappingFilter = ref('')
const protocolFilter = ref('')
const auditLoading = ref(false)

function fmtBytes(value: unknown) {
  const size = Number(value || 0)
  if (size < 1024) return `${Math.round(size)} B`
  if (size < 1048576) return `${(size / 1024).toFixed(1)} KiB`
  if (size < 1073741824) return `${(size / 1048576).toFixed(1)} MiB`
  return `${(size / 1073741824).toFixed(1)} GiB`
}

function shortTime(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '--' : date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function fmtCount(value: unknown) {
  return Number(value || 0).toLocaleString('zh-CN')
}

async function refreshSourceAudit() {
  auditLoading.value = true
  try {
    await ops.refreshPublicSourceAudits({
      source_ip: sourceIPFilter.value.trim(),
      mapping_id: mappingFilter.value.trim(),
      protocol: protocolFilter.value,
    })
    emit('notify', '公网来源审计已刷新')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  } finally {
    auditLoading.value = false
  }
}

function clearSourceAuditFilters() {
  sourceIPFilter.value = ''
  mappingFilter.value = ''
  protocolFilter.value = ''
  void refreshSourceAudit()
}

async function acknowledge(id: number) {
  try {
    await ops.acknowledgeAlert(id)
    emit('notify', '告警已确认，状态恢复后会自动转为已解决')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}
</script>

<template>
  <section class="panel monitoring-panel">
    <div class="panel-title monitoring-title">
      <div><span class="eyebrow">OBSERVABILITY</span><h2>流量与连接</h2><p>实时数据来自 Edge 内核计数器，不采集业务数据包内容</p></div>
      <div class="page-actions"><n-button size="small" secondary @click="guideOpen = !guideOpen"><CircleHelp :size="16" />使用向导</n-button><n-button size="small" secondary @click="emit('collect')"><Gauge :size="16" />保存当前样本</n-button></div>
    </div>

    <n-collapse-transition :show="guideOpen">
      <div class="monitor-guide"><b>怎么看这页</b><span>“实时概览”用于看带宽趋势；“当前连接”用于定位正在发生的连接；“公网来源审计”保存最近 {{ ops.publicSourceAudits.retention_days }} 天的公网访问来源；“系统告警”只提示需要处理的容量或资源问题。</span></div>
    </n-collapse-transition>

    <div class="monitor-summary">
      <div><span class="metric-icon green"><ArrowDownToLine :size="18" /></span><p><small>实时接收</small><b>{{ fmtBytes(ops.metrics.rx_bytes_per_second) }}/s</b></p></div>
      <div><span class="metric-icon cyan"><ArrowUpFromLine :size="18" /></span><p><small>实时发送</small><b>{{ fmtBytes(ops.metrics.tx_bytes_per_second) }}/s</b></p></div>
      <div><span class="metric-icon blue"><Activity :size="18" /></span><p><small class="term-label">当前连接<n-popover trigger="hover"><template #trigger><CircleHelp :size="13" /></template>conntrack 是 Linux 记录连接状态的内核模块，这里只显示数量和必要元数据。</n-popover></small><b>{{ Number(ops.metrics.connections || 0).toLocaleString() }}</b></p></div>
      <div><span class="metric-icon amber"><ShieldAlert :size="18" /></span><p><small>未解决告警</small><b>{{ activeAlerts.length + (ops.metrics.alerts?.length || 0) }}</b></p></div>
    </div>

    <div class="segmented monitor-tabs">
      <button :class="{ active: tab === 'overview' }" @click="tab = 'overview'">实时概览</button>
      <button :class="{ active: tab === 'connections' }" @click="tab = 'connections'">当前连接 {{ connections.length }}</button>
      <button :class="{ active: tab === 'source-audit' }" @click="tab = 'source-audit'"><Globe2 :size="14" />公网来源审计 {{ ops.publicSourceAudits.total }}</button>
      <button :class="{ active: tab === 'alerts' }" @click="tab = 'alerts'">系统告警 {{ activeAlerts.length }}</button>
    </div>

    <div v-if="tab === 'overview'" class="monitor-overview">
      <article class="monitor-section">
        <header><div><b>映射流量排行</b><span>累计计数来自 nftables</span></div><i :class="['live-indicator', { online: ops.monitorConnected }]">{{ ops.monitorConnected ? '实时' : '重连中' }}</i></header>
        <div v-if="ops.rank.length" class="traffic-list">
          <div v-for="row in ops.rank" :key="`${row.protocol}-${row.port}-${row.target}`" class="traffic-row">
            <div class="traffic-meta"><strong><span class="protocol-pill">{{ row.protocol.toUpperCase() }}</span> {{ row.port }} → {{ row.target }}</strong><span>{{ fmtBytes(row.bytes) }}</span></div>
            <div class="bar"><span :style="{ width: `${Math.max(3, Math.round((row.bytes * 100) / Math.max(...ops.rank.map((item) => item.bytes), 1)))}%` }"></span></div>
          </div>
        </div>
        <div v-else class="empty-state"><Activity :size="21" /><span>映射尚未产生流量</span></div>
      </article>
      <article class="monitor-section sample-history">
        <header><div><b>最近历史样本</b><span>每分钟由 Core 保存</span></div></header>
        <div v-if="ops.samples.length" class="sample-list">
          <div v-for="row in ops.samples" :key="row.ts"><span>{{ shortTime(row.ts) }}</span><b><i class="rx"></i>{{ fmtBytes(row.rx_bytes_per_second) }}/s</b><b><i class="tx"></i>{{ fmtBytes(row.tx_bytes_per_second) }}/s</b><em>{{ row.connections || 0 }} 连接</em></div>
        </div>
        <div v-else class="empty-state">等待第一个历史样本</div>
      </article>
    </div>

    <div v-else-if="tab === 'connections'" class="table-wrap monitor-table">
      <table><thead><tr><th>来源地址</th><th>映射</th><th>协议 / 公网端口</th><th>内网目标</th><th>状态</th><th>字节</th></tr></thead><tbody>
        <tr v-for="row in connections" :key="`${row.source_ip}-${row.mapping_id}-${row.public_port}-${row.observed_at}`"><td><code>{{ row.source_ip }}</code></td><td><b>{{ row.mapping }}</b></td><td><span class="protocol-pill">{{ row.protocol.toUpperCase() }}</span> {{ row.public_port }}</td><td><code>{{ row.target }}</code></td><td><span class="state-pill enabled">{{ row.state }}</span></td><td>{{ fmtBytes(row.bytes) }}</td></tr>
      </tbody></table>
      <div v-if="!connections.length" class="empty-state"><Activity :size="22" /><span>当前没有可归属到 PortHub 映射的连接</span></div>
    </div>

    <div v-else-if="tab === 'source-audit'" class="source-audit-view">
      <div class="source-audit-toolbar">
        <div class="source-audit-heading"><span class="metric-icon cyan"><Globe2 :size="17" /></span><div><b>公网来源 IP 审计</b><span>Core 按分钟保存 Edge 当前连接摘要，只记录来源、映射、协议、端口和字节数。</span></div></div>
        <div class="source-audit-actions"><n-button size="small" secondary :loading="auditLoading" @click="refreshSourceAudit"><RefreshCw :size="15" />刷新</n-button><n-button size="small" quaternary @click="clearSourceAuditFilters">清空筛选</n-button></div>
      </div>
      <div class="source-audit-filters">
        <label><span>来源 IP</span><input v-model="sourceIPFilter" :disabled="!ops.publicSourceAudits.exact_source_ip" type="text" :placeholder="ops.publicSourceAudits.exact_source_ip ? '例如 203.0.113.8' : '运维角色可按精确 IP 筛选'" @keyup.enter="refreshSourceAudit"></label>
        <label><span>映射名称或 ID</span><input v-model="mappingFilter" type="text" placeholder="例如 Minecraft" @keyup.enter="refreshSourceAudit"></label>
        <label><span>协议</span><select v-model="protocolFilter" @change="refreshSourceAudit"><option value="">全部协议</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
        <div class="source-audit-hint"><Filter :size="14" />{{ ops.publicSourceAudits.exact_source_ip ? '当前角色可查看精确来源地址' : '当前角色默认显示来源地址掩码' }}</div>
      </div>
      <div class="source-audit-summary">
        <article v-for="item in sourceSummary.slice(0, 5)" :key="`${item.source_ip_masked}-${item.last_seen_at}`" class="source-summary-card"><span class="source-rank">{{ sourceSummary.indexOf(item) + 1 }}</span><div><b>{{ item.source_ip }}</b><small>{{ fmtCount(item.observations) }} 次观察 · {{ fmtBytes(item.bytes) }}</small></div><time>{{ shortTime(item.last_seen_at) }}</time></article>
        <div v-if="!sourceSummary.length" class="source-audit-empty">还没有公网来源记录。保持映射有访问后，Core 会在下一次采样写入。</div>
      </div>
      <div class="table-wrap monitor-table source-audit-table">
        <table><thead><tr><th>来源 IP</th><th>最后观察</th><th>映射</th><th>协议 / 端口</th><th>内网目标</th><th>观察次数</th><th>字节</th></tr></thead><tbody>
          <tr v-for="row in sourceAudits" :key="row.id"><td><code>{{ row.source_ip }}</code></td><td>{{ shortTime(row.last_seen_at) }}</td><td><b>{{ row.mapping || row.mapping_id || '--' }}</b><small v-if="row.mapping_id" class="table-subline">{{ row.mapping_id }}</small></td><td><span class="protocol-pill">{{ row.protocol.toUpperCase() }}</span> {{ row.public_port }}</td><td><code>{{ row.target }}</code></td><td>{{ fmtCount(row.observations) }}</td><td>{{ fmtBytes(row.bytes) }}</td></tr>
        </tbody></table>
        <div v-if="!sourceAudits.length" class="empty-state"><Globe2 :size="22" /><span>筛选范围内没有公网来源记录</span></div>
      </div>
    </div>

    <div v-else class="alert-history">
      <article v-for="alert in ops.alerts" :key="alert.id" :class="['alert-row', alert.severity, { resolved: !alert.active }]">
        <span><ShieldAlert :size="17" /></span><div><b>{{ alert.title }}</b><p>{{ alert.detail }}</p><small>{{ alert.source }} · {{ shortTime(alert.last_seen_at) }} · {{ alert.active ? '仍需处理' : '已恢复' }}</small></div>
        <n-button v-if="alert.active && !alert.acknowledged_at" size="tiny" secondary @click="acknowledge(alert.id)"><Check :size="14" />确认</n-button><span v-else class="state-pill neutral">{{ alert.acknowledged_at ? '已确认' : '已解决' }}</span>
      </article>
      <div v-if="!ops.alerts.length" class="empty-state"><ShieldAlert :size="22" /><span>当前没有系统告警</span></div>
    </div>
  </section>
</template>
