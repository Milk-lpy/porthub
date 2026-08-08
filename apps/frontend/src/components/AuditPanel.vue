<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  Activity,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock3,
  Filter,
  History,
  Search,
  ShieldAlert,
  UserRound,
  X,
} from '@lucide/vue'
import { NButton, NInput, NSelect } from 'naive-ui'
import { useOpsStore, type AuditRecord } from '../stores/ops'

const ops = useOpsStore()
const keyword = ref('')
const actor = ref('')
const category = ref('all')
const severity = ref('all')
const result = ref('all')
const range = ref('all')
const limit = ref(200)
const loading = ref(false)
const error = ref('')
const selected = ref<AuditRecord | null>(null)

const categoryOptions = [
  { label: '全部类别', value: 'all' },
  { label: '映射与入口', value: 'mapping' },
  { label: '配置下发', value: 'config' },
  { label: '身份与权限', value: 'auth' },
  { label: '域名与证书', value: 'domain' },
  { label: '安全策略', value: 'security' },
  { label: '节点与网络', value: 'network' },
  { label: '资源发现', value: 'inventory' },
  { label: '反向代理', value: 'proxy' },
  { label: '备份恢复', value: 'backup' },
  { label: '服务管理', value: 'service' },
  { label: '系统管理', value: 'system' },
  { label: '其他操作', value: 'other' },
]
const severityOptions = [
  { label: '全部风险级别', value: 'all' },
  { label: '普通记录', value: 'info' },
  { label: '需关注', value: 'warning' },
  { label: '高风险', value: 'critical' },
]
const resultOptions = [
  { label: '全部结果', value: 'all' },
  { label: '已完成', value: 'success' },
  { label: '失败', value: 'failure' },
  { label: '已记录', value: 'neutral' },
]
const rangeOptions = [
  { label: '全部时间', value: 'all' },
  { label: '最近 24 小时', value: '24h' },
  { label: '最近 7 天', value: '7d' },
  { label: '最近 30 天', value: '30d' },
]
const limitOptions = [
  { label: '显示 100 条', value: 100 },
  { label: '显示 200 条', value: 200 },
  { label: '显示 500 条', value: 500 },
]

const records = computed(() => ops.audit as AuditRecord[])
const warningCount = computed(() => records.value.filter((row) => row.severity === 'warning' || row.severity === 'critical').length)
const successCount = computed(() => records.value.filter((row) => row.result === 'success').length)
const systemCount = computed(() => records.value.filter((row) => row.system || row.actor === 'system').length)
const latestRecord = computed(() => records.value[0])
const hasFilters = computed(() => Boolean(keyword.value || actor.value || category.value !== 'all' || severity.value !== 'all' || result.value !== 'all' || range.value !== 'all'))

function dateWindow() {
  if (range.value === 'all') return {}
  const days = range.value === '24h' ? 1 / 24 : range.value === '7d' ? 7 : 30
  const now = Date.now()
  return { from: new Date(now - days * 24 * 60 * 60 * 1000).toISOString(), to: new Date(now).toISOString() }
}

async function loadAudit() {
  loading.value = true
  error.value = ''
  try {
    await ops.refreshAudit({
      q: keyword.value.trim(),
      actor: actor.value.trim(),
      category: category.value,
      severity: severity.value,
      result: result.value,
      limit: limit.value,
      ...dateWindow(),
    })
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

function clearFilters() {
  keyword.value = ''
  actor.value = ''
  category.value = 'all'
  severity.value = 'all'
  result.value = 'all'
  range.value = 'all'
  void loadAudit()
}

function actionLabel(row: AuditRecord) {
  return row.action_label || row.action || '未命名操作'
}

function categoryLabel(row: AuditRecord) {
  return row.category_label || '其他操作'
}

function severityLabel(row: AuditRecord) {
  return row.severity_label || (row.severity === 'critical' ? '高风险' : row.severity === 'warning' ? '需关注' : '普通')
}

function resultLabel(row: AuditRecord) {
  return row.result_label || (row.result === 'failure' ? '失败' : row.result === 'success' ? '已完成' : '已记录')
}

function actorLabel(row: AuditRecord) {
  if (row.system || row.actor === 'system') return '系统任务'
  if (row.actor?.startsWith('agent:')) return `Agent · ${row.actor.slice(6)}`
  return row.actor || '未知身份'
}

function targetLabel(row: AuditRecord) {
  return row.target || row.detail || '系统操作'
}

function summaryLabel(row: AuditRecord) {
  return row.summary || `${actionLabel(row)}：${targetLabel(row)}`
}

function formatTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value || '--'
  return date.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function relativeTime(value: string) {
  const timestamp = new Date(value).getTime()
  if (!Number.isFinite(timestamp)) return '--'
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000))
  if (seconds < 60) return '刚刚'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
  return `${Math.floor(seconds / 86400)} 天前`
}

function openDetail(row: AuditRecord) {
  selected.value = row
}

function closeDetail() {
  selected.value = null
}

onMounted(() => {
  void loadAudit()
})
</script>

<template>
  <section class="panel audit-page">
    <div class="audit-page-head">
      <div class="panel-title audit-title-block">
        <div class="audit-title-icon"><History :size="22" /></div>
        <div>
          <span class="eyebrow">AUDIT TRAIL</span>
          <h2>操作审计</h2>
          <p>把登录、配置修改、服务下发和安全操作整理成一条清晰的时间线。</p>
        </div>
      </div>
      <div class="audit-head-note"><ShieldAlert :size="16" />只记录操作元数据，不记录业务数据包内容</div>
    </div>

    <div class="audit-stats">
      <div class="audit-stat"><span class="audit-stat-icon green"><Activity :size="17" /></span><div><small>当前结果集</small><strong>{{ records.length }}</strong><em>条可查看记录</em></div></div>
      <div class="audit-stat"><span class="audit-stat-icon amber"><ShieldAlert :size="17" /></span><div><small>需要关注</small><strong>{{ warningCount }}</strong><em>失败或高风险操作</em></div></div>
      <div class="audit-stat"><span class="audit-stat-icon cyan"><CheckCircle2 :size="17" /></span><div><small>已完成操作</small><strong>{{ successCount }}</strong><em>有明确完成结果</em></div></div>
      <div class="audit-stat"><span class="audit-stat-icon blue"><UserRound :size="17" /></span><div><small>系统任务</small><strong>{{ systemCount }}</strong><em>后台自动执行</em></div></div>
    </div>

    <div class="audit-guide"><Clock3 :size="16" /><span><b>怎么看：</b>先看颜色和结果，再看“操作者”和“对象”；需要核对底层信息时，点击记录右侧的“详情”。</span></div>

    <div class="audit-toolbar">
      <div class="audit-search"><NInput v-model:value="keyword" clearable placeholder="搜索操作、对象或详细信息" @keyup.enter="loadAudit"><template #prefix><Search :size="16" /></template></NInput></div>
      <div class="audit-filter"><NInput v-model:value="actor" clearable placeholder="操作者" @keyup.enter="loadAudit"><template #prefix><UserRound :size="15" /></template></NInput></div>
      <NSelect v-model:value="category" :options="categoryOptions" />
      <NSelect v-model:value="severity" :options="severityOptions" />
      <NSelect v-model:value="result" :options="resultOptions" />
      <NSelect v-model:value="range" :options="rangeOptions" />
      <NSelect v-model:value="limit" :options="limitOptions" />
      <div class="audit-toolbar-actions">
        <NButton type="primary" :loading="loading" @click="loadAudit"><Filter :size="15" />筛选</NButton>
        <NButton secondary :disabled="!hasFilters" @click="clearFilters">清空</NButton>
      </div>
    </div>

    <div v-if="error" class="audit-error"><ShieldAlert :size="17" /><span>{{ error }}</span><button type="button" @click="error = ''"><X :size="15" /></button></div>

    <div class="audit-list-head"><span><b>{{ records.length }}</b> 条记录 <em v-if="latestRecord">· 最新 {{ relativeTime(latestRecord.ts) }}</em></span><span class="audit-list-hint">点击任意记录查看完整详情</span></div>

    <div v-if="records.length" class="audit-feed">
      <article v-for="row in records" :key="row.id || `${row.ts}-${row.actor}-${row.action}-${row.detail}`" class="audit-entry" :class="[`severity-${row.severity || 'info'}`, `result-${row.result || 'neutral'}`]" tabindex="0" @click="openDetail(row)" @keydown.enter="openDetail(row)">
        <div class="audit-entry-mark">
          <ShieldAlert v-if="row.severity === 'critical' || row.severity === 'warning'" :size="17" />
          <CheckCircle2 v-else-if="row.result === 'success'" :size="17" />
          <CircleDot v-else :size="17" />
        </div>
        <div class="audit-entry-main">
          <div class="audit-entry-top"><div class="audit-action"><b>{{ actionLabel(row) }}</b><code>{{ row.action }}</code></div><span class="audit-result" :class="`result-${row.result || 'neutral'}`">{{ resultLabel(row) }}</span></div>
          <p>{{ summaryLabel(row) }}</p>
          <div class="audit-entry-meta"><span class="audit-category">{{ categoryLabel(row) }}</span><span><UserRound :size="12" />{{ actorLabel(row) }}</span><span><Clock3 :size="12" />{{ formatTime(row.ts) }}</span></div>
        </div>
        <button class="audit-detail-button" type="button" title="查看完整详情" @click.stop="openDetail(row)">详情<ChevronRight :size="15" /></button>
      </article>
    </div>
    <div v-else class="audit-empty"><History :size="30" /><b>没有匹配的审计记录</b><span>{{ hasFilters ? '试试放宽筛选条件，或清空筛选重新查看。' : '系统还没有产生可展示的管理操作。' }}</span></div>

    <div class="audit-footnote"><Filter :size="14" /><span>审计记录按时间倒序排列，最多显示 {{ limit }} 条；原始操作名和详情只在详情面板中展开，便于快速浏览。</span></div>

    <Transition name="audit-detail">
      <div v-if="selected" class="audit-detail-backdrop" @click.self="closeDetail">
        <aside class="audit-detail-panel" role="dialog" aria-modal="true" aria-label="审计记录详情">
          <header class="audit-detail-head"><div><span class="eyebrow">EVENT DETAIL</span><h3>{{ actionLabel(selected) }}</h3><p>{{ formatTime(selected.ts) }}</p></div><button class="icon-button" type="button" title="关闭详情" aria-label="关闭详情" @click="closeDetail"><X :size="19" /></button></header>
          <div class="audit-detail-status" :class="`severity-${selected.severity || 'info'}`"><span><ShieldAlert v-if="selected.severity === 'critical' || selected.severity === 'warning'" :size="17" /><CheckCircle2 v-else-if="selected.result === 'success'" :size="17" /><CircleDot v-else :size="17" />{{ severityLabel(selected) }}</span><b>{{ resultLabel(selected) }}</b></div>
          <div class="audit-detail-grid">
            <div><small>操作者</small><strong>{{ actorLabel(selected) }}</strong></div>
            <div><small>操作类别</small><strong>{{ categoryLabel(selected) }}</strong></div>
            <div><small>影响对象</small><strong>{{ targetLabel(selected) }}</strong></div>
            <div><small>记录编号</small><strong>#{{ selected.id || '--' }}</strong></div>
          </div>
          <div class="audit-detail-section"><small>可读摘要</small><p>{{ summaryLabel(selected) }}</p></div>
          <div class="audit-detail-section"><small>原始操作名</small><code>{{ selected.action || '--' }}</code></div>
          <div class="audit-detail-section"><small>完整详情</small><pre>{{ selected.detail || '该操作没有附加详情。' }}</pre></div>
          <div class="audit-detail-actions"><NButton secondary @click="closeDetail">关闭</NButton></div>
        </aside>
      </div>
    </Transition>
  </section>
</template>
