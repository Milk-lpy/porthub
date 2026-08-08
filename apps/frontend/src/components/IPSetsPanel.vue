<script setup lang="ts">
import { ref } from 'vue'
import { ChevronDown, CircleHelp, CloudDownload, Plus, RefreshCw, ShieldCheck, Trash2 } from '@lucide/vue'
import { NButton, NCollapseTransition, NInput, NInputNumber, NPopover, NPopconfirm, NSwitch } from 'naive-ui'
import { useOpsStore, type IPFeed } from '../stores/ops'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const tab = ref<'sets' | 'feeds'>('sets')
const formOpen = ref(false)
const advancedOpen = ref(false)
const setForm = ref({ name: '', kind: 'custom', action: 'deny', cidrs: '', enabled: true })
const feedForm = ref({ name: '', kind: 'geoip' as 'geoip' | 'asn', action: 'deny' as 'allow' | 'deny', url: '', expected_sha256: '', refresh_hours: 24, enabled: true })
const preview = ref<Record<number, string>>({})
const busy = ref(0)

async function addSet() {
  try {
    await ops.importIPSet({ ...setForm.value, source: setForm.value.cidrs })
    formOpen.value = false
    emit('notify', 'IP 集合已保存，部署配置后才会在 Edge 生效')
  } catch (err) { emit('notify', message(err), 'error') }
}

async function addFeed() {
  try {
    await ops.createIPFeed(feedForm.value)
    formOpen.value = false
    emit('notify', '自动数据源已保存，建议先执行预览')
  } catch (err) { emit('notify', message(err), 'error') }
}

async function previewFeed(feed: IPFeed) {
  busy.value = feed.id
  try {
    const result = await ops.syncIPFeed(feed.id, true)
    preview.value[feed.id] = `检测到 ${result.count} 个网段 · SHA256 ${result.sha256.slice(0, 12)}…`
    emit('notify', '数据源预览成功，没有修改 IP 集合')
  } catch (err) { emit('notify', message(err), 'error') } finally { busy.value = 0 }
}

async function syncFeed(feed: IPFeed) {
  busy.value = feed.id
  try {
    const result = await ops.syncIPFeed(feed.id, false)
    preview.value[feed.id] = ''
    emit('notify', `已同步 ${result.count} 个网段到 IP 集合，尚未部署 Edge`)
  } catch (err) { emit('notify', message(err), 'error') } finally { busy.value = 0 }
}

async function toggleFeed(feed: IPFeed) {
  try { await ops.updateIPFeed({ ...feed, enabled: !feed.enabled }); emit('notify', feed.enabled ? '已暂停自动刷新' : '已启用自动刷新') } catch (err) { emit('notify', message(err), 'error') }
}

async function removeFeed(id: number) {
  try { await ops.deleteIPFeed(id); emit('notify', '数据源已删除，已生成的 IP 集合会保留') } catch (err) { emit('notify', message(err), 'error') }
}

async function removeSet(id: string) {
  try { await ops.deleteIPSet(id); emit('notify', 'IP 集合已删除，部署后 Edge 才会更新') } catch (err) { emit('notify', message(err), 'error') }
}

function message(err: unknown) { return err instanceof Error ? err.message : String(err) }
function shortTime(value?: string) { if (!value) return '从未'; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN') }
</script>

<template>
  <section class="panel ipsets-panel">
    <div class="panel-title"><div><span class="eyebrow">NETWORK POLICY</span><h2>IP 集合与数据源</h2><p>Core 整理网段，Edge 只接收轻量规则，不运行 GeoIP 数据库查询</p></div><div class="page-actions"><div class="segmented"><button :class="{ active: tab === 'sets' }" @click="tab = 'sets'">IP 集合</button><button :class="{ active: tab === 'feeds' }" @click="tab = 'feeds'">自动数据源</button></div><n-button type="primary" size="small" class="create-action" @click="formOpen = !formOpen"><Plus :size="16" />{{ formOpen ? '收起' : '新增' }}</n-button></div></div>
    <div class="catalog-summary"><div><small>IP 集合</small><b>{{ ops.ipSets.length }}</b></div><div><small>自动数据源</small><b>{{ ops.ipFeeds.length }}</b></div><div><small>已启用</small><b>{{ tab === 'sets' ? ops.ipSets.filter((row) => row.enabled).length : ops.ipFeeds.filter((row) => row.enabled).length }}</b></div><div><small>处理位置</small><b class="platform-name">Core</b></div></div>

    <n-collapse-transition :show="formOpen">
      <div v-if="tab === 'sets'" class="ipset-editor reveal-form"><div class="form-grid"><label>集合名称<n-input v-model:value="setForm.name" placeholder="例如：办公网络白名单" /></label><label>类型<select v-model="setForm.kind"><option value="custom">手工列表</option><option value="geoip">GeoIP 网段</option><option value="asn">ASN 网段</option></select></label><label>处理动作<select v-model="setForm.action"><option value="deny">拒绝</option><option value="allow">允许</option></select></label><label class="span-2">IP 或 CIDR<n-input v-model:value="setForm.cidrs" type="textarea" :autosize="{ minRows: 3, maxRows: 8 }" placeholder="每行一个，例如 203.0.113.0/24" /></label></div><footer><n-button type="primary" :disabled="!setForm.name || !setForm.cidrs" @click="addSet">保存集合</n-button></footer></div>
      <div v-else class="ipset-editor reveal-form"><div class="form-grid"><label>数据源名称<n-input v-model:value="feedForm.name" placeholder="例如：CN IPv4" /></label><label>数据类型<select v-model="feedForm.kind"><option value="geoip">GeoIP</option><option value="asn">ASN</option></select></label><label>处理动作<select v-model="feedForm.action"><option value="deny">拒绝</option><option value="allow">允许</option></select></label><label class="span-2"><span class="field-label">HTTPS CIDR 地址<n-popover trigger="hover"><template #trigger><CircleHelp :size="14" /></template>地址必须公开可达且每行返回一个 IP/CIDR；内网、回环和 HTTP 地址会被拒绝。</n-popover></span><n-input v-model:value="feedForm.url" placeholder="https://vendor.example/country/cn.txt" /></label></div><button class="advanced-toggle" @click="advancedOpen = !advancedOpen"><ChevronDown :size="15" :class="{ rotated: advancedOpen }" />校验与刷新 <span>默认每 24 小时</span></button><n-collapse-transition :show="advancedOpen"><div class="form-grid feed-advanced"><label>刷新间隔<n-input-number v-model:value="feedForm.refresh_hours" :min="1" :max="720" suffix="小时" /></label><label><span class="field-label">固定 SHA256<n-popover trigger="hover"><template #trigger><CircleHelp :size="14" /></template>可选。填写后内容哈希变化会拒绝同步，适合固定版本数据源。</n-popover></span><n-input v-model:value="feedForm.expected_sha256" placeholder="可选，64 位小写哈希" /></label></div></n-collapse-transition><footer><n-button type="primary" :disabled="!feedForm.name || !feedForm.url" @click="addFeed">保存数据源</n-button></footer></div>
    </n-collapse-transition>

    <div v-if="tab === 'sets'" class="ipset-grid"><article v-for="set in ops.ipSets" :key="set.id" class="ipset-card"><header><span><ShieldCheck :size="16" /><b>{{ set.name }}</b></span><span :class="['state-pill', set.enabled ? 'enabled' : 'disabled']">{{ set.enabled ? '启用' : '禁用' }}</span></header><div><span>{{ set.kind.toUpperCase() }}</span><b>{{ set.cidrs.length }}</b><small>个网段 · {{ set.action === 'allow' ? '允许' : '拒绝' }}</small></div><footer><code>{{ set.cidrs.slice(0, 2).join(', ') || '--' }}</code><n-popconfirm positive-text="删除" negative-text="取消" @positive-click="removeSet(set.id)"><template #trigger><button class="icon-button danger" title="删除集合"><Trash2 :size="15" /></button></template>删除后需再次部署配置，Edge 规则才会更新。</n-popconfirm></footer></article><div v-if="!ops.ipSets.length" class="empty-state">还没有 IP 集合</div></div>
    <div v-else class="feed-list"><article v-for="feed in ops.ipFeeds" :key="feed.id" class="feed-row"><span class="feed-icon"><CloudDownload :size="18" /></span><div class="feed-main"><header><b>{{ feed.name }}</b><span :class="['state-pill', feed.last_error ? 'disabled' : feed.ip_set_id ? 'enabled' : 'neutral']">{{ feed.last_error ? '同步失败' : feed.ip_set_id ? '已同步' : '待预览' }}</span></header><code>{{ feed.url }}</code><small>{{ feed.kind.toUpperCase() }} · 每 {{ feed.refresh_hours }} 小时 · 上次 {{ shortTime(feed.last_fetch_at) }}</small><p v-if="feed.last_error">{{ feed.last_error }}</p><p v-if="preview[feed.id]" class="preview-ok">{{ preview[feed.id] }}</p></div><div class="feed-actions"><n-switch :value="feed.enabled" size="small" @update:value="toggleFeed(feed)" /><n-button size="tiny" secondary :loading="busy === feed.id" @click="previewFeed(feed)"><RefreshCw :size="14" />预览</n-button><n-popconfirm :disabled="!preview[feed.id]" positive-text="确认同步" negative-text="取消" @positive-click="syncFeed(feed)"><template #trigger><n-button size="tiny" type="primary" :disabled="!preview[feed.id]">同步</n-button></template>将预览内容写入 Core IP 集合；不会自动部署 Edge。</n-popconfirm><n-popconfirm positive-text="删除" negative-text="取消" @positive-click="removeFeed(feed.id)"><template #trigger><button class="icon-button danger" title="删除数据源"><Trash2 :size="15" /></button></template>已生成的 IP 集合会保留。</n-popconfirm></div></article><div v-if="!ops.ipFeeds.length" class="empty-state">还没有自动数据源</div></div>
  </section>
</template>
