<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ArrowLeftRight, CircleHelp, Copy, Pencil, Play, Plus, Power, Rocket, Trash2, X } from '@lucide/vue'
import { NAlert, NButton, NCheckbox, NInput, NInputNumber, NPopconfirm, NSelect, NSwitch, NTag } from 'naive-ui'
import { useOpsStore, type PortForward } from '../stores/ops'
import { hasRole } from '../api'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
// Port-forward mutations require at least the admin role (backend enforced).
const canModify = computed(() => hasRole('admin'))
const editorOpen = ref(false)
const advancedOpen = ref(false)
const saving = ref(false)
const applying = ref(false)
const batchAction = ref<'enable' | 'disable' | ''>('')
const testing = ref(false)
const testResult = ref('')
const editingID = ref(0)
const selectedIDs = ref<number[]>([])
const selectedSet = computed(() => new Set(selectedIDs.value))
const allSelected = computed(() => ops.portForwards.length > 0 && selectedIDs.value.length === ops.portForwards.length)
const partlySelected = computed(() => selectedIDs.value.length > 0 && !allSelected.value)
const form = ref<{
  name: string
  node_id: string
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
  acl_id: number
  allowed_cidrs: string
  denied_cidrs: string
  rate_limit_kbps: number
  udp_idle_timeout: number
  health_check: boolean
}>(emptyForm())

function emptyForm(): {
  name: string
  node_id: string
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
  acl_id: number
  allowed_cidrs: string
  denied_cidrs: string
  rate_limit_kbps: number
  udp_idle_timeout: number
  health_check: boolean
} {
  return {
    name: '',
    node_id: 'local',
    listen_family: 'auto',
    listen_address: '',
    listen_port_start: 8000,
    listen_port_end: 0,
    protocol: 'tcp',
    target_family: 'auto',
    target_host: '',
    target_port_start: 8080,
    target_port_end: 0,
    forward_mode: 'auto',
    snat_mode: 'auto',
    enabled: true,
    acl_id: 0,
    allowed_cidrs: '',
    denied_cidrs: '',
    rate_limit_kbps: 0,
    udp_idle_timeout: 60,
    health_check: true,
  }
}

const familyOptions = [
  { label: '自动', value: 'auto' },
  { label: 'IPv4', value: 'ipv4' },
  { label: 'IPv6', value: 'ipv6' },
]
const protocolOptions = [
  { label: 'TCP', value: 'tcp' },
  { label: 'UDP', value: 'udp' },
  { label: 'TCP + UDP', value: 'both' },
]
const modeOptions = [
  { label: '自动（同族 nft / 跨族 relay）', value: 'auto' },
  { label: 'nftables（仅同地址族）', value: 'nft' },
  { label: 'Relay（支持跨地址族与域名）', value: 'relay' },
]
const snatOptions = [
  { label: '自动', value: 'auto' },
  { label: 'MASQUERADE（SNAT）', value: 'masquerade' },
  { label: '不 SNAT', value: 'none' },
]
const listenAddressOptions = [
  { label: '全部地址（0.0.0.0 / ::）', value: '' },
  { label: 'IPv4 全部（0.0.0.0）', value: '0.0.0.0' },
  { label: 'IPv6 全部（::）', value: '::' },
]

const direction = computed(() => {
  const listen = form.value.listen_family === 'auto' ? inferFamily(form.value.listen_address) : form.value.listen_family
  const target = form.value.target_family === 'auto' ? inferFamily(form.value.target_host) : form.value.target_family
  const a = listen === 'ipv6' ? 'IPv6' : 'IPv4'
  const b = target === 'ipv6' ? 'IPv6' : target === 'ipv4' ? 'IPv4' : '自动'
  return { text: `${a} → ${b}`, cross: (listen === 'ipv4' && target === 'ipv6') || (listen === 'ipv6' && target === 'ipv4') }
})

function inferFamily(value: string) {
  const trimmed = String(value || '').trim()
  if (!trimmed) return ''
  if (trimmed.includes(':')) return 'ipv6'
  if (/^\d+\.\d+\.\d+\.\d+$/.test(trimmed)) return 'ipv4'
  return ''
}

function openCreate() {
  editingID.value = 0
  form.value = emptyForm()
  advancedOpen.value = false
  testResult.value = ''
  editorOpen.value = true
}

function openEdit(item: PortForward) {
  editingID.value = item.id
  form.value = {
    name: item.name,
    node_id: item.node_id || 'local',
    listen_family: item.listen_family,
    listen_address: item.listen_address,
    listen_port_start: item.listen_port_start,
    listen_port_end: item.listen_port_end === item.listen_port_start ? 0 : item.listen_port_end,
    protocol: item.protocol,
    target_family: item.target_family,
    target_host: item.target_host,
    target_port_start: item.target_port_start,
    target_port_end: item.target_port_end === item.target_port_start ? 0 : item.target_port_end,
    forward_mode: item.forward_mode,
    snat_mode: item.snat_mode,
    enabled: item.enabled,
    acl_id: item.acl_id || 0,
    allowed_cidrs: (item.allowed_cidrs || []).join('\n'),
    denied_cidrs: (item.denied_cidrs || []).join('\n'),
    rate_limit_kbps: item.rate_limit_kbps || 0,
    udp_idle_timeout: item.udp_idle_timeout || 60,
    health_check: item.health_check !== false,
  }
  advancedOpen.value = Boolean(item.allowed_cidrs?.length || item.denied_cidrs?.length || item.rate_limit_kbps || item.acl_id)
  testResult.value = ''
  editorOpen.value = true
}

async function saveRule() {
  if (!form.value.name.trim()) return emit('notify', '请填写规则名称', 'error')
  if (!form.value.listen_port_start) return emit('notify', '请填写监听端口', 'error')
  if (!form.value.target_host.trim()) return emit('notify', '请填写目标 IP 或域名', 'error')
  if (!form.value.target_port_start) return emit('notify', '请填写目标端口', 'error')
  saving.value = true
  const payload = {
    name: form.value.name.trim(),
    node_id: form.value.node_id.trim() || 'local',
    listen_family: form.value.listen_family,
    listen_address: form.value.listen_address,
    listen_port_start: form.value.listen_port_start,
    listen_port_end: form.value.listen_port_end || form.value.listen_port_start,
    protocol: form.value.protocol,
    target_family: form.value.target_family,
    target_host: form.value.target_host.trim(),
    target_port_start: form.value.target_port_start,
    target_port_end: form.value.target_port_end || form.value.target_port_start,
    forward_mode: form.value.forward_mode,
    snat_mode: form.value.snat_mode,
    enabled: form.value.enabled,
    acl_id: form.value.acl_id || 0,
    allowed_cidrs: parseCIDRs(form.value.allowed_cidrs),
    denied_cidrs: parseCIDRs(form.value.denied_cidrs),
    rate_limit_kbps: form.value.rate_limit_kbps || 0,
    udp_idle_timeout: form.value.udp_idle_timeout || 60,
    health_check: form.value.health_check,
  }
  try {
    if (editingID.value) await ops.updatePortForward({ id: editingID.value, ...payload })
    else await ops.createPortForward(payload)
    editorOpen.value = false
    emit('notify', editingID.value ? '规则已更新，点击“应用变更”后生效' : '规则已保存，点击“应用变更”后生效')
  } catch (err) {
    emit('notify', friendlyError(err), 'error')
  } finally {
    saving.value = false
  }
}

function parseCIDRs(text: string) {
  return text.split(/[\n,]+/).map((value) => value.trim()).filter(Boolean)
}

async function applyAll() {
  applying.value = true
  try {
    await ops.applyPortForwards()
    await ops.fetchPortForwardStatus()
    emit('notify', '端口转发规则已应用')
  } catch (err) {
    emit('notify', friendlyError(err), 'error')
  } finally {
    applying.value = false
  }
}

async function removeRule(id: number) {
  try {
    await ops.deletePortForward(id)
    await ops.fetchPortForwardStatus()
    emit('notify', '规则已删除并已从数据面移除')
  } catch (err) {
    emit('notify', friendlyError(err), 'error')
  }
}

async function toggleRule(item: PortForward) {
  try {
    await ops.togglePortForward(item.id, !item.enabled)
    await ops.fetchPortForwardStatus()
    emit('notify', item.enabled ? '规则已禁用' : '规则已启用')
  } catch (err) {
    emit('notify', friendlyError(err), 'error')
  }
}

function setRuleSelected(id: number, checked: boolean) {
  if (checked) {
    if (!selectedIDs.value.includes(id)) selectedIDs.value = [...selectedIDs.value, id]
    return
  }
  selectedIDs.value = selectedIDs.value.filter((value) => value !== id)
}

function setAllSelected(checked: boolean) {
  selectedIDs.value = checked ? ops.portForwards.map((item) => item.id) : []
}

async function batchToggleRules(enabled: boolean) {
  if (!selectedIDs.value.length) return
  batchAction.value = enabled ? 'enable' : 'disable'
  try {
    const count = selectedIDs.value.length
    await ops.batchTogglePortForwards(selectedIDs.value, enabled)
    await ops.fetchPortForwardStatus()
    selectedIDs.value = []
    emit('notify', `已${enabled ? '启用' : '停用'} ${count} 条端口转发`)
  } catch (err) {
    emit('notify', friendlyError(err), 'error')
  } finally {
    batchAction.value = ''
  }
}

async function duplicateRule(item: PortForward) {
  try {
    await ops.duplicatePortForward(item.id)
    emit('notify', '已复制为新规则（草稿）')
  } catch (err) {
    emit('notify', friendlyError(err), 'error')
  }
}

async function testTarget() {
  if (!form.value.target_host.trim() || !form.value.target_port_start) {
    return emit('notify', '请先填写目标地址和端口', 'error')
  }
  testing.value = true
  testResult.value = ''
  try {
    const result = await ops.testPortForwardTarget(form.value.target_host.trim(), form.value.target_port_start, form.value.protocol === 'udp' ? 'udp' : 'tcp')
    testResult.value = result.ok
      ? `目标可达（${result.latency_ms}ms）${result.note ? ' · ' + result.note : ''}`
      : `不可达：${result.error || '未知错误'}`
  } catch (err) {
    testResult.value = `测试失败：${friendlyError(err)}`
  } finally {
    testing.value = false
  }
}

function ruleDirection(item: PortForward) {
  const listen = item.listen_family === 'auto' ? inferFamily(item.listen_address) : item.listen_family
  const target = item.target_family === 'auto' ? inferFamily(item.target_host) : item.target_family
  const a = listen === 'ipv6' ? 'IPv6' : 'IPv4'
  const b = target === 'ipv6' ? 'IPv6' : target === 'ipv4' ? 'IPv4' : '域名'
  return `${a} → ${b}`
}

function portLabel(item: PortForward) {
  const listen = item.listen_port_start === item.listen_port_end ? String(item.listen_port_start) : `${item.listen_port_start}-${item.listen_port_end}`
  const target = item.target_port_start === item.target_port_end ? String(item.target_port_start) : `${item.target_port_start}-${item.target_port_end}`
  return { listen, target }
}

function statusTag(item: PortForward): { type: 'default' | 'success' | 'warning' | 'error'; text: string } {
  if (!item.enabled) return { type: 'default', text: '已禁用' }
  switch (item.last_status) {
    case 'applied':
      return { type: 'success', text: '已生效' }
    case 'pending':
      return { type: 'warning', text: '待应用' }
    case 'disabled':
      return { type: 'default', text: '已禁用' }
    default:
      return { type: 'error', text: '失败' }
  }
}

function directionTagType(item: PortForward): 'warning' | 'default' {
  const dir = ruleDirection(item)
  if (dir.includes('→') && dir.startsWith('IPv4') !== dir.endsWith('IPv4')) return 'warning'
  return 'default'
}

function friendlyError(err: unknown) {
  const value = err instanceof Error ? err.message : String(err)
  return value.replace(/^Error: /, '')
}

onMounted(() => {
  ops.fetchPortForwardStatus()
})
</script>

<template>
  <div class="stack">
    <section class="panel">
      <div class="panel-title">
        <div>
          <span class="eyebrow">PORT FORWARDING</span>
          <h2>通用端口转发</h2>
          <p>把进入本节点的 TCP/UDP 流量转发到任意设备，支持 IPv4↔IPv6 互转与端口范围。</p>
        </div>
        <div class="page-actions">
          <n-button v-if="canModify" secondary :loading="applying" @click="applyAll"><Rocket :size="16" />应用变更</n-button>
          <n-button v-if="canModify" type="primary" class="create-action" @click="openCreate"><Plus :size="16" />新增转发</n-button>
        </div>
      </div>

      <n-alert v-if="ops.portForwardStatus?.relay_rules" type="info" :bordered="false" class="mb">
        <template #header>Relay 状态</template>
        跨地址族规则由 porthub-relay 处理：{{ ops.portForwardStatus.relay.running ? '运行中' : '未运行' }}（
        {{ ops.portForwardStatus.relay_rules }} 条 relay 规则 / {{ ops.portForwardStatus.nft_rules }} 条 nft 规则 ）
      </n-alert>

      <transition name="batch-bar">
        <div v-if="canModify && selectedIDs.length" class="batch-toolbar">
          <div class="batch-summary">
            <span class="batch-count">{{ selectedIDs.length }}</span>
            <span>条规则已选择</span>
          </div>
          <div class="batch-actions">
            <n-popconfirm positive-text="批量启用" negative-text="取消" @positive-click="batchToggleRules(true)">
              <template #trigger>
                <n-button type="primary" size="small" :loading="batchAction === 'enable'" :disabled="Boolean(batchAction)">
                  <Power :size="15" />批量启用
                </n-button>
              </template>
              将一次启用选中的 {{ selectedIDs.length }} 条规则。系统会先检查端口冲突，失败时自动恢复。
            </n-popconfirm>
            <n-popconfirm positive-text="批量停用" negative-text="取消" @positive-click="batchToggleRules(false)">
              <template #trigger>
                <n-button size="small" :loading="batchAction === 'disable'" :disabled="Boolean(batchAction)">
                  <Power :size="15" />批量停用
                </n-button>
              </template>
              停用后外部连接将不能再通过这些端口进入，确认继续？
            </n-popconfirm>
            <n-button text size="small" :disabled="Boolean(batchAction)" @click="selectedIDs = []">取消选择</n-button>
          </div>
        </div>
      </transition>

      <div class="table-wrap">
        <table class="mapping-table pf-table">
          <thead>
            <tr>
              <th v-if="canModify" class="select-cell">
                <n-checkbox :checked="allSelected" :indeterminate="partlySelected" aria-label="全选端口转发" @update:checked="setAllSelected" />
              </th>
              <th>名称</th>
              <th>监听</th>
              <th>协议</th>
              <th>方向</th>
              <th>目标</th>
              <th>状态</th>
              <th class="ta-r">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in ops.portForwards" :key="item.id" :class="{ 'is-selected': selectedSet.has(item.id) }">
              <td v-if="canModify" class="select-cell" data-label="选择">
                <n-checkbox :checked="selectedSet.has(item.id)" :aria-label="`选择 ${item.name}`" @update:checked="setRuleSelected(item.id, $event)" />
              </td>
              <td class="pf-name" data-label="名称">
                <b>{{ item.name }}</b>
                <small class="cell-sub">
                  {{ item.node_id || 'local' }}<template v-if="item.last_error"> · <span class="text-danger">{{ item.last_error }}</span></template>
                </small>
              </td>
              <td data-label="监听">
                <code>{{ item.listen_address || (item.listen_family === 'ipv6' ? '::' : '0.0.0.0') }}:{{ portLabel(item).listen }}</code>
              </td>
              <td data-label="协议"><n-tag size="small" :bordered="false">{{ item.protocol === 'both' ? 'TCP+UDP' : item.protocol.toUpperCase() }}</n-tag></td>
              <td data-label="方向"><n-tag size="small" :type="directionTagType(item)" :bordered="false">{{ ruleDirection(item) }}</n-tag></td>
              <td data-label="目标"><code>{{ item.target_host }}:{{ portLabel(item).target }}</code></td>
              <td data-label="状态"><n-tag size="small" :type="statusTag(item).type" :bordered="false">{{ statusTag(item).text }}</n-tag></td>
              <td data-label="操作" class="ta-r">
                <div v-if="canModify" class="row-actions">
                  <button class="icon-button" title="编辑" @click="openEdit(item)"><Pencil :size="15" /></button>
                  <button class="icon-button" title="复制" @click="duplicateRule(item)"><Copy :size="15" /></button>
                  <button class="icon-button" :title="item.enabled ? '禁用' : '启用'" @click="toggleRule(item)"><Power :size="15" /></button>
                  <n-popconfirm positive-text="删除" negative-text="取消" @positive-click="removeRule(item.id)">
                    <template #trigger><button class="icon-button danger" title="删除"><Trash2 :size="15" /></button></template>
                    删除后将从数据面移除该规则，确认？
                  </n-popconfirm>
                </div>
                <span v-else class="field-hint">只读</span>
              </td>
            </tr>
            <tr v-if="!ops.portForwards.length">
              <td :colspan="canModify ? 8 : 7" class="empty-cell">还没有端口转发规则。点击右上角「新增转发」创建第一条规则。</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <transition name="drawer">
      <section v-if="editorOpen" class="panel editor-panel">
        <div class="panel-title">
          <div>
            <span class="eyebrow">{{ editingID ? 'EDIT RULE' : 'NEW RULE' }}</span>
            <h2>{{ editingID ? '编辑转发规则' : '新增端口转发' }}</h2>
            <p>监听地址与端口必须不与 PortHub 映射、SSH、WireGuard 或其他服务冲突。</p>
          </div>
          <button class="icon-button" title="关闭" @click="editorOpen = false"><X :size="18" /></button>
        </div>

        <div class="form-grid">
          <label class="field span-2">
            <span class="field-label">规则名称</span>
            <n-input v-model:value="form.name" placeholder="例如：转发 NAS 管理端口" />
          </label>

          <label class="field">
            <span class="field-label">监听地址族</span>
            <n-select v-model:value="form.listen_family" :options="familyOptions" />
          </label>
          <label class="field">
            <span class="field-label">监听地址</span>
            <n-select v-model:value="form.listen_address" :options="listenAddressOptions" filterable tag placeholder="0.0.0.0 / :: / 具体 IP" />
          </label>
          <label class="field">
            <span class="field-label">监听端口</span>
            <n-input-number v-model:value="form.listen_port_start" :min="1" :max="65535" placeholder="起始" class="w-full" />
          </label>
          <label class="field">
            <span class="field-label">监听端口（结束，可选）</span>
            <n-input-number v-model:value="form.listen_port_end" :min="0" :max="65535" placeholder="范围结束，留空为单端口" class="w-full" />
          </label>

          <label class="field">
            <span class="field-label">协议</span>
            <n-select v-model:value="form.protocol" :options="protocolOptions" />
          </label>
          <label class="field">
            <span class="field-label">转发模式</span>
            <n-select v-model:value="form.forward_mode" :options="modeOptions" />
          </label>

          <label class="field">
            <span class="field-label">目标地址族</span>
            <n-select v-model:value="form.target_family" :options="familyOptions" />
          </label>
          <label class="field">
            <span class="field-label">目标主机（IP 或域名）</span>
            <n-input v-model:value="form.target_host" placeholder="192.0.2.150 或 2409:xxxx::10 或 service.example.com" />
          </label>
          <label class="field">
            <span class="field-label">目标端口</span>
            <n-input-number v-model:value="form.target_port_start" :min="1" :max="65535" placeholder="起始" class="w-full" />
          </label>
          <label class="field">
            <span class="field-label">目标端口（结束，可选）</span>
            <n-input-number v-model:value="form.target_port_end" :min="0" :max="65535" placeholder="范围结束，留空为单端口" class="w-full" />
          </label>

          <div class="span-2">
            <n-alert :type="direction.cross ? 'warning' : 'info'" :bordered="false">
              <template #header>转发方向：{{ direction.text }}<template v-if="direction.cross">（跨地址族，走 relay）</template></template>
              <template v-if="direction.cross">跨地址族转换由 porthub-relay 完成，不依赖 socat 等外部工具。</template>
              <template v-else>同地址族转发优先使用 nftables 快速数据面。</template>
            </n-alert>
          </div>

          <div class="span-2">
            <n-button secondary size="small" :loading="testing" @click="testTarget"><Play :size="14" />测试目标可达性</n-button>
            <span v-if="testResult" class="test-result" :class="{ 'text-danger': testResult.includes('不可达') || testResult.includes('失败') }">{{ testResult }}</span>
          </div>

          <button class="toggle-row span-2" @click="advancedOpen = !advancedOpen">
            {{ advancedOpen ? '收起高级选项' : '高级选项（ACL / 限速 / SNAT / 超时）' }}
          </button>

          <template v-if="advancedOpen">
            <label class="field">
              <span class="field-label">SNAT / MASQUERADE</span>
              <n-select v-model:value="form.snat_mode" :options="snatOptions" />
            </label>
            <label class="field">
              <span class="field-label">UDP 会话空闲超时（秒）</span>
              <n-input-number v-model:value="form.udp_idle_timeout" :min="5" :max="3600" class="w-full" />
            </label>
            <label class="field">
              <span class="field-label">限速（Kbps，0=不限）</span>
              <n-input-number v-model:value="form.rate_limit_kbps" :min="0" :max="10000000" class="w-full" />
            </label>
            <label class="field">
              <span class="field-label">健康检查</span>
              <div class="switch-row"><n-switch v-model:value="form.health_check" /><span>{{ form.health_check ? '应用后探测目标可达性' : '关闭' }}</span></div>
            </label>
            <label class="field span-2">
              <span class="field-label">来源白名单 CIDR（每行一个，留空=允许所有）</span>
              <n-input v-model:value="form.allowed_cidrs" type="textarea" :rows="2" placeholder="10.0.0.0/8&#10;192.0.2.0/24" />
            </label>
            <label class="field span-2">
              <span class="field-label">来源黑名单 CIDR（每行一个）</span>
              <n-input v-model:value="form.denied_cidrs" type="textarea" :rows="2" placeholder="203.0.113.0/24" />
            </label>
            <label class="field">
              <span class="field-label">关联 ACL（可选）</span>
              <n-select v-model:value="form.acl_id" :options="ops.aclRules.map((acl) => ({ label: acl.name, value: acl.id }))" clearable placeholder="选择 ACL" />
            </label>
            <label class="field">
              <span class="field-label">入口节点</span>
              <n-input v-model:value="form.node_id" placeholder="local / agent 节点 ID" />
            </label>
          </template>
        </div>

        <div class="editor-actions">
          <n-button secondary @click="editorOpen = false">取消</n-button>
          <n-button type="primary" class="create-action" :loading="saving" @click="saveRule">保存规则</n-button>
        </div>
      </section>
    </transition>
  </div>
</template>

<style scoped>
.mb { margin-bottom: 14px; }
.cell-sub { display: block; color: var(--text-dim); font-size: 12px; margin-top: 2px; }
.text-danger { color: var(--red); }
.ta-r { text-align: right; }
.row-actions { display: flex; gap: 4px; justify-content: flex-end; }
.select-cell { width: 42px; text-align: center; }
.mapping-table tr.is-selected td { background: color-mix(in srgb, var(--primary-color) 8%, transparent); }
.batch-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 14px; min-height: 48px; margin-bottom: 12px; padding: 8px 12px; border: 1px solid color-mix(in srgb, var(--primary-color) 34%, var(--border-color)); border-radius: 6px; background: color-mix(in srgb, var(--primary-color) 7%, var(--panel-bg)); }
.batch-summary, .batch-actions { display: flex; align-items: center; gap: 9px; }
.batch-summary { color: var(--text-dim); font-size: 13px; }
.batch-count { display: grid; place-items: center; min-width: 26px; height: 26px; padding: 0 7px; border-radius: 5px; background: var(--primary-color); color: #fff; font-weight: 700; }
.batch-bar-enter-active, .batch-bar-leave-active { transition: opacity .18s ease, transform .18s ease; }
.batch-bar-enter-from, .batch-bar-leave-to { opacity: 0; transform: translateY(-5px); }
.empty-cell { text-align: center; color: var(--text-dim); padding: 28px 0; }
.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.span-2 { grid-column: span 2; }
.field { display: flex; flex-direction: column; gap: 6px; }
.field-label { font-size: 12px; font-weight: 600; color: var(--text-dim); }
.w-full { width: 100%; }
.switch-row { display: flex; align-items: center; gap: 8px; }
.toggle-row { background: none; border: 1px dashed var(--border-color); border-radius: 6px; padding: 8px; color: var(--text-dim); cursor: pointer; font-size: 13px; }
.test-result { margin-left: 10px; font-size: 13px; }
.editor-panel { margin-top: 16px; }
.editor-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 18px; }
@media (max-width: 720px) {
  .batch-toolbar { align-items: flex-start; flex-direction: column; }
  .batch-actions { width: 100%; flex-wrap: wrap; }
  .select-cell { width: auto; text-align: left; }
}
</style>
