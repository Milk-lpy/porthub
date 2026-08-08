<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Plus } from '@lucide/vue'
import { NButton, NDrawer, NDrawerContent, NInput, NSelect } from 'naive-ui'
import { useOpsStore } from '../stores/ops'
import type { DDNSProvider, DDNSRecord, DomainItem, NetInterface, ProviderField } from '../stores/ops'
import TermHint from './TermHint.vue'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()

const domainForm = ref({ name: '家庭入口', zone: '', provider: 'external', managed_by: 'porthub', enabled: true })
const providerForm = ref({
  name: '',
  type: 'cloudflare',
  enabled: true,
  fields: {} as Record<string, string>,
  secret: {} as Record<string, string>,
})
const editingProviderID = ref(0)
const ddnsForm = ref({
  name: 'Edge 公网', fqdn: '', provider_id: '', record_type: 'A', ip_source: 'public_api',
  last_value: '', ttl: '600', interval_seconds: '300', enabled: true, managed_by_lucky: false,
  ip_urls: '', net_interface: '', ip_regex: '', manual_ip: '', force_interval_seconds: '0', notify_webhook: '', verify_dns: false,
})
const syncValue = ref('')
const selectedRecordID = ref('')
const allowRealSync = ref(false)
const syncResult = ref('')

// 二级抽屉可见性: 新增/编辑表单收进抽屉, 不平铺占位
const domainDrawer = ref(false)
const providerDrawer = ref(false)
const recordDrawer = ref(false)
const editingDomainID = ref(0)
const editingRecordID = ref(0)

const domainDefaults = () => ({ name: '家庭入口', zone: '', provider: 'external', managed_by: 'porthub', enabled: true })
const recordDefaults = () => ({
  name: 'Edge 公网', fqdn: '', provider_id: '', record_type: 'A', ip_source: 'public_api',
  last_value: '', ttl: '600', interval_seconds: '300', enabled: true, managed_by_lucky: false,
  ip_urls: '', net_interface: '', ip_regex: '', manual_ip: '', force_interval_seconds: '0', notify_webhook: '', verify_dns: false,
})

function openCreateDomain() {
  editingDomainID.value = 0
  domainForm.value = domainDefaults()
  domainDrawer.value = true
}
function openEditDomain(row: DomainItem) {
  editingDomainID.value = row.id
  domainForm.value = { name: row.name, zone: row.zone, provider: row.provider, managed_by: row.managed_by, enabled: row.enabled }
  domainDrawer.value = true
}
function openCreateProvider() {
  resetProviderForm()
  providerDrawer.value = true
}
function openCreateRecord() {
  editingRecordID.value = 0
  ddnsForm.value = recordDefaults()
  recordDrawer.value = true
}
function openEditRecord(row: DDNSRecord) {
  editingRecordID.value = row.id
  ddnsForm.value = {
    name: row.name, fqdn: row.fqdn, provider_id: String(row.provider_id || ''),
    record_type: row.record_type, ip_source: row.ip_source, last_value: row.last_value || '',
    ttl: String(row.ttl ?? '600'), interval_seconds: String(row.interval_seconds ?? '300'),
    enabled: Boolean(row.enabled), managed_by_lucky: Boolean(row.managed_by_lucky),
    ip_urls: (row.ip_urls || []).join('\n'), net_interface: row.net_interface || '',
    ip_regex: row.ip_regex || '', manual_ip: row.manual_ip || '',
    force_interval_seconds: String(row.force_interval_seconds ?? '0'),
    notify_webhook: row.notify_webhook || '', verify_dns: Boolean(row.verify_dns),
  }
  recordDrawer.value = true
}

const selectedRecord = computed(() => ops.ddnsRecords.find((row) => String(row.id) === selectedRecordID.value))

function schemaOf(type: string) {
  return ops.providerSchemas.find((s) => s.type === type)
}

const providerSchema = computed(() => schemaOf(providerForm.value.type))

function providerTypeLabel(type: string) {
  return schemaOf(type)?.label || type
}

function sourceLabel(row: DDNSRecord) {
  switch (row.ip_source) {
    case 'public_api': return `接口${row.ip_urls?.length ? ` (${row.ip_urls.length} 个)` : ''}`
    case 'edge_public': return 'Edge 公网'
    case 'net_interface': return `网卡 ${row.net_interface || ''}`
    case 'manual': return row.manual_ip ? `手动 ${row.manual_ip}` : '手动'
    default: return row.ip_source
  }
}

// IP 正则预置选项（可自定义输入）
const IP_REGEX_OPTIONS = [
  { label: '全部 IPv4 地址', value: '^\\d+\\.\\d+\\.\\d+\\.\\d+$' },
  { label: '全部 IPv6 地址', value: '^[0-9a-fA-F:]+$' },
  { label: '仅全局 IPv4（排除私网）', value: '^(?!10\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.)\\d+\\.\\d+\\.\\d+\\.\\d+$' },
  { label: '仅全局 IPv6（排除链路本地）', value: '^(?!fe80:)[0-9a-fA-F:]+$' },
]

// 当前 IP 正则选中项的说明（自定义值时回退为空）
const ipRegexOptionLabel = computed(() =>
  IP_REGEX_OPTIONS.find((o) => o.value === ddnsForm.value.ip_regex)?.label || '',
)

// 网卡下拉选项: 显示网卡名 + 当前 v4/v6 地址
const netInterfaceOptions = computed(() =>
  ops.ddnsInterfaces.map((iface: NetInterface) => ({
    label: `${iface.name}${iface.up ? '' : ' (down)'} · ${[...(iface.ipv4 ?? []), ...(iface.ipv6 ?? [])].join(', ') || '无 IP'}`,
    value: iface.name,
  })),
)

// 当前选中的网卡详情 (展示 v4/v6)
const selectedNetInterface = computed(() =>
  ops.ddnsInterfaces.find((iface: NetInterface) => iface.name === ddnsForm.value.net_interface),
)

function interfaceIPSummary(iface?: NetInterface) {
  if (!iface) return ''
  const parts: string[] = []
  if ((iface.ipv4 ?? []).length) parts.push(`IPv4: ${(iface.ipv4 ?? []).join(', ')}`)
  if ((iface.ipv6 ?? []).length) parts.push(`IPv6: ${(iface.ipv6 ?? []).join(', ')}`)
  return parts.join('  ')
}

onMounted(() => {
  ops.fetchDDNSInterfaces()
})

function providerName(id: number) {
  return ops.ddnsProviders.find((row) => row.id === id)?.name || (id ? `#${id}` : '--')
}

function safeConfig(row: DDNSProvider) {
  const text = JSON.stringify(row.config || {})
  return text.length > 96 ? `${text.slice(0, 96)}...` : text
}

function fieldValue(field: ProviderField) {
  const val = providerForm.value.fields[field.key]
  return val ?? field.default ?? ''
}

function secretValue(field: ProviderField) {
  return providerForm.value.secret[field.key] ?? ''
}

function isEditing() {
  return editingProviderID.value > 0
}

function secretAlreadySet(field: ProviderField) {
  const row = ops.ddnsProviders.find((p) => p.id === editingProviderID.value)
  return Boolean(row?.secret_ref) && !providerForm.value.secret[field.key]
}

function resetProviderForm() {
  editingProviderID.value = 0
  providerForm.value = { name: '', type: 'cloudflare', enabled: true, fields: {}, secret: {} }
}

function onProviderTypeChange() {
  providerForm.value.fields = {}
  providerForm.value.secret = {}
}

function editProvider(row: DDNSProvider) {
  editingProviderID.value = row.id
  providerForm.value = {
    name: row.name,
    type: row.type || 'cloudflare',
    enabled: row.enabled,
    fields: {},
    secret: {},
  }
  const cfg = (row.config || {}) as Record<string, string>
  for (const field of schemaOf(row.type)?.fields || []) {
    if (!field.secret && cfg[field.key] !== undefined) {
      providerForm.value.fields[field.key] = String(cfg[field.key])
    }
  }
}

async function saveProvider() {
  try {
    const config: Record<string, unknown> = {}
    const secret: Record<string, string> = {}
    for (const field of providerSchema.value?.fields || []) {
      const v = field.secret ? secretValue(field) : fieldValue(field)
      if (!field.secret && v.trim() !== '') {
        config[field.key] = v.trim()
      }
      if (field.secret && v.trim() !== '') {
        secret[field.key] = v.trim()
      }
    }
    const payload = { ...providerForm.value, config, secret }
    if (isEditing()) {
      await ops.updateDDNSProvider({ ...payload, id: editingProviderID.value } as DDNSProvider)
      emit('notify', 'DDNS Provider 已更新')
    } else {
      await ops.createDDNSProvider(payload)
      emit('notify', 'DDNS Provider 已保存')
    }
    resetProviderForm()
    providerDrawer.value = false
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function toggleProvider(row: DDNSProvider) {
  try {
    await ops.updateDDNSProvider({ ...row, enabled: !row.enabled })
    emit('notify', row.enabled ? 'Provider 已禁用' : 'Provider 已启用')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function removeProvider(id: number) {
  try {
    await ops.deleteDDNSProvider(id)
    emit('notify', 'Provider 已删除')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function addDomain() {
  try {
    if (editingDomainID.value > 0) {
      await ops.updateDomain({ ...domainForm.value, id: editingDomainID.value } as DomainItem)
      emit('notify', '域名已更新')
    } else {
      await ops.createDomain({ ...domainForm.value })
      emit('notify', '域名已保存')
    }
    domainDrawer.value = false
    editingDomainID.value = 0
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function toggleDomain(row: DomainItem) {
  try {
    await ops.updateDomain({ ...row, enabled: !row.enabled })
    emit('notify', row.enabled ? '域名已禁用' : '域名已启用')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function removeDomain(id: number) {
  try {
    await ops.deleteDomain(id)
    emit('notify', '域名已删除')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function addDDNSRecord() {
  try {
    const payload = {
      ...ddnsForm.value,
      provider_id: Number(ddnsForm.value.provider_id || 0),
      ttl: Number(ddnsForm.value.ttl || 600),
      interval_seconds: Number(ddnsForm.value.interval_seconds || 300),
      force_interval_seconds: Number(ddnsForm.value.force_interval_seconds || 0),
      ip_urls: ddnsForm.value.ip_urls.split('\n').map((s) => s.trim()).filter(Boolean),
    }
    if (editingRecordID.value > 0) {
      await ops.updateDDNSRecord({ ...payload, id: editingRecordID.value } as unknown as DDNSRecord)
      emit('notify', 'DDNS 记录已更新')
    } else {
      await ops.createDDNSRecord(payload)
      emit('notify', 'DDNS 记录已保存')
    }
    recordDrawer.value = false
    editingRecordID.value = 0
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function toggleDDNSRecord(row: DDNSRecord) {
  try {
    await ops.updateDDNSRecord({ ...row, enabled: !row.enabled })
    emit('notify', row.enabled ? 'DDNS 记录已禁用' : 'DDNS 记录已启用')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function removeDDNSRecord(id: number) {
  try {
    await ops.deleteDDNSRecord(id)
    emit('notify', 'DDNS 记录已删除')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function runSync(dryRun: boolean) {
  try {
    const id = Number(selectedRecordID.value || selectedRecord.value?.id || 0)
    if (!id) throw new Error('请选择一条 DDNS 记录')
    if (!dryRun && !allowRealSync.value) throw new Error('真实同步前需要勾选确认')
    const result = await ops.syncDDNS(id, syncValue.value, dryRun)
    syncResult.value = JSON.stringify(result, null, 2)
    allowRealSync.value = false
    emit('notify', dryRun ? 'DDNS 同步预演已生成' : 'DDNS 真实同步已执行')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}
</script>

<template>
  <section class="two-col">
    <div class="panel">
      <div class="panel-title">
        <div>
          <h2>域名资产</h2>
          <span>记录 Zone、管理方和 Provider，不写入 Lucky 配置</span>
        </div>
        <div class="page-actions">
          <n-button type="primary" size="small" class="create-action" @click="openCreateDomain"><Plus :size="16" />新增域名</n-button>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>名称</th><th>Zone</th><th>Provider</th><th>管理方</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="row in ops.domains" :key="row.id">
              <td>{{ row.name }}</td>
              <td>{{ row.zone }}</td>
              <td>{{ row.provider }}</td>
              <td>{{ row.managed_by }}</td>
              <td><span :class="['state-pill', row.enabled ? 'enabled' : 'disabled']">{{ row.enabled ? '启用' : '禁用' }}</span></td>
              <td><div class="button-row compact"><n-button size="small" secondary @click="openEditDomain(row)">编辑</n-button><n-button size="small" secondary @click="toggleDomain(row)">{{ row.enabled ? '禁用' : '启用' }}</n-button><n-button size="small" tertiary type="error" @click="removeDomain(row.id)">删除</n-button></div></td>
            </tr>
            <tr v-if="!ops.domains.length"><td colspan="6" class="empty-cell">还没有域名资产。点击右上角「新增域名」添加第一条。</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <n-drawer v-model:show="domainDrawer" :width="440" placement="right">
      <n-drawer-content :title="editingDomainID ? '编辑域名' : '新增域名'" closable>
        <div class="drawer-form">
          <label>名称<n-input v-model:value="domainForm.name" /></label>
          <label><span class="field-label">Zone<TermHint text="DNS 区域的根域名，例如 home.example.com 的 Zone 通常是 example.com。" /></span><n-input v-model:value="domainForm.zone" placeholder="example.com" /></label>
          <label>Provider
            <select v-model="domainForm.provider">
              <option value="external">external</option>
              <option value="lucky">lucky</option>
              <option value="cloudflare">cloudflare</option>
              <option value="aliyun">aliyun</option>
              <option value="tencent">tencent</option>
              <option value="huawei">huawei</option>
              <option value="baidu">baidu</option>
              <option value="porkbun">porkbun</option>
              <option value="webhook">webhook</option>
            </select>
          </label>
          <label>管理方
            <select v-model="domainForm.managed_by">
              <option value="porthub">PortHub</option>
              <option value="lucky">Lucky</option>
              <option value="external">外部</option>
            </select>
          </label>
        </div>
        <template #footer>
          <n-button secondary @click="domainDrawer = false">取消</n-button>
          <n-button type="primary" class="create-action" @click="addDomain">{{ editingDomainID ? '保存修改' : '新增域名' }}</n-button>
        </template>
      </n-drawer-content>
    </n-drawer>

    <div class="panel">
      <div class="panel-title">
        <div>
          <h2>DDNS Provider</h2>
          <span>按类型交互式填写认证凭据，密钥由系统安全保存</span>
        </div>
        <div class="page-actions">
          <n-button type="primary" size="small" class="create-action" @click="openCreateProvider"><Plus :size="16" />新增 Provider</n-button>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>名称</th><th>类型</th><th>配置</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="row in ops.ddnsProviders" :key="row.id">
              <td>{{ row.name }}</td>
              <td>{{ providerTypeLabel(row.type) }}</td>
              <td><code>{{ safeConfig(row) }}</code> <span v-if="row.secret_ref" class="state-pill enabled">密钥已配置</span></td>
              <td><span :class="['state-pill', row.enabled ? 'enabled' : 'disabled']">{{ row.enabled ? '启用' : '禁用' }}</span></td>
              <td><div class="button-row compact"><n-button size="small" secondary @click="editProvider(row); providerDrawer = true">编辑</n-button><n-button size="small" secondary @click="toggleProvider(row)">{{ row.enabled ? '禁用' : '启用' }}</n-button><n-button size="small" tertiary type="error" @click="removeProvider(row.id)">删除</n-button></div></td>
            </tr>
            <tr v-if="!ops.ddnsProviders.length"><td colspan="5" class="empty-cell">还没有 DDNS Provider。点击右上角「新增 Provider」配置认证凭据。</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <n-drawer v-model:show="providerDrawer" :width="480" placement="right">
    <n-drawer-content :title="isEditing() ? '编辑 DDNS Provider' : '新增 DDNS Provider'" closable>
      <div class="drawer-form">
        <label>名称<n-input v-model:value="providerForm.name" placeholder="例如：Cloudflare 主域名" /></label>
        <label>类型
          <select v-model="providerForm.type" @change="onProviderTypeChange">
            <option v-for="s in ops.providerSchemas" :key="s.type" :value="s.type">{{ s.label }}</option>
          </select>
        </label>
        <template v-for="field in providerSchema?.fields || []" :key="field.key">
          <label v-if="field.type === 'textarea'">
            <span class="field-label">{{ field.label }}<TermHint v-if="field.help" :text="field.help" /></span>
            <n-input v-model:value="providerForm.fields[field.key]" type="textarea" :rows="2" :placeholder="field.placeholder" />
          </label>
          <label v-else>
            <span class="field-label">{{ field.label }}{{ field.required ? ' *' : '' }}<TermHint v-if="field.help" :text="field.help" /></span>
            <n-input
              v-if="field.secret"
              v-model:value="providerForm.secret[field.key]"
              type="password"
              :placeholder="secretAlreadySet(field) ? '已设置，留空保持不变' : field.placeholder"
              show-password-on="click"
            />
            <n-input v-else v-model:value="providerForm.fields[field.key]" :placeholder="field.placeholder || field.default" />
            <span v-if="field.secret && secretAlreadySet(field)" class="field-hint">已保存密钥，留空则保持不变</span>
          </label>
        </template>
        <span v-if="providerSchema?.note" class="field-hint">{{ providerSchema.note }}</span>
      </div>
      <template #footer>
        <n-button secondary @click="providerDrawer = false; resetProviderForm()">取消</n-button>
        <n-button type="primary" class="create-action" @click="saveProvider">{{ isEditing() ? '保存修改' : '新增 Provider' }}</n-button>
      </template>
    </n-drawer-content>
  </n-drawer>

  <section class="panel">
    <div class="panel-title">
      <div>
        <h2>DDNS 记录和同步</h2>
        <span>预演不会请求外部 DNS；真实同步需要显式确认</span>
      </div>
      <div class="button-row">
        <n-button secondary size="small" @click="runSync(true)">预演同步</n-button>
        <n-button type="primary" size="small" :disabled="!allowRealSync" @click="runSync(false)">真实同步</n-button>
        <n-button type="primary" size="small" class="create-action" @click="openCreateRecord"><Plus :size="16" />新增记录</n-button>
      </div>
    </div>

    <n-drawer v-model:show="recordDrawer" :width="560" placement="right">
      <n-drawer-content :title="editingRecordID ? '编辑 DDNS 记录' : '新增 DDNS 记录'" closable>
        <div class="drawer-form wide">
      <label>名称<n-input v-model:value="ddnsForm.name" /></label>
      <label><span class="field-label">FQDN<TermHint text="完整域名，例如 home.example.com，必须包含主机名和根域名。" /></span><n-input v-model:value="ddnsForm.fqdn" placeholder="home.example.com" /></label>
      <label>Provider
        <select v-model="ddnsForm.provider_id" :disabled="ddnsForm.managed_by_lucky">
          <option value="">未选择</option>
          <option v-for="provider in ops.ddnsProviders" :key="provider.id" :value="String(provider.id)">{{ provider.id }} - {{ provider.name }}</option>
        </select>
      </label>
      <label>类型
        <select v-model="ddnsForm.record_type">
          <option value="A">A</option>
          <option value="AAAA">AAAA</option>
        </select>
      </label>
      <label>IP 来源
        <select v-model="ddnsForm.ip_source">
          <option value="public_api">公网 IP 接口（推荐）</option>
          <option value="edge_public">Edge 公网</option>
          <option value="net_interface">本机网卡</option>
          <option value="manual">手动</option>
          <option value="lucky">Lucky 状态</option>
        </select>
      </label>
      <template v-if="ddnsForm.ip_source === 'public_api'">
        <label class="span-2"><span class="field-label">公网 IP 查询接口<TermHint text="每行一个 URL，按顺序尝试，自动用正则提取 IP。留空使用内置接口（api.ipify.org 等）。" /></span>
          <n-input v-model:value="ddnsForm.ip_urls" type="textarea" :rows="2" placeholder="https://api.ipify.org&#10;https://4.ipw.cn" />
        </label>
      </template>
      <template v-if="ddnsForm.ip_source === 'net_interface'">
        <label class="span-2"><span class="field-label">本机网卡<TermHint text="自动识别 Core 服务器上的网卡并显示当前 IP（含 IPv4 和 IPv6）。选择后同步将读取该网卡对应类型的地址。" /></span>
          <n-select
            v-model:value="ddnsForm.net_interface"
            :options="netInterfaceOptions"
            filterable
            clearable
            placeholder="选择网卡，或输入自定义名称"
          />
        </label>
        <div v-if="selectedNetInterface" class="span-2 iface-ip-summary">
          <span :class="['state-pill', selectedNetInterface.up ? 'enabled' : 'disabled']">{{ selectedNetInterface.up ? 'UP' : 'DOWN' }}</span>
          <code>{{ interfaceIPSummary(selectedNetInterface) || '该网卡无 IP 地址' }}</code>
        </div>
        <label class="span-2"><span class="field-label">IP 正则<TermHint text="过滤网卡上的 IP。预置常用选项，也可直接输入自定义正则。留空使用 A/AAAA 类型默认匹配。" /></span>
          <n-select
            v-model:value="ddnsForm.ip_regex"
            :options="IP_REGEX_OPTIONS"
            filterable
            clearable
            tag
            placeholder="选择常用正则，或输入自定义"
          />
          <div v-if="ipRegexOptionLabel" class="iface-ip-summary" style="margin-top: 6px">{{ ipRegexOptionLabel }}</div>
        </label>
      </template>
      <template v-if="ddnsForm.ip_source === 'manual'">
        <label class="span-2"><span class="field-label">手动 IP<TermHint text="直接填写要同步到 DNS 的 IP 地址。A 记录填 IPv4，AAAA 记录填 IPv6。" /></span>
          <n-input v-model:value="ddnsForm.manual_ip" placeholder="203.0.113.10 或 2001:db8::1" />
        </label>
      </template>
      <label><span class="field-label">TTL<TermHint text="DNS 缓存秒数。家庭动态 IP 常用 300 秒，过小会增加查询量。" /></span><n-input v-model:value="ddnsForm.ttl" /></label>
      <label>检查周期（秒）<n-input v-model:value="ddnsForm.interval_seconds" /></label>
      <label><span class="field-label">强制更新间隔（秒）<TermHint text="IP 未变化时也强制调 API 更新的间隔。0 表示禁用，仅在 IP 变化时更新。" /></span><n-input v-model:value="ddnsForm.force_interval_seconds" placeholder="0" /></label>
      <label><span class="field-label">通知 Webhook<TermHint text="同步完成后通知的 URL 或 JSON：{&quot;url&quot;:&quot;...&quot;,&quot;secret_ref&quot;:&quot;...&quot;,&quot;template&quot;:&quot;...&quot;}。占位符：{fqdn} {ip} {status} {action} {message} {time}" /></span><n-input v-model:value="ddnsForm.notify_webhook" placeholder="https://example.com/hook" /></label>
      <label>Lucky 协作
        <select v-model="ddnsForm.managed_by_lucky">
          <option :value="true">由 Lucky 管理</option>
          <option :value="false">由 PortHub 同步</option>
        </select>
      </label>
      <label class="check-line"><input v-model="ddnsForm.verify_dns" type="checkbox"> 同步前校验 DNS 已生效</label>
        </div>
        <template #footer>
          <n-button secondary @click="recordDrawer = false">取消</n-button>
          <n-button type="primary" class="create-action" @click="addDDNSRecord">{{ editingRecordID ? '保存修改' : '新增记录' }}</n-button>
        </template>
      </n-drawer-content>
    </n-drawer>

    <div class="sync-strip">
      <label>选择记录
        <select v-model="selectedRecordID">
          <option value="">选择 DDNS 记录</option>
          <option v-for="row in ops.ddnsRecords" :key="row.id" :value="String(row.id)">{{ row.id }} - {{ row.fqdn }}</option>
        </select>
      </label>
      <label>目标 IP<n-input v-model:value="syncValue" placeholder="真实同步必填；预演可留空" /></label>
      <label class="check-line"><input v-model="allowRealSync" type="checkbox"> 确认执行真实 DNS 同步</label>
    </div>

    <div class="table-wrap">
      <table>
        <thead><tr><th>名称</th><th>FQDN</th><th>Provider</th><th>类型</th><th>来源</th><th>最后值</th><th>同步状态</th><th>协作</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="row in ops.ddnsRecords" :key="row.id">
            <td>{{ row.name }}</td>
            <td>{{ row.fqdn }}</td>
            <td>{{ row.managed_by_lucky ? 'Lucky' : providerName(row.provider_id) }}</td>
            <td>{{ row.record_type }}</td>
            <td>{{ sourceLabel(row) }}</td>
            <td>{{ row.last_value || '--' }}</td>
            <td><span :class="['state-pill', row.last_error ? 'danger' : row.last_sync_at ? 'enabled' : 'neutral']">{{ row.last_error ? `失败 ${row.failure_count}` : row.last_sync_at ? '已同步' : '等待' }}</span></td>
            <td>{{ row.managed_by_lucky ? '协作' : 'PortHub' }}</td>
            <td><span :class="['state-pill', row.enabled ? 'enabled' : 'disabled']">{{ row.enabled ? '启用' : '禁用' }}</span></td>
            <td>
              <div class="button-row compact">
                <n-button size="small" secondary @click="openEditRecord(row)">编辑</n-button>
                <n-button size="small" secondary @click="selectedRecordID = String(row.id); runSync(true)">预演</n-button>
                <n-button size="small" secondary @click="toggleDDNSRecord(row)">{{ row.enabled ? '禁用' : '启用' }}</n-button>
                <n-button size="small" tertiary type="error" @click="removeDDNSRecord(row.id)">删除</n-button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <pre v-if="syncResult" class="result-box">{{ syncResult }}</pre>
  </section>
</template>

<style scoped>
.drawer-form {
  display: grid;
  gap: 14px;
}
.drawer-form.wide {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.drawer-form label {
  min-width: 0;
  display: grid;
  gap: 6px;
  color: var(--text-soft);
  font-size: 12px;
  font-weight: 550;
}
/* full-width fields inside the 2-col record drawer */
.drawer-form.wide > label.span-2,
.drawer-form.wide > .span-2,
.drawer-form.wide > .iface-ip-summary {
  grid-column: 1 / -1;
}
.drawer-form .field-hint {
  color: var(--muted);
  font-size: 11px;
  font-weight: 400;
}
.drawer-form .check-line {
  flex-direction: row;
  align-items: center;
  gap: 8px;
}
</style>
