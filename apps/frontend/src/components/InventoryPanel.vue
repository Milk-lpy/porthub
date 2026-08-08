<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { Boxes, ChevronDown, CircleHelp, Container, Network, Plus, RadioTower, ScanSearch, Sparkles, X } from '@lucide/vue'
import { NButton, NCollapseTransition, NInput, NInputNumber, NPopover, NTag } from 'naive-ui'
import { useOpsStore } from '../stores/ops'
import type { GenericItem } from '../stores/ops'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const tab = ref<'resources' | 'services' | 'groups'>('resources')
const formOpen = ref(false)
const advancedOpen = ref(false)
const discoveryOpen = ref(true)
const form = ref({ name: '', description: '', enabled: true, resourceType: 'server', ip: '', protocol: 'tcp', port: 0, data: '{}' })
const editingID = ref<number | null>(null)
const scanMode = ref<'common' | 'deep'>('common')
const scanHost = ref('')
const scanBusy = ref(false)
let scanTimer = 0

const title = computed(() => ({ resources: '内网资源', services: '服务目录', groups: '映射组' }[tab.value]))
const items = computed(() => ({ resources: ops.resources, services: ops.services, groups: ops.groups }[tab.value]))
const containers = computed(() => ops.nodeDiscovery.containers || [])
const listeners = computed(() => ops.nodeDiscovery.listeners.slice(0, 12))
const scan = computed(() => ops.lanScan)
const scanPercent = computed(() => scan.value.total ? Math.min(100, Math.round(scan.value.progress / scan.value.total * 100)) : 0)

function buildData() {
  if (advancedOpen.value && form.value.data.trim() !== '{}') return form.value.data
  if (tab.value === 'resources') return JSON.stringify({ type: form.value.resourceType, ip: form.value.ip.trim() })
  if (tab.value === 'services') return JSON.stringify({ protocol: form.value.protocol, port: Number(form.value.port || 0) })
  return JSON.stringify({ type: 'mapping_group' })
}

async function addItem() {
  try {
    const wasEditing = Boolean(editingID.value)
    const data = buildData()
    JSON.parse(data)
    if (editingID.value) await ops.updateGeneric(tab.value, { id: editingID.value, name: form.value.name.trim(), description: form.value.description.trim(), data, enabled: form.value.enabled })
    else await ops.createGeneric(tab.value, { name: form.value.name.trim(), description: form.value.description.trim(), data, enabled: form.value.enabled })
    form.value = { name: '', description: '', enabled: true, resourceType: 'server', ip: '', protocol: 'tcp', port: 0, data: '{}' }
    formOpen.value = false
    editingID.value = null
    emit('notify', `${title.value}${wasEditing ? '已更新' : '已保存'}`)
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

function editItem(row: GenericItem) {
  let data: Record<string, any> = {}
  try { data = JSON.parse(row.data || '{}') } catch { data = {} }
  editingID.value = row.id
  form.value = { name: row.name, description: row.description || '', enabled: row.enabled, resourceType: data.type || 'server', ip: data.ip || '', protocol: data.protocol || 'tcp', port: Number(data.port || 0), data: row.data || '{}' }
  advancedOpen.value = false
  formOpen.value = true
}

function toggleForm() {
  if (formOpen.value) editingID.value = null
  formOpen.value = !formOpen.value
}

async function importContainer(container: NonNullable<typeof ops.nodeDiscovery.containers>[number]) {
  try {
    await ops.createGeneric('resources', {
      name: container.name,
      description: `Docker · ${container.image}`,
      data: JSON.stringify({ type: 'docker', container_id: container.id, image: container.image, ports: container.ports }),
      enabled: container.state === 'running',
    })
    emit('notify', `已导入容器 ${container.name}`)
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function importListener(listener: { protocol: string; address: string; port: number }) {
  try {
    await ops.createGeneric('services', {
      name: `${listener.protocol.toUpperCase()} ${listener.port}`,
      description: `在 ${listener.address} 上自动发现`,
      data: JSON.stringify({ type: 'listener', protocol: listener.protocol, address: listener.address, port: listener.port }),
      enabled: true,
    })
    emit('notify', `已导入 ${listener.protocol.toUpperCase()} ${listener.port}`)
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function toggleItem(row: GenericItem) {
  try {
    await ops.updateGeneric(tab.value, { ...row, enabled: !row.enabled })
    emit('notify', '状态已更新')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function deleteItem(row: GenericItem) {
  try {
    await ops.deleteGeneric(tab.value, row.id)
    emit('notify', '条目已删除')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function startScan() {
  try {
    scanBusy.value = true
    await ops.startLanScan({ mode: scanMode.value, host: scanHost.value.trim() || undefined })
    await ops.refreshLanScan()
    startScanPolling()
    emit('notify', scanMode.value === 'deep' ? '全局深度扫描已开始，正在探测整个局域网的全部 TCP 端口' : '局域网扫描已开始')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  } finally {
    scanBusy.value = false
  }
}

async function stopScan() {
  try {
    await ops.stopLanScan()
    emit('notify', '已请求停止扫描，已发现的数据会保留')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

function startScanPolling() {
  window.clearInterval(scanTimer)
  scanTimer = window.setInterval(async () => {
    await ops.refreshLanScan()
    if (scan.value.status !== 'running') window.clearInterval(scanTimer)
  }, 1500)
}

async function importScanResource(host: NonNullable<typeof scan.value.hosts>[number]) {
  try {
    await ops.createGeneric('resources', { name: `${host.classification} ${host.ip}`, description: `局域网扫描发现 · ${host.ports.length} 个 TCP 服务`, data: JSON.stringify({ type: host.classification, ip: host.ip, source: 'lan_scan', ports: host.ports }), enabled: true })
    emit('notify', `已导入资源 ${host.ip}`)
  } catch (err) { emit('notify', err instanceof Error ? err.message : String(err), 'error') }
}

async function importScanPort(host: NonNullable<typeof scan.value.hosts>[number], port: NonNullable<typeof host.ports>[number]) {
  try {
    await ops.createGeneric('services', { name: `${port.suggested_name} · ${host.ip}`, description: `自动扫描发现 · ${port.category}`, data: JSON.stringify({ type: 'lan_scan', protocol: port.protocol, port: port.port, ip: host.ip, service: port.service, category: port.category, risk: port.risk }), enabled: true })
    emit('notify', `已导入 ${host.ip}:${port.port}`)
  } catch (err) { emit('notify', err instanceof Error ? err.message : String(err), 'error') }
}

async function draftScanForward(host: NonNullable<typeof scan.value.hosts>[number], port: NonNullable<typeof host.ports>[number]) {
  try {
    await ops.createPortForward({
      name: `${port.suggested_name} · ${host.ip}`,
      node_id: 'local', listen_family: 'ipv4', listen_address: '0.0.0.0', listen_port_start: port.port, listen_port_end: port.port,
      protocol: 'tcp', target_family: 'ipv4', target_host: host.ip, target_port_start: port.port, target_port_end: port.port,
      forward_mode: 'auto', snat_mode: 'masquerade', enabled: false, acl_id: 0, allowed_cidrs: [], denied_cidrs: [], rate_limit_kbps: 0, udp_idle_timeout: 60, health_check: true,
    })
    emit('notify', `已创建停用状态的发布草稿：${host.ip}:${port.port}`)
  } catch (err) { emit('notify', err instanceof Error ? err.message : String(err), 'error') }
}

onMounted(() => { if (scan.value.status === 'running') startScanPolling() })
onBeforeUnmount(() => window.clearInterval(scanTimer))
</script>

<template>
  <section class="panel inventory-panel">
    <div class="panel-title">
      <div><span class="eyebrow">RESOURCE CATALOG</span><h2>{{ title }}</h2><span>把设备与服务整理成发布向导可以直接选择的对象</span></div>
      <div class="page-actions"><div class="segmented"><button :class="{ active: tab === 'resources' }" @click="tab = 'resources'">资源</button><button :class="{ active: tab === 'services' }" @click="tab = 'services'">服务</button><button :class="{ active: tab === 'groups' }" @click="tab = 'groups'">映射组</button></div><n-button type="primary" size="small" class="create-action" @click="toggleForm"><X v-if="formOpen" :size="16" /><Plus v-else :size="16" />{{ formOpen ? '收起' : `新增${title}` }}</n-button></div>
    </div>

    <div class="catalog-summary"><div><small>内网资源</small><b>{{ ops.resources.length }}</b></div><div><small>服务目录</small><b>{{ ops.services.length }}</b></div><div><small>映射组</small><b>{{ ops.groups.length }}</b></div><div><small>发现平台</small><b class="platform-name">{{ ops.nodeDiscovery.platform || 'Linux' }}</b></div></div>

    <div class="lan-scan-panel">
      <header class="lan-scan-header"><div><span class="scan-icon"><Network :size="17" /></span><span><b>局域网自动扫描</b><small>只扫描 PortHub 配置的局域网范围，发现结果需要确认后才会进入目录</small></span></div><n-tag size="small" :type="scan.status === 'running' ? 'warning' : scan.status === 'completed' ? 'success' : scan.status === 'failed' ? 'error' : scan.status === 'stopped' ? 'info' : 'default'" :bordered="false">{{ scan.status === 'running' ? '扫描中' : scan.status === 'completed' ? '已完成' : scan.status === 'failed' ? '失败' : scan.status === 'stopped' ? '已停止' : '待开始' }}</n-tag></header>
      <div class="lan-scan-controls"><label>扫描方式<select v-model="scanMode"><option value="common">常用端口 · 全局域网</option><option value="deep">全部端口 · 全局深度扫描</option></select></label><label>扫描范围 <n-input value="PortHub 配置的全部局域网网段" readonly /></label><div class="scan-actions"><n-button type="primary" :loading="scanBusy || scan.status === 'running'" :disabled="scan.status === 'running'" @click="startScan"><ScanSearch :size="15" />开始扫描</n-button><n-button v-if="scan.status === 'running'" type="error" secondary @click="stopScan">停止检测</n-button></div></div>
      <div v-if="scan.status === 'running' || scan.status === 'stopped'" class="scan-progress"><span><b>{{ scan.status === 'stopped' ? '检测已停止，已保留已发现数据' : '正在探测 TCP 端口' }}</b><small>{{ scan.progress.toLocaleString() }} / {{ scan.total.toLocaleString() }} · {{ scanPercent }}%</small></span><i><em :style="{ width: `${scanPercent}%` }" /></i></div>
      <div v-if="scan.error" class="scan-error">{{ scan.error }}</div>
      <div v-if="scan.hosts.length" class="scan-results"><article v-for="host in scan.hosts" :key="host.ip" class="scan-host"><div class="scan-host-head"><div><b>{{ host.ip }}</b><n-tag size="tiny" type="info" :bordered="false">{{ host.classification }}</n-tag><small>{{ host.ports.length }} 个 TCP 服务</small></div><n-button size="tiny" secondary @click="importScanResource(host)">导入资源</n-button></div><div class="scan-port-list"><div v-for="port in host.ports" :key="`${host.ip}-${port.port}`"><span><b>{{ port.port }} · {{ port.service }}</b><small>{{ port.category }} · {{ port.protocol.toUpperCase() }}</small></span><n-tag size="tiny" :type="port.risk === '高' ? 'error' : 'warning'" :bordered="false">风险{{ port.risk }}</n-tag><n-button size="tiny" tertiary @click="importScanPort(host, port)">导入服务</n-button><n-button size="tiny" type="primary" secondary @click="draftScanForward(host, port)">创建发布草稿</n-button></div></div></article></div>
      <p class="scan-note">说明：全局深度扫描会逐台探测配置网段内每个 IPv4 地址的 1-65535 TCP 端口，耗时可能较长；UDP 没有握手，仍以 Agent 的本机监听发现为准。SSH、RDP、SMB、数据库等高风险服务导入后不会自动发布。</p>
    </div>

    <n-collapse-transition :show="formOpen">
      <div class="inventory-editor reveal-form">
        <div class="form-grid">
          <label>名称<n-input v-model:value="form.name" :placeholder="tab === 'resources' ? '例如：书房 NAS' : tab === 'services' ? '例如：NAS 管理页面' : '例如：远程管理组'" /></label>
          <label>描述<n-input v-model:value="form.description" placeholder="用途、位置或负责人（可选）" /></label>
          <template v-if="tab === 'resources'"><label>设备类型<select v-model="form.resourceType"><option value="server">Linux 服务器</option><option value="nas">NAS</option><option value="pve">PVE</option><option value="windows">Windows</option><option value="docker">Docker 主机</option></select></label><label>内网 IP<n-input v-model:value="form.ip" placeholder="192.0.2.50" /></label></template>
          <template v-else-if="tab === 'services'"><label>协议<select v-model="form.protocol"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="http">HTTP</option><option value="https">HTTPS</option></select></label><label>服务端口<n-input-number v-model:value="form.port" :min="1" :max="65535" /></label></template>
        </div>
        <button class="advanced-toggle" @click="advancedOpen = !advancedOpen"><ChevronDown :size="15" :class="{ rotated: advancedOpen }" />高级数据 <span>仅在需要自定义字段时使用</span></button>
        <n-collapse-transition :show="advancedOpen"><label class="advanced-json"><span>数据 JSON<n-popover trigger="hover"><template #trigger><CircleHelp :size="14" /></template>高级集成使用的结构化扩展字段，普通发布不需要修改。</n-popover></span><n-input v-model:value="form.data" type="textarea" :autosize="{ minRows: 2, maxRows: 6 }" /></label></n-collapse-transition>
        <footer><n-button type="primary" :disabled="!form.name.trim()" @click="addItem">{{ editingID ? '保存修改' : `保存${title}` }}</n-button></footer>
      </div>
    </n-collapse-transition>

    <div class="discovery-head"><div><Sparkles :size="17" /><span><b>自动发现</b><small>{{ containers.length }} 个容器 · {{ ops.nodeDiscovery.listeners.length }} 个监听端口</small></span></div><n-button size="tiny" tertiary @click="discoveryOpen = !discoveryOpen">{{ discoveryOpen ? '收起' : '展开' }}</n-button></div>
    <n-collapse-transition :show="discoveryOpen">
      <div class="discovery-grid">
        <article class="discovery-column"><header><Container :size="16" /><b>Docker 容器</b></header><div v-if="containers.length" class="discovery-list"><div v-for="container in containers" :key="container.id"><span><b>{{ container.name }}</b><small>{{ container.image }} · {{ container.status }}</small></span><n-button size="tiny" secondary @click="importContainer(container)">导入资源</n-button></div></div><div v-else class="compact-empty"><Boxes :size="18" />未发现可读取的容器</div></article>
        <article class="discovery-column"><header><RadioTower :size="16" /><b>监听服务</b><span>显示前 12 项</span></header><div v-if="listeners.length" class="discovery-list"><div v-for="(listener, index) in listeners" :key="`${listener.protocol}-${listener.address}-${listener.port}-${index}`"><span><b>{{ listener.protocol.toUpperCase() }} {{ listener.port }}</b><small>{{ listener.address }}</small></span><n-button size="tiny" secondary @click="importListener(listener)">导入服务</n-button></div></div><div v-else class="compact-empty">未发现监听服务</div></article>
      </div>
    </n-collapse-transition>

    <div v-if="items.length" class="table-wrap inventory-table"><table><thead><tr><th>名称</th><th>描述</th><th>状态</th><th>操作</th></tr></thead><tbody><tr v-for="row in items" :key="row.id"><td><b>{{ row.name }}</b></td><td>{{ row.description || '--' }}</td><td><span :class="['state-pill', row.enabled ? 'enabled' : 'disabled']">{{ row.enabled ? '启用' : '禁用' }}</span></td><td><div class="button-row compact"><n-button size="small" secondary @click="editItem(row)">编辑</n-button><n-button size="small" secondary @click="toggleItem(row)">{{ row.enabled ? '禁用' : '启用' }}</n-button><n-button size="small" tertiary type="error" @click="deleteItem(row)">删除</n-button></div></td></tr></tbody></table></div>
    <div v-else class="empty-state">当前分类还没有数据，可以从自动发现中导入</div>
  </section>
</template>

<style scoped>
.lan-scan-panel { margin: 0 0 16px; border: 1px solid color-mix(in srgb, var(--accent-2) 36%, var(--line)); border-radius: 8px; background: var(--surface-2); overflow: hidden; }
.lan-scan-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 14px; border-bottom: 1px solid var(--line); background: color-mix(in srgb, var(--accent-2) 6%, var(--surface-2)); }
.lan-scan-header > div, .lan-scan-header > div > span:last-child { display: flex; align-items: center; gap: 9px; min-width: 0; }.lan-scan-header > div > span:last-child { display: grid; gap: 2px; }.lan-scan-header b { color: var(--text); font-size: 11px; }.lan-scan-header small { color: var(--muted); font-size: 9px; line-height: 1.4; }.scan-icon { width: 32px; height: 32px; display: grid; place-items: center; border: 1px solid color-mix(in srgb, var(--accent-2) 40%, var(--line)); border-radius: 7px; color: var(--accent-2); }
.lan-scan-controls { display: grid; grid-template-columns: 1fr 1.4fr auto; align-items: end; gap: 10px; padding: 12px 14px; }.lan-scan-controls label { display: grid; gap: 5px; color: var(--muted); font-size: 9px; }.lan-scan-controls select { width: 100%; min-height: 34px; padding: 0 9px; border: 1px solid var(--line); border-radius: 5px; background: var(--surface-raised); color: var(--text); font-size: 11px; }.scan-actions { display: flex; gap: 7px; align-items: center; }
.scan-progress { display: grid; gap: 7px; padding: 0 14px 12px; }.scan-progress > span { display: flex; justify-content: space-between; gap: 10px; color: var(--text-soft); font-size: 10px; }.scan-progress small { color: var(--muted); }.scan-progress i { display: block; height: 5px; border-radius: 5px; background: var(--line); overflow: hidden; }.scan-progress em { display: block; height: 100%; border-radius: inherit; background: var(--accent-2); transition: width .25s ease; }.scan-error { margin: 0 14px 12px; padding: 8px 10px; border: 1px solid color-mix(in srgb, var(--red) 35%, var(--line)); color: var(--red); font-size: 10px; }
.scan-results { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; padding: 0 14px 12px; }.scan-host { min-width: 0; border: 1px solid var(--line); border-radius: 6px; background: var(--surface-raised); overflow: hidden; }.scan-host-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 9px 10px; border-bottom: 1px solid var(--line); }.scan-host-head > div { min-width: 0; display: flex; align-items: center; flex-wrap: wrap; gap: 6px; }.scan-host-head b { color: var(--text); font-size: 11px; }.scan-host-head small { color: var(--muted); font-size: 9px; }.scan-port-list { display: grid; max-height: 205px; overflow-y: auto; }.scan-port-list > div { display: grid; grid-template-columns: minmax(0, 1fr) auto auto auto; align-items: center; gap: 7px; padding: 7px 10px; border-bottom: 1px solid var(--line); }.scan-port-list > div:last-child { border-bottom: 0; }.scan-port-list span { min-width: 0; display: grid; gap: 2px; }.scan-port-list b { overflow: hidden; color: var(--text-soft); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }.scan-port-list small { color: var(--muted); font-size: 8px; }.scan-note { margin: 0; padding: 0 14px 12px; color: var(--muted); font-size: 9px; line-height: 1.5; }
@media (max-width: 700px) { .lan-scan-header { align-items: flex-start; }.lan-scan-controls { grid-template-columns: 1fr; }.lan-scan-controls .n-button { width: 100%; }.scan-results { grid-template-columns: 1fr; }.scan-port-list > div { grid-template-columns: minmax(0, 1fr) auto; }.scan-port-list .n-button { grid-column: 1 / -1; width: 100%; } }
</style>
