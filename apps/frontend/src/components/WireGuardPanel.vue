<script setup lang="ts">
import { computed, ref } from 'vue'
import { Cable, ChevronDown, CircleHelp, Pencil, Plus, Rocket, ShieldCheck, Trash2, Wifi, X } from '@lucide/vue'
import { NButton, NCollapseTransition, NInput, NInputNumber, NPopover, NPopconfirm, NSwitch } from 'naive-ui'
import { useOpsStore, type WireGuardPeer } from '../stores/ops'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const editorOpen = ref(false)
const advancedOpen = ref(false)
const guideOpen = ref(false)
const saving = ref(false)
const deploying = ref(false)
const editingID = ref(0)
const form = ref(emptyForm())

function emptyForm() {
  return {
    node_id: '', name: '', public_key: '', address: '', allowed_ips: '',
    persistent_keepalive: 25, enabled: true,
  }
}

const runtimeByID = computed(() => new Map((ops.wireGuardStatus.peers || []).map((peer) => [peer.id, peer])))
const enabledCount = computed(() => ops.wireGuardPeers.filter((peer) => peer.enabled).length)
const onlineCount = computed(() => (ops.wireGuardStatus.peers || []).filter((peer) => peer.online).length)

function openCreate() {
  editingID.value = 0
  form.value = emptyForm()
  advancedOpen.value = false
  editorOpen.value = true
}

function openEdit(peer: WireGuardPeer) {
  editingID.value = peer.id
  form.value = {
    node_id: peer.node_id,
    name: peer.name,
    public_key: peer.public_key,
    address: peer.address,
    allowed_ips: peer.allowed_ips.join('\n'),
    persistent_keepalive: peer.persistent_keepalive,
    enabled: peer.enabled,
  }
  advancedOpen.value = Boolean(peer.node_id || peer.allowed_ips.length)
  editorOpen.value = true
}

async function savePeer() {
  if (!form.value.name.trim()) return emit('notify', '请填写节点名称', 'error')
  if (!form.value.public_key.trim()) return emit('notify', '请粘贴客户端公钥', 'error')
  saving.value = true
  const payload = {
    node_id: form.value.node_id.trim(),
    name: form.value.name.trim(),
    public_key: form.value.public_key.trim(),
    address: form.value.address.trim(),
    allowed_ips: form.value.allowed_ips.split(/[\n,]+/).map((value) => value.trim()).filter(Boolean),
    persistent_keepalive: form.value.persistent_keepalive || 25,
    enabled: form.value.enabled,
  }
  try {
    if (editingID.value) await ops.updateWireGuardPeer({ id: editingID.value, ...payload })
    else await ops.createWireGuardPeer(payload)
    editorOpen.value = false
    emit('notify', editingID.value ? '节点配置已更新，点击“部署变更”后生效' : '节点已保存，点击“部署变更”后接入 Edge')
  } catch (err) {
    emit('notify', friendlyError(err), 'error')
  } finally {
    saving.value = false
  }
}

async function removePeer(id: number) {
  try {
    await ops.deleteWireGuardPeer(id)
    emit('notify', '节点已从草稿移除，部署变更后 Edge 才会断开该节点')
  } catch (err) {
    emit('notify', friendlyError(err), 'error')
  }
}

async function deployPeers() {
  deploying.value = true
  try {
    const result = await ops.deployWireGuardPeers()
    emit('notify', `隧道配置已部署，当前管理 ${result.managed_peers || 0} 个节点`)
  } catch (err) {
    emit('notify', friendlyError(err), 'error')
  } finally {
    deploying.value = false
  }
}

function shortKey(value: string) {
  return value.length > 18 ? `${value.slice(0, 9)}…${value.slice(-7)}` : value
}

function formatBytes(value = 0) {
  if (value < 1024) return `${value} B`
  if (value < 1048576) return `${(value / 1024).toFixed(1)} KiB`
  if (value < 1073741824) return `${(value / 1048576).toFixed(1)} MiB`
  return `${(value / 1073741824).toFixed(1)} GiB`
}

function handshakeText(value?: number) {
  if (!value) return '尚未握手'
  const seconds = Math.max(0, Math.floor(Date.now() / 1000 - value))
  if (seconds < 60) return `${seconds} 秒前握手`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前握手`
  return `${Math.floor(seconds / 3600)} 小时前握手`
}

function friendlyError(err: unknown) {
  const value = err instanceof Error ? err.message : String(err)
  if (value.includes('public key')) return '公钥格式不正确，或该公钥已经被其他节点使用'
  if (value.includes('address')) return '隧道地址格式不正确，或已经被占用'
  if (value.includes('overlap')) return '路由范围与现有 WireGuard 节点冲突，请检查高级设置'
  return value
}
</script>

<template>
  <section class="panel wireguard-panel">
    <div class="panel-title wireguard-title">
      <div>
        <span class="eyebrow">PRIVATE NETWORK</span>
        <h2>WireGuard 隧道</h2>
        <p>安全连接外部 Linux、NAS、PVE 或 Docker 节点</p>
      </div>
      <div class="page-actions">
        <n-button secondary size="small" @click="guideOpen = !guideOpen"><CircleHelp :size="16" />使用向导</n-button>
        <n-button secondary size="small" @click="openCreate"><Plus :size="16" />添加节点</n-button>
        <n-popconfirm positive-text="确认部署" negative-text="取消" @positive-click="deployPeers">
          <template #trigger><n-button type="primary" size="small" class="create-action" :loading="deploying"><Rocket :size="16" />部署变更</n-button></template>
          将当前已启用的节点配置同步到 Edge。已有 Core 隧道受保护，不会被修改。
        </n-popconfirm>
      </div>
    </div>

    <n-collapse-transition :show="guideOpen">
      <div class="wg-guide">
        <div><b>1</b><span><strong>在客户端生成密钥</strong>私钥留在客户端，只复制公钥。</span></div>
        <div><b>2</b><span><strong>添加并保存节点</strong>留空隧道地址即可自动分配。</span></div>
        <div><b>3</b><span><strong>部署到 Edge</strong>客户端填入 Edge 公钥和公网端口后连接。</span></div>
      </div>
    </n-collapse-transition>

    <div class="wg-summary">
      <div><span class="wg-summary-icon"><Cable :size="19" /></span><p><small>隧道接口</small><strong>{{ ops.wireGuardStatus.interface || 'wg-porthub' }}</strong></p></div>
      <div><span class="wg-summary-icon"><Wifi :size="19" /></span><p><small>在线节点</small><strong>{{ onlineCount }} / {{ enabledCount }}</strong></p></div>
      <div><span class="wg-summary-icon"><ShieldCheck :size="19" /></span><p><small>Edge 监听端口</small><strong>{{ ops.wireGuardStatus.listen_port || '--' }} / UDP</strong></p></div>
      <div><span class="wg-summary-icon"><ShieldCheck :size="19" /></span><p><small>受保护的已有节点</small><strong>{{ ops.wireGuardStatus.protected_peers ?? '--' }}</strong></p></div>
    </div>

    <n-collapse-transition :show="editorOpen">
      <div class="wg-editor">
        <header><div><b>{{ editingID ? '编辑节点' : '添加新节点' }}</b><span>基础接入只需填写名称与客户端公钥</span></div><button class="icon-button" title="关闭编辑器" @click="editorOpen = false"><X :size="17" /></button></header>
        <div class="form-grid wg-form">
          <label>节点名称<n-input v-model:value="form.name" placeholder="例如：书房 NAS" /></label>
          <label>
            <span class="field-label">客户端公钥
              <n-popover trigger="hover" placement="top"><template #trigger><CircleHelp :size="14" /></template>在客户端运行 <code>wg pubkey</code> 得到。私钥不要粘贴到面板。</n-popover>
            </span>
            <n-input v-model:value="form.public_key" placeholder="44 位 Base64 公钥" />
          </label>
        </div>
        <button class="advanced-toggle" @click="advancedOpen = !advancedOpen"><ChevronDown :size="15" :class="{ rotated: advancedOpen }" />高级设置 <span>通常保持默认即可</span></button>
        <n-collapse-transition :show="advancedOpen">
          <div class="form-grid wg-form advanced">
            <label>关联节点 ID<n-input v-model:value="form.node_id" placeholder="可选，例如 nas-01" /></label>
            <label>
              <span class="field-label">隧道地址<n-popover trigger="hover"><template #trigger><CircleHelp :size="14" /></template>节点在 PortHub 私网中的固定地址。留空时从 .10 开始自动分配。</n-popover></span>
              <n-input v-model:value="form.address" placeholder="留空自动分配" />
            </label>
            <label>
              <span class="field-label">Allowed IPs<n-popover trigger="hover"><template #trigger><CircleHelp :size="14" /></template>还需要通过这个节点访问的内网网段。只接入节点本身时留空。</n-popover></span>
              <n-input v-model:value="form.allowed_ips" type="textarea" :autosize="{ minRows: 2, maxRows: 4 }" placeholder="例如 192.168.50.0/24，每行一个" />
            </label>
            <label>
              <span class="field-label">保活间隔<n-popover trigger="hover"><template #trigger><CircleHelp :size="14" /></template>位于 NAT 后的节点建议 25 秒，可让隧道持续可达。</n-popover></span>
              <n-input-number v-model:value="form.persistent_keepalive" :min="1" :max="300" suffix="秒" />
            </label>
          </div>
        </n-collapse-transition>
        <footer><span><n-switch v-model:value="form.enabled" size="small" />启用该节点</span><n-button type="primary" class="create-action" :loading="saving" @click="savePeer">保存草稿</n-button></footer>
      </div>
    </n-collapse-transition>

    <div v-if="ops.wireGuardPeers.length" class="wg-peer-list">
      <article v-for="peer in ops.wireGuardPeers" :key="peer.id" class="wg-peer">
        <div class="wg-peer-state"><i :class="runtimeByID.get(peer.id)?.online ? 'online' : peer.enabled ? 'warn' : 'disabled'"></i></div>
        <div class="wg-peer-main">
          <header><div><b>{{ peer.name }}</b><span :class="['state-pill', runtimeByID.get(peer.id)?.online ? 'enabled' : peer.enabled ? 'warn' : 'disabled']">{{ runtimeByID.get(peer.id)?.online ? '在线' : peer.enabled ? '等待连接' : '已禁用' }}</span></div><code :title="peer.public_key">{{ shortKey(peer.public_key) }}</code></header>
          <div class="wg-peer-meta"><span>隧道地址 <b>{{ peer.address }}</b></span><span>{{ handshakeText(runtimeByID.get(peer.id)?.latest_handshake) }}</span><span>接收 {{ formatBytes(runtimeByID.get(peer.id)?.rx_bytes) }}</span><span>发送 {{ formatBytes(runtimeByID.get(peer.id)?.tx_bytes) }}</span></div>
        </div>
        <div class="wg-peer-actions">
          <button class="icon-button" title="编辑节点" @click="openEdit(peer)"><Pencil :size="16" /></button>
          <n-popconfirm positive-text="移除草稿" negative-text="取消" @positive-click="removePeer(peer.id)">
            <template #trigger><button class="icon-button danger" title="移除节点"><Trash2 :size="16" /></button></template>
            移除后还需点击“部署变更”，Edge 才会断开这个节点。
          </n-popconfirm>
        </div>
      </article>
    </div>
    <div v-else class="empty-state wg-empty"><Cable :size="25" /><b>还没有受管节点</b><span>添加节点不会影响当前 Core 隧道</span><n-button size="small" secondary @click="openCreate"><Plus :size="15" />添加第一个节点</n-button></div>
  </section>
</template>
