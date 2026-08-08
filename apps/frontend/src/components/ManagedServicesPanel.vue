<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, type Component } from 'vue'
import { Activity, Cable, CircleHelp, Clock3, KeyRound, Play, RefreshCw, RotateCw, Route, ServerCog, Square, Wifi, WifiOff } from '@lucide/vue'
import { NAlert, NButton, NPopconfirm, NSpin, NSwitch, NTag, NTooltip } from 'naive-ui'
import { hasRole, request } from '../api'

type ServiceAction = 'start' | 'stop' | 'restart' | 'enable' | 'disable'
type Listener = { protocol: string; address: string; port: number }
type ManagedService = {
  name: string
  description: string
  active_state: string
  sub_state: string
  unit_file_state: string
  main_pid: number
  started_at: string
  listeners: Listener[]
}
type WireGuardState = {
  interface: string
  present: boolean
  addresses: string[]
  listen_port: number
  peer_count: number
  latest_handshake: number
  rx_bytes: number
  tx_bytes: number
}
type ManagedResponse = { ok?: boolean; services: ManagedService[]; wireguard: WireGuardState; updated_at: string }
type ServiceMeta = { title: string; subtitle: string; impact: string; category: 'dst' | 'qx'; icon: Component; actions: ServiceAction[] }

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const services = ref<ManagedService[]>([])
const wireGuard = ref<WireGuardState>({ interface: 'wg-dst', present: false, addresses: [], listen_port: 0, peer_count: 0, latest_handshake: 0, rx_bytes: 0, tx_bytes: 0 })
const loading = ref(true)
const error = ref('')
const updatedAt = ref('')
const busyService = ref('')
const canControl = computed(() => hasRole('admin'))
let pollTimer = 0

const display: Record<string, ServiceMeta> = {
  'dst-wireguard': {
    title: 'DST 加密隧道', subtitle: '为 DST 客户端建立独立 WireGuard 网络', category: 'dst', icon: Cable,
    impact: '停止后会删除 wg-dst 接口，所有 DST 隧道连接立即中断。', actions: ['start', 'stop', 'restart', 'enable', 'disable'],
  },
  'dst-wireguard-health': {
    title: 'DST 健康检测', subtitle: '让客户端判断隧道与服务端是否可用', category: 'dst', icon: Activity,
    impact: '停止后客户端无法进行健康探测，但现有隧道不会被删除。', actions: ['start', 'stop', 'restart', 'enable', 'disable'],
  },
  'dst-wireguard-register': {
    title: 'DST 设备注册', subtitle: '处理受签名保护的客户端注册请求', category: 'dst', icon: KeyRound,
    impact: '停止后新设备无法注册，已经建立的 Peer 不会被删除。', actions: ['start', 'stop', 'restart', 'enable', 'disable'],
  },
  'prefer-real-ipv6-gateway': {
    title: 'IPv6 出口策略', subtitle: '让公网 IPv6 优先经过实体路由器', category: 'dst', icon: Route,
    impact: '这是一次性路由策略，仅允许重新应用或调整开机自启。', actions: ['restart', 'enable', 'disable'],
  },
  'qx-lan-socks': {
    title: 'QX 局域网 SOCKS5', subtitle: '为局域网设备提供代理入口', category: 'qx', icon: Wifi,
    impact: '停止后，正在使用此代理的设备会立即断开。', actions: ['start', 'stop', 'restart', 'enable', 'disable'],
  },
  'qx-lan-config-http': {
    title: 'QX 配置分发', subtitle: '向手机等设备提供配置下载地址', category: 'qx', icon: ServerCog,
    impact: '停止后，已有配置仍在，但设备无法重新下载。', actions: ['start', 'stop', 'restart', 'enable', 'disable'],
  },
}

const groups = computed(() => [
  { key: 'dst', eyebrow: 'DST NETWORK', title: 'DST 网络', description: '隧道、健康检测、设备注册与 IPv6 出口策略', services: services.value.filter((item) => info(item).category === 'dst') },
  { key: 'qx', eyebrow: 'QX TOOLING', title: 'QX 工具', description: '局域网代理和移动端配置分发', services: services.value.filter((item) => info(item).category === 'qx') },
].filter((group) => group.services.length))

function info(service: ManagedService): ServiceMeta {
  return display[service.name] || {
    title: service.description || service.name, subtitle: '受 PortHub 管理的固定本机服务', category: 'dst', icon: ServerCog,
    impact: '停止前请确认没有设备正在使用。', actions: ['start', 'stop', 'restart', 'enable', 'disable'],
  }
}

function isHealthy(service: ManagedService) {
  return service.active_state === 'active' && ['running', 'exited'].includes(service.sub_state)
}

function isEnabled(service: ManagedService) {
  return ['enabled', 'enabled-runtime'].includes(service.unit_file_state)
}

function supports(service: ManagedService, action: ServiceAction) {
  return info(service).actions.includes(action)
}

function stateLabel(service: ManagedService) {
  if (service.active_state === 'active' && service.sub_state === 'exited') return '已生效'
  if (isHealthy(service)) return '运行中'
  if (service.active_state === 'activating') return '正在启动'
  if (service.active_state === 'failed') return '运行失败'
  return '已停止'
}

function stateType(service: ManagedService): 'success' | 'warning' | 'error' | 'default' {
  if (isHealthy(service)) return 'success'
  if (service.active_state === 'activating') return 'warning'
  if (service.active_state === 'failed') return 'error'
  return 'default'
}

function formatListener(listener: Listener) {
  const address = ['0.0.0.0', '::', '全部地址'].includes(listener.address) ? '全部地址' : listener.address
  return `${listener.protocol.toUpperCase()} ${address}:${listener.port}`
}

function formatUpdated(value: string) {
  if (!value) return '--'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour12: false })
}

function formatBytes(value: number) {
  if (!value) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB']
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  return `${(value / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`
}

function handshakeText(value: number) {
  if (!value) return '尚无握手'
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - value)
  if (seconds < 60) return `${seconds} 秒前`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
  return `${Math.floor(seconds / 86400)} 天前`
}

async function refresh(silent = false) {
  if (!silent) loading.value = true
  try {
    const response = await request<ManagedResponse>('/api/managed-services')
    services.value = response.services || []
    wireGuard.value = response.wireguard || wireGuard.value
    updatedAt.value = response.updated_at
    error.value = ''
  } catch (err) {
    error.value = friendlyError(err)
  } finally {
    loading.value = false
  }
}

async function control(service: ManagedService, action: ServiceAction) {
  busyService.value = service.name
  try {
    const response = await request<ManagedResponse>('/api/managed-services', {
      method: 'POST', body: JSON.stringify({ service: service.name, action }),
    })
    services.value = response.services || []
    wireGuard.value = response.wireguard || wireGuard.value
    updatedAt.value = response.updated_at
    error.value = ''
    emit('notify', actionMessage(action, info(service).title))
  } catch (err) {
    const message = friendlyError(err)
    error.value = message
    emit('notify', message, 'error')
  } finally {
    busyService.value = ''
  }
}

function changeAutostart(service: ManagedService, enabled: boolean) {
  void control(service, enabled ? 'enable' : 'disable')
}

function actionMessage(action: ServiceAction, title: string) {
  const labels: Record<ServiceAction, string> = { start: '已启动', stop: '已停止', restart: '已重新应用', enable: '已启用开机自启', disable: '已关闭开机自启' }
  return `${title}${labels[action]}`
}

function friendlyError(err: unknown) {
  const message = err instanceof Error ? err.message : String(err)
  if (message.includes('forbidden')) return '当前账号没有管理本机服务的权限'
  if (message.includes('助手不可用')) return '服务管理助手暂时不可用，请检查 PortHub netd'
  return message || '本机服务操作失败'
}

onMounted(() => {
  void refresh()
  pollTimer = window.setInterval(() => {
    if (!busyService.value && document.visibilityState === 'visible') void refresh(true)
  }, 15000)
})
onBeforeUnmount(() => window.clearInterval(pollTimer))
</script>

<template>
  <section class="panel service-center">
    <div class="panel-title">
      <div><span class="eyebrow">LOCAL SERVICE CENTER</span><h2>本机服务中心</h2><p>统一管理 DST 网络组件与 QX 局域网工具，所有操作都经过固定白名单。</p></div>
      <n-button secondary :loading="loading" aria-label="刷新本机服务状态" @click="refresh()"><RefreshCw :size="16" />刷新状态</n-button>
    </div>

    <div class="service-guide" aria-label="本机服务使用步骤">
      <div><span>1</span><b>先看隧道</b><small>确认 wg-dst 在线且最近有握手</small></div>
      <div><span>2</span><b>再看服务</b><small>绿色表示运行正常或策略已生效</small></div>
      <div><span>3</span><b>谨慎操作</b><small>重启隧道会短暂中断游戏连接</small></div>
    </div>

    <div class="tunnel-strip" :class="{ offline: !wireGuard.present }">
      <div class="tunnel-identity"><span><Cable :size="22" /></span><div><small>DST 加密隧道</small><b>{{ wireGuard.interface || 'wg-dst' }}</b><code>{{ wireGuard.addresses?.join(' · ') || '接口未建立' }}</code></div></div>
      <div class="tunnel-metric"><small>状态</small><b :class="wireGuard.present ? 'ok' : 'bad'">{{ wireGuard.present ? '在线' : '离线' }}</b></div>
      <div class="tunnel-metric"><small>监听端口</small><b>{{ wireGuard.listen_port || '--' }}</b><span>UDP</span></div>
      <div class="tunnel-metric"><small>Peer <n-tooltip trigger="hover"><template #trigger><CircleHelp :size="13" /></template>Peer 是接入这条加密隧道的客户端设备。</n-tooltip></small><b>{{ wireGuard.peer_count }}</b><span>台设备</span></div>
      <div class="tunnel-metric"><small>最近握手 <n-tooltip trigger="hover"><template #trigger><CircleHelp :size="13" /></template>最近一次客户端与服务器成功确认加密连接的时间。</n-tooltip></small><b>{{ handshakeText(wireGuard.latest_handshake) }}</b><span>{{ wireGuard.latest_handshake ? '连接有活动' : '等待客户端' }}</span></div>
      <div class="tunnel-metric traffic"><small>隧道流量</small><b>↓ {{ formatBytes(wireGuard.rx_bytes) }}</b><span>↑ {{ formatBytes(wireGuard.tx_bytes) }}</span></div>
    </div>

    <n-alert v-if="error" class="service-alert" type="error" :bordered="false" closable @close="error = ''">{{ error }}</n-alert>
    <n-alert class="service-alert" type="warning" :bordered="false">停止 DST 隧道会删除 <b>wg-dst</b> 并中断相关连接；PortHub 不会显示或修改 DST、QX 的任何私钥和密码。</n-alert>

    <n-spin :show="loading && services.length === 0">
      <div v-for="group in groups" :key="group.key" class="service-group" :class="`group-${group.key}`">
        <header><div><span>{{ group.eyebrow }}</span><h3>{{ group.title }}</h3></div><p>{{ group.description }}</p><b>{{ group.services.filter(isHealthy).length }}/{{ group.services.length }} 正常</b></header>
        <article v-for="(service, index) in group.services" :key="service.name" class="service-row" :style="{ '--delay': `${index * 55}ms` }">
          <div class="service-identity">
            <span class="service-icon" :class="{ online: isHealthy(service) }"><component :is="isHealthy(service) ? info(service).icon : WifiOff" :size="20" /></span>
            <div><div class="service-name"><h4>{{ info(service).title }}</h4><n-tag size="small" :type="stateType(service)" :bordered="false">{{ stateLabel(service) }}</n-tag></div><p>{{ info(service).subtitle }}</p><code>{{ service.name }}.service</code></div>
          </div>

          <div class="service-runtime">
            <div class="runtime-item"><span>监听地址与端口</span><div v-if="service.listeners?.length" class="listener-list"><code v-for="listener in service.listeners" :key="`${listener.protocol}-${listener.address}-${listener.port}`">{{ formatListener(listener) }}</code></div><b v-else>{{ isHealthy(service) ? '不直接监听应用端口' : '服务停止后不再监听' }}</b></div>
            <div class="runtime-item compact"><span>进程编号 <n-tooltip trigger="hover"><template #trigger><CircleHelp :size="13" /></template>PID 是持续运行进程的编号；一次性策略生效后不会保留 PID。</n-tooltip></span><b>{{ service.main_pid || '一次性' }}</b></div>
          </div>

          <div class="service-control">
            <div class="autostart"><div><b>开机自动启动</b><small>服务器重启后自动恢复</small></div><n-switch :value="isEnabled(service)" :disabled="!canControl || Boolean(busyService)" :loading="busyService === service.name" :aria-label="`${info(service).title}开机自动启动`" @update:value="changeAutostart(service, $event)" /></div>
            <div v-if="canControl" class="service-actions">
              <n-button v-if="!isHealthy(service) && supports(service, 'start')" type="primary" :loading="busyService === service.name" @click="control(service, 'start')"><Play :size="15" />启动</n-button>
              <n-popconfirm v-if="supports(service, 'restart')" positive-text="确认执行" negative-text="取消" @positive-click="control(service, 'restart')"><template #trigger><n-button secondary :disabled="Boolean(busyService)"><RotateCw :size="15" />{{ service.sub_state === 'exited' ? '重新应用' : '重启' }}</n-button></template><b>{{ info(service).impact }}</b><br>确定继续吗？</n-popconfirm>
              <n-popconfirm v-if="isHealthy(service) && supports(service, 'stop')" positive-text="确认停止" negative-text="取消" @positive-click="control(service, 'stop')"><template #trigger><n-button type="error" secondary :disabled="Boolean(busyService)"><Square :size="14" />停止</n-button></template><b>{{ info(service).impact }}</b><br>确定停止这个服务吗？</n-popconfirm>
            </div>
            <small v-else class="readonly-note">只读账号可以查看，管理员才能操作。</small>
          </div>
        </article>
      </div>
      <div v-if="!loading && services.length === 0" class="service-empty">当前 Core 没有启用本机服务管理。</div>
    </n-spin>

    <footer class="service-footer"><span><Clock3 :size="14" />最后更新：{{ formatUpdated(updatedAt) }}</span><span>状态每 15 秒自动刷新</span></footer>
  </section>
</template>

<style scoped>
.service-center { overflow: hidden; }
.service-guide { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1px; margin: 0 -24px 18px; border-block: 1px solid var(--line); background: var(--line); }
.service-guide > div { min-height: 76px; display: grid; grid-template-columns: 28px 1fr; align-content: center; gap: 2px 9px; padding: 14px 24px; background: var(--surface-soft); }
.service-guide span { grid-row: 1 / 3; width: 26px; height: 26px; display: grid; place-items: center; border: 1px solid color-mix(in srgb, var(--accent) 42%, var(--line)); border-radius: 7px; background: var(--accent-soft); color: var(--accent); font-size: 11px; font-weight: 750; }
.service-guide b { color: var(--text); font-size: 12px; }
.service-guide small { color: var(--muted); font-size: 10px; line-height: 1.45; }
.tunnel-strip { display: grid; grid-template-columns: minmax(220px, 1.4fr) repeat(5, minmax(100px, .65fr)); gap: 1px; margin: 0 0 16px; border: 1px solid color-mix(in srgb, var(--accent-2) 38%, var(--line)); background: var(--line); overflow: hidden; }
.tunnel-strip > div { min-height: 88px; padding: 14px; background: color-mix(in srgb, var(--accent-2) 5%, var(--surface-soft)); }
.tunnel-strip.offline { border-color: color-mix(in srgb, var(--red) 42%, var(--line)); }
.tunnel-identity { display: flex; align-items: center; gap: 12px; }
.tunnel-identity > span { width: 40px; height: 40px; display: grid; place-items: center; border: 1px solid color-mix(in srgb, var(--accent-2) 48%, var(--line)); border-radius: 8px; background: color-mix(in srgb, var(--accent-2) 12%, transparent); color: var(--accent-2); }
.tunnel-identity div, .tunnel-metric { min-width: 0; display: grid; align-content: center; gap: 3px; }
.tunnel-identity small, .tunnel-metric small { display: flex; align-items: center; gap: 4px; color: var(--muted); font-size: 9px; }
.tunnel-identity b { color: var(--text); font-size: 16px; }
.tunnel-identity code { color: var(--text-soft); font-size: 9px; overflow-wrap: anywhere; }
.tunnel-metric b { color: var(--text); font-size: 15px; overflow-wrap: anywhere; }
.tunnel-metric b.ok { color: var(--green); }.tunnel-metric b.bad { color: var(--red); }
.tunnel-metric span { color: var(--muted); font-size: 9px; }.tunnel-metric.traffic b { font-size: 11px; }
.service-alert { margin-bottom: 12px; }
.service-group { margin: 18px -24px 0; border-top: 1px solid var(--line); }
.service-group > header { min-height: 66px; display: grid; grid-template-columns: minmax(180px, auto) 1fr auto; align-items: center; gap: 20px; padding: 12px 24px; background: var(--surface-soft); border-bottom: 1px solid var(--line); }
.service-group > header div { display: grid; gap: 2px; }.service-group > header span { color: var(--accent-2); font-size: 8px; font-weight: 750; }.group-qx > header span { color: var(--accent); }
.service-group > header h3 { margin: 0; color: var(--text); font-size: 14px; }.service-group > header p { margin: 0; color: var(--muted); font-size: 10px; }.service-group > header > b { color: var(--text-soft); font-size: 10px; }
.service-row { display: grid; grid-template-columns: minmax(240px, .9fr) minmax(280px, 1.1fr) minmax(220px, .72fr); gap: 24px; align-items: center; min-height: 148px; padding: 21px 24px; border-bottom: 1px solid var(--line); animation: service-row-in .34s ease-out both; animation-delay: var(--delay); }
.service-row:hover { background: color-mix(in srgb, var(--accent-soft) 32%, transparent); }
.service-identity { min-width: 0; display: flex; align-items: flex-start; gap: 13px; }.service-identity > div { min-width: 0; }
.service-icon { flex: 0 0 42px; height: 42px; display: grid; place-items: center; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-raised); color: var(--muted); }.service-icon.online { border-color: color-mix(in srgb, var(--green) 42%, var(--line)); background: var(--green-soft); color: var(--green); }
.service-name { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }.service-name h4 { margin: 0; color: var(--text); font-size: 14px; letter-spacing: 0; }
.service-identity p { margin: 5px 0 8px; color: var(--text-soft); font-size: 11px; line-height: 1.5; }.service-identity code { color: var(--muted); font-size: 10px; overflow-wrap: anywhere; }
.service-runtime { min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) 92px; gap: 12px; }.runtime-item { min-width: 0; min-height: 74px; padding: 12px 13px; border-left: 2px solid var(--line); background: var(--surface-soft); }
.runtime-item > span { display: flex; align-items: center; gap: 5px; margin-bottom: 9px; color: var(--muted); font-size: 9px; }.runtime-item > b { color: var(--text-soft); font-size: 10px; font-weight: 550; }.runtime-item.compact b { color: var(--text); font-size: 15px; }
.listener-list { display: flex; flex-wrap: wrap; gap: 6px; }.listener-list code { max-width: 100%; padding: 4px 7px; border: 1px solid var(--line); border-radius: 5px; background: var(--surface-raised); color: var(--text); font-size: 9px; overflow-wrap: anywhere; }
.service-control { display: grid; gap: 15px; }.autostart { display: flex; align-items: center; justify-content: space-between; gap: 12px; }.autostart > div { display: grid; gap: 2px; }.autostart b { color: var(--text); font-size: 11px; }.autostart small, .readonly-note { color: var(--muted); font-size: 9px; line-height: 1.45; }
.service-actions { display: flex; flex-wrap: wrap; gap: 8px; }.service-actions :deep(.n-button) { min-width: 82px; }.service-empty { min-height: 180px; display: grid; place-items: center; color: var(--muted); font-size: 12px; }
.service-footer { display: flex; justify-content: space-between; gap: 16px; padding-top: 16px; color: var(--muted); font-size: 9px; }.service-footer span { display: inline-flex; align-items: center; gap: 5px; }
@keyframes service-row-in { from { opacity: 0; transform: translateY(7px); } to { opacity: 1; transform: translateY(0); } } @media (prefers-reduced-motion: reduce) { .service-row { animation: none; } }
@media (max-width: 1180px) { .tunnel-strip { grid-template-columns: minmax(220px, 1.3fr) repeat(3, minmax(100px, .7fr)); }.tunnel-strip > div:nth-last-child(-n+2) { grid-column: span 2; }.service-row { grid-template-columns: minmax(230px, .8fr) minmax(280px, 1.2fr); }.service-control { grid-column: 1 / -1; grid-template-columns: minmax(220px, 1fr) auto; align-items: center; } }
@media (max-width: 700px) { .service-guide { grid-template-columns: 1fr; margin-inline: -16px; }.service-guide > div { min-height: 66px; padding: 11px 16px; }.tunnel-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }.tunnel-identity { grid-column: 1 / -1; }.tunnel-strip > div:nth-last-child(-n+2) { grid-column: auto; }.service-group { margin-inline: -16px; }.service-group > header { grid-template-columns: 1fr auto; padding-inline: 16px; }.service-group > header p { grid-column: 1 / -1; }.service-row { grid-template-columns: minmax(0, 1fr); gap: 17px; padding: 19px 16px; }.service-runtime { grid-template-columns: minmax(0, 1fr) 86px; }.service-control { grid-column: auto; grid-template-columns: 1fr; }.service-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); }.service-actions :deep(.n-button) { width: 100%; min-width: 0; }.service-footer { flex-direction: column; gap: 5px; } }
@media (max-width: 390px) { .tunnel-strip, .service-runtime { grid-template-columns: 1fr; }.tunnel-identity { grid-column: auto; }.service-actions { grid-template-columns: 1fr; } }
</style>

