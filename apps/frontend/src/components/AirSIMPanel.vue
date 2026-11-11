<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Activity, ExternalLink, RefreshCw, ShieldCheck, Smartphone, Server } from '@lucide/vue'
import { NButton, NInput } from 'naive-ui'
import { hasRole, request } from '../api'
import { useOpsStore } from '../stores/ops'

type AirSIMStatus = {
  configured: boolean
  reachable: boolean
  status: 'http_ready' | 'unreachable' | 'invalid_configuration'
  checked_at: string
  source: 'environment' | 'default_loopback'
}

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const health = ref<AirSIMStatus | null>(null)
const busy = ref(false)
const creating = ref(false)
const domain = ref('')
const target = ref('')
const canCreate = hasRole('operator')
const airsimProxies = computed(() => ops.httpProxies.filter((p) => p.name === 'AirSIM Relay'))
const statusText = computed(() => {
  if (!health.value) return '尚未检测'
  if (health.value.status === 'http_ready') return '本地 Relay HTTP 正常'
  if (health.value.status === 'invalid_configuration') return '健康检查配置无效'
  return 'Relay 未响应'
})

async function refresh() {
  busy.value = true
  try {
    health.value = await request<AirSIMStatus>('/api/integrations/airsim')
  } catch (error) {
    emit('notify', error instanceof Error ? error.message : String(error), 'error')
  } finally {
    busy.value = false
  }
}

async function createDraft() {
  if (!canCreate) return
  const host = domain.value.trim().toLowerCase()
  if (!/^(?=.{4,253}$)[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host) || host.split('.').some((part) => part.startsWith('-') || part.endsWith('-'))) {
    emit('notify', '请填写完整且有效的公网域名', 'error')
    return
  }
  let endpoint: URL
  try { endpoint = new URL(target.value.trim()) } catch {
    emit('notify', '后端地址必须是完整的 HTTP URL', 'error')
    return
  }
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password ||
      (endpoint.pathname !== '/' && endpoint.pathname !== '') || endpoint.search || endpoint.hash) {
    emit('notify', '后端只能填写内网 HTTP(S) 服务根地址，不能包含凭据、路径或查询参数', 'error')
    return
  }
  if (ops.httpProxies.some((p) => p.host.toLowerCase() === host && (p.path || '/') === '/')) {
    emit('notify', '该域名的根路径代理已经存在，请检查反向代理列表', 'error')
    return
  }
  creating.value = true
  try {
    await ops.createHTTPProxy({
      name: 'AirSIM Relay', host, path: '/', target: endpoint.origin, targets: [endpoint.origin],
      headers: {}, health_path: '/healthz', load_balance: 'round_robin',
      enabled: false, force_tls: true, websocket: true, preserve_host: true,
    })
    emit('notify', '已创建默认禁用的 AirSIM HTTPS/WSS 代理草稿；检查证书、隧道和访问控制后再启用下发')
  } catch (error) {
    emit('notify', error instanceof Error ? error.message : String(error), 'error')
  } finally {
    creating.value = false
  }
}

onMounted(refresh)
</script>

<template>
  <section class="panel airsim-panel">
    <div class="panel-title">
      <div>
        <span class="eyebrow">COMMUNICATION GATEWAY</span>
        <h2>AirSIM 通信网关</h2>
        <span>本地独立 Relay · PortHub Edge 公网反代 · 已有 WireGuard 隧道</span>
      </div>
      <n-button secondary size="small" :loading="busy" @click="refresh"><RefreshCw :size="16" />检测 Relay</n-button>
    </div>

    <div class="catalog-summary airsim-summary">
      <div><Server :size="18" /><small>本地 Relay</small><b>{{ statusText }}</b></div>
      <div><Activity :size="18" /><small>HTTP 检查</small><b>{{ health?.reachable ? '200 OK' : '未通过' }}</b></div>
      <div><ShieldCheck :size="18" /><small>代理草稿</small><b>{{ airsimProxies.length }}</b></div>
      <div><Smartphone :size="18" /><small>通话路径</small><b>VPN 优先</b></div>
    </div>

    <div class="airsim-note">
      <strong>检测边界</strong>
      <p>HTTP 200 仅证明 Relay 的 /healthz 能响应，不代表安卓在线、短信送达、APNs/PushKit 可用或双向 PCM 通话成功。后台来电必须完成真机测试。</p>
      <p>默认探测 Core 本机的 127.0.0.1:8787。若 Relay 运行在另一台内网主机，配置 Core 服务环境变量 <code>AIRSIM_RELAY_HEALTH_URL=http://内网IP:端口/healthz</code>（仅允许私网地址）。</p>
    </div>

    <div class="airsim-section">
      <h3>创建 PortHub 反向代理草稿</h3>
      <p>使用现有 Edge HTTPS/WSS 代理，不在 VPS 新装 Nginx。先让 VPS Edge 通过 WireGuard 访问内网 Relay 入口；绝不要将 8787、8789、8790 直接暴露公网。</p>
      <div class="form-grid wide">
        <label>公网域名<n-input v-model:value="domain" placeholder="airsim.example.com" /></label>
        <label>隧道可达的内网入口<n-input v-model:value="target" placeholder="http://10.255.0.2:18787" /></label>
      </div>
      <div class="button-row airsim-actions">
        <n-button type="primary" :loading="creating" :disabled="!canCreate" @click="createDraft">创建禁用代理草稿</n-button>
        <span v-if="!canCreate">至少需要操作员权限。</span>
        <RouterLink to="/proxy">打开反向代理配置</RouterLink>
      </div>
      <p>草稿固定使用 Host 根路径、HTTPS 强制跳转、WebSocket、/healthz 检查和保留 Host。保存后仍需确认证书、路由及快照，人工启用并下发。</p>
      <div v-if="airsimProxies.length" class="airsim-routes">
        <div v-for="proxy in airsimProxies" :key="proxy.id">
          <strong>{{ proxy.host }}</strong>
          <span>{{ proxy.target }} · {{ proxy.enabled ? '已启用' : '未启用' }}</span>
        </div>
      </div>
    </div>

    <div class="airsim-section">
      <h3>部署与验收</h3>
      <ol>
        <li>本地 Linux 按 AirSIM 官方 ECS 手册安装 workerd、SQLite 和 APNs 适配器；密钥只写本机受限配置。</li>
        <li>通过已有 WG 隧道提供仅限 Edge 可达的 HTTP 转发入口，不改动现有 wg-porthub。</li>
        <li>在本页创建禁用代理草稿，检查 DNS/TLS、端口和 WebSocket 后到代理页发布。</li>
        <li>安卓安装 Standalone + Shizuku，iPhone 自签并填同一自建 Relay 地址。</li>
        <li>分别验证短信、前台双向 PCM、APNs VoIP Push、锁屏接听及重连；无 APNs 服务端凭据时仅测试前台。</li>
      </ol>
      <div class="button-row airsim-links">
        <a href="https://github.com/kai-wu-cortex/AirSIM/tree/main/push-relay-worker/self-hosted" target="_blank" rel="noopener noreferrer">AirSIM 官方自建文档 <ExternalLink :size="14" /></a>
        <a href="https://github.com/kai-wu-cortex/AirSIM/releases" target="_blank" rel="noopener noreferrer">AirSIM Releases <ExternalLink :size="14" /></a>
      </div>
    </div>
  </section>
</template>

<style scoped>
.airsim-summary { margin-bottom: 20px; }
.airsim-summary b { font-size: 13px; }
.airsim-note, .airsim-section { border: 1px solid var(--border, rgba(148,163,184,.2)); border-radius: 12px; padding: 17px; margin-top: 14px; }
.airsim-note { background: var(--surface-2, rgba(148,163,184,.06)); }
.airsim-note p, .airsim-section p, .airsim-section li { font-size: 13px; line-height: 1.7; color: var(--text-soft); }
.airsim-section h3 { margin: 0 0 10px; font-size: 16px; }
.airsim-section ol { padding-left: 22px; }
.airsim-actions, .airsim-links { margin: 14px 0; align-items: center; gap: 14px; flex-wrap: wrap; }
.airsim-links a, .airsim-actions a { display: inline-flex; align-items: center; gap: 4px; color: var(--primary-color, #2f9d68); }
.airsim-routes { margin-top: 14px; display: grid; gap: 8px; }
.airsim-routes > div { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 8px; font-size: 13px; padding: 10px; border: 1px solid var(--border, rgba(148,163,184,.2)); border-radius: 8px; }
.airsim-routes span { color: var(--text-soft); }
</style>
