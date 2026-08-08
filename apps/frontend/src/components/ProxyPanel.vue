<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Activity, Globe2, Plus, RefreshCw, Server, ShieldCheck, X } from '@lucide/vue'
import { NButton, NInput, NSwitch } from 'naive-ui'
import { request } from '../api'
import { useOpsStore } from '../stores/ops'
import type { HTTPProxy, ProxyBackendHealth } from '../stores/ops'
import TermHint from './TermHint.vue'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const preview = ref('')
const formOpen = ref(false)
const health = ref<ProxyBackendHealth[]>([])
const healthLoading = ref(false)
const form = ref({
  name: 'NAS Web', host: '', path: '/', targets_text: 'http://10.255.0.2:8080', headers_text: '', health_path: '/health',
  enabled: true, force_tls: false, websocket: true, preserve_host: false,
})

const healthyCount = computed(() => health.value.filter((item) => item.healthy).length)

function parseLines(value: string) {
  return value.split('\n').map((line) => line.trim()).filter(Boolean)
}

function parseHeaders(value: string) {
  const headers: Record<string, string> = {}
  for (const line of parseLines(value)) {
    const separator = line.indexOf(':')
    if (separator < 1) throw new Error(`Header 格式错误：${line}`)
    headers[line.slice(0, separator).trim()] = line.slice(separator + 1).trim()
  }
  return headers
}

async function addProxy() {
  try {
    const targets = parseLines(form.value.targets_text)
    if (!targets.length) throw new Error('至少填写一个后端地址')
    await ops.createHTTPProxy({
      name: form.value.name, host: form.value.host, path: form.value.path, target: targets[0], targets,
      headers: parseHeaders(form.value.headers_text), health_path: form.value.health_path, load_balance: 'round_robin',
      enabled: form.value.enabled, force_tls: form.value.force_tls, websocket: form.value.websocket, preserve_host: form.value.preserve_host,
    })
    form.value.host = ''
    formOpen.value = false
    emit('notify', 'HTTP 代理已保存，确认后可签名下发到 Edge')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function toggleProxy(row: HTTPProxy) {
  try {
    await ops.updateHTTPProxy({ ...row, enabled: !row.enabled })
    emit('notify', row.enabled ? 'HTTP 代理已禁用' : 'HTTP 代理已启用')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function removeProxy(id: string | number) {
  try {
    await ops.deleteHTTPProxy(id)
    emit('notify', 'HTTP 代理已删除，确认后可签名下发到 Edge')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function refreshHealth(showNotice = true) {
  healthLoading.value = true
  try {
    health.value = await request<ProxyBackendHealth[]>('/api/http-proxies/health') || []
    if (showNotice) emit('notify', '后端健康状态已刷新')
  } catch (err) {
    if (showNotice) emit('notify', err instanceof Error ? err.message : String(err), 'error')
  } finally {
    healthLoading.value = false
  }
}

function targetHealth(target: string) {
  return health.value.find((item) => item.target === target)
}

async function previewNFT() {
  try {
    const result = await ops.previewNFT()
    preview.value = result.nft
    emit('notify', `nft / proxy 快照预览已生成，版本 ${result.version}`)
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function deploySnapshot() {
  try {
    const result = await ops.deploySnapshot()
    emit('notify', `配置已签名下发，版本 ${result.version}`)
    window.setTimeout(() => refreshHealth(false), 1200)
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

onMounted(() => refreshHealth(false))
</script>

<template>
  <section class="panel proxy-panel">
    <div class="panel-title">
      <div>
        <span class="eyebrow">APPLICATION GATEWAY</span>
        <h2>HTTP / HTTPS 代理</h2>
        <span>Host 与 Path 路由，多后端健康检查由 Edge 轻量执行</span>
      </div>
      <div class="button-row">
        <n-button quaternary size="small" :loading="healthLoading" title="刷新后端状态" @click="refreshHealth()"><RefreshCw :size="16" />刷新</n-button>
        <n-button secondary size="small" @click="previewNFT">预览快照</n-button>
        <n-button secondary size="small" @click="deploySnapshot">签名下发</n-button>
        <n-button type="primary" size="small" class="create-action" @click="formOpen = !formOpen"><X v-if="formOpen" :size="16" /><Plus v-else :size="16" />{{ formOpen ? '收起' : '新增代理' }}</n-button>
      </div>
    </div>

    <div class="catalog-summary proxy-summary">
      <div><Globe2 :size="18" /><small>代理路由</small><b>{{ ops.httpProxies.length }}</b></div>
      <div><ShieldCheck :size="18" /><small>当前启用</small><b>{{ ops.httpProxies.filter((row) => row.enabled).length }}</b></div>
      <div><Activity :size="18" /><small>健康后端</small><b>{{ healthyCount }} / {{ health.length }}</b></div>
      <div><Server :size="18" /><small>Edge 入口</small><b>18090 / 18443</b></div>
    </div>

    <div v-if="formOpen" class="proxy-editor reveal-form">
      <div class="editor-section">
        <div class="section-caption"><b>公网入口</b><span>请求匹配条件</span></div>
        <div class="form-grid wide">
          <label>名称<n-input v-model:value="form.name" placeholder="NAS Web" /></label>
          <label><span class="field-label">Host<TermHint text="用户访问的完整域名，例如 nas.example.com。" /></span><n-input v-model:value="form.host" placeholder="nas.example.com" /></label>
          <label><span class="field-label">Path<TermHint text="域名后的路径。填写 / 表示整个网站，填写 /api 只匹配该路径。" /></span><n-input v-model:value="form.path" placeholder="/" /></label>
        </div>
      </div>
      <div class="editor-section">
        <div class="section-caption"><b>后端池</b><span>每行一个 URL，按轮询分配</span></div>
        <div class="form-grid proxy-grid">
          <label class="span-two">后端地址<n-input v-model:value="form.targets_text" type="textarea" :autosize="{ minRows: 3, maxRows: 7 }" placeholder="http://192.0.2.20:8080" /></label>
          <label>健康检查路径<n-input v-model:value="form.health_path" placeholder="/health，留空则关闭" /></label>
          <label class="span-two"><span class="field-label">自定义请求 Header<TermHint text="转发给后端时额外携带的 HTTP 信息。普通网站通常不需要填写。" /></span><n-input v-model:value="form.headers_text" type="textarea" :autosize="{ minRows: 3, maxRows: 7 }" placeholder="X-Forwarded-By: PortHub" /></label>
        </div>
      </div>
      <div class="editor-section proxy-options">
        <div><span>启用路由</span><n-switch v-model:value="form.enabled" /></div>
        <div><span>HTTP 跳转 HTTPS</span><n-switch v-model:value="form.force_tls" /></div>
        <div><span>WebSocket</span><n-switch v-model:value="form.websocket" /></div>
        <div><span>保留原始 Host</span><n-switch v-model:value="form.preserve_host" /></div>
        <n-button type="primary" class="create-action" @click="addProxy"><Plus :size="16" />保存代理</n-button>
      </div>
    </div>

    <div v-if="ops.httpProxies.length" class="proxy-list">
      <article v-for="row in ops.httpProxies" :key="row.id" class="proxy-route">
        <header>
          <div class="route-identity"><span :class="['status-dot', row.enabled ? 'online' : 'disabled']"></span><div><b>{{ row.name }}</b><small>{{ row.host }}{{ row.path || '/' }}</small></div></div>
          <div class="button-row compact">
            <span v-if="row.force_tls" class="state-pill enabled">HTTPS</span>
            <span v-if="row.websocket" class="state-pill neutral">WS</span>
            <n-button size="tiny" secondary @click="toggleProxy(row)">{{ row.enabled ? '禁用' : '启用' }}</n-button>
            <n-button size="tiny" tertiary type="error" @click="removeProxy(row.id)">删除</n-button>
          </div>
        </header>
        <div class="backend-strip">
          <div v-for="target in (row.targets?.length ? row.targets : [row.target])" :key="target" class="backend-item">
            <span :class="['status-dot', targetHealth(target) ? (targetHealth(target)?.healthy ? 'online' : 'offline') : 'unknown']"></span>
            <code>{{ target }}</code>
            <small v-if="targetHealth(target)">{{ targetHealth(target)?.status_code || targetHealth(target)?.error || '检测中' }}</small>
          </div>
        </div>
        <footer><span>健康检查 {{ row.health_path || '未启用' }}</span><span>{{ row.preserve_host ? '保留 Host' : '后端 Host' }}</span><span>{{ Object.keys(row.headers || {}).length }} 个 Header</span></footer>
      </article>
    </div>
    <div v-else class="empty-state">还没有配置反向代理</div>

    <pre v-if="preview" class="result-box">{{ preview }}</pre>
  </section>
</template>
