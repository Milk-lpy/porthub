<script setup lang="ts">
import { computed, ref } from 'vue'
import { NButton, NInput } from 'naive-ui'
import { useOpsStore } from '../stores/ops'
import type { GenericItem } from '../stores/ops'
import TermHint from './TermHint.vue'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()

const form = ref({
  name: '配置变更通知',
  description: '',
  event: 'snapshot.applied',
  url: '',
  method: 'POST',
  timeout: '8',
  retries: '2',
  secret_ref: '',
  enabled: true,
})
const rawData = ref('')
const selectedID = ref('')

const selected = computed(() => ops.webhooks.find((row) => String(row.id) === selectedID.value))

function buildData() {
  const extra = rawData.value.trim() ? JSON.parse(rawData.value) : {}
  return JSON.stringify({
    event: form.value.event,
    url: form.value.url.trim(),
    method: form.value.method,
    timeout_seconds: Number(form.value.timeout || 8),
    retries: Number(form.value.retries || 0),
    secret_ref: form.value.secret_ref.trim(),
    ...extra,
  })
}

function prettyData(row: GenericItem) {
  try {
    return JSON.stringify(JSON.parse(row.data || '{}'), null, 2)
  } catch {
    return row.data || '{}'
  }
}

async function addWebhook() {
  try {
    const data = buildData()
    await ops.createGeneric('webhooks', {
      name: form.value.name.trim(),
      description: form.value.description.trim(),
      data,
      enabled: form.value.enabled,
    })
    form.value.url = ''
    rawData.value = ''
    emit('notify', 'Webhook 已保存；后续事件执行器会按白名单事件触发')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function toggleWebhook(row: GenericItem) {
  try {
    await ops.updateGeneric('webhooks', { ...row, enabled: !row.enabled })
    emit('notify', row.enabled ? 'Webhook 已禁用' : 'Webhook 已启用')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function removeWebhook(row: GenericItem) {
  try {
    await ops.deleteGeneric('webhooks', row.id)
    if (selectedID.value === String(row.id)) selectedID.value = ''
    emit('notify', 'Webhook 已删除')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}
</script>

<template>
  <section class="panel">
    <div class="panel-title">
      <div>
        <h2>Webhook</h2>
        <span>保存事件订阅元数据；Secret 只填写文件引用，不保存明文</span>
      </div>
      <span class="badge">{{ ops.webhooks.length }} 个订阅</span>
    </div>

    <div class="webhook-layout">
      <div class="form-grid action-form">
        <label>名称<n-input v-model:value="form.name" placeholder="配置变更通知" /></label>
        <label>事件
          <select v-model="form.event">
            <option value="snapshot.applied">snapshot.applied</option>
            <option value="snapshot.failed">snapshot.failed</option>
            <option value="mapping.changed">mapping.changed</option>
            <option value="certificate.changed">certificate.changed</option>
            <option value="ddns.changed">ddns.changed</option>
          </select>
        </label>
        <label>URL<n-input v-model:value="form.url" placeholder="https://example.com/porthub-webhook" /></label>
        <label>方法
          <select v-model="form.method">
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
          </select>
        </label>
        <label>超时秒<n-input v-model:value="form.timeout" /></label>
        <label>重试次数<n-input v-model:value="form.retries" /></label>
        <label><span class="field-label">Secret 引用<TermHint text="用于签名通知的密钥文件路径，接收方可用它验证消息确实来自 PortHub。" /></span><n-input v-model:value="form.secret_ref" placeholder="/etc/porthub/secrets/webhook-token" /></label>
        <label>状态
          <select v-model="form.enabled">
            <option :value="true">启用</option>
            <option :value="false">禁用</option>
          </select>
        </label>
        <label class="span-2">附加 JSON<n-input v-model:value="rawData" type="textarea" placeholder='{"headers":{"X-Team":"home-lab"}}' /></label>
        <n-button type="primary" class="form-action create-action" @click="addWebhook">新增 Webhook</n-button>
      </div>

      <div class="quick-card">
        <b>事件执行边界</b>
        <span>当前页面只维护订阅配置，不执行任意 Shell，也不保存明文 token。事件执行器后续只会发送结构化 HTTP 请求。</span>
        <label>查看详情
          <select v-model="selectedID">
            <option value="">选择 Webhook</option>
            <option v-for="row in ops.webhooks" :key="row.id" :value="String(row.id)">{{ row.id }} - {{ row.name }}</option>
          </select>
        </label>
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <thead><tr><th>名称</th><th>描述</th><th>数据</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="row in ops.webhooks" :key="row.id">
            <td>{{ row.name }}</td>
            <td>{{ row.description || '--' }}</td>
            <td><code>{{ row.data || '{}' }}</code></td>
            <td><span :class="['state-pill', row.enabled ? 'enabled' : 'disabled']">{{ row.enabled ? '启用' : '禁用' }}</span></td>
            <td>
              <div class="button-row compact">
                <n-button size="small" secondary @click="selectedID = String(row.id)">查看</n-button>
                <n-button size="small" secondary @click="toggleWebhook(row)">{{ row.enabled ? '禁用' : '启用' }}</n-button>
                <n-button size="small" tertiary type="error" @click="removeWebhook(row)">删除</n-button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <pre v-if="selected" class="result-box">{{ prettyData(selected) }}</pre>
  </section>
</template>
