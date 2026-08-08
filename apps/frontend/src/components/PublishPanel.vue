<script setup lang="ts">
import { computed, ref } from 'vue'
import { Gamepad2, Globe2, MonitorCog, Server, ShieldAlert } from '@lucide/vue'
import { NButton, NInput } from 'naive-ui'
import { useOpsStore } from '../stores/ops'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const form = ref({ template_id: 'minecraft', name: 'Minecraft Java', target_ip: '10.255.0.2', enabled: false, allow_high_risk: false })

const selected = computed(() => ops.templates.find((tpl) => tpl.id === form.value.template_id))

function templateIcon(category: string) {
  const value = category.toLowerCase()
  if (value.includes('game')) return Gamepad2
  if (value.includes('web') || value.includes('nas')) return Globe2
  if (value.includes('remote') || value.includes('admin')) return MonitorCog
  return Server
}

function choose(id: string) {
  const tpl = ops.templates.find((item) => item.id === id)
  if (!tpl) return
  form.value.template_id = tpl.id
  form.value.name = tpl.name
  form.value.enabled = false
  form.value.allow_high_risk = false
}

async function applyTemplate() {
  try {
    const result = await ops.applyTemplate({ ...form.value })
    emit('notify', result.high_risk && !result.enabled ? `高风险模板已保存为禁用：${result.warning || ''}` : `已生成 ${result.created} 条映射`)
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}
</script>

<template>
  <section class="panel">
    <div class="panel-title">
      <div>
        <span class="eyebrow">PUBLISH WORKFLOW</span>
        <h2>发布入口</h2>
        <span>用模板生成映射，避免手写 nftables 和 WireGuard 细节</span>
      </div>
      <span class="template-count">{{ ops.templates.length }} 个可用模板</span>
    </div>

    <div class="template-grid">
      <button v-for="tpl in ops.templates" :key="tpl.id" :class="['template-card', { active: tpl.id === form.template_id }]" @click="choose(tpl.id)">
        <span class="template-card-head"><span class="template-icon"><component :is="templateIcon(tpl.category)" :size="20" /></span><em v-if="tpl.high_risk"><ShieldAlert :size="12" />高风险</em></span>
        <b>{{ tpl.name }}</b>
        <span>{{ tpl.description }}</span>
        <small>{{ tpl.category }} · {{ tpl.ports.length }} 个端口</small>
      </button>
    </div>

    <div class="two-col">
      <div class="panel-sub">
        <div class="panel-title"><div><span class="eyebrow">PARAMETERS</span><h2>发布参数</h2></div><span>{{ selected?.name || '--' }}</span></div>
        <div class="form-grid">
          <label>发布名称<n-input v-model:value="form.name" placeholder="给这组入口命名" /></label>
          <label>目标 IP<n-input v-model:value="form.target_ip" placeholder="10.255.0.2 或内网目标" /></label>
          <label>启用状态
            <select v-model="form.enabled">
              <option :value="false">先保存为禁用</option>
              <option :value="true">创建后启用</option>
            </select>
          </label>
          <label>高风险确认
            <select v-model="form.allow_high_risk">
              <option :value="false">不允许高风险直接启用</option>
              <option :value="true">允许高风险模板</option>
            </select>
          </label>
          <n-button type="primary" class="form-action create-action" @click="applyTemplate">生成映射</n-button>
        </div>
        <div v-if="selected?.warning" class="risk-box">{{ selected.warning }}</div>
      </div>

      <div class="panel-sub">
        <div class="panel-title"><div><span class="eyebrow">PORT PREVIEW</span><h2>端口预览</h2></div><span>生成前可检查冲突</span></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>名称</th><th>协议</th><th>公网端口</th><th>目标端口</th></tr></thead>
            <tbody>
              <tr v-for="port in selected?.ports || []" :key="`${port.name}-${port.public_port}`">
                <td>{{ port.name }}</td>
                <td><span class="protocol-pill">{{ port.protocol.toUpperCase() }}</span></td>
                <td>{{ port.public_port }}</td>
                <td>{{ port.target_port }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </section>
</template>
