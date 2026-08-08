<script setup lang="ts">
import { computed, ref } from 'vue'
import { Plus, X } from '@lucide/vue'
import { NButton, NInput, NSwitch } from 'naive-ui'
import { useOpsStore } from '../stores/ops'
import type { ACLRule } from '../stores/ops'
import TermHint from './TermHint.vue'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const form = ref({
  name: '家庭白名单', action: 'allow', cidr: '', enabled: true, protocol: 'both', port_start: '', port_end: '',
  node_ids: '', service_ids: '', group_ids: '', schedule: false, weekdays: [1, 2, 3, 4, 5], start_time: '09:00', end_time: '18:00', timezone: 'Asia/Shanghai',
})
const formOpen = ref(false)
const allowCount = computed(() => ops.aclRules.filter((row) => row.action === 'allow').length)
const denyCount = computed(() => ops.aclRules.filter((row) => row.action === 'deny').length)

async function addRule() {
  try {
    const splitIDs = (value: string) => value.split(',').map((item) => item.trim()).filter(Boolean)
    await ops.createACLRule({
      name: form.value.name, action: form.value.action, cidr: form.value.cidr, enabled: form.value.enabled,
      protocols: form.value.protocol === 'both' ? ['tcp', 'udp'] : [form.value.protocol as 'tcp' | 'udp'],
      port_start: Number(form.value.port_start || 0), port_end: Number(form.value.port_end || form.value.port_start || 0),
      node_ids: splitIDs(form.value.node_ids), service_ids: splitIDs(form.value.service_ids), group_ids: splitIDs(form.value.group_ids),
      weekdays: form.value.schedule ? form.value.weekdays : [], start_time: form.value.schedule ? form.value.start_time : '',
      end_time: form.value.schedule ? form.value.end_time : '', timezone: form.value.schedule ? form.value.timezone : '',
    })
    form.value.cidr = ''
    formOpen.value = false
    emit('notify', 'ACL 规则已保存，绑定到映射并下发后生效')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

function scopeText(row: ACLRule) {
  const scopes = [row.node_ids?.length ? `节点 ${row.node_ids.join(',')}` : '', row.service_ids?.length ? `服务 ${row.service_ids.join(',')}` : '', row.group_ids?.length ? `组 ${row.group_ids.join(',')}` : ''].filter(Boolean)
  return scopes.join(' · ') || '映射显式绑定'
}

function timeText(row: ACLRule) {
  if (!row.start_time) return '全天'
  const dayNames = ['日', '一', '二', '三', '四', '五', '六']
  return `${(row.weekdays || []).map((day) => dayNames[day]).join('')} ${row.start_time}-${row.end_time}`
}

async function toggleRule(row: ACLRule) {
  try {
    await ops.updateACLRule({ ...row, enabled: !row.enabled })
    emit('notify', row.enabled ? 'ACL 已禁用' : 'ACL 已启用')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function deleteRule(id: string | number) {
  try {
    await ops.deleteACLRule(id)
    emit('notify', 'ACL 规则已删除')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function previewNFT() {
  try {
    const result = await ops.previewNFT()
    emit('notify', `ACL 快照预览已生成，版本 ${result.version}`)
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}
</script>

<template>
  <section class="panel">
    <div class="panel-title">
      <div>
        <span class="eyebrow">ACCESS CONTROL</span>
        <h2>ACL 安全</h2>
        <span>支持 IPv4/IPv6 CIDR allow/deny；映射表单可通过 ACL ID 绑定</span>
      </div>
      <div class="button-row"><n-button secondary size="small" @click="previewNFT">预览 nft</n-button><n-button type="primary" size="small" class="create-action" @click="formOpen = !formOpen"><X v-if="formOpen" :size="16" /><Plus v-else :size="16" />{{ formOpen ? '收起表单' : '新增 ACL' }}</n-button></div>
    </div>

    <div class="catalog-summary security-summary">
      <div><small>规则总数</small><b>{{ ops.aclRules.length }}</b></div>
      <div><small>白名单</small><b>{{ allowCount }}</b></div>
      <div><small>黑名单</small><b>{{ denyCount }}</b></div>
      <div><small>生效规则</small><b>{{ ops.aclRules.filter((row) => row.enabled).length }}</b></div>
    </div>

    <div v-if="formOpen" class="acl-editor reveal-form">
      <div class="form-grid wide">
      <label>名称<n-input v-model:value="form.name" placeholder="办公室白名单" /></label>
      <label>动作
        <select v-model="form.action">
          <option value="allow">白名单 allow</option>
          <option value="deny">黑名单 deny</option>
        </select>
      </label>
      <label><span class="field-label">CIDR / 单 IP / IP 段<TermHint text="CIDR 可一次表示一个网段，例如 192.0.2.0/24；也可以直接填写单个地址或起止地址。" /></span><n-input v-model:value="form.cidr" placeholder="203.0.113.10-203.0.113.20" /></label>
      <label>协议<select v-model="form.protocol"><option value="both">TCP + UDP</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
      <label>公网端口起<n-input v-model:value="form.port_start" placeholder="留空为全部" /></label>
      <label>公网端口止<n-input v-model:value="form.port_end" placeholder="留空等于起始" /></label>
      <label>节点 ID<n-input v-model:value="form.node_ids" placeholder="逗号分隔，留空则绑定映射" /></label>
      <label>服务 ID<n-input v-model:value="form.service_ids" placeholder="逗号分隔" /></label>
      <label>映射组 ID<n-input v-model:value="form.group_ids" placeholder="逗号分隔" /></label>
      <label>状态
        <select v-model="form.enabled">
          <option :value="true">启用</option>
          <option :value="false">禁用</option>
        </select>
      </label>
      </div>
      <div class="acl-schedule">
        <div><span>启用时间窗</span><n-switch v-model:value="form.schedule" /></div>
        <template v-if="form.schedule">
          <label>开始<n-input v-model:value="form.start_time" placeholder="09:00" /></label>
          <label>结束<n-input v-model:value="form.end_time" placeholder="18:00" /></label>
          <label>时区<n-input v-model:value="form.timezone" /></label>
          <div class="weekday-row"><label v-for="(name, day) in ['日','一','二','三','四','五','六']" :key="day"><input v-model="form.weekdays" type="checkbox" :value="day">{{ name }}</label></div>
        </template>
        <n-button type="primary" class="create-action" @click="addRule">新增 ACL</n-button>
      </div>
    </div>

    <div v-if="ops.aclRules.length" class="table-wrap">
      <table>
        <thead><tr><th>ID</th><th>名称</th><th>动作</th><th>来源范围</th><th>协议 / 端口</th><th>作用域</th><th>时间窗</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="row in ops.aclRules" :key="row.id">
            <td><code>{{ row.id }}</code></td>
            <td><b>{{ row.name }}</b></td>
            <td><span :class="['state-pill', row.action === 'allow' ? 'enabled' : 'disabled']">{{ row.action }}</span></td>
            <td>{{ row.cidr }}</td>
            <td>{{ row.protocols?.join(' + ').toUpperCase() || '全部' }} · {{ row.port_start ? `${row.port_start}-${row.port_end}` : '全部端口' }}</td>
            <td><small>{{ scopeText(row) }}</small></td>
            <td><small>{{ timeText(row) }}</small></td>
            <td><span :class="['state-pill', row.enabled ? 'enabled' : 'disabled']">{{ row.enabled ? '启用' : '禁用' }}</span></td>
            <td>
              <div class="button-row compact">
                <n-button size="small" secondary @click="toggleRule(row)">{{ row.enabled ? '禁用' : '启用' }}</n-button>
                <n-button size="small" tertiary type="error" @click="deleteRule(row.id)">删除</n-button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="empty-state">尚未创建 ACL 规则</div>
  </section>
</template>
