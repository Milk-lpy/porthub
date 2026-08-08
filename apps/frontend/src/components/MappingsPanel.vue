<script setup lang="ts">
import { computed, ref } from 'vue'
import { Plus, X } from '@lucide/vue'
import { NButton, NInput } from 'naive-ui'
import { useOpsStore } from '../stores/ops'
import type { Mapping } from '../stores/ops'
import TermHint from './TermHint.vue'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const selected = ref<string[]>([])
const importText = ref('')
const exportText = ref('')
const nftPreviewResult = ref('')
const conflictResult = ref('')
const formOpen = ref(false)
const editingId = ref<number | string | null>(null)
const form = ref({
  name: '新映射',
  description: '',
  tags: '',
  protocol: 'tcp',
  public_ip: '',
  public_start: '',
  public_end: '',
  target_ip: '10.255.0.2',
  target_start: '',
  target_end: '',
  enabled: true,
  acl_ids: '',
  resource_id: '',
  service_id: '',
  group_id: '',
  target_node_id: '',
  rate_limit_kbps: '',
  connection_limit: '',
  log_level: 'info' as 'off' | 'error' | 'info' | 'verbose',
  source_mode: 'compat' as 'compat' | 'preserve',
})

const selectedCount = computed(() => selected.value.length)
const allSelected = computed(() => ops.mappings.length > 0 && selected.value.length === ops.mappings.length)

function parsePort(value: string, fallback?: number) {
  const n = Number(value || fallback || 0)
  return Number.isInteger(n) ? n : 0
}

function ids() {
  return selected.value.map(String)
}

function toggleAll() {
  selected.value = allSelected.value ? [] : ops.mappings.map((row) => String(row.ID))
}

function toInput(): Omit<Mapping, 'ID'> {
  const publicStart = parsePort(form.value.public_start)
  const targetStart = parsePort(form.value.target_start)
  return {
    Name: form.value.name.trim(),
		Description: form.value.description.trim(),
		Tags: form.value.tags.split(/[,\n]+/).map((tag) => tag.trim()).filter(Boolean),
    Protocol: form.value.protocol,
		PublicIP: form.value.public_ip.trim(),
    PublicStart: publicStart,
    PublicEnd: parsePort(form.value.public_end, publicStart),
    TargetIP: form.value.target_ip.trim(),
    TargetStart: targetStart,
    TargetEnd: parsePort(form.value.target_end, targetStart),
    Enabled: form.value.enabled,
    acl_ids: form.value.acl_ids.split(/[\n,]+/).map((id) => id.trim()).filter(Boolean),
		ResourceID: form.value.resource_id.trim(),
		ServiceID: form.value.service_id.trim(),
		GroupID: form.value.group_id.trim(),
		TargetNodeID: form.value.target_node_id.trim(),
		RateLimitKbps: parsePort(form.value.rate_limit_kbps),
		ConnectionLimit: parsePort(form.value.connection_limit),
		LogLevel: form.value.log_level,
		SourceMode: form.value.source_mode,
  }
}

function resetPorts() {
  form.value.name = '新映射'
	form.value.description = ''
	form.value.tags = ''
  form.value.public_start = ''
  form.value.public_end = ''
  form.value.target_start = ''
  form.value.target_end = ''
  form.value.acl_ids = ''
	form.value.rate_limit_kbps = ''
	form.value.connection_limit = ''
}

async function addMapping() {
  try {
    if (editingId.value !== null) {
      await ops.updateMapping({ ...toInput(), ID: editingId.value })
      emit('notify', '映射已更新，确认后可签名下发到 Edge')
    } else {
      await ops.createMapping(toInput())
      emit('notify', '映射已保存，确认后可签名下发到 Edge')
    }
    resetPorts()
    editingId.value = null
    formOpen.value = false
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

function toggleForm() {
  if (formOpen.value) {
    formOpen.value = false
    editingId.value = null
  } else {
    if (editingId.value !== null) {
      resetPorts()
      editingId.value = null
    }
    formOpen.value = true
  }
}

function editMapping(row: Mapping) {
  editingId.value = row.ID
  form.value = {
    name: row.Name,
		description: row.Description || '',
		tags: row.Tags?.join(', ') || '',
    protocol: row.Protocol,
		public_ip: row.PublicIP || '',
    public_start: String(row.PublicStart),
    public_end: row.PublicEnd === row.PublicStart ? '' : String(row.PublicEnd),
    target_ip: row.TargetIP,
    target_start: String(row.TargetStart),
    target_end: row.TargetEnd === row.TargetStart ? '' : String(row.TargetEnd),
    enabled: row.Enabled,
    acl_ids: row.acl_ids?.join(', ') || '',
		resource_id: row.ResourceID || '',
		service_id: row.ServiceID || '',
		group_id: row.GroupID || '',
		target_node_id: row.TargetNodeID || '',
		rate_limit_kbps: row.RateLimitKbps ? String(row.RateLimitKbps) : '',
		connection_limit: row.ConnectionLimit ? String(row.ConnectionLimit) : '',
		log_level: row.LogLevel || 'info',
		source_mode: row.SourceMode || 'compat',
  }
  formOpen.value = true
  emit('notify', '已载入映射，修改后点击保存')
}

function copyMapping(row: Mapping) {
  editingId.value = null
  form.value = {
    name: `${row.Name} 副本`,
		description: row.Description || '',
		tags: row.Tags?.join(', ') || '',
    protocol: row.Protocol,
		public_ip: row.PublicIP || '',
    public_start: '',
    public_end: '',
    target_ip: row.TargetIP,
    target_start: String(row.TargetStart),
    target_end: row.TargetEnd === row.TargetStart ? '' : String(row.TargetEnd),
    enabled: false,
    acl_ids: row.acl_ids?.join(', ') || '',
		resource_id: row.ResourceID || '',
		service_id: row.ServiceID || '',
		group_id: row.GroupID || '',
		target_node_id: row.TargetNodeID || '',
		rate_limit_kbps: row.RateLimitKbps ? String(row.RateLimitKbps) : '',
		connection_limit: row.ConnectionLimit ? String(row.ConnectionLimit) : '',
		log_level: row.LogLevel || 'info',
		source_mode: row.SourceMode || 'compat',
  }
  formOpen.value = true
  emit('notify', '已复制到表单，请填写新的公网端口')
}

async function toggleMapping(row: Mapping) {
  try {
    await ops.updateMapping({ ...row, Enabled: !row.Enabled })
    emit('notify', row.Enabled ? '映射已禁用' : '映射已启用')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function removeMapping(id: string | number) {
  try {
    await ops.deleteMapping(id)
    selected.value = selected.value.filter((value) => value !== String(id))
    emit('notify', '映射已删除，确认后可签名下发到 Edge')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function bulk(action: 'enable' | 'disable' | 'delete') {
  if (!selected.value.length) {
    emit('notify', '请先选择映射', 'error')
    return
  }
  try {
    await ops.bulkMappings(action, ids())
    selected.value = []
    emit('notify', action === 'enable' ? '已批量启用' : action === 'disable' ? '已批量禁用' : '已批量删除')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function previewNFT() {
  try {
    const result = await ops.previewNFT()
    nftPreviewResult.value = result.nft
    conflictResult.value = ''
    emit('notify', `nft 预览已生成，版本 ${result.version}`)
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function checkConflicts() {
  try {
    const result = await ops.checkMappingConflicts()
    conflictResult.value = JSON.stringify(result, null, 2)
    nftPreviewResult.value = ''
    emit('notify', result.ok ? '当前映射无端口冲突' : `发现冲突：${result.error || '未知错误'}`, result.ok ? 'success' : 'error')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function deployMappings() {
  try {
    const result = await ops.deploySnapshot()
    emit('notify', `配置已签名下发，版本 ${result.version}`)
    await ops.refresh()
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function exportMappings() {
  try {
    exportText.value = JSON.stringify(await ops.exportMappings(), null, 2)
    emit('notify', '映射导出已生成')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function importMappings() {
  try {
    const parsed = JSON.parse(importText.value)
    const mappings = Array.isArray(parsed) ? parsed : parsed.mappings
    if (!Array.isArray(mappings)) throw new Error('导入内容必须是映射数组或导出 JSON')
    await ops.importMappings(mappings)
    importText.value = ''
    emit('notify', `已导入 ${mappings.length} 条映射`)
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}
</script>

<template>
  <section class="panel">
    <div class="panel-title">
      <div>
        <h2>TCP / UDP 映射</h2>
        <span>新增后先保存到 Core；点击签名下发后才会应用到 Edge</span>
      </div>
      <div class="button-row">
        <n-button secondary size="small" @click="checkConflicts">冲突检查</n-button>
        <n-button secondary size="small" @click="previewNFT">预览 nft</n-button>
        <n-button secondary size="small" @click="deployMappings">签名下发</n-button>
        <n-button type="primary" size="small" class="create-action" @click="toggleForm">
          <X v-if="formOpen" :size="16" />
          <Plus v-else :size="16" />
          {{ formOpen ? (editingId !== null ? '取消编辑' : '收起表单') : '新增映射' }}
        </n-button>
      </div>
    </div>

    <div v-if="formOpen" class="form-grid mappings-form create-mapping-form">
        <label>名称<n-input v-model:value="form.name" placeholder="例如 饥荒 Master" /></label>
		<label class="span-2">描述<n-input v-model:value="form.description" placeholder="用途、负责人或发布范围" /></label>
		<label>标签<n-input v-model:value="form.tags" placeholder="game, family" /></label>
        <label>协议
          <select v-model="form.protocol">
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="tcpudp">TCP + UDP</option>
          </select>
        </label>
		<label>公网监听 IP<n-input v-model:value="form.public_ip" placeholder="云公网 NAT 环境通常留空" /></label>
        <label>公网起始端口<n-input v-model:value="form.public_start" placeholder="18080" /></label>
        <label>公网结束端口<n-input v-model:value="form.public_end" placeholder="留空=单端口" /></label>
        <label>目标 IP<n-input v-model:value="form.target_ip" placeholder="10.255.0.2" /></label>
        <label>目标起始端口<n-input v-model:value="form.target_start" placeholder="9731" /></label>
        <label>目标结束端口<n-input v-model:value="form.target_end" placeholder="留空=单端口" /></label>
        <label>状态
          <select v-model="form.enabled">
            <option :value="true">启用</option>
            <option :value="false">禁用</option>
          </select>
        </label>
		<label class="span-2"><span class="field-label">ACL ID<TermHint text="访问控制规则编号。留空使用默认策略，多个编号用逗号分隔。" /></span><n-input v-model:value="form.acl_ids" placeholder="可选，多个用逗号分隔" /></label>
		<label>资源 ID<n-input v-model:value="form.resource_id" placeholder="可选" /></label>
		<label>服务 ID<n-input v-model:value="form.service_id" placeholder="可选" /></label>
		<label>映射组 ID<n-input v-model:value="form.group_id" placeholder="可选" /></label>
		<label>目标节点 ID<n-input v-model:value="form.target_node_id" placeholder="可选" /></label>
		<label>限速 KiB/s<n-input v-model:value="form.rate_limit_kbps" placeholder="0 = 不限制" /></label>
		<label>TCP 连接上限<n-input v-model:value="form.connection_limit" placeholder="0 = 不限制" /></label>
		<label>日志等级
			<select v-model="form.log_level"><option value="off">关闭</option><option value="error">错误</option><option value="info">标准</option><option value="verbose">详细</option></select>
		</label>
        <label><span class="field-label">源地址模式<TermHint text="兼容 SNAT 会隐藏公网来源 IP，但绝大多数家庭网络无需额外路由即可稳定返回。" /></span>
          <select v-model="form.source_mode"><option value="compat">兼容 SNAT</option><option value="preserve">保留源 IP（高级）</option></select>
        </label>
        <div v-if="form.source_mode === 'preserve'" class="inline-warning span-2">需要局域网网关为公网源地址配置经 Core 返回的策略路由；Core 未显式确认前会拒绝下发。</div>
        <n-button type="primary" class="form-action create-action" @click="addMapping">{{ editingId !== null ? '保存修改' : '新增映射' }}</n-button>
    </div>

    <div class="mapping-bulk-bar">
      <div><b>批量操作</b><span>已选择 {{ selectedCount }} 条</span></div>
      <div class="mapping-bulk-actions">
        <div class="button-row compact">
          <n-button size="small" secondary @click="bulk('enable')">启用</n-button>
          <n-button size="small" secondary @click="bulk('disable')">禁用</n-button>
          <n-button size="small" tertiary type="error" @click="bulk('delete')">删除</n-button>
        </div>
        <div class="button-row compact">
          <n-button size="small" secondary @click="exportMappings">导出</n-button>
          <n-button size="small" secondary @click="importMappings">导入</n-button>
        </div>
      </div>
    </div>

    <div class="table-wrap mapping-table">
      <table>
        <thead>
          <tr>
            <th><input type="checkbox" :checked="allSelected" @change="toggleAll"></th>
			<th>名称</th><th>协议</th><th>公网入口</th><th>目标</th><th>安全控制</th><th>状态</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in ops.mappings" :key="row.ID">
            <td class="mapping-check"><input v-model="selected" type="checkbox" :value="String(row.ID)"></td>
			<td class="mapping-name" data-label="名称"><b>{{ row.Name }}</b><small v-if="row.Tags?.length" class="table-subline">{{ row.Tags.join(' · ') }}</small></td>
            <td data-label="协议"><span class="protocol-pill">{{ row.Protocol.toUpperCase() }}</span></td>
			<td data-label="公网入口"><code>{{ row.PublicIP || '*' }}:{{ row.PublicStart }}-{{ row.PublicEnd }}</code></td>
            <td data-label="内网目标"><code>{{ row.TargetIP }}:{{ row.TargetStart }}-{{ row.TargetEnd }}</code></td>
			<td data-label="安全控制"><span class="mapping-security"><span>{{ row.acl_ids?.length ? `ACL ${row.acl_ids.join(', ')}` : '默认 ACL' }}</span><small class="table-subline">{{ row.RateLimitKbps ? `${row.RateLimitKbps} KiB/s` : '不限速' }} · {{ row.ConnectionLimit ? `${row.ConnectionLimit} 连接` : '不限连接' }}</small></span></td>
            <td data-label="状态"><span :class="['state-pill', row.Enabled ? 'enabled' : 'disabled']">{{ row.Enabled ? '启用' : '禁用' }}</span></td>
            <td data-label="操作">
              <div class="button-row compact">
                <n-button size="small" secondary @click="editMapping(row)">编辑</n-button>
                <n-button size="small" secondary @click="copyMapping(row)">复制</n-button>
                <n-button size="small" secondary @click="toggleMapping(row)">{{ row.Enabled ? '禁用' : '启用' }}</n-button>
                <n-button size="small" tertiary type="error" @click="removeMapping(row.ID)">删除</n-button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="two-col utility-panels">
      <div class="panel-sub">
        <div class="panel-title"><h2>导入 JSON</h2><span>支持导出文件或映射数组</span></div>
        <n-input v-model:value="importText" type="textarea" placeholder='[{"Name":"Game","Protocol":"udp","PublicStart":11001,"TargetIP":"10.255.0.2","TargetStart":11001,"Enabled":true}]' />
      </div>
      <div class="panel-sub">
        <div class="panel-title"><h2>导出 / nft 预览</h2><span>用于审查和留档</span></div>
        <pre v-if="conflictResult" class="result-box">{{ conflictResult }}</pre>
        <pre v-else-if="nftPreviewResult" class="result-box">{{ nftPreviewResult }}</pre>
        <pre v-else-if="exportText" class="result-box">{{ exportText }}</pre>
        <div v-else class="empty-box">暂无预览内容</div>
      </div>
    </div>
  </section>
</template>
