<script setup lang="ts">
import { ref } from 'vue'
import { NButton, NInput } from 'naive-ui'
import { useOpsStore } from '../stores/ops'
import TermHint from './TermHint.vue'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const tokenValue = ref('')
const form = ref({ name: '自动化脚本', role: 'operator' })

async function createToken() {
  try {
    const result = await ops.createToken({ ...form.value })
    tokenValue.value = result.token
    emit('notify', 'API Token 已创建，请立即保存一次性 token')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function revokeToken(id: string | number) {
  try {
    await ops.revokeToken(id)
    emit('notify', 'API Token 已吊销')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}
</script>

<template>
  <section class="panel">
    <div class="panel-title">
      <div>
        <h2>API Token</h2>
        <span>Token 只保存 SHA-256 哈希；完整值只在创建后显示一次</span>
      </div>
    </div>

    <div class="form-grid action-form">
      <label>名称<n-input v-model:value="form.name" placeholder="CI / 自动化脚本" /></label>
      <label><span class="field-label">角色<TermHint text="只读只能查看；运维可管理发布；管理员还可管理安全配置。请选择最低够用权限。" /></span>
        <select v-model="form.role">
          <option value="operator">运维人员</option>
          <option value="readonly">只读用户</option>
          <option value="admin">管理员</option>
        </select>
      </label>
      <n-button type="primary" class="form-action create-action" @click="createToken">创建 Token</n-button>
    </div>

    <div v-if="tokenValue" class="secret-once">
      <span>一次性 Token</span>
      <code>{{ tokenValue }}</code>
    </div>

    <div class="table-wrap">
      <table>
        <thead><tr><th>名称</th><th>前缀</th><th>角色</th><th>创建时间</th><th>最后使用</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="row in ops.apiTokens" :key="row.id">
            <td>{{ row.name }}</td>
            <td>{{ row.prefix }}</td>
            <td>{{ row.role }}</td>
            <td>{{ row.created_at || '--' }}</td>
            <td>{{ row.last_used_at || '--' }}</td>
            <td><span :class="['state-pill', row.revoked ? 'disabled' : 'enabled']">{{ row.revoked ? '已吊销' : '有效' }}</span></td>
            <td><n-button size="small" tertiary type="error" :disabled="row.revoked" @click="revokeToken(row.id)">吊销</n-button></td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
