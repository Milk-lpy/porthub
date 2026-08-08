<script setup lang="ts">
import { ref } from 'vue'
import { NButton, NInput } from 'naive-ui'
import { useOpsStore } from '../stores/ops'
import type { UserItem } from '../stores/ops'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const oneTime = ref('')
const form = ref({ username: '', password: '', role: 'operator' })

function showOneTime(data: Record<string, unknown>) {
  const lines = []
  if (data.initial_password) lines.push(`initial_password=${data.initial_password}`)
  if (data.temporary_password) lines.push(`temporary_password=${data.temporary_password}`)
  if (data.totp_secret) lines.push(`totp_secret=${data.totp_secret}`)
  oneTime.value = lines.join('\n')
}

async function createUser() {
  try {
    const result = await ops.createUser({ ...form.value })
    showOneTime(result as Record<string, unknown>)
    form.value.username = ''
    form.value.password = ''
    emit('notify', '用户已创建，请立即保存一次性凭据')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function saveUser(row: UserItem) {
  try {
    await ops.updateUser(row)
    emit('notify', '用户已更新')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function resetPassword(row: UserItem) {
  try {
    const result = await ops.resetUserPassword(row.id)
    showOneTime(result as Record<string, unknown>)
    emit('notify', '临时密码已生成，请立即保存')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function resetTOTP(row: UserItem) {
  try {
    const result = await ops.resetUserTOTP(row.id)
    showOneTime(result as Record<string, unknown>)
    emit('notify', 'TOTP Secret 已重置，请立即重新绑定')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function deleteUser(row: UserItem) {
  try {
    await ops.deleteUser(row.id)
    emit('notify', '用户已删除')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}
</script>

<template>
  <section class="panel">
    <div class="panel-title">
      <div>
        <h2>用户和角色</h2>
        <span>密码哈希和 TOTP Secret 不会在列表中返回；重置值只显示一次</span>
      </div>
    </div>

    <div class="form-grid action-form">
      <label>用户名<n-input v-model:value="form.username" placeholder="operator1" /></label>
      <label>初始密码<n-input v-model:value="form.password" type="password" placeholder="留空自动生成强密码" /></label>
      <label>角色
        <select v-model="form.role">
          <option value="operator">运维人员</option>
          <option value="readonly">只读用户</option>
          <option value="admin">管理员</option>
          <option value="super_admin">超级管理员</option>
        </select>
      </label>
      <n-button type="primary" class="form-action create-action" @click="createUser">创建用户</n-button>
    </div>

    <div v-if="oneTime" class="secret-once">
      <span>一次性凭据</span>
      <code>{{ oneTime }}</code>
    </div>

    <div class="table-wrap">
      <table>
        <thead><tr><th>用户名</th><th>角色</th><th>首次改密</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="row in ops.users" :key="row.id">
            <td>{{ row.username }}</td>
            <td>
              <select v-model="row.role" @change="saveUser(row)">
                <option value="super_admin">超级管理员</option>
                <option value="admin">管理员</option>
                <option value="operator">运维人员</option>
                <option value="readonly">只读用户</option>
              </select>
            </td>
            <td><span :class="['state-pill', row.must_change ? 'disabled' : 'enabled']">{{ row.must_change ? '需要' : '否' }}</span></td>
            <td>
              <div class="button-row compact">
                <n-button size="small" secondary @click="resetPassword(row)">重置密码</n-button>
                <n-button size="small" secondary @click="resetTOTP(row)">重置 2FA</n-button>
                <n-button size="small" tertiary type="error" @click="deleteUser(row)">删除</n-button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
