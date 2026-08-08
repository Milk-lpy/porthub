<script setup lang="ts">
import { ref } from 'vue'
import { NButton } from 'naive-ui'
import { useOpsStore } from '../stores/ops'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const plan = ref('')

function fmtSize(value: number) {
  if (value < 1024) return `${value} B`
  if (value < 1048576) return `${(value / 1024).toFixed(1)} KiB`
  return `${(value / 1048576).toFixed(1)} MiB`
}

async function createBackup() {
  try {
    const result = await ops.createBackup()
    emit('notify', `备份已创建：${result.name}`)
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function restorePlan(name: string) {
  try {
    plan.value = JSON.stringify(await ops.restorePlan(name), null, 2)
    emit('notify', '恢复计划已生成')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}
</script>

<template>
  <section class="panel">
    <div class="panel-title">
      <div>
        <h2>备份恢复</h2>
        <span>页面只创建备份和生成恢复计划；执行恢复需维护窗口手动确认</span>
      </div>
      <n-button type="primary" size="small" class="create-action" @click="createBackup">创建 Core 备份</n-button>
    </div>

    <div class="table-wrap">
      <table>
        <thead><tr><th>文件</th><th>大小</th><th>创建时间</th><th>路径</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="row in ops.backups" :key="row.name">
            <td>{{ row.name }}</td>
            <td>{{ fmtSize(row.size) }}</td>
            <td>{{ row.created_at }}</td>
            <td>{{ row.path }}</td>
            <td><n-button size="small" secondary @click="restorePlan(row.name)">恢复计划</n-button></td>
          </tr>
        </tbody>
      </table>
    </div>

    <pre v-if="plan" class="result-box">{{ plan }}</pre>
  </section>
</template>
