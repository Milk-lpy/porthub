<script setup lang="ts">
import { computed, ref } from 'vue'
import { FileClock, RefreshCw, RotateCcw } from '@lucide/vue'
import { NButton, NPopconfirm } from 'naive-ui'
import { hasRole } from '../api'
import { useOpsStore } from '../stores/ops'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const rollingBack = ref<number | null>(null)
const canRollback = computed(() => hasRole('admin'))

async function rollback(version: number) {
  rollingBack.value = version
  try {
    const result = await ops.rollbackSnapshot(version)
    emit('notify', `已从版本 ${version} 生成并应用回滚版本 ${result.version}`)
  } catch (error) {
    emit('notify', error instanceof Error ? error.message : String(error), 'error')
  } finally {
    rollingBack.value = null
  }
}

function shortHash(value: string) {
  return value ? `${value.slice(0, 12)}...${value.slice(-6)}` : '--'
}

function localTime(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN')
}
</script>

<template>
  <section class="panel snapshot-panel">
    <div class="panel-title">
      <div><span class="eyebrow">IMMUTABLE HISTORY</span><h2>配置快照</h2><p>每次下发均保留签名载荷、应用结果和回滚来源</p></div>
      <n-button secondary size="small" :loading="ops.loading" @click="ops.refresh"><RefreshCw :size="16" />刷新</n-button>
    </div>

    <div class="snapshot-summary">
      <div><span class="snapshot-icon"><FileClock :size="22" /></span><p><small>已记录版本</small><strong>{{ ops.snapshotHistory.length }}</strong></p></div>
      <div><small>当前状态</small><strong>{{ ops.snapshotHistory[0]?.status === 'applied' ? '已同步' : ops.snapshotHistory[0]?.status || '暂无快照' }}</strong></div>
      <div><small>最近操作者</small><strong>{{ ops.snapshotHistory[0]?.operator || '--' }}</strong></div>
    </div>

    <div v-if="ops.snapshotHistory.length" class="table-wrap">
      <table>
        <thead><tr><th>版本</th><th>状态</th><th>操作者</th><th>SHA256</th><th>来源</th><th>时间</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="row in ops.snapshotHistory" :key="row.version">
            <td><code>{{ row.version }}</code></td>
            <td><span :class="['state-pill', row.status === 'applied' ? 'enabled' : 'disabled']">{{ row.status }}</span></td>
            <td><b>{{ row.operator }}</b></td>
            <td><code :title="row.sha256">{{ shortHash(row.sha256) }}</code></td>
            <td>{{ row.source_version ? `回滚自 ${row.source_version}` : '正常下发' }}</td>
            <td>{{ localTime(row.created_at) }}</td>
            <td>
              <n-popconfirm
                :disabled="!canRollback || row.status !== 'applied'"
                positive-text="确认回滚"
                negative-text="取消"
                @positive-click="rollback(row.version)"
              >
                <template #trigger>
                  <n-button size="small" secondary :disabled="!canRollback || row.status !== 'applied'" :loading="rollingBack === row.version"><RotateCcw :size="15" />回滚</n-button>
                </template>
                将映射、ACL、IP 集合与代理恢复到该版本，并生成新的签名快照。
              </n-popconfirm>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="empty-state">尚无下发历史，下一次配置下发后会自动建立首个快照。</div>
  </section>
</template>
