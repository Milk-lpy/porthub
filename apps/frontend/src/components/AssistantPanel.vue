<script setup lang="ts">
import { ref } from 'vue'
import { ArrowRight, Bot, CheckCircle2, CircleHelp, LockKeyhole, Send, ShieldAlert } from '@lucide/vue'
import { NButton, NCheckbox, NInput, NPopover } from 'naive-ui'
import { useOpsStore, type AIDraftResult } from '../stores/ops'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const intent = ref('开放 192.0.2.150 上的 11001 和 11002 UDP，用于饥荒')
const draft = ref<AIDraftResult>()
const loading = ref(false)
const saving = ref(false)
const confirmed = ref(false)
const examples = [
  '开放 192.0.2.150 上的 11001 和 11002 UDP，用于饥荒',
  '发布 192.0.2.20 的 Minecraft 服务',
  '把 192.0.2.30 的 SSH 开放出去',
]

async function generate() {
  loading.value = true
  confirmed.value = false
  try {
    draft.value = await ops.generateAIDraft(intent.value)
    emit('notify', draft.value.blockers.length ? '草稿已生成，请先处理阻断项' : '草稿已生成，可以预览确认')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  } finally {
    loading.value = false
  }
}

async function saveDraft() {
  if (!draft.value || draft.value.blockers.length) return
  if (!confirmed.value) return emit('notify', '请先确认已检查目标和端口', 'error')
  saving.value = true
  try {
    await ops.saveAIDraft(draft.value)
    emit('notify', '已保存为禁用映射，请到映射页继续复核')
    confirmed.value = false
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <section class="panel assistant-panel">
    <div class="panel-title assistant-title">
      <div><span class="eyebrow">LOCAL INTENT COMPILER</span><h2>命令助手</h2><p>用自然语言生成可检查的端口映射草稿</p></div>
      <span class="local-ai-badge"><LockKeyhole :size="15" />本地解析 · 不上传</span>
    </div>

    <div class="assistant-composer">
      <div class="assistant-avatar"><Bot :size="22" /></div>
      <div class="assistant-input">
        <label><span>描述你要发布的服务<n-popover trigger="hover"><template #trigger><CircleHelp :size="14" /></template>请至少写明目标 IP。端口和 TCP/UDP 也写清楚时，结果会更准确。</n-popover></span><n-input v-model:value="intent" type="textarea" :autosize="{ minRows: 3, maxRows: 7 }" maxlength="2000" show-count placeholder="例如：开放 192.0.2.50 的 25565 TCP" /></label>
        <div class="assistant-examples"><span>试试：</span><button v-for="example in examples" :key="example" @click="intent = example">{{ example }}</button></div>
        <n-button class="create-action" type="primary" :loading="loading" :disabled="intent.trim().length < 3" @click="generate"><Send :size="16" />生成草稿</n-button>
      </div>
    </div>

    <div v-if="draft" class="assistant-result">
      <header><div><CheckCircle2 :size="19" /><span><b>{{ draft.group_name }}</b><small>{{ draft.mappings.length }} 条禁用映射 · {{ draft.engine }}</small></span></div><span class="state-pill neutral">等待确认</span></header>
      <div v-if="draft.blockers.length" class="draft-messages blocker"><ShieldAlert :size="17" /><div><b>暂时不能保存</b><span v-for="item in draft.blockers" :key="item">{{ item }}</span></div></div>
      <div v-if="draft.warnings.length" class="draft-messages warning"><ShieldAlert :size="17" /><div><b>检查这些风险</b><span v-for="item in draft.warnings" :key="item">{{ item }}</span></div></div>
      <div class="draft-list">
        <article v-for="(mapping, index) in draft.mappings" :key="`${mapping.Name}-${index}`"><span class="protocol-pill">{{ mapping.Protocol.toUpperCase() }}</span><div><b>{{ mapping.Name }}</b><small>公网 {{ mapping.PublicStart }} <ArrowRight :size="12" /> {{ mapping.TargetIP || '待补充 IP' }}:{{ mapping.TargetStart }}</small></div><span class="state-pill disabled">禁用草稿</span></article>
      </div>
      <footer><n-checkbox v-model:checked="confirmed" :disabled="draft.blockers.length > 0">我已检查目标 IP、协议和端口</n-checkbox><n-button class="create-action" type="primary" :loading="saving" :disabled="!confirmed || draft.blockers.length > 0" @click="saveDraft">保存到映射草稿</n-button></footer>
    </div>

    <div v-else class="assistant-boundary"><div><Bot :size="19" /><b>助手能做什么</b><span>识别 IP、端口、协议与常见游戏模板</span></div><div><ShieldAlert :size="19" /><b>助手不会做什么</b><span>不会执行 Shell，也不会绕过校验和部署确认</span></div></div>
  </section>
</template>
