<script setup lang="ts">
import { computed, ref } from 'vue'
import { CheckCircle2, CircleHelp, ClipboardCopy, Download, KeyRound, PackageCheck, RefreshCw, ShieldCheck, Terminal } from '@lucide/vue'
import { NAlert, NButton, NPopover } from 'naive-ui'
import { useOpsStore, type UpdateCheckResult } from '../stores/ops'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()
const checking = ref(false)
const staging = ref<'' | 'core' | 'agent'>('')
const result = ref<UpdateCheckResult>()

const stateLabel = computed(() => {
  if (!ops.updateStatus.enabled) return '未配置可信更新源'
  if (ops.updateStatus.staged_version) return `已暂存 ${ops.updateStatus.staged_version}`
  if (result.value?.available) return `发现 ${result.value.latest_version}`
  return '当前已是检查到的版本'
})
const installCommand = computed(() => {
  if (!ops.updateStatus.staged_version || !ops.updateStatus.staged_component) return ''
  return `sudo /opt/porthub/bin/porthub-update-helper --execute --version ${ops.updateStatus.staged_version} --component ${ops.updateStatus.staged_component}`
})

async function copyInstallCommand() {
  if (!installCommand.value) return
  try {
    await navigator.clipboard.writeText(installCommand.value)
    emit('notify', '维护命令已复制')
  } catch {
    emit('notify', '浏览器未允许复制，请在帮助弹层中手工选择命令', 'error')
  }
}

async function check() {
  checking.value = true
  try {
    result.value = await ops.checkUpdates()
    emit('notify', result.value.available ? `发现新版本 ${result.value.latest_version}` : '当前已是最新检查版本')
  } catch (error) {
    emit('notify', error instanceof Error ? error.message : String(error), 'error')
  } finally {
    checking.value = false
  }
}

async function stage(component: 'core' | 'agent') {
  staging.value = component
  try {
    const response = await ops.stageUpdate(component)
    emit('notify', `${component === 'core' ? 'Core' : 'Agent'} ${response.version} 已完成签名校验并暂存`)
  } catch (error) {
    emit('notify', error instanceof Error ? error.message : String(error), 'error')
  } finally {
    staging.value = ''
  }
}
</script>

<template>
  <section class="panel updates-panel">
    <div class="panel-title">
      <div>
        <span class="eyebrow">VERIFIED DELIVERY</span>
        <h2>升级管理</h2>
        <p>只接收由 PortHub 更新密钥签名、且文件哈希完全匹配的版本</p>
      </div>
      <n-popover trigger="click" placement="bottom-end" style="max-width: 320px">
        <template #trigger><button class="help-icon" aria-label="查看升级说明"><CircleHelp :size="18" /></button></template>
        <b>怎样升级</b><p class="popover-copy">先检查版本，再暂存需要更新的组件。暂存不会重启服务；安装需要维护窗口和再次确认。</p>
      </n-popover>
    </div>

    <n-alert v-if="!ops.updateStatus.enabled" type="warning" :bordered="false" class="inline-alert">
      管理员尚未配置签名清单地址和 Ed25519 公钥。系统不会尝试连接任何默认更新服务器。
    </n-alert>

    <div class="update-hero">
      <div class="update-mark"><PackageCheck :size="25" /></div>
      <div class="update-version"><span>当前 Core 版本</span><b>{{ ops.updateStatus.current_version }}</b><small>{{ stateLabel }}</small></div>
      <n-button class="create-action" type="primary" :disabled="!ops.updateStatus.enabled" :loading="checking" @click="check"><RefreshCw :size="15" />检查更新</n-button>
    </div>

    <div class="trust-strip">
      <div><KeyRound :size="17" /><span><b>签名身份</b><small>Ed25519 清单签名</small></span><CheckCircle2 :size="15" /></div>
      <div><ShieldCheck :size="17" /><span><b>下载校验</b><small>HTTPS、大小和 SHA-256</small></span><CheckCircle2 :size="15" /></div>
      <div><Download :size="17" /><span><b>两阶段更新</b><small>暂存与安装相互独立</small></span><CheckCircle2 :size="15" /></div>
    </div>

    <div v-if="result" class="update-release">
      <header><div><b>版本 {{ result.latest_version }}</b><small>{{ result.published_at }}</small></div><span :class="['state-pill', result.available ? 'warning' : 'enabled']">{{ result.available ? '可更新' : '已是当前版本' }}</span></header>
      <p>{{ result.notes || '此版本未附带发布说明。' }}</p>
      <footer v-if="result.available">
        <span>暂存后不会自动重启</span>
        <div class="button-row compact"><n-button secondary :loading="staging === 'agent'" @click="stage('agent')">暂存 Agent</n-button><n-button class="create-action" type="primary" :loading="staging === 'core'" @click="stage('core')">暂存 Core</n-button></div>
      </footer>
    </div>

    <div v-if="ops.updateStatus.staged_version" class="staged-update">
      <CheckCircle2 :size="20" /><span><b>{{ ops.updateStatus.staged_version }} 已安全暂存</b><small>安装包已通过签名和哈希校验，等待维护窗口确认安装。</small></span>
      <details v-if="installCommand" class="update-install">
        <summary><Terminal :size="15" /><span>安装</span></summary>
        <div class="update-install-help">
          <b>维护窗口安装</b><p class="popover-copy">助手会再次验签、备份旧二进制、只重启目标组件，并在健康失败时自动回滚。</p>
          <code class="command-preview">{{ installCommand }}</code>
          <n-button size="small" secondary @click="copyInstallCommand"><ClipboardCopy :size="14" />复制命令</n-button>
        </div>
      </details>
    </div>
  </section>
</template>
