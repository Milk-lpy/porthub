<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { KeyRound, RotateCw, Upload } from '@lucide/vue'
import { NButton, NInput, NSwitch } from 'naive-ui'
import { useOpsStore } from '../stores/ops'
import type { CertificateItem } from '../stores/ops'
import TermHint from './TermHint.vue'

const emit = defineEmits<{ notify: [text: string, type?: 'success' | 'error'] }>()
const ops = useOpsStore()

const form = ref({
  name: 'NAS Web',
  domains: '',
  issuer: 'manual',
  mode: 'manual',
  status: 'draft',
  expires_at: '',
  key_ref: '',
  dns_provider_id: 0,
  enabled: true,
})
const selectedCertificateID = ref('')
const allowPrepare = ref(false)
const planResult = ref('')
const prepareResult = ref('')
const certificatePEM = ref('')
const privateKeyPEM = ref('')
const deployAfterImport = ref(true)
const importing = ref(false)
const issuing = ref(false)
const acceptTerms = ref(false)
const deployAfterIssue = ref(true)
const acmeEmail = ref('')
const acmeDirectory = ref('')

const selectedCertificate = computed(() => ops.certificates.find((row) => String(row.id) === selectedCertificateID.value))
const selectedMode = computed(() => selectedCertificate.value?.mode || '')
const canIssue = computed(() => {
  if (selectedMode.value === 'acme_http_01') return true
  return selectedMode.value === 'acme_dns_01' && Boolean(selectedCertificate.value?.dns_provider_id)
})

function splitDomains(value: string) {
  return value.split(/[\n,]+/).map((name) => name.trim()).filter(Boolean)
}

function statusClass(row: CertificateItem) {
  if (!row.enabled) return 'disabled'
  if (row.status === 'valid' || row.status === 'issued' || row.status === 'prepared') return 'enabled'
  if (row.status === 'failed' || row.status === 'expired') return 'disabled'
  return 'warn'
}

async function addCertificate() {
  try {
    await ops.createCertificate({ ...form.value, domains: splitDomains(form.value.domains) })
    form.value.domains = ''
    emit('notify', '证书元数据已保存')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function toggleCertificate(row: CertificateItem) {
  try {
    await ops.updateCertificate({ ...row, enabled: !row.enabled })
    emit('notify', row.enabled ? '证书已禁用' : '证书已启用')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function removeCertificate(id: number) {
  try {
    await ops.deleteCertificate(id)
    emit('notify', '证书元数据已删除；不会删除已有私钥文件')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function previewPlan(id = Number(selectedCertificateID.value || 0)) {
  try {
    if (!id) throw new Error('请选择证书')
    selectedCertificateID.value = String(id)
    const result = await ops.previewCertificatePlan(id)
    planResult.value = JSON.stringify(result, null, 2)
    emit('notify', '证书计划已生成')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function prepareACME(dryRun: boolean) {
  try {
    const id = Number(selectedCertificateID.value || selectedCertificate.value?.id || 0)
    if (!id) throw new Error('请选择证书')
    if (selectedCertificate.value?.mode !== 'acme_http_01') throw new Error('本地准备仅用于 HTTP-01；DNS-01 会在申请时自动发布 TXT 记录')
    if (!dryRun && !allowPrepare.value) throw new Error('真实准备前需要勾选确认')
    const result = await ops.prepareCertificate(id, dryRun)
    prepareResult.value = JSON.stringify(result, null, 2)
    allowPrepare.value = false
    emit('notify', dryRun ? 'ACME HTTP-01 准备预演已生成' : 'ACME HTTP-01 本地材料已准备')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function importAndDeploy() {
  const id = Number(selectedCertificateID.value || 0)
  if (!id) return emit('notify', '请选择证书', 'error')
  if (!certificatePEM.value.trim() || !privateKeyPEM.value.trim()) return emit('notify', '证书链和私钥不能为空', 'error')
  importing.value = true
  try {
    const result = await ops.importCertificate(id, certificatePEM.value, privateKeyPEM.value, deployAfterImport.value)
    emit('notify', result.deployed ? '证书已校验并热加载到 Edge' : '证书已安全导入 Core')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  } finally {
    certificatePEM.value = ''
    privateKeyPEM.value = ''
    importing.value = false
  }
}

async function redeployCertificate(id: number) {
  try {
    await ops.deployCertificate(id)
    emit('notify', '证书已重新下发到 Edge')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  }
}

async function issueACME() {
  const id = Number(selectedCertificateID.value || 0)
  if (!id) return emit('notify', '请选择证书', 'error')
  if (!acceptTerms.value) return emit('notify', '请先确认已阅读所配置 CA 的服务条款', 'error')
  if (!acmeEmail.value.trim()) return emit('notify', '请填写 ACME 联系邮箱', 'error')
  issuing.value = true
  try {
    const result = await ops.issueCertificate(id, acmeEmail.value.trim(), deployAfterIssue.value)
    acceptTerms.value = false
    emit('notify', result.deployed ? `证书已签发并热加载到 Edge，有效至 ${result.expires_at}` : '证书已签发并安全保存到 Core')
  } catch (err) {
    emit('notify', err instanceof Error ? err.message : String(err), 'error')
  } finally {
    issuing.value = false
  }
}

onMounted(async () => {
  try {
    const status = await ops.getACMEStatus()
    acmeEmail.value = status.email || ''
    acmeDirectory.value = status.directory_url || ''
  } catch {
    acmeDirectory.value = ''
  }
})
</script>

<template>
  <section class="panel">
    <div class="panel-title">
      <div>
        <h2>TLS 证书</h2>
        <span>保存元数据和 key_ref；私钥文件只在 Core 本地生成，不返回前端</span>
      </div>
      <div class="button-row">
        <n-button secondary size="small" @click="previewPlan()">预览计划</n-button>
        <n-button secondary size="small" @click="prepareACME(true)">预演准备</n-button>
        <n-button type="primary" size="small" class="create-action" :disabled="!allowPrepare" @click="prepareACME(false)">生成本地材料</n-button>
      </div>
    </div>

    <div class="form-grid wide action-form">
      <label>名称<n-input v-model:value="form.name" placeholder="NAS Web" /></label>
      <label>域名<n-input v-model:value="form.domains" type="textarea" placeholder="nas.example.com&#10;home.example.com" /></label>
      <label>签发方
        <select v-model="form.issuer">
          <option value="manual">manual</option>
          <option value="acme">acme</option>
        </select>
      </label>
      <label><span class="field-label">验证模式<TermHint text="HTTP-01 通过网站路径验证；DNS-01 通过 DNS 记录验证，也支持通配符证书。" /></span>
        <select v-model="form.mode">
          <option value="manual">手工导入</option>
          <option value="acme_http_01">ACME HTTP-01</option>
          <option value="acme_dns_01">ACME DNS-01</option>
        </select>
      </label>
      <label v-if="form.mode === 'acme_dns_01'"><span class="field-label">DNS Provider<TermHint text="选择一个已在域名与 DDNS 页配置好的 DNS 服务。系统只读取它的受保护密钥引用。" /></span>
        <select v-model.number="form.dns_provider_id">
          <option :value="0">请选择 Provider</option>
          <option v-for="provider in ops.ddnsProviders.filter((item) => item.enabled && ['cloudflare', 'webhook'].includes(item.type))" :key="provider.id" :value="provider.id">{{ provider.name }} ({{ provider.type }})</option>
        </select>
      </label>
      <label>状态
        <select v-model="form.status">
          <option value="draft">draft</option>
          <option value="prepared">prepared</option>
          <option value="valid">valid</option>
          <option value="expired">expired</option>
          <option value="failed">failed</option>
        </select>
      </label>
      <label>到期时间<n-input v-model:value="form.expires_at" placeholder="2026-12-31T00:00:00Z" /></label>
      <label><span class="field-label">Key 引用<TermHint text="证书私钥在 Core 上的受保护文件路径。普通用户建议留空由系统管理。" /></span><n-input v-model:value="form.key_ref" placeholder="留空则生成到 Core 数据目录" /></label>
      <label>状态开关
        <select v-model="form.enabled">
          <option :value="true">启用</option>
          <option :value="false">禁用</option>
        </select>
      </label>
      <n-button type="primary" class="form-action create-action" @click="addCertificate">新增证书</n-button>
    </div>

    <div class="cert-action-strip">
      <label>选择证书
        <select v-model="selectedCertificateID">
          <option value="">选择证书</option>
          <option v-for="row in ops.certificates" :key="row.id" :value="String(row.id)">{{ row.id }} - {{ row.name }}</option>
        </select>
      </label>
      <label class="check-line"><input v-model="allowPrepare" type="checkbox"> 确认在 Core 本地生成私钥和 HTTP-01 占位文件</label>
    </div>

    <div class="acme-issue-strip">
      <div><b>自动签发</b><span v-if="selectedMode === 'acme_dns_01'">通过绑定的 Provider 创建临时 TXT 记录，验证结束后自动清理。</span><span v-else>先签名下发挑战并检查公网 80 路径，验证失败不会改动现有证书。</span></div>
      <label><span class="field-label">联系邮箱<TermHint text="证书机构用于发送账户和续期通知，不属于密钥。保存后自动续期会继续使用。" /></span><n-input v-model:value="acmeEmail" placeholder="admin@example.com" /></label>
      <label class="check-line"><input v-model="acceptTerms" type="checkbox"> 已阅读并接受所配置 CA 的服务条款</label>
      <label class="check-line"><input v-model="deployAfterIssue" type="checkbox"> 签发后热加载到 Edge</label>
      <n-button type="primary" class="create-action" :loading="issuing" :disabled="!selectedCertificateID || !canIssue || !acceptTerms || !acmeEmail" :title="acmeDirectory || 'ACME 目录未加载'" @click="issueACME">申请证书</n-button>
    </div>

    <div class="certificate-import">
      <div class="section-caption"><b><KeyRound :size="16" />证书材料</b><span>域名、有效期和密钥匹配校验</span></div>
      <div class="certificate-pem-grid">
        <label>证书链 PEM<n-input v-model:value="certificatePEM" type="textarea" :rows="6" placeholder="-----BEGIN CERTIFICATE-----" /></label>
        <label>私钥 PEM<n-input v-model:value="privateKeyPEM" type="textarea" :rows="6" placeholder="-----BEGIN PRIVATE KEY-----" /></label>
      </div>
      <div class="certificate-import-actions">
        <span>导入后下发 Edge</span><n-switch v-model:value="deployAfterImport" />
        <n-button type="primary" class="create-action" :loading="importing" @click="importAndDeploy"><Upload :size="16" />导入证书</n-button>
      </div>
    </div>

    <div class="table-wrap certificate-table-wrap">
      <table class="certificate-table">
        <thead><tr><th>名称</th><th>域名</th><th>签发方</th><th>模式</th><th>状态</th><th>到期</th><th>Key 引用</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="row in ops.certificates" :key="row.id">
            <td data-label="名称">{{ row.name }}</td>
            <td data-label="域名">{{ row.domains.join(', ') }}</td>
            <td data-label="签发方">{{ row.issuer }}</td>
            <td data-label="模式">{{ row.mode }}<small v-if="row.dns_provider_id" class="cell-note">Provider #{{ row.dns_provider_id }}</small></td>
            <td data-label="状态"><span :class="['state-pill', statusClass(row)]">{{ row.enabled ? row.status : 'disabled' }}</span></td>
            <td data-label="到期">{{ row.expires_at || '--' }}</td>
            <td data-label="Key 引用">{{ row.key_ref || '--' }}</td>
            <td data-label="操作">
              <div class="button-row compact">
                <n-button size="small" secondary @click="previewPlan(row.id)">计划</n-button>
                <n-button size="small" secondary @click="selectedCertificateID = String(row.id); prepareACME(true)">预演</n-button>
                <n-button v-if="row.status === 'issued'" size="small" secondary title="重新下发到 Edge" @click="redeployCertificate(row.id)"><RotateCw :size="14" />下发</n-button>
                <n-button size="small" secondary @click="toggleCertificate(row)">{{ row.enabled ? '禁用' : '启用' }}</n-button>
                <n-button size="small" tertiary type="error" @click="removeCertificate(row.id)">删除</n-button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <section v-if="planResult || prepareResult" class="two-col result-grid">
      <div>
        <div class="panel-title mini"><h2>证书计划</h2><span>不写文件</span></div>
        <pre v-if="planResult" class="result-box">{{ planResult }}</pre>
      </div>
      <div>
        <div class="panel-title mini"><h2>ACME 准备</h2><span>只准备本地 HTTP-01 材料</span></div>
        <pre v-if="prepareResult" class="result-box">{{ prepareResult }}</pre>
      </div>
    </section>
  </section>
</template>
