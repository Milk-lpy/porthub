<script setup lang="ts">
import { ref } from 'vue'
import { ArrowRight, Eye, EyeOff, LockKeyhole, Moon, Network, ShieldCheck, Sun, Waypoints } from '@lucide/vue'
import { NButton, NCheckbox, NInput } from 'naive-ui'

defineProps<{
  loading: boolean
  error: string
  dark: boolean
}>()

const emit = defineEmits<{
  submit: [payload: { username: string; password: string; totp: string; rememberDevice: boolean }]
  toggleTheme: []
}>()

const form = ref({ username: '', password: '', totp: '', rememberDevice: true })

function submit() {
  emit('submit', { ...form.value })
}
</script>

<template>
  <main class="login-screen">
    <button class="icon-button login-theme" title="切换主题" aria-label="切换主题" @click="emit('toggleTheme')">
      <Sun v-if="dark" :size="19" />
      <Moon v-else :size="19" />
    </button>

    <section class="login-context">
      <div class="login-brand">
        <span class="mark large"><Waypoints :size="27" :stroke-width="2.2" /></span>
        <span><strong>PortHub</strong><small>Network Control</small></span>
      </div>
      <div class="login-copy">
        <span class="eyebrow">统一公网入口控制平面</span>
        <h1>让每一条入口，<br>都有清晰的去向。</h1>
        <p>Edge、WireGuard 与内网资源的运行状态集中在一个工作台中。</p>
      </div>
      <div class="login-network" aria-hidden="true">
        <div class="network-node internet"><Network :size="19" /><span>Internet</span></div>
        <span class="network-line first"></span>
        <div class="network-node edge"><ShieldCheck :size="19" /><span>Edge</span><i></i></div>
        <span class="network-line second"></span>
        <div class="network-node core"><Waypoints :size="19" /><span>Core</span><i></i></div>
      </div>
      <div class="login-assurance">
        <span><LockKeyhole :size="16" /> mTLS 链路</span>
        <span><ShieldCheck :size="16" /> TOTP 保护</span>
      </div>
    </section>

    <section class="login-form-area">
      <form class="login-card" @submit.prevent="submit">
        <header>
          <span class="login-kicker">PORT HUB CONSOLE</span>
          <h2>登录管理面板</h2>
          <p>使用管理员账户继续</p>
        </header>

        <label class="field-label">
          <span>用户名</span>
          <n-input v-model:value="form.username" size="large" autocomplete="username" placeholder="管理员用户名" />
        </label>
        <label class="field-label">
          <span>密码</span>
          <n-input
            v-model:value="form.password"
            size="large"
            type="password"
            show-password-on="click"
            autocomplete="current-password"
            placeholder="输入密码"
          >
            <template #password-visible-icon><EyeOff :size="17" /></template>
            <template #password-invisible-icon><Eye :size="17" /></template>
          </n-input>
        </label>
        <label class="field-label">
          <span>验证码</span>
          <n-input v-model:value="form.totp" size="large" inputmode="numeric" maxlength="6" placeholder="可信设备可留空" />
        </label>

        <div class="login-options">
          <n-checkbox v-model:checked="form.rememberDevice">记住这台设备 30 天</n-checkbox>
          <span>双重验证已启用</span>
        </div>

        <p v-if="error" class="login-error">{{ error }}</p>
        <n-button type="primary" size="large" attr-type="submit" :loading="loading" block>
          进入控制台 <ArrowRight :size="18" />
        </n-button>
        <footer>受信任设备仍会保留会话和 CSRF 防护</footer>
      </form>
    </section>
  </main>
</template>
