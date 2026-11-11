<script setup lang="ts">
import { computed, defineAsyncComponent, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { CircleHelp, LogOut, Menu, Moon, RefreshCw, Sun } from '@lucide/vue'
import { NAlert, NButton, NConfigProvider, darkTheme, type GlobalThemeOverrides } from 'naive-ui'
import { useRoute } from 'vue-router'
import { login, logout, restoreSession, type UserRole } from './api'
import AppSidebar from './components/AppSidebar.vue'
// 页面级懒加载: 每个 Panel 独立 chunk, 按路由按需加载, 缩小首屏主包
const AssistantPanel = defineAsyncComponent(() => import('./components/AssistantPanel.vue'))
const AuditPanel = defineAsyncComponent(() => import('./components/AuditPanel.vue'))
const AirSIMPanel = defineAsyncComponent(() => import('./components/AirSIMPanel.vue'))
const BackupsPanel = defineAsyncComponent(() => import('./components/BackupsPanel.vue'))
const CertificatesPanel = defineAsyncComponent(() => import('./components/CertificatesPanel.vue'))
const DashboardPanel = defineAsyncComponent(() => import('./components/DashboardPanel.vue'))
const DomainsPanel = defineAsyncComponent(() => import('./components/DomainsPanel.vue'))
const InventoryPanel = defineAsyncComponent(() => import('./components/InventoryPanel.vue'))
const IPSetsPanel = defineAsyncComponent(() => import('./components/IPSetsPanel.vue'))
import LoginScreen from './components/LoginScreen.vue'
const MappingsPanel = defineAsyncComponent(() => import('./components/MappingsPanel.vue'))
const NodesPanel = defineAsyncComponent(() => import('./components/NodesPanel.vue'))
import PageHelpDrawer from './components/PageHelpDrawer.vue'
const PortForwardPanel = defineAsyncComponent(() => import('./components/PortForwardPanel.vue'))
const ProxyPanel = defineAsyncComponent(() => import('./components/ProxyPanel.vue'))
const PublishPanel = defineAsyncComponent(() => import('./components/PublishPanel.vue'))
const ManagedServicesPanel = defineAsyncComponent(() => import('./components/ManagedServicesPanel.vue'))
const SecurityPanel = defineAsyncComponent(() => import('./components/SecurityPanel.vue'))
const SnapshotsPanel = defineAsyncComponent(() => import('./components/SnapshotsPanel.vue'))
const TokensPanel = defineAsyncComponent(() => import('./components/TokensPanel.vue'))
const TrafficPanel = defineAsyncComponent(() => import('./components/TrafficPanel.vue'))
const UpdatesPanel = defineAsyncComponent(() => import('./components/UpdatesPanel.vue'))
const UsersPanel = defineAsyncComponent(() => import('./components/UsersPanel.vue'))
const WebhooksPanel = defineAsyncComponent(() => import('./components/WebhooksPanel.vue'))
const WireGuardPanel = defineAsyncComponent(() => import('./components/WireGuardPanel.vue'))
import { useOpsStore } from './stores/ops'

const route = useRoute()
const ops = useOpsStore()
const authed = ref(false)
const authChecking = ref(true)
const sessionRole = ref<UserRole>('readonly')
const loginLoading = ref(false)
const loginError = ref('')
const notice = ref('')
const noticeType = ref<'success' | 'error'>('success')
const mobileNavOpen = ref(false)
const isDark = ref(localStorage.getItem('porthub-theme') !== 'light')
const helpOpen = ref(false)

const activeLabel = computed(() => String(route.meta.label || '运行总览'))
const activeSection = computed(() => {
  if (['/', '/nodes', '/wireguard', '/inventory'].includes(route.path)) return '工作台'
  if (['/publish', '/mappings', '/port-forward', '/proxy'].includes(route.path)) return '入口管理'
  if (['/domains', '/certificates', '/ip-sets', '/security'].includes(route.path)) return '域名与安全'
  if (['/traffic', '/audit', '/snapshots'].includes(route.path)) return '可观测性'
  return '系统'
})

const themeOverrides = computed<GlobalThemeOverrides>(() => {
  const accent = isDark.value ? '#34e5a0' : '#2f9d68'
  const accentHover = isDark.value ? '#4dedb0' : '#3caf78'
  const accentPressed = isDark.value ? '#25c98a' : '#27855a'
  // Primary buttons carry white label text in both themes. White on the bright
  // neon (#34e5a0) fails contrast, so in dark mode the button FILL is deepened
  // to a rich emerald where white reads cleanly; the neon accent is kept for
  // glows, active-nav and sparklines. Light mode's #2f9d68 already pairs with
  // white. hover/pressed/focus text stay white too.
  const btnFill = isDark.value ? '#0d9d61' : accent
  const btnFillHover = isDark.value ? '#12b06e' : accentHover
  const btnFillPressed = isDark.value ? '#0a8452' : accentPressed
  return {
    common: {
      primaryColor: accent,
      primaryColorHover: accentHover,
      primaryColorPressed: accentPressed,
      primaryColorSuppl: accent,
      borderRadius: '9px',
      borderRadiusSmall: '7px',
      fontFamily: 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    },
    Button: {
      borderRadiusMedium: '9px',
      heightMedium: '36px',
      fontWeight: '600',
      colorPrimary: btnFill,
      colorHoverPrimary: btnFillHover,
      colorPressedPrimary: btnFillPressed,
      colorFocusPrimary: btnFill,
      borderPrimary: `1px solid ${btnFill}`,
      borderHoverPrimary: `1px solid ${btnFillHover}`,
      borderPressedPrimary: `1px solid ${btnFillPressed}`,
      borderFocusPrimary: `1px solid ${btnFill}`,
      textColorPrimary: '#ffffff',
      textColorHoverPrimary: '#ffffff',
      textColorPressedPrimary: '#ffffff',
      textColorFocusPrimary: '#ffffff',
    },
    Input: { borderRadius: '9px', heightMedium: '36px', heightLarge: '44px' },
  }
})

async function submitLogin(form: { username: string; password: string; totp: string; rememberDevice: boolean }) {
  loginLoading.value = true
  loginError.value = ''
  try {
    const session = await login({
      Username: form.username,
      Password: form.password,
      TOTP: form.totp,
      RememberDevice: form.rememberDevice,
    })
		sessionRole.value = session.role
    authed.value = true
    await ops.refresh()
    if (ops.error) throw new Error(ops.error)
    ops.startLiveMonitoring()
    showNotice('登录成功')
  } catch (err) {
    ops.stopLiveMonitoring()
    authed.value = false
    loginError.value = friendlyError(err)
  } finally {
    loginLoading.value = false
  }
}

async function refreshAll() {
  await ops.refresh()
  if (!ops.error) showNotice('运行数据已刷新')
}

async function handleLogout() {
  ops.stopLiveMonitoring()
  try {
    await logout()
  } catch {
    // 后端 session 已失效也照样回登录页
  }
  authed.value = false
  loginError.value = ''
  showNotice('已退出登录')
}

async function collectTraffic() {
  try {
    await ops.collectTraffic()
    showNotice('流量样本已采集')
  } catch (err) {
    showNotice(friendlyError(err), 'error')
  }
}

function toggleTheme() {
  isDark.value = !isDark.value
  localStorage.setItem('porthub-theme', isDark.value ? 'dark' : 'light')
}

function showNotice(text: string, type: 'success' | 'error' = 'success') {
  notice.value = text
  noticeType.value = type
  window.setTimeout(() => {
    if (notice.value === text) notice.value = ''
  }, 3200)
}

function friendlyError(err: unknown) {
  const value = err instanceof Error ? err.message : String(err)
  if (value.includes('unauthorized')) return '用户名、密码或验证码不正确'
  if (value.includes('rate')) return '登录尝试过于频繁，请稍后再试'
  return value
}

watch(isDark, (dark) => {
  document.documentElement.dataset.theme = dark ? 'dark' : 'light'
}, { immediate: true })

watch(() => route.path, () => {
  mobileNavOpen.value = false
  window.scrollTo({ top: 0, behavior: 'smooth' })
})

onMounted(async () => {
  document.documentElement.dataset.theme = isDark.value ? 'dark' : 'light'
	try {
		const session = await restoreSession()
		sessionRole.value = session.role
		authed.value = true
		await ops.refresh()
		ops.startLiveMonitoring()
	} catch {
		ops.stopLiveMonitoring()
		authed.value = false
	} finally {
		authChecking.value = false
	}
})

onBeforeUnmount(() => ops.stopLiveMonitoring())
</script>

<template>
  <n-config-provider :theme="isDark ? darkTheme : null" :theme-overrides="themeOverrides">
    <div v-if="authChecking" class="auth-checking" aria-label="正在恢复会话"></div>
    <LoginScreen
      v-else-if="!authed"
      :loading="loginLoading"
      :error="loginError"
      :dark="isDark"
      @submit="submitLogin"
      @toggle-theme="toggleTheme"
    />

    <div v-else class="app-shell">
      <AppSidebar
        :open="mobileNavOpen"
        :core-status="ops.status.core || ''"
        :edge-status="ops.status.edge || ''"
		:role="sessionRole"
        @close="mobileNavOpen = false"
      />

      <main class="content">
        <header class="topbar">
          <div class="topbar-title">
            <button class="icon-button mobile-menu" title="打开导航" aria-label="打开导航" @click="mobileNavOpen = true"><Menu :size="20" /></button>
            <div><span>{{ activeSection }}</span><strong>{{ activeLabel }}</strong></div>
          </div>
          <div class="topbar-actions">
            <span class="edge-badge"><i class="status-dot online"></i><span>Edge</span><b>203.0.113.10</b></span>
            <button class="icon-button" title="本页使用说明" aria-label="本页使用说明" @click="helpOpen = true"><CircleHelp :size="18" /></button>
            <button class="icon-button" title="切换主题" aria-label="切换主题" @click="toggleTheme">
              <Sun v-if="isDark" :size="18" />
              <Moon v-else :size="18" />
            </button>
            <n-button secondary size="small" :loading="ops.loading" @click="refreshAll"><RefreshCw :size="16" />刷新</n-button>
            <n-button secondary size="small" title="退出登录" aria-label="退出登录" @click="handleLogout"><LogOut :size="16" />退出</n-button>
          </div>
        </header>

        <div class="wrap">
          <transition name="page" mode="out-in"><div :key="route.path" class="page-stage">
          <DashboardPanel v-if="route.path === '/'" :dark="isDark" @collect-traffic="collectTraffic" />
          <NodesPanel v-else-if="route.path === '/nodes'" @notify="showNotice" />
          <WireGuardPanel v-else-if="route.path === '/wireguard'" @notify="showNotice" />
          <InventoryPanel v-else-if="route.path === '/inventory'" @notify="showNotice" />
          <PublishPanel v-else-if="route.path === '/publish'" @notify="showNotice" />
          <MappingsPanel v-else-if="route.path === '/mappings'" @notify="showNotice" />
          <PortForwardPanel v-else-if="route.path === '/port-forward'" @notify="showNotice" />
          <ProxyPanel v-else-if="route.path === '/proxy'" @notify="showNotice" />
          <DomainsPanel v-else-if="route.path === '/domains'" @notify="showNotice" />
          <CertificatesPanel v-else-if="route.path === '/certificates'" @notify="showNotice" />

          <IPSetsPanel v-else-if="route.path === '/ip-sets'" @notify="showNotice" />

          <SecurityPanel v-else-if="route.path === '/security'" @notify="showNotice" />

          <TrafficPanel v-else-if="route.path === '/traffic'" @collect="collectTraffic" @notify="showNotice" />

          <ManagedServicesPanel v-else-if="route.path === '/qx-services'" @notify="showNotice" />
          <AirSIMPanel v-else-if="route.path === '/airsim'" @notify="showNotice" />
          <TokensPanel v-else-if="route.path === '/tokens'" @notify="showNotice" />
          <WebhooksPanel v-else-if="route.path === '/webhooks'" @notify="showNotice" />
          <UsersPanel v-else-if="route.path === '/users'" @notify="showNotice" />
          <BackupsPanel v-else-if="route.path === '/backups'" @notify="showNotice" />
          <SnapshotsPanel v-else-if="route.path === '/snapshots'" @notify="showNotice" />
          <AssistantPanel v-else-if="route.path === '/assistant'" @notify="showNotice" />
          <UpdatesPanel v-else-if="route.path === '/updates'" @notify="showNotice" />

          <AuditPanel v-else-if="route.path === '/audit'" />
          </div></transition>
        </div>

        <PageHelpDrawer v-model:show="helpOpen" :path="route.path" />

        <transition name="toast">
          <n-alert v-if="notice" class="global-notice" :type="noticeType" :bordered="false" closable @close="notice = ''">{{ notice }}</n-alert>
        </transition>
        <n-alert v-if="ops.error" class="global-error" type="error" :bordered="false" closable @close="ops.error = ''">{{ ops.error }}</n-alert>
      </main>
    </div>
  </n-config-provider>
</template>
