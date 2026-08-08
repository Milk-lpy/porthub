<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { X, Waypoints } from '@lucide/vue'
import { navGroups } from '../navigation'
import type { UserRole } from '../api'

const props = defineProps<{
  open: boolean
  coreStatus: string
  edgeStatus: string
  role: UserRole
}>()

const emit = defineEmits<{ close: [] }>()
const route = useRoute()
const visibleGroups = computed(() => {
  const ranks: Record<UserRole, number> = { readonly: 0, operator: 1, admin: 2, super_admin: 3 }
  return navGroups.map((group) => ({
    ...group,
    items: group.items.filter((item) => ranks[props.role] >= ranks[item.minimumRole || 'readonly']),
  })).filter((group) => group.items.length > 0)
})

function closeOnNavigate() {
  emit('close')
}
</script>

<template>
  <button v-if="open" class="sidebar-backdrop" aria-label="关闭导航" @click="emit('close')"></button>
  <aside :class="['sidebar', { open }]">
    <div class="sidebar-head">
      <RouterLink class="brand" to="/" @click="closeOnNavigate">
        <span class="mark"><Waypoints :size="21" :stroke-width="2.2" /></span>
        <span class="brand-copy">
          <strong>PortHub</strong>
          <small>Network Control</small>
        </span>
      </RouterLink>
      <button class="icon-button sidebar-close" title="关闭导航" aria-label="关闭导航" @click="emit('close')">
        <X :size="19" />
      </button>
    </div>

    <nav class="nav" aria-label="主导航">
      <div v-for="group in visibleGroups" :key="group.label" class="nav-group">
        <span class="nav-group-label">{{ group.label }}</span>
        <RouterLink
          v-for="item in group.items"
          :key="item.path"
          :to="item.path"
          :class="{ active: route.path === item.path }"
          @click="closeOnNavigate"
        >
          <component :is="item.icon" :size="18" :stroke-width="1.8" />
          <span>{{ item.label }}</span>
          <i v-if="route.path === item.path"></i>
        </RouterLink>
      </div>
    </nav>

    <div class="sidebar-health">
      <div class="sidebar-health-title">
        <span>控制平面</span>
        <span class="live-indicator"><i></i> LIVE</span>
      </div>
      <div class="health-line">
        <span><i class="status-dot online"></i>Core</span>
        <b>{{ coreStatus || '--' }}</b>
      </div>
      <div class="health-line">
        <span><i class="status-dot online"></i>Edge</span>
        <b>{{ edgeStatus || '--' }}</b>
      </div>
    </div>
  </aside>
</template>
