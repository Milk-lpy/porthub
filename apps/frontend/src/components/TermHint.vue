<script setup lang="ts">
import { CircleHelp } from '@lucide/vue'
import { NPopover } from 'naive-ui'

defineProps<{ text: string }>()
</script>

<template>
  <n-popover trigger="hover" placement="top" style="max-width: 280px">
    <template #trigger><button type="button" class="term-hint" aria-label="查看名词解释"><CircleHelp :size="13" /></button></template>
    <span class="term-hint-copy">{{ text }}</span>
  </n-popover>
</template>
