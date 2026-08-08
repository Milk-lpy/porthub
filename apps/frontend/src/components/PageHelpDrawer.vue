<script setup lang="ts">
import { BookOpen, CircleAlert, MousePointerClick, X } from '@lucide/vue'
import { NDrawer, NDrawerContent } from 'naive-ui'
import { computed } from 'vue'
import { helpFor } from '../pageHelp'

const props = defineProps<{ path: string }>()
const show = defineModel<boolean>('show', { required: true })
const page = computed(() => helpFor(props.path))
</script>

<template>
  <n-drawer v-model:show="show" :width="380" placement="right" class="help-drawer">
    <n-drawer-content :native-scrollbar="false">
      <template #header><div class="drawer-title"><BookOpen :size="19" /><span><b>{{ page.title }}</b><small>使用说明</small></span><button class="icon-button" aria-label="关闭说明" @click="show = false"><X :size="17" /></button></div></template>

      <p class="help-summary">{{ page.summary }}</p>
      <section class="help-section">
        <h3><MousePointerClick :size="16" />建议操作顺序</h3>
        <ol><li v-for="(step, index) in page.steps" :key="step"><i>{{ index + 1 }}</i><span>{{ step }}</span></li></ol>
      </section>
      <section class="help-section">
        <h3><BookOpen :size="16" />名词解释</h3>
        <dl><div v-for="item in page.terms" :key="item.term"><dt>{{ item.term }}</dt><dd>{{ item.meaning }}</dd></div></dl>
      </section>
      <div v-if="page.caution" class="help-caution"><CircleAlert :size="17" /><span>{{ page.caution }}</span></div>
    </n-drawer-content>
  </n-drawer>
</template>
