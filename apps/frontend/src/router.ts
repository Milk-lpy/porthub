import { createRouter, createWebHistory } from 'vue-router'
import { navItems } from './navigation'

const Placeholder = { template: '<div />' }

export { navItems } from './navigation'

export const router = createRouter({
  history: createWebHistory(),
  routes: navItems.map((item) => ({
    path: item.path,
    component: Placeholder,
    meta: { label: item.label },
  })),
})
