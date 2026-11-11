import type { Component } from 'vue'
import {
  Activity,
  ArrowLeftRight,
  Boxes,
  Bot,
  Cable,
  ChartNoAxesCombined,
  DatabaseBackup,
  FileClock,
  Globe2,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  Network,
  PhoneCall,
  RadioTower,
  Router,
  Route,
  ScrollText,
  Send,
  ServerCog,
  ShieldCheck,
  SquareChevronUp,
  Users,
  Webhook,
} from '@lucide/vue'

export type NavItem = {
  path: string
  label: string
  shortLabel: string
  icon: Component
  minimumRole?: 'readonly' | 'operator' | 'admin' | 'super_admin'
}

export type NavGroup = {
  label: string
  items: NavItem[]
}

export const navGroups: NavGroup[] = [
  {
    label: '工作台',
    items: [
      { path: '/', label: '运行总览', shortLabel: '总览', icon: LayoutDashboard },
      { path: '/nodes', label: '节点管理', shortLabel: '节点', icon: Network },
      { path: '/wireguard', label: 'WireGuard 隧道', shortLabel: '隧道', icon: Cable },
      { path: '/inventory', label: '资源与服务', shortLabel: '资源', icon: Boxes },
    ],
  },
  {
    label: '入口管理',
    items: [
      { path: '/publish', label: '快速发布', shortLabel: '发布', icon: Send },
      { path: '/mappings', label: '端口映射', shortLabel: '映射', icon: Route },
      { path: '/port-forward', label: '端口转发', shortLabel: '转发', icon: ArrowLeftRight },
      { path: '/proxy', label: '反向代理', shortLabel: '代理', icon: Cable },
    ],
  },
  {
    label: '域名与安全',
    items: [
      { path: '/domains', label: '域名与 DDNS', shortLabel: '域名', icon: Globe2 },
      { path: '/certificates', label: 'TLS 证书', shortLabel: '证书', icon: LockKeyhole },
      { path: '/ip-sets', label: 'IP 集合', shortLabel: 'IP 集', icon: RadioTower },
      { path: '/security', label: 'ACL 安全', shortLabel: 'ACL', icon: ShieldCheck },
    ],
  },
  {
    label: '可观测性',
    items: [
      { path: '/traffic', label: '流量统计', shortLabel: '流量', icon: ChartNoAxesCombined },
      { path: '/audit', label: '审计日志', shortLabel: '审计', icon: ScrollText },
      { path: '/snapshots', label: '配置快照', shortLabel: '快照', icon: FileClock },
    ],
  },
  {
    label: '系统',
    items: [
      { path: '/qx-services', label: '本机服务', shortLabel: '服务', icon: Router },
      { path: '/airsim', label: 'AirSIM 通信', shortLabel: 'AirSIM', icon: PhoneCall },
      { path: '/assistant', label: '命令助手', shortLabel: '助手', icon: Bot },
      { path: '/tokens', label: 'API Token', shortLabel: 'Token', icon: KeyRound, minimumRole: 'admin' },
      { path: '/webhooks', label: 'Webhook', shortLabel: 'Webhook', icon: Webhook, minimumRole: 'admin' },
      { path: '/users', label: '用户与角色', shortLabel: '用户', icon: Users, minimumRole: 'super_admin' },
      { path: '/backups', label: '备份恢复', shortLabel: '备份', icon: DatabaseBackup, minimumRole: 'admin' },
      { path: '/updates', label: '升级管理', shortLabel: '升级', icon: SquareChevronUp, minimumRole: 'admin' },
    ],
  },
]

export const navItems = navGroups.flatMap((group) => group.items)

export const utilityIcons = {
  activity: Activity,
  snapshots: FileClock,
  server: ServerCog,
}
