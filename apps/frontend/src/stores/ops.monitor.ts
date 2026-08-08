export type TrafficRule = {
  ts: string
  protocol: string
  port: number
  target: string
  packets: number
  bytes: number
}

export type TrafficSample = {
  ts: string
  edge_version: string
  packets: number
  bytes: number
  rx_bytes: number
  tx_bytes: number
  rx_bytes_per_second: number
  tx_bytes_per_second: number
  connections: number
  cpu_percent: number
  memory_used_bytes: number
  memory_total_bytes: number
}

export type ConnectionSummary = {
  observed_at: string
  source_ip: string
  mapping_id: string
  mapping: string
  protocol: string
  public_port: number
  target: string
  state: string
  bytes: number
  timeout_seconds: number
}

export type PublicSourceAuditRecord = {
  id: number
  observed_minute: string
  first_seen_at: string
  last_seen_at: string
  edge_version: string
  source_ip: string
  source_ip_masked: string
  mapping_id: string
  mapping: string
  protocol: string
  public_port: number
  target: string
  state: string
  bytes: number
  observations: number
  timeout_seconds: number
}

export type PublicSourceSummary = {
  source_ip: string
  source_ip_masked: string
  mappings: number
  bytes: number
  observations: number
  last_seen_at: string
}

export type PublicSourceAuditResponse = {
  records: PublicSourceAuditRecord[]
  summary: PublicSourceSummary[]
  total: number
  retention_days: number
  exact_source_ip: boolean
}

export type MetricAlert = {
  fingerprint: string
  severity: 'warning' | 'critical'
  title: string
  detail: string
}

export type SystemAlert = MetricAlert & {
  id: number
  source: string
  first_seen_at: string
  last_seen_at: string
  active: boolean
  acknowledged_at?: string
  resolved_at?: string
}

export type EdgeMetrics = Record<string, unknown> & {
  time?: string
  bytes?: number
  packets?: number
  public_interface?: string
  rx_bytes?: number
  tx_bytes?: number
  rx_bytes_per_second?: number
  tx_bytes_per_second?: number
  cpu_percent?: number
  memory_used_bytes?: number
  memory_total_bytes?: number
  disk_used_bytes?: number
  disk_total_bytes?: number
  load_1?: number
  connections?: number
  conntrack_max?: number
  connection_summary?: ConnectionSummary[]
  alerts?: MetricAlert[]
}

// CoreMetrics 是 Core 节点本机实时指标 (GET /api/metrics, core 进程直接采集)。
export type CoreMetrics = Record<string, unknown> & {
  time?: string
  cpu_percent?: number
  memory_used_bytes?: number
  memory_total_bytes?: number
  disk_used_bytes?: number
  disk_total_bytes?: number
  load_1?: number
  load_5?: number
  load_15?: number
  processes?: number
  uptime_seconds?: number
}
