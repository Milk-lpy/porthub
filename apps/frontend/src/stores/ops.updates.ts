export type UpdateStatus = {
  enabled: boolean
  current_version: string
  manifest_url?: string
  latest_version?: string
  last_checked_at?: string
  last_status?: string
  last_error?: string
  staged_version?: string
  staged_component?: 'core' | 'agent'
  staged_path?: string
}

export type UpdateCheckResult = {
  ok: boolean
  current_version: string
  latest_version: string
  published_at: string
  notes?: string
  available: boolean
}
