export type CertificateItem = {
  id: number
  name: string
  domains: string[]
  issuer: string
  mode: string
  status: string
  expires_at: string
  key_ref?: string
  dns_provider_id?: number
  enabled: boolean
}

export type CertificatePlan = {
  ok: boolean
  certificate_id: number
  name: string
  mode: string
  domains: string[]
  renewal_required: boolean
  expires_at?: string
  steps: string[]
  blockers: string[]
}

export type CertificatePrepareResult = {
  ok: boolean
  dry_run: boolean
  certificate_id: number
  key_ref?: string
  webroot?: string
  challenge_refs: string[]
  steps: string[]
  blockers: string[]
}

export type ACMEIssueResult = {
  ok: boolean
  certificate_id: number
  domains: string[]
  expires_at: string
  deployed: boolean
  issuer: string
}

export type ACMEStatus = {
  email: string
  directory_url: string
  ready: boolean
}
