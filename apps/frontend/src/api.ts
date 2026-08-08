export type LoginInput = {
  Username: string
  Password: string
  TOTP: string
  RememberDevice?: boolean
}

export type UserRole = 'readonly' | 'operator' | 'admin' | 'super_admin'

export type SessionInfo = {
  ok: boolean
  username: string
  role: UserRole
  csrf: string
  must_change: boolean
  trusted_device?: boolean
}

let csrf = ''
let role: UserRole = 'readonly'

export function isAuthed() {
  return csrf.length > 0
}

export async function login(input: LoginInput) {
	const res = await request<SessionInfo>('/api/login', {
    method: 'POST',
    body: JSON.stringify(input),
  })
	csrf = res.csrf
	role = res.role
	return res
}

export async function restoreSession() {
  const res = await request<SessionInfo>('/api/session')
  csrf = res.csrf
  role = res.role
  return res
}

export async function logout() {
  try {
    await request<{ ok: boolean }>('/api/logout', { method: 'POST' })
  } finally {
    csrf = ''
    role = 'readonly'
  }
}

export function hasRole(required: UserRole) {
  const ranks: Record<UserRole, number> = { readonly: 0, operator: 1, admin: 2, super_admin: 3 }
  return ranks[role] >= ranks[required]
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('content-type', 'application/json')
  if (init.method && init.method !== 'GET' && csrf) {
    headers.set('X-CSRF-Token', csrf)
  }
  const res = await fetch(path, { ...init, headers, credentials: 'same-origin' })
  const text = await res.text()
  if (!res.ok) {
    throw new Error(text || `${res.status}`)
  }
  return (text ? JSON.parse(text) : {}) as T
}
