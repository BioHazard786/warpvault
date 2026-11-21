/** Server limits from GET /api/info; read at runtime so the UI always matches the server's config. */
export type Info = {
  version: string
  max_secret_size_mb: number
  allowed_expiries: string[]
  default_expiry: string
  auth_required: boolean
}

/** Answer to storing a blob (POST /api/vault). */
export type Created = {
  id: string
  url: string
  delete_url: string
  delete_token: string
  size_bytes: number
  created_at: string
  expires_at: string
  burn: boolean
}

/** Public details of a secret, from GET /api/vault/{id}. Reading them never burns it. */
export type Meta = {
  id: string
  size_bytes: number
  burn: boolean
  passphrase: boolean
  expires_at: string
}

/** Error text from a JSON `{error}` body, else plain text, else the status. */
async function errorText(res: Response): Promise<string> {
  const text = (await res.text().catch(() => "")).trim()
  try {
    return JSON.parse(text).error || `HTTP ${res.status}`
  } catch {
    return text || `HTTP ${res.status}`
  }
}

export async function fetchInfo(): Promise<Info> {
  const res = await fetch("/api/info", { headers: { Accept: "application/json" } })
  if (!res.ok) throw new Error(`Server returned HTTP ${res.status}`)
  return res.json()
}

/** Store an encrypted blob. */
export async function createSecret(
  blob: Uint8Array<ArrayBuffer>,
  expiry: string,
  token: string,
): Promise<Created> {
  const res = await fetch(`/api/vault?expiry=${encodeURIComponent(expiry)}`, {
    method: "POST",
    headers: { Accept: "application/json", ...(token ? { "X-Auth-Token": token } : {}) },
    body: new Blob([blob]),
  })
  if (res.status === 401) throw new Error("Wrong or missing upload token")
  if (!res.ok) throw new Error(await errorText(res))
  return res.json()
}

/** The secret's details, or the HTTP status when it's gone (410) or unknown/expired (404). */
export async function fetchMeta(id: string): Promise<Meta | number> {
  const res = await fetch(`/api/vault/${encodeURIComponent(id)}`, {
    headers: { Accept: "application/json" },
  })
  if (res.status === 404 || res.status === 410) return res.status
  if (!res.ok) throw new Error(await errorText(res))
  return res.json()
}

/** Download the blob. A burn-after-reading secret is destroyed on the server by this call, so the caller
 *  must keep the bytes until decryption succeeds. Returns the HTTP status when it's gone (410) or unknown (404). */
export async function openSecret(id: string): Promise<Uint8Array<ArrayBuffer> | number> {
  const res = await fetch(`/api/vault/${encodeURIComponent(id)}/open`, { method: "POST" })
  if (res.status === 404 || res.status === 410) return res.status
  if (!res.ok) throw new Error(await errorText(res))
  return new Uint8Array(await res.arrayBuffer())
}

/** Delete early with the token from the create response. Already gone (404/410) counts as success. */
export async function deleteSecret(id: string, token: string): Promise<void> {
  const res = await fetch(`/api/vault/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: { "X-Delete-Token": token },
  })
  if (!res.ok && res.status !== 404 && res.status !== 410) throw new Error(await errorText(res))
}

/** Used by the /d/{token} page. Resolves to whether something was actually destroyed. */
export async function destroyByToken(token: string): Promise<boolean> {
  const res = await fetch(`/api/destroy/${encodeURIComponent(token)}`, { method: "POST" })
  if (res.status === 404) return false
  if (!res.ok) throw new Error(await errorText(res))
  return true
}
