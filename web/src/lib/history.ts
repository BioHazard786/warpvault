import { useMemo, useSyncExternalStore } from "react"

/** Secrets created in this browser. The share link (with its #key) is kept so it can be copied again. */
export type HistoryRecord = {
  id: string
  shareUrl: string
  burn: boolean
  createdAt: string
  expiresAt: string
  deleteToken: string
}

const KEY = "warpvault_history"
const EVENT = "warpvault:history"
const MAX = 50

/** Valid, unexpired records from the stored JSON. */
export function parseHistory(raw: string | null, now = Date.now()): HistoryRecord[] {
  let list: unknown
  try {
    list = JSON.parse(raw || "[]")
  } catch {
    return []
  }
  if (!Array.isArray(list)) return []
  return list.filter((r): r is HistoryRecord => {
    if (!r || typeof r.id !== "string" || typeof r.shareUrl !== "string") return false
    const exp = new Date(r.expiresAt).getTime()
    return isNaN(exp) || exp > now
  })
}

const read = () => parseHistory(localStorage.getItem(KEY))

function write(list: HistoryRecord[]) {
  try {
    localStorage.setItem(KEY, JSON.stringify(list.slice(0, MAX)))
  } catch {
    return // storage full or blocked: history is a convenience, never fail the user's action
  }
  dispatchEvent(new Event(EVENT))
}

export const addHistory = (r: HistoryRecord) => write([r, ...read().filter((x) => x.id !== r.id)])
export const removeHistory = (id: string) => write(read().filter((r) => r.id !== id))
export const clearHistory = () => write([])

function subscribe(cb: () => void) {
  addEventListener(EVENT, cb)
  addEventListener("storage", cb) // other tabs
  return () => {
    removeEventListener(EVENT, cb)
    removeEventListener("storage", cb)
  }
}

export function useHistory(): HistoryRecord[] {
  const raw = useSyncExternalStore(subscribe, () => localStorage.getItem(KEY))
  return useMemo(() => parseHistory(raw), [raw])
}
