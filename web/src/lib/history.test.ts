import { describe, expect, test } from "vitest"
import { parseHistory } from "./history"

const rec = (over: object = {}) => ({
  id: "a1",
  shareUrl: "http://x/v/a1#k",
  burn: false,
  createdAt: "2026-01-01T00:00:00Z",
  expiresAt: "2099-01-01T00:00:00Z",
  deleteToken: "t",
  ...over,
})

describe("parseHistory", () => {
  test("keeps valid unexpired records", () => {
    expect(parseHistory(JSON.stringify([rec()]))).toHaveLength(1)
  })
  test("drops expired and malformed records", () => {
    const raw = JSON.stringify([
      rec({ expiresAt: "2000-01-01T00:00:00Z" }),
      { id: 5 },
      null,
      rec({ id: "b2" }),
    ])
    expect(parseHistory(raw).map((r) => r.id)).toEqual(["b2"])
  })
  test("survives garbage", () => {
    expect(parseHistory("{nope")).toEqual([])
    expect(parseHistory('{"a":1}')).toEqual([])
    expect(parseHistory(null)).toEqual([])
  })
})
