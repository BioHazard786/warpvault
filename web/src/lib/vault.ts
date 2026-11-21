// Warpvault blob format (protocol/PROTOCOL.md): AES-256-GCM, key = HKDF(link key [|| PBKDF2(passphrase)]).
// The server only ever sees the blob. Must reproduce protocol/fixtures/vectors.json byte for byte.

const VERSION = 0x01
const FLAG_PASS = 0x01
const SALT_LEN = 16
const NONCE_LEN = 12
const HEADER_LEN = 2 + SALT_LEN + NONCE_LEN // also the GCM additional data
const TAG_LEN = 16
const KEY_LEN = 32
const PBKDF2_ITERATIONS = 600_000
const MAX_NAME_BYTES = 0xffff
const PLAIN_OVERHEAD = 1 + 2 // kind + nameLen

export type Bytes = Uint8Array<ArrayBuffer>

export type SecretKind = "text" | "file"
export type Secret = { kind: SecretKind; name: string; data: Bytes }

export type VaultErrorCode = "not-blob" | "bad-key" | "passphrase-required" | "decrypt"
export class VaultError extends Error {
  readonly code: VaultErrorCode
  constructor(code: VaultErrorCode, message: string) {
    super(message)
    this.code = code
  }
}

const utf8 = (s: string): Bytes => new TextEncoder().encode(s) as Bytes

export function b64urlEncode(bytes: Uint8Array): string {
  let bin = ""
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function b64urlDecode(s: string): Bytes | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"))
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  } catch {
    return null
  }
}

/** A fresh link key: 32 random bytes, base64url without padding (43 characters). */
export function newKey(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(KEY_LEN)))
}

/** True when the blob header says a passphrase is required. */
export function needsPassphrase(blob: Uint8Array): boolean {
  return blob.length >= HEADER_LEN + TAG_LEN && blob[0] === VERSION && (blob[1]! & FLAG_PASS) !== 0
}

/** Exact size of the blob `seal` will produce, for checking the server's size limit before encrypting. */
export function sealedSize(secret: { name: string; data: { length: number } }): number {
  return HEADER_LEN + PLAIN_OVERHEAD + utf8(secret.name).length + secret.data.length + TAG_LEN
}

async function deriveKey(keyStr: string, passphrase: string, salt: Bytes): Promise<CryptoKey> {
  const k = b64urlDecode(keyStr)
  if (!k || k.length !== KEY_LEN)
    throw new VaultError(
      "bad-key",
      "The link's key is malformed. Copy the complete link, including the part after #.",
    )
  let ikm: Bytes = k
  let info = "warpvault/1"
  if (passphrase) {
    const pw = await crypto.subtle.importKey("raw", utf8(passphrase), "PBKDF2", false, [
      "deriveBits",
    ])
    const pk = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
        pw,
        256,
      ),
    )
    ikm = new Uint8Array(KEY_LEN * 2)
    ikm.set(k)
    ikm.set(pk, KEY_LEN)
    info = "warpvault/1/pass"
  }
  const hk = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"])
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: utf8(info) },
    hk,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  )
}

/** Encrypt `secret`. `fixed` pins salt and nonce for the test vectors only; never pass it otherwise. */
export async function seal(
  secret: Secret,
  key: string,
  passphrase = "",
  fixed?: { salt: Bytes; nonce: Bytes },
): Promise<Bytes> {
  const name = utf8(secret.kind === "file" ? secret.name : "")
  if (name.length > MAX_NAME_BYTES) throw new Error("File name is too long")
  const plain = new Uint8Array(PLAIN_OVERHEAD + name.length + secret.data.length)
  plain[0] = secret.kind === "file" ? 1 : 0
  new DataView(plain.buffer).setUint16(1, name.length)
  plain.set(name, 3)
  plain.set(secret.data, 3 + name.length)

  const salt = fixed?.salt ?? crypto.getRandomValues(new Uint8Array(SALT_LEN))
  const nonce = fixed?.nonce ?? crypto.getRandomValues(new Uint8Array(NONCE_LEN))
  const header = new Uint8Array(HEADER_LEN)
  header[0] = VERSION
  header[1] = passphrase ? FLAG_PASS : 0
  header.set(salt, 2)
  header.set(nonce, 2 + SALT_LEN)

  const aesKey = await deriveKey(key, passphrase, salt)
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: header },
      aesKey,
      plain,
    ),
  )
  const out = new Uint8Array(HEADER_LEN + ct.length)
  out.set(header)
  out.set(ct, HEADER_LEN)
  return out
}

/** Decrypt a blob. Throws VaultError: "passphrase-required" when one is needed and missing, "decrypt" when key/passphrase is wrong or data was altered. */
export async function open(blob: Uint8Array, key: string, passphrase = ""): Promise<Secret> {
  if (blob.length < HEADER_LEN + TAG_LEN || blob[0] !== VERSION || (blob[1]! & ~FLAG_PASS) !== 0)
    throw new VaultError("not-blob", "This is not a Warpvault secret (wrong format).")
  const protectedBlob = needsPassphrase(blob)
  if (protectedBlob && !passphrase)
    throw new VaultError("passphrase-required", "This secret needs a passphrase.")

  const header = blob.slice(0, HEADER_LEN)
  const salt = header.slice(2, 2 + SALT_LEN)
  const nonce = header.slice(2 + SALT_LEN)
  const aesKey = await deriveKey(key, protectedBlob ? passphrase : "", salt)
  let plain: Bytes
  try {
    plain = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: header },
        aesKey,
        blob.slice(HEADER_LEN),
      ),
    )
  } catch {
    throw new VaultError("decrypt", "Wrong key or passphrase, or the data was modified.")
  }
  if (plain.length < PLAIN_OVERHEAD) throw new VaultError("not-blob", "This secret is malformed.")
  const nameLen = new DataView(plain.buffer, plain.byteOffset).getUint16(1)
  if (plain.length < PLAIN_OVERHEAD + nameLen)
    throw new VaultError("not-blob", "This secret is malformed.")
  return {
    kind: plain[0] === 1 ? "file" : "text",
    name: new TextDecoder().decode(plain.subarray(3, 3 + nameLen)),
    data: plain.subarray(3 + nameLen),
  }
}
