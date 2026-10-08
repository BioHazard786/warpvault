/**
 * Warpvault Client-Side WebCrypto Engine
 *
 * Implements 100% OpenSSL PBKDF2-AES-256-CBC compatible client-side encryption
 * and decryption using pure browser Web Crypto API (crypto.subtle).
 */

const OPENSSL_MAGIC = "Salted__";
const SALT_LEN = 8;
const KEY_LEN = 32;
const IV_LEN = 16;
const DERIVED_LEN_BITS = (KEY_LEN + IV_LEN) * 8; // 48 bytes * 8 = 384 bits
const PBKDF2_ITERATIONS = 10000;

/**
 * Generate a cryptographically secure 16-byte random key (32 hex characters).
 */
export function generateKey(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Derives a 32-byte AES key and 16-byte IV from password + salt via PBKDF2-HMAC-SHA256.
 */
async function deriveKeyAndIV(
  password: string,
  salt: Uint8Array,
  usage: "encrypt" | "decrypt"
): Promise<{ key: CryptoKey; iv: Uint8Array }> {
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(password);

  const baseKey = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    DERIVED_LEN_BITS
  );

  const derivedBytes = new Uint8Array(derivedBits);
  const keyBytes = derivedBytes.subarray(0, KEY_LEN);
  const ivBytes = derivedBytes.subarray(KEY_LEN, KEY_LEN + IV_LEN);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    [usage]
  );

  return { key, iv: ivBytes };
}

export interface EncryptResult {
  ciphertext: Uint8Array;
  key: string;
}

/**
 * Encrypts a payload into standard OpenSSL PBKDF2-AES-256-CBC wire container format.
 */
export async function encryptPayload(
  plaintext: Uint8Array | string,
  keyStr?: string
): Promise<EncryptResult> {
  const key = keyStr && keyStr.trim().length > 0 ? keyStr.trim() : generateKey();

  const dataBytes =
    typeof plaintext === "string"
      ? new TextEncoder().encode(plaintext)
      : plaintext;

  const salt = new Uint8Array(SALT_LEN);
  crypto.getRandomValues(salt);

  const { key: aesKey, iv } = await deriveKeyAndIV(key, salt, "encrypt");

  const encryptedBuf = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    aesKey,
    dataBytes
  );

  const encryptedBytes = new Uint8Array(encryptedBuf);
  const magicBytes = new TextEncoder().encode(OPENSSL_MAGIC);

  // Wire format: "Salted__" (8 bytes) + Salt (8 bytes) + Ciphertext (N bytes)
  const fullPayload = new Uint8Array(
    magicBytes.length + salt.length + encryptedBytes.length
  );
  fullPayload.set(magicBytes, 0);
  fullPayload.set(salt, magicBytes.length);
  fullPayload.set(encryptedBytes, magicBytes.length + salt.length);

  return {
    ciphertext: fullPayload,
    key,
  };
}

/**
 * Decrypts an OpenSSL PBKDF2-AES-256-CBC payload in browser memory.
 */
export async function decryptPayload(
  data: Uint8Array,
  keyStr: string
): Promise<Uint8Array> {
  const key = keyStr.trim();
  if (!key) {
    throw new Error("Decryption key cannot be empty");
  }

  const minLength = OPENSSL_MAGIC.length + SALT_LEN + 16;
  if (data.length < minLength) {
    throw new Error("Encrypted payload is too short or invalid");
  }

  const magic = new TextDecoder().decode(data.subarray(0, OPENSSL_MAGIC.length));
  if (magic !== OPENSSL_MAGIC) {
    throw new Error("Invalid format: missing OpenSSL Salted__ header");
  }

  const salt = data.subarray(OPENSSL_MAGIC.length, OPENSSL_MAGIC.length + SALT_LEN);
  const ciphertext = data.subarray(OPENSSL_MAGIC.length + SALT_LEN);

  const { key: aesKey, iv } = await deriveKeyAndIV(key, salt, "decrypt");

  try {
    const decryptedBuf = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv },
      aesKey,
      ciphertext
    );
    return new Uint8Array(decryptedBuf);
  } catch (err) {
    throw new Error("Decryption failed: incorrect key or corrupted secret");
  }
}

/**
 * Package a confidential file into a JSON envelope before encryption.
 */
export function packFile(filename: string, fileBytes: Uint8Array): Uint8Array {
  // Convert binary to base64
  let binary = "";
  const len = fileBytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(fileBytes[i]);
  }
  const b64 = btoa(binary);

  const envelope = JSON.stringify({
    __warpvault__: true,
    type: "file",
    filename: filename,
    size: len,
    data: b64,
  });

  return new TextEncoder().encode(envelope);
}

export interface DecodedSecret {
  isFile: boolean;
  filename?: string;
  data: Uint8Array;
  text?: string;
}

/**
 * Unpacks decrypted bytes into either a structured file attachment or plaintext text.
 */
export function unpackSecret(decryptedBytes: Uint8Array): DecodedSecret {
  try {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(decryptedBytes);
    if (text.startsWith('{"__warpvault__":true')) {
      const parsed = JSON.parse(text);
      if (parsed.__warpvault__ && parsed.type === "file" && parsed.data) {
        const binaryStr = atob(parsed.data);
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
          bytes[i] = binaryStr.charCodeAt(i);
        }
        return {
          isFile: true,
          filename: parsed.filename || "secret-attachment.bin",
          data: bytes,
        };
      }
    }
  } catch {
    // Fall through if not JSON
  }

  // Check if text is clean UTF-8
  const text = new TextDecoder("utf-8", { fatal: false }).decode(decryptedBytes);
  // Simple binary heuristic: check for null bytes
  let isBinary = false;
  for (let i = 0; i < Math.min(decryptedBytes.length, 1024); i++) {
    if (decryptedBytes[i] === 0) {
      isBinary = true;
      break;
    }
  }

  if (isBinary) {
    return {
      isFile: true,
      filename: "secret.bin",
      data: decryptedBytes,
    };
  }

  return {
    isFile: false,
    text: text,
    data: decryptedBytes,
  };
}
