# Warpvault protocol v1

The server stores opaque blobs and never sees a key. The browser (`web/src/lib/vault.ts`) and the CLI
(`cli/internal/vault`) implement this document and must both reproduce `fixtures/vectors.json`
byte for byte (regenerate with `bun scripts/gen-fixtures.mjs` from `web/`).

## 1. Share link

`https://<host>/v/<id>#<k>`

`k` is 32 random bytes, base64url without padding (43 characters). It lives in the URL fragment, which
browsers never send to the server. `id` is a 10-character server-chosen identifier.

## 2. Blob (what the server stores)

```
offset  size  field
0       1     version = 0x01
1       1     flags: bit 0 = a passphrase is required (other bits must be 0)
2       16    salt (random)
18      12    nonce (random)
30      N+16  AES-256-GCM ciphertext || 16-byte tag
```

The 30 header bytes are the GCM additional authenticated data, so tampering with the version, flags,
salt or nonce fails decryption. The server rejects uploads whose version byte is not `0x01`, whose
flags use unknown bits, or that are shorter than 46 bytes. That is only a guard against uploading
plaintext by mistake; it cannot verify the encryption.

## 3. Key derivation

Without a passphrase:

```
key = HKDF-SHA256(ikm = k, salt = salt, info = "warpvault/1", length = 32)
```

With a passphrase (the link still carries `k`, so a leaked link alone can't open the secret and the
passphrase can't be brute-forced offline without `k`):

```
pk  = PBKDF2-HMAC-SHA256(password = UTF-8(passphrase), salt = salt, iterations = 600000, length = 32)
key = HKDF-SHA256(ikm = k || pk, salt = salt, info = "warpvault/1/pass", length = 32)
```

## 4. Plaintext

```
kind(1)  0 = text, 1 = file
nameLen(2, big endian)  length of name in bytes; 0 for text
name(nameLen)  UTF-8 file name, no path separators
data(...)  the secret's bytes
```

Raw bytes are used for files (no base64), so the full size limit is available for file content
minus a few dozen bytes of overhead.

## 5. HTTP API

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/vault?expiry=burn\|1h\|…` | body = blob. `X-Auth-Token` when the server requires one. 201 `{id,url,delete_url,delete_token,size_bytes,created_at,expires_at,burn}` |
| `GET` | `/api/vault/{id}` | metadata `{id,size_bytes,burn,passphrase,expires_at}` (`passphrase` is the blob's flag bit, so a viewer can ask for it before opening). Never burns. 404 unknown/expired, 410 burned/destroyed |
| `POST` | `/api/vault/{id}/open` | returns the blob; burns it when it is a burn-after-reading secret. POST so link previewers can't burn it |
| `DELETE` | `/api/vault/{id}` | `X-Delete-Token` header |
| `POST` | `/api/destroy/{token}` | used by the `/d/{token}` confirmation page |
| `GET` | `/api/info` | limits and allowed expiries |
| `GET` | `/healthz` | liveness + database check |

## 6. Fixtures

`fixtures/vectors.json` holds fixed `k`, salt, nonce, passphrase and plaintext for five cases, with
the expected `derivedKey` and `blob`. Implementations must (a) produce `blob` exactly when given the
fixed salt and nonce, and (b) decrypt it back to the plaintext. They must also reject a blob with any
flipped byte and a wrong passphrase.

## 7. Threat model

- **Stored data**: the server holds only blobs. Without `k` (never sent to it) they can't be decrypted,
  and GCM authentication means it can't alter one undetected either.
- **Passphrase**: a secret with a passphrase needs both `k` and the passphrase. PBKDF2 (600 000
  rounds) slows guessing, but a weak passphrase is still weak once someone has `k`.
- **What the server does see**: ciphertext size, timing, the uploader's IP and whether a passphrase is
  set (the flag bit is public so a viewer can ask for it before a burn-after-reading secret is opened).
- **Web delivery**: in a browser, the server also delivers the JavaScript that does the decrypting, so a
  compromised or malicious server could ship a page that leaks the key from the URL. This is inherent to
  any web app. The CLI and the open protocol let you avoid trusting the delivered page.
- **Links**: anyone who sees the full link (including `#k`) can open the secret, once for burn secrets.
  Send the passphrase over a different channel than the link.
