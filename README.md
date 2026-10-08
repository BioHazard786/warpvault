# 🔐 Warpvault

> **Zero-knowledge, client-side encrypted secret sharing for people who don't want their production database credentials floating in Slack or saved in plaintext on Big Cloud.**

Warpvault is a minimalist, self-hosted secret dropper and password vault. You paste a secret or drag & drop a private key, your browser or terminal encrypts it locally with **AES-256** before it ever touches the network, and you get a link. 

The encryption key lives exclusively in the URL hash fragment (`#<key>`). Because browsers never send `#...` fragments across HTTP requests (RFC 3986), **our server never sees your plaintext and couldn't decrypt your secret even if someone held a magnet to its disk**.

> ⚡ **Looking for file sharing instead?** If you need to share 500MB videos, logs, or screenshots without encryption, check out Warpvault's sibling: **[Warpstash](https://github.com/biohazard786/warpstash)**.

---

## 🎯 Why You'll Love It

- 💥 **Burn After Reading by Default**: Mission Impossible style. The instant someone opens and reveals the secret, it is atomically deleted from disk and database forever.
- 🤖 **Discord & Slack Bot Shield**: Preview bots from Discord, Slack, iMessage, and Twitter love to crawl links and accidentally detonate one-time secrets. We slap their hands away. Only an actual human clicking "Reveal Secret" detonates it.
- 🔑 **True Zero-Knowledge**: AES-256-CBC encryption runs client-side in RAM using native Web Crypto API (`crypto.subtle`) or Go crypto. Zero third-party npm crypto bloat.
- 💻 **Dedicated Go CLI (`warpvault`)**: Send secrets, pipe terminal outputs, or download and decrypt directly to your shell.
- 🛡️ **Zero-Install OpenSSL Piping (`curl | openssl`)**: Working on a remote server or air-gapped machine with no CLI installed? Pipe directly through standard `openssl enc` and `curl`.
- 📱 **QR Code for Mobile Handoffs**: Transfer 2FA backup codes, private keys, or passwords to your phone instantly via built-in QR codes.
- 🪶 **Stupidly Lightweight**: Runs as a single tiny binary with SQLite built right in. Takes almost zero RAM and boots in milliseconds.

---

## 🚀 CLI in 5 Seconds

Because opening a web browser to send an API token is 3 clicks too many.

### With the `warpvault` CLI

```bash
# 1. Send piped secret from terminal (defaults to Burn-After-Reading)
echo "sk_live_999888777" | warpvault send

# 2. Send a confidential file with custom 12h expiration
warpvault send -f ~/.ssh/id_rsa --expiry 12h

# 3. Add an extra passphrase (recipient must enter it to decrypt)
warpvault send -f credentials.env --password "team-passphrase"

# 4. Fetch and decrypt directly to stdout
warpvault get "https://vault.biohazard.qzz.io/v/a8X2mP9z#f8c3e210a4b7..."

# 5. Fetch and save decrypted file
warpvault get "https://vault.biohazard.qzz.io/v/m9Q2kL1x#90e4a7..." -o ./decrypted_key
```

---

### With `curl` + `openssl` *(Zero Installation Required)*

For headless servers, CI/CD runners, or systems where you cannot install the CLI:

```bash
# Upload a secret (generates key, encrypts locally, returns share link)
PASS=$(openssl rand -hex 16)
ID=$(echo "DATABASE_URL=postgres://..." | \
    openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:"$PASS" | \
    curl -s -X POST -T - "https://vault.biohazard.qzz.io/api/vault?burn=true" | jq -r .id)
echo "https://vault.biohazard.qzz.io/v/${ID}#${PASS}"

# Download & decrypt a secret
curl -s "https://vault.biohazard.qzz.io/api/vault/a8X2mP9z" | \
    openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:"f8c3e210a4b7..."
```

---

### 💡 Shell Helpers (`~/.bashrc` or `~/.zshrc`)

Drop these helpers into your `~/.bashrc` or `~/.zshrc` for instant zero-knowledge sharing:

```bash
# Send a secret (usage: vault <text-or-file> [burn|1h|12h|24h|72h])
vault() {
    local pass=$(openssl rand -hex 16)
    local expiry="${2:-burn}"
    local data="$1"
    local id
    if [ -f "$data" ]; then
        id=$(openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:"$pass" -in "$data" | \
            curl -s -X POST -T - "https://vault.biohazard.qzz.io/api/vault?time=${expiry}" | jq -r .id)
    else
        id=$(echo -n "$data" | openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:"$pass" | \
            curl -s -X POST -T - "https://vault.biohazard.qzz.io/api/vault?time=${expiry}" | jq -r .id)
    fi
    echo "https://vault.biohazard.qzz.io/v/${id}#${pass}"
}

# Download & decrypt a secret (usage: vault-get <url>)
vault-get() {
    local url="$1"
    local id=$(echo "$url" | sed -E 's|.*/v/([^#]+).*|\1|')
    local pass=$(echo "$url" | sed -E 's|.*#(.*)|\1|')
    curl -s "https://vault.biohazard.qzz.io/api/vault/${id}" | \
        openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:"$pass"
}
```

Reload your shell (`source ~/.bashrc` or `source ~/.zshrc`), and you can send & receive encrypted secrets with one word:

```bash
# Send text (burns after 1 reading)
vault "supersecretpassword"

# Send a private key with 1-hour expiry
vault ~/.ssh/id_rsa 1h

# Download and view
vault-get "https://vault.biohazard.qzz.io/v/a8X2mP9z#f8c3e210..."
```

---

## 🐳 Self-Hosting

### Option A: Prebuilt Docker Image (Quickest)

Using the included [docker-compose.prod.yml](docker-compose.prod.yml):

```bash
# 1. Download compose file
curl -O https://raw.githubusercontent.com/biohazard786/warpvault/main/docker-compose.prod.yml

# 2. Fire it up
docker compose -f docker-compose.prod.yml up -d
```

### Option B: Build with Docker Compose

Using [docker-compose.yml](docker-compose.yml):

```bash
# 1. Clone & enter
git clone https://github.com/biohazard786/warpvault.git
cd warpvault

# 2. Set your environment variables
cp .env.example .env

# 3. Build and run
docker compose up -d --build
```

### Option C: The Bare-Metal Way (Single Binary)

If you prefer standalone binaries:

```bash
# 1. Build everything (frontend bundle + static Go binaries)
make build

# 2. Run the server
./warpvault-server --port 8080 --base-url https://vault.example.com
```

---

## 🌐 Reverse Proxy Setups

Put Warpvault behind your favorite web server for automatic HTTPS and SSL certificates.

### Caddy *(Recommended)*

```caddy
vault.example.com {
    reverse_proxy localhost:8080
}
```

### Nginx

```nginx
server {
    listen 80;
    server_name vault.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name vault.example.com;

    ssl_certificate /etc/letsencrypt/live/vault.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vault.example.com/privkey.pem;

    client_max_body_size 25M;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

> **Pro-Tip**: When hosting behind Caddy or Nginx, remember to set `WARPVAULT_TRUST_PROXY=true` and `WARPVAULT_BASE_URL=https://vault.example.com` so Warpvault generates proper public HTTPS links!

---

## ⚙️ Essential Configuration

| Setting | Default | What it does |
| :--- | :--- | :--- |
| `WARPVAULT_BASE_URL` | `http://localhost:8080` | Your canonical public domain used for shareable links |
| `WARPVAULT_PORT` | `8080` | Internal port the server listens on |
| `WARPVAULT_MAX_SECRET_SIZE_MB` | `25` | Maximum single secret size in MB |
| `WARPVAULT_DEFAULT_EXPIRY` | `burn` | Default expiration if omitted (`burn`, `1h`, `12h`, `24h`, `72h`) |
| `WARPVAULT_AUTH_TOKEN` | *(none)* | Optional password required to create new vaults |
| `WARPVAULT_TRUST_PROXY` | `false` | Flip to `true` if behind Caddy, Nginx, or Cloudflare |

---

## 📜 License

[MIT](LICENSE). Self-host it, share secrets, let them burn.
