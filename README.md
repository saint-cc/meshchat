# MeshChat

Decentralised, end-to-end encrypted messaging. No accounts. No central server. No plaintext.

Messages are encrypted in the browser before they leave your device. Relay servers route ciphertext — they never see your messages, your contacts, or your identity.

---

## How it works

Your identity is derived from your username and passphrase using PBKDF2 + HKDF. The same credentials always produce the same keypair. There is no registration, no server account, and no password reset — your passphrase **is** the key.

Contacts are added by exchanging a shareable address (QR code or copy-paste). This address contains your encryption public key, signing public key, and relay server URL. No other information is needed.

Messages are encrypted with AES-256-GCM for the recipient and signed with Ed25519. Relay servers see only routing metadata (sender ID, recipient ID, size) and store nothing permanently.

---

## Features

- End-to-end encrypted text, image, and audio messages
- Message signing and verification
- Cross-relay messaging — clients on different servers communicate directly
- Offline delivery — messages are buffered on the recipient's relay until they reconnect
- Peer backup — contacts automatically back up each other's encrypted data
- Multi-device sync — same identity on multiple devices converges over time
- Reactions
- QR code contact exchange
- Encrypted backup export / import
- Progressive Web App — installable, works offline for reading
- No dependencies on accounts, email, or phone numbers

---

## Running a relay server

### Requirements

- Python 3.11+
- `websockets` and `flask` packages

```bash
pip install websockets flask
```

### Configuration

Copy and edit `start.sh` (Linux/Mac) or create a `start.bat` (Windows):

```bash
export RELAY_WSS_URL="wss://yourrelay.example.com/ws/"
export HTTP_PORT=8000
export WS_PORT=8888
export BUF_DIR="./relay_buf"
export BUF_MAX_MSGS=100
export BUF_MAX_AGE=86400
export BUF_MAX_MB=10

python3 server.py
```

`RELAY_WSS_URL` is the only required setting for cross-relay messaging. It tells clients where to find this relay so they can include it in their shareable address.

### Nginx reverse proxy (recommended)

```nginx
server {
    listen 443 ssl;
    server_name yourrelay.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600;
    }
}
```

### Static files

Put the client files (`index.html`, `style.css`, `script.js`, `manifest.json`, `sw.js`) in a `static/` directory next to `server.py`. Flask serves them automatically.

---

## Security model

- **Relay operators** can see: sender publicId, recipient publicId, message timing, approximate size. They cannot see message content.
- **Contacts** can see: your publicId, your relay URL, when you send messages.
- **Passphrase security** is everything. A weak passphrase means a weak identity. The login screen shows an entropy estimate to help.
- **No forward secrecy** — keys are static. A compromised passphrase exposes all past messages if an attacker has stored ciphertext.
- **No anonymity** — IP addresses are visible to relay operators. MeshChat is not a replacement for Tor.

See [known-limitations.md](known-limitations.md) for a full list of trade-offs.

---

## Cross-relay messaging

Clients on different relay servers communicate directly:

1. Alice shares her address (QR code) which includes her relay WSS URL
2. Bob scans it — his client now knows Alice's relay
3. When Bob sends a message, his client opens a temporary WebSocket to Alice's relay and delivers it directly
4. If Alice is offline, her relay buffers the message to disk and delivers it when she reconnects
5. Alice's relay URL updates automatically as she moves between relays, propagated via message payloads

---

## Privacy tips

- Choose a unique username — common names are easier to correlate
- Use a strong passphrase — it is your only protection
- Share your QR code only with people you trust — it reveals your relay server
- There is no way to prove a new key belongs to the same person — verify out-of-band when re-adding contacts

---

## Protocol

See [protocol.md](protocol.md) for the full protocol specification including packet formats, key derivation, routing rules, and backup protocol.

---

*MeshChat v0 — experimental*