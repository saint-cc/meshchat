````markdown
# MeshChat

Decentralised, end-to-end encrypted messaging built around cryptographic identities rather than accounts.

No registration. No central identity provider. No plaintext.

Messages are encrypted in the browser before they leave your device. Relay servers transport and 
temporarily buffer ciphertext, but never possess your private keys or message contents.

---

## How it works

Your identity is derived locally from your username and passphrase using PBKDF2 + HKDF. The same 
credentials always produce the same cryptographic identity.

There are no accounts to create and no passwords stored on any server. Your passphrase **is** your identity.

Contacts are added by exchanging a shareable address (QR code or copy-paste). This contains your encryption 
public key, signing public key and current relay address. No registration or central directory is required.

Messages are encrypted with AES-256-GCM for the recipient and signed with Ed25519 before leaving your device.

---

## Features

- End-to-end encrypted text, image and audio messages
- Message signing and verification
- No accounts, email addresses or phone numbers
- Roaming identities — move freely between relay servers
- No central directory or identity provider
- Direct client-to-relay delivery across different relays
- Offline delivery through temporary encrypted relay buffers
- Multi-device synchronization
- Peer backup of encrypted data
- QR code contact exchange
- Encrypted backup export / import
- Progressive Web App (PWA)
- Installable and offline-capable for reading conversations

---

## Running a relay server

### Requirements

- Python 3.11+
- `websockets`
- `flask`
- `cryptograpy`

```bash
pip install websockets flask cryptography
```

### Configuration

Example:

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

`RELAY_WSS_URL` is the relay address clients distribute when sharing their identity.

### Nginx reverse proxy

```nginx
server {
    listen 443 ssl;
    server_name yourrelay.example.com;

    ssl_certificate     /etc/letsencrypt/live/yourrelay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourrelay.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;


    ## General protection

    client_max_body_size 5m;

    client_header_timeout 10s;
    client_body_timeout   10s;
    send_timeout          30s;

    keepalive_timeout     30s;

    limit_conn conn_limit 20;

    ## Security headers

    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;

    ## Logging

    access_log /var/log/nginx/meshchat_access.log;
    error_log  /var/log/nginx/meshchat_error.log;


    location / {

        limit_req zone=req_limit burst=20 nodelay;

        proxy_pass http://127.0.0.1:8000;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /ws/ {
        limit_req zone=req_limit burst=10 nodelay;
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

### Static files

The client files (`index.html`, `style.css`, `script.js`, `manifest.json`, `sw.js`) are inside a `static/` 
directory next to `server.py`.

---

## Relay authentication

When a client connects, the relay authenticates the session by verifying ownership of the presented public 
key through 
a challenge-response exchange.

This allows the relay to associate active connections and offline message buffers with authenticated 
identities without ever learning private keys or passphrases.

Relay authentication protects against identity spoofing while preserving end-to-end encryption.

---

## Design philosophy

MeshChat separates **transport** from **trust**.

Relay servers are intentionally simple transport nodes. They forward ciphertext, temporarily buffer encrypted 
messages for offline users, and authenticate ownership of public identities during connection.

Trust resides entirely in cryptographic identities generated locally by each client.

There is no global directory, no relay-to-relay communication and no central authority coordinating the network. 
Contacts learn each other's current relay location directly, allowing identities to migrate between relays 
while remaining reachable.

---

## Security model

### Relay operators can see

* sender public ID
* recipient public ID
* message timing
* approximate message size
* relay currently used by connected clients

### Relay operators cannot see

* plaintext messages
* attachments
* private keys
* passphrases
* contact names
* encrypted backups

### Important limitations

* Passphrase security is everything.
* Static identities mean there is currently **no forward secrecy**.
* Relay operators can observe IP addresses.
* MeshChat is **not** an anonymity network and is not a replacement for Tor.

See `known-limitations.md` for a complete discussion.

---

## Routing

Messages are delivered directly to the recipient's current relay.

1. Alice shares her MeshChat address.
2. Bob stores Alice's current relay information.
3. Bob's client opens a temporary connection directly to Alice's relay.
4. Alice's relay immediately delivers the message if she is connected.
5. Otherwise the encrypted message is buffered until Alice reconnects.
6. When Alice migrates to another relay, her contacts automatically learn her new location through normal protocol traffic.

Relay servers never communicate with one another.

---

## Privacy tips

* Choose a unique username.
* Use a strong passphrase.
* Verify contacts out-of-band when first exchanging identities.
* Treat your passphrase as your private key.
* Share your MeshChat address only with people you trust.

---

## Protocol

See `protocol.md` for the complete protocol specification, packet formats, routing rules, synchronization protocol and backup protocol.

---

## Status

MeshChat is an experimental research project exploring decentralised, roaming, end-to-end encrypted messaging.

The protocol is still evolving and should not yet be considered stable.

```
```
