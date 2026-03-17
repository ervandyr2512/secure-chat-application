# secure-chat-crypto

AFL-2 Kriptografi: hash, digital signature, encryption, secure chat app

## Struktur Proyek

```
secure-chat-crypto/
├── server.js                  # WebSocket chat server (honest)
├── client.js                  # Terminal chat client
├── malicious-server.js        # Server yang memodifikasi pesan (demo attack)
├── generate-hash.js           # SHA-256 hash generation
├── verify-hash.js             # SHA-256 hash verification
├── generate-signature.js      # RSA-2048 key pair + digital signature
├── verify-signature.js        # RSA signature verification
├── generate-rsa-encryption.js # RSA-OAEP encryption
├── decrypt-rsa.js             # RSA-OAEP decryption
├── generate-aes.js            # AES-256-GCM key generation + encryption
├── decrypt-aes.js             # AES-256-GCM decryption
├── build-report.js            # Generate AFL-2_Report.md
├── AFL-2_Report.md            # Laporan hasil (generated)
├── package.json
└── README.md
```

## Prerequisites

```bash
node --version   # >= 18.0.0
npm install
```

## Quick Start

```bash
# Terminal 1: Server
node server.js

# Terminal 2: Alice
node client.js Alice ws://localhost:8765

# Terminal 3: Bob
node client.js Bob ws://localhost:8765
```

## Demo Chat Commands

```
<message>           Kirim ke semua (+ hash + signature)
/msg Bob hello      Private message ke Bob
/enc Bob secret     Pesan dienkripsi untuk Bob (hybrid RSA+AES)
/users              Lihat user online
/help               Bantuan
/quit               Keluar
```

## Demo Serangan

### 1. Malicious Server (Hash Attack)
```bash
# Terminal 1: Malicious server
node malicious-server.js

# Terminal 2: Alice
node client.js Alice ws://localhost:8766

# Terminal 3: Bob  
node client.js Bob ws://localhost:8766
```
Alice kirim pesan → server memodifikasi → Bob lihat **[HASH✗ TAMPERED!]**

Kirim pesan terenkripsi `/enc Bob secret msg` → server tidak bisa memodifikasi ciphertext.

### 2. Impersonasi (Signature Attack)
Jika seseorang mencoba mengirim pesan dengan mengklaim sebagai "Alice" tapi tanpa private key Alice → client akan tampilkan **[SIG✗ INVALID!]**.

## Modul Individual

```bash
node generate-hash.js           # Demo SHA-256
node verify-hash.js             # Demo verifikasi + tampering detection
node generate-signature.js      # Demo generate RSA key + sign
node verify-signature.js        # Demo verifikasi signature
node generate-rsa-encryption.js # Demo RSA-OAEP encrypt
node decrypt-rsa.js             # Demo RSA-OAEP decrypt
node generate-aes.js            # Demo AES-256-GCM encrypt
node decrypt-aes.js             # Demo AES-256-GCM decrypt
node build-report.js            # Generate laporan AFL-2
```

## Keamanan

| Fitur | Algoritma | Tujuan |
|---|---|---|
| Hash | SHA-256 | Integritas pesan |
| Digital Signature | RSA-2048 + SHA-256 | Autentisitas, anti-impersonasi |
| Encryption (pesan pendek) | RSA-OAEP | Kerahasiaan |
| Encryption (pesan panjang) | AES-256-GCM | Kerahasiaan efisien |
| Hybrid | RSA + AES | Kerahasiaan optimal |
