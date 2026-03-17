/**
 * build-report.js
 * Menjalankan semua modul kriptografi dan menghasilkan laporan AFL-2.
 * Usage: node build-report.js
 */

import crypto from "crypto";
import fs from "fs";
import { generateHash } from "./generate-hash.js";
import { verifyHash } from "./verify-hash.js";
import { generateRSAKeyPair, signMessage } from "./generate-signature.js";
import { verifySignature } from "./verify-signature.js";
import { encryptRSA } from "./generate-rsa-encryption.js";
import { decryptRSA } from "./decrypt-rsa.js";
import { generateAESKey, encryptAES } from "./generate-aes.js";
import { decryptAES } from "./decrypt-aes.js";

console.log("Building AFL-2 Cryptography Report...\n");

const report = [];
const time = new Date().toISOString();

// ─── 1. HASH ─────────────────────────────────────────────────────────────────
const hashMsg = "Hello, SecureChat!";
const hash = generateHash(hashMsg);
const { valid: hashValid } = verifyHash(hashMsg, hash);
const { valid: hashTampered } = verifyHash(hashMsg + " TAMPERED", hash);

report.push({
  section: "1. Hash (SHA-256)",
  message: hashMsg,
  hash,
  verifyOriginal: hashValid,
  verifyTampered: hashTampered,
});

// ─── 2. DIGITAL SIGNATURE ────────────────────────────────────────────────────
const { publicKey, privateKey } = generateRSAKeyPair();
const sigMsg = "Transfer $500 to Bob";
const signature = signMessage(sigMsg, privateKey);
const sigValid = verifySignature(sigMsg, signature, publicKey);
const sigTampered = verifySignature(sigMsg + " TAMPERED", signature, publicKey);
const sigFake = verifySignature(sigMsg, Buffer.from("fakesig").toString("base64"), publicKey);

report.push({
  section: "2. Digital Signature (RSA-2048 + SHA-256)",
  message: sigMsg,
  signaturePreview: signature.substring(0, 60) + "...",
  verifyOriginal: sigValid,
  verifyTampered: sigTampered,
  verifyFake: sigFake,
});

// ─── 3. RSA ENCRYPTION ───────────────────────────────────────────────────────
const { publicKey: encPub, privateKey: encPriv } = generateRSAKeyPair();
const encMsg = "Secret: meet at 9pm at the park.";
const cipherRSA = encryptRSA(encMsg, encPub);
const decryptedRSA = decryptRSA(cipherRSA, encPriv);

report.push({
  section: "3. RSA Encryption (RSA-OAEP + SHA-256)",
  original: encMsg,
  cipherPreview: cipherRSA.substring(0, 60) + "...",
  decrypted: decryptedRSA,
  match: encMsg === decryptedRSA,
});

// ─── 4. AES ENCRYPTION ───────────────────────────────────────────────────────
const aesKey = generateAESKey();
const aesMsg = "This is a long message suitable for AES-256-GCM symmetric encryption.";
const { iv, ciphertext, authTag } = encryptAES(aesMsg, aesKey);
const decryptedAES = decryptAES(ciphertext, iv, authTag, aesKey);

report.push({
  section: "4. AES-256-GCM Encryption",
  original: aesMsg,
  cipherPreview: ciphertext.substring(0, 60) + "...",
  iv,
  authTag,
  decrypted: decryptedAES,
  match: aesMsg === decryptedAES,
});

// ─── 5. HYBRID ENCRYPTION ────────────────────────────────────────────────────
const hybridMsg = "Hybrid encryption demo: RSA encrypts AES key, AES encrypts the message.";
const sessionKey = generateAESKey();
const { iv: hIv, ciphertext: hCipher, authTag: hTag } = encryptAES(hybridMsg, sessionKey);
const encryptedKey = encryptRSA(sessionKey.toString("base64"), encPub);
const decryptedKeyB64 = decryptRSA(encryptedKey, encPriv);
const decryptedHybrid = decryptAES(hCipher, hIv, hTag, Buffer.from(decryptedKeyB64, "base64"));

report.push({
  section: "5. Hybrid Encryption (RSA + AES)",
  original: hybridMsg,
  decrypted: decryptedHybrid,
  match: hybridMsg === decryptedHybrid,
});

// ─── PRINT REPORT ────────────────────────────────────────────────────────────
console.log("╔══════════════════════════════════════════════════════╗");
console.log("║         AFL-2 Cryptography Report                   ║");
console.log(`║         Generated: ${time.substring(0,10)}                    ║`);
console.log("╚══════════════════════════════════════════════════════╝\n");

for (const r of report) {
  console.log(`── ${r.section} ──`);
  Object.entries(r).forEach(([k, v]) => {
    if (k === "section") return;
    const label = k.padEnd(20);
    const display =
      typeof v === "boolean"
        ? v
          ? "✓ PASS"
          : "✗ FAIL"
        : String(v);
    console.log(`   ${label}: ${display}`);
  });
  console.log();
}

// ─── WRITE AFL-2_Report.md ───────────────────────────────────────────────────
const md = `# AFL-2 Kriptografi Report
*Generated: ${time}*

## 1. Hash (SHA-256)

| Field | Value |
|---|---|
| Message | \`${hashMsg}\` |
| SHA-256 Hash | \`${hash}\` |
| Verify Original | ${hashValid ? "✓ VALID" : "✗ INVALID"} |
| Verify Tampered | ${hashTampered ? "✓ VALID" : "✗ INVALID — Tampering detected"} |

**Kesimpulan**: SHA-256 hash mendeteksi setiap perubahan pada pesan. Jika server memodifikasi pesan, hash tidak akan cocok.

---

## 2. Digital Signature (RSA-2048 + SHA-256)

| Field | Value |
|---|---|
| Message | \`${sigMsg}\` |
| Signature (preview) | \`${signature.substring(0, 40)}...\` |
| Verify Original | ${sigValid ? "✓ VALID" : "✗ INVALID"} |
| Verify Tampered Msg | ${sigTampered ? "✓ VALID" : "✗ INVALID — Impersonation/tampering detected"} |
| Verify Fake Sig | ${sigFake ? "✓ VALID" : "✗ INVALID — Fake signature rejected"} |

**Kesimpulan**: Hanya pemilik private key yang bisa menghasilkan signature yang valid. Impersonasi terdeteksi.

---

## 3. RSA Encryption (RSA-OAEP)

| Field | Value |
|---|---|
| Plaintext | \`${encMsg}\` |
| Ciphertext (preview) | \`${cipherRSA.substring(0, 40)}...\` |
| Decrypted | \`${decryptedRSA}\` |
| Match | ${encMsg === decryptedRSA ? "✓ MATCH" : "✗ MISMATCH"} |

**Kesimpulan**: Hanya pemilik private key yang bisa mendekripsi. Server tidak bisa membaca pesan terenkripsi.

---

## 4. AES-256-GCM Encryption

| Field | Value |
|---|---|
| Plaintext | \`${aesMsg.substring(0, 50)}...\` |
| Ciphertext (preview) | \`${ciphertext.substring(0, 40)}...\` |
| IV | \`${iv}\` |
| Auth Tag | \`${authTag}\` |
| Decrypted | \`${decryptedAES.substring(0, 50)}...\` |
| Match | ${aesMsg === decryptedAES ? "✓ MATCH" : "✗ MISMATCH"} |

**Kesimpulan**: AES-256-GCM lebih efisien dari RSA untuk pesan panjang. Auth tag mendeteksi tampering pada ciphertext.

---

## 5. Hybrid Encryption (RSA + AES)

| Field | Value |
|---|---|
| Plaintext | \`${hybridMsg.substring(0, 50)}...\` |
| Decrypted | \`${decryptedHybrid.substring(0, 50)}...\` |
| Match | ${hybridMsg === decryptedHybrid ? "✓ MATCH" : "✗ MISMATCH"} |

**Kesimpulan**: RSA mengenkripsi AES session key, AES mengenkripsi pesan. Menggabungkan keamanan RSA dengan efisiensi AES.

---

## Cara Menjalankan

\`\`\`bash
# Install dependencies
npm install

# Jalankan server normal
node server.js

# Jalankan client (terminal lain)
node client.js Alice ws://localhost:8765
node client.js Bob   ws://localhost:8765

# Demo malicious server (port 8766)
node malicious-server.js

# Demo modul individual
node generate-hash.js
node verify-hash.js
node generate-signature.js
node verify-signature.js
node generate-rsa-encryption.js
node decrypt-rsa.js
node generate-aes.js
node decrypt-aes.js
\`\`\`
`;

fs.writeFileSync("AFL-2_Report.md", md);
console.log("✓ AFL-2_Report.md generated.");
