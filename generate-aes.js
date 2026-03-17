/**
 * generate-aes.js
 * Menghasilkan AES-256-GCM key dan mengenkripsi pesan.
 * AES-GCM lebih efisien dari RSA untuk pesan panjang,
 * biasanya digunakan dengan RSA sebagai hybrid encryption.
 */

import crypto from "crypto";
import fs from "fs";

const AES_KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 12;       // 96 bits (recommended for GCM)

/**
 * Menghasilkan random AES-256 key
 * @returns {Buffer} 32-byte random key
 */
export function generateAESKey() {
  return crypto.randomBytes(AES_KEY_LENGTH);
}

/**
 * Mengenkripsi pesan dengan AES-256-GCM
 * @param {string} message - Pesan plaintext
 * @param {Buffer} key - AES key (32 bytes)
 * @returns {{ iv: string, ciphertext: string, authTag: string }} - Base64 encoded
 */
export function encryptAES(message, key) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  let encrypted = cipher.update(message, "utf8", "base64");
  encrypted += cipher.final("base64");

  const authTag = cipher.getAuthTag().toString("base64");

  return {
    iv: iv.toString("base64"),
    ciphertext: encrypted,
    authTag,
  };
}

// Demo jika dijalankan langsung
if (process.argv[1].endsWith("generate-aes.js")) {
  console.log("=== AES-256-GCM Encryption ===\n");

  const key = generateAESKey();
  console.log(`AES Key (hex)  : ${key.toString("hex")}`);
  console.log(`Key Length     : ${key.length * 8} bits\n`);

  const message =
    "This is a long secret message that would be inefficient to encrypt with RSA directly.";
  console.log(`Plaintext      : "${message}"`);

  const { iv, ciphertext, authTag } = encryptAES(message, key);
  console.log(`\nIV (base64)    : ${iv}`);
  console.log(`Ciphertext     : ${ciphertext}`);
  console.log(`Auth Tag       : ${authTag}`);

  // Save for decrypt demo
  fs.writeFileSync(
    "aes-data.json",
    JSON.stringify(
      {
        key: key.toString("base64"),
        iv,
        ciphertext,
        authTag,
      },
      null,
      2
    )
  );

  console.log("\n✓ Saved to aes-data.json");
  console.log("Run 'node decrypt-aes.js' to decrypt.");
}
