/**
 * decrypt-aes.js
 * Mendekripsi ciphertext AES-256-GCM.
 * Auth tag memastikan ciphertext tidak dimodifikasi (authenticated encryption).
 */

import crypto from "crypto";
import fs from "fs";

/**
 * Mendekripsi ciphertext AES-256-GCM
 * @param {string} ciphertextBase64 - Ciphertext dalam base64
 * @param {string} ivBase64 - IV dalam base64
 * @param {string} authTagBase64 - Authentication tag dalam base64
 * @param {Buffer} key - AES key (32 bytes)
 * @returns {string} Plaintext pesan asli
 */
export function decryptAES(ciphertextBase64, ivBase64, authTagBase64, key) {
  const iv = Buffer.from(ivBase64, "base64");
  const authTag = Buffer.from(authTagBase64, "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(ciphertextBase64, "base64", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

// Demo jika dijalankan langsung
if (process.argv[1].endsWith("decrypt-aes.js")) {
  console.log("=== AES-256-GCM Decryption ===\n");

  let data;
  try {
    data = JSON.parse(fs.readFileSync("aes-data.json", "utf8"));
  } catch {
    console.log("Demo file not found. Run 'node generate-aes.js' first.");
    process.exit(1);
  }

  const key = Buffer.from(data.key, "base64");

  console.log(`Ciphertext  : ${data.ciphertext}`);
  console.log(`IV          : ${data.iv}`);
  console.log(`Auth Tag    : ${data.authTag}\n`);

  // Test 1: Valid decryption
  try {
    const plaintext = decryptAES(data.ciphertext, data.iv, data.authTag, key);
    console.log("Test 1 - Decrypt with correct key:");
    console.log(`  Result    : ✓ Decrypted successfully`);
    console.log(`  Plaintext : "${plaintext}"\n`);
  } catch (e) {
    console.log(`  Error: ${e.message}\n`);
  }

  // Test 2: Wrong key
  const wrongKey = crypto.randomBytes(32);
  try {
    decryptAES(data.ciphertext, data.iv, data.authTag, wrongKey);
    console.log("Test 2 - Wrong key: SHOULD NOT SUCCEED");
  } catch {
    console.log("Test 2 - Decrypt with wrong key:");
    console.log("  Result    : ✗ Decryption failed — Auth tag mismatch!\n");
  }

  // Test 3: Tampered ciphertext
  const tamperedCipher = data.ciphertext.slice(0, -4) + "XXXX";
  try {
    decryptAES(tamperedCipher, data.iv, data.authTag, key);
    console.log("Test 3 - Tampered ciphertext: SHOULD NOT SUCCEED");
  } catch {
    console.log("Test 3 - Tampered ciphertext:");
    console.log("  Result    : ✗ Decryption failed — Ciphertext tampered!");
  }
}
