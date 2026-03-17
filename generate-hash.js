/**
 * generate-hash.js
 * Menghasilkan SHA-256 hash dari sebuah pesan.
 * Digunakan untuk memastikan integritas pesan.
 */

import crypto from "crypto";

/**
 * Menghasilkan SHA-256 hash dari pesan
 * @param {string} message - Pesan yang akan di-hash
 * @returns {string} Hash dalam format hex string
 */
export function generateHash(message) {
  return crypto.createHash("sha256").update(message).digest("hex");
}

// Demo jika dijalankan langsung
if (process.argv[1].endsWith("generate-hash.js")) {
  const testMessage = "Hello, SecureChat!";
  const hash = generateHash(testMessage);

  console.log("=== Generate Hash (SHA-256) ===");
  console.log(`Message : "${testMessage}"`);
  console.log(`Hash    : ${hash}`);
  console.log(`Length  : ${hash.length} chars (256 bits)`);
}
