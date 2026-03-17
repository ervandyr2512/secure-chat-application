/**
 * verify-hash.js
 * Memverifikasi SHA-256 hash dari sebuah pesan.
 * Digunakan oleh penerima untuk mendeteksi tampering.
 */

import { generateHash } from "./generate-hash.js";

/**
 * Memverifikasi apakah hash cocok dengan pesan
 * @param {string} message - Pesan yang akan diverifikasi
 * @param {string} receivedHash - Hash yang diterima dari pengirim
 * @returns {{ valid: boolean, computedHash: string, receivedHash: string }}
 */
export function verifyHash(message, receivedHash) {
  const computedHash = generateHash(message);
  const valid = computedHash === receivedHash;
  return { valid, computedHash, receivedHash };
}

// Demo jika dijalankan langsung
if (process.argv[1].endsWith("verify-hash.js")) {
  const { generateHash } = await import("./generate-hash.js");

  const message = "Hello, SecureChat!";
  const correctHash = generateHash(message);
  const tamperedMessage = "Hello, SecureChat! [TAMPERED]";

  console.log("=== Verify Hash (SHA-256) ===\n");

  // Test 1: Valid hash
  const result1 = verifyHash(message, correctHash);
  console.log("Test 1 - Original message vs correct hash:");
  console.log(`  Message       : "${message}"`);
  console.log(`  Received Hash : ${result1.receivedHash}`);
  console.log(`  Computed Hash : ${result1.computedHash}`);
  console.log(`  Valid         : ${result1.valid ? "✓ VALID" : "✗ INVALID"}\n`);

  // Test 2: Tampered message
  const result2 = verifyHash(tamperedMessage, correctHash);
  console.log("Test 2 - Tampered message vs original hash:");
  console.log(`  Message       : "${tamperedMessage}"`);
  console.log(`  Received Hash : ${result2.receivedHash}`);
  console.log(`  Computed Hash : ${result2.computedHash}`);
  console.log(`  Valid         : ${result2.valid ? "✓ VALID" : "✗ INVALID — Tampering detected!"}`);
}
