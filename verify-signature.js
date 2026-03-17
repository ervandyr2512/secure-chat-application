/**
 * verify-signature.js
 * Memverifikasi digital signature RSA dari sebuah pesan.
 * Digunakan penerima untuk memastikan pesan benar-benar dari pengirim yang diklaim.
 */

import crypto from "crypto";
import fs from "fs";

/**
 * Memverifikasi signature RSA dari sebuah pesan
 * @param {string} message - Pesan asli
 * @param {string} signatureBase64 - Signature dalam format base64
 * @param {string} publicKeyPem - Public key pengirim dalam format PEM
 * @returns {boolean} true jika signature valid
 */
export function verifySignature(message, signatureBase64, publicKeyPem) {
  try {
    const verify = crypto.createVerify("SHA256");
    verify.update(message);
    verify.end();
    return verify.verify(publicKeyPem, signatureBase64, "base64");
  } catch {
    return false;
  }
}

// Demo jika dijalankan langsung
if (process.argv[1].endsWith("verify-signature.js")) {
  console.log("=== Verify Digital Signature (RSA-2048 + SHA-256) ===\n");

  // Load demo files dari generate-signature.js
  let publicKey, signature, message;
  try {
    publicKey = fs.readFileSync("demo-public.pem", "utf8");
    signature = fs.readFileSync("demo-signature.txt", "utf8");
    message = fs.readFileSync("demo-message.txt", "utf8");
  } catch {
    console.log("Demo files not found. Run 'node generate-signature.js' first.");
    process.exit(1);
  }

  console.log(`Message   : "${message}"`);
  console.log(`Signature : ${signature.substring(0, 60)}...\n`);

  // Test 1: Valid
  const valid1 = verifySignature(message, signature, publicKey);
  console.log("Test 1 - Original message:");
  console.log(`  Result: ${valid1 ? "✓ SIGNATURE VALID" : "✗ SIGNATURE INVALID"}\n`);

  // Test 2: Tampered message
  const tamperedMsg = message + " [TAMPERED]";
  const valid2 = verifySignature(tamperedMsg, signature, publicKey);
  console.log(`Test 2 - Tampered message: "${tamperedMsg}"`);
  console.log(
    `  Result: ${valid2 ? "✓ SIGNATURE VALID" : "✗ SIGNATURE INVALID — Impersonation or tampering detected!"}`
  );

  // Test 3: Fake signature
  const fakeSignature = Buffer.from("this-is-a-fake-signature").toString("base64");
  const valid3 = verifySignature(message, fakeSignature, publicKey);
  console.log("\nTest 3 - Fake signature:");
  console.log(
    `  Result: ${valid3 ? "✓ SIGNATURE VALID" : "✗ SIGNATURE INVALID — Fake signature detected!"}`
  );
}
