/**
 * generate-signature.js
 * Menghasilkan RSA-2048 key pair dan menandatangani pesan.
 * Digunakan untuk membuktikan autentisitas pengirim (mencegah impersonasi).
 */

import crypto from "crypto";
import fs from "fs";

/**
 * Menghasilkan RSA-2048 key pair
 * @returns {{ publicKey: string, privateKey: string }} PEM-encoded keys
 */
export function generateRSAKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

/**
 * Menandatangani pesan dengan private key RSA
 * @param {string} message - Pesan yang akan ditandatangani
 * @param {string} privateKeyPem - Private key dalam format PEM
 * @returns {string} Signature dalam format base64
 */
export function signMessage(message, privateKeyPem) {
  const sign = crypto.createSign("SHA256");
  sign.update(message);
  sign.end();
  return sign.sign(privateKeyPem, "base64");
}

// Demo jika dijalankan langsung
if (process.argv[1].endsWith("generate-signature.js")) {
  console.log("=== Generate Digital Signature (RSA-2048 + SHA-256) ===\n");

  console.log("Generating RSA-2048 key pair...");
  const { publicKey, privateKey } = generateRSAKeyPair();
  console.log("✓ Key pair generated\n");

  const message = "Transfer $1000 to Bob";
  console.log(`Message   : "${message}"`);

  const signature = signMessage(message, privateKey);
  console.log(`Signature : ${signature.substring(0, 60)}...`);
  console.log(`Sig Length: ${signature.length} chars (base64)`);

  // Save keys to file for demo
  fs.writeFileSync("demo-public.pem", publicKey);
  fs.writeFileSync("demo-private.pem", privateKey);
  fs.writeFileSync("demo-signature.txt", signature);
  fs.writeFileSync("demo-message.txt", message);

  console.log("\n✓ Keys and signature saved:");
  console.log("  - demo-public.pem");
  console.log("  - demo-private.pem");
  console.log("  - demo-signature.txt");
  console.log("  - demo-message.txt");
  console.log("\nRun 'node verify-signature.js' to verify.");
}
