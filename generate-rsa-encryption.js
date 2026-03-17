/**
 * generate-rsa-encryption.js
 * Mengenkripsi pesan menggunakan RSA-OAEP dengan public key penerima.
 * Hanya penerima yang memiliki private key yang bisa mendekripsi.
 */

import crypto from "crypto";
import fs from "fs";
import { generateRSAKeyPair } from "./generate-signature.js";

/**
 * Mengenkripsi pesan dengan RSA-OAEP menggunakan public key
 * @param {string} message - Pesan plaintext (max ~245 bytes untuk RSA-2048)
 * @param {string} publicKeyPem - Public key penerima dalam format PEM
 * @returns {string} Ciphertext dalam format base64
 */
export function encryptRSA(message, publicKeyPem) {
  const buffer = Buffer.from(message, "utf8");
  const encrypted = crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    buffer
  );
  return encrypted.toString("base64");
}

// Demo jika dijalankan langsung
if (process.argv[1].endsWith("generate-rsa-encryption.js")) {
  console.log("=== RSA Encryption (RSA-OAEP + SHA-256) ===\n");

  // Generate fresh key pair for Bob (the recipient)
  console.log("Generating RSA-2048 key pair for Bob (recipient)...");
  const { publicKey, privateKey } = generateRSAKeyPair();
  console.log("✓ Bob's key pair generated\n");

  const message = "Secret message: meet at 9pm at the park.";
  console.log(`Plaintext : "${message}"`);

  const ciphertext = encryptRSA(message, publicKey);
  console.log(`Encrypted : ${ciphertext.substring(0, 60)}...`);
  console.log(`Ciphertext length: ${ciphertext.length} chars\n`);

  // Save for decrypt demo
  fs.writeFileSync("rsa-public.pem", publicKey);
  fs.writeFileSync("rsa-private.pem", privateKey);
  fs.writeFileSync("rsa-ciphertext.txt", ciphertext);

  console.log("✓ Files saved:");
  console.log("  - rsa-public.pem  (Bob's public key)");
  console.log("  - rsa-private.pem (Bob's private key)");
  console.log("  - rsa-ciphertext.txt");
  console.log("\nRun 'node decrypt-rsa.js' to decrypt.");
}
