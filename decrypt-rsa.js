/**
 * decrypt-rsa.js
 * Mendekripsi ciphertext RSA-OAEP menggunakan private key penerima.
 * Hanya pemilik private key yang bisa membaca pesan terenkripsi.
 */

import crypto from "crypto";
import fs from "fs";

/**
 * Mendekripsi ciphertext RSA-OAEP dengan private key
 * @param {string} ciphertextBase64 - Ciphertext dalam format base64
 * @param {string} privateKeyPem - Private key penerima dalam format PEM
 * @returns {string} Plaintext pesan asli
 */
export function decryptRSA(ciphertextBase64, privateKeyPem) {
  const buffer = Buffer.from(ciphertextBase64, "base64");
  const decrypted = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    buffer
  );
  return decrypted.toString("utf8");
}

// Demo jika dijalankan langsung
if (process.argv[1].endsWith("decrypt-rsa.js")) {
  console.log("=== RSA Decryption (RSA-OAEP) ===\n");

  let privateKey, ciphertext;
  try {
    privateKey = fs.readFileSync("rsa-private.pem", "utf8");
    ciphertext = fs.readFileSync("rsa-ciphertext.txt", "utf8");
  } catch {
    console.log("Demo files not found. Run 'node generate-rsa-encryption.js' first.");
    process.exit(1);
  }

  console.log(`Ciphertext : ${ciphertext.substring(0, 60)}...\n`);

  // Test 1: Decrypt with correct private key
  try {
    const plaintext = decryptRSA(ciphertext, privateKey);
    console.log("Test 1 - Decrypt with correct private key:");
    console.log(`  Result: ✓ Decrypted successfully`);
    console.log(`  Plaintext: "${plaintext}"\n`);
  } catch (e) {
    console.log(`  Error: ${e.message}\n`);
  }

  // Test 2: Try with wrong key
  const { generateRSAKeyPair } = await import("./generate-signature.js");
  const { privateKey: wrongKey } = generateRSAKeyPair();

  try {
    decryptRSA(ciphertext, wrongKey);
    console.log("Test 2 - Decrypt with wrong private key: SHOULD NOT SUCCEED");
  } catch {
    console.log("Test 2 - Decrypt with wrong private key:");
    console.log("  Result: ✗ Decryption failed — Wrong key cannot decrypt!");
  }
}
