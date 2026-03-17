/**
 * client.js
 * Terminal-based SecureChat client.
 * Mengimplementasikan: SHA-256 hash, RSA digital signature, RSA/AES encryption.
 *
 * Usage: node client.js [username] [ws://server:port]
 * Example:
 *   node client.js Alice ws://localhost:8765
 *   node client.js Bob   ws://localhost:8765
 */

import WebSocket from "ws";
import readline from "readline";
import crypto from "crypto";
import { generateHash } from "./generate-hash.js";
import { verifyHash } from "./verify-hash.js";
import { generateRSAKeyPair, signMessage } from "./generate-signature.js";
import { verifySignature } from "./verify-signature.js";
import { encryptRSA } from "./generate-rsa-encryption.js";
import { decryptRSA } from "./decrypt-rsa.js";
import { generateAESKey, encryptAES } from "./generate-aes.js";
import { decryptAES } from "./decrypt-aes.js";

// ─── CONFIG ─────────────────────────────────────────────────────────────────
const username = process.argv[2] || "User" + Math.floor(Math.random() * 1000);
const serverUrl = process.argv[3] || "ws://localhost:8765";

// ─── KEY MANAGEMENT ──────────────────────────────────────────────────────────
console.log(`\n[*] Generating RSA-2048 key pair for ${username}...`);
const { publicKey: myPublicKey, privateKey: myPrivateKey } = generateRSAKeyPair();
console.log(`[✓] Keys ready.\n`);

// Known peers' public keys: username -> PEM string
const peerKeys = new Map();

// ─── WEBSOCKET ───────────────────────────────────────────────────────────────
const ws = new WebSocket(serverUrl);

ws.on("open", () => {
  ws.send(
    JSON.stringify({
      type: "join",
      username,
      publicKey: myPublicKey,
    })
  );
  console.log(`[✓] Connected to ${serverUrl} as "${username}"`);
  printHelp();
  promptUser();
});

ws.on("message", async (raw) => {
  let data;
  try {
    data = JSON.parse(raw.toString());
  } catch {
    return;
  }

  process.stdout.clearLine(0);
  process.stdout.cursorTo(0);

  switch (data.type) {
    case "welcome":
      console.log(`[Server] Online users: ${data.users.join(", ") || "(none)"}`);
      break;

    case "user_joined":
      peerKeys.set(data.username, data.publicKey);
      console.log(`[+] ${data.username} joined | Online: ${data.users.join(", ")}`);
      break;

    case "user_left":
      peerKeys.delete(data.username);
      console.log(`[-] ${data.username} left`);
      break;

    case "public_key":
      peerKeys.set(data.username, data.publicKey);
      break;

    case "chat":
      await handleIncomingChat(data);
      break;
  }

  promptUser();
});

ws.on("close", () => {
  console.log("\n[!] Disconnected from server.");
  process.exit(0);
});

ws.on("error", (err) => {
  console.error(`[!] Connection error: ${err.message}`);
  process.exit(1);
});

// ─── INCOMING MESSAGE HANDLER ────────────────────────────────────────────────
async function handleIncomingChat(data) {
  const { from, content, hash, signature, publicKey, encrypted, recipient } = data;

  let displayContent = content;
  let decrypted = false;
  let decryptError = null;

  // 1. Decrypt if encrypted and addressed to me
  if (encrypted) {
    try {
      if (data.encryptedAESKey) {
        // Hybrid: decrypt AES key with RSA, then decrypt content with AES
        const aesKeyB64 = decryptRSA(data.encryptedAESKey, myPrivateKey);
        const aesKey = Buffer.from(aesKeyB64, "base64");
        displayContent = decryptAES(content, data.iv, data.authTag, aesKey);
      } else {
        // Pure RSA
        displayContent = decryptRSA(content, myPrivateKey);
      }
      decrypted = true;
    } catch {
      displayContent = "[🔒 Encrypted — not intended for you or decryption failed]";
      decryptError = true;
    }
  }

  // 2. Verify hash integrity (use decrypted content if applicable)
  const contentToVerify = decrypted ? displayContent : content;
  const { valid: hashValid } = verifyHash(contentToVerify, hash);

  // 3. Verify digital signature
  let sigValid = false;
  const senderKey = publicKey || peerKeys.get(from);
  if (signature && senderKey) {
    sigValid = verifySignature(contentToVerify, signature, senderKey);
    peerKeys.set(from, senderKey); // cache key
  }

  // ─── DISPLAY ────────────────────────────────────────────────────────────
  const time = new Date(data.timestamp).toLocaleTimeString();
  const pm = recipient ? ` [PM]` : "";
  const encTag = encrypted ? (decrypted ? " [ENC✓]" : " [ENC🔒]") : "";
  const hashTag = hashValid ? " [HASH✓]" : " [HASH✗ TAMPERED!]";
  const sigTag = signature ? (sigValid ? " [SIG✓]" : " [SIG✗ INVALID!]") : " [NO SIG]";

  const prefix = from === username ? "→ You" : `← ${from}`;
  console.log(`\n${time} ${prefix}${pm}${encTag}${hashTag}${sigTag}`);
  console.log(`   ${displayContent}`);

  if (!hashValid) {
    console.log("   ⚠ WARNING: Message hash mismatch! Server may have tampered with this message.");
  }
  if (signature && !sigValid) {
    console.log("   ⚠ WARNING: Signature invalid! Possible impersonation or tampering.");
  }
}

// ─── READLINE ────────────────────────────────────────────────────────────────
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function promptUser() {
  rl.question("> ", handleInput);
}

async function handleInput(input) {
  input = input.trim();
  if (!input) { promptUser(); return; }

  // Commands
  if (input === "/help") { printHelp(); promptUser(); return; }
  if (input === "/users") {
    console.log(`[Keys] Known peers: ${[...peerKeys.keys()].join(", ") || "(none)"}`);
    promptUser(); return;
  }
  if (input === "/quit") { ws.close(); return; }

  // Parse: /msg <user> <message>  OR  /enc <user> <message>  OR plain message
  let recipient = null;
  let plaintext = input;
  let useEncryption = false;

  if (input.startsWith("/msg ")) {
    const parts = input.slice(5).split(" ");
    recipient = parts[0];
    plaintext = parts.slice(1).join(" ");
  } else if (input.startsWith("/enc ")) {
    const parts = input.slice(5).split(" ");
    recipient = parts[0];
    plaintext = parts.slice(1).join(" ");
    useEncryption = true;
  }

  if (!plaintext) { promptUser(); return; }

  let content = plaintext;
  let encrypted = false;
  let encryptedAESKey = null;
  let iv = null;
  let authTag = null;

  // Encrypt if requested
  if (useEncryption && recipient) {
    const recipientKey = peerKeys.get(recipient);
    if (!recipientKey) {
      console.log(`[!] No public key for ${recipient}. Cannot encrypt.`);
      promptUser(); return;
    }

    // Hybrid encryption: random AES key for content, RSA for AES key
    const aesKey = generateAESKey();
    const aesResult = encryptAES(plaintext, aesKey);
    content = aesResult.ciphertext;
    iv = aesResult.iv;
    authTag = aesResult.authTag;

    // Encrypt the AES key with recipient's RSA public key
    encryptedAESKey = encryptRSA(aesKey.toString("base64"), recipientKey);
    encrypted = true;
  }

  // Sign
  const contentToSign = content;
  const signature = signMessage(contentToSign, myPrivateKey);

  // Hash
  const hash = generateHash(content);

  // Send
  ws.send(
    JSON.stringify({
      type: "chat",
      from: username,
      content,
      hash,
      signature,
      publicKey: myPublicKey,
      encrypted,
      encryptedAESKey,
      iv,
      authTag,
      recipient,
      timestamp: new Date().toISOString(),
    })
  );

  promptUser();
}

function printHelp() {
  console.log(`
Commands:
  <message>              Broadcast to all (signed + hashed)
  /msg <user> <msg>      Private message (signed + hashed)
  /enc <user> <msg>      Private encrypted message (hybrid RSA+AES)
  /users                 Show known users and keys
  /help                  Show this help
  /quit                  Disconnect
`);
}
