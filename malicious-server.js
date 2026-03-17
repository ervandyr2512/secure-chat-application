/**
 * malicious-server.js
 * Server jahat yang mencoba memodifikasi isi pesan.
 * Mendemonstrasikan: client dapat mendeteksi tampering melalui hash & signature.
 *
 * Percobaan serangan:
 * 1. Memodifikasi teks pesan (client deteksi via HASH FAIL)
 * 2. Pesan terenkripsi tidak bisa dimodifikasi (content = ciphertext)
 *
 * Usage: node malicious-server.js
 */

import { WebSocketServer } from "ws";
import { generateHash } from "./generate-hash.js";

const PORT = 8766;
const wss = new WebSocketServer({ port: PORT });

const clients = new Map();

// Kata-kata yang akan diganti server jahat
const REPLACEMENTS = {
  buy: "SELL",
  yes: "NO",
  good: "BAD",
  safe: "DANGEROUS",
  trust: "DISTRUST",
  send: "BLOCK",
  agree: "DISAGREE",
};

/**
 * Memodifikasi pesan secara diam-diam
 * @param {string} content
 * @returns {{ tampered: string, wasTampered: boolean }}
 */
function tamperMessage(content) {
  let tampered = content;
  let wasTampered = false;

  for (const [original, replacement] of Object.entries(REPLACEMENTS)) {
    const regex = new RegExp(`\\b${original}\\b`, "gi");
    if (regex.test(tampered)) {
      tampered = tampered.replace(regex, replacement);
      wasTampered = true;
    }
  }

  // Jika tidak ada kata yang cocok, tambahkan suffix
  if (!wasTampered && content.length > 5) {
    tampered = content + " [SERVER MODIFIED]";
    wasTampered = true;
  }

  return { tampered, wasTampered };
}

function sendTo(ws, data) {
  if (ws.readyState === 1) ws.send(JSON.stringify(data));
}

function broadcast(data, excludeWs = null) {
  for (const [, ws] of clients) {
    if (ws !== excludeWs) sendTo(ws, data);
  }
}

wss.on("connection", (ws) => {
  let username = null;

  ws.on("message", (raw) => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }

    switch (data.type) {
      case "join": {
        username = data.username;
        clients.set(username, ws);

        sendTo(ws, {
          type: "welcome",
          users: [...clients.keys()].filter((u) => u !== username),
          timestamp: new Date().toISOString(),
        });

        broadcast(
          {
            type: "user_joined",
            username,
            publicKey: data.publicKey || null,
            users: [...clients.keys()],
            timestamp: new Date().toISOString(),
          },
          ws
        );

        console.log(`[EVIL+] ${username} joined (doesn't know this server is malicious!)`);
        break;
      }

      case "chat": {
        const originalContent = data.content || "";
        let finalContent = originalContent;
        let wasTampered = false;

        if (!data.encrypted) {
          // Server bisa baca & modifikasi plaintext
          const result = tamperMessage(originalContent);
          finalContent = result.tampered;
          wasTampered = result.wasTampered;

          if (wasTampered) {
            console.log(`[EVIL✗] TAMPERED message from ${username}!`);
            console.log(`  Original : "${originalContent}"`);
            console.log(`  Modified : "${finalContent}"`);
            console.log(`  NOTE: Client will detect via HASH FAIL!`);
          }
        } else {
          // Pesan terenkripsi — server tidak bisa baca isinya
          console.log(`[EVIL✗] ENCRYPTED message from ${username} — cannot tamper!`);
          console.log(`  Ciphertext passed through unchanged.`);
        }

        // KRITIS: Server mengirim konten yang DIMODIFIKASI
        // tapi hash & signature tetap dari aslinya → client mendeteksi!
        const packet = {
          type: "chat",
          from: data.from || username,
          content: finalContent,           // ← DIMODIFIKASI!
          hash: data.hash,                 // ← hash asli, tidak cocok dengan konten baru
          signature: data.signature,       // ← signature asli, tidak cocok dengan konten baru
          publicKey: data.publicKey,
          encrypted: data.encrypted || false,
          encryptedAESKey: data.encryptedAESKey || null,
          iv: data.iv || null,
          authTag: data.authTag || null,
          recipient: data.recipient || null,
          timestamp: new Date().toISOString(),
          _serverNote: wasTampered ? "TAMPERED_BY_MALICIOUS_SERVER" : "original",
        };

        if (data.recipient) {
          const recipientWs = clients.get(data.recipient);
          if (recipientWs) sendTo(recipientWs, packet);
          sendTo(ws, packet);
        } else {
          broadcast(packet);
        }
        break;
      }

      case "public_key": {
        broadcast(
          {
            type: "public_key",
            username,
            publicKey: data.publicKey,
            timestamp: new Date().toISOString(),
          },
          ws
        );
        break;
      }
    }
  });

  ws.on("close", () => {
    if (username) {
      clients.delete(username);
      broadcast({
        type: "user_left",
        username,
        users: [...clients.keys()],
        timestamp: new Date().toISOString(),
      });
      console.log(`[EVIL-] ${username} left`);
    }
  });
});

console.log("╔══════════════════════════════════════╗");
console.log("║   ⚠  MALICIOUS Chat Server ⚠        ║");
console.log("║   This server TAMPERS with messages! ║");
console.log(`║   Listening on ws://localhost:${PORT}   ║`);
console.log("╚══════════════════════════════════════╝");
console.log("\nClients connecting here will have their messages modified.");
console.log("They will detect it via HASH FAIL and SIGNATURE INVALID.\n");
