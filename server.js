/**
 * server.js
 * Server WebSocket untuk aplikasi SecureChat.
 * Server hanya meneruskan pesan tanpa memodifikasinya (honest server).
 * Integritas pesan dijaga oleh kriptografi di sisi client.
 *
 * Usage: node server.js
 */

import { WebSocketServer } from "ws";
import { generateHash } from "./generate-hash.js";

const PORT = 8765;
const wss = new WebSocketServer({ port: PORT });

// Map: username -> WebSocket
const clients = new Map();

/**
 * Kirim data JSON ke satu client
 */
function sendTo(ws, data) {
  if (ws.readyState === 1) {
    ws.send(JSON.stringify(data));
  }
}

/**
 * Broadcast ke semua client (kecuali sender jika exclude=true)
 */
function broadcast(data, excludeWs = null) {
  for (const [, ws] of clients) {
    if (ws !== excludeWs) {
      sendTo(ws, data);
    }
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

        // Sambut user baru dengan daftar user aktif
        sendTo(ws, {
          type: "welcome",
          users: [...clients.keys()].filter((u) => u !== username),
          timestamp: new Date().toISOString(),
        });

        // Beritahu semua user lain
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

        console.log(`[+] ${username} joined | Online: ${clients.size}`);
        break;
      }

      case "chat": {
        const content = data.content || "";
        const hash = data.hash || generateHash(content);

        const packet = {
          type: "chat",
          from: data.from || username,
          content,
          hash,
          signature: data.signature || null,
          publicKey: data.publicKey || null,
          encrypted: data.encrypted || false,
          encryptedAESKey: data.encryptedAESKey || null,
          iv: data.iv || null,
          authTag: data.authTag || null,
          recipient: data.recipient || null,
          timestamp: new Date().toISOString(),
        };

        if (data.recipient) {
          // Private message
          const recipientWs = clients.get(data.recipient);
          if (recipientWs) sendTo(recipientWs, packet);
          sendTo(ws, packet); // echo balik ke pengirim
        } else {
          // Broadcast
          broadcast(packet);
        }

        console.log(
          `[MSG] ${username} -> ${data.recipient || "all"}: ${content.substring(0, 40)}...`
        );
        break;
      }

      case "public_key": {
        // Relay public key ke semua user lain
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
      console.log(`[-] ${username} left | Online: ${clients.size}`);
    }
  });

  ws.on("error", (err) => {
    console.error(`[!] Error from ${username}: ${err.message}`);
  });
});

console.log("╔══════════════════════════════════════╗");
console.log("║       SecureChat Server v1.0         ║");
console.log(`║   Listening on ws://localhost:${PORT}   ║`);
console.log("╚══════════════════════════════════════╝");
