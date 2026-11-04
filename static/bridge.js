/**
 * Puente NIP-07 (window.nostr) -> NIP-46 Remote Signer (Bunker)
 * Archivo: static/bridge.js
 *
 * Permite que aplicaciones web que buscan `window.nostr` (como el botón
 * "Login with browser extension" de Stacker News) deleguen la custodia de
 * la clave y la firma de eventos (Kind 27235) a nuestro Bunker NIP-46 local
 * mediante llamadas JSON-RPC empaquetadas en eventos Nostr Kind 24133.
 */
(function () {
  const BUNKER_URL = window.__NIP46_BUNKER_URL__ || "http://localhost:8000";

  async function nip46Rpc(method, params = []) {
    const reqId = "nip46-" + Math.random().toString(36).slice(2, 10);
    const response = await fetch(`${BUNKER_URL}/api/nip46/rpc`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: reqId, method, params }),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Error comunicando con Bunker NIP-46: ${errText}`);
    }

    const data = await response.json();
    const rpc = data.rpc_response;
    if (rpc.error) {
      throw new Error(`NIP-46 RPC Error (${method}): ${rpc.error}`);
    }
    return rpc.result;
  }

  window.nostr = {
    _isNip46BunkerBridge: true,

    async getPublicKey() {
      await nip46Rpc("connect", []);
      const pubkey = await nip46Rpc("get_public_key", []);
      console.log("[NIP-46 Bridge] getPublicKey ->", pubkey);
      return pubkey;
    },

    async signEvent(eventTemplate) {
      console.log("[NIP-46 Bridge] Solicitando firma remota NIP-46 (Kind 24133)...", eventTemplate);
      const signedJson = await nip46Rpc("sign_event", [JSON.stringify(eventTemplate)]);
      const signedEvent = typeof signedJson === "string" ? JSON.parse(signedJson) : signedJson;
      console.log("[NIP-46 Bridge] Evento firmado por Bunker:", signedEvent);
      return signedEvent;
    },

    async getRelays() {
      const relaysJson = await nip46Rpc("get_relays", []);
      return typeof relaysJson === "string" ? JSON.parse(relaysJson) : relaysJson;
    },

    nip04: {
      async encrypt(peerPubkey, plaintext) {
        return await nip46Rpc("nip04_encrypt", [peerPubkey, plaintext]);
      },
      async decrypt(peerPubkey, ciphertext) {
        return await nip46Rpc("nip04_decrypt", [peerPubkey, ciphertext]);
      },
    },

    nip44: {
      async encrypt(peerPubkey, plaintext) {
        return await nip46Rpc("nip44_encrypt", [peerPubkey, plaintext]);
      },
      async decrypt(peerPubkey, ciphertext) {
        return await nip46Rpc("nip44_decrypt", [peerPubkey, ciphertext]);
      },
    },
  };

  // Notificación visual flotante en la pestaña de Stacker News
  try {
    const existing = document.getElementById("nip46-bunker-toast");
    if (existing) existing.remove();
    const badge = document.createElement("div");
    badge.id = "nip46-bunker-toast";
    badge.style.cssText =
      "position:fixed;bottom:20px;right:20px;z-index:999999;background:#0f172a;color:#f8fafc;" +
      "border:1px solid #8b5cf6;border-radius:10px;padding:12px 16px;font-family:system-ui,sans-serif;" +
      "font-size:13px;box-shadow:0 10px 25px rgba(0,0,0,0.4);display:flex;align-items:center;gap:10px;";
    badge.innerHTML =
      '<span style="display:inline-block;width:10px;height:10px;background:#22c55e;border-radius:50%;"></span>' +
      '<div><strong>NIP-46 Bunker Conectado</strong><br/><span style="color:#cbd5e1;font-size:11px;">' +
      "window.nostr inyectado • Listo para firmar en Stacker News</span></div>";
    document.body.appendChild(badge);
    setTimeout(() => {
      badge.style.transition = "opacity 0.5s ease";
      badge.style.opacity = "0.85";
    }, 4000);
  } catch (_) {}

  console.log(
    "%c🔐 [NIP-46 Remote Signer Bridge] window.nostr conectado a " + BUNKER_URL,
    "background:#4c1d95;color:#fff;padding:4px 8px;border-radius:4px;font-weight:bold;"
  );
})();
