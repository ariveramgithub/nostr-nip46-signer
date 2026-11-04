"""
Manejador del Protocolo NIP-46 — Nostr Remote Signing / Bunker (app/nip46.py).

Implementa el servidor JSON-RPC sobre eventos Nostr Kind 24133 (tanto con cifrado
NIP-44 v2 como NIP-04 por retrocompatibilidad) para procesar solicitudes de:
- `connect`
- `get_public_key`
- `sign_event`
- `ping`
- `get_relays` / `switch_relays`
- `nip04_encrypt` / `nip04_decrypt` / `nip44_encrypt` / `nip44_decrypt`
- `logout`
"""

from __future__ import annotations

import json
from typing import Any

from app.crypto import (
    nip04_decrypt,
    nip04_encrypt,
    nip44_decrypt,
    nip44_encrypt,
    nip46_decrypt,
    nip46_encrypt,
    sign_nostr_event,
    verify_nostr_event,
)
from app.storage import KeyStorage


class NIP46Handler:
    """
    Procesador de comandos JSON-RPC para el Bunker NIP-46.
    Desacoplado de la capa de red (WebSockets) para facilitar pruebas unitarias.
    """

    def __init__(self, storage: KeyStorage, strict_secret: bool = False) -> None:
        self.storage = storage
        self.strict_secret = strict_secret

    def handle_rpc_request(
        self,
        client_pubkey: str,
        request_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Ejecuta una llamada JSON-RPC NIP-46 ya descifrada y retorna el diccionario
        de respuesta `{ "id": <req_id>, "result": ..., "error": ... }`.
        """
        req_id = str(request_payload.get("id") or "")
        method = str(request_payload.get("method") or "")
        params = request_payload.get("params") or []
        if not isinstance(params, list):
            params = [params]

        if not req_id or not method:
            return {
                "id": req_id or "unknown",
                "result": None,
                "error": "Invalid NIP-46 JSON-RPC request: missing 'id' or 'method'.",
            }

        if not self.storage.has_identity or not self.storage.privkey_hex:
            self.storage.add_log(
                "error",
                method,
                f"Solicitud '{method}' rechazada: el Bunker no tiene una clave nsec cargada.",
                {"client_pubkey": client_pubkey},
            )
            return {
                "id": req_id,
                "result": None,
                "error": "Bunker has no active key loaded.",
            }

        try:
            if method == "connect":
                result = self._rpc_connect(client_pubkey, params)
            elif method == "get_public_key":
                result = self._rpc_get_public_key(client_pubkey)
            elif method == "sign_event":
                result = self._rpc_sign_event(client_pubkey, params)
            elif method == "ping":
                result = self._rpc_ping(client_pubkey)
            elif method == "get_relays":
                result = self._rpc_get_relays(client_pubkey)
            elif method == "switch_relays":
                result = self._rpc_switch_relays(client_pubkey)
            elif method == "logout":
                result = self._rpc_logout(client_pubkey)
            elif method == "nip04_encrypt":
                result = self._rpc_nip04_encrypt(params)
            elif method == "nip04_decrypt":
                result = self._rpc_nip04_decrypt(params)
            elif method == "nip44_encrypt":
                result = self._rpc_nip44_encrypt(params)
            elif method == "nip44_decrypt":
                result = self._rpc_nip44_decrypt(params)
            else:
                self.storage.add_log(
                    "warning",
                    method,
                    f"Método NIP-46 no soportado: {method}",
                    {"client_pubkey": client_pubkey},
                )
                return {
                    "id": req_id,
                    "result": None,
                    "error": f"Unsupported NIP-46 method: {method}",
                }

            return {"id": req_id, "result": result}

        except Exception as exc:
            self.storage.add_log(
                "error",
                method,
                f"Error al procesar '{method}': {exc}",
                {"client_pubkey": client_pubkey},
            )
            return {
                "id": req_id,
                "result": None,
                "error": str(exc),
            }

    # ========================================================================
    # Implementación de Métodos RPC NIP-46
    # ========================================================================
    def _rpc_connect(self, client_pubkey: str, params: list[Any]) -> str:
        """
        connect([<remote-signer-pubkey>, <optional_secret>, <optional_perms>, <optional_metadata>])
        Valida el secreto compartido (si se proporciona) y autoriza al cliente.
        """
        target_pubkey = str(params[0]) if len(params) > 0 and params[0] else ""
        provided_secret = str(params[1]) if len(params) > 1 and params[1] else None
        requested_perms = str(params[2]) if len(params) > 2 and params[2] else None
        raw_metadata = params[3] if len(params) > 3 else None

        # Si target_pubkey fue pasado y no coincide con nuestra pubkey ni con el secret, validar
        my_pubkey = self.storage.pubkey_hex or ""
        if (
            target_pubkey
            and target_pubkey.lower() != my_pubkey.lower()
            and target_pubkey != self.storage.secret
        ):
            raise ValueError("Target remote-signer-pubkey does not match this Bunker.")

        # Validar el secreto si el cliente envió uno explícitamente o si strict_secret está activo
        expected_secret = self.storage.secret
        if provided_secret is not None and provided_secret != "":
            if expected_secret and provided_secret != expected_secret:
                raise ValueError("Invalid NIP-46 connection secret.")
        elif self.strict_secret and expected_secret:
            # Algunos clientes pasan el secret como primer parámetro
            if target_pubkey != expected_secret:
                raise ValueError("Missing or invalid NIP-46 connection secret.")

        metadata: dict[str, Any] = {}
        if isinstance(raw_metadata, str) and raw_metadata.strip():
            try:
                metadata = json.loads(raw_metadata)
            except Exception:
                metadata = {"raw": raw_metadata}
        elif isinstance(raw_metadata, dict):
            metadata = raw_metadata

        self.storage.authorize_client(
            client_pubkey=client_pubkey,
            perms=requested_perms,
            metadata=metadata,
        )
        client_name = metadata.get("name") or f"{client_pubkey[:12]}..."
        self.storage.add_log(
            "success",
            "connect",
            f"Cliente conectado y autorizado vía NIP-46 ({client_name})",
            {
                "client_pubkey": client_pubkey,
                "perms": requested_perms,
                "metadata": metadata,
            },
        )
        return "ack"

    def _rpc_get_public_key(self, client_pubkey: str) -> str:
        """Retorna la clave pública en formato hex (64 caracteres) del usuario custodiado."""
        pubkey = self.storage.pubkey_hex
        if not pubkey:
            raise RuntimeError("No public key available.")
        # Autorizar implícitamente en flujo directo MVP si aún no llamó a connect
        if not self.storage.is_client_authorized(client_pubkey):
            self.storage.authorize_client(client_pubkey)
        self.storage.add_log(
            "info",
            "get_public_key",
            f"Clave pública entregada al cliente {client_pubkey[:12]}...",
            {"client_pubkey": client_pubkey, "user_pubkey": pubkey},
        )
        return pubkey

    def _rpc_sign_event(self, client_pubkey: str, params: list[Any]) -> str:
        """
        sign_event([<{kind, content, tags, created_at}>])
        Calcula el ID canónico NIP-01, firma con Schnorr BIP-340 y retorna el evento JSON-stringified.
        """
        if not params:
            raise ValueError("Missing event parameter in sign_event.")

        raw_event = params[0]
        if isinstance(raw_event, str):
            try:
                event_dict = json.loads(raw_event)
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid JSON in sign_event parameter.") from exc
        elif isinstance(raw_event, dict):
            event_dict = dict(raw_event)
        else:
            raise ValueError("Unsupported event format in sign_event.")

        if "kind" not in event_dict:
            raise ValueError("Event template is missing required field 'kind'.")

        privkey = self.storage.privkey_hex
        if not privkey:
            raise RuntimeError("Private key is not loaded.")

        if not self.storage.is_client_authorized(client_pubkey):
            self.storage.authorize_client(client_pubkey)

        signed_event = sign_nostr_event(event_dict, privkey)
        self.storage.record_signed_event(signed_event, client_pubkey=client_pubkey)
        return json.dumps(signed_event, separators=(",", ":"), ensure_ascii=False)

    def _rpc_ping(self, client_pubkey: str) -> str:
        self.storage.add_log(
            "info",
            "ping",
            f"Ping recibido de {client_pubkey[:12]}... -> pong",
            {"client_pubkey": client_pubkey},
        )
        return "pong"

    def _rpc_get_relays(self, client_pubkey: str) -> str:
        relays_map = {
            url: {"read": True, "write": True} for url in self.storage.relays
        }
        self.storage.add_log(
            "info",
            "get_relays",
            f"Lista de relays enviada a {client_pubkey[:12]}...",
            {"relays": self.storage.relays},
        )
        return json.dumps(relays_map, separators=(",", ":"))

    def _rpc_switch_relays(self, client_pubkey: str) -> None:
        """
        Responde a `switch_relays` (usado por NDK / Stacker News tras `connect`).
        Retornar `None` (`null` en JSON) indica al cliente que mantenga los relays actuales sin demora.
        """
        self.storage.add_log(
            "info",
            "switch_relays",
            f"Confirmación de relays activos para {client_pubkey[:12]}...",
            {"relays": self.storage.relays},
        )
        return None

    def _rpc_logout(self, client_pubkey: str) -> str:
        self.storage.revoke_client(client_pubkey)
        self.storage.add_log(
            "info",
            "logout",
            f"Sesión cerrada para el cliente {client_pubkey[:12]}...",
            {"client_pubkey": client_pubkey},
        )
        return "ack"

    def _rpc_nip04_encrypt(self, params: list[Any]) -> str:
        if len(params) < 2:
            raise ValueError("nip04_encrypt requires [peer_pubkey, plaintext].")
        priv = self.storage.privkey_hex or ""
        return nip04_encrypt(str(params[1]), priv, str(params[0]))

    def _rpc_nip04_decrypt(self, params: list[Any]) -> str:
        if len(params) < 2:
            raise ValueError("nip04_decrypt requires [peer_pubkey, ciphertext].")
        priv = self.storage.privkey_hex or ""
        return nip04_decrypt(str(params[1]), priv, str(params[0]))

    def _rpc_nip44_encrypt(self, params: list[Any]) -> str:
        if len(params) < 2:
            raise ValueError("nip44_encrypt requires [peer_pubkey, plaintext].")
        priv = self.storage.privkey_hex or ""
        return nip44_encrypt(str(params[1]), priv, str(params[0]))

    def _rpc_nip44_decrypt(self, params: list[Any]) -> str:
        if len(params) < 2:
            raise ValueError("nip44_decrypt requires [peer_pubkey, ciphertext].")
        priv = self.storage.privkey_hex or ""
        return nip44_decrypt(str(params[1]), priv, str(params[0]))

    # ========================================================================
    # Procesamiento Integral de Eventos Nostr Kind 24133
    # ========================================================================
    def process_kind24133_event(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """
        Recibe un evento Nostr Kind 24133 desde un relay:
        1. Verifica que sea Kind 24133 y esté dirigido a la clave pública del Bunker.
        2. Verifica la firma Schnorr BIP-340 del evento entrante.
        3. Descifra el `content` (autodetección NIP-44 / NIP-04).
        4. Si es una solicitud (`method` presente), ejecuta el comando RPC.
        5. Cifra la respuesta con el mismo esquema y firma un nuevo evento Kind 24133.
        """
        if not self.storage.has_identity or not self.storage.privkey_hex:
            return None

        if int(event.get("kind", 0)) != 24133:
            return None

        my_pubkey = (self.storage.pubkey_hex or "").lower()
        client_pubkey = str(event.get("pubkey") or "").lower()
        if not client_pubkey or client_pubkey == my_pubkey:
            # Ignorar eventos propios reflejados por el relay
            return None

        # Verificar que el tag #p apunte a nuestro Bunker
        p_tags = [
            tag[1].lower()
            for tag in event.get("tags", [])
            if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "p"
        ]
        if my_pubkey not in p_tags:
            return None

        if not verify_nostr_event(event):
            self.storage.add_log(
                "warning",
                "invalid_sig",
                f"Evento Kind 24133 descartado: firma BIP-340 inválida de {client_pubkey[:12]}...",
            )
            return None

        encrypted_content = str(event.get("content") or "")
        try:
            decrypted_json, scheme = nip46_decrypt(
                encrypted_content,
                self.storage.privkey_hex,
                client_pubkey,
            )
            payload = json.loads(decrypted_json)
        except Exception as exc:
            self.storage.add_log(
                "error",
                "decrypt_error",
                f"No se pudo descifrar evento Kind 24133 de {client_pubkey[:12]}...: {exc}",
            )
            return None

        # Ignorar si el mensaje entrante es una respuesta y no una solicitud RPC
        if "method" not in payload:
            return None

        response_obj = self.handle_rpc_request(client_pubkey, payload)
        # Eliminar claves nulas innecesarias según convención NIP-46
        clean_response: dict[str, Any] = {"id": response_obj["id"]}
        if response_obj.get("error"):
            clean_response["result"] = response_obj.get("result") or ""
            clean_response["error"] = response_obj["error"]
        else:
            clean_response["result"] = response_obj.get("result")

        response_json = json.dumps(clean_response, separators=(",", ":"), ensure_ascii=False)
        encrypted_response = nip46_encrypt(
            response_json,
            self.storage.privkey_hex,
            client_pubkey,
            scheme=scheme,
        )

        response_event_tpl = {
            "kind": 24133,
            "tags": [["p", client_pubkey]],
            "content": encrypted_response,
        }
        return sign_nostr_event(response_event_tpl, self.storage.privkey_hex)
