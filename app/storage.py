"""
Custodia de Claves y Estado de Sesión del Bunker NIP-46 (app/storage.py).

Mantiene en memoria la identidad activa (nsec / clave privada hex), el secreto
de vinculación para URIs `bunker://`, los clientes autorizados y el registro
de auditoría en vivo para el panel de control web.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from app.crypto import (
    generate_private_key,
    get_public_key,
    hex_to_npub,
    hex_to_nsec,
    normalize_private_key,
)

DEFAULT_RELAYS: list[str] = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
]


@dataclass
class AuditLogEntry:
    """Entrada del registro de actividad en vivo del Bunker."""

    timestamp: float
    level: str  # "info", "success", "warning", "error"
    action: str  # Ej: "sign_event", "connect", "get_public_key", "relay"
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "iso_time": time.strftime("%H:%M:%S", time.localtime(self.timestamp)),
            "level": self.level,
            "action": self.action,
            "message": self.message,
            "details": self.details,
        }


class KeyStorage:
    """
    Almacén en memoria para la clave secreta (`nsec`) y estado de sesión NIP-46.

    Diseño MVP:
    - La clave privada se mantiene únicamente en la memoria del proceso Python.
    - Administra el secreto de conexión (`secret`), clientes autorizados y estadísticas.
    """

    def __init__(self, relays: list[str] | None = None) -> None:
        self._privkey_hex: str | None = None
        self._secret: str = secrets.token_hex(8)
        self._relays: list[str] = list(relays) if relays else list(DEFAULT_RELAYS)
        self._authorized_clients: dict[str, dict[str, Any]] = {}
        self._signed_events_count: int = 0
        self._logs: list[AuditLogEntry] = []
        self._max_logs: int = 100

    @property
    def has_identity(self) -> bool:
        return self._privkey_hex is not None

    @property
    def privkey_hex(self) -> str | None:
        return self._privkey_hex

    @property
    def pubkey_hex(self) -> str | None:
        if not self._privkey_hex:
            return None
        return get_public_key(self._privkey_hex)

    @property
    def nsec(self) -> str | None:
        if not self._privkey_hex:
            return None
        return hex_to_nsec(self._privkey_hex)

    @property
    def npub(self) -> str | None:
        pub = self.pubkey_hex
        if not pub:
            return None
        return hex_to_npub(pub)

    @property
    def secret(self) -> str:
        return self._secret

    @property
    def relays(self) -> list[str]:
        return list(self._relays)

    @property
    def signed_events_count(self) -> int:
        return self._signed_events_count

    @property
    def authorized_clients(self) -> dict[str, dict[str, Any]]:
        return dict(self._authorized_clients)

    def set_relays(self, relays: list[str]) -> None:
        cleaned = [r.strip() for r in relays if r.strip().startswith(("wss://", "ws://"))]
        if not cleaned:
            raise ValueError("Debe especificar al menos un relay WebSocket válido (wss:// o ws://).")
        self._relays = cleaned
        self.add_log(
            "info",
            "relays_updated",
            f"Relays actualizados ({len(cleaned)} configurados)",
            {"relays": cleaned},
        )

    def generate_new_identity(self) -> dict[str, str]:
        """Genera un nuevo par de claves criptográficamente seguro y rota el secreto."""
        priv_hex = generate_private_key()
        return self.load_identity(priv_hex, source="generated")

    def load_identity(self, key_input: str, source: str = "imported") -> dict[str, str]:
        """Carga y valida una clave privada en formato `nsec1...` o hex de 64 caracteres."""
        priv_hex = normalize_private_key(key_input)
        self._privkey_hex = priv_hex
        self._secret = secrets.token_hex(8)
        self._authorized_clients.clear()

        pub_hex = self.pubkey_hex or ""
        npub_str = self.npub or ""
        nsec_str = self.nsec or ""

        action_label = "generada" if source == "generated" else "importada"
        self.add_log(
            "success",
            "identity_loaded",
            f"Identidad Nostr {action_label}: {npub_str[:16]}...{npub_str[-6:]}",
            {"pubkey": pub_hex, "npub": npub_str, "source": source},
        )
        return {
            "privkey_hex": priv_hex,
            "pubkey_hex": pub_hex,
            "nsec": nsec_str,
            "npub": npub_str,
            "bunker_uri": self.get_bunker_uri(),
        }

    def clear_identity(self) -> None:
        """Elimina la clave privada de la memoria y cierra sesiones activas."""
        self._privkey_hex = None
        self._authorized_clients.clear()
        self._secret = secrets.token_hex(8)
        self.add_log("warning", "identity_cleared", "Clave privada eliminada de la memoria.")

    def rotate_secret(self) -> str:
        """Genera un nuevo secreto compartido para la URI bunker://."""
        self._secret = secrets.token_hex(8)
        self.add_log("info", "secret_rotated", "Secreto de conexión bunker:// regenerado.")
        return self._secret

    def get_bunker_uri(self, include_secret: bool = True) -> str:
        """
        Construye la URI estándar NIP-46:
        bunker://<remote-signer-pubkey>?relay=<wss://...>&secret=<secret>
        """
        pub = self.pubkey_hex
        if not pub:
            return ""
        params: list[tuple[str, str]] = [("relay", r) for r in self._relays]
        if include_secret and self._secret:
            params.append(("secret", self._secret))
        query = urlencode(params)
        return f"bunker://{pub}?{query}"

    def authorize_client(
        self,
        client_pubkey: str,
        perms: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Registra un cliente remoto como autorizado para operar con el Bunker."""
        client_pubkey = client_pubkey.lower().strip()
        self._authorized_clients[client_pubkey] = {
            "client_pubkey": client_pubkey,
            "connected_at": time.time(),
            "perms": perms or "default",
            "metadata": metadata or {},
        }

    def revoke_client(self, client_pubkey: str) -> None:
        """Revoca la sesión de un cliente remoto (ej. en llamada RPC `logout`)."""
        self._authorized_clients.pop(client_pubkey.lower().strip(), None)

    def is_client_authorized(self, client_pubkey: str) -> bool:
        return client_pubkey.lower().strip() in self._authorized_clients

    def record_signed_event(self, signed_event: dict[str, Any], client_pubkey: str) -> None:
        """Incrementa el contador de eventos firmados y registra el detalle en el log."""
        self._signed_events_count += 1
        kind = signed_event.get("kind")
        event_id = signed_event.get("id", "")
        content_preview = str(signed_event.get("content", ""))[:80]
        self.add_log(
            "success",
            "sign_event",
            f"Evento Kind {kind} firmado exitosamente (ID: {event_id[:12]}...)",
            {
                "event_id": event_id,
                "kind": kind,
                "client_pubkey": client_pubkey,
                "content": content_preview,
                "tags": signed_event.get("tags", []),
                "sig_prefix": signed_event.get("sig", "")[:24] + "...",
            },
        )

    def add_log(
        self,
        level: str,
        action: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        entry = AuditLogEntry(
            timestamp=time.time(),
            level=level,
            action=action,
            message=message,
            details=details or {},
        )
        self._logs.insert(0, entry)
        if len(self._logs) > self._max_logs:
            self._logs = self._logs[: self._max_logs]
        return entry

    def get_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        return [entry.to_dict() for entry in self._logs[:limit]]
