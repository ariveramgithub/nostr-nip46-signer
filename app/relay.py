"""
Cliente WebSocket Asíncrono para Relays de Nostr (app/relay.py).

Se conecta a múltiples relays públicos en paralelo, publica la suscripción NIP-46:
    ["REQ", "<sub_id>", {"kinds": [24133], "#p": ["<bunker_pubkey>"]}]
y procesa eventos entrantes Kind 24133 enviando las respuestas firmadas de vuelta.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from typing import Any

import websockets
from websockets.exceptions import ConnectionClosed

from app.nip46 import NIP46Handler
from app.storage import KeyStorage


class RelayManager:
    """
    Gestiona las conexiones WebSocket persistentes hacia los relays Nostr configurados
    y coordina la suscripción y publicación de eventos NIP-46 (Kind 24133).
    """

    def __init__(self, storage: KeyStorage, handler: NIP46Handler) -> None:
        self.storage = storage
        self.handler = handler
        self._running: bool = False
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._connections: dict[str, Any] = {}
        self._relay_status: dict[str, dict[str, Any]] = {}
        self._sub_id: str = f"nip46-bunker-{secrets.token_hex(4)}"
        self._processed_events: dict[str, dict[str, Any] | None] = {}
        self._max_cache_size: int = 500

    @property
    def is_running(self) -> bool:
        return self._running

    def get_status(self) -> dict[str, Any]:
        """Retorna el estado consolidado de conexión a cada relay."""
        relays_info = []
        connected_count = 0
        for url in self.storage.relays:
            st = self._relay_status.get(
                url,
                {"url": url, "connected": False, "last_error": None, "events_rx": 0},
            )
            if st.get("connected"):
                connected_count += 1
            relays_info.append(st)

        return {
            "running": self._running,
            "connected_count": connected_count,
            "total_relays": len(self.storage.relays),
            "sub_id": self._sub_id,
            "relays": relays_info,
        }

    async def start(self) -> None:
        """Inicia los workers asíncronos de conexión para cada relay."""
        self._running = True
        await self.sync_relays()

    async def stop(self) -> None:
        """Cierra ordenadamente todas las conexiones WebSocket y tareas."""
        self._running = False
        for url, ws in list(self._connections.items()):
            try:
                await ws.close()
            except Exception:
                pass
        self._connections.clear()

        for url, task in list(self._tasks.items()):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()

        for url in self._relay_status:
            self._relay_status[url]["connected"] = False

    async def sync_relays(self) -> None:
        """Sincroniza las tareas activas con la lista de relays en `storage`."""
        desired = set(self.storage.relays)
        current = set(self._tasks.keys())

        # Detener relays eliminados
        for removed in current - desired:
            ws = self._connections.pop(removed, None)
            if ws:
                try:
                    await ws.close()
                except Exception:
                    pass
            task = self._tasks.pop(removed, None)
            if task:
                task.cancel()
            self._relay_status.pop(removed, None)

        # Iniciar nuevos relays
        if self._running:
            for added in desired - current:
                self._relay_status[added] = {
                    "url": added,
                    "connected": False,
                    "last_error": None,
                    "events_rx": 0,
                }
                self._tasks[added] = asyncio.create_task(
                    self._relay_worker(added),
                    name=f"relay-{added}",
                )

    async def resubscribe_all(self) -> None:
        """
        Actualiza la suscripción REQ en todos los relays conectados cuando el usuario
        genera o carga una nueva identidad `nsec`.
        """
        self._sub_id = f"nip46-bunker-{secrets.token_hex(4)}"
        for url, ws in list(self._connections.items()):
            try:
                await self._send_subscription(url, ws)
            except Exception as exc:
                self._relay_status.setdefault(url, {})["last_error"] = str(exc)

    async def publish_event(self, event: dict[str, Any]) -> int:
        """Publica un evento Nostr firmado en todos los relays actualmente conectados."""
        msg = json.dumps(["EVENT", event], separators=(",", ":"), ensure_ascii=False)
        published = 0
        for url, ws in list(self._connections.items()):
            try:
                await ws.send(msg)
                published += 1
            except Exception as exc:
                self._relay_status.setdefault(url, {})["last_error"] = str(exc)
        return published

    async def _send_subscription(self, url: str, ws: Any) -> None:
        """Envía el mensaje REQ de suscripción a Kind 24133 para la pubkey activa."""
        pubkey = self.storage.pubkey_hex
        if not pubkey:
            return
        req_filter = {
            "kinds": [24133],
            "#p": [pubkey.lower()],
            "since": int(time.time()) - 120,
        }
        req_msg = json.dumps(["REQ", self._sub_id, req_filter])
        await ws.send(req_msg)

    async def _relay_worker(self, url: str) -> None:
        """Bucle de conexión y escucha con reconexión automática para un relay."""
        backoff = 2.0
        while self._running:
            try:
                async with websockets.connect(
                    url,
                    ping_interval=25,
                    ping_timeout=20,
                    close_timeout=5,
                    user_agent_header="NostrNIP46PythonBunker/1.0",
                ) as ws:
                    self._connections[url] = ws
                    self._relay_status[url] = {
                        "url": url,
                        "connected": True,
                        "last_error": None,
                        "events_rx": self._relay_status.get(url, {}).get("events_rx", 0),
                    }
                    backoff = 2.0
                    self.storage.add_log(
                        "info",
                        "relay_connected",
                        f"Conectado al relay {url}",
                        {"relay": url},
                    )

                    if self.storage.has_identity:
                        await self._send_subscription(url, ws)

                    async for raw_msg in ws:
                        if not self._running:
                            break
                        await self._handle_relay_message(url, ws, str(raw_msg))

            except asyncio.CancelledError:
                break
            except (ConnectionClosed, OSError, Exception) as exc:
                self._relay_status.setdefault(
                    url, {"url": url, "events_rx": 0}
                ).update({"connected": False, "last_error": str(exc)})
            finally:
                self._connections.pop(url, None)
                if url in self._relay_status:
                    self._relay_status[url]["connected"] = False

            if self._running:
                await asyncio.sleep(backoff)
                backoff = min(backoff * 1.5, 20.0)

    async def _handle_relay_message(self, url: str, ws: Any, raw_msg: str) -> None:
        """Procesa tramas JSON estándar NIP-01 (`EVENT`, `EOSE`, `OK`, `NOTICE`)."""
        try:
            data = json.loads(raw_msg)
        except json.JSONDecodeError:
            return

        if not isinstance(data, list) or not data:
            return

        msg_type = data[0]
        if msg_type == "EVENT" and len(data) >= 3:
            event = data[2]
            if not isinstance(event, dict):
                return

            event_id = str(event.get("id") or "")
            if not event_id:
                return

            self._relay_status[url]["events_rx"] = (
                self._relay_status[url].get("events_rx", 0) + 1
            )

            # Deduplicación multi-relay: si otro relay ya procesó este mismo event_id,
            # solo reenviamos la respuesta firmada en caché a este relay.
            if event_id in self._processed_events:
                cached_resp = self._processed_events[event_id]
                if cached_resp is not None:
                    try:
                        await ws.send(
                            json.dumps(
                                ["EVENT", cached_resp],
                                separators=(",", ":"),
                                ensure_ascii=False,
                            )
                        )
                    except Exception:
                        pass
                return

            # Procesar la solicitud NIP-46 por primera vez
            response_event = self.handler.process_kind24133_event(event)
            if len(self._processed_events) >= self._max_cache_size:
                oldest_key = next(iter(self._processed_events))
                self._processed_events.pop(oldest_key, None)
            self._processed_events[event_id] = response_event

            if response_event is not None:
                # Publicar la respuesta firmada en todos los relays activos
                await self.publish_event(response_event)
