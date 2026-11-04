"""
Servidor Principal FastAPI del Firmante Remoto Nostr NIP-46 / Bunker (app/main.py).

Expone:
- Panel de Control Web Local en `http://localhost:8000` (`static/index.html`).
- Script puente NIP-07 -> NIP-46 en `http://localhost:8000/static/bridge.js`.
- API REST para gestión de identidad (`nsec`), estado de relays, URI `bunker://`,
  transporte NIP-46 y simulación de extremo a extremo para Stacker News.
"""

from __future__ import annotations

import json
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import uvicorn
import websockets
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.crypto import (
    generate_private_key,
    get_public_key,
    nip46_decrypt,
    nip46_encrypt,
    sign_nostr_event,
    verify_nostr_event,
)
from app.nip46 import NIP46Handler
from app.relay import RelayManager
from app.storage import KeyStorage

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

# Instancias globales del Bunker
storage = KeyStorage()
nip46_handler = NIP46Handler(storage=storage, strict_secret=False)
relay_manager = RelayManager(storage=storage, handler=nip46_handler)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Ciclo de vida de la aplicación: inicia una identidad por defecto y conecta a relays."""
    # Si se provee NSEC en variable de entorno, cargarla al iniciar; si no, generar una lista para usar
    env_nsec = os.getenv("NOSTR_NSEC", "").strip()
    if env_nsec:
        try:
            storage.load_identity(env_nsec, source="env")
        except Exception as exc:
            storage.add_log("error", "startup", f"NOSTR_NSEC inválido: {exc}")
    elif not storage.has_identity:
        storage.generate_new_identity()

    if os.getenv("DISABLE_RELAY_WORKERS", "").lower() not in ("1", "true", "yes"):
        await relay_manager.start()
    yield
    await relay_manager.stop()


app = FastAPI(
    title="Nostr NIP-46 Remote Signer (Bunker)",
    description="Firmante Remoto Nostr (NIP-46) en Python para autenticación en Stacker News",
    version="1.0.0",
    lifespan=lifespan,
)

# Habilitar CORS para permitir que bridge.js inyectado en https://stacker.news consulte al Bunker
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ============================================================================
# Modelos Pydantic de Solicitud
# ============================================================================
class LoadIdentityRequest(BaseModel):
    key: str = Field(..., description="Clave privada en formato nsec1... o 64 caracteres hex")


class UpdateRelaysRequest(BaseModel):
    relays: list[str] = Field(..., description="Lista de URLs WebSocket de relays (wss://...)")


class NIP46DirectRpcRequest(BaseModel):
    id: str = Field(default="bridge-req-1")
    method: str = Field(..., description="Método NIP-46: connect, get_public_key, sign_event, ping")
    params: list[Any] = Field(default_factory=list)
    client_pubkey: str | None = Field(default=None)


class NostrConnectUriRequest(BaseModel):
    uri: str = Field(..., description="URI nostrconnect://<client-pubkey>?relay=...&secret=...")


# ============================================================================
# Rutas Frontend y Estado del Bunker
# ============================================================================
@app.get("/", include_in_schema=False)
async def serve_dashboard() -> FileResponse:
    """Sirve el Panel de Control Local en HTML/CSS/JS vainilla."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/status")
async def get_status() -> dict[str, Any]:
    """Retorna el estado actual del Bunker, la identidad activa, relays y bitácora."""
    return {
        "has_identity": storage.has_identity,
        "pubkey_hex": storage.pubkey_hex,
        "npub": storage.npub,
        "nsec": storage.nsec,
        "secret": storage.secret,
        "bunker_uri": storage.get_bunker_uri(include_secret=True),
        "bunker_uri_no_secret": storage.get_bunker_uri(include_secret=False),
        "signed_events_count": storage.signed_events_count,
        "authorized_clients": list(storage.authorized_clients.values()),
        "relay_status": relay_manager.get_status(),
        "logs": storage.get_logs(limit=50),
    }


@app.post("/api/identity/generate")
async def generate_identity() -> dict[str, Any]:
    """Genera una nueva identidad Nostr aleatoria (`nsec` / `npub`) y actualiza suscripciones."""
    info = storage.generate_new_identity()
    await relay_manager.resubscribe_all()
    return {
        "status": "ok",
        "identity": info,
        "bunker_uri": storage.get_bunker_uri(),
    }


@app.post("/api/identity/load")
async def load_identity(req: LoadIdentityRequest) -> dict[str, Any]:
    """Carga una clave secreta `nsec1...` o hex existente en el Bunker."""
    try:
        info = storage.load_identity(req.key, source="imported")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await relay_manager.resubscribe_all()
    return {
        "status": "ok",
        "identity": info,
        "bunker_uri": storage.get_bunker_uri(),
    }


@app.delete("/api/identity")
async def clear_identity() -> dict[str, str]:
    """Limpia la clave privada activa de la memoria del proceso."""
    storage.clear_identity()
    return {"status": "cleared"}


@app.post("/api/secret/rotate")
async def rotate_secret() -> dict[str, str]:
    """Regenera el secreto compartido de la URI `bunker://`."""
    new_secret = storage.rotate_secret()
    return {
        "status": "ok",
        "secret": new_secret,
        "bunker_uri": storage.get_bunker_uri(),
    }


@app.post("/api/relays")
async def update_relays(req: UpdateRelaysRequest) -> dict[str, Any]:
    """Actualiza la lista de relays públicos y reconecta."""
    try:
        storage.set_relays(req.relays)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await relay_manager.sync_relays()
    await relay_manager.resubscribe_all()
    return {
        "status": "ok",
        "relays": storage.relays,
        "bunker_uri": storage.get_bunker_uri(),
    }


# ============================================================================
# Endpoints de Protocolo NIP-46 (Bridge, NostrConnect y Simulador E2E)
# ============================================================================
@app.post("/api/nip46/rpc")
async def nip46_rpc_endpoint(req: NIP46DirectRpcRequest) -> dict[str, Any]:
    """
    Endpoint RPC para `static/bridge.js` y clientes locales.
    Empaqueta la solicitud en un evento Nostr Kind 24133 real firmado por un cliente
    efímero (o el `client_pubkey` indicado), lo procesa a través del flujo criptográfico
    completo NIP-46 (NIP-44 + BIP-340) y retorna el resultado JSON-RPC junto al evento
    Kind 24133 firmado por el Bunker.
    """
    if not storage.has_identity or not storage.privkey_hex or not storage.pubkey_hex:
        raise HTTPException(status_code=400, detail="El Bunker no tiene una clave nsec activa.")

    # Generar par de claves efímero de cliente para envolver la llamada en un Kind 24133 auténtico
    ephemeral_client_priv = generate_private_key()
    bunker_pub = storage.pubkey_hex

    rpc_request = {
        "id": req.id,
        "method": req.method,
        "params": req.params,
    }
    encrypted_req = nip46_encrypt(
        json.dumps(rpc_request, separators=(",", ":"), ensure_ascii=False),
        ephemeral_client_priv,
        bunker_pub,
        scheme="nip44",
    )
    kind24133_req_event = sign_nostr_event(
        {
            "kind": 24133,
            "tags": [["p", bunker_pub]],
            "content": encrypted_req,
        },
        ephemeral_client_priv,
    )

    kind24133_resp_event = nip46_handler.process_kind24133_event(kind24133_req_event)
    if kind24133_resp_event is None:
        raise HTTPException(status_code=500, detail="Error al procesar el evento Kind 24133.")

    decrypted_resp, _scheme = nip46_decrypt(
        kind24133_resp_event["content"],
        ephemeral_client_priv,
        bunker_pub,
    )
    rpc_response = json.loads(decrypted_resp)

    # Publicar también en los relays conectados para trazabilidad en la red Nostr
    if relay_manager.is_running:
        await relay_manager.publish_event(kind24133_resp_event)

    return {
        "rpc_response": rpc_response,
        "request_event_kind24133": kind24133_req_event,
        "response_event_kind24133": kind24133_resp_event,
    }


@app.post("/api/nip46/simulate-stacker-news")
async def simulate_stacker_news_flow() -> dict[str, Any]:
    """
    Ejecuta una prueba de integración completa del flujo de inicio de sesión de Stacker News:
    1. Cliente genera keypair efímero.
    2. Envía Kind 24133 `connect` cifrado con NIP-44 v2 -> Bunker valida `secret` y responde `"ack"`.
    3. Envía Kind 24133 `get_public_key` -> Bunker responde con el `pubkey` del usuario.
    4. Envía Kind 24133 `sign_event` con el desafío Kind 27235 (`Stacker News Authentication`) ->
       Bunker calcula el ID NIP-01, firma con Schnorr BIP-340 y retorna el evento firmado.
    """
    if not storage.has_identity or not storage.pubkey_hex:
        raise HTTPException(status_code=400, detail="Primero cargue o genere una clave nsec.")

    bunker_pub = storage.pubkey_hex
    secret = storage.secret
    client_priv = generate_private_key()
    client_pub = get_public_key(client_priv)

    steps = []

    def _run_step(step_id: str, method: str, params: list[Any]) -> dict[str, Any]:
        req_json = json.dumps({"id": step_id, "method": method, "params": params})
        enc_req = nip46_encrypt(req_json, client_priv, bunker_pub, scheme="nip44")
        req_ev = sign_nostr_event(
            {"kind": 24133, "tags": [["p", bunker_pub]], "content": enc_req},
            client_priv,
        )
        resp_ev = nip46_handler.process_kind24133_event(req_ev)
        if resp_ev is None:
            raise RuntimeError(f"Step {method} returned None")
        dec_resp, scheme = nip46_decrypt(resp_ev["content"], client_priv, bunker_pub)
        parsed_resp = json.loads(dec_resp)
        return {
            "method": method,
            "encryption": scheme,
            "request_event_id": req_ev["id"],
            "response_event_id": resp_ev["id"],
            "rpc_response": parsed_resp,
        }

    # Paso 1: connect
    steps.append(
        _run_step(
            "sim-connect-1",
            "connect",
            [bunker_pub, secret, "sign_event:27235", json.dumps({"name": "Stacker News (Simulador E2E)"})],
        )
    )
    # Paso 2: get_public_key
    steps.append(_run_step("sim-pk-2", "get_public_key", []))
    # Paso 3: sign_event (Kind 27235 Stacker News Auth Challenge)
    sn_challenge_event = {
        "kind": 27235,
        "created_at": 1730000000,
        "tags": [
            ["challenge", "stacker-news-k1-challenge-demo-" + secret],
            ["u", "https://stacker.news"],
            ["method", "GET"],
        ],
        "content": "Stacker News Authentication",
    }
    sign_step = _run_step("sim-sign-3", "sign_event", [json.dumps(sn_challenge_event)])
    steps.append(sign_step)

    signed_event = json.loads(sign_step["rpc_response"]["result"])
    return {
        "status": "ok",
        "client_pubkey": client_pub,
        "bunker_pubkey": bunker_pub,
        "verified_bip340": verify_nostr_event(signed_event),
        "signed_auth_event": signed_event,
        "steps": steps,
    }


@app.post("/api/nostrconnect")
async def connect_via_nostrconnect_uri(req: NostrConnectUriRequest) -> dict[str, Any]:
    """
    Soporte adicional para URIs iniciadas por el cliente (`nostrconnect://<client-pubkey>?relay=...&secret=...`).
    Publica el evento Kind 24133 de confirmación hacia el relay indicado por el cliente.
    """
    if not storage.has_identity or not storage.privkey_hex or not storage.pubkey_hex:
        raise HTTPException(status_code=400, detail="Cargue o genere una clave nsec primero.")

    uri = req.uri.strip()
    if not uri.startswith("nostrconnect://"):
        raise HTTPException(status_code=400, detail="La URI debe comenzar con 'nostrconnect://'.")

    parsed = urlparse(uri.replace("nostrconnect://", "http://", 1))
    client_pubkey = (parsed.hostname or parsed.path.lstrip("/")).lower()
    if len(client_pubkey) != 64:
        raise HTTPException(status_code=400, detail="client-pubkey inválido en URI nostrconnect://.")

    qs = parse_qs(parsed.query)
    relays = qs.get("relay", [])
    secret = (qs.get("secret", ["ack"])[0]).strip()
    app_name = (qs.get("name", ["Cliente Nostr"])[0]).strip()

    storage.authorize_client(
        client_pubkey=client_pubkey,
        perms=qs.get("perms", [None])[0],
        metadata={"name": app_name, "flow": "nostrconnect"},
    )

    resp_payload = json.dumps({"id": secrets.token_hex(6), "result": secret})
    encrypted = nip46_encrypt(resp_payload, storage.privkey_hex, client_pubkey, scheme="nip44")
    connect_event = sign_nostr_event(
        {"kind": 24133, "tags": [["p", client_pubkey]], "content": encrypted},
        storage.privkey_hex,
    )

    # Asegurar que los relays del cliente estén en nuestra lista activa y publicar
    current_relays = storage.relays
    new_relays = list(dict.fromkeys(current_relays + relays))
    if new_relays != current_relays:
        storage.set_relays(new_relays)
        await relay_manager.sync_relays()
        await relay_manager.resubscribe_all()

    published = await relay_manager.publish_event(connect_event)
    # También intentar envío directo one-shot a los relays de la URI por si aún están abriendo conexión
    for r_url in relays:
        try:
            async with websockets.connect(r_url, close_timeout=3) as ws:
                await ws.send(json.dumps(["EVENT", connect_event]))
                published += 1
        except Exception:
            pass

    storage.add_log(
        "success",
        "nostrconnect",
        f"Handshake nostrconnect:// enviado a {app_name} ({client_pubkey[:12]}...)",
        {"client_pubkey": client_pubkey, "relays": relays, "published": published},
    )
    return {
        "status": "ok",
        "client_pubkey": client_pubkey,
        "app_name": app_name,
        "published_relays": published,
    }


def main() -> None:
    """Punto de entrada ejecutable (`python -m app.main`)."""
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    print(f"\n🔐 Nostr NIP-46 Remote Signer (Bunker) iniciando en http://{host}:{port}\n")
    uvicorn.run("app.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
