"""Tests unitarios y de integración de protocolo para app/nip46.py y app/storage.py."""

import json

from app.crypto import (
    generate_private_key,
    get_public_key,
    nip46_decrypt,
    nip46_encrypt,
    sign_nostr_event,
    verify_nostr_event,
)
from app.nip46 import NIP46Handler
from app.storage import KeyStorage


def _build_client_request_event(
    client_priv: str,
    bunker_pub: str,
    req_id: str,
    method: str,
    params: list,
    scheme: str = "nip44",
) -> dict:
    payload = json.dumps({"id": req_id, "method": method, "params": params})
    encrypted = nip46_encrypt(payload, client_priv, bunker_pub, scheme=scheme)
    tpl = {
        "kind": 24133,
        "tags": [["p", bunker_pub]],
        "content": encrypted,
    }
    return sign_nostr_event(tpl, client_priv)


def test_nip46_connect_and_get_public_key():
    """Verifica el flujo de conexión (`connect`) y obtención de clave pública (`get_public_key`)."""
    storage = KeyStorage()
    identity = storage.generate_new_identity()
    bunker_pub = identity["pubkey_hex"]
    secret = storage.secret

    handler = NIP46Handler(storage, strict_secret=True)
    client_priv = generate_private_key()
    client_pub = get_public_key(client_priv)

    # 1. Intento de connect con secreto inválido debe devolver error
    bad_res = handler.handle_rpc_request(
        client_pub,
        {"id": "req-bad", "method": "connect", "params": [bunker_pub, "wrong-secret"]},
    )
    assert "error" in bad_res and bad_res["error"]

    # 2. Connect con secreto válido (formato NDK / Stacker News: ["", secret] o [bunker_pub, secret])
    good_res = handler.handle_rpc_request(
        client_pub,
        {"id": "req-1", "method": "connect", "params": ["", secret]},
    )
    assert good_res == {"id": "req-1", "result": "ack"}
    assert storage.is_client_authorized(client_pub) is True

    # 3. get_public_key retorna la clave pública hex del usuario
    pk_res = handler.handle_rpc_request(
        client_pub,
        {"id": "req-2", "method": "get_public_key", "params": []},
    )
    assert pk_res == {"id": "req-2", "result": bunker_pub}


def test_nip46_sign_stacker_news_auth_event():
    """
    Simula exactamente el evento de desafío NIP-98 (Kind 27235) que Stacker News
    envía al Bunker durante el inicio de sesión con Nostr.
    """
    storage = KeyStorage()
    identity = storage.generate_new_identity()
    bunker_pub = identity["pubkey_hex"]
    handler = NIP46Handler(storage)

    client_priv = generate_private_key()
    client_pub = get_public_key(client_priv)

    stacker_news_challenge = {
        "kind": 27235,
        "created_at": 1730000000,
        "tags": [
            ["challenge", "8f9d2a1b4c3e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a"],
            ["u", "https://stacker.news"],
            ["method", "GET"],
        ],
        "content": "Stacker News Authentication",
    }

    res = handler.handle_rpc_request(
        client_pub,
        {
            "id": "sn-sign-1",
            "method": "sign_event",
            "params": [json.dumps(stacker_news_challenge)],
        },
    )
    assert "error" not in res
    signed_event = json.loads(res["result"])
    assert signed_event["kind"] == 27235
    assert signed_event["pubkey"] == bunker_pub
    assert signed_event["content"] == "Stacker News Authentication"
    assert verify_nostr_event(signed_event) is True
    assert storage.signed_events_count == 1


def test_nip46_kind24133_end_to_end_nip44_and_nip04():
    """
    Verifica el ciclo completo de un evento Kind 24133 cifrado (tanto NIP-44 como NIP-04):
    Cliente -> Kind 24133 -> Bunker -> Kind 24133 firmado -> Cliente descifra respuesta.
    """
    storage = KeyStorage()
    identity = storage.generate_new_identity()
    bunker_pub = identity["pubkey_hex"]
    handler = NIP46Handler(storage)

    client_priv = generate_private_key()
    client_pub = get_public_key(client_priv)

    for scheme in ("nip44", "nip04"):
        req_event = _build_client_request_event(
            client_priv=client_priv,
            bunker_pub=bunker_pub,
            req_id=f"ping-{scheme}",
            method="ping",
            params=[],
            scheme=scheme,
        )
        resp_event = handler.process_kind24133_event(req_event)
        assert resp_event is not None
        assert resp_event["kind"] == 24133
        assert resp_event["pubkey"] == bunker_pub
        assert ["p", client_pub] in resp_event["tags"]
        assert verify_nostr_event(resp_event) is True

        decrypted_str, detected_scheme = nip46_decrypt(
            resp_event["content"], client_priv, bunker_pub
        )
        assert detected_scheme == scheme
        rpc_resp = json.loads(decrypted_str)
        assert rpc_resp == {"id": f"ping-{scheme}", "result": "pong"}


def test_nip46_switch_relays_and_get_relays():
    """Verifica el soporte de switch_relays (NDK) y get_relays."""
    storage = KeyStorage()
    storage.generate_new_identity()
    handler = NIP46Handler(storage)
    client_pub = get_public_key(generate_private_key())

    sw_res = handler.handle_rpc_request(
        client_pub, {"id": "sw-1", "method": "switch_relays", "params": []}
    )
    assert sw_res == {"id": "sw-1", "result": None}

    gr_res = handler.handle_rpc_request(
        client_pub, {"id": "gr-1", "method": "get_relays", "params": []}
    )
    relays_dict = json.loads(gr_res["result"])
    assert "wss://relay.damus.io" in relays_dict


def test_fastapi_endpoints_and_e2e_simulation(monkeypatch):
    """Verifica los endpoints HTTP de control y el simulador E2E de Stacker News."""
    monkeypatch.setenv("DISABLE_RELAY_WORKERS", "1")
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        # 1. Dashboard y bridge.js sirven correctamente
        dash = client.get("/")
        assert dash.status_code == 200
        assert "Nostr NIP-46 Remote Signer" in dash.text

        bridge = client.get("/static/bridge.js")
        assert bridge.status_code == 200
        assert "window.nostr" in bridge.text

        # 2. Generar nueva identidad
        gen = client.post("/api/identity/generate")
        assert gen.status_code == 200
        gen_data = gen.json()
        assert gen_data["bunker_uri"].startswith("bunker://")
        nsec = gen_data["identity"]["nsec"]
        pubkey = gen_data["identity"]["pubkey_hex"]

        # 3. Cargar identidad existente via nsec
        loaded = client.post("/api/identity/load", json={"key": nsec})
        assert loaded.status_code == 200
        assert loaded.json()["identity"]["pubkey_hex"] == pubkey

        # 4. Llamada al puente RPC (/api/nip46/rpc)
        rpc = client.post(
            "/api/nip46/rpc",
            json={"id": "b-1", "method": "get_public_key", "params": []},
        )
        assert rpc.status_code == 200
        assert rpc.json()["rpc_response"] == {"id": "b-1", "result": pubkey}

        # 5. Simulador E2E Stacker News (connect -> get_public_key -> sign_event Kind 27235)
        sim = client.post("/api/nip46/simulate-stacker-news")
        assert sim.status_code == 200
        sim_data = sim.json()
        assert sim_data["verified_bip340"] is True
        assert sim_data["signed_auth_event"]["kind"] == 27235
        assert sim_data["signed_auth_event"]["pubkey"] == pubkey

