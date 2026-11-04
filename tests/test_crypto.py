"""Tests unitarios para app/crypto.py con vectores oficiales BIP-340, NIP-19, NIP-04 y NIP-44."""

import pytest

from app.crypto import (
    compute_event_id,
    generate_private_key,
    get_public_key,
    hex_to_npub,
    hex_to_nsec,
    nip04_decrypt,
    nip04_encrypt,
    nip44_calc_padded_len,
    nip44_decrypt,
    nip44_decrypt_with_key,
    nip44_encrypt,
    nip44_encrypt_with_key,
    nip44_get_conversation_key,
    nip46_decrypt,
    nip46_encrypt,
    normalize_private_key,
    npub_to_hex,
    nsec_to_hex,
    schnorr_sign,
    schnorr_verify,
    sign_nostr_event,
    verify_nostr_event,
)


def test_bip340_official_vector_0():
    """Verifica contra el vector de prueba oficial #0 de Bitcoin BIP-340."""
    seckey = "0000000000000000000000000000000000000000000000000000000000000003"
    expected_pubkey = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    aux_rand = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    msg = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    expected_sig = (
        "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215"
        "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
    )

    assert get_public_key(seckey) == expected_pubkey
    sig = schnorr_sign(msg, seckey, aux_rand=aux_rand)
    assert sig == expected_sig
    assert schnorr_verify(msg, expected_pubkey, sig) is True


def test_bip340_official_vector_1():
    """Verifica contra el vector de prueba oficial #1 de Bitcoin BIP-340 (punto con y impar)."""
    seckey = "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef"
    expected_pubkey = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
    aux_rand = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )
    msg = bytes.fromhex(
        "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89"
    )
    expected_sig = (
        "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de3341"
        "8906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a"
    )

    assert get_public_key(seckey) == expected_pubkey
    sig = schnorr_sign(msg, seckey, aux_rand=aux_rand)
    assert sig == expected_sig
    assert schnorr_verify(msg, expected_pubkey, sig) is True


def test_bech32_nsec_npub_roundtrip():
    """Verifica la codificación y decodificación NIP-19 (nsec y npub)."""
    priv_hex = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"
    expected_nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
    assert hex_to_nsec(priv_hex) == expected_nsec
    assert nsec_to_hex(expected_nsec) == priv_hex
    assert normalize_private_key(expected_nsec) == priv_hex
    assert normalize_private_key(priv_hex) == priv_hex

    pub_hex = get_public_key(priv_hex)
    npub = hex_to_npub(pub_hex)
    assert npub.startswith("npub1")
    assert npub_to_hex(npub) == pub_hex


def test_nostr_event_signing_and_verification():
    """Verifica la serialización NIP-01, el cálculo de ID y la firma del evento."""
    priv_hex = generate_private_key()
    event_tpl = {
        "kind": 27235,
        "created_at": 1714078911,
        "tags": [
            ["challenge", "k1-random-challenge"],
            ["u", "https://stacker.news"],
            ["method", "GET"],
        ],
        "content": "Stacker News Authentication",
    }
    signed = sign_nostr_event(event_tpl, priv_hex)
    assert signed["pubkey"] == get_public_key(priv_hex)
    assert len(signed["id"]) == 64
    assert len(signed["sig"]) == 128
    assert verify_nostr_event(signed) is True

    # Si se altera el contenido, la verificación debe fallar
    tampered = dict(signed, content="Tampered content")
    assert verify_nostr_event(tampered) is False


def test_nip04_encrypt_decrypt():
    """Verifica que el cifrado/descifrado ECDH NIP-04 sea simétrico entre dos pares."""
    alice_priv = generate_private_key()
    alice_pub = get_public_key(alice_priv)
    bob_priv = generate_private_key()
    bob_pub = get_public_key(bob_priv)

    secret_msg = '{"id":"req-1","method":"sign_event","params":["{...}"]}'
    encrypted = nip04_encrypt(secret_msg, alice_priv, bob_pub)
    assert "?iv=" in encrypted

    decrypted = nip04_decrypt(encrypted, bob_priv, alice_pub)
    assert decrypted == secret_msg


def test_nip44_official_vector():
    """Verifica contra el vector de prueba oficial de la especificación NIP-44 v2."""
    sec1 = "0000000000000000000000000000000000000000000000000000000000000001"
    sec2 = "0000000000000000000000000000000000000000000000000000000000000002"
    expected_conv_key = bytes.fromhex(
        "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
    )
    nonce = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )
    plaintext = "a"
    expected_payload = (
        "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD3"
        "5uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"
    )

    pub1 = get_public_key(sec1)
    pub2 = get_public_key(sec2)

    conv_key_12 = nip44_get_conversation_key(sec1, pub2)
    conv_key_21 = nip44_get_conversation_key(sec2, pub1)
    assert conv_key_12 == expected_conv_key
    assert conv_key_21 == expected_conv_key

    payload = nip44_encrypt_with_key(plaintext, conv_key_12, nonce=nonce)
    assert payload == expected_payload
    assert nip44_decrypt_with_key(payload, conv_key_21) == plaintext


def test_nip46_dual_encryption_autodetect():
    """Verifica la autodetección de esquema NIP-04 y NIP-44 en transporte NIP-46."""
    bunker_priv = generate_private_key()
    bunker_pub = get_public_key(bunker_priv)
    client_priv = generate_private_key()
    client_pub = get_public_key(client_priv)

    rpc_msg = '{"id":"123","method":"get_public_key","params":[]}'

    ct_44 = nip46_encrypt(rpc_msg, client_priv, bunker_pub, scheme="nip44")
    plain_44, scheme_44 = nip46_decrypt(ct_44, bunker_priv, client_pub)
    assert plain_44 == rpc_msg
    assert scheme_44 == "nip44"

    ct_04 = nip46_encrypt(rpc_msg, client_priv, bunker_pub, scheme="nip04")
    plain_04, scheme_04 = nip46_decrypt(ct_04, bunker_priv, client_pub)
    assert plain_04 == rpc_msg
    assert scheme_04 == "nip04"


def test_nip44_padded_lengths():
    """Verifica el cálculo de buckets de padding de NIP-44."""
    assert nip44_calc_padded_len(1) == 32
    assert nip44_calc_padded_len(32) == 32
    assert nip44_calc_padded_len(33) == 64
    assert nip44_calc_padded_len(65535) == 65536
    assert nip44_calc_padded_len(65536) == 65536
    assert nip44_calc_padded_len(65537) == 81920
