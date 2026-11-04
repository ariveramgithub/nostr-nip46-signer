"""
Módulo Criptográfico para Nostr (NIP-01, NIP-04, NIP-19, NIP-44, BIP-340).

Implementa:
- Derivación de claves sobre la curva secp256k1 y firmas Schnorr BIP-340.
- Codificación/decodificación Bech32 NIP-19 (nsec <-> hex, npub <-> hex).
- Cálculo de ID y firma de eventos Nostr (NIP-01).
- Cifrado y descifrado ECDH NIP-04 (AES-256-CBC) y NIP-44 v2 (ChaCha20 + HMAC-SHA256).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import struct
from typing import Any, Literal, Tuple

import bech32
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

# ============================================================================
# Parámetros de la curva secp256k1 (BIP-340)
# ============================================================================
P: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX: int = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY: int = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G: Tuple[int, int] = (GX, GY)

EncryptionScheme = Literal["nip04", "nip44"]


# ============================================================================
# Aritmética de curva elíptica secp256k1 (Coordenadas Jacobianas para velocidad)
# ============================================================================
def _jacobian_double(p: Tuple[int, int, int]) -> Tuple[int, int, int]:
    """Duplica un punto en coordenadas Jacobianas sobre secp256k1."""
    x, y, z = p
    if y == 0 or z == 0:
        return (0, 1, 0)
    y2 = (y * y) % P
    s = (4 * x * y2) % P
    m = (3 * x * x) % P
    nx = (m * m - 2 * s) % P
    ny = (m * (s - nx) - 8 * y2 * y2) % P
    nz = (2 * y * z) % P
    return (nx, ny, nz)


def _jacobian_add(
    p1: Tuple[int, int, int], p2: Tuple[int, int, int]
) -> Tuple[int, int, int]:
    """Suma dos puntos en coordenadas Jacobianas sobre secp256k1."""
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1

    z1z1 = (z1 * z1) % P
    z2z2 = (z2 * z2) % P
    u1 = (x1 * z2z2) % P
    u2 = (x2 * z1z1) % P
    s1 = (y1 * z2 * z2z2) % P
    s2 = (y2 * z1 * z1z1) % P

    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return _jacobian_double(p1)

    h = (u2 - u1) % P
    i = (4 * h * h) % P
    j = (h * i) % P
    r = (2 * (s2 - s1)) % P
    v = (u1 * i) % P

    nx = (r * r - j - 2 * v) % P
    ny = (r * (v - nx) - 2 * s1 * j) % P
    nz = (((z1 + z2) ** 2 - z1z1 - z2z2) * h) % P
    return (nx, ny, nz)


def _from_jacobian(p: Tuple[int, int, int]) -> Tuple[int, int] | None:
    """Convierte un punto de coordenadas Jacobianas a afines (x, y)."""
    x, y, z = p
    if z == 0:
        return None
    z_inv = pow(z, P - 2, P)
    z_inv2 = (z_inv * z_inv) % P
    z_inv3 = (z_inv2 * z_inv) % P
    return ((x * z_inv2) % P, (y * z_inv3) % P)


def _point_mul(pt: Tuple[int, int], scalar: int) -> Tuple[int, int] | None:
    """Multiplicación escalar k * P sobre secp256k1."""
    scalar = scalar % N
    if scalar == 0:
        return None
    result = (0, 1, 0)
    addend = (pt[0], pt[1], 1)
    while scalar > 0:
        if scalar & 1:
            result = _jacobian_add(result, addend)
        addend = _jacobian_double(addend)
        scalar >>= 1
    return _from_jacobian(result)


def _point_add(
    p1: Tuple[int, int] | None, p2: Tuple[int, int] | None
) -> Tuple[int, int] | None:
    """Suma afín de dos puntos sobre secp256k1."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    res = _jacobian_add((p1[0], p1[1], 1), (p2[0], p2[1], 1))
    return _from_jacobian(res)


def _lift_x(x: int) -> Tuple[int, int] | None:
    """Eleva una coordenada x (32 bytes) al punto de la curva con y par (BIP-340)."""
    if x <= 0 or x >= P:
        return None
    c = (pow(x, 3, P) + 7) % P
    y = pow(c, (P + 1) // 4, P)
    if pow(y, 2, P) != c:
        return None
    return (x, y if y % 2 == 0 else P - y)


def _has_even_y(pt: Tuple[int, int]) -> bool:
    return pt[1] % 2 == 0


def _int_to_bytes32(val: int) -> bytes:
    return val.to_bytes(32, byteorder="big")


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def _tagged_hash(tag: str, msg: bytes) -> bytes:
    """Hash etiquetado SHA256(SHA256(tag) || SHA256(tag) || msg) según BIP-340."""
    tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


# ============================================================================
# Gestión de Claves y Bech32 (NIP-19: nsec / npub)
# ============================================================================
def generate_private_key() -> str:
    """Genera una clave privada aleatoria de 32 bytes (hex de 64 caracteres)."""
    while True:
        raw = secrets.token_bytes(32)
        d = _bytes_to_int(raw)
        if 1 <= d < N:
            return raw.hex()


def get_public_key(privkey_hex: str) -> str:
    """Deriva la clave pública x-only (64 caracteres hex) a partir de la clave privada hex."""
    priv_bytes = bytes.fromhex(normalize_private_key(privkey_hex))
    d0 = _bytes_to_int(priv_bytes)
    if not (1 <= d0 < N):
        raise ValueError("La clave privada está fuera del rango válido de secp256k1.")
    pt = _point_mul(G, d0)
    if pt is None:
        raise ValueError("Punto en el infinito inválido.")
    return _int_to_bytes32(pt[0]).hex()


def hex_to_bech32(hex_str: str, hrp: str) -> str:
    """Convierte un string hexadecimal de 32 bytes a formato Bech32 (nsec o npub)."""
    raw = bytes.fromhex(hex_str)
    if len(raw) != 32:
        raise ValueError(f"Se esperaban 32 bytes para {hrp}, se recibieron {len(raw)}.")
    words = bech32.convertbits(raw, 8, 5, True)
    if words is None:
        raise ValueError("Error al convertir bits para Bech32.")
    return bech32.bech32_encode(hrp, words)


def bech32_to_hex(bech_str: str, expected_hrp: str | None = None) -> str:
    """Decodifica una cadena Bech32 (nsec/npub) a su representación hex de 64 caracteres."""
    bech_str = bech_str.strip()
    hrp, data = bech32.bech32_decode(bech_str)
    if hrp is None or data is None:
        raise ValueError("Cadena Bech32 inválida.")
    if expected_hrp and hrp != expected_hrp:
        raise ValueError(f"Prefijo Bech32 inválido: se esperaba '{expected_hrp}', se obtuvo '{hrp}'.")
    decoded = bech32.convertbits(data, 5, 8, False)
    if decoded is None or len(decoded) != 32:
        raise ValueError("Longitud de datos Bech32 inválida.")
    return bytes(decoded).hex()


def hex_to_nsec(privkey_hex: str) -> str:
    """Convierte clave privada hex a formato Bech32 nsec1..."""
    return hex_to_bech32(privkey_hex, "nsec")


def nsec_to_hex(nsec_str: str) -> str:
    """Convierte clave privada Bech32 nsec1... a hex de 64 caracteres."""
    return bech32_to_hex(nsec_str, "nsec")


def hex_to_npub(pubkey_hex: str) -> str:
    """Convierte clave pública hex a formato Bech32 npub1..."""
    return hex_to_bech32(pubkey_hex, "npub")


def npub_to_hex(npub_str: str) -> str:
    """Convierte clave pública Bech32 npub1... a hex de 64 caracteres."""
    return bech32_to_hex(npub_str, "npub")


def normalize_private_key(key_input: str) -> str:
    """
    Acepta una clave privada tanto en formato 'nsec1...' como en hexadecimal (64 chars)
    y retorna siempre el string hexadecimal validado en minúsculas.
    """
    cleaned = key_input.strip()
    if cleaned.startswith("nsec1"):
        hex_key = nsec_to_hex(cleaned)
    else:
        if len(cleaned) != 64:
            raise ValueError("La clave privada debe ser un 'nsec1...' válido o 64 caracteres hex.")
        try:
            bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError("La clave privada hexadecimal contiene caracteres inválidos.") from exc
        hex_key = cleaned.lower()

    d = _bytes_to_int(bytes.fromhex(hex_key))
    if not (1 <= d < N):
        raise ValueError("Clave privada fuera del orden de la curva secp256k1.")
    return hex_key


def normalize_public_key(key_input: str) -> str:
    """
    Acepta una clave pública en formato 'npub1...' o hexadecimal (64 chars)
    y retorna el string hexadecimal validado en minúsculas.
    """
    cleaned = key_input.strip()
    if cleaned.startswith("npub1"):
        hex_key = npub_to_hex(cleaned)
    else:
        if len(cleaned) != 64:
            raise ValueError("La clave pública debe ser un 'npub1...' válido o 64 caracteres hex.")
        bytes.fromhex(cleaned)
        hex_key = cleaned.lower()

    if _lift_x(_bytes_to_int(bytes.fromhex(hex_key))) is None:
        raise ValueError("La clave pública no corresponde a un punto válido en secp256k1.")
    return hex_key


# ============================================================================
# Firmas Digitales Schnorr BIP-340 y Eventos Nostr (NIP-01)
# ============================================================================
def schnorr_sign(
    msg_32: bytes, privkey_hex: str, aux_rand: bytes | None = None
) -> str:
    """
    Firma un mensaje de 32 bytes usando el estándar Schnorr BIP-340.
    Retorna la firma de 64 bytes como string hexadecimal (128 caracteres).
    """
    if len(msg_32) != 32:
        raise ValueError("El mensaje a firmar con BIP-340 debe tener exactamente 32 bytes.")
    d0 = _bytes_to_int(bytes.fromhex(normalize_private_key(privkey_hex)))
    if not (1 <= d0 < N):
        raise ValueError("Clave privada inválida.")

    P_pt = _point_mul(G, d0)
    if P_pt is None:
        raise ValueError("Error al derivar el punto público.")

    d = d0 if _has_even_y(P_pt) else N - d0
    if aux_rand is None:
        aux_rand = secrets.token_bytes(32)
    if len(aux_rand) != 32:
        raise ValueError("aux_rand debe tener 32 bytes.")

    t = d ^ _bytes_to_int(_tagged_hash("BIP0340/aux", aux_rand))
    rand = _tagged_hash(
        "BIP0340/nonce",
        _int_to_bytes32(t) + _int_to_bytes32(P_pt[0]) + msg_32,
    )
    k0 = _bytes_to_int(rand) % N
    if k0 == 0:
        raise RuntimeError("Fallo improbable al generar nonce BIP-340.")

    R = _point_mul(G, k0)
    if R is None:
        raise RuntimeError("Punto R inválido.")

    k = k0 if _has_even_y(R) else N - k0
    e_bytes = _tagged_hash(
        "BIP0340/challenge",
        _int_to_bytes32(R[0]) + _int_to_bytes32(P_pt[0]) + msg_32,
    )
    e = _bytes_to_int(e_bytes) % N
    sig = _int_to_bytes32(R[0]) + _int_to_bytes32((k + e * d) % N)
    return sig.hex()


def schnorr_verify(msg_32: bytes, pubkey_hex: str, sig_hex: str) -> bool:
    """Verifica una firma Schnorr BIP-340 sobre un mensaje de 32 bytes."""
    try:
        if len(msg_32) != 32:
            return False
        pub_bytes = bytes.fromhex(pubkey_hex)
        sig_bytes = bytes.fromhex(sig_hex)
        if len(pub_bytes) != 32 or len(sig_bytes) != 64:
            return False

        P_pt = _lift_x(_bytes_to_int(pub_bytes))
        if P_pt is None:
            return False

        r = _bytes_to_int(sig_bytes[:32])
        s = _bytes_to_int(sig_bytes[32:])
        if r >= P or s >= N:
            return False

        e_bytes = _tagged_hash(
            "BIP0340/challenge",
            sig_bytes[:32] + pub_bytes + msg_32,
        )
        e = _bytes_to_int(e_bytes) % N

        sG = _point_mul(G, s)
        eP = _point_mul(P_pt, N - e)
        R = _point_add(sG, eP)
        if R is None or not _has_even_y(R) or R[0] != r:
            return False
        return True
    except Exception:
        return False


def compute_event_id(
    pubkey: str,
    created_at: int,
    kind: int,
    tags: list[list[str]],
    content: str,
) -> str:
    """
    Calcula el ID canónico (SHA-256 hex) de un evento Nostr según NIP-01:
    [0, <pubkey>, <created_at>, <kind>, <tags>, <content>]
    """
    commitment = [0, pubkey.lower(), int(created_at), int(kind), tags, content]
    serialized = json.dumps(commitment, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def sign_nostr_event(event_template: dict[str, Any], privkey_hex: str) -> dict[str, Any]:
    """
    Completa y firma un evento Nostr (NIP-01) usando la clave privada indicada.
    Calcula `pubkey`, `id` y `sig` retornando un nuevo diccionario listo para transmitir.
    """
    import time

    priv_hex = normalize_private_key(privkey_hex)
    pubkey = get_public_key(priv_hex)
    created_at = int(event_template.get("created_at") or int(time.time()))
    kind = int(event_template["kind"])
    tags = list(event_template.get("tags") or [])
    content = str(event_template.get("content") or "")

    event_id = compute_event_id(pubkey, created_at, kind, tags, content)
    sig = schnorr_sign(bytes.fromhex(event_id), priv_hex)

    return {
        "id": event_id,
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig,
    }


def verify_nostr_event(event: dict[str, Any]) -> bool:
    """Verifica la integridad del ID y la firma Schnorr BIP-340 de un evento Nostr."""
    try:
        expected_id = compute_event_id(
            event["pubkey"],
            int(event["created_at"]),
            int(event["kind"]),
            event.get("tags", []),
            event.get("content", ""),
        )
        if expected_id != event.get("id"):
            return False
        return schnorr_verify(
            bytes.fromhex(expected_id),
            event["pubkey"],
            event["sig"],
        )
    except Exception:
        return False


# ============================================================================
# ECDH secp256k1 (Compartido para NIP-04 y NIP-44)
# ============================================================================
def compute_shared_secret(privkey_hex: str, peer_pubkey_hex: str) -> bytes:
    """
    Calcula la coordenada X de 32 bytes (sin hash) del punto compartido ECDH
    entre `privkey_hex` y la clave pública x-only `peer_pubkey_hex`.
    Utiliza OpenSSL (cryptography) para velocidad nativa y validación de curva.
    """
    priv_int = _bytes_to_int(bytes.fromhex(normalize_private_key(privkey_hex)))
    peer_bytes = bytes.fromhex(peer_pubkey_hex.strip().lower())
    if len(peer_bytes) != 32:
        raise ValueError("La clave pública del par debe tener 32 bytes (64 hex).")
    if _lift_x(_bytes_to_int(peer_bytes)) is None:
        raise ValueError("La clave pública del par no está en la curva secp256k1.")

    priv_key = ec.derive_private_key(priv_int, ec.SECP256K1())
    compressed_pub = b"\x02" + peer_bytes
    pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), compressed_pub)
    shared_x = priv_key.exchange(ec.ECDH(), pub_key)
    return shared_x


# ============================================================================
# Cifrado NIP-04 (AES-256-CBC con ?iv=)
# ============================================================================
def nip04_encrypt(
    plaintext: str, privkey_hex: str, peer_pubkey_hex: str, iv: bytes | None = None
) -> str:
    """Cifra un texto plano usando NIP-04 (AES-256-CBC) y retorna '<ct_b64>?iv=<iv_b64>'."""
    shared_key = compute_shared_secret(privkey_hex, peer_pubkey_hex)
    if iv is None:
        iv = secrets.token_bytes(16)
    if len(iv) != 16:
        raise ValueError("El IV para NIP-04 debe tener 16 bytes.")

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    ct_b64 = base64.b64encode(ciphertext).decode("ascii")
    iv_b64 = base64.b64encode(iv).decode("ascii")
    return f"{ct_b64}?iv={iv_b64}"


def nip04_decrypt(payload: str, privkey_hex: str, peer_pubkey_hex: str) -> str:
    """Descifra un payload en formato NIP-04 ('<ct_b64>?iv=<iv_b64>')."""
    if "?iv=" not in payload:
        raise ValueError("Formato NIP-04 inválido: falta el separador '?iv='.")
    ct_b64, iv_b64 = payload.split("?iv=", 1)
    ciphertext = base64.b64decode(ct_b64)
    iv = base64.b64decode(iv_b64)
    if len(iv) != 16:
        raise ValueError("Longitud de IV inválida en NIP-04.")

    shared_key = compute_shared_secret(privkey_hex, peer_pubkey_hex)
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plain) + unpadder.finalize()
    return plaintext.decode("utf-8")


# ============================================================================
# Cifrado NIP-44 v2 (HKDF-SHA256 + ChaCha20 + HMAC-SHA256)
# ============================================================================
def nip44_calc_padded_len(unpadded_len: int) -> int:
    """Calcula la longitud con padding según la especificación oficial NIP-44 v2."""
    if unpadded_len <= 0:
        raise ValueError("Longitud de texto plano inválida para NIP-44.")
    if unpadded_len <= 32:
        return 32
    next_power = 1 << (int(math.floor(math.log2(unpadded_len - 1))) + 1)
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * (((unpadded_len - 1) // chunk) + 1)


def nip44_pad(plaintext: str) -> bytes:
    """Aplica el prefijo de longitud y padding de ceros según NIP-44 v2."""
    unpadded = plaintext.encode("utf-8")
    unpadded_len = len(unpadded)
    if unpadded_len < 1 or unpadded_len > 0xFFFFFFFF:
        raise ValueError("Longitud de texto plano fuera de rango para NIP-44.")
    if unpadded_len >= 65536:
        prefix = b"\x00\x00" + struct.pack(">I", unpadded_len)
    else:
        prefix = struct.pack(">H", unpadded_len)
    padded_len = nip44_calc_padded_len(unpadded_len)
    return prefix + unpadded + (b"\x00" * (padded_len - unpadded_len))


def nip44_unpad(padded: bytes) -> str:
    """Remueve y valida el padding de un bloque descifrado según NIP-44 v2."""
    if len(padded) < 34:
        raise ValueError("Padding NIP-44 inválido (demasiado corto).")
    first_two = struct.unpack(">H", padded[:2])[0]
    if first_two == 0:
        if len(padded) < 6:
            raise ValueError("Padding extendido NIP-44 inválido.")
        unpadded_len = struct.unpack(">I", padded[2:6])[0]
        if unpadded_len < 65536:
            raise ValueError("Prefijo extendido inválido en NIP-44.")
        prefix_len = 6
    else:
        unpadded_len = first_two
        prefix_len = 2

    expected_total = prefix_len + nip44_calc_padded_len(unpadded_len)
    if unpadded_len == 0 or len(padded) != expected_total:
        raise ValueError("Longitud de bloque con padding inválida en NIP-44.")

    unpadded = padded[prefix_len : prefix_len + unpadded_len]
    padding_tail = padded[prefix_len + unpadded_len :]
    if any(b != 0 for b in padding_tail):
        raise ValueError("Bytes de padding no nulos en NIP-44.")
    return unpadded.decode("utf-8")


def nip44_get_conversation_key(privkey_hex: str, peer_pubkey_hex: str) -> bytes:
    """Deriva la conversation_key de 32 bytes usando HKDF-extract(salt='nip44-v2', IKM=shared_x)."""
    shared_x = compute_shared_secret(privkey_hex, peer_pubkey_hex)
    return HKDF.extract(hashes.SHA256(), salt=b"nip44-v2", key_material=shared_x)


def nip44_get_message_keys(
    conversation_key: bytes, nonce: bytes
) -> Tuple[bytes, bytes, bytes]:
    """Deriva (chacha_key, chacha_nonce, hmac_key) usando HKDF-expand (76 bytes)."""
    if len(conversation_key) != 32:
        raise ValueError("conversation_key debe tener 32 bytes.")
    if len(nonce) != 32:
        raise ValueError("nonce debe tener 32 bytes.")
    keys = HKDFExpand(algorithm=hashes.SHA256(), length=76, info=nonce).derive(
        conversation_key
    )
    return keys[0:32], keys[32:44], keys[44:76]


def _chacha20_crypt(key: bytes, nonce_12: bytes, data: bytes) -> bytes:
    """Ejecuta ChaCha20 IETF (RFC 8439) con contador inicial 0 según NIP-44 v2."""
    full_nonce = struct.pack("<I", 0) + nonce_12
    cipher = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None)
    cryptor = cipher.encryptor()
    return cryptor.update(data) + cryptor.finalize()


def nip44_encrypt(
    plaintext: str,
    privkey_hex: str,
    peer_pubkey_hex: str,
    nonce: bytes | None = None,
) -> str:
    """Cifra un texto plano usando el estándar moderno NIP-44 v2."""
    conv_key = nip44_get_conversation_key(privkey_hex, peer_pubkey_hex)
    return nip44_encrypt_with_key(plaintext, conv_key, nonce=nonce)


def nip44_encrypt_with_key(
    plaintext: str, conversation_key: bytes, nonce: bytes | None = None
) -> str:
    """Cifra un texto plano dada una conversation_key de 32 bytes (NIP-44 v2)."""
    if nonce is None:
        nonce = secrets.token_bytes(32)
    chacha_key, chacha_nonce, hmac_key = nip44_get_message_keys(conversation_key, nonce)
    padded = nip44_pad(plaintext)
    ciphertext = _chacha20_crypt(chacha_key, chacha_nonce, padded)
    mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    raw_payload = b"\x02" + nonce + ciphertext + mac
    return base64.b64encode(raw_payload).decode("ascii")


def nip44_decrypt(payload: str, privkey_hex: str, peer_pubkey_hex: str) -> str:
    """Descifra un payload NIP-44 v2 usando la clave privada local y la pública remota."""
    conv_key = nip44_get_conversation_key(privkey_hex, peer_pubkey_hex)
    return nip44_decrypt_with_key(payload, conv_key)


def nip44_decrypt_with_key(payload: str, conversation_key: bytes) -> str:
    """Descifra un payload NIP-44 v2 dada una conversation_key de 32 bytes."""
    if not payload or payload.startswith("#"):
        raise ValueError("Versión de payload NIP-44 no soportada.")
    if len(payload) < 132:
        raise ValueError("Tamaño de payload NIP-44 inválido (demasiado corto).")

    raw = base64.b64decode(payload)
    if len(raw) < 99:
        raise ValueError("Datos decodificados NIP-44 demasiado cortos.")
    version = raw[0]
    if version != 2:
        raise ValueError(f"Versión NIP-44 desconocida: {version}")

    nonce = raw[1:33]
    ciphertext = raw[33:-32]
    mac = raw[-32:]

    chacha_key, chacha_nonce, hmac_key = nip44_get_message_keys(conversation_key, nonce)
    expected_mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, mac):
        raise ValueError("MAC inválido en payload NIP-44.")

    padded = _chacha20_crypt(chacha_key, chacha_nonce, ciphertext)
    return nip44_unpad(padded)


# ============================================================================
# Envoltorio Dual NIP-04 / NIP-44 para Transporte NIP-46 (Kind 24133)
# ============================================================================
def nip46_decrypt(
    payload: str, privkey_hex: str, peer_pubkey_hex: str
) -> Tuple[str, EncryptionScheme]:
    """
    Detecta automáticamente el esquema de cifrado (NIP-04 o NIP-44) de un evento Kind 24133,
    descifra el contenido y retorna `(plaintext, scheme)`.
    """
    if "?iv=" in payload:
        return nip04_decrypt(payload, privkey_hex, peer_pubkey_hex), "nip04"
    try:
        return nip44_decrypt(payload, privkey_hex, peer_pubkey_hex), "nip44"
    except Exception:
        return nip04_decrypt(payload, privkey_hex, peer_pubkey_hex), "nip04"


def nip46_encrypt(
    plaintext: str,
    privkey_hex: str,
    peer_pubkey_hex: str,
    scheme: EncryptionScheme = "nip44",
) -> str:
    """Cifra un mensaje JSON-RPC NIP-46 usando el esquema indicado ('nip44' o 'nip04')."""
    if scheme == "nip04":
        return nip04_encrypt(plaintext, privkey_hex, peer_pubkey_hex)
    return nip44_encrypt(plaintext, privkey_hex, peer_pubkey_hex)
