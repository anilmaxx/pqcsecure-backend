"""
crypto.py — Cryptographic helpers

Encapsulates Phase 2, 3, and 7 logic so app.py stays clean.

Algorithms
----------
- Phase 2 / 7 : ML-KEM-768 (CRYSTALS-Kyber) via kyber-py
                FIPS 203, lattice-based, quantum-safe
- Phase 3 / 7 : AES-256-GCM (authenticated encryption)
                Key = 32-byte shared secret from KEM
"""

import struct
from kyber_py.ml_kem import ML_KEM_768
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ─── Key Generation ───────────────────────────────────────────────────────────

def generate_keypair() -> tuple[bytes, bytes]:
    """
    Phase 1 — Generate ML-KEM-768 keypair.

    Returns
    -------
    (encapsulation_key, decapsulation_key)
        ek : 1184 bytes  (public  — share with sender)
        dk : 2400 bytes  (private — keep on receiver)
    """
    ek, dk = ML_KEM_768.keygen()
    return ek, dk


# ─── Encapsulation (Sender) ───────────────────────────────────────────────────

def encapsulate(ek: bytes) -> tuple[bytes, bytes]:
    """
    Phase 2 — Encapsulate a shared secret using the recipient's public key.

    Parameters
    ----------
    ek : encapsulation key (1184 bytes)

    Returns
    -------
    (shared_secret, kyber_ciphertext)
        shared_secret   : 32 bytes — used as AES-256 key
        kyber_ciphertext: 1088 bytes — sent to recipient
    """
    shared_secret, kyber_ct = ML_KEM_768.encaps(ek)
    return shared_secret, kyber_ct


# ─── Decapsulation (Receiver) ─────────────────────────────────────────────────

def decapsulate(dk: bytes, kyber_ct: bytes) -> bytes:
    """
    Phase 7 — Recover the shared secret from Kyber ciphertext.

    Parameters
    ----------
    dk        : decapsulation key (2400 bytes)
    kyber_ct  : Kyber ciphertext extracted from stego-image

    Returns
    -------
    shared_secret : 32 bytes
    """
    return ML_KEM_768.decaps(dk, kyber_ct)


# ─── AES-256-GCM Encrypt ──────────────────────────────────────────────────────

def aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Phase 3 — Encrypt plaintext with AES-256-GCM.

    Parameters
    ----------
    key       : 32-byte symmetric key (from KEM shared secret)
    plaintext : message bytes

    Returns
    -------
    (iv, auth_tag, ciphertext)
        iv        : 12-byte nonce
        auth_tag  : 16-byte GCM authentication tag
        ciphertext: encrypted message bytes
    """
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)
    return iv, auth_tag, ciphertext


# ─── AES-256-GCM Decrypt ──────────────────────────────────────────────────────

def aes_decrypt(key: bytes, iv: bytes, auth_tag: bytes, ciphertext: bytes) -> bytes:
    """
    Phase 7 — Decrypt and verify AES-256-GCM ciphertext.

    Parameters
    ----------
    key        : 32-byte symmetric key
    iv         : 12-byte nonce
    auth_tag   : 16-byte GCM tag
    ciphertext : encrypted message bytes

    Returns
    -------
    plaintext bytes

    Raises
    ------
    ValueError  if authentication tag does not match (tampered data)
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, auth_tag)


# ─── Payload Construction / Parsing ──────────────────────────────────────────

def build_payload(kyber_ct: bytes, iv: bytes, auth_tag: bytes, ciphertext: bytes) -> bytes:
    """
    Phase 4 — Pack all components into a single binary payload.

    Layout (bytes):
    ┌──────────────┬──────────────┬───────────┬────────┬─────────┬────────────┐
    │ kyber_ct_len │ enc_msg_len  │ kyber_ct  │   IV   │  Tag    │  EncMsg    │
    │   4 bytes    │   4 bytes    │ 1088 B    │  12 B  │  16 B   │  variable  │
    └──────────────┴──────────────┴───────────┴────────┴─────────┴────────────┘
    """
    header = struct.pack(">II", len(kyber_ct), len(ciphertext))
    return header + kyber_ct + iv + auth_tag + ciphertext


def parse_payload(payload: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Phase 7 — Parse binary payload back into components.

    Returns
    -------
    (kyber_ct, iv, auth_tag, ciphertext)
    """
    kyber_ct_len, enc_msg_len = struct.unpack(">II", payload[:8])
    offset = 8
    kyber_ct  = payload[offset : offset + kyber_ct_len];  offset += kyber_ct_len
    iv        = payload[offset : offset + 12];            offset += 12
    auth_tag  = payload[offset : offset + 16];            offset += 16
    ciphertext = payload[offset : offset + enc_msg_len]
    return kyber_ct, iv, auth_tag, ciphertext


def header_size() -> int:
    """Return byte size of the fixed-length payload header."""
    return 8  # 2 × uint32
