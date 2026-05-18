"""
app.py — Post-Quantum Secure Data Transmission System
Flask REST API

Phases implemented here:
  1  Key Generation      → /api/keygen
  2  Key Encapsulation   ┐
  3  AES-256-GCM Encrypt │
  4  Payload Build       ├→ /api/encrypt-embed
  5  LSB Embed           │
  6  (return stego img)  ┘
  7  Extract + Decrypt   → /api/extract-decrypt
"""

import io
import struct
import base64
import logging
import time

from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
from Crypto.Random import get_random_bytes

import crypto
import steganography

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ─── In-memory key store ──────────────────────────────────────────────────────
_key_store: dict = {}


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — Key Generation
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/keygen", methods=["POST"])
def keygen():
    """Generate ML-KEM-768 keypair and return session metadata."""
    try:
        t0 = time.perf_counter()
        ek, dk = crypto.generate_keypair()
        keygen_time_ms = (time.perf_counter() - t0) * 1000

        session_id = base64.urlsafe_b64encode(get_random_bytes(16)).decode()
        _key_store[session_id] = {"ek": ek, "dk": dk}

        logger.info("Keygen OK — session=%s  ek=%d B  dk=%d B",
                    session_id[:8] + "…", len(ek), len(dk))

        return jsonify({
            "session_id":         session_id,
            "public_key_b64":     base64.b64encode(ek).decode(),
            "public_key_length":  len(ek),
            "private_key_length": len(dk),
            "algorithm":          "ML-KEM-768 (FIPS 203)",
            "security_level":     "NIST Level 3 — 192-bit classical / quantum-safe",
            "keygen_time_ms":     round(keygen_time_ms, 3),
        })

    except Exception as exc:
        logger.exception("Keygen failed")
        return jsonify({"error": str(exc)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# PHASES 2-6 — Encrypt + Embed
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/encrypt-embed", methods=["POST"])
def encrypt_embed():
    """Encapsulate shared secret, encrypt message, embed payload into image."""
    try:
        session_id = request.form.get("session_id", "").strip()
        message    = request.form.get("message", "")
        image_file = request.files.get("image")

        if session_id not in _key_store:
            return jsonify({"error": "Invalid session_id — generate keys first."}), 400
        if not message:
            return jsonify({"error": "Message is empty."}), 400
        if image_file is None:
            return jsonify({"error": "No image file provided."}), 400

        ek = _key_store[session_id]["ek"]

        # Phase 2: Key Encapsulation
        t0 = time.perf_counter()
        shared_secret, kyber_ct = crypto.encapsulate(ek)
        encaps_time_ms = (time.perf_counter() - t0) * 1000

        # Phase 3: AES-256-GCM Encryption
        t1 = time.perf_counter()
        iv, auth_tag, ciphertext = crypto.aes_encrypt(shared_secret, message.encode("utf-8"))
        aes_enc_time_ms = (time.perf_counter() - t1) * 1000

        # Phase 4: Payload Construction
        payload = crypto.build_payload(kyber_ct, iv, auth_tag, ciphertext)

        # Phase 5: LSB Embedding
        cover_img = Image.open(image_file)
        max_bytes = steganography.max_payload_bytes(cover_img)

        if len(payload) > max_bytes:
            return jsonify({
                "error": (
                    f"Image too small. Payload needs {len(payload)} B "
                    f"but image holds {max_bytes} B. Use a larger image."
                )
            }), 400

        stego_img = steganography.embed(cover_img, payload)
        psnr, ssim = steganography.calculate_image_metrics(cover_img, stego_img)

        # Phase 6: Serialise stego image (PNG = lossless, preserves LSBs)
        buf = io.BytesIO()
        stego_img.save(buf, format="PNG")
        stego_b64 = base64.b64encode(buf.getvalue()).decode()

        return jsonify({
            "stego_image_b64":     stego_b64,
            "kyber_ct_length":     len(kyber_ct),
            "payload_bytes":       len(payload),
            "image_capacity_bits": max_bytes * 8,
            "aes_mode":            "AES-256-GCM",
            "iv_b64":              base64.b64encode(iv).decode(),
            "auth_tag_b64":        base64.b64encode(auth_tag).decode(),
            "encaps_time_ms":      round(encaps_time_ms, 3),
            "aes_enc_time_ms":     round(aes_enc_time_ms, 3),
            "psnr":                round(psnr, 2),
            "ssim":                round(ssim, 2),
        })

    except Exception as exc:
        logger.exception("Encrypt-embed failed")
        return jsonify({"error": str(exc)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7 — Extract + Decrypt
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/extract-decrypt", methods=["POST"])
def extract_decrypt():
    """Extract hidden payload from stego-image and decrypt the message."""
    try:
        session_id = request.form.get("session_id", "").strip()
        stego_file = request.files.get("stego_image")

        if session_id not in _key_store:
            return jsonify({"error": "Invalid session_id."}), 400
        if stego_file is None:
            return jsonify({"error": "No stego image provided."}), 400

        dk = _key_store[session_id]["dk"]

        # LSB Extraction — read header first to know full payload size
        stego_img    = Image.open(stego_file)
        header_bytes = steganography.extract(stego_img, crypto.header_size())
        kyber_ct_len, enc_msg_len = struct.unpack(">II", header_bytes)
        total_payload = crypto.header_size() + kyber_ct_len + 12 + 16 + enc_msg_len

        payload = steganography.extract(stego_img, total_payload)

        # Parse payload components
        kyber_ct, iv, auth_tag, ciphertext = crypto.parse_payload(payload)

        # ML-KEM-768 Decapsulation
        t0 = time.perf_counter()
        shared_secret = crypto.decapsulate(dk, kyber_ct)
        decaps_time_ms = (time.perf_counter() - t0) * 1000

        # AES-256-GCM Decryption + Integrity Verification
        t1 = time.perf_counter()
        plaintext = crypto.aes_decrypt(shared_secret, iv, auth_tag, ciphertext)
        aes_dec_time_ms = (time.perf_counter() - t1) * 1000

        return jsonify({
            "message":            plaintext.decode("utf-8"),
            "integrity_verified": True,
            "extraction_success": True,
            "kyber_ct_length":    len(kyber_ct),
            "algorithm":          "ML-KEM-768 + AES-256-GCM + LSB Steganography",
            "decaps_time_ms":     round(decaps_time_ms, 3),
            "aes_dec_time_ms":    round(aes_dec_time_ms, 3),
        })

    except ValueError as exc:
        logger.warning("Integrity check FAILED: %s", exc)
        return jsonify({
            "error":              "Integrity check FAILED — ciphertext has been tampered with!",
            "integrity_verified": False,
            "detail":             str(exc),
        }), 400

    except Exception as exc:
        logger.exception("Extract-decrypt failed")
        return jsonify({"error": str(exc)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# Health Check
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "message": "PQCSecure API is running. Send requests to /api/..."
    })

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status":     "ok",
        "algorithms": ["ML-KEM-768 (FIPS 203)", "AES-256-GCM", "LSB Steganography"],
        "endpoints":  ["/api/keygen", "/api/encrypt-embed", "/api/extract-decrypt"],
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
