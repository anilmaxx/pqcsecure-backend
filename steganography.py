"""
steganography.py — LSB (Least Significant Bit) Image Steganography

Phase 5 & 7 helper module.

Each byte of the payload is spread across 8 consecutive pixel channels
(R, G, B treated individually) by replacing the least significant bit of
each channel value.  This produces imperceptible visual changes while
embedding arbitrary binary data.

Capacity:  width × height × 3  bits  (one bit per channel)
"""

import numpy as np
from PIL import Image
import skimage.metrics


# ─── Embed ────────────────────────────────────────────────────────────────────

def embed(image: Image.Image, payload: bytes) -> Image.Image:
    """
    Embed *payload* bytes into *image* using 1-bit LSB per channel.

    Parameters
    ----------
    image   : PIL Image (any mode; converted to RGB internally)
    payload : bytes to hide

    Returns
    -------
    PIL Image with payload hidden in pixel LSBs (PNG-safe, lossless)

    Raises
    ------
    ValueError  if the image is too small to hold the payload
    """
    img = image.convert("RGB")
    arr = np.array(img, dtype=np.uint8)

    capacity_bits = arr.size          # total R+G+B values = width*height*3
    required_bits = len(payload) * 8

    if required_bits > capacity_bits:
        raise ValueError(
            f"Image capacity {capacity_bits} bits is smaller than "
            f"payload {required_bits} bits. Use a larger image."
        )

    flat = arr.flatten().copy()
    bit_pos = 0

    for byte in payload:
        for shift in range(7, -1, -1):          # MSB first
            bit = (byte >> shift) & 1
            flat[bit_pos] = (flat[bit_pos] & 0xFE) | bit
            bit_pos += 1

    stego_arr = flat.reshape(arr.shape)
    return Image.fromarray(stego_arr, mode="RGB")


# ─── Extract ─────────────────────────────────────────────────────────────────

def extract(image: Image.Image, num_bytes: int) -> bytes:
    """
    Extract *num_bytes* bytes from the LSBs of *image*.

    Parameters
    ----------
    image     : PIL Image containing a hidden payload
    num_bytes : exact number of bytes to extract

    Returns
    -------
    bytes of length *num_bytes*

    Raises
    ------
    ValueError  if the image does not contain enough pixel data
    """
    img = image.convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    flat = arr.flatten()

    required_bits = num_bytes * 8
    if required_bits > flat.size:
        raise ValueError(
            f"Image has only {flat.size} bits available; "
            f"need {required_bits} bits."
        )

    result = bytearray()
    bit_pos = 0

    for _ in range(num_bytes):
        byte = 0
        for _ in range(8):
            byte = (byte << 1) | (flat[bit_pos] & 1)
            bit_pos += 1
        result.append(byte)

    return bytes(result)


# ─── Utility ──────────────────────────────────────────────────────────────────

def max_payload_bytes(image: Image.Image) -> int:
    """Return the maximum number of bytes that can be hidden in *image*."""
    img = image.convert("RGB")
    arr = np.array(img)
    return arr.size // 8

def calculate_image_metrics(cover_img: Image.Image, stego_img: Image.Image) -> tuple[float, float]:
    """Calculate PSNR and SSIM between the cover and stego images."""
    cover_arr = np.array(cover_img.convert("RGB"))
    stego_arr = np.array(stego_img.convert("RGB"))
    
    psnr = float(skimage.metrics.peak_signal_noise_ratio(cover_arr, stego_arr))
    ssim = float(skimage.metrics.structural_similarity(cover_arr, stego_arr, channel_axis=2))
    
    return psnr, ssim

