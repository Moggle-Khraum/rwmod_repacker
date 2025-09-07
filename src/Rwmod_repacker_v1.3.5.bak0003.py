# ===========================================================================
# ============================= IMPORTS =====================================
# ===========================================================================
from __future__ import annotations
import os, io, json, time, mmap, random, string, webbrowser
import logging, hashlib, threading, tempfile, zipfile, hmac
import tkinter as tk, traceback

from datetime import datetime
from pathlib import Path
from typing import Optional, Union, Callable, List, Tuple
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Lock
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk

# Splash Screen
from splashScreen import show_splash


# ===========================================================================
# ========================== HYBRID CONFIGURATION ===========================
# ===========================================================================

# Define the config directory and file paths
CONFIG_DIR = "config"
HISTORY_FILE = os.path.join(CONFIG_DIR, "history_log.txt")
THEME_FILE = os.path.join(CONFIG_DIR, "theme_settings.json")

# ------------------ Tunables / Defaults ------------------
DEFAULT_FAKE_LAYERS = 2 #Default is 7
DEFAULT_PAD_MIN = 2048
DEFAULT_PAD_MAX = 65536

# Hybrid read thresholds (global, tunable)
STREAM_THRESHOLD = 50 * 1024 * 1024     # 50 MB - stream instead of single read
MMAP_THRESHOLD = 200 * 1024 * 1024      # 200 MB - use mmap for very large reads
STREAM_CHUNK_SIZE = 8 * 1024 * 1024     # 8 MB chunk for streaming

# For ZIP creation (per-file threshold to use mmap when zipping)
ZIP_MMAP_THRESHOLD = 50 * 1024 * 1024   # 50 MB

# ICON paths (optional)
ICON_PATHS = {
    'ico': 'app_icon.ico',
    'png': 'app_icon.png'
}

# Global variables
history_log = []
open_popups = []


# ===========================================================================
# ============================ HYBRID UTILITIES =============================
# ===========================================================================

# ------------------- SPLASH SCREEN ------------------------
def show_splash_and_start(main_app_func, splash_image="logo.png", icon_path="logo.ico", duration=2500):
    splash = tk.Tk()
    splash.overrideredirect(True)
    splash.configure(bg="white")


    # set icon
    if os.path.exists(icon_path):
        try:
            splash.iconbitmap(icon_path)
        except Exception:
            pass


    # load splash PNG
    if os.path.exists(splash_image):
        img = Image.open(splash_image)
        logo = ImageTk.PhotoImage(img)
        w, h = img.size
    else:
        logo = None
        w, h = 400, 200


    # center window
    sw, sh = splash.winfo_screenwidth(), splash.winfo_screenheight()
    x, y = (sw - w) // 2, (sh - h) // 2
    splash.geometry(f"{w}x{h}+{x}+{y}")


    if logo:
        label = tk.Label(splash, image=logo, bg="white")
        label.image = logo
        label.pack(expand=True, fill="both")
    else:
        label = tk.Label(splash, text="Loading RWMod Repacker...", font=("Arial", 16), bg="white")
        label.pack(expand=True, fill="both")


    def close_splash():
        time.sleep(duration / 1000)
        splash.destroy()
        main_app_func()


    threading.Thread(target=close_splash, daemon=True).start()
    splash.mainloop()

# --------------------- SAFE OPEN PATH ------------------------
def safe_open(path, mode="r"):
    """
    Opens a text file safely:
    - Tries UTF-8 first
    - Falls back to Latin-1 if UTF-8 fails
    """
    if "b" in mode:
        # Binary mode unchanged
        return open(path, mode)
    try:
        return open(path, mode, encoding="utf-8")
    except UnicodeDecodeError:
        return open(path, mode, encoding="latin-1", errors="replace")

# ------------------ Hybrid readers ------------------
def smart_file_read(path: str) -> bytes:
    """Binary hybrid reader: small -> read(); medium -> chunked stream; large -> mmap."""
    file_size = os.path.getsize(path)
    if file_size < STREAM_THRESHOLD:
        with open(path, "rb") as f:
            return f.read()
    elif file_size < MMAP_THRESHOLD:
        data = bytearray()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(STREAM_CHUNK_SIZE)
                if not chunk:
                    break
                data.extend(chunk)
        return bytes(data)
    else:
        with open(path, "rb") as f:
            with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                return mm.read()

# ------------------ packerRW-style byte ops & helpers ------------------
def xor_bytes(b: bytes, key: int) -> bytes: return bytes([x ^ key for x in b])
def add_bytes(b: bytes, val: int) -> bytes: return bytes([(x + val) & 0xFF for x in b])
def rol_byte(x: int, n: int) -> int: return ((x << n) | (x >> (8 - n))) & 0xFF
def rol_bytes(b: bytes, n: int) -> bytes: return bytes([rol_byte(x, n) for x in b])
def apply_ops_sequence(data: bytes, ops: list) -> bytes:
    for op, param in ops:
        if op == "XOR": data = xor_bytes(data, param)
        elif op == "ADD": data = add_bytes(data, param)
        elif op == "ROL": data = rol_bytes(data, param)
    return data

# ------------------ small ZIP helpers ------------------
def make_zip_with_file(entry_name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(entry_name, data)
    return buf.getvalue()

def pad_bytes_to_random_size(data: bytes, min_size: int, max_size: int, rng: random.Random) -> bytes:
    target = rng.randint(min_size, max_size)
    if len(data) >= target: return data
    return data + os.urandom(target - len(data))

# ------------------ ZIP creation (RAM-friendly) ------------------
def zip_folder_hybrid(folder_path: str, temp_zip_path: str,
                      zip_mmap_threshold: int = ZIP_MMAP_THRESHOLD,
                      progress: Optional[Callable[[float], None]] = None) -> None:
    files_to_zip = []
    for root, _, files in os.walk(folder_path):
        for f in files:
            files_to_zip.append(os.path.join(root, f))
    total = len(files_to_zip)
    os.makedirs(os.path.dirname(temp_zip_path) or '.', exist_ok=True)
    with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        if total == 0:
            if progress: progress(1.0)
            return
        for i, path in enumerate(files_to_zip):
            arcname = os.path.relpath(path, folder_path)
            size = os.path.getsize(path)
            if size > zip_mmap_threshold:
                with open(path, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    zf.writestr(arcname, mm)
            else:
                zf.write(path, arcname)
            if progress:
                progress((i + 1) / max(1, total))

# ------------------ RWMod helpers (streamed hash, empty shell) ------------------
def _stream_sha3_512(path: str) -> bytes:
    h = hashlib.sha3_512()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.digest()


# ------ build invisible zip shell
def _make_invisible_zip_shell_bytes() -> bytes:
    """
    Minimal EOCD marker for reference. We don’t actually use this to
    write junk inside — it’s here in case you need a clean ZIP signature.
    """
    return (
        b"\x50\x4b\x05\x06"  # EOCD signature
        b"\x00\x00"          # number of this disk
        b"\x00\x00"          # disk with start of central directory
        b"\x00\x00"          # total # of entries on this disk
        b"\x00\x00"          # total # of entries
        b"\x00\x00\x00\x00"  # size of central directory
        b"\x00\x00\x00\x00"  # offset of central directory
        b"\x00\x00"          # .ZIP file comment length
    )

# ------ build invisible poly layer
def _build_invisible_poly_layer(seed: bytes, target_kb: int) -> bytes:
    rng = random.Random(int.from_bytes(seed[:16], "big"))
    target = max(256, target_kb * 1024)

    header = get_header_sig(file_data=seed)[:rng.randint(16, 64)]
    sig    = mutable_signature(base=b"layer_sig", seed=seed)

    base    = os.urandom(rng.randint(128, 512))
    chaffed = encrypt_with_chaff(base, seed)
    poly    = polymorphic_encoder(os.urandom(rng.randint(128, 512)), seed)

    body = header + sig + chaffed + poly
    if len(body) < target:
        body += os.urandom(target - len(body))

    footer = get_footer_sig(file_data=seed)[:rng.randint(12, 40)]
    return body + footer

#------ Proportional Pad Size
def _proportional_pad_size(payload_len: int, seed: bytes, min_ratio: float = 0.20, max_ratio: float = 0.50) -> int:
    rng = random.Random(int.from_bytes(hashlib.blake2b(seed, digest_size=16).digest(), "big"))
    ratio = min_ratio + (max_ratio - min_ratio) * rng.random()
    return int(payload_len * ratio)

# ------ WRAPPER FOR INVISIBLE SHELL
def wrap_with_invisible_shell(zip_bytes: bytes, seed: bytes, min_ratio: float = 0.20, max_ratio: float = 0.50) -> bytes:
    rng = random.Random(int.from_bytes(seed[:16], "big"))

    pre_hdr = get_header_sig(file_data=seed)[:rng.randint(24, 64)]
    pre_sig = mutable_signature(base=b"invisible_shell", seed=seed)

    total_pad = _proportional_pad_size(len(zip_bytes), seed, min_ratio, max_ratio)
    split = 0.4 + (seed[0] % 21) / 100.0
    layer1 = _build_invisible_poly_layer(seed, target_kb=max(1, int((total_pad * split) / 1024)))

    rem = max(0, total_pad - len(layer1))
    layer2 = b""
    if rem > 0 and (seed[1] & 1):
        layer2 = _build_invisible_poly_layer(hashlib.sha3_256(seed + b"\x01").digest(), target_kb=max(1, rem // 1024))

    pre_trl = get_footer_sig(file_data=hashlib.sha3_256(seed + b"tail").digest())[:rng.randint(16, 40)]
    prelude = pre_hdr + pre_sig + layer1 + layer2 + pre_trl

    return prelude + zip_bytes


# ===========================================================================
# ============================= PACKING/OBFUSCATION =========================
# ===========================================================================

class RepackerConfig:
    def __init__(self):
        self.min_junk_size = 24
        self.max_junk_size = 81

        self.min_decoy_blocks = 10
        self.max_decoy_blocks = 50
        self.obfuscation_level = "medium"

    def get_junk_size(self):
    # Only "beyond" level is allowed
        if self.obfuscation_level == "medium":
            return random.randint(24, 81)
        else:
            raise ValueError("Invalid obfuscation level: only 'beyond' is supported")

# Header
def get_header_sig(file_data: bytes = None) -> bytes:
    if file_data:
        seed = hashlib.sha3_512(file_data).digest()[:16]
    else:
        seed = os.urandom(16)

    rng = random.Random(int.from_bytes(seed, "big"))

    patterns = [
        lambda: bytes([rng.randint(0x80, 0xFF), 0x50 + rng.randint(0, 15),
                       0x4E + rng.choice([0, 1, -1]), rng.choice([0x47, 0x46, 0x48]),
                       0x0D, 0x0A, rng.choice([0x1A, 0x1B, 0x1C]),
                       rng.choice([0x00, 0x0A, 0xFF])]),

        lambda: bytes([0x50, 0x4B, rng.choice([0x03, 0x05, 0x07]), 0x04,
                       rng.randint(0x10, 0x20), 0x00, 0x00,
                       rng.choice([0x08, 0x00])]),

        lambda: bytes([rng.randint(0x80, 0xEF), rng.randint(0x20, 0x7F),
                       rng.randint(0x00, 0x1F), rng.randint(0xC0, 0xFF),
                       rng.choice([0x00, 0xFF]), rng.randint(0x10, 0xF0)])
    ]

    header = bytearray(rng.choice(patterns)())

    def mutate_byte(b: int) -> int:
        b ^= 0xFF
        b = (b + rng.randint(1, 255)) % 256
        b = (b - rng.randint(1, 255)) % 256
        b = (b * rng.randint(2, 255)) % 256
        b = (b // rng.randint(1, 255)) % 256
        b = rng.randint(0, 255)
        return b

    # Always apply 5 mutations to header
    for _ in range(5):
        pos = rng.randint(0, len(header)-1)
        header[pos] = mutate_byte(header[pos])

    # Generate trailer
    trailer_len = rng.randint(2, 8)
    trailer = bytearray([rng.randint(0, 255) for _ in range(trailer_len)])

    # Always apply 5 mutations per trailer byte
    for i in range(len(trailer)):
        for _ in range(5):
            trailer[i] = mutate_byte(trailer[i])

    # Insert trailer randomly
    if rng.random() > 0.7:
        insert_pos = rng.randint(1, len(header)-1)
        header = header[:insert_pos] + trailer + header[insert_pos:]
    else:
        header += trailer

    return bytes(header)


# Footer
def get_footer_sig(file_data: Optional[bytes] = None) -> bytes:
    if file_data:
        seed = hashlib.sha3_512(file_data).digest()[:16]
    else:
        seed = os.urandom(16)
    rng = random.Random(int.from_bytes(seed, "big"))

    # Base patterns
    patterns = [
        lambda: (
            ''.join(rng.choices(string.ascii_letters + string.digits, k=rng.randint(8, 16))).encode('ascii')
            + rng.choice([b"--", b"~~", b"||", b"::", b"$$"])
            + bytes([rng.randint(32, 126) for _ in range(rng.randint(8, 16))])
            + rng.choice([b"\x00\x00", b"\xFF\xFF", b"\xFE\xFE", b"\x01\x01"])
        ),
        lambda: (
            bytes([rng.randint(0x80, 0xFF) for _ in range(rng.randint(6, 12))])
            + bytes([rng.randint(0x00, 0x7F) for _ in range(rng.randint(4, 8))])
            + rng.choice([b"\x55\xAA", b"\xAA\x55", b"\xC3\x3C"])
        )
    ]

    footer = bytearray(rng.choice(patterns)())

    # Define mutation types
    mutations = [
        "xor",
        "swap",
        "rotate",
        "multiply_mod",
        "divide_mod",
        "insert"
    ]

    # Shuffle order based on seed
    rng.shuffle(mutations)

    # Apply all mutations in shuffled order
    for mutation in mutations:
        if mutation == "xor":
            for pos in range(len(footer)):
                footer[pos] ^= 0xFF

        elif mutation == "swap":
            for pos in range(len(footer) - 1):
                footer[pos], footer[pos+1] = footer[pos+1], footer[pos]

        elif mutation == "rotate":
            for pos in range(len(footer)):
                shift = rng.randint(1, 7)
                if shift < 0:
                    shift = -shift
                footer[pos] = ((footer[pos] << shift) | (footer[pos] >> (8 - shift))) & 0xFF

        elif mutation == "multiply_mod":
            mul = rng.randint(2, 15)
            for pos in range(len(footer)):
                footer[pos] = (footer[pos] * mul) % 256

        elif mutation == "divide_mod":
            div = rng.randint(2, 15)
            for pos in range(len(footer)):
                footer[pos] = (footer[pos] // div) % 256

        elif mutation == "insert":
            new_footer = bytearray()
            for pos in range(len(footer)):
                new_footer.append(footer[pos])
                if len(new_footer) < 100 and rng.random() < 0.2:
                    new_footer.append(rng.randint(0, 255))
            footer = new_footer

    return bytes(footer)


# Mutable Signature
def mutable_signature(base: Union[bytes, str], seed: Optional[bytes] = None, heavy: bool = True) -> bytes:
    # Initialize RNG
    if seed:
        rng = random.Random(int.from_bytes(seed, "big"))
    else:
        rng = random.Random()

    # Normalize base input
    base_bytes = base.encode("utf-8") if isinstance(base, str) else base

    # Create deterministic hash
    base_hash = hashlib.sha256(base_bytes).digest()

    # Noise length depends on hash
    noise_len = (base_hash[0] % 32) + 16

    # Select unified noise pattern
    noise_pattern = rng.randint(0, 3)
    if noise_pattern == 0:  # Pure random
        noise = bytes([rng.randint(0, 255) for _ in range(noise_len)])
    elif noise_pattern == 1:  # Printable characters
        chars = string.ascii_letters + string.digits + string.punctuation
        noise = ''.join(rng.choices(chars, k=noise_len)).encode('ascii')
    elif noise_pattern == 2:  # Arithmetic progression
        start = rng.randint(0, 255)
        step = rng.choice([1, -1, 2, -2, 5])
        noise = bytes([(start + i * step) % 256 for i in range(noise_len)])
    else:  # XOR sequence
        key = rng.randint(1, 255)
        base_val = rng.randint(0, 255)
        noise = bytes([(base_val + i) % 256 ^ key for i in range(noise_len)])

    # Insert noise (random split or embed)
    insertion_point = rng.randint(0, len(base_bytes))
    if rng.random() > 0.5:
        signature = bytearray(base_bytes[:insertion_point] + noise + base_bytes[insertion_point:])
    else:
        noise_before = noise[:rng.randint(0, len(noise))]
        noise_after = noise[len(noise_before):]
        signature = bytearray(noise_before + base_bytes + noise_after)

    # Number of transformation passes
    passes = rng.randint(8, 15) if heavy else rng.randint(3, 6)

    for _ in range(passes):
        transform_type = rng.randint(0, 9)
        pos = rng.randint(0, len(signature) - 1)

        if transform_type == 0:  # XOR with mask
            mask = rng.randint(1, 255)
            signature[pos] ^= mask

        elif transform_type == 1:  # Swap range
            if len(signature) > 4:
                start = rng.randint(0, len(signature) - 2)
                end = min(len(signature), start + rng.randint(2, 8))
                chunk = signature[start:end]
                chunk.reverse()
                signature[start:end] = chunk

        elif transform_type == 2:  # Rotate left
            shift = rng.randint(1, 7)
            signature[pos] = ((signature[pos] << shift) | (signature[pos] >> (8 - shift))) & 0xFF

        elif transform_type == 3:  # Rotate right
            shift = rng.randint(1, 7)
            signature[pos] = ((signature[pos] >> shift) | (signature[pos] << (8 - shift))) & 0xFF

        elif transform_type == 4:  # Insert random byte
            if len(signature) < 256:
                signature.insert(pos, rng.randint(0, 255))

        elif transform_type == 5:  # Delete byte
            if len(signature) > 8:
                del signature[pos]

        elif transform_type == 6:  # Multiply modulo
            factor = rng.randint(2, 15)
            signature[pos] = (signature[pos] * factor) % 256

        elif transform_type == 7:  # Divide modulo
            divisor = rng.randint(1, 15)
            signature[pos] = (signature[pos] // divisor) % 256

        elif transform_type == 8:  # Chunk shuffle
            if len(signature) > 12:
                size = rng.randint(3, 6)
                i = rng.randint(0, len(signature) - size)
                j = rng.randint(0, len(signature) - size)
                if i != j:
                    chunk_i = signature[i:i+size]
                    chunk_j = signature[j:j+size]
                    signature[i:i+size], signature[j:j+size] = chunk_j, chunk_i

        elif transform_type == 9:  # Overwrite with hash fragment
            frag = hashlib.md5(signature).digest()
            signature[pos] = frag[rng.randint(0, len(frag)-1)]

    # Final remix pass (scramble globally if heavy mode)
    if heavy and len(signature) > 32:
        rng.shuffle(signature)

    return bytes(signature)


# Mutable Hex Key
def mutable_hex_key(seed: Optional[Union[int, bytes, str]] = None) -> bytes:
    # --- Seeded RNG ---
    if seed is None:
        rng = random.Random(int.from_bytes(os.urandom(8), "big"))
    else:
        seed_bytes = str(seed).encode("utf-8") if not isinstance(seed, (bytes, bytearray)) else seed
        rng = random.Random(int.from_bytes(hashlib.sha3_256(seed_bytes).digest()[:8], "big"))

    # --- Select key pattern ---
    key_type = rng.randint(0, 5)

    # --- KeyType 0: Random + single checksum ---
    if key_type == 0:
        key = bytearray([rng.randint(0, 255) for _ in range(8)])
        checksum = sum(key) % 256
        key.append(checksum)
        return bytes(key)

    # --- KeyType 1: Header + body + checksum + trailer ---
    elif key_type == 1:
        header = bytes([rng.randint(0xA0, 0xAF)])
        key = bytes([rng.randint(0, 255) for _ in range(6)])
        checksum = (sum(key) + header[0]) % 256
        trailer = bytes([rng.randint(0xC0, 0xCF)])
        return header + key + bytes([checksum]) + trailer

    # --- KeyType 2: XOR protected ---
    elif key_type == 2:
        key = bytearray([rng.randint(0, 255) for _ in range(8)])
        xor_key = rng.randint(1, 255)
        for i in range(len(key)):
            key[i] ^= xor_key
        key.append(xor_key)
        return bytes(key)

    # --- KeyType 3: Dual checksum (parity based) ---
    elif key_type == 3:
        key = bytearray([rng.randint(0, 255) for _ in range(8)])
        checksum1 = sum(key) % 256
        checksum2 = (sum(key[::2]) - sum(key[1::2])) % 256
        key.append(checksum1)
        key.append(checksum2)
        return bytes(key)

    # --- KeyType 4: Division & modulo mutations ---
    elif key_type == 4:
        base = [rng.randint(1, 255) for _ in range(8)]
        div_mod = rng.randint(2, 10)
        transformed = [(x * rng.randint(2, 5)) % div_mod for x in base]
        checksum = sum(transformed) % 256
        return bytes(transformed + [checksum])

    # --- KeyType 5: Multiply & rotate ---
    else:
        base = [rng.randint(0, 255) for _ in range(8)]
        factor = rng.randint(2, 7)
        rotated = [(base[(i - 1) % 8] * factor) % 256 for i in range(8)]
        checksum = (sum(rotated) ^ factor) % 256
        trailer = rng.randint(0, 255)
        return bytes(rotated + [checksum, trailer])

# Secret Key
def get_secret_key(epoch: int = 2025, pid: Optional[int] = None) -> bytes:
    pid = pid if pid is not None else os.getpid()

    # --- Stronger seeding material ---
    # Combine epoch, PID, time, randomness, and hardware-level entropy
    seed_material = (
        f"{epoch}-{pid}-{time.time_ns()}-{os.urandom(16).hex()}"
    ).encode()

    # Hash it multiple times with different digests for diffusion
    digest1 = hashlib.sha3_512(seed_material).digest()
    digest2 = hashlib.blake2b(digest1, digest_size=32).digest()
    digest3 = hashlib.shake_256(digest2).digest(32)

    # Use part of digest3 as RNG seed
    rand = random.Random(int.from_bytes(digest3[:16], "big"))

    # Derive initial key from mutable_hex_key using digest3
    key = bytearray(mutable_hex_key(seed=digest3))

    # --- Strengthening transformations ---
    mask = rand.randint(1, 255)
    rotate = rand.randint(1, len(key))
    xor_key = digest2[rand.randint(0, len(digest2) - 1)]

    for i in range(len(key)):
        key[i] ^= mask
        key[i] ^= xor_key
        key[i] = ((key[i] << 1) | (key[i] >> 7)) & 0xFF  # bit rotation

    # --- Shuffle bytes deterministically based on digest1 ---
    rand.shuffle(key)

    # --- Append integrity tag (HMAC) ---
    hmac_tag = hmac.new(digest1, key, hashlib.sha3_256).digest()[:4]
    key.extend(hmac_tag)

    return bytes(key)


# Encrypt with Chaffing
def encrypt_with_chaff(real_data: bytes, seed: bytes) -> bytes:
    rng = random.Random(int.from_bytes(hashlib.blake2b(seed, digest_size=16).digest(), "big"))

    # --- Copy real data ---
    data = bytearray(real_data)

    # --- Dynamic chaff insertion ---
    chaff_amount = rng.randint(10, 30)  # more noise, harder to detect
    for _ in range(chaff_amount):
        pos = rng.randint(0, len(data))
        chaff_length = rng.randint(2, 16)  # longer, varied chunks
        chaff_data = os.urandom(chaff_length)
        # Mix in deterministic noise from seed for consistency
        salted = hashlib.sha3_256(seed + chaff_data).digest()[:chaff_length]
        mixed_chaff = bytes(a ^ b for a, b in zip(chaff_data, salted))
        data[pos:pos] = mixed_chaff

    # --- Stronger key schedule ---
    base_key = hashlib.sha3_512(seed).digest()
    key_stream = hashlib.shake_256(base_key).digest(len(data))  # full-length stream

    # --- XOR with keystream ---
    encrypted = bytearray(len(data))
    for i, byte in enumerate(data):
        encrypted[i] = byte ^ key_stream[i]

    # --- Append HMAC (integrity & authenticity check) ---
    hmac_tag = hmac.new(base_key, encrypted, hashlib.blake2s).digest()[:16]
    encrypted.extend(hmac_tag)

    return bytes(encrypted)

# Create obfuscation_layer
# ------------------ FUSED Interleaved Hybrid Builder ------------------
# This new function combines the cycle-based polymorphic layers with the
# original script's create_obfuscation_layers function. It still
# uses the old name.

def build_hybrid_layers(
    payload_folder: str,
    out_file: str,
    *,
    pad_min: int = DEFAULT_PAD_MIN,
    pad_max: int = DEFAULT_PAD_MAX,
    callback: Optional[Callable[[str, float], None]] = None
) -> None:
    """
    Build .rwmod using the invisible shell strategy:
    - Payload folder is zipped normally.
    - An obfuscation prelude (headers + polymorphic garbage) is generated.
    - The real ZIP is appended intact.
    - A small footer is added.
    File size only increases ~20–50%.
    """

    if callback: callback("zip", 0.0)

    # Step 1: Create the payload ZIP
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        temp_zip = tmp.name
    try:
        zip_folder_hybrid(
            payload_folder,
            temp_zip,
            ZIP_MMAP_THRESHOLD,
            progress=(lambda p: callback and callback("zip", p)),
        )
        if callback: callback("zip", 1.0)

        # Step 2: Compute content-based seed
        content_hash_seed = _stream_sha3_512(temp_zip)

        # Step 3: Read the real ZIP into memory
        with open(temp_zip, "rb") as f:
            zip_bytes = f.read()

        # Step 4: Wrap with invisible shell
        wrapped = wrap_with_invisible_shell(
            zip_bytes,
            seed=content_hash_seed,
            min_ratio=0.10,  # 10% padding
            max_ratio=0.25   # up to 25% padding
        )

        # Step 5: Write final obfuscated rwmod file
        os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
        with open(out_file, "wb") as out:
            out.write(wrapped)

        if callback:
            callback("finalize", 1.0)

    finally:
        try:
            os.remove(temp_zip)
        except Exception:
            pass


# Polymorphic Encoder
def polymorphic_encoder(data: bytes, seed: bytes) -> bytes:
    rng = random.Random(int.from_bytes(seed, "big"))

    # === 1. XOR Layer ===
    key_len = 2 + (int.from_bytes(seed[:1], "big") % 7)  # 2–8
    key = hashlib.sha256(seed).digest()[:key_len]
    xor_stage = bytearray()
    for i, byte in enumerate(data):
        xor_stage.append(byte ^ key[i % key_len])

    # === 2. Block Shuffle Layer ===
    block_size = [2, 4, 8][seed[1] % 3]
    shuffle_stage = bytearray()
    for i in range(0, len(xor_stage), block_size):
        block = bytearray(xor_stage[i:i+block_size])
        if (seed[i % len(seed)] & 1) == 0:
            block.reverse()
        else:
            rng.shuffle(block)
        shuffle_stage.extend(block)

    # === 3. Add/Sub Transform ===
    key_val = (seed[2] % 254) + 1
    addsub_stage = bytearray()
    for b in shuffle_stage:
        if b & 1:
            addsub_stage.append((b + key_val) % 256)
        else:
            addsub_stage.append((b - key_val) % 256)

    # === 4. Bit Rotation Layer ===
    shift = abs((seed[3] % 7) + 1)
    rotate_stage = bytearray()
    for b in addsub_stage:
        rotate_stage.append(((b << shift) | (b >> (8 - shift))) & 0xFF)

    # === 5. Combo Layer (XOR + Rotate + Reverse Blocks) ===
    final_key = (seed[4] % 254) + 1
    step1 = bytearray([b ^ final_key for b in rotate_stage])

    shift2 = (seed[5] % 7) + 1
    step2 = bytearray([((b << shift2) | (b >> (8 - shift2))) & 0xFF for b in step1])

    block_size2 = [2, 4][seed[6] % 2]
    final = bytearray()
    for i in range(0, len(step2), block_size2):
        block = step2[i:i+block_size2]
        final.extend(block[::-1])

    return bytes(final)


# ---------------------------
# ====== ZIP / PACKING ======
# ---------------------------

def zip_folder(folder_path: str, zip_path: str, callback: Optional[Callable[[float], None]] = None) -> None:
    """
    Compress folder to ZIP with mmap support on large files.
    callback(progress: float) where progress in [0.0, 1.0]
    """
    if not os.path.exists(folder_path):
        raise FileNotFoundError(f"Folder not found: {folder_path}")
    files_to_zip = []
    try:
        for root, _, files in os.walk(folder_path):
            for f in files:
                files_to_zip.append(os.path.join(root, f))
    except PermissionError as e:
        raise Exception(f"Permission denied accessing {folder_path}: {e}")
    total = len(files_to_zip)
    os.makedirs(os.path.dirname(zip_path) or '.', exist_ok=True)
    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            if total == 0:
                if callback: callback(1.0)
                return
            for i, path in enumerate(files_to_zip):
                try:
                    arcname = os.path.relpath(path, folder_path)
                    size = os.path.getsize(path)
                    if size > 50 * 1024 * 1024:
                        # memory-map large file for efficient writing
                        with open(path, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                            zf.writestr(arcname, mm)
                    else:
                        zf.write(path, arcname)
                except Exception as e:
                    logger.warning("Skipping %s: %s", path, e)
                    continue
                if callback:
                    callback((i + 1) / total)
    except Exception as e:
        if os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except Exception:
                pass
        raise

#--------------- Tamper Zip
def tamper_zip_with_obfuscation(zip_path: str, rwmod_path: str, callback=None, config=None):
    build_hybrid_layers(
        payload_folder=zip_path,
        out_file=rwmod_path,
        callback=(lambda stage, p: callback and callback(p))
    )


# ------------------ GUI wrapper ------------------
def pack_as_rwmod(folder_path: str, rwmod_path: str,
                  callback: Optional[Callable[[str, float], None]] = None):
    # Change this line to call the new hybrid function
    build_hybrid_layers(
        payload_folder=folder_path,
        out_file=rwmod_path,
        callback=callback
    )

# ===========================================================================
# ========================== CONFIG / HISTORY ===============================
# ===========================================================================

# ------------ LOADS HISTORY ------------------------
def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


def save_history(history):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)


def clear_history():
    if not os.path.exists(HISTORY_FILE):
        messagebox.showinfo("Info", "History is already empty.")
        return
    if messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete all history logs?\nThis action cannot be undone.", icon="warning"):
        try:
            os.remove(HISTORY_FILE)
            history_log.clear()
            messagebox.showinfo("Success", "History cleared successfully.")
        except OSError as e:
            messagebox.showerror("Error", f"Could not delete history file: {e}")

def add_to_log(folder_name_value: str, output_path: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    checksum = calculate_sha256(output_path)
    entry = {
        "timestamp": ts,
        "folder": folder_name_value,
        "output": output_path,
        "checksum": checksum
        }
    history = load_history()
    history.insert(0, entry)
    save_history(history)


def view_selected(lb):
    sel = lb.curselection()
    if not sel:
        messagebox.showinfo("View History", "No entry selected.")
        return
    index = sel[0]
    text = lb.get(index)
    messagebox.showinfo("History Entry", text)


def delete_selected(lb):
    sel = lb.curselection()
    if not sel:
        messagebox.showwarning("Delete History", "No entry selected.")
        return
    to_delete = [lb.get(i) for i in sel]
    history = load_history()
    new_history = []
    for entry in history:
        entry_text = f"{entry['timestamp']} | {entry['folder']}"
        if not any(entry_text in d for d in to_delete):
            new_history.append(entry)
    save_history(new_history)
    for i in reversed(sel):
        lb.delete(i)


def clear_all():
    if messagebox.askyesno("Clear History", "Are you sure you want to clear all history?"):
        save_history([])
        messagebox.showinfo("History", "All history cleared.")

# ------------ THEMES -------------
def save_theme(theme_id):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    try:
        with open(THEME_FILE, 'w') as f:
            json.dump({"theme_id": theme_id}, f)
    except IOError as e:
        logger.warning("Error saving theme settings: %s", e)


def load_theme():
    if not os.path.exists(THEME_FILE):
        return "clam"
    try:
        with safe_open(THEME_FILE, "r") as f:
            settings = json.load(f)
            return settings.get("theme_id", "clam")
    except (json.JSONDecodeError, IOError):
        return "clam"


# ===========================================================================
# ============================= GUI HELPERS =================================
# ===========================================================================
# ---------------- CENTER WINDOW FUNCTION ----------------

# makes the Main Window to spawn in Center
def center_window(win, width, height):
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    win.geometry(f"{width}x{height}+{x}+{y}")

# Helps in Selecting Folder
def select_folder():
    folder = filedialog.askdirectory()
    if folder:
        folder_entry.delete(0, tk.END)
        folder_entry.insert(0, folder)
        folder_name.set(f"FOLDER: {os.path.basename(folder)}")
        modinfo_path = os.path.join(folder, "mod-info.txt")
        modinfo_text.configure(state='normal')
        modinfo_text.delete('1.0', tk.END)
        if os.path.exists(modinfo_path):
            try:
                with safe_open(modinfo_path, "r") as f:
                    modinfo_text.insert(tk.END, f.read())
            except Exception as e:
                modinfo_text.insert(tk.END, f"[⚠️ Error reading mod-info.txt: {e}]")

        else:
            modinfo_text.insert(tk.END, "📜 No mod-info.txt found.")
        modinfo_text.configure(state='disabled')

# Helps in Selecting Output
def select_output():
    output = filedialog.askdirectory()
    if output:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, output)

# Buttton State
def set_pack_button_state(enabled: bool):
    try:
        if enabled:
            pack_button.state(["!disabled"])
        else:
            pack_button.state(["disabled"])
    except Exception:
        pass


# Replace your existing calculate_sha256 with this streaming version
def calculate_sha256(file_path: str) -> str:
    """Calculates the SHA-256 hash of a file by streaming it in chunks."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192): # Read in 8KB chunks
                h.update(chunk)
    except Exception as e:
        return f"Error: {e}"
    return h.hexdigest()

# ===========================================================================
# ============================= PACKING FLOW (GUI) ==========================
# ===========================================================================

def run_packing_flow():
    if pack_button['state'] == 'disabled':
        return
    set_pack_button_state(False)
    progress_bar["value"] = 0
    progress_zip["value"] = 0
    progress_poly["value"] = 0
    
    last_update_time = time.time()
    watchdog_event = threading.Event()
    def update_status(main_msg, sub_msg=""):
        def do_update():
            status_label_main.config(text=main_msg)
            status_label_sub.config(text=sub_msg)
        root.after(0, do_update)
    def watchdog_thread():
        while not watchdog_event.is_set():
            if time.time() - last_update_time > 100:
                root.after(0, lambda: messagebox.showerror("Error", "The program has frozen.\n\nPlease restart the application."))
                root.after(0, lambda: set_pack_button_state(True))
                break
            time.sleep(2)
    def packing_thread():
        nonlocal last_update_time
       # DELETE the old progress_callback function and REPLACE it with this:
        def progress_callback(stage, progress):
            overall_progress = 0

            if stage == "zip":
                progress_zip["value"] = progress * 100
                if progress >= 1.0:
                    progress_zip["value"] = 100  # snap to 100%
                overall_progress = progress * 30

            elif stage == "poly":
                progress_poly["value"] = progress * 100
                if progress >= 1.0:
                    progress_poly["value"] = 100
                overall_progress = 30 + (progress * 40)

            elif stage == "finalize":
                progress_finalize["value"] = progress * 100
                if progress >= 1.0:
                    progress_finalize["value"] = 100
                overall_progress = 95 + (progress * 5)

            # ensure overall bar doesn’t get stuck below 100
            progress_bar["value"] = min(overall_progress, 100)
            if stage == "finalize" and progress >= 1.0:
                progress_bar["value"] = 100

            root.update_idletasks()

  
        try:
            update_status("⚙ Initializing...", "🎲 Preparing to pack...")
            folder_path = folder_entry.get().strip()
            output_dir = output_entry.get().strip() or os.path.expanduser("~")
            if not folder_path or not os.path.isdir(folder_path):
                raise ValueError("Please select a valid folder to pack.")
            modname = os.path.basename(folder_path.rstrip("/\\"))
            rwmod_path = os.path.join(output_dir, modname + ".rwmod")
            # call unified pack function (accepts callback(stage, progress))
            pack_as_rwmod(folder_path, rwmod_path, callback=progress_callback)
            add_to_log(modname, rwmod_path)
            update_status("✅ Packing Complete!", f"Saved To: {os.path.basename(output_dir)}")
            show_success_popup(folder_path, rwmod_path)
            
        except Exception as e:
            tb = traceback.format_exc()
            print(tb)  # <-- prints the real traceback in the console
            update_status("⚙️ FOLDER ERROR", "⚠ Please select a VALID folder to begin.")
            messagebox.showerror("Packing Error", f"An error occurred:\n\n{e}\n\n")

        finally:
            watchdog_event.set()
            def reset_ui():
                folder_entry.delete(0, tk.END)
                output_entry.delete(0, tk.END)
                folder_name.set("📁 FOLDER: (NONE)")
                modinfo_text.config(state='normal')
                modinfo_text.delete("1.0", tk.END)
                modinfo_text.config(state='disabled')
                progress_bar["value"] = 0
                progress_zip["value"] = 0
                progress_poly["value"] = 0
                progress_finalize["value"] = 0
                update_status("⚙️ Ready and waiting...", "⏳ Select a folder to begin.")
                set_pack_button_state(True)
            root.after(0, reset_ui)
    threading.Thread(target=packing_thread, daemon=True).start()
    threading.Thread(target=watchdog_thread, daemon=True).start()

# ===========================================================================
# ============================= THEME MANAGEMENT ============================
# ===========================================================================

def create_custom_themes(style):
    # Modern Dark
    if "modern_dark" not in style.theme_names():
        style.theme_create("modern_dark", parent="clam", settings={
            "TFrame": {"configure": {"background": "#2e2e2e"}},
            "TLabel": {"configure": {"background": "#2e2e2e", "foreground": "white"}},
            "TButton": {"configure": {"background": "#444444", "foreground": "white"}},
            "TEntry": {"configure": {"fieldbackground": "#3c3c3c", "foreground": "white"}},
            # Special title label style
            "Title.TLabel": {"configure": {"foreground": "#00ccff", "background": "#2e2e2e", "font": ("Segoe UI", 18, "bold")}},
            # Accent button for Pack
            "Accent.TButton": {"configure": {"background": "#3399ff", "foreground": "white", "font": ("Segoe UI", 12, "bold")}}
    })


    # Modern Light
    if "modern_light" not in style.theme_names():
        style.theme_create("modern_light", parent="clam", settings={
            "TFrame": {"configure": {"background": "#f8f8f8"}},
            "TLabel": {"configure": {"background": "#f8f8f8", "foreground": "black"}},
            "TButton": {"configure": {"background": "#e0e0e0", "foreground": "black"}},
            "TEntry": {"configure": {"fieldbackground": "#ffffff", "foreground": "black"}},
            # Special title label style
            "Title.TLabel": {"configure": {"foreground": "#4a4a4a", "background": "#f8f8f8", "font": ("Segoe UI", 18, "bold")}},
            # Accent button for Pack
            "Accent.TButton": {"configure": {"background": "#4a4a4a", "foreground": "white", "font": ("Segoe UI", 12, "bold")}}
    })


    # RWMod Blue
    if "rwmod_blue" not in style.theme_names():
        style.theme_create("rwmod_blue", parent="clam", settings={
            "TFrame": {"configure": {"background": "#1e2a38"}},
            "TLabel": {"configure": {"background": "#1e2a38", "foreground": "white"}},
            "TButton": {"configure": {"background": "#2e4a62", "foreground": "white"}},
            "TEntry": {"configure": {"fieldbackground": "#2a3f55", "foreground": "white"}},
            # Special title label style
            "Title.TLabel": {"configure": {"foreground": "#66ccff", "background": "#1e2a38", "font": ("Segoe UI", 18, "bold")}},
            # Accent button for Pack
            "Accent.TButton": {"configure": {"background": "#66ccff", "foreground": "#1e2a38", "font": ("Segoe UI", 12, "bold")}}
    })

    
    # Twilight
    if "twilight" not in style.theme_names():
        style.theme_create("twilight", parent="clam", settings={
            "TFrame": {"configure": {"background": "#2c3e50"}},
            "TLabel": {"configure": {"background": "#2c3e50", "foreground": "#ecf0f1"}},
            "TButton": {"configure": {"background": "#34495e", "foreground": "#ecf0f1"}},
            "TEntry": {"configure": {"fieldbackground": "#34495e", "foreground": "#ecf0f1"}},
            # Special title label style
            "Title.TLabel": {"configure": {"foreground": "#7fffd4", "background": "#2c3e50", "font": ("Segoe UI", 18, "bold")}},
            # Accent button for Pack
            "Accent.TButton": {"configure": {"background": "#66ccff", "foreground": "#34495e", "font": ("Segoe UI", 12, "bold")}}
    })


  # Sunshine
    if "sunshine" not in style.theme_names():
        style.theme_create("sunshine", parent="clam", settings={
            "TFrame": {"configure": {"background": "#f39c12"}},
            "TLabel": {"configure": {"background": "#f39c12", "foreground": "#2c3e50"}},
            "TButton": {"configure": {"background": "#e67e22", "foreground": "#2c3e50"}},
            "TEntry": {"configure": {"fieldbackground": "#e67e22", "foreground": "#2c3e50"}},
            # Special title label style
            "Title.TLabel": {"configure": {"foreground": "#ffffff", "background": "#f39c12", "font": ("Segoe UI", 18, "bold")}},
            # Accent button for Pack
            "Accent.TButton": {"configure": {"background": "#d35400", "foreground": "white", "font": ("Segoe UI", 12, "bold")}}
    })


    # RWMod Midnight
    if "rwmod_midnight" not in style.theme_names():
        style.theme_create("rwmod_midnight", parent="clam", settings={
            "TFrame": {"configure": {"background": "#0a0a1a"}},
            "TLabel": {"configure": {"background": "#0a0a1a", "foreground": "#a0a0c0"}},
            "TButton": {"configure": {"background": "#151530", "foreground": "#a0a0c0"}},
            "TEntry": {"configure": {"fieldbackground": "#151530", "foreground": "#a0a0c0"}},
            # Special title label style
            "Title.TLabel": {"configure": {"foreground": "#66ccff", "background": "#0a0a1a", "font": ("Segoe UI", 18, "bold")}},
            # Accent button for Pack
            "Accent.TButton": {"configure": {"background": "#336699", "foreground": "white", "font": ("Segoe UI", 12, "bold")}}
    })


    if "darken_gray" not in style.theme_names():
        style.theme_create("darken_gray", parent="clam", settings={
            "TFrame": {"configure": {"background": "#1a1a1a"}},
            "TLabel": {"configure": {"background": "#1a1a1a", "foreground": "#cccccc"}},
            "TButton": {"configure": {"background": "#333333", "foreground": "#cccccc"}},
            "TEntry": {"configure": {"fieldbackground": "#333333", "foreground": "#cccccc"}},
            # Special title label style
            "Title.TLabel": {"configure": {"foreground": "#00ccff", "background": "#1a1a1a", "font": ("Segoe UI", 18, "bold")}},
            # Accent button for Pack
            "Accent.TButton": {"configure": {"background": "#006666", "foreground": "white", "font": ("Segoe UI", 12, "bold")}}
    })

    # RWMod Core
    if "rwmod_core" not in style.theme_names():
        style.theme_create("rwmod_core", parent="clam", settings={
            "TFrame": {"configure": {"background": "#1e1e1e"}},   # main bg
            "TLabel": {"configure": {"background": "#1e1e1e", "foreground": "white"}},  # labels
            "TButton": {"configure": {"background": "#e1e1e1", "foreground": "black"}}, # buttons
            "TEntry": {"configure": {"fieldbackground": "#ffffff", "foreground": "black"}}, # entry fields
            # Special title label style
            "Title.TLabel": {"configure": {"foreground": "#00ff88", "background": "#1e1e1e", "font": ("Segoe UI", 18, "bold")}},
            # Accent button for Pack
            "Accent.TButton": {"configure": {"background": "#008080", "foreground": "white", "font": ("Segoe UI", 12, "bold")}
            }
        })


    # Azure Sky
    if "azure_sky" not in style.theme_names():
        style.theme_create("azure_sky", parent="clam", settings={
            # Backgrounds
            "TFrame": {"configure": {"background": "#e6f4ff"}},   # light sky blue background
            "TLabel": {"configure": {"background": "#e6f4ff", "foreground": "#003366"}},  # deep blue text
            "TButton": {"configure": {"background": "#99ccff", "foreground": "#003366"}}, # softer button
            "TEntry": {"configure": {"fieldbackground": "#ffffff", "foreground": "#003366"}},
            # Title
            "Title.TLabel": {"configure": {"foreground": "#0066cc", "background": "#e6f4ff", "font": ("Segoe UI", 18, "bold")}},
            # Accent Button
            "Accent.TButton": {"configure": {"background": "#3399ff", "foreground": "white", "font": ("Segoe UI", 12, "bold")}
        }
    })

def is_dark_color(hex_color: str) -> bool:
    hex_color = hex_color.lstrip("#")
    if len(hex_color) != 6:
        return False
    r, g, b = (int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    brightness = (0.299*r + 0.587*g + 0.114*b)
    return brightness < 128

def apply_radio_style(bg, text_color):
    style.configure("Custom.TRadiobutton",
                    background=bg,
                    foreground=text_color,
                    font=("Segoe UI", 10))

def refresh_styles():
    big_button_style = ttk.Style()
    big_button_style.configure("Big.TButton", font=("Segoe UI", 12, "bold"))

def apply_progressbar_style(style, bg):
    try:
        accent = style.lookup("TButton", "background") or "#1e90ff"
    except tk.TclError:
        accent = "#1e90ff"
    style.configure("Accent.Horizontal.TProgressbar",
                    background=accent,
                    troughcolor=bg)

def register_popup(win: tk.Toplevel):
    open_popups.append(win)
    win.bind("<Destroy>", lambda e: open_popups.remove(win) if win in open_popups else None)

def _apply_text_widget_theme(style: ttk.Style):
    try:
        bg = style.lookup('TFrame', 'background') or '#f0f0f0'
        fg = style.lookup('TLabel', 'foreground') or 'black'
    except tk.TclError:
        bg, fg = '#f0f0f0', 'black'
    if is_dark_color(bg):
        border_color = "white"
        text_color = "white"
    else:
        border_color = "black"
        text_color = "black"
    try:
        root.configure(bg=bg)
    except Exception:
        pass
    apply_radio_style(bg, text_color)
    apply_progressbar_style(style, bg)
    for win in open_popups:
        try:
            win.configure(bg=bg)
        except Exception:
            pass
        for child in win.winfo_children():
            if isinstance(child, tk.LabelFrame):
                child.configure(bg=bg, fg=text_color,
                                highlightbackground=border_color,
                                highlightcolor=border_color)
            elif isinstance(child, tk.Label):
                child.configure(bg=bg, fg=text_color)
            elif isinstance(child, tk.Entry):
                child.configure(bg=bg, fg=text_color, insertbackground=text_color)
            elif isinstance(child, tk.Button):
                child.configure(bg=bg, fg=text_color)


def apply_theme(theme_id: str):
    try:
        style.theme_use(theme_id)
        save_theme(theme_id)
        _apply_text_widget_theme(style)
        refresh_styles()
    except tk.TclError as e:
        messagebox.showerror("Theme Error", f"Could not apply theme '{theme_id}':\n{e}")

# ===========================================================================
# ============================= POPUPS / HISTORY ============================
# ===========================================================================

# ------- SHOW THEME SELECTOR -------
def show_theme_selector():
    popup = tk.Toplevel(root)
    register_popup(popup)
    popup.title("Theme Selector [Beta]")
    popup.geometry("430x350")
    popup.resizable(False, False)
    try:
        popup.iconbitmap(ICON_PATHS['ico'])
    except Exception:
        pass

    # Calculate x and y coordinates for centering
    root_x = root.winfo_x()
    root_y = root.winfo_y()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    
    popup_width = 430
    popup_height = 350

    x = root_x + (root_width - popup_width) // 2
    y = root_y + (root_height - popup_height) // 2
    
    popup.geometry(f"{popup_width}x{popup_height}+{x}+{y}")
    
    popup.transient(root)
    popup.grab_set()
    ttk.Label(popup, text="🎨 Theme Selector", font=("Segoe UI", 16, "bold")).pack(pady=10)
    ttk.Label(popup, text="Click a theme to apply instantly:", font=("Segoe UI", 11)).pack(pady=4)
    custom_labelframe = tk.LabelFrame(popup, text="Custom Themes", padx=12, pady=12, bd=2, relief="groove", font=("Segoe UI", 10, "bold"))
    custom_labelframe.pack(fill="x", padx=15, pady=12)
    custom_themes = [
        ("modern_dark", "Modern Dark"),
        ("modern_light", "Modern Light"),
        ("rwmod_core", "RWMod Core"),
        ("rwmod_blue", "RWMod Blue"),
        ("rwmod_midnight", "RWMod Midnight"),
        ("sunshine", "Sunshine"),
        ("darken_gray", "Darken Gray"),
        ("azure_sky", "Azure Sky"),
        ("twilight","Twilight")
    ]
    current_theme = style.theme_use()
    custom_var = tk.StringVar(value=current_theme)
    for i, (theme_id, theme_name) in enumerate(custom_themes):
        rb = ttk.Radiobutton(custom_labelframe, text=theme_name, value=theme_id, variable=custom_var, style="Custom.TRadiobutton", command=lambda t=theme_id: apply_theme(t))
        rb.grid(row=i // 3, column=i % 3, sticky="w", padx=12, pady=10)
    ttk.Button(popup, text="❌Close", style="Big.TButton", takefocus=0, command=popup.destroy).pack(pady=18)
    refresh_styles()
    _apply_text_widget_theme(style)




# ----- SHOW HISTORY POPUP -------
def show_history_popup():
    history = load_history()
    win = tk.Toplevel(root)
    win.title("History Log")
    win.transient(root)
    win.resizable(False, False)
    win.grab_set()

    try:
        win.iconbitmap(ICON_PATHS['ico'])
    except Exception:
        pass

    # Calculate x and y coordinates for centering
    root_x = root.winfo_x()
    root_y = root.winfo_y()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    
    popup_width = 550
    popup_height = 520

    x = root_x + (root_width - popup_width) // 2
    y = root_y + (root_height - popup_height) // 2
    
    win.geometry(f"{popup_width}x{popup_height}+{x}+{y}")
    
    bg = style.lookup("TFrame", "background") or "#f0f0f0"
    fg = style.lookup("TLabel", "foreground") or "black"
    entry_bg = style.lookup("TEntry", "fieldbackground") or "white"
    entry_fg = style.lookup("TEntry", "foreground") or "black"
    win.configure(bg=bg)
    title = ttk.Label(win, text="📜 History Log", font=("Segoe UI", 14, "bold"))
    title.pack(pady=8)
    list_frame = ttk.Frame(win, padding=8)
    list_frame.pack(fill="both", expand=True, padx=12, pady=8)
    lb = tk.Listbox(list_frame, selectmode="extended", bg=entry_bg, fg=entry_fg, selectbackground=fg, selectforeground=bg, font=("Segoe UI", 10))
    lb.pack(fill="both", expand=True, side="left")
    scrollbar = ttk.Scrollbar(list_frame, command=lb.yview)
    scrollbar.pack(side="right", fill="y")
    lb.config(yscrollcommand=scrollbar.set)
    for i, entry in enumerate(reversed(history), 1):
        lb.insert("end", f"{i}. {entry['timestamp']} | {entry['folder']}")
    ctl = ttk.Frame(win, padding=8)
    ctl.pack(fill="x", padx=12, pady=8)
    for text, cmd, side in [
        ("🔍 View", lambda: view_selected(lb), "left"),
        ("🗑 Delete Selected", lambda: delete_selected(lb), "left"),
        ("❌ Close", win.destroy, "right"),
    ]:
        b = ttk.Button(ctl, text=text, style="Big.TButton", takefocus=0, command=cmd)
        b.pack(side=side, padx=6, pady=4)
    for frame in (list_frame, ctl):
        frame.configure(style="TFrame")
    _apply_text_widget_theme(style)


# ------------ SHOW SUCCESS POPUP -------
def show_success_popup(origin_folder, output_file):
    popup = tk.Toplevel(root)
    popup.title("Repacking Complete")
    popup.geometry("400x200")
    popup.resizable(False, False)

    # Center on screen
    popup.update_idletasks()
    w, h = 400, 200
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    x, y = (sw - w) // 2, (sh - h) // 2
    popup.geometry(f"{w}x{h}+{x}+{y}")

    # Labels
    tk.Label(popup, text="⏳ Repacking to .RWMOD is Complete!", font=("Segoe UI", 12, "bold")).pack(pady=(10,5))
    tk.Label(popup, text=f"📂 Origin Folder:\n{origin_folder}", wraplength=380, justify="left").pack(pady=(0,10))
    tk.Label(popup, text=f"💾 Saved File:\n{output_file}", wraplength=380, justify="left").pack(pady=(0,10))

    # Button frame
    btn_frame = tk.Frame(popup)
    btn_frame.pack(pady=10)

    def locate_file():
        import subprocess, os
        if os.name == "nt":  # Windows
            subprocess.Popen(f'explorer /select,"{output_file}"')
        else:  # Linux/Mac fallback
            subprocess.Popen(["xdg-open", os.path.dirname(output_file)])
        popup.destroy()

    tk.Button(btn_frame, text="📂 Locate Saved File", command=locate_file, width=18).grid(row=0, column=0, padx=5)
    tk.Button(btn_frame, text="❌ Close", command=popup.destroy, width=10).grid(row=0, column=1, padx=5)

    popup.transient(root)   # keep on top of main window
    popup.grab_set()        # modal behavior
    root.wait_window(popup)

# ===========================================================================
# ============================= ABOUT DIALOG ================================
# ===========================================================================
# Opens the website
def open_website():
    webbrowser.open("https://moggle-khraum.github.io/rwmod_repacker/")

# Show License
def show_license_message():
    license_text = """
    RWMod Repacker

    Provided [AS IS] for mod authors and personal use only.

    This tool is not for commercial use or distribution. 
    It is intended to help mod authors protect their work.
    """
    messagebox.showinfo("License", license_text)

# For the Show About
def show_about():
    about_win = tk.Toplevel(root)
    about_win.title("About RWMod Repacker v3.5")
    about_win.transient(root)
    about_win.resizable(False, False)
    about_win.grab_set()

    # Calculate x and y coordinates for centering
    root_x = root.winfo_x()
    root_y = root.winfo_y()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    
    popup_width = 380
    popup_height = 420

    x = root_x + (root_width - popup_width) // 2
    y = root_y + (root_height - popup_height) // 2
    
    about_win.geometry(f"{popup_width}x{popup_height}+{x}+{y}")
    
    try:
        about_win.iconbitmap(ICON_PATHS['ico'])
    except Exception:
        pass

    bg = style.lookup("TFrame", "background") or "#f0f0f0"
    fg = style.lookup("TLabel", "foreground") or "black"
    about_win.configure(bg=bg)
    
    # Header Frame with Image and Title
    header_frame = ttk.Frame(about_win)
    header_frame.pack(pady=(15, 5))

    # --- Start of new code to add the logo ---
    try:
        # Load the PNG image
        image_path = ICON_PATHS['png']
        if not os.path.exists(image_path):
            # Fallback to ICO if PNG is not found
            image_path = ICON_PATHS['ico']
            
        original_image = Image.open(image_path)
        
        # Resize the image to a smaller, appropriate size
        resized_image = original_image.resize((115, 115), Image.LANCZOS)
        
        # Convert the image for Tkinter
        logo_image = ImageTk.PhotoImage(resized_image)
        
        # Create and pack a label to display the image
        image_label = ttk.Label(header_frame, image=logo_image)
        image_label.image = logo_image # Keep a reference to prevent garbage collection
        image_label.pack(side="left", padx=(0, 5))
    except Exception as e:
        print(f"Error loading logo: {e}")
    # --- End of new code ---
    
    title_label = ttk.Label(header_frame, text="RWMod\nRepacker", font=("Segoe UI", 28, "bold"), justify="left")
    title_label.pack(side="left", padx=2)
    
    version_label = ttk.Label(about_win, text="Version: 1.3.5", font=("Segoe UI", 12, "bold"))
    version_label.pack(pady=(0, 5))

    # Info LabelFrame to create the box effect
    info_frame = tk.LabelFrame(about_win, text="About", padx=12, bd=2, relief="groove", font=("Segoe UI", 10, "bold"), bg=bg, fg=fg)
    info_frame.pack(fill="x", padx=25)

    # Add text content inside the LabelFrame
    info_text = ttk.Label(
        info_frame,
        text="Converts the Mod Folders into an '.rwmod' format\nembedded with anti-theft protection using an\nextensive and robust obfuscation methods.\n",
        font=("Segoe UI", 10),
        justify="left"
    )
    info_text.pack(fill="x")

    # A single frame to hold all the author information
    author_info_frame = ttk.Frame(about_win)
    author_info_frame.pack(fill="x", padx=25)

    # Label for "Author:" with bold font
    author_label = ttk.Label(
        author_info_frame,
        text="✒️ Author: ",
        font=("Segoe UI", 10, "bold")
    )
    author_label.pack(side="left")

    # Label for the rest of the author details with a regular font
    author_details_label = ttk.Label(
        author_info_frame,
        text="Moggs/Moggle Khraum/BugoManGudKo",
        font=("Segoe UI", 10)
    )
    author_details_label.pack(side="left")

    # A single frame to hold all the Pioneer information
    pioneer_info_frame = ttk.Frame(about_win)
    pioneer_info_frame.pack(fill="x", padx=25)

    # Label for "Author:" with bold font
    pioneer_label = ttk.Label(
        pioneer_info_frame,
        text="🛠 Pioneer: ",
        font=("Segoe UI", 10, "bold")
    )
    pioneer_label.pack(side="left")

    # Label for the rest of the author details with a regular font
    pioneer_details_label = ttk.Label(
        pioneer_info_frame,
        text="Gen. Airon's FLOD Protect",
        font=("Segoe UI", 10)
    )
    pioneer_details_label.pack(side="left")

    # A single frame to hold all the Protect Against information
    protect_frame = ttk.Frame(about_win)
    protect_frame.pack(fill="x", padx=25)

    # Label for "Author:" with bold font
    protect_label = ttk.Label(
        protect_frame,
        text="🛡 Protect Against: ",
        font=("Segoe UI", 10, "bold")
    )
    protect_label.pack(side="left")

    # Label for the rest of the author details with a regular font
    protect_details_label = ttk.Label(
        protect_frame,
        text="Casual MOD Stealers",
        font=("Segoe UI", 10)
    )
    protect_details_label.pack(side="left")
    

    # A single frame to hold all the buttons at the bottom
    buttons_frame = ttk.Frame(about_win)
    buttons_frame.pack(fill="x", padx=25, pady=35)

    # Pack the "License" and "Website" buttons to the left
    ttk.Button(buttons_frame, text="🧾 License", style="Big.TButton", width=11, takefocus=0, command=show_license_message).pack(side="left", padx=(0, 5))
    ttk.Button(buttons_frame, text="🌎 Website", style="Big.TButton", width=12, takefocus=0, command=open_website).pack(side="left", padx=(5, 0))

    # Pack the "Close" button to the right
    ttk.Button(buttons_frame, text="❌ Close", style="Big.TButton", takefocus=0, width=9, command=about_win.destroy,).pack(side="right")

    _apply_text_widget_theme(style)


def show_tool_manual():
    about_win = tk.Toplevel(root)
    about_win.title("RWMod Repacker Manual")
    about_win.transient(root)
    about_win.resizable(False, False)
    about_win.grab_set()

    # Calculate x and y coordinates for centering
    root_x = root.winfo_x()
    root_y = root.winfo_y()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    
    popup_width = 380
    popup_height = 420

    x = root_x + (root_width - popup_width) // 2
    y = root_y + (root_height - popup_height) // 2
    
    about_win.geometry(f"{popup_width}x{popup_height}+{x}+{y}")
    
    try:
        about_win.iconbitmap(ICON_PATHS['ico'])
    except Exception:
        pass

    bg = style.lookup("TFrame", "background") or "#f0f0f0"
    fg = style.lookup("TLabel", "foreground") or "black"
    about_win.configure(bg=bg)
    
    # Header Frame with Image and Title
    header_frame = ttk.Frame(about_win)
    header_frame.pack(pady=(15, 5))

    # --- Start of new code to add the logo ---
    try:
        # Load the PNG image
        image_path = ICON_PATHS['png']
        if not os.path.exists(image_path):
            # Fallback to ICO if PNG is not found
            image_path = ICON_PATHS['ico']
            
        original_image = Image.open(image_path)
        
        # Resize the image to a smaller, appropriate size
        resized_image = original_image.resize((115, 115), Image.LANCZOS)
        
        # Convert the image for Tkinter
        logo_image = ImageTk.PhotoImage(resized_image)
        
        # Create and pack a label to display the image
        image_label = ttk.Label(header_frame, image=logo_image)
        image_label.image = logo_image # Keep a reference to prevent garbage collection
        image_label.pack(side="left", padx=(0, 5))
    except Exception as e:
        print(f"Error loading logo: {e}")
    # --- End of new code ---
    
    title_label = ttk.Label(header_frame, text="RWMod\nRepacker", font=("Segoe UI", 28, "bold"), justify="left")
    title_label.pack(side="left", padx=2)
    
    version_label = ttk.Label(about_win, text="Version: 1.3.5 Tool Manual", font=("Segoe UI", 12, "bold"))
    version_label.pack(pady=(0, 5))

    # A single frame to hold all the author information
    author_info_frame = ttk.Frame(about_win)
    author_info_frame.pack(fill="x", padx=25)

    # Label for "Author:" with bold font
    author_label = ttk.Label(
        author_info_frame,
        text="✒️ Manual Written by: ",
        font=("Segoe UI", 10, "bold")
    )
    author_label.pack(side="left")

    # Label for the rest of the author details with a regular font
    author_details_label = ttk.Label(
        author_info_frame,
        text="Moggs / Dr. Buggstavius",
        font=("Segoe UI", 10)
    )
    author_details_label.pack(side="left")

##    # A single frame to hold all the Pioneer information
##    pioneer_info_frame = ttk.Frame(about_win)
##    pioneer_info_frame.pack(fill="x", padx=25)
##
##    # Label for "Author:" with bold font
##    pioneer_label = ttk.Label(
##        pioneer_info_frame,
##        text="🛠 Pioneer: ",
##        font=("Segoe UI", 10, "bold")
##    )
##    pioneer_label.pack(side="left")
##
##    # Label for the rest of the author details with a regular font
##    pioneer_details_label = ttk.Label(
##        pioneer_info_frame,
##        text="Gen. Airon's FLOD Protect",
##        font=("Segoe UI", 10)
##    )
##    pioneer_details_label.pack(side="left")
##
##    # A single frame to hold all the Protect Against information
##    protect_frame = ttk.Frame(about_win)
##    protect_frame.pack(fill="x", padx=25)
##
##    # Label for "Author:" with bold font
##    protect_label = ttk.Label(
##        protect_frame,
##        text="🛡 Protect Against: ",
##        font=("Segoe UI", 10, "bold")
##    )
##    protect_label.pack(side="left")
##
##    # Label for the rest of the author details with a regular font
##    protect_details_label = ttk.Label(
##        protect_frame,
##        text="Casual MOD Stealers",
##        font=("Segoe UI", 10)
##    )
##    protect_details_label.pack(side="left")
    

    # A single frame to hold all the buttons at the bottom
    buttons_frame = ttk.Frame(about_win)
    buttons_frame.pack(fill="x", padx=25, pady=35)

    # Pack the "Close" button to the right
    ttk.Button(buttons_frame, text="❌ Close", style="Big.TButton", takefocus=0, width=9, command=about_win.destroy,).pack(side="bottom")

    _apply_text_widget_theme(style)
    




# ===========================================================================
# ============================= GUI BUILD ==================================
# ===========================================================================

def create_gui_widgets():
    global folder_entry, output_entry, modinfo_text, folder_name
    global progress_bar, progress_zip, progress_poly, progress_rwmod, progress_finalize
    global status_label_main, status_label_sub, pack_button

    main_title_label = ttk.Label(root, text="🛠 RWMod Anti-Theft Repacker v1.3.5 📦", style="Title.TLabel")
    main_title_label.pack(pady=10)

    input_frame = ttk.Frame(root)
    input_frame.pack(fill="x", padx=10, pady=5)

    folder_name = tk.StringVar(value="📁 FOLDER: (NONE)")
    folder_name_label = ttk.Label(input_frame, textvariable=folder_name)
    folder_name_label.pack(anchor="w")

    folder_entry_frame = ttk.Frame(input_frame)
    folder_entry_frame.pack(fill="x", pady=(2, 5))
    folder_entry = ttk.Entry(folder_entry_frame)
    folder_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
    ttk.Button(folder_entry_frame, text="📚 BROWSE", takefocus=0, style="Big.TButton", command=select_folder).pack(side="right")

    output_entry_frame = ttk.Frame(input_frame)
    output_entry_frame.pack(fill="x", pady=5)
    output_entry = ttk.Entry(output_entry_frame)
    output_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
    ttk.Button(output_entry_frame, text="💾 OUTPUT", takefocus=0, style="Big.TButton", command=select_output).pack(side="right")

    modinfo_preview_label = ttk.Label(root, text="📜 MOD-INFO PREVIEW:")
    modinfo_preview_label.pack(anchor="w", padx=10)
    modinfo_text = scrolledtext.ScrolledText(root, height=11, state='disabled', wrap='word')
    modinfo_text.pack(fill="x", expand=False, padx=10, pady=(0, 10))

    main_frame = ttk.Frame(root)
    main_frame.pack(fill="x", padx=10, pady=10)
    main_frame.grid_columnconfigure(0, weight=3)
    main_frame.grid_columnconfigure(1, weight=0)
    main_frame.grid_columnconfigure(2, weight=1)

    progress_frame = ttk.Frame(main_frame)
    progress_frame.grid(row=0, column=0, sticky="nsew")
    settings_frame = ttk.Frame(main_frame)
    settings_frame.grid(row=0, column=2, sticky="nsew")

    status_sequence_label = ttk.Label(progress_frame, text="📜 SEQUENCE STATUS", font=("Segoe UI", 12, "bold"))
    status_sequence_label.pack(anchor="center", pady=(0, 5))
    settings_label = ttk.Label(settings_frame, text="⚙ SETTINGS", font=("Segoe UI", 12, "bold"))
    settings_label.pack(anchor="center", pady=(0, 5))

    overall_label = ttk.Label(progress_frame, text="📝 OVERALL PROGRESS:")
    overall_label.pack(anchor="w")

    progress_bar = ttk.Progressbar(progress_frame, mode="determinate", length=250, style="Accent.Horizontal.TProgressbar")
    progress_bar.pack(fill='x', pady=(0, 10))

    archiving_label = ttk.Label(progress_frame, text="📦 ARCHIVING/OBFUSCATION:")
    archiving_label.pack(anchor="w")

    progress_zip = ttk.Progressbar(progress_frame, mode="determinate", length=250, style="Accent.Horizontal.TProgressbar")
    progress_zip.pack(fill='x', pady=(0, 10))

    # ADD THE NEW CODE BLOCK DIRECTLY BELOW IT
    poly_label = ttk.Label(progress_frame, text="🎭 POLYMORPHIC LAYERS:")
    poly_label.pack(anchor="w")

    progress_poly = ttk.Progressbar(progress_frame, mode="determinate", length=250, style="Accent.Horizontal.TProgressbar")
    progress_poly.pack(fill='x', pady=(0, 10))

    finalization_label = ttk.Label(progress_frame, text="⚒ FINALIZING PROGRESS:")
    finalization_label.pack(anchor="w")

    progress_finalize = ttk.Progressbar(progress_frame, mode="determinate", length=250, style="Accent.Horizontal.TProgressbar")
    progress_finalize.pack(fill='x', pady=(0, 10))

    status_label_main = ttk.Label(progress_frame, text="⚙️ Ready and waiting..", font=("Segoe UI", 10, "bold"))
    status_label_main.pack(anchor="w")
    status_label_sub = ttk.Label(progress_frame, text="⏳ Select a folder to begin.", font=("Segoe UI", 9))
    status_label_sub.pack(anchor="w", pady=(0, 10))

    ttk.Separator(main_frame, orient="vertical").grid(row=0, column=1, sticky="ns", padx=15)
    # NOTE: pass function refs (no parentheses) — fixes the accidental popup issue

    ttk.Button(settings_frame, text="📜 View Tool Help", takefocus=0, style="Big.TButton", command=show_tool_manual).pack(fill='x', pady=5)
    ttk.Button(settings_frame, text="📚 View History Log", takefocus=0, style="Big.TButton", command=show_history_popup).pack(fill='x', pady=5)
    ttk.Button(settings_frame, text="🎨 Change Theme", takefocus=0, style="Big.TButton", command=show_theme_selector).pack(fill='x', pady=5)
    ttk.Button(settings_frame, text="🗑 Clear History Log", takefocus=0, style="Big.TButton", command=clear_history).pack(fill='x', pady=5)
    ttk.Button(settings_frame, text="📖 About Repacker", takefocus=0, style="Big.TButton", command=show_about).pack(fill='x', pady=5)

    pack_button = ttk.Button(settings_frame, text="⚙ PACK AS .RWMOD", command=run_packing_flow, width=20, takefocus=0, style="Accent.TButton")
    pack_button.pack(anchor="center", pady=(10, 0))
    _apply_text_widget_theme(style)

# ===========================================================================
# ============================= MAIN / ENTRY =================================
# ===========================================================================

def main():
    global root, style, folder_entry, output_entry, modinfo_text
    global progress_bar, progress_zip, status_label_main, status_label_sub, pack_button

    root = tk.Tk()
    root.title("RWMod Anti-Theft Repacker v1.3.5")
    style = ttk.Style(root)
    root.resizable(False, False)

    window_width = 580
    window_height = 695
    center_window(root, window_width, window_height)

    # --- theme setup + icon loading ---
    try:
        create_custom_themes(style)
    except Exception:
        pass

    saved_theme = load_theme()
    try:
        style.theme_use(saved_theme)
    except tk.TclError:
        style.theme_use("clam")

    try:
        icon_path = ICON_PATHS['ico']
        if os.path.exists(icon_path):
            icon_image = Image.open(icon_path)
            icon_photo = ImageTk.PhotoImage(icon_image)
            root.iconphoto(True, icon_photo)
            root.icon_photo = icon_photo
    except Exception as e:
        print(f"Error loading icon: {e}")

    # --- function to build main window widgets ---
    def start_main_window():
        _apply_text_widget_theme(style)
        refresh_styles()
        create_gui_widgets()
        center_window(root, window_width, window_height)
        root.deiconify()  # show the main window

    # Show splash and call main window setup when done
    show_splash(root, image="app_icon.png", icon="app_icon.ico",
                duration=6000, pause_after_full=5000,
                on_finish=start_main_window)

    root.mainloop()

if __name__ == "__main__":
    main()



    
    
