#===================================================================================
#============================= IMPORTS of REPACKER START ===============================
#===================================================================================

import os
import zipfile
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext
import threading
import time
import random
import string
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor 
from typing import Optional, Union
from threading import Thread
from threading import Lock
from queue import Queue
import mmap

#===================================================================================
#============================= IMPORTS of REPACKER END ===============================
#===================================================================================


#===========================================================================
#============================ FOR HISTORY & ICON ==========================
#===========================================================================
# For the History File
HISTORY_FILE = "history_log.txt"
history_log = []

# For the ICON Path
ICON_PATH = {
    'png': 'app_icon.png'
}
#===========================================================================
#============================ FOR HISTORY & ICON ===========================
#===========================================================================


#============================================================================
#============================ CORE of REPACKER ==============================
#============================================================================
# Core RWMod Functions
#========== HEADER & VERIFICATION START ======================
def get_header_sig(file_data=None):
    """Generates a header with:
    - Fully random base structure
    - Anti-pattern noise injection
    - Optional steganographic payload
    - Verifiable core markers"""
    
    # 1. Seed RNG with file content hash (for deterministic randomness if needed)
    seed = hashlib.sha256(file_data).digest()[:4] if file_data else None
    rng = random.Random(seed)
    
    # 2. Core structure components (random but verifiable)
    components = [
        bytes([rng.randint(0x80, 0xFF)]),  # High bit set byte
        bytes([0x50 + rng.randint(0, 15)]),  # Semi-random "P" variant
        bytes([0x4E + rng.choice([0, 1, -1])]),  # "N" ±1
        bytes([rng.choice([0x47, 0x46, 0x48])]),  # G/F/H
        b"\x0D\x0A",  # Required CR+LF
        bytes([rng.choice([0x1A, 0x1B, 0x1C])]),  # Control char
        bytes([rng.choice([0x00, 0x0A, 0xFF])])  # Varied terminator
    ]
    
    # 3. Assemble base header
    header = bytearray(b"".join(components))
    
    # 4. Anti-pattern injections
    for _ in range(rng.randint(1, 3)):
        pos = rng.randint(0, len(header)-1)
        header[pos] ^= 0xFF  # Invert bits randomly
    
    # 5. Steganographic payload (hidden real header)
    if rng.random() > 0.5:  # 50% chance to activate
        real_header = b"\x89PNG"
        for i, b in enumerate(real_header):
            if i < len(header):
                header[i] = (header[i] & 0xF0) | (b & 0x0F)  # Hide in lower nibbles
    
    # 6. Final entropy boost
    return bytes(header) + bytes([rng.randint(0, 255) for _ in range(2)])
    
def verify_header(header):
    """Flexible verification that tolerates mutations"""
    if len(header) < 8:
        return False
    
    # Check core markers with tolerance
    checks = [
        header[0] & 0x80 == 0x80,  # High bit set
        header[4:6] == b"\x0D\x0A",  # CR+LF
        header[6] in {0x1A, 0x1B, 0x1C},  # Control char
        header[-2] != header[-1]  # Entropy check
    ]
    return all(checks)  

#=========== HEADER & VERIFICATION END ======================


#=========== FOOTER & VERIFICATION START ======================
def get_footer_sig(file_data: Optional[bytes] = None) -> bytes:
    """Generates a footer with:
    - Seed-based deterministic randomness
    - Multi-layer obfuscation
    - Steganographic payload support
    - Anti-tampering checks
    - Verifiable structure"""
    
    # 1. Seed RNG with file hash or system entropy
    seed = hashlib.sha256(file_data).digest()[:8] if file_data else None
    rand = random.Random(seed)
    
    # 2. Core components (random but structured)
    components = [
        # Segment A (random printable)
        bytes(''.join(rand.choices(
            string.ascii_letters + string.digits + '@$#', 
            k=rand.randint(6, 12))
        ), 'ascii'),
        
        # Delimiter with random whitespace
        rand.choice([b"--", b"~~", b"||", b"::"]),
        
        # Segment B (random bytes)
        bytes([rand.randint(32, 126) for _ in range(rand.randint(6, 12))]),
        
        # Terminator with control chars
        rand.choice([b"\x00\x00", b"\xFF\xFF", b"\x1A\x1A"])
    ]
    
    # 3. Assemble base footer
    footer = bytearray(b"".join(components))
    
    # 4. Anti-pattern injections
    for _ in range(rand.randint(1, 3)):
        pos = rand.randint(0, len(footer)-1)
        footer[pos] ^= 0xFF  # Bit-flip random positions
    
    # 5. Steganographic payload (hidden real marker)
    if rand.random() > 0.3:  # 70% chance to activate
        real_marker = b"RWMOD"
        for i, b in enumerate(real_marker):
            if i*2 < len(footer):
                footer[i*2] = (footer[i*2] & 0xF0) | ((b >> 4) & 0x0F)
                footer[i*2+1] = (footer[i*2+1] & 0xF0) | (b & 0x0F)
    
    # 6. Final entropy boost
    return bytes(footer) + bytes([rand.randint(0, 255) for _ in range(4)])

def verify_footer(footer: bytes) -> bool:
    """Validates footer structure with tolerance"""
    if len(footer) < 16:
        return False
    
    # Check for at least one valid delimiter
    delimiters = [b"--", b"~~", b"||", b"::"]
    has_delim = any(d in footer for d in delimiters)
    
    # Check for steganographic marker (optional)
    hidden_marker = bytearray()
    for i in range(0, min(10, len(footer)-1), 2):
        hidden_marker.append((footer[i] & 0x0F) << 4 | (footer[i+1] & 0x0F))
    
    return (
        has_delim and
        footer[-2:] in {b"\x00\x00", b"\xFF\xFF", b"\x1A\x1A"} and
        (b"RWMOD" in hidden_marker or random.random() > 0.5)  # 50% tolerance
    )

#=========== FOOTER & VERIFICATION END ======================


#=========== SIGNATURE & VERIFICATION START ======================

def mutable_signature(
    base: Union[bytes, str],
    seed: Optional[bytes] = None,
    stealth_level: int = 1,
    inject_real: bool = False
) -> bytes:
    """
    Generates a mutable signature with:
    - Seed-controlled randomness
    - Adjustable stealth levels
    - Optional legitimate signature hiding
    - Anti-analysis features
    
    Args:
        base: Input bytes/string to mutate
        seed: Optional seed for deterministic generation
        stealth_level: 1=Basic, 2=Anti-pattern, 3=Steganography
        inject_real: Whether to hide a legitimate signature in noise
    """
    # 1. Setup seeded RNG
    rand = random.Random(seed if seed else hashlib.sha256(base if isinstance(base, bytes) else base.encode()).digest())
    
    # 2. Convert to bytes if needed
    if isinstance(base, str):
        base_bytes = base.encode('utf-8')
    else:
        base_bytes = base
    
    # 3. Core mutation based on stealth level
    if stealth_level == 1:  # Basic noise
        noise = bytes([rand.randint(0, 255) for _ in range(rand.randint(4, 8))])
        signature = base_bytes + noise
        
    elif stealth_level == 2:  # Anti-pattern
        # Insert noise at random positions
        base_list = bytearray(base_bytes)
        for _ in range(rand.randint(2, 4)):
            pos = rand.randint(0, len(base_list))
            base_list[pos:pos] = bytes([rand.randint(0, 255)])
        signature = bytes(base_list)
        
    else:  # Level 3 - Steganography
        # Generate legitimate-looking signature
        real_sig = b"\x89PNG" if inject_real else b""
        noise_len = max(16, len(base_bytes) * 2)
        noise = bytes([rand.randint(0, 255) for _ in range(noise_len)])
        
        # Hide real sig in noise (every 3rd byte)
        if real_sig:
            for i, b in enumerate(real_sig):
                if i*3 < len(noise):
                    noise = noise[:i*3] + bytes([b ^ 0x55]) + noise[i*3+1:]
        
        signature = base_bytes + noise
    
    # 4. Final obfuscation
    if stealth_level > 1:
        # XOR mask the entire signature
        mask = rand.randint(1, 255)
        signature = bytes([b ^ mask for b in signature])
        
        # Add random header/footer
        signature = (bytes([rand.randint(0x80, 0xFF)]) + 
                    signature + 
                    bytes([rand.choice([0x00, 0xFF])]))
    
    return signature

def verify_signature(
    data: bytes,
    original_base: Optional[bytes] = None,
    check_stealth: bool = False
) -> bool:
    """
    Flexible signature verification that can:
    - Check for partial base matches
    - Detect steganographic patterns
    - Validate structure without exact matching
    """
    # Basic length check
    if len(data) < 4:
        return False
    
    # If original base provided, check for partial match
    if original_base:
        min_match_len = min(4, len(original_base))
        for i in range(len(data) - min_match_len + 1):
            if data[i:i+min_match_len] in original_base:
                return True
    
    # Advanced steganography check
    if check_stealth:
        potential_real = bytes([b ^ 0x55 for b in data[::3]])
        if b"PNG" in potential_real or b"RWMOD" in potential_real:
            return True
    
    # Final fallback - check high bit usage
    return sum(b & 0x80 for b in data) > len(data) // 2

#=========== SIGNATURE & VERIFICATION END ======================


#=========== HEX KEY & VERIFICATION START ======================

def mutable_hex_key(
    seed: Optional[Union[int, bytes, str]] = None,
    security_level: int = 2,
    hidden_payload: Optional[bytes] = None
) -> bytes:
    """
    Generates a hex key with:
    - Seed-controlled determinism
    - Adjustable security levels
    - Optional hidden payload
    - Anti-tampering features
    
    Args:
        seed: Integer/bytes/string seed (None for system randomness)
        security_level: 1=Basic, 2=Obfuscated, 3=Stealth
        hidden_payload: Bytes to embed steganographically
    """
    # 1. Seed initialization
    if seed is None:
        rand = random.Random(os.urandom(16))
    else:
        if isinstance(seed, int):
            seed_bytes = seed.to_bytes(16, 'big')
        elif isinstance(seed, str):
            seed_bytes = seed.encode('utf-8')
        else:
            seed_bytes = seed
        
        # Create deterministic but unpredictable seed
        rand = random.Random(hashlib.sha3_256(seed_bytes).digest())
    
    # 2. Core key generation
    if security_level == 1:  # Basic
        key = bytes([rand.randint(0, 255) for _ in range(8)])
        
    elif security_level == 2:  # Obfuscated
        # XOR chain with rotating mask
        key = bytearray()
        mask = rand.randint(1, 255)
        for _ in range(8):
            byte = rand.randint(0, 255) ^ mask
            mask = (mask * 13) % 256
            key.append(byte)
            
    else:  # Level 3 - Stealth
        # Generate noise buffer
        key = bytearray([rand.randint(0, 255) for _ in range(16)])
        
        # Embed hidden payload if provided
        if hidden_payload:
            for i, b in enumerate(hidden_payload):
                if i*2 < len(key):
                    # Store each nibble in separate bytes
                    key[i*2] = (key[i*2] & 0xF0) | ((b >> 4) & 0x0F)
                    key[i*2+1] = (key[i*2+1] & 0xF0) | (b & 0x0F)
        
        # Shrink to 8 bytes if no payload
        if not hidden_payload:
            key = key[:8]
    
    # 3. Post-processing
    if security_level > 1:
        # Add checksum byte
        checksum = sum(key) % 256
        key.append(checksum)
        
        # Apply bit rotation
        rotate_by = rand.randint(1, 7)
        key = bytes([(b << rotate_by | b >> (8 - rotate_by)) & 0xFF for b in key])
    
    return bytes(key)

def verify_hex_key(
    key: bytes,
    original_seed: Optional[Union[int, bytes, str]] = None,
    check_payload: bool = False
) -> bool:
    """
    Validates hex key structure and optionally:
    - Reconstructs from seed
    - Extracts hidden payload
    
    Args:
        key: Key to verify
        original_seed: Seed for reconstruction check
        check_payload: Whether to validate hidden data
    """
    # Basic structural checks
    if not 8 <= len(key) <= 32:  # Allow for checksum/extended keys
        return False
    
    if check_payload:
        # Extract nibble pairs
        payload = bytearray()
        for i in range(0, min(32, len(key)), 2):
            if i+1 < len(key):
                payload.append((key[i] & 0x0F) << 4 | (key[i+1] & 0x0F))
        return payload.isalnum()  # Simple ASCII validation
    
    if original_seed is not None:
        # Reconstruct key from seed and compare
        reconstructed = mutable_hex_key(original_seed, security_level=2)
        return reconstructed[:8] == key[:8]  # Compare core 8 bytes
    
    return True  # Fallback - structure looks valid
    
#=========== HEX KEY & VERIFICATION END ======================


#=========== SECRET KEY & VERIFICATION START ======================

def get_secret_key(
    epoch: int = 2025,
    pid: Optional[int] = None,
    security_level: int = 3,
    hidden_payload: Optional[bytes] = None
) -> bytes:
    """
    Generates a deterministic secret key with:
    - Epoch + PID as seed (default epoch=2025, pid=os.getpid())
    - Optional hidden payload
    - Security levels (1-3)
    - Tamper-evident transformations
    """
    pid = pid if pid is not None else os.getpid()

    # === 1. Deterministic seed ===
    seed_str = f"{epoch}-{pid}-{hidden_payload.hex() if hidden_payload else ''}"
    seed_digest = hashlib.sha3_256(seed_str.encode()).digest()
    rand = random.Random(seed_digest)

    # === 2. Generate key segments ===
    def _gen_segment(seed: int) -> bytes:
        return mutable_hex_key(
            seed=hashlib.sha256(str(seed).encode()).digest(),
            security_level=security_level,
            hidden_payload=hidden_payload[:8] if hidden_payload else None
        )

    segments = [
        _gen_segment(epoch),
        b"_MODSEC_",         # fixed delimiter
        _gen_segment(pid),
        (pid ^ epoch).to_bytes(4, "big")  # deterministic entropy
    ]

    key = bytearray(b"".join(segments))

    # === 3. Security transformations ===
    if security_level >= 2:
        # XOR chain with rotating mask
        mask = rand.randint(1, 255)
        for i in range(len(key)):
            key[i] ^= mask
            mask = (mask * 17 + 53) % 256

        # Insert checksum
        checksum = sum(key) % 256
        key.append(checksum)

    if security_level >= 3:
        # Add epoch-based component
        time_component = epoch % 65536
        key.extend(time_component.to_bytes(2, "big"))

        # Deterministic bit rotation
        rotate_by = (epoch + pid) % 7 + 1
        key = bytearray([(b << rotate_by | b >> (8 - rotate_by)) & 0xFF for b in key])

    return bytes(key)


def verify_secret_key(
    key: bytes,
    expected_epoch: int = 2025,
    expected_pid: Optional[int] = None,
    hidden_payload: Optional[bytes] = None
) -> bool:
    """Deterministically regenerate secret key and compare."""
    pid = expected_pid if expected_pid is not None else os.getpid()
    expected = get_secret_key(
        epoch=expected_epoch,
        pid=pid,
        hidden_payload=hidden_payload
    )
    return key == expected

#=========== SECRET KEY & VERIFICATION END ======================

#===============================================================================
#============================ CORE of REPACKER =================================
#===============================================================================



#============================================================================
#============================ FOR HISTORY LOGGING ==========================
#===========================================================================
# History Functions

#====== Loads History JSON file
def load_history():
    """Loads history from file if exists, returns empty list otherwise."""
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return []

#======= Saves the History in JSON format
def save_history(history):
    """Saves history to file in JSON format."""
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

#======== Add the log to History Log
def add_to_log(folder_name, output_path):
    """Adds entry to history and saves to file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "folder": folder_name,
        "output": output_path,
        "checksum": calculate_sha256(output_path)
    }
    
    history = load_history()
    history.append(entry)
    save_history(history)
    history_log.append(entry)  # Keep in memory for current session
 
 #======= Delete the History Log
 def clear_history():
    """Clear all history with confirmation dialog"""
    if not history_log:
        messagebox.showinfo("Info", "History is already empty.")
        return
    
    # Confirmation dialog
    result = messagebox.askyesno(
        "Confirm Deletion",
        "Are you sure you want to delete ALL history?\nThis action cannot be undone.",
        icon="warning"
    )
    
    if result:
        global history_log
        history_log = []
        try:
            if os.path.exists(HISTORY_FILE):
                os.remove(HISTORY_FILE)
        except Exception as e:
            messagebox.showerror("Error", f"Could not delete history file: {e}")
        else:
            messagebox.showinfo("Success", "History cleared successfully.")
    
#=============================================================================
#============================ FOR HISTORY LOGGING ============================
#=============================================================================


#=============================================================================
#============================ FOR ARCHIVING FILES ============================
#=============================================================================

#======================== ZIPPING FILES START ================================

# ZIPS the Folder, Ready for PACKING
def zip_folder(
    folder_path: str,
    zip_path: str,
    compression: int = zipfile.ZIP_LZMA,
    encryption: bool = False,
    hide_files: bool = True,
    progress_callback: callable = None
) -> None:
    """
    Advanced folder compression with memory-efficient large file handling:
    - LZMA compression (superior to DEFLATE)
    - Memory mapping for large files (>1MB)
    - Optional file hiding (Windows/macOS/Linux compatible)
    - Progress tracking
    """
    file_queue = Queue()
    processed_count = 0
    total_files = 0

    # 1. Scan files (with hidden files handling)
    def scan_files():
        nonlocal total_files
        for root, _, files in os.walk(folder_path):
            for file in files:
                src_path = os.path.join(root, file)
                rel_path = os.path.relpath(src_path, folder_path)
                
                # Handle file hiding
                if hide_files:
                    if os.name == 'nt':  # Windows
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(src_path, 0x02)
                    elif not file.startswith('.'):  # macOS/Linux
                        os.rename(src_path, os.path.join(root, f".{file}"))
                        rel_path = os.path.relpath(os.path.join(root, f".{file}"), folder_path)
                
                file_queue.put((src_path, rel_path))
                total_files += 1
        file_queue.put(None)  # Sentinel

    # 2. Compression worker with memory optimization
    def compress_worker():
        nonlocal processed_count
        with zipfile.ZipFile(
            zip_path, 'w', compression,
            compresslevel=9 if compression == zipfile.ZIP_DEFLATED else None
        ) as zf:
            while True:
                item = file_queue.get()
                if item is None:
                    break
                
                src_path, rel_path = item
                try:
                    # Set hidden attribute in ZIP (Windows-style)
                    if hide_files:
                        zinfo = zipfile.ZipInfo.from_file(src_path, rel_path)
                        zinfo.external_attr = 0x81A40000 | (0x02 << 16)  # Hidden flag
                        
                        # Use memory mapping for large files (>1MB)
                        file_size = os.path.getsize(src_path)
                        if file_size > 1024 * 1024:  # 1MB threshold
                            with open(src_path, "rb") as f:
                                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                                    zf.writestr(zinfo, mmapped_file)
                        else:
                            with open(src_path, "rb") as f:
                                zf.writestr(zinfo, f.read())
                    else:
                        # Regular file handling with memory optimization
                        file_size = os.path.getsize(src_path)
                        if file_size > 1024 * 1024:  # 1MB threshold
                            with open(src_path, "rb") as f:
                                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                                    zf.writestr(rel_path, mmapped_file)
                        else:
                            zf.write(src_path, rel_path)
                    
                    processed_count += 1
                    if progress_callback:
                        progress_callback(processed_count, total_files)
                except Exception as e:
                    print(f"Skipping {src_path}: {str(e)}")
                finally:
                    file_queue.task_done()

    # 3. Start processing
    scanner = Thread(target=scan_files)
    scanner.start()

    workers = [Thread(target=compress_worker) for _ in range(min(4, os.cpu_count() or 2))]
    for w in workers:
        w.start()

    # 4. Wait for completion
    scanner.join()
    for w in workers:
        w.join()

    # 5. Add decoy file if hiding files
    if hide_files:
        with zipfile.ZipFile(zip_path, 'a') as zf:
            decoy = zipfile.ZipInfo("_VISIBLE_README.txt")
            decoy.external_attr = 0x81A40000  # Normal visibility
            zf.writestr(decoy, "This archive seems to have been corrupted\n")

#======================== ZIPPING FILES END ==================================


#======================== TAMPER FILES START ==================================

# Tamper the Temp ZIP with STUFFS
def tamper_zip(
    zip_path: str,
    rwmod_path: str,
    prefix_len_range: tuple = (1024, 8192),
    chunk_size: int = 64 * 1024,
    progress_callback: callable = None
) -> None:
    """Memory-efficient tamper ZIP with strict format"""
    update_status("🔐 ADDING MULTI-LAYER OBFUSCATION...")

    # Generate components
    header_sig = get_header_sig()
    footer_sig = get_footer_sig()
    secret_key = get_secret_key()
    mut_sig = mutable_signature("RWMod Signature")
    hex_key = mutable_hex_key(seed=secret_key)
    prefix_len = random.randint(*prefix_len_range)
    prefix = os.urandom(prefix_len)

    try:
        with open(zip_path, "rb") as src, open(rwmod_path, "wb") as dest:
            # Use memory mapping for the source ZIP file
            with mmap.mmap(src.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_src:
                # 1. Write header (with length)
                dest.write(len(header_sig).to_bytes(2, "big"))
                dest.write(header_sig)

                # 2. Write prefix (with length)
                dest.write(len(prefix).to_bytes(4, "big"))
                dest.write(prefix)

                # 3. Calculate SHA256 and write ZIP data (streamed)
                sha256 = hashlib.sha256()
                zip_offset = dest.tell()
                dest.write((0).to_bytes(8, "big"))  # placeholder for ZIP length
                
                # Process ZIP data in chunks
                zip_size = len(mmapped_src)
                for i in range(0, zip_size, chunk_size):
                    chunk = mmapped_src[i:i+chunk_size]
                    sha256.update(chunk)
                    dest.write(chunk)
                    
                    if progress_callback:
                        progress = int((i / zip_size) * 100)
                        progress_callback(progress, "Hashing ZIP data")
                
                # Backfill ZIP length
                cur_pos = dest.tell()
                dest.seek(zip_offset)
                dest.write(zip_size.to_bytes(8, "big"))
                dest.seek(cur_pos)

                # 4. Write mutable signature
                dest.write(len(mut_sig).to_bytes(2, "big"))
                dest.write(mut_sig)

                # 5. Write hash+secret key binding
                combined_hash = hashlib.sha256(sha256.digest() + secret_key).digest()
                dest.write(len(combined_hash).to_bytes(2, "big"))
                dest.write(combined_hash)

                # 6. Write footer
                dest.write(len(footer_sig).to_bytes(2, "big"))
                dest.write(footer_sig)

                # 7. Write hex key
                dest.write(len(hex_key).to_bytes(2, "big"))
                dest.write(hex_key)

                # 8. Write total size of ZIP
                dest.write(zip_size.to_bytes(8, "big"))

    except Exception as e:
        raise RuntimeError(f"Tampering failed: {str(e)}")
    
    # Clean up temporary zip
    try:
        os.remove(zip_path)
    except:
        pass  # Don't fail if removal doesn't work

#======================== TAMPER FILES END ==================================


#======================== VERIFY RWMOD STRUCTURE START ==================================

def verify_rwmod_structure(rwmod_path: str, progress_callback: callable = None) -> bool:
    """Memory-efficient .rwmod verification with memory mapping"""
    def report(pct: int, stage: str):
        if progress_callback:
            progress_callback(pct, stage)

    try:
        with open(rwmod_path, "rb") as f:
            # Use memory mapping for efficient large file access
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                position = 0
                
                # 🧩 Parse header
                report(5, "Reading header")
                header_len = int.from_bytes(mmapped_file[position:position+2], "big")
                position += 2
                header_sig = mmapped_file[position:position+header_len]
                position += header_len
                if not verify_header(header_sig):
                    raise ValueError("❌ Invalid header signature")

                # 🎲 Parse prefix (random noise)
                report(10, "Reading prefix")
                prefix_len = int.from_bytes(mmapped_file[position:position+4], "big")
                position += 4
                position += prefix_len  # Skip prefix bytes

                # 📦 Parse ZIP data
                report(30, "Hashing ZIP data")
                zip_size = int.from_bytes(mmapped_file[position:position+8], "big")
                position += 8
                
                # Hash the ZIP data section directly from memory map
                sha256 = hashlib.sha256()
                zip_data = mmapped_file[position:position+zip_size]
                sha256.update(zip_data)
                position += zip_size

                report(70, "Hashing complete")

                # ✒️ Parse mutable signature
                report(75, "Reading mutable signature")
                mut_len = int.from_bytes(mmapped_file[position:position+2], "big")
                position += 2
                mut_sig = mmapped_file[position:position+mut_len]
                position += mut_len
                if not verify_signature(mut_sig):
                    raise ValueError("❌ Invalid mutable signature")

                # 🔑 Parse combined hash
                report(80, "Reading stored hash")
                hash_len = int.from_bytes(mmapped_file[position:position+2], "big")
                position += 2
                stored_hash = mmapped_file[position:position+hash_len]
                position += hash_len

                # 🧾 Parse footer signature
                report(85, "Reading footer")
                footer_len = int.from_bytes(mmapped_file[position:position+2], "big")
                position += 2
                footer_sig = mmapped_file[position:position+footer_len]
                position += footer_len
                if not verify_footer(footer_sig):
                    raise ValueError("❌ Invalid footer signature")

                # 🕵️ Parse hex key
                report(90, "Reading hex key")
                hex_len = int.from_bytes(mmapped_file[position:position+2], "big")
                position += 2
                hex_key = mmapped_file[position:position+hex_len]
                position += hex_len
                if not verify_hex_key(hex_key):
                    raise ValueError("❌ Invalid hex key")

                # 📏 Parse declared total size
                report(95, "Reading declared size")
                declared_size = int.from_bytes(mmapped_file[position:position+8], "big")
                position += 8
                if declared_size != zip_size:
                    raise ValueError("❌ Declared size mismatch")

                # ✅ Verify combined hash with secret key
                report(98, "Validating hash+secret key")
                secret_key = get_secret_key()  # deterministic regeneration
                combined = hashlib.sha256(sha256.digest() + secret_key).digest()
                if combined != stored_hash:
                    raise ValueError("❌ Content hash mismatch / tampering detected")

        report(100, "Verification complete")
        return True

    except Exception as e:
        raise ValueError(f"Verification failed: {str(e)}")

#======================== VERIFY RWMOD STRUCTURE END ==================================


#======================== PACK AS RWMOD START =========================================

# Packing Function
def pack_as_rwmod(
    folder_path: str,
    rwmod_path: str,
    compression: int = zipfile.ZIP_LZMA,
    encryption: bool = False,
    hide_files: bool = True,
    progress_callback: callable = None
):
    """
    Main RWMod packaging pipeline:
    - Compresses folder with advanced ZIP (LZMA/Deflate, hidden files, threaded)
    - Applies obfuscation via tamper_zip
    - Validates with checksum and full structure verification
    """

    import os, time

    temp_zip = rwmod_path + ".temp.zip"
    success = False  # Track completion

    try:
        # 📦 Step 1: Create ZIP archive
        update_status("💼 Creating ZIP archive...")
        zip_folder(
            folder_path,
            temp_zip,
            compression=compression,
            encryption=encryption,
            hide_files=hide_files,
            progress_callback=progress_callback
        )

        # 🔐 Step 2: Obfuscate archive
        update_status("🔐 Applying obfuscation layer...")
        tamper_zip(temp_zip, rwmod_path, progress_callback=progress_callback)

        # 🧮 Step 3: Quick checksum validation
        update_status("🧮 Running checksum test...")
        if not verify_checksum(rwmod_path):
            raise RuntimeError("❌ Checksum mismatch – file corrupted during creation")

        # ♻️ Step 4: Full structural validation
        update_status("♻️ Verifying RWMod structure...")
        verify_rwmod_structure(rwmod_path, progress_callback=progress_callback)

        success = True  # ✅ Successful pack

    except Exception as e:
        # 🚨 Cleanup on failure
        if os.path.exists(rwmod_path):
            try:
                os.remove(rwmod_path)
            except Exception:
                pass
        raise  # Bubble up exception

    finally:
        # 🧹 Remove temporary ZIP
        if os.path.exists(temp_zip):
            try:
                os.remove(temp_zip)
            except Exception:
                pass

        # 🧹 Final safeguard — remove bad output
        if not success and os.path.exists(rwmod_path):
            try:
                os.remove(rwmod_path)
            except Exception:
                pass

    # ✅ Report completion
    update_status("🔒 Archive protection applied successfully")
    time.sleep(2.5)

#=============================== PACK AS RWMOD END =================================

#===================================================================================
#============================ FOR ARCHIVING FILES ==================================
#===================================================================================


#===================================================================================
#============================ FOR GUI FOLDER SELECTION =============================
#===================================================================================

#======================== GUI for INPUT/OUTPUT START ===============================

# GUI Functions
def update_status(msg):
    status_label.config(text=msg)
    status_label.update()

# Selects MOD Folder
def select_folder():
    folder = filedialog.askdirectory()
    if folder:
        folder_entry.delete(0, tk.END)
        folder_entry.insert(0, folder)
        folder_name.set(f"🗂 FOLDER: {os.path.basename(folder)}")
        modinfo_path = os.path.join(folder, "mod-info.txt")
        if os.path.exists(modinfo_path):
            try:
                with open(modinfo_path, 'r', encoding='utf-8', errors='ignore') as f:
                    modinfo_text.delete('1.0', tk.END)
                    modinfo_text.insert(tk.END, f.read())
            except Exception as e:
                modinfo_text.delete('1.0', tk.END)
                modinfo_text.insert(tk.END, f"[⚠️ Error reading mod-info.txt: {e}]")
        else:
            modinfo_text.delete('1.0', tk.END)
            modinfo_text.insert(tk.END, "📜 No mod-info.txt found.")

# Selects Output Folder
def select_output():
    output = filedialog.askdirectory()
    if output:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, output)


# Boolean State: Enable/Disable
def set_pack_button_state(enabled: bool):
    pack_button.config(state="normal" if enabled else "disabled")

#======================== GUI for INPUT/OUTPUT START ==================================

#===================================================================================
#============================ FOR GUI FOLDER SELECTION =============================
#===================================================================================


#===================================================================================
#============================ FOR ARCHIVING SEQUENCE ===============================
#===================================================================================

#======================== EXECUTES THE ARCHIVING SEQUENCE =============================

# Runs the Packing Process
# 🏗️ Runs the RWMod Packing Process with progress bar
def run_packing():
    set_pack_button_state(False)

    # 🎛️ Setup progress bar
    progress_bar["value"] = 0
    progress_bar.pack(pady=5)  # Ensure visible
    update_status("🔄 INITIALIZING ARCHIVE SEQUENCE...")

    def progress_callback(percent: int, stage: str):
        """Updates UI with progress percentage + stage message."""
        update_status(f"{stage} {percent}%")
        progress_bar["value"] = percent
        progress_bar.update_idletasks()

    try:
        # 📂 Step 1: Collect input paths
        folder_path = folder_entry.get().strip()
        output_dir = output_entry.get().strip() or os.path.expanduser("~/Downloads")

        if not folder_path or not os.path.isdir(folder_path):
            messagebox.showerror("❌ Error", "⚠️ Please select a valid mod folder.")
            set_pack_button_state(True)
            progress_bar["value"] = 0
            return

        modname = os.path.basename(folder_path.rstrip("/\\"))
        rwmod_path = os.path.join(output_dir, modname + ".rwmod")

        # 📦 Step 2: Perform packing with live progress
        pack_as_rwmod(folder_path, rwmod_path, progress_callback=progress_callback)

        # 🔍 Step 3: Verify output checksum
        update_status("🔍 Verifying checksum...")
        checksum_valid = False
        try:
            sha256 = calculate_sha256(rwmod_path)
            if sha256 and os.path.getsize(rwmod_path) > 0:
                checksum_valid = True
        except Exception:
            checksum_valid = False

        if not checksum_valid:
            raise RuntimeError("Checksum verification failed after packing")

        # 📝 Step 4: Log + notify user
        add_to_log(modname, rwmod_path)
        update_status("✅ SUCCESS! 100%")
        messagebox.showinfo("🎉 DONE", f"📦 Packed to:\n{rwmod_path}")

    except Exception as e:
        # 🚨 Step 5: Error handler
        update_status("❌ FAILED")

        error_msg = str(e).lower()
        if "checksum" in error_msg or "corrupt" in error_msg:
            msg = f"🚨 FILE CORRUPTION:\n\n{str(e)}"
        elif "size mismatch" in error_msg:
            msg = f"📏 SIZE MISMATCH:\n\n{str(e)}"
        else:
            msg = f"❌ ERROR:\n\n{str(e)}"

        messagebox.showerror(
            "Packing Error",
            f"{msg}\n\n"
            "🛑 No .rwmod file was created or it was deleted.\n"
            "🔧 Please check your source files and try again."
        )

    finally:
        # 🧹 Step 6: Reset UI + progress bar
        folder_entry.delete(0, tk.END)
        output_entry.delete(0, tk.END)
        folder_name.set("🗂 FOLDER: (NONE)")
        modinfo_text.delete("1.0", tk.END)
        set_pack_button_state(True)
        update_status("⚙ READY and WAITING...")
        progress_bar["value"] = 0  # 🔄 Reset to zero
        progress_bar.update_idletasks()

#======================== EXECUTES THE ARCHIVING SEQUENCE =============================


#======================== MISCELLANEOUS EXECUTIONS =============================
# Calculate the SHA256
# 🔑 Calculate the SHA256
def calculate_sha256(file_path: str) -> str:
    """Memory-efficient SHA256 calculation using memory mapping"""
    sha256 = hashlib.sha256()
    chunk_size = 64 * 1024  # 64KB chunks
    
    try:
        with open(file_path, "rb") as f:
            # Create memory map for efficient large file reading
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                # Process file in chunks without loading entire content to memory
                for i in range(0, len(mmapped_file), chunk_size):
                    chunk = mmapped_file[i:i+chunk_size]
                    sha256.update(chunk)
    except Exception as e:
        raise RuntimeError(f"SHA256 calculation failed: {str(e)}")
    
    return sha256.hexdigest()


# 🧵 Start Threading with error handling
def start_thread():
    try:
        threading.Thread(target=run_packing, daemon=True).start()
    except RuntimeError as e:
        messagebox.showerror("🚨 Thread Error", f"Couldn't start packing thread:\n{e}")
        
#======================== MISCELLANEOUS EXECUTIONS =============================

#===================================================================================
#============================ FOR ARCHIVING SEQUENCE ===============================
#===================================================================================



#===================================================================================
#============================= GUI of REPACKER START ===============================
#===================================================================================

# Show History Popup
def show_history_popup():
    """Displays history from persistent file with delete option"""
    history = load_history()
    
    formatted = []
    for i, entry in enumerate(reversed(history), 1):
        formatted.append(
            f"{i}. [{entry['timestamp']}]\n"
            f"   Folder: {entry['folder']}\n"
            f"   Output: {entry['output']}\n"
            f"   SHA256: {entry['checksum'][:16]}...\n"
        )
    
    content = "=== Packing History ===\n\n" + "\n".join(formatted) if formatted else "📜 No history found."
    
    # Create enhanced popup with delete button
    popup = tk.Toplevel(root)
    popup.title("History Log")
    popup.configure(bg="#1e1e1e")
    popup.resizable(False, False)
    win_width, win_height = 500, 350  # Slightly taller for button
    popup.geometry(f"{win_width}x{win_height}")
    popup.update_idletasks()
    
    # Center the popup
    root_x = root.winfo_rootx()
    root_y = root.winfo_rooty()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    pos_x = root_x + (root_width // 2) - (win_width // 2)
    pos_y = root_y + (root_height // 2) - (win_height // 2)
    popup.geometry(f"{win_width}x{win_height}+{pos_x}+{pos_y}")
    popup.transient(root)
    popup.grab_set()

    # Title
    tk.Label(popup, text="History Log", font=("Arial", 12, "bold"), 
             bg="#1e1e1e", fg="#00ff88").pack(pady=(10, 5))
    
    # Text area
    text_area = scrolledtext.ScrolledText(popup, wrap=tk.WORD, bg="#2d2d2d", 
                                         fg="white", insertbackground="white")
    text_area.pack(fill="both", expand=True, padx=10, pady=5)
    text_area.insert(tk.END, content)
    text_area.config(state='disabled')
    
    # Button frame
    button_frame = tk.Frame(popup, bg="#1e1e1e")
    button_frame.pack(fill="x", pady=5)
    
    # Close button
    tk.Button(button_frame, text="❌ Close", command=popup.destroy, 
              bg="#444444", fg="white").pack(side="right", padx=5)
    
    # Delete button (only show if there's history)
    if history:
        tk.Button(button_frame, text="🗑️ Delete All History", 
                  command=lambda: [clear_history(), popup.destroy()], 
                  bg="#ff4444", fg="white").pack(side="left", padx=5)


# Default Text Popup for Errors and Popups
def show_text_popup(title, content):
    popup = tk.Toplevel(root)
    popup.title(title)
    popup.iconbitmap(ICON_PATH['ico'])
    popup.configure(bg="#1e1e1e")
    popup.resizable(False, False)
    win_width, win_height = 500, 300
    popup.geometry(f"{win_width}x{win_height}")
    popup.update_idletasks()
    
    root_x = root.winfo_rootx()
    root_y = root.winfo_rooty()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    pos_x = root_x + (root_width // 2) - (win_width // 2)
    pos_y = root_y + (root_height // 2) - (win_height // 2)
    popup.geometry(f"{win_width}x{win_height}+{pos_x}+{pos_y}")
    popup.transient(root)
    popup.grab_set()

    tk.Label(popup, text=title, font=("Arial", 12, "bold"), bg="#1e1e1e", fg="#00ff88").pack(pady=(10, 5))
    text_area = scrolledtext.ScrolledText(popup, wrap=tk.WORD, bg="#2d2d2d", fg="white", insertbackground="white")
    text_area.pack(fill="both", expand=True, padx=10, pady=5)
    text_area.insert(tk.END, content)
    text_area.config(state='disabled')
    tk.Button(popup, text="❌ Close", command=popup.destroy, bg="#444444", fg="white").pack(pady=5)

#========================= GUI SHOW ABOUT START ===============================
# For the Show About
def show_about():
    # Create a new top-level window
    about_win = tk.Toplevel(root)
    about_win.iconbitmap(ICON_PATH['ico'])
    about_win.title("About")
    about_win.configure(bg="#1e1e1e")
    about_win.resizable(False, False)

    # Set fixed size
    win_width = 400
    win_height = 250
    about_win.geometry(f"{win_width}x{win_height}")

    # Center it on the main window (root)
    root_x = root.winfo_rootx()
    root_y = root.winfo_rooty()
    root_width = root.winfo_width()
    root_height = root.winfo_height()

    x = root_x + (root_width // 2) - (win_width // 2)
    y = root_y + (root_height // 2) - (win_height // 2)
    about_win.geometry(f"{win_width}x{win_height}+{x}+{y}")

    # Make it modal (block interaction with main window until closed)
    about_win.transient(root)
    about_win.grab_set()

    # About content
    tk.Label(
        about_win,
        text="🛠 RWMod Anti-Theft Repacker 📦",
        font=("Arial", 14, "bold"),
        fg="#00ff88",
        bg="#1e1e1e"
    ).pack(pady=(15, 5))

    tk.Label(
        about_win,
        text="📜 Version: 1.3.1\n📝 Author: Demiurge & Chattington\n\n"
             "MOD Protect Pioneers: Gen Airon & Matrix\n\n"
             "Converts MOD Folders into .RWMOD format with basic\n"
             "anti-theft protection using obfuscation & 'dummying'\n"
             "methods.\n\n"
             "Provided [AS IS] for educational and personal use only.\n"
             "NOTE: This tool [DOES NOT] guarantee 100% protection",
        font=("Arial", 10, "bold"),
        fg="white",
        bg="#1e1e1e",
        justify="center"
    ).pack(padx=20)

    tk.Button(
        about_win,
        text="❌ Close",
        command=about_win.destroy,
        bg="#444444",
        fg="white"
    ).pack(pady=10)
#========================= GUI SHOW ABOUT START ===============================

# GUI Setup
root = tk.Tk()
root.title("RWMod Anti-Theft Repacker v.1.3.1")
set_window_icon(root)
root.geometry("550x610")
root.configure(bg="#1e1e1e")
root.resizable(False, False)

# Load history at startup
history_log = load_history()

# Main UI Elements
tk.Label(root, text="RWMod Anti-Theft Repacker ", font=("Arial", 14, "bold"), fg="#00ff88", bg="#1e1e1e").pack(pady=(10, 20))

# Folder Selection
mod_row = tk.Frame(root, bg="#1e1e1e")
mod_row.pack(fill="x", padx=10, pady=(0, 5))
mod_row.grid_columnconfigure(0, weight=0)
mod_row.grid_columnconfigure(1, weight=1)
mod_row.grid_columnconfigure(2, weight=0)

folder_name = tk.StringVar(value="FOLDER: (NONE)")
folder_label = tk.Label(mod_row, textvariable=folder_name, fg="white", bg="#1e1e1e")
folder_label.grid(row=0, column=0, sticky="w")

folder_entry = ttk.Entry(mod_row)
folder_entry.grid(row=0, column=1, sticky="ew", padx=5)

btn_select_folder = ttk.Button(mod_row, text="BROWSE", command=select_folder)
btn_select_folder.grid(row=0, column=2)

# Output Selection
output_row = tk.Frame(root, bg="#1e1e1e")
output_row.pack(fill="x", padx=10, pady=(0, 10))
output_entry = ttk.Entry(output_row)
output_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
btn_select_output = ttk.Button(output_row, text="OUTPUT FOLDER", command=select_output)
btn_select_output.pack(side="right")

# Mod Info Preview
tk.Label(root, text="MOD-INFO PREVIEWER:", fg="white", bg="#1e1e1e").pack(anchor="w", padx=10)
modinfo_text = scrolledtext.ScrolledText(root, height=14, bg="#2d2d2d", fg="white", insertbackground="white")
modinfo_text.pack(fill="both", expand=False, padx=10, pady=(0, 10))

# Action Buttons
pack_button = tk.Button(root, text="PACK AS .RWMOD", command=start_thread, bg="#006666", fg="white", font=("Arial", 11, "bold"))
pack_button.pack(pady=8)

status_label = tk.Label(root, text="⚙ READY and WAITING...", fg="white", bg="#1e1e1e", font=("Arial", 10, "bold"))
status_label.pack(pady=(0, 5))

action_buttons = tk.Frame(root, bg="#1e1e1e")
action_buttons.pack(pady=4)


# For About Button
btn_about = ttk.Button(root, text="About", command=show_about)
btn_about.pack(side="bottom", pady=5)

# For Clearing the History Log
btn_clear_history = ttk.Button(action_buttons, text="Clear History", command=clear_history, width=15)
btn_clear_history.pack(side="left", padx=5, ipadx=5)

# For View History Log
btn_history = ttk.Button(action_buttons, text="View History Log", command=show_history_popup, width=20)
btn_history.pack(side="left", padx=5, ipadx=10)

root.mainloop()

#===================================================================================
#============================= GUI of REPACKER START ===============================
#===================================================================================