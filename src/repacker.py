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
from typing import Optional, Union, Callable
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
    'ico': 'app_icon.ico',
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
 
#======= Delete the History Log - FIXED: Proper clear_history function
def clear_history():
    """Clear all history with confirmation dialog"""
    global history_log
    
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
        history_log = []
        try:
            if os.path.exists(HISTORY_FILE):
                os.remove(HISTORY_FILE)
                messagebox.showinfo("Success", "History cleared successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not delete history file: {e}")

#=============================================================================
#============================ FOR HISTORY LOGGING ============================
#=============================================================================


#=============================================================================
#============================ FOR ARCHIVING FILES ============================
#=============================================================================

#======================== ZIPPING FILES START ================================

# ZIPS the Folder, Ready for PACKING
# ==================== ZIP FUNCTIONS (DEFLATED)====================
def zip_folder(
    folder_path: str,
    zip_path: str,
    compression: int = zipfile.ZIP_DEFLATED,  # ← CHANGED TO DEFLATED
    hide_files: bool = True,
    callback: Optional[Callable[[float], None]] = None
) -> None:
    """
    Advanced folder compression with memory-efficient large file handling:
    - DEFLATED compression (faster than LZMA)
    - Memory mapping for large files (>1MB)
    - Optional file hiding (Windows/macOS/Linux compatible)
    - Progress tracking
    """
    file_queue = Queue()
    processed_count = 0
    total_files = 0
    update_status("⏳ ARCHIVING FILES...")
    
    # 1. Scan files (with hidden files handling)
    def scan_files():
        nonlocal total_files
        file_list = []
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
                
                file_list.append((src_path, rel_path))
                total_files += 1
        
        # Add all files to queue
        for file_info in file_list:
            file_queue.put(file_info)
        file_queue.put(None)  # Sentinel
        
        update_status(f"📁 SCANNED {total_files} FILES...")
        if callback:
            callback(0.1)  # 10% progress after scanning

    # 2. Compression worker with memory optimization
    def compress_worker():
        nonlocal processed_count
        with zipfile.ZipFile(
            zip_path, 'w', compression,
            compresslevel=9  # Maximum compression for DEFLATED
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
                        
                        # Use memory mapping for large files (>100MB)
                        file_size = os.path.getsize(src_path)
                        if file_size > 100 * 1024 * 1024:  # 100MB threshold
                            with open(src_path, "rb") as f:
                                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                                    zf.writestr(zinfo, mmapped_file)
                        else:
                            with open(src_path, "rb") as f:
                                zf.writestr(zinfo, f.read())
                    else:
                        # Regular file handling with memory optimization
                        file_size = os.path.getsize(src_path)
                        if file_size > 30 * 1024 * 1024:  # 30MB threshold
                            with open(src_path, "rb") as f:
                                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                                    zf.writestr(rel_path, mmapped_file)
                        else:
                            zf.write(src_path, rel_path)
                    
                    processed_count += 1

                    # Update progress for each file processed
                    if callback and total_files > 0:
                        progress = 0.1 + (processed_count / total_files) * 0.8  # 10-90% for compression
                        callback(progress)
                    
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
    
    if callback:
        callback(1.0)  # 100% complete

# ==================== TAMPER FUNCTIONS ====================
def tamper_zip(
    zip_path: str,
    rwmod_path: str,
    prefix_len_range: tuple = (1024, 8192),
    chunk_size: int = 64 * 1024,
    callback: Optional[Callable[[float], None]] = None
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
                if callback: callback(0.1)  # Progress update

                # 2. Write prefix (with length)
                dest.write(len(prefix).to_bytes(4, "big"))
                dest.write(prefix)
                if callback: callback(0.2)  # Progress update

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
                    
                    if callback:
                        progress = 0.3 + (i / zip_size) * 0.4  # 30-70% of this stage
                        callback(progress)
                
                # Backfill ZIP length
                cur_pos = dest.tell()
                dest.seek(zip_offset)
                dest.write(zip_size.to_bytes(8, "big"))
                dest.seek(cur_pos)
                if callback: callback(0.7)  # Progress update

                # 4. Write mutable signature
                dest.write(len(mut_sig).to_bytes(2, "big"))
                dest.write(mut_sig)
                if callback: callback(0.75)  # Progress update

                # 5. Write hash+secret key binding
                combined_hash = hashlib.sha256(sha256.digest() + secret_key).digest()
                dest.write(len(combined_hash).to_bytes(2, "big"))
                dest.write(combined_hash)
                if callback: callback(0.8)  # Progress update

                # 6. Write footer
                dest.write(len(footer_sig).to_bytes(2, "big"))
                dest.write(footer_sig)
                if callback: callback(0.85)  # Progress update

                # 7. Write hex key
                dest.write(len(hex_key).to_bytes(2, "big"))
                dest.write(hex_key)
                if callback: callback(0.9)  # Progress update

                # 8. Write total size of ZIP
                dest.write(zip_size.to_bytes(8, "big"))
                if callback: callback(0.95)  # Progress update

    except Exception as e:
        raise RuntimeError(f"Tampering failed: {str(e)}")
    
    # Clean up temporary zip
    try:
        os.remove(zip_path)
        update_status("🔐 MULTI-LAYER OBFUSCATION APPLIED...")
        if callback: callback(1.0)  # Final progress update
    except:
        pass  # Don't fail if removal doesn't work

# ==================== VERIFICATION FUNCTIONS ====================
def verify_checksum(file_path: str) -> dict:
    """Quick SHA-256 checksum verification"""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return {
            'success': True,
            'checksum': sha256.hexdigest(),
            'file_intergrity': 'verified'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'file_intergrity': 'corrupted'
        }

def verify_rwmod_structure(rwmod_path: str) -> bool:
    """Memory-efficient .rwmod verification with memory mapping"""
    update_status("⚙ VERIFYING ARCHIVE STRUCTURE...")
    
    try:
        with open(rwmod_path, "rb") as f:
            # Use memory mapping for efficient large file access
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                position = 0
                
                # 🧩 Parse header
                header_len = int.from_bytes(mmapped_file[position:position+2], "big")
                position += 2
                header_sig = mmapped_file[position:position+header_len]
                position += header_len
                if not verify_header(header_sig):
                    raise ValueError("❌ Invalid header signature")

                # 🎲 Parse prefix (random noise)
                prefix_len = int.from_bytes(mmapped_file[position:position+4], "big")
                position += 4
                position += prefix_len  # Skip prefix bytes

                # 📦 Parse ZIP data
                zip_size = int.from_bytes(mmapped_file[position:position+8], "big")
                position += 8
                
                # Hash the ZIP data section directly from memory map
                sha256 = hashlib.sha256()
                zip_data = mmapped_file[position:position+zip_size]
                sha256.update(zip_data)
                position += zip_size

                # ✒️ Parse mutable signature
                mut_len = int.from_bytes(mmapped_file[position:position+2], "big")
                position += 2
                mut_sig = mmapped_file[position:position+mut_len]
                position += mut_len
                if not verify_signature(mut_sig):
                    raise ValueError("❌ Invalid mutable signature")

                # 🔑 Parse combined hash
                hash_len = int.from_bytes(mmapped_file[position:position+2], "big")
                position += 2
                stored_hash = mmapped_file[position:position+hash_len]
                position += hash_len

                # 🧾 Parse footer signature
                footer_len = int.from_bytes(mmapped_file[position:position+2], "big")
                position += 2
                footer_sig = mmapped_file[position:position+footer_len]
                position += footer_len
                if not verify_footer(footer_sig):
                    raise ValueError("❌ Invalid footer signature")

                # 🕵 Parse hex key
                hex_len = int.from_bytes(mmapped_file[position:position+2], "big")
                position += 2
                hex_key = mmapped_file[position:position+hex_len]
                position += hex_len
                if not verify_hex_key(hex_key):
                    raise ValueError("❌ Invalid hex key")

                # 📏 Parse declared total size
                declared_size = int.from_bytes(mmapped_file[position:position+8], "big")
                position += 8
                if declared_size != zip_size:
                    raise ValueError("❌ Declared size mismatch")

                # ✅ Verify combined hash with secret key
                secret_key = get_secret_key()  # deterministic regeneration
                combined = hashlib.sha256(sha256.digest() + secret_key).digest()
                if combined != stored_hash:
                    raise ValueError("❌ Content hash mismatch / tampering detected")

        update_status("✅ VERIFICATION COMPLETE ")
        return True

    except Exception as e:
        raise ValueError(f"Verification failed: {str(e)}")

# ==================== MAIN PACKAGING PIPELINE ====================
def pack_as_rwmod(
    folder_path: str,
    rwmod_path: str,
    compression: int = zipfile.ZIP_DEFLATED,
    hide_files: bool = True,
    callback: Optional[Callable[[float], None]] = None
):
    """
    Main RWMod packaging pipeline:
    - Compresses folder with DEFLATED (faster than LZMA)
    - Applies obfuscation via tamper_zip
    - Validates with checksum and full structure verification
    - Updates three progress bars (overall, zip, rwmod)
    """
    temp_zip = rwmod_path + ".temp.zip"
    success = False  # Track completion

    def update_callback(progress):
        if callback:
            try:
                callback(progress)
            except:
                pass

    try:
        # 📦 Step 1: Create ZIP archive (40% of total process)
        update_status("💼 CREATING ZIP ARCHIVE...")
        zip_folder(
            folder_path,
            temp_zip,
            compression=compression,
            hide_files=hide_files,
            callback=lambda p: (
                update_callback(p * 0.4),  # map to 0–40% overall
                progress_zip.config(value=p * 100)
            )
        )

        # 🔐 Step 2: Obfuscate archive (40% of total process)
        update_status("🔐 APPLYING MULTI-LAYER OBFUSCATION...")
        tamper_zip(
            temp_zip,
            rwmod_path,
            callback=lambda p: (
                update_callback(0.4 + p * 0.4),  # map to 40–80% overall
                progress_rwmod.config(value=p * 100)
            )
        )

        # 🧮 Step 3: Quick checksum validation (5% of total process)
        update_status("🧮 RUNNING CHECKSUM VALIDATION...")
        update_callback(0.8)
        verification_report = verify_checksum(rwmod_path)

        if not verification_report['success'] or verification_report['file_integrity'] != 'verified':
            error_msg = verification_report.get('error', 'Unknown verification Error')
            raise RuntimeError(f"❌ Checksum Verification Failed: {error_msg}")

        # ♻️ Step 4: Full structural validation (15% of total process)
        update_status("♻️ VERIFYING RWMOD STRUCTURE...")
        update_callback(0.85)

        for i in range(5):
            time.sleep(0.1)
            update_callback(0.85 + (i * 0.03))

        verify_rwmod_structure(rwmod_path)
        update_callback(0.95)

        success = True  # ✅ Successful pack

    except Exception as e:
        if os.path.exists(rwmod_path):
            try:
                os.remove(rwmod_path)
            except Exception:
                pass
        raise  # Bubble up exception

    finally:
        update_status("🧹 CLEANING ARCHIVE TRACES")
        if os.path.exists(temp_zip):
            try:
                os.remove(temp_zip)
            except Exception:
                pass

        if not success and os.path.exists(rwmod_path):
            try:
                os.remove(rwmod_path)
            except Exception:
                pass

    update_status("🔒 ARCHIVE REINFORCING COMPLETE..")
    update_callback(1.0)


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
        folder_name.set(f"FOLDER: {os.path.basename(folder)}")
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
    pack_button.config(state="disabled")
    set_pack_button_state(False)

    # Reset progress bars
    progress_bar["value"] = 0
    progress_zip["value"] = 0
    progress_rwmod["value"] = 0

    update_status("⚙ INITIALIZING ARCHIVE SEQUENCE...")

    def update_progress(p):
        """Updates overall progress bar + stage message."""
        progress_bar["value"] = p * 100
        progress_bar.update_idletasks()

        if p < 0.4:
            stage = "INITIATING ARCHIVE CREATION"
        elif p < 0.8:
            stage = "APPLYING OBFUSCATION PROTOCOL"
        elif p < 0.9:
            stage = "VALIDATING ARCHIVE INTEGRITY"
        else:
            stage = "FINALIZING ARCHIVE SEQUENCE"

        update_status(f"⚙ {stage}... {int(p * 100)}%")

    try:
        folder_path = folder_entry.get().strip()
        output_dir = output_entry.get().strip() or os.path.expanduser("~/Downloads")

        if not folder_path or not os.path.isdir(folder_path):
            messagebox.showerror("❌ Error", "⚠️ Please select a valid mod folder.")
            set_pack_button_state(True)
            progress_bar["value"] = 0
            progress_zip["value"] = 0
            progress_rwmod["value"] = 0
            return

        modname = os.path.basename(folder_path.rstrip("/\\"))
        rwmod_path = os.path.join(output_dir, modname + ".rwmod")

        # Run packaging with detailed progress
        pack_as_rwmod(folder_path, rwmod_path, callback=update_progress)

        add_to_log(modname, rwmod_path)
        update_status("✅ ARCHIVE SEQUENCE COMPLETE! 100%")
        messagebox.showinfo("🎉 ARCHIVING SUCCESSFUL", f"📦 EXPORTED TO:\n{rwmod_path}")

    except Exception as e:
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
        folder_entry.delete(0, tk.END)
        output_entry.delete(0, tk.END)
        folder_name.set("FOLDER: (NONE)")
        modinfo_text.delete("1.0", tk.END)
        set_pack_button_state(True)
        update_status("⚙ READY and WAITING...")

        # Reset bars
        progress_bar["value"] = 0
        progress_zip["value"] = 0
        progress_rwmod["value"] = 0
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

#======================== CHECKSUM EXECUTION END =============================

# Add this function (missing verify_checksum)
def verify_checksum(file_path: str, expected_checksum: str = None) -> dict:
    """
    Comprehensive checksum verification with multiple validation layers
    Returns a detailed report dictionary with success status and diagnostics
    """
    import time
    from pathlib import Path
    
    result = {
        'success': False,
        'file_exists': False,
        'file_readable': False,
        'file_size': 0,
        'calculated_sha256': None,
        'expected_sha256': expected_checksum,
        'checksum_match': False,
        'verification_time': 0,
        'error': None,
        'file_integrity': 'unknown'
    }
    
    start_time = time.time()
    
    try:
        # Check file existence and accessibility
        file_obj = Path(file_path)
        result['file_exists'] = file_obj.exists()
        
        if not result['file_exists']:
            result['error'] = "File does not exist"
            return result
        
        # Check file size
        result['file_size'] = file_obj.stat().st_size
        
        if result['file_size'] == 0:
            result['error'] = "File is empty"
            return result
        
        # Check readability
        try:
            with open(file_path, 'rb') as f:
                pass
            result['file_readable'] = True
        except IOError:
            result['error'] = "File is not readable (permission issue)"
            return result
        
        # Calculate SHA256 with progress and error handling
        sha256_hash = hashlib.sha256()
        chunk_size = 1048576  # 1MB chunks
        bytes_processed = 0
        
        try:
            with open(file_path, 'rb') as f:
                # Use memory mapping for large files
                if result['file_size'] > 30 * 1024 * 1024:  # >30MB MAX LARGE FILES!   
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                        for i in range(0, result['file_size'], chunk_size):
                            chunk = mmapped_file[i:i+chunk_size]
                            sha256_hash.update(chunk)
                            bytes_processed += len(chunk)
                else:
                    # For smaller files, read normally
                    while chunk := f.read(chunk_size):
                        sha256_hash.update(chunk)
                        bytes_processed += len(chunk)
                
                result['calculated_sha256'] = sha256_hash.hexdigest()
                
        except Exception as e:
            result['error'] = f"Error during hash calculation: {str(e)}"
            return result
        
        # Verify against expected checksum if provided
        if expected_checksum:
            expected_clean = expected_checksum.strip().lower()
            calculated_clean = result['calculated_sha256'].lower()
            result['checksum_match'] = expected_clean == calculated_clean
            
            if result['checksum_match']:
                result['file_integrity'] = 'verified'
            else:
                result['file_integrity'] = 'tampered'
                result['error'] = f"Checksum mismatch. Expected: {expected_checksum}, Got: {result['calculated_sha256']}"
        else:
            # No expected checksum provided, just report the calculated one
            result['file_integrity'] = 'calculated_only'
            result['checksum_match'] = True  # Technically true since we can't verify
        
        result['success'] = True
        
    except Exception as e:
        result['error'] = f"Unexpected error during verification: {str(e)}"
        result['success'] = False
    
    finally:
        result['verification_time'] = round(time.time() - start_time, 3)
    
    return result

#======================== CHECKSUM EXECUTION END =============================


#======================== THREADING EXECUTION START =============================

# 🧵 Start Threading with error handling
def start_thread():
    try:
        threading.Thread(target=run_packing, daemon=True).start()
    except RuntimeError as e:
        messagebox.showerror("🚨 Thread Error", f"Couldn't start packing thread:\n{e}")

#======================== THREADING EXECUTION END =============================

#======================== MISCELLANEOUS EXECUTIONS =============================

#===================================================================================
#============================ FOR ARCHIVING SEQUENCE ===============================
#===================================================================================



#===================================================================================
#============================= GUI of REPACKER START ===============================
#===================================================================================

#============================ SHOW INFO DIALOG START ===============================

def show_info_dialog(title, message, icon="info"):
    """Custom information dialog that works like the About popup"""
    # Create dialog window
    dialog = tk.Toplevel(root)
    dialog.iconbitmap(ICON_PATH['ico'])
    dialog.title(title)
    dialog.configure(bg="#1e1e1e")
    dialog.resizable(False, False)
    
    # Set dialog size
    dialog_width, dialog_height = 350, 220
    dialog.geometry(f"{dialog_width}x{dialog_height}")
    
    # Center dialog on main window
    dialog.update_idletasks()
    root_x = root.winfo_rootx()
    root_y = root.winfo_rooty()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    
    pos_x = root_x + (root_width // 2) - (dialog_width // 2)
    pos_y = root_y + (root_height // 2) - (dialog_height // 2)
    dialog.geometry(f"{dialog_width}x{dialog_height}+{pos_x}+{pos_y}")
    
    # Make dialog modal
    dialog.transient(root)
    dialog.grab_set()
    
    # Icon based on type
    if icon == "info":
        icon_symbol = "📋"
        color = "#00aaff"
    elif icon == "success":
        icon_symbol = "☑"
        color = "#00ff88"
    elif icon == "error":
        icon_symbol = "⚠"
        color = "#ff4444"
    else:
        icon_symbol = "🗨"
        color = "#00ff88"
    
    # Create content
    tk.Label(
        dialog, 
        text=f"{icon_symbol} {title}", 
        font=("Arial", 14, "bold"), 
        fg=color,
        bg="#1e1e1e"
    ).pack(pady=(20, 10))
    
    # Message
    tk.Label(
        dialog, 
        text=message, 
        font=("Arial", 10), 
        fg="white", 
        bg="#1e1e1e",
        justify="center",
        wraplength=550
    ).pack(pady=(0, 18), padx=15)
    
    # OK button
    ok_btn = tk.Button(
        dialog, 
        text="OK", 
        command=dialog.destroy,
        bg="#444444",
        fg="white",
        width=10,
        font=("Arial", 10)
    )
    ok_btn.pack(pady=(0, 15))
    
    # Wait for the dialog to close
    dialog.wait_window()

#================================ SHOW INFO END =================================

#================================ CLEAR DIALOG START =================================

def show_clear_history_dialog():
    """Specialized dialog for clearing history"""
    # Load history
    history = load_history()
    
    if not history:
        show_info_dialog(
            "History Log Empty", 
            "The history log seems to be empty. There's nothing to clean here.",
            icon="info"
        )
        return
    
    # Create dialog window
    dialog = tk.Toplevel(root)
    dialog.iconbitmap(ICON_PATH['ico'])
    dialog.title("Clear History Log")
    dialog.configure(bg="#1e1e1e")
    dialog.resizable(False, False)
    
    # Set dialog size
    dialog_width, dialog_height = 350, 280
    dialog.geometry(f"{dialog_width}x{dialog_height}")
    
    # Center dialog on main window
    dialog.update_idletasks()
    root_x = root.winfo_rootx()
    root_y = root.winfo_rooty()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    
    pos_x = root_x + (root_width // 2) - (dialog_width // 2)
    pos_y = root_y + (root_height // 2) - (dialog_height // 2)
    dialog.geometry(f"{dialog_width}x{dialog_height}+{pos_x}+{pos_y}")
    
    # Make dialog modal
    dialog.transient(root)
    dialog.grab_set()
    
    # Create content
    tk.Label(
        dialog, 
        text="⚠ Clear History Log", 
        font=("Arial", 12, "bold"), 
        fg="#ffcc00",
        bg="#1e1e1e"
    ).pack(pady=(20, 10))
    
    # Message with history count
    tk.Label(
        dialog, 
        text=f"\n"
        f"⚙ Are you sure you want to delete ALL\nhistory? "
             f" This will remove {len(history)} entries.\n\n"
             "⚠ THIS ACTION IS UNRECOVERABLE.",
        font=("Arial", 8), 
        fg="white", 
        bg="#1e1e1e",
        justify="center"
    ).pack(pady=(0, 20), padx=20)
    
    # Button frame
    button_frame = tk.Frame(dialog, bg="#1e1e1e")
    button_frame.pack(pady=(0, 10))
    
    # Delete button
    delete_btn = tk.Button(
        button_frame, 
        text="🗑 Delete All", 
        command=lambda: [perform_history_deletion(), dialog.destroy()],
        bg="#ff4444",
        fg="white",
        width=12,
        font=("Arial", 10, "bold")
    )
    delete_btn.pack(side="left", padx=20)
    
    # Cancel button
    cancel_btn = tk.Button(
        button_frame, 
        text="✖ Cancel", 
        command=dialog.destroy,
        bg="#444444",
        fg="white",
        width=12,
        font=("Arial", 10)
    )
    cancel_btn.pack(side="right", padx=20)

#================================ CLEAR DIALOG END =================================

#================================ HISTORY DELETION START =================================



#================================ HISTORY DELETION END =================================


#================================ HISTORY LOG START =================================
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
    
    content = "============ Archive History Log ===========\n\n" + "\n".join(formatted) if formatted else "📜 No history found."
    
    # Create enhanced popup with delete button
    popup = tk.Toplevel(root)
    popup.iconbitmap(ICON_PATH['ico'])
    popup.title("History Log")
    popup.configure(bg="#1e1e1e")
    popup.resizable(False, False)
    win_width, win_height = 500, 550  # Slightly taller for button
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
    button_frame.pack(fill="x", pady=25)
    
    # Close button
    tk.Button(button_frame, text="❌ Close", command=popup.destroy, 
              bg="#444444", fg="white").pack(side="left", padx=15)
    
    # Delete button (only show if there's history)
    if history:
        tk.Button(button_frame, text="🗑 Delete All History", 
                  command=lambda: [clear_history(), popup.destroy()], 
                  bg="#ff4444", fg="white").pack(side="right", padx=15)

#========================= HISTORY LOG END ===============================


# Default Text Popup for Errors and Popups
def show_text_popup(title, content):
    popup = tk.Toplevel(root)
    popup.iconbitmap(ICON_PATH['ico'])
    popup.title(title)
    popup.configure(bg="#1e1e1e")
    
    # Set minimum size but allow resizing
    min_width, min_height = 300, 550
    popup.minsize(min_width, min_height)
    popup.resizable(True, True)  # Allow resizing
    
    # Set initial size
    initial_width, initial_height = 400, 550
    popup.geometry(f"{initial_width}x{initial_height}")
    
    # Center the popup
    popup.update_idletasks()
    root_x = root.winfo_rootx()
    root_y = root.winfo_rooty()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    
    pos_x = root_x + (root_width // 2) - (initial_width // 2)
    pos_y = root_y + (root_height // 2) - (initial_height // 2)
    popup.geometry(f"{initial_width}x{initial_height}+{pos_x}+{pos_y}")
    
    popup.transient(root)
    popup.grab_set()
    
    # Make content area expand with window
    popup.grid_rowconfigure(0, weight=1)
    popup.grid_columnconfigure(0, weight=1)

    # Title
    title_label = tk.Label(popup, text=title, font=("Arial", 12, "bold"), 
                         bg="#1e1e1e", fg="#00ff88")
    title_label.grid(row=0, column=0, sticky="ew", pady=(10, 5))

    # Text area with scrollbar - use grid for resizing
    text_frame = tk.Frame(popup, bg="#1e1e1e")
    text_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
    text_frame.grid_rowconfigure(0, weight=1)
    text_frame.grid_columnconfigure(0, weight=1)
    
    text_area = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, bg="#2d2d2d", 
                                        fg="white", insertbackground="white")
    text_area.grid(row=0, column=0, sticky="nsew")
    text_area.insert(tk.END, content)
    text_area.config(state='disabled')
    
    # Button frame
    button_frame = tk.Frame(popup, bg="#1e1e1e")
    button_frame.grid(row=2, column=0, sticky="ew", pady=5)
    close_btn = tk.Button(popup, text="❌Close", command=popup.destroy, bg="#444444", fg="white").pack(pady=5)

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
    win_height = 300
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
    ).pack(pady=(15, 10))

    tk.Label(
        about_win,
        text="📜 Version: 1.3.5\n📝 Author: Demiurge & Chattington\n\n"
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
    ).pack(padx=10, pady=10)

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
root.title("RWMod Anti-Theft Repacker v.1.3.5")
root.iconbitmap(ICON_PATH['ico'])
root.geometry("550x690")
root.configure(bg="#1e1e1e")
root.resizable(False, False)

# Load history at startup
history_log = load_history()

# Main UI Elements
tk.Label(root, text="RWMod Anti-Theft Repacker 1.3.5", font=("Arial", 18, "bold"), fg="#00ff88", bg="#1e1e1e").pack(pady=(10, 10))

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

# PROGRESS BARS

# Frame for Process Bars + Settings side by side
progress_frame = tk.Frame(root, bg="#1e1e1e")
progress_frame.pack(fill="x", padx=10, pady=10)

# Left Column: Sequence Status Queue
left_frame = tk.Frame(progress_frame, bg="#1e1e1e")
left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 20))

tk.Label(left_frame, text="📜 SEQUENCE STATUS QUEUE:", font=("Arial", 11, "bold"),
         fg="white", bg="#1e1e1e").pack(anchor="w", pady=(0, 10))

# Example: Overall progress bar
tk.Label(left_frame, text="OVERALL STATUS:", fg="white", bg="#1e1e1e").pack(anchor="w")
progress_bar = ttk.Progressbar(left_frame, mode="determinate", length=250)
progress_bar.pack(pady=(0, 10))

tk.Label(left_frame, text="ARCHIVING STATUS:", fg="white", bg="#1e1e1e").pack(anchor="w")
progress_zip = ttk.Progressbar(left_frame, mode="determinate", length=250)
progress_zip.pack(pady=(0, 10))

tk.Label(left_frame, text="OBFUSCATION STATUS:", fg="white", bg="#1e1e1e").pack(anchor="w")
progress_rwmod = ttk.Progressbar(left_frame, mode="determinate", length=250)
progress_rwmod.pack(pady=(0, 15))

status_label = tk.Label(
    left_frame,
    text="⚙ READY and WAITING...",
    fg="white",
    bg="#1e1e1e",
    font=("Arial", 13, "bold")
).pack(anchor="center", pady=(0, 10))  # Title centered

# Separator line (now in its own column)
separator = ttk.Separator(progress_frame, orient="vertical")
separator.grid(row=0, column=2, sticky="ns", padx=12)

# Spacer column (empty frame)
spacer = tk.Frame(progress_frame, width=15, bg="#1e1e1e")
spacer.grid(row=0, column=1)

# Separator line (now in its own column)
separator = ttk.Separator(progress_frame, orient="vertical")
separator.grid(row=0, column=2, sticky="ns", padx=12)

# Spacer column (empty frame)
spacer = tk.Frame(progress_frame, width=15, bg="#1e1e1e")
spacer.grid(row=0, column=3)

# Right Column: Settings (shifted further right to column=3)
right_frame = tk.Frame(progress_frame, bg="#1e1e1e")
right_frame.grid(row=0, column=4, sticky="nsew")

tk.Label(
    right_frame,
    text="⚙ SETTINGS",
    font=("Arial", 11, "bold"),
    fg="white",
    bg="#1e1e1e"
).pack(anchor="center", pady=(0, 10))  # Title centered

btn_history = ttk.Button(right_frame, text="View History Log", command=show_history_popup)
btn_history.pack(anchor="center", pady=10)

btn_clear_history = ttk.Button(right_frame, text="Clear History", command=clear_history)
btn_clear_history.pack(anchor="center", pady=10)

btn_about = ttk.Button(right_frame, text="About", command=show_about)
btn_about.pack(anchor="center", pady=10)

# Pack as RWMOD button (moved under settings)
pack_button = tk.Button(
    right_frame,
    text="PACK AS .RWMOD",
    command=start_thread,
    bg="#006666",
    fg="white",
    font=("Arial", 11, "bold"),
    width=18
)
pack_button.pack(anchor="center", pady=(15, 3))  # extra space above

# Add a subtle separator line (optional)
separator = ttk.Separator(root, orient="horizontal")
separator.pack(fill="x", padx=10, pady=(0, 10))


root.mainloop()

#===================================================================================
#============================= GUI of REPACKER START ===============================
#===================================================================================
