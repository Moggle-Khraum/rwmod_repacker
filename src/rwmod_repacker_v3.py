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

history_log = []

# Replace your old constants with these:
def get_header_sig():
    base = b"\x89\x50\x4E\x47"  # PNG start
    return mutable_signature(base + b"\x0D\x0A\x1A\x0A")

def get_footer_sig():
    # Fixed footer base (no mutation here)
    base = b"\xDE\xAD\xBE\xEF--RWMOD_LOCKED--\x00\x00"
    return base

def get_secret_key():
    return mutable_hex_key(2023) + b"_MODSEC_" + mutable_hex_key(os.getpid())

def add_to_log(folder_name, output_path):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] Packed '{folder_name}' to '{output_path}'"
    history_log.append(log_entry)
    
def generate_footer_signature():
    prefix = b"--RWMOD_LOCKED--"
    rand_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=10)).encode()
    return prefix + rand_suffix

# --- UPDATED zip_folder with trailing junk obfuscation ---

def add_junk_trailing(data: bytes, junk_len=32) -> bytes:
    return data + os.urandom(junk_len)

def create_zipinfo_with_new_size(original_info, new_size):
    zi = zipfile.ZipInfo(filename=original_info.filename)
    zi.date_time = original_info.date_time if hasattr(original_info, "date_time") else time.localtime()[:6]
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = getattr(original_info, "external_attr", 0)
    zi.create_system = getattr(original_info, "create_system", 0)
    # Setting file_size on ZipInfo is not required for writestr but can be helpful
    # ZipInfo.file_size is read-only, so we don't set it directly.
    return zi

def zip_folder(folder_path, zip_path):
    update_status("🗜 Zipping files without file content tampering...")
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, folder_path)
                # Store files exactly as they are
                zf.write(abs_path, rel_path)


# 3. Update tamper_zip to use dynamic signatures:
def tamper_zip(zip_path, rwmod_path, prefix_len_range=(1024, 8192)):
    """Offset-shift ZIP with random prefix and append hash+footer+size."""
    update_status("🔐 Adding offset + protection...")
    footer_signature = get_footer_sig()  # Your existing footer signature function

    with open(zip_path, "rb") as f:
        zip_data = f.read()

    # SHA256 of original zip data
    content_hash = hashlib.sha256(zip_data).digest()

    # Random prefix (offset shifting)
    prefix_len = random.randint(*prefix_len_range)
    prefix = os.urandom(prefix_len)

    # Final file layout
    with open(rwmod_path, "wb") as out:
        out.write(prefix)                 # random prefix bytes
        out.write(zip_data)               # zip data
        out.write(content_hash)           # 32-byte hash
        out.write(footer_signature)       # footer bytes
        out.write(len(zip_data).to_bytes(4, "big"))  # original zip size

    os.remove(zip_path)  # Clean up temporary zip


def verify_rwmod_integrity(file_path):
    """Verifies .rwmod with optional random prefix."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Get stored size from last 4 bytes
        zip_size = int.from_bytes(data[-4:], 'big')

        # Get footer signature length dynamically
        footer_sig = get_footer_sig()
        footer_len = len(footer_sig)

        # Positions
        footer_start = - (footer_len + 4)
        hash_start = footer_start - 32
        zip_end = hash_start
        zip_start = zip_end - zip_size

        # Verify footer
        if data[footer_start:-4] != footer_sig:
            return False, "Footer signature mismatch"

        # Verify hash
        stored_hash = data[hash_start:footer_start]
        zip_data = data[zip_start:zip_end]
        calc_hash = hashlib.sha256(zip_data).digest()
        if stored_hash != calc_hash:
            return False, "Content hash mismatch"

        return True, "Verification passed"

    except Exception as e:
        return False, f"Verification error: {str(e)}"



def verify_signature(sig, base_pattern):
    """Flexible verification that allows some mutation"""
    if len(sig) != len(base_pattern):
        return False
    
    # Allow ±3 variation in the last 4 bytes
    for i in range(len(sig)):
        if i < len(sig) - 4:  # First part must match exactly
            if sig[i] != base_pattern[i]:
                return False
        else:  # Last 4 bytes can vary slightly
            if abs(sig[i] - base_pattern[i]) > 3:
                return False
    return True

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def mutable_hex_key(seed=None):
    """Generates a mutable hex key that changes based on runtime factors"""
    if seed is None:
        seed = int(time.time()) % 1000  # Time-based seed
        
    # Dynamic components
    pid = os.getpid() % 256
    rand_val = random.randint(1, 255)
    
    # Algorithm to generate mutable key
    key_part1 = bytes([(pid + seed) % 256, (rand_val * 3) % 256])
    key_part2 = bytes([(pid ^ seed) % 256, (rand_val + 0xBE) % 256])
    
    return key_part1 + key_part2

def mutable_signature(base_sig):
    """Creates a signature that mutates while maintaining validation rules"""
    mutable_part = bytes([(x + random.randint(0, 3)) % 256 for x in base_sig[-4:]])
    return base_sig[:-4] + mutable_part

def generate_fake_header():
    """Generates a header with embedded secret key"""
    header = get_header_sig()
    secret_key = get_secret_key()
    # Embed parts of the secret key in random positions
    positions = sorted(random.sample(range(len(header), len(header)+24), k=3))
    header += bytes(random.getrandbits(8) for _ in range(24))
    for i, pos in enumerate(positions):
        header = header[:pos] + secret_key[i:i+1] + header[pos+1:]
    return header

def pack_as_rwmod(folder_path, rwmod_path):
    temp_zip = rwmod_path + ".temp.zip"
    zip_folder(folder_path, temp_zip)
    tamper_zip(temp_zip, rwmod_path)
    update_status("🔄 Verifying protection...")

    # Verify the created file
    is_valid, message = verify_rwmod_integrity(rwmod_path)
    if not is_valid:
        os.remove(rwmod_path)
        raise RuntimeError(f"Protection verification failed: {message}")

    time.sleep(3.5)

def update_status(msg):
    status_label.config(text=msg)
    status_label.update()

def select_folder():
    folder = filedialog.askdirectory()
    if folder:
        folder_entry.delete(0, tk.END)
        folder_entry.insert(0, folder)
        folder_name.set(f"📁 Folder: {os.path.basename(folder)}")
        modinfo_path = os.path.join(folder, "mod-info.txt")
        if os.path.exists(modinfo_path):
            try:
                with open(modinfo_path, 'r', encoding='utf-8', errors='ignore') as f:
                    modinfo_text.delete('1.0', tk.END)
                    modinfo_text.insert(tk.END, f.read())
            except Exception as e:
                modinfo_text.delete('1.0', tk.END)
                modinfo_text.insert(tk.END, f"[Error reading mod-info.txt: {e}]")
        else:
            modinfo_text.delete('1.0', tk.END)
            modinfo_text.insert(tk.END, "No mod-info.txt found.")

def select_output():
    output = filedialog.askdirectory()
    if output:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, output)


# Disable and enable the Pack button
def set_pack_button_state(enabled: bool):
    if enabled:
        pack_button.config(state="normal")
    else:
        pack_button.config(state="disabled")

def run_packing():
    set_pack_button_state(False)  # Disable button on start

    try:
        folder_path = folder_entry.get().strip()
        output_dir = output_entry.get().strip() or os.path.expanduser("~/Downloads")

        if not folder_path or not os.path.isdir(folder_path):
            messagebox.showerror("Error", "Please select a valid mod folder.")
            set_pack_button_state(True)
            return

        modname = os.path.basename(folder_path.rstrip("/\\"))
        rwmod_path = os.path.join(output_dir, modname + ".rwmod")

        pack_as_rwmod(folder_path, rwmod_path)

        # ✅ Simple integrity check using SHA-256
        checksum_valid = False
        try:
            sha256 = calculate_sha256(rwmod_path)
            if sha256 and os.path.getsize(rwmod_path) > 0:
                checksum_valid = True
        except:
            checksum_valid = False

        # 📝 Add to history log with checksum result
        result = "✅ Checksum OK" if checksum_valid else "❌ Checksum Failed"
        add_to_log(modname, rwmod_path)

        update_status("✅ SUCCESS!")
        messagebox.showinfo("Done", f"Packed to:\n{rwmod_path}")

        # Reset UI
        folder_entry.delete(0, tk.END)
        output_entry.delete(0, tk.END)
        folder_name.set("📁 Folder: (none)")
        modinfo_text.delete('1.0', tk.END)
        update_status("READY and WAITING...")

    except Exception as e:
        update_status("❌ FAILED.")
        messagebox.showerror("Error", str(e))
    finally:
        set_pack_button_state(True)  # Re-enable button no matter what

        
def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def start_thread():
    threading.Thread(target=run_packing, daemon=True).start()

def show_about():
    # Create a new top-level window
    about_win = tk.Toplevel(root)
    about_win.title("About")
    about_win.configure(bg="#1e1e1e")
    about_win.resizable(False, False)

    # Set fixed size
    win_width = 400
    win_height = 220
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
        text="RWMod Anti-Theft Packer",
        font=("Arial", 14, "bold"),
        fg="#00ff88",
        bg="#1e1e1e"
    ).pack(pady=(15, 5))

    tk.Label(
        about_win,
        text="Version: 1.3\nAuthor: Demiurge & Chattington\n\n"
             "MOD Protect Pioneers: Gen Airon & Matrix\n\n"
             "Converts MOD Folders into .RWMOD format with basic\n"
             "anti-theft protection using obfuscation and tampering\n"
             "methods.\n\n"
             "Provided [as is] for educational and personal use only.",
        font=("Arial", 10, "bold"),
        fg="white",
        bg="#1e1e1e",
        justify="center"
    ).pack(padx=20)

    tk.Button(
        about_win,
        text="Close",
        command=about_win.destroy,
        bg="#444444",
        fg="white"
    ).pack(pady=10)

def show_text_popup(title, content):
    popup = tk.Toplevel(root)
    popup.title(title)
    popup.configure(bg="#1e1e1e")
    popup.resizable(False, False)

    win_width = 500
    win_height = 300
    popup.geometry(f"{win_width}x{win_height}")

    # Wait for the window to be drawn so we can calculate its position
    popup.update_idletasks()

    # Get root window position and size
    root_x = root.winfo_rootx()
    root_y = root.winfo_rooty()
    root_width = root.winfo_width()
    root_height = root.winfo_height()

    # Calculate centered position
    pos_x = root_x + (root_width // 2) - (win_width // 2)
    pos_y = root_y + (root_height // 2) - (win_height // 2)

    popup.geometry(f"{win_width}x{win_height}+{pos_x}+{pos_y}")

    # Make it modal
    popup.transient(root)
    popup.grab_set()

    # UI content
    tk.Label(
        popup,
        text=title,
        font=("Arial", 12, "bold"),
        bg="#1e1e1e",
        fg="#00ff88"
    ).pack(pady=(10, 5))

    text_area = scrolledtext.ScrolledText(popup, wrap=tk.WORD, bg="#2d2d2d", fg="white", insertbackground="white")
    text_area.pack(fill="both", expand=True, padx=10, pady=5)
    text_area.insert(tk.END, content or "(No content available)")
    text_area.config(state='disabled')  # Read-only

    tk.Button(popup, text="Close", command=popup.destroy, bg="#444444", fg="white").pack(pady=5)


def show_license_popup(mod_folder):
    license_path = os.path.join(mod_folder, "LICENSE.txt")

    # Try to read the license file
    if os.path.exists(license_path):
        with open(license_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    else:
        content = "(No LICENSE.txt found)"

    # Create and center the popup like show_text_popup
    popup = tk.Toplevel(root)
    popup.title("License")
    popup.configure(bg="#1e1e1e")
    popup.resizable(False, False)

    win_width = 500
    win_height = 300
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

    tk.Label(
        popup,
        text="LICENSE.txt",
        font=("Arial", 12, "bold"),
        bg="#1e1e1e",
        fg="#00ff88"
    ).pack(pady=(10, 5))

    text_area = scrolledtext.ScrolledText(popup, wrap=tk.WORD, bg="#2d2d2d", fg="white", insertbackground="white")
    text_area.pack(fill="both", expand=True, padx=10, pady=5)
    text_area.insert(tk.END, content)
    text_area.config(state='disabled')  # Read-only

    tk.Button(popup, text="Close", command=popup.destroy, bg="#444444", fg="white").pack(pady=5)

# GUI Setup
root = tk.Tk()
root.title("RWMod Anti-Theft Packer")
root.geometry("550x610")
root.configure(bg="#1e1e1e")
root.resizable(False, False)

tk.Label(
    root,
    text="RWMod Anti-Theft Packer",
    font=("Arial", 18, "bold"),
    fg="#00ff88",
    bg="#1e1e1e",
).pack(pady=(10, 20))

# Frame for Mod Folder row
mod_row = tk.Frame(root, bg="#1e1e1e")
mod_row.pack(fill="x", padx=10, pady=(0, 5))

# Configure grid with 3 columns: left (label), middle (entry), right (button)
mod_row.grid_columnconfigure(0, weight=0)
mod_row.grid_columnconfigure(1, weight=1)
mod_row.grid_columnconfigure(2, weight=0)

folder_name = tk.StringVar(value="📁 Folder: (none)")
folder_label = tk.Label(mod_row, textvariable=folder_name, fg="white", bg="#1e1e1e")
folder_label.grid(row=0, column=0, sticky="w")

folder_entry = ttk.Entry(mod_row)
folder_entry.grid(row=0, column=1, sticky="ew", padx=5)

btn_select_folder = ttk.Button(mod_row, text="Browse", command=select_folder)
btn_select_folder.grid(row=0, column=2)

# Frame for Output Directory row
output_row = tk.Frame(root, bg="#1e1e1e")
output_row.pack(fill="x", padx=10, pady=(0, 10))

output_entry = ttk.Entry(output_row)
output_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

btn_select_output = ttk.Button(output_row, text="Output Folder", command=select_output)
btn_select_output.pack(side="right")

# Text area for mod-info.txt preview
tk.Label(root, text="mod-info.txt preview:", fg="white", bg="#1e1e1e").pack(anchor="w", padx=10)

modinfo_text = scrolledtext.ScrolledText(root, height=14, bg="#2d2d2d", fg="white", insertbackground="white")
modinfo_text.pack(fill="both", expand=False, padx=10, pady=(0, 10))

# Start pack button
# Update the button creation to a global variable for easy access
pack_button = tk.Button(root, text="Pack as .rwmod", command=start_thread, bg="#006666", fg="white", font=("Arial", 11, "bold"))
pack_button.pack(pady=8)

# Status label
status_label = tk.Label(root, text="READY and WAITING...", fg="white", bg="#1e1e1e", font=("Arial", 10, "bold"))
status_label.pack(pady=(0, 5))

# About button
btn_about = ttk.Button(root, text="About", command=show_about)
btn_about.pack(side="bottom", pady=5)

#About History Log

action_buttons = tk.Frame(root, bg="#1e1e1e")
action_buttons.pack(pady=4)

btn_history = ttk.Button(action_buttons, text="View History Log", command=lambda: show_text_popup("History Log", "\n".join(history_log)), width=20)
btn_history.pack(side="left", padx=5, ipadx=10)

def view_license():
    folder_path = folder_entry.get().strip()
    if folder_path and os.path.isdir(folder_path):
        show_license_popup(folder_path)
    else:
        messagebox.showwarning("Warning", "Please select a valid mod folder first.")

#About License
btn_license = ttk.Button(action_buttons, text="View License Mod", command=view_license, width=20)
btn_license.pack(side="left", padx=5, ipadx=10)

#The End of Loop
root.mainloop()
