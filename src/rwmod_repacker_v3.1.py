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

# For the History File
HISTORY_FILE = "history_log.txt"
history_log = []

# For the ICON Path
ICON_PATH = {
    'ico': 'app_icon.ico',
    'png': 'app_icon.png'
}


# History Functions
def load_history():
    """Loads history from file if exists, returns empty list otherwise."""
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return []

def save_history(history):
    """Saves history to file in JSON format."""
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

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

# File Protection Functions
def hide_files_in_folder(folder_path):
    """Marks all files in folder as hidden (Windows-only)."""
    if sys.platform == 'win32':
        for root, _, files in os.walk(folder_path):
            for file in files:
                os.system(f'attrib +h "{os.path.join(root, file)}"')

def create_protected_archive(source_folder, output_zip):
    """Creates archive with hidden files + decoy."""
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add real files (will extract as hidden)
        for root, _, files in os.walk(source_folder):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, source_folder)
                zipf.write(abs_path, rel_path)
        
        # Add decoy note
        zipf.writestr("_READ_ME.txt", 
                     "⚠️THIS MOD FOLDER IS PROTECTED⚠️")

# Core RWMod Functions
def get_header_sig():
    # Mutable Header
    base = b"\x89\x50\x4E\x47"
    return mutable_signature(base + b"\x0D\x0A\x1A\x0A")

def get_footer_sig():
    # Fixed footer base (no mutation here)
    base = b"\xDE\xAD\xBE\xEF--RWMOD_LOCKED--\x00\x00"
    return base

def get_secret_key():
    # Mutable HEX Key
    return mutable_hex_key(2023) + b"_MODSEC_" + mutable_hex_key(os.getpid())


def zip_folder(folder_path, zip_path):
    update_status("⏳ ARCHIVING FILES...")
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, folder_path)
                zf.write(abs_path, rel_path)

def tamper_zip(zip_path, rwmod_path, prefix_len_range=(1024, 8192)):
    """Offset-shift ZIP with random prefix and append hash+footer+size."""
    update_status("🔐 ADDING OBFUSCATION LAYER...")
    footer_signature = get_footer_sig()

    with open(zip_path, "rb") as f:
        zip_data = f.read()

    content_hash = hashlib.sha256(zip_data).digest()
    prefix_len = random.randint(*prefix_len_range)
    prefix = os.urandom(prefix_len)

    with open(rwmod_path, "wb") as out:
        out.write(prefix)
        out.write(zip_data)
        out.write(content_hash)
        out.write(footer_signature)
        out.write(len(zip_data).to_bytes(4, "big"))

    os.remove(zip_path)

def verify_rwmod_integrity(file_path):
    """Verifies .rwmod integrity."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        zip_size = int.from_bytes(data[-4:], 'big')
        footer_sig = get_footer_sig()
        footer_len = len(footer_sig)
        footer_start = - (footer_len + 4)
        hash_start = footer_start - 32
        zip_end = hash_start
        zip_start = zip_end - zip_size

        if data[footer_start:-4] != footer_sig:
            return False, "⚠️ FOOTER SIGNATURE MISMATCH ⚠️"

        stored_hash = data[hash_start:footer_start]
        zip_data = data[zip_start:zip_end]
        calc_hash = hashlib.sha256(zip_data).digest()
        if stored_hash != calc_hash:
            return False, "⚠️ CONTENT HASH MISMATCH ⚠️"

        return True, "✅ VERIFICATION PASSED"
    except Exception as e:
        return False, f"⚠️ VERIFICATION ERROR: {str(e)}"


# Unhides and cleans the repacking traces
def unhide_files_in_folder(folder_path):
    """Removes hidden attribute from files (Windows only)"""
    if sys.platform == 'win32':
        for root, _, files in os.walk(folder_path):
            for file in files:
                os.system(f'attrib -h "{os.path.join(root, file)}"')


# Modified Packing Function
def pack_as_rwmod(folder_path, rwmod_path):
    """Main packing process with auto-hidden files."""
    temp_zip = rwmod_path + ".temp.zip"

    try:
        # 1. Hide original files (Windows only)
        if sys.platform == 'win32':
            update_status("👻 CONCEALING THE UNDERLYING FILES...")
            hide_files_in_folder(folder_path)
    
        # 2. Create & Apply RWMod protection
        update_status("💼 ADDING PROTECTIVE LAYER...")
        create_protected_archive(folder_path, temp_zip)
        tamper_zip(temp_zip, rwmod_path)
    
        # 3. Verify Package
        update_status("♻️ VERIFYING PACKAGE...")
        is_valid, msg = verify_rwmod_integrity(rwmod_path)
        if not is_valid:
            os.remove(rwmod_path)
            raise RuntimeError(f"⚠️ VERIFICATION FAILED: {msg}")

    finally:
        # 4. Revert Attributes
        if sys.platform == 'win32':
            unhide_files_in_folder(folder_path)
        # 5. Cleanup Temp File
        if os.path.exists(temp_zip):
            os.remove(temp_zip)
        
    update_status("🔒 ARCHIVE PROTECTION APPLIED")
    time.sleep(2.5)



# GUI Functions
def update_status(msg):
    status_label.config(text=msg)
    status_label.update()

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

def select_output():
    output = filedialog.askdirectory()
    if output:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, output)

def set_pack_button_state(enabled: bool):
    pack_button.config(state="normal" if enabled else "disabled")

def run_packing():
    set_pack_button_state(False)
    try:
        folder_path = folder_entry.get().strip()
        output_dir = output_entry.get().strip() or os.path.expanduser("~/Downloads")

        if not folder_path or not os.path.isdir(folder_path):
            messagebox.showerror("Error", "⚠️ Please select a valid mod folder.")
            set_pack_button_state(True)
            return

        modname = os.path.basename(folder_path.rstrip("/\\"))
        rwmod_path = os.path.join(output_dir, modname + ".rwmod")

        pack_as_rwmod(folder_path, rwmod_path)

        checksum_valid = False
        try:
            sha256 = calculate_sha256(rwmod_path)
            if sha256 and os.path.getsize(rwmod_path) > 0:
                checksum_valid = True
        except:
            checksum_valid = False

        add_to_log(modname, rwmod_path)
        update_status("✅ SUCCESS!")
        messagebox.showinfo("DONE", f"📦 PACKED TO:\n{rwmod_path}")

        folder_entry.delete(0, tk.END)
        output_entry.delete(0, tk.END)
        folder_name.set("🗂 FOLDER: (NONE)")
        modinfo_text.delete('1.0', tk.END)
        update_status("⚙ READY and WAITING...")

    except Exception as e:
        update_status("❌ FAILED.")
        messagebox.showerror("Error", str(e))
    finally:
        set_pack_button_state(True)

def start_thread():
    threading.Thread(target=run_packing, daemon=True).start()

def show_history_popup():
    """Displays history from persistent file."""
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
    show_text_popup("History Log", content)

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


# For Icons
def set_window_icon(root):
    """Attempts to load window icon with fallbacks"""
    try:
        root.iconbitmap(ICON_PATH['ico'])  # Windows .ico
    except:
        try:
            icon = tk.PhotoImage(file=ICON_PATH['png'])  # Cross-platform
            root.iconphoto(True, icon)
        except Exception as e:
            print(f"Couldn't load window icon: {str(e)}")


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
tk.Label(root, text="🛠 RWMod Anti-Theft Repacker 📦", font=("Arial", 18, "bold"), fg="#00ff88", bg="#1e1e1e").pack(pady=(10, 20))

# Folder Selection
mod_row = tk.Frame(root, bg="#1e1e1e")
mod_row.pack(fill="x", padx=10, pady=(0, 5))
mod_row.grid_columnconfigure(0, weight=0)
mod_row.grid_columnconfigure(1, weight=1)
mod_row.grid_columnconfigure(2, weight=0)

folder_name = tk.StringVar(value="🗂 FOLDER: (NONE)")
folder_label = tk.Label(mod_row, textvariable=folder_name, fg="white", bg="#1e1e1e")
folder_label.grid(row=0, column=0, sticky="w")

folder_entry = ttk.Entry(mod_row)
folder_entry.grid(row=0, column=1, sticky="ew", padx=5)

btn_select_folder = ttk.Button(mod_row, text="🔍 BROWSE", command=select_folder)
btn_select_folder.grid(row=0, column=2)

# Output Selection
output_row = tk.Frame(root, bg="#1e1e1e")
output_row.pack(fill="x", padx=10, pady=(0, 10))
output_entry = ttk.Entry(output_row)
output_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
btn_select_output = ttk.Button(output_row, text="💾 OUTPUT FOLDER", command=select_output)
btn_select_output.pack(side="right")

# Mod Info Preview
tk.Label(root, text="📜 MOD-INFO PREVIEWER:", fg="white", bg="#1e1e1e").pack(anchor="w", padx=10)
modinfo_text = scrolledtext.ScrolledText(root, height=14, bg="#2d2d2d", fg="white", insertbackground="white")
modinfo_text.pack(fill="both", expand=False, padx=10, pady=(0, 10))

# Action Buttons
pack_button = tk.Button(root, text="📦 PACK AS .RWMOD", command=start_thread, bg="#006666", fg="white", font=("Arial", 11, "bold"))
pack_button.pack(pady=8)

status_label = tk.Label(root, text="⚙ READY and WAITING...", fg="white", bg="#1e1e1e", font=("Arial", 10, "bold"))
status_label.pack(pady=(0, 5))

action_buttons = tk.Frame(root, bg="#1e1e1e")
action_buttons.pack(pady=4)


# For About Button
btn_about = ttk.Button(root, text="📝 About", command=show_about)
btn_about.pack(side="bottom", pady=5)

# For View History Log
btn_history = ttk.Button(action_buttons, text="📜 View History Log", command=show_history_popup, width=20)
btn_history.pack(side="left", padx=5, ipadx=10)

root.mainloop()
