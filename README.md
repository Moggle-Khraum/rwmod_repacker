# RWMod Repacker 🛡️

![RWMod Repacker Screenshot](screenshot.png)

A security-focused tool that packages game mods into protected `.rwmod` files with anti-tampering measures.

## Features
- 🔒 Tamper-evident packaging
- 🎲 Random prefix obfuscation (1024-8192 bytes)
- 🔐 SHA-256 content verification
- 💻 Windows installer & portable versions
- 🖥️ Simple GUI interface

## 📥 Pre-Built Downloads
- [Installer (.msi)](https://github.com/yourrepo/releases/latest)
- [Portable (.zip)](https://github.com/yourrepo/releases/latest)

## 🔨 For Paranoid Builders
Build your own executable to verify the code:

### Prerequisites
- **Python 3.8-3.11** (64-bit recommended)
- **Windows 10/11** (Linux/WSL requires cross-compile)
- **10MB disk space** for build artifacts

### 1. Clone & Prepare
```bash
git clone https://github.com/yourrepo/rwmod_repacker.git
cd rwmod_repacker
pip install -r requirements.txt
```

### 2. Customize Build
Edit these in `setup.py`:
```python
# Generate new GUID at https://guidgen.com/
UPGRADE_CODE = "{a6ad4b2e-92f4-4062-9547-ff06205e6a87}" 

# Personalize metadata
author="Your Name"
description="Your custom description"
```

Replace `app_icon.ico` with your own 256x256px Windows icon file.

### 3. Build Options
```bash
# Option A: Create installer (recommended)
python setup.py bdist_msi

# Option B: Portable build
python setup.py build
```

### 4. Expected Warnings (Safe to Ignore)
```
? api-ms-win-crt-*.dll → Windows system files
? test → Unused testing modules
? tomllib → Python 3.11+ backport
```
These don't affect functionality.

### 5. Clean & Rebuild
```bash
# Full clean (Windows)
python setup.py clean
rmdir /s /q build dist

# Full clean (Linux/WSL)
python setup.py clean
rm -rf build dist

# Rebuild
python setup.py bdist_msi
```

## 🧪 Testing Your Build
1. Run from command line for debug info:
   ```bash
   cd dist
   RWMod_Repacker.exe
   ```
2. Pack a test mod folder
3. Verify output:
   ```python
   import hashlib
   with open("test.rwmod","rb") as f:
       print(hashlib.sha256(f.read()).hexdigest())
   ```

## ⚠️ Security Notes
- Compiled builds are deterministic
- All protection layers activate at build time
- Antivirus may flag due to protection methods

## 🚨 Troubleshooting
| Issue | Solution |
|-------|----------|
| Missing DLLs | Install [VC++ Redist](https://aka.ms/vs/17/release/vc_redist.x64.exe) |
| GUI fails | Run with `base = None` in `setup.py` |
| False positives | Verify SHA256 matches your build |

---
🔧 **Advanced**: To modify protections, edit `rwmod_repacker_v3.py`:
- `get_header_sig()` - Change signature pattern
- `tamper_zip()` - Adjust obfuscation settings

© 2023 Moggstone | [Report Issues](https://github.com/yourrepo/issues)
