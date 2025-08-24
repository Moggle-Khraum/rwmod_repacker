# ⚙️ RWMod Repacker 🛡️

<div align="center">
<img width="200" height="195" src="docs/lock.png" alt="Icon of the tool" title="Tool Icon">
</div>

## 📌 Introducing RWMod Anti-theft Repacker Tool
- A security-focused tool that packages your MOD folders into a protected ZIP file with simple anti-tampering methods, then convereted to `.rwmod` files which is readable by the game 'Rusted Warfare' which is both available on [Android](https://play.google.com/store/apps/details?id=com.corrodinggames.rts&hl=en_US), [iOS](https://apps.apple.com/us/app/rusted-warfare-rts/id1514329124), [PC via STEAM](https://store.steampowered.com/app/647960/Rusted_Warfare__RTS/), and [Mac](https://apps.apple.com/us/app/rusted-warfare-rts/id1514329124) platforms.

## 🛡️ Protection Process & AI Role 🔒
- The RWMod Repacker uses a multi-layered extensive methods to protect mod files from being easily extracted using common tools such as 7-Zip or WinRAR.
The program was made through the use of multiple AI's such as ChatGPT, DeepSeek, and Gemini AI. The process was ardous as sometimes after asking so much the AI now starts hallucinating and spits out the same code prone with errors. And that is why, other AI come in handy in answering my specific queries, assists me in debugging the code in Python, exporting the PY Script into a working EXE program.

## Features
- ----------- TOOL FEATURES --------------
- 🖥️ Simple GUI interface
- 📂 Easy Click in Mod/Output Selection
- 🛡️ Select Modes for Protection: Partial/Maximum
- 📰 Reads 'MOD-INFO.txt' of the Mod's Folder
- 
- ---------- TOOL FUNCTIONS -------------
- 🔒 
- 🎲 Random prefix obfuscation (1024-8192 bytes)
- 🔐 SHA-256 content verification
- 🔏 Mutable Unique Header/Footer Signature
- 💽 Rusted Warfare Readable File


## 📥 Pre-Built Downloads
- ----------- WINDOWS -------------
- 💽 RWMod Repacker Installer [Download Here (.msi)](https://github.com/Moggle-Khraum/rwmod_repacker/blob/main/releases/program_installer/RWMod_Repacker_Setup.msi)
- 🧰 [REC] RWMod Repacker Portable [Downlaod Here (.zip)](https://github.com/Moggle-Khraum/rwmod_repacker/blob/main/releases/portable_zips/RWMod_repacker_v1.3.zip)
- ----------- LINUX ---------------
- 🧰 NONE
-  ---------- ANDROID -------------
-  📱 Pyroid 3 and RWMod Repacker Script (FOR TESTING ONLY)
-  - Download Pyroid 3 from [Google Playstore](https://play.google.com/store/apps/details?id=ru.iiec.pydroid3&hl=en_US)
   - Download RWMod Anti Repacker [here]() or go to `src/


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
## 🔧Advanced : 
- To modify protections, edit `rwmod_repacker_v3.py`:
- `get_header_sig()` - Change signature pattern
- `tamper_zip()` - Adjust obfuscation settings

© 2023 Moggstone | [Report Issues](https://github.com/Moggle-Khraum/rwmod_repacker/issues)
