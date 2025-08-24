# ⚙️ RWMod Repacker 🛡️

<div align="center">
<img width="200" height="195" src="docs/lock.png" alt="Icon of the tool" title="Tool Icon">
</div>

## 📌 Introducing RWMod Anti-theft Repacker Tool
- A security-focused tool that packages your MOD folders into a protected ZIP file with simple anti-tampering methods, then convereted to `.rwmod` files which is readable by the game 'Rusted Warfare' which is both available on [Android](https://play.google.com/store/apps/details?id=com.corrodinggames.rts&hl=en_US), [iOS](https://apps.apple.com/us/app/rusted-warfare-rts/id1514329124), [PC via STEAM](https://store.steampowered.com/app/647960/Rusted_Warfare__RTS/), and [Mac](https://apps.apple.com/us/app/rusted-warfare-rts/id1514329124) platforms.

## 🛡️ Protection Process & AI Role 🔒
- The RWMod Repacker uses a multi-layered extensive methods to protect mod files from being easily extracted using common tools such as 7-Zip or WinRAR.
The program was made through the use of multiple AI's such as ChatGPT, DeepSeek, and Gemini AI. The process was ardous as sometimes after asking so much the AI now starts hallucinating and spits out the same code prone with errors. And that is why, other AI come in handy in answering my specific queries, assists me in debugging the code in Python, exporting the PY Script into a working EXE program.

## 📌 Features
- ----------- TOOL FEATURES --------------
- 🖥️ Simple GUI interface
- 📂 Easy Click in Mod/Output Selection
- 🛡️ Select Modes for Protection: Partial/Maximum
- 📰 Reads 'MOD-INFO.txt' of the Mod's Folder
- 🎮 .RWMOD file is still readable and playable
- ---------- TOOL FUNCTIONS -------------
- 🔒 Scans files, Zips your file, inject dummies, Convert to .RWMOD
- 🖼️ It has Mod-info Previewer, View History Log & Delete Log, About Repacker, Theme Editor[BETA]
- 🔏 You can select Modes of Security: Partial or Maximum.

## 📥 Pre-Built Downloads
| Platform | Package | Source |
|----------|---------|--------|
| Windows  | 💽 Installer [MSI] | [Download Here (.msi)](https://github.com/Moggle-Khraum/rwmod_repacker/blob/main/releases/program_installer/RWMod_Repacker_Setup.msi)       |
| Windows  | 🧰 Portable [ZIP] | [Downlaod Here (.zip)](https://github.com/Moggle-Khraum/rwmod_repacker/blob/main/releases/portable_zips/RWMod_repacker_v1.3.zip)       |
| MAC OS   |   NONE  |  NONE  |
| LINUX    |   NONE  |  NONE  |
| Android  |  SCRIPT/Pyroid3 | [INSTRUCTIONS BELOW] |

## 📌 HOW TO RUN IN ANDROID
-  📱 Pyroid 3 and RWMod Repacker Script (FOR TESTING ONLY)
-  - Download Pyroid 3 from [Google Playstore](https://play.google.com/store/apps/details?id=ru.iiec.pydroid3&hl=en_US)
   - Download RWMod Anti Repacker by going to ``src/`` and find ``rwmod_repacker_v3_Android.py``. Click it and click the ``Download Raw File``.
   - Make sure both the SCRIPT and your MOD Folder is in your INTERNAL STORAGE. Open the Script on Pyroid 3 and Run it.
   - Then browse your folder, select output location, PACK IT, and if successful, your .RWMOD is now complete.

## 🔨 For Paranoid Builders
Build your own executable to verify the code:

### 🗒️ Prerequisites
- **Python 3.8-3.11**
- **Be it Windows 10/11**
- **10MB disk space**

### 🔧 Run the script on your PC
- Download Python 3.8-3.11
- Open the PY File using IDLE
- Run it, and voila. No need for conversion to EXE
- Works the same as Installer or Portable Version

## ⚠️ Security Notes
- Compiled builds are deterministic
- All protection layers activate at build time

## 🚨 Troubleshooting
| Issue | Solution |
|-------|----------|
| False Positives |Run the Code instead |
| GUI Fails | Restart IDLE and open the code again |

---

© 2023 Moggstone | Assisted with AI | [Report Issues](https://github.com/Moggle-Khraum/rwmod_repacker/issues)
