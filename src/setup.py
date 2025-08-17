from cx_Freeze import setup, Executable
import os

# Your custom GUID
UPGRADE_CODE = "{a6ad4b2e-92f4-4062-9547-ff06205e6a87}"

build_exe_options = {
    "packages": ["os", "tkinter", "zipfile", "hashlib", "random", "datetime"],
    "excludes": ["test", "tomllib"],
    "include_files": ["app_icon.ico"] if os.path.exists("app_icon.ico") else [],
    "bin_excludes": ["api-ms-win-*.dll"]
}

setup(
    name="RWMod Repacker",
    version="1.3.1",
    description="Package RW mods with anti-theft protection",
    author="Moggstone",  # This becomes the "Publisher" in Add/Remove Programs
    options={
        "build_exe": build_exe_options,
        "bdist_msi": {
            "upgrade_code": UPGRADE_CODE,
            "add_to_path": False,
            "target_name": "RWMod_Repacker_Setup.msi",
            "install_icon": "app_icon.ico",
            "all_users": True,
            # These are the ONLY valid options for bdist_msi in cx_Freeze:
            "summary_data": {
                "author": "Moggstone",
                "comments": "Built with my own PC and ChatGPT"
            },
            "data": {
                "Shortcut": [
                    ("DesktopShortcut", "DesktopFolder", "RWMod Repacker",
                     "TARGETDIR", "[TARGETDIR]RWMod_Repacker.exe",
                     None, None, None, None, None, None, None),
                    ("StartMenuShortcut", "ProgramMenuFolder", "RWMod Repacker",
                     "TARGETDIR", "[TARGETDIR]RWMod_Repacker.exe",
                     None, None, None, None, None, None, None)
                ]
            }
        }
    },
    executables=[Executable(
        "rwmod_repacker_v3.py",
        base="Win32GUI",
        icon="app_icon.ico",
        target_name="RWMod_Repacker.exe",
        # Additional metadata that shows in file properties:
        copyright="Copyright © 2025 Moggstone",
        
    )]
)