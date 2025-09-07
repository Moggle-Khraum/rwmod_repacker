import tkinter as tk
import tkinter.font as tkFont
from tkinter import ttk
from PIL import Image, ImageTk
import os

def show_splash(root, image="app_icon.png", icon=None,
                duration=6000, pause_after_full=5000,
                width=450, height=300, on_finish=None):
    splash = tk.Toplevel(root)
    splash.overrideredirect(True)
    splash.configure(bg="black")  # border color
    splash.attributes("-alpha", 0.0)

    # Frame with white background inside black border
    frame = tk.Frame(splash, bg="white", bd=2, relief="solid")
    frame.place(x=2, y=2, width=width-4, height=height-4)

    # --- Header Frame: Logo + Title ---
    header_frame = tk.Frame(frame, bg="white")
    header_frame.pack(anchor="center", pady=(15,5))

    # Logo
    logo = None
    if image and os.path.exists(image):
        try:
            img = Image.open(image).resize((115, 115))
            logo = ImageTk.PhotoImage(img)
        except Exception:
            pass

    if logo:
        lbl_img = tk.Label(header_frame, image=logo, bg="white")
        lbl_img.image = logo
        lbl_img.pack(side="left", padx=(0,10))

    # Title beside logo
    title_label = tk.Label(header_frame, text="RWMod\nRepacker",
                           font=("Segoe UI", 30, "bold"),
                           justify="left", bg="white")
    title_label.pack(side="left", padx=5)

    # Version label
    version_label = tk.Label(frame, text="Version: 1.3.5",
                             font=("Segoe UI", 18, "bold"),
                             bg="white")
    version_label.pack(pady=(0,5))

    # Loading label with StringVar
    loading_text = tk.StringVar(value="Loading RWMod Repacker...")
    loading_label = tk.Label(frame, textvariable=loading_text,
                             font=("Segoe UI", 15, "italic"), bg="white")
    loading_label.pack(pady=(0, 5))

    # Progress bar
    pb = ttk.Progressbar(frame, orient="horizontal", length=360,
                         mode="determinate", maximum=100)
    pb.pack(pady=(0,5))

    # "Brought to you by" label
    by_label = tk.Label(frame, text="Brought to you by: Moggs / Dr. Buggstavius",
                        font=("Segoe UI", 9, "italic"), bg="white")
    by_label.pack()

    # Center splash on screen
    sw = splash.winfo_screenwidth()
    sh = splash.winfo_screenheight()
    x = (sw - width) // 2
    y = (sh - height) // 2
    splash.geometry(f"{width}x{height}+{x}+{y}")
    splash.resizable(False, False)
    root.withdraw()

    progress = 0
    alpha = 0.0

    # --- Fade-in ---
    def fade_in():
        nonlocal alpha
        alpha += 0.02
        if alpha < 1.0:
            splash.attributes("-alpha", alpha)
            splash.after(30, fade_in)
        else:
            splash.attributes("-alpha", 1.0)
            start_progress()

    # --- Progress fill ---
    def start_progress():
        nonlocal progress
        increment = max(0.3, (100 - progress) / 50)
        progress += increment
        pb['value'] = progress
        if progress < 100:
            splash.after(int(duration / 100), start_progress)
        else:
            pb['value'] = 100
            loading_text.set("RWMod Repacker Loaded...")  # 👈 change text here
            splash.after(pause_after_full, fade_out)

    # --- Fade-out ---
    def fade_out():
        nonlocal alpha
        alpha -= 0.02
        if alpha > 0:
            splash.attributes("-alpha", alpha)
            splash.after(30, fade_out)
        else:
            splash.destroy()
            if on_finish:
                on_finish()

    fade_in()
    splash.lift()
    splash.attributes("-topmost", True)
    splash.after_idle(splash.attributes, "-topmost", False)
