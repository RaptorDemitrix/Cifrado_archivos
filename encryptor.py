# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════╗
║           🔐 SecureVault - File Encryptor            ║
║     Encrypt & Decrypt files with a master password   ║
╚══════════════════════════════════════════════════════╝

Requires: pip install cryptography
"""

from __future__ import annotations

import os
import sys
import json
import base64
import hashlib
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime

import subprocess

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("[SecureVault] Dependencia 'cryptography' no encontrada. Instalando automáticamente...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "--break-system-packages"])
        from cryptography.fernet import Fernet, InvalidToken
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        print("[SecureVault] 'cryptography' se instaló con éxito.")
    except Exception as err:
        root_temp = tk.Tk()
        root_temp.withdraw()
        messagebox.showerror(
            "Falta Dependencia",
            f"No se pudo cargar o instalar 'cryptography':\n{err}\n\nPor favor ejecuta en tu terminal:\n{sys.executable} -m pip install cryptography"
        )
        root_temp.destroy()
        sys.exit(1)


# ─── Constantes ───────────────────────────────────────────────────────────────
ENCRYPTED_EXTENSION = ".vault"
SALT_SIZE = 16
ITERATIONS = 480_000  # PBKDF2 iterations (OWASP recommendation)
METADATA_MARKER = b"SECUREVAULT_V1"


# ─── Motor de Encriptación ───────────────────────────────────────────────────
class CryptoEngine:
    """Handles all encryption/decryption operations."""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive a Fernet key from password + salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
        return key

    @staticmethod
    def encrypt_file(filepath: str, password: str) -> str:
        """
        Encrypt a single file. Returns the path to the encrypted file.
        Format: MARKER | salt(16) | metadata_len(4) | metadata_json | encrypted_data
        """
        filepath = Path(filepath)
        if not filepath.is_file():
            raise FileNotFoundError(f"Archivo no encontrado: {filepath}")
        if filepath.suffix == ENCRYPTED_EXTENSION:
            raise ValueError(f"El archivo ya está encriptado: {filepath.name}")

        salt = os.urandom(SALT_SIZE)
        key = CryptoEngine.derive_key(password, salt)
        fernet = Fernet(key)

        # Read original file
        with open(filepath, "rb") as f:
            data = f.read()

        # Encrypt
        encrypted_data = fernet.encrypt(data)

        # Metadata
        metadata = {
            "original_name": filepath.name,
            "original_size": len(data),
            "encrypted_at": datetime.now().isoformat(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        metadata_bytes = json.dumps(metadata).encode("utf-8")
        metadata_len = len(metadata_bytes).to_bytes(4, "big")

        # Write encrypted file
        output_path = filepath.with_suffix(filepath.suffix + ENCRYPTED_EXTENSION)
        with open(output_path, "wb") as f:
            f.write(METADATA_MARKER)
            f.write(salt)
            f.write(metadata_len)
            f.write(metadata_bytes)
            f.write(encrypted_data)

        # Remove original
        os.remove(filepath)
        return str(output_path)

    @staticmethod
    def decrypt_file(filepath: str, password: str) -> str:
        """
        Decrypt a single .vault file. Returns the path to the decrypted file.
        """
        filepath = Path(filepath)
        if not filepath.is_file():
            raise FileNotFoundError(f"Archivo no encontrado: {filepath}")
        if filepath.suffix != ENCRYPTED_EXTENSION:
            raise ValueError(f"No es un archivo encriptado (.vault): {filepath.name}")

        with open(filepath, "rb") as f:
            # Read and validate marker
            marker = f.read(len(METADATA_MARKER))
            if marker != METADATA_MARKER:
                raise ValueError("Formato de archivo no válido o corrupto.")

            salt = f.read(SALT_SIZE)
            metadata_len = int.from_bytes(f.read(4), "big")
            metadata_bytes = f.read(metadata_len)
            encrypted_data = f.read()

        metadata = json.loads(metadata_bytes.decode("utf-8"))
        key = CryptoEngine.derive_key(password, salt)
        fernet = Fernet(key)

        try:
            decrypted_data = fernet.decrypt(encrypted_data)
        except InvalidToken:
            raise ValueError("❌ Clave maestra incorrecta o archivo corrupto.")

        # Verify integrity
        actual_hash = hashlib.sha256(decrypted_data).hexdigest()
        if actual_hash != metadata.get("sha256"):
            raise ValueError("⚠️ Verificación de integridad fallida. Archivo posiblemente corrupto.")

        # Restore original filename
        original_name = metadata.get("original_name", filepath.stem)
        output_path = filepath.parent / original_name

        # Handle name conflicts
        counter = 1
        base_stem = output_path.stem
        base_suffix = output_path.suffix
        while output_path.exists():
            output_path = filepath.parent / f"{base_stem} ({counter}){base_suffix}"
            counter += 1

        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        # Remove encrypted file
        os.remove(filepath)
        return str(output_path)

    @staticmethod
    def get_file_info(filepath: str) -> dict | None:
        """Read metadata from an encrypted file without decrypting."""
        filepath = Path(filepath)
        if filepath.suffix != ENCRYPTED_EXTENSION:
            return None
        try:
            with open(filepath, "rb") as f:
                marker = f.read(len(METADATA_MARKER))
                if marker != METADATA_MARKER:
                    return None
                f.read(SALT_SIZE)  # skip salt
                metadata_len = int.from_bytes(f.read(4), "big")
                metadata_bytes = f.read(metadata_len)
            return json.loads(metadata_bytes.decode("utf-8"))
        except Exception:
            return None


# ─── Colores y Estilos ───────────────────────────────────────────────────────
class Theme:
    BG_DARK = "#0f0f1a"
    BG_CARD = "#1a1a2e"
    BG_INPUT = "#16213e"
    BG_HOVER = "#252547"
    ACCENT_BLUE = "#4361ee"
    ACCENT_CYAN = "#00b4d8"
    ACCENT_GREEN = "#06d6a0"
    ACCENT_RED = "#ef476f"
    ACCENT_ORANGE = "#f77f00"
    ACCENT_PURPLE = "#7209b7"
    TEXT_PRIMARY = "#e8e8f0"
    TEXT_SECONDARY = "#8888aa"
    TEXT_DIM = "#555577"
    BORDER = "#2a2a4a"
    SUCCESS = "#06d6a0"
    ERROR = "#ef476f"
    WARNING = "#f77f00"


# ─── Aplicación Principal ────────────────────────────────────────────────────
class SecureVaultApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 SecureVault — File Encryptor")
        self.root.geometry("640x580")
        self.root.minsize(580, 520)
        self.root.configure(bg=Theme.BG_DARK)
        self.root.resizable(True, True)

        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - 320
        y = (self.root.winfo_screenheight() // 2) - 290
        self.root.geometry(f"+{x}+{y}")

        # State
        self.selected_files: list[str] = []
        self.is_processing = False
        self.mode = tk.StringVar(value="encrypt")

        self._configure_styles()
        self._build_ui()

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Card.TFrame", background=Theme.BG_CARD)
        style.configure(
            "Title.TLabel",
            background=Theme.BG_DARK,
            foreground=Theme.TEXT_PRIMARY,
            font=("Segoe UI", 16, "bold"),
        )
        style.configure(
            "Subtitle.TLabel",
            background=Theme.BG_DARK,
            foreground=Theme.TEXT_SECONDARY,
            font=("Segoe UI", 9),
        )
        style.configure(
            "CardTitle.TLabel",
            background=Theme.BG_CARD,
            foreground=Theme.TEXT_PRIMARY,
            font=("Segoe UI", 10, "bold"),
        )
        style.configure(
            "CardText.TLabel",
            background=Theme.BG_CARD,
            foreground=Theme.TEXT_SECONDARY,
            font=("Segoe UI", 8),
        )
        style.configure(
            "Status.TLabel",
            background=Theme.BG_DARK,
            foreground=Theme.TEXT_SECONDARY,
            font=("Segoe UI", 8),
        )
        style.configure(
            "FileCount.TLabel",
            background=Theme.BG_CARD,
            foreground=Theme.ACCENT_CYAN,
            font=("Segoe UI", 10, "bold"),
        )

        # Radiobutton styles
        style.configure(
            "Mode.TRadiobutton",
            background=Theme.BG_CARD,
            foreground=Theme.TEXT_PRIMARY,
            font=("Segoe UI", 10),
            focuscolor=Theme.BG_CARD,
        )
        style.map(
            "Mode.TRadiobutton",
            background=[("active", Theme.BG_HOVER)],
            foreground=[("active", Theme.ACCENT_CYAN)],
        )

        # Progress bar
        style.configure(
            "Custom.Horizontal.TProgressbar",
            troughcolor=Theme.BG_INPUT,
            background=Theme.ACCENT_BLUE,
            thickness=5,
        )

    def _build_ui(self):
        # ── Main container with padding ──
        main = tk.Frame(self.root, bg=Theme.BG_DARK, padx=20, pady=14)
        main.pack(fill="both", expand=True)

        # ── Header ──
        header = tk.Frame(main, bg=Theme.BG_DARK)
        header.pack(fill="x", pady=(0, 10))

        ttk.Label(header, text="🔐 SecureVault", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Encripta y desencripta archivos con una clave maestra",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(1, 0))

        # ── Mode Selection Card ──
        mode_card = self._make_card(main)
        mode_card.pack(fill="x", pady=(0, 8))

        mode_inner = tk.Frame(mode_card, bg=Theme.BG_CARD, padx=16, pady=10)
        mode_inner.pack(fill="x")

        ttk.Label(mode_inner, text="Modo de operación", style="CardTitle.TLabel").pack(anchor="w")

        mode_row = tk.Frame(mode_inner, bg=Theme.BG_CARD)
        mode_row.pack(fill="x", pady=(6, 0))

        ttk.Radiobutton(
            mode_row, text="🔒  Encriptar", variable=self.mode,
            value="encrypt", style="Mode.TRadiobutton", command=self._on_mode_change,
        ).pack(side="left", padx=(0, 24))
        ttk.Radiobutton(
            mode_row, text="🔓  Desencriptar", variable=self.mode,
            value="decrypt", style="Mode.TRadiobutton", command=self._on_mode_change,
        ).pack(side="left")

        # ── File Selection Card ──
        file_card = self._make_card(main)
        file_card.pack(fill="x", pady=(0, 8))

        file_inner = tk.Frame(file_card, bg=Theme.BG_CARD, padx=16, pady=10)
        file_inner.pack(fill="x")

        file_header = tk.Frame(file_inner, bg=Theme.BG_CARD)
        file_header.pack(fill="x")

        ttk.Label(file_header, text="Archivos seleccionados", style="CardTitle.TLabel").pack(
            side="left"
        )
        self.file_count_label = ttk.Label(file_header, text="0 archivos", style="FileCount.TLabel")
        self.file_count_label.pack(side="right")

        # File list
        list_frame = tk.Frame(file_inner, bg=Theme.BG_INPUT, highlightbackground=Theme.BORDER,
                              highlightthickness=1)
        list_frame.pack(fill="x", pady=(8, 8))

        self.file_listbox = tk.Listbox(
            list_frame,
            height=4,
            bg=Theme.BG_INPUT,
            fg=Theme.TEXT_PRIMARY,
            font=("Consolas", 9),
            selectbackground=Theme.ACCENT_BLUE,
            selectforeground="white",
            borderwidth=0,
            highlightthickness=0,
            activestyle="none",
        )
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_listbox.yview)
        self.file_listbox.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.file_listbox.pack(side="left", fill="both", expand=True, padx=6, pady=4)

        # Buttons row
        btn_row = tk.Frame(file_inner, bg=Theme.BG_CARD)
        btn_row.pack(fill="x")

        self._make_button(btn_row, "📁 Seleccionar Archivos", Theme.ACCENT_BLUE,
                          self._select_files).pack(side="left", padx=(0, 6))
        self._make_button(btn_row, "📂 Seleccionar Carpeta", Theme.ACCENT_PURPLE,
                          self._select_folder).pack(side="left", padx=(0, 6))
        self._make_button(btn_row, "🗑 Limpiar", Theme.TEXT_DIM,
                          self._clear_files).pack(side="right")

        # ── Password Card ──
        pass_card = self._make_card(main)
        pass_card.pack(fill="x", pady=(0, 8))

        pass_inner = tk.Frame(pass_card, bg=Theme.BG_CARD, padx=16, pady=10)
        pass_inner.pack(fill="x")

        ttk.Label(pass_inner, text="Clave maestra", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(
            pass_inner,
            text="Usa una clave fuerte. Si la pierdes, no podrás recuperar tus archivos.",
            style="CardText.TLabel",
        ).pack(anchor="w", pady=(1, 6))

        # Password entry
        pass_frame = tk.Frame(pass_inner, bg=Theme.BG_INPUT, highlightbackground=Theme.BORDER,
                              highlightthickness=1)
        pass_frame.pack(fill="x")

        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(
            pass_frame,
            textvariable=self.password_var,
            show="●",
            bg=Theme.BG_INPUT,
            fg=Theme.TEXT_PRIMARY,
            insertbackground=Theme.ACCENT_CYAN,
            font=("Segoe UI", 11),
            borderwidth=0,
            highlightthickness=0,
        )
        self.password_entry.pack(side="left", fill="both", expand=True, padx=10, pady=7)

        self.show_pass = False
        self.toggle_btn = tk.Label(
            pass_frame, text="👁", bg=Theme.BG_INPUT, fg=Theme.TEXT_SECONDARY,
            font=("Segoe UI", 11), cursor="hand2",
        )
        self.toggle_btn.pack(side="right", padx=(0, 8))
        self.toggle_btn.bind("<Button-1>", self._toggle_password)

        # Password strength indicator
        self.strength_frame = tk.Frame(pass_inner, bg=Theme.BG_CARD)
        self.strength_frame.pack(fill="x", pady=(6, 0))

        self.strength_bar = tk.Canvas(
            self.strength_frame, height=3, bg=Theme.BG_INPUT,
            highlightthickness=0, bd=0,
        )
        self.strength_bar.pack(fill="x")
        self.strength_label = ttk.Label(
            self.strength_frame, text="", style="CardText.TLabel",
        )
        self.strength_label.pack(anchor="w", pady=(3, 0))

        self.password_var.trace_add("write", self._update_strength)

        # Confirm password (only for encrypt)
        self.confirm_frame = tk.Frame(pass_inner, bg=Theme.BG_CARD)
        self.confirm_frame.pack(fill="x", pady=(8, 0))

        ttk.Label(self.confirm_frame, text="Confirmar clave", style="CardText.TLabel").pack(
            anchor="w", pady=(0, 3)
        )

        confirm_entry_frame = tk.Frame(self.confirm_frame, bg=Theme.BG_INPUT,
                                       highlightbackground=Theme.BORDER, highlightthickness=1)
        confirm_entry_frame.pack(fill="x")

        self.confirm_var = tk.StringVar()
        self.confirm_entry = tk.Entry(
            confirm_entry_frame,
            textvariable=self.confirm_var,
            show="●",
            bg=Theme.BG_INPUT,
            fg=Theme.TEXT_PRIMARY,
            insertbackground=Theme.ACCENT_CYAN,
            font=("Segoe UI", 11),
            borderwidth=0,
            highlightthickness=0,
        )
        self.confirm_entry.pack(fill="both", expand=True, padx=10, pady=7)

        # ── Progress & Action ──
        self.progress_frame = tk.Frame(main, bg=Theme.BG_DARK)
        self.progress_frame.pack(fill="x", pady=(0, 6))

        self.progress = ttk.Progressbar(
            self.progress_frame, style="Custom.Horizontal.TProgressbar",
            mode="determinate", maximum=100,
        )
        self.progress.pack(fill="x", pady=(0, 4))

        self.status_label = ttk.Label(
            self.progress_frame, text="Listo", style="Status.TLabel",
        )
        self.status_label.pack(anchor="w")

        # Action button
        self.action_btn = self._make_button(
            main, "🔒  ENCRIPTAR ARCHIVOS", Theme.ACCENT_GREEN, self._execute, large=True,
        )
        self.action_btn.pack(fill="x", pady=(4, 0))

        # Bind enter key
        self.root.bind("<Return>", lambda e: self._execute())

    def _make_card(self, parent) -> tk.Frame:
        """Create a styled card frame."""
        card = tk.Frame(
            parent, bg=Theme.BG_CARD,
            highlightbackground=Theme.BORDER, highlightthickness=1,
        )
        return card

    def _make_button(self, parent, text, color, command, large=False):
        """Create a styled button."""
        font = ("Segoe UI", 11, "bold") if large else ("Segoe UI", 9)
        pady = 10 if large else 6
        padx = 16 if large else 12

        btn = tk.Label(
            parent, text=text, bg=color, fg="white",
            font=font, cursor="hand2", padx=padx, pady=pady,
        )
        btn.bind("<Button-1>", lambda e: command())

        # Store base color on widget so it can be updated externally
        btn._base_color = color

        # Hover effects
        def on_enter(e):
            base = btn._base_color
            r, g, b = btn.winfo_rgb(base)
            r = min(65535, int(r * 1.15))
            g = min(65535, int(g * 1.15))
            b = min(65535, int(b * 1.15))
            btn.configure(bg=f"#{r >> 8:02x}{g >> 8:02x}{b >> 8:02x}")

        def on_leave(e):
            btn.configure(bg=btn._base_color)

        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return btn

    def _on_mode_change(self):
        mode = self.mode.get()
        if mode == "encrypt":
            self.action_btn.configure(text="🔒  ENCRIPTAR ARCHIVOS", bg=Theme.ACCENT_GREEN)
            self.action_btn._base_color = Theme.ACCENT_GREEN
            self.confirm_frame.pack(fill="x", pady=(10, 0))
        else:
            self.action_btn.configure(text="🔓  DESENCRIPTAR ARCHIVOS", bg=Theme.ACCENT_CYAN)
            self.action_btn._base_color = Theme.ACCENT_CYAN
            self.confirm_frame.pack_forget()
        self._clear_files()

    def _select_files(self):
        if self.is_processing:
            return
        mode = self.mode.get()
        if mode == "encrypt":
            filetypes = [("Todos los archivos", "*.*")]
        else:
            filetypes = [("Archivos encriptados", f"*{ENCRYPTED_EXTENSION}"),
                         ("Todos los archivos", "*.*")]

        files = filedialog.askopenfilenames(
            title="Seleccionar archivos",
            filetypes=filetypes,
        )
        if files:
            for f in files:
                if f not in self.selected_files:
                    self.selected_files.append(f)
            self._refresh_file_list()

    def _select_folder(self):
        if self.is_processing:
            return
        folder = filedialog.askdirectory(title="Seleccionar carpeta")
        if not folder:
            return

        mode = self.mode.get()
        folder_path = Path(folder)

        for f in folder_path.rglob("*"):
            if not f.is_file():
                continue
            fstr = str(f)
            if fstr in self.selected_files:
                continue
            if mode == "encrypt" and f.suffix == ENCRYPTED_EXTENSION:
                continue
            if mode == "decrypt" and f.suffix != ENCRYPTED_EXTENSION:
                continue
            self.selected_files.append(fstr)

        self._refresh_file_list()

    def _clear_files(self):
        self.selected_files.clear()
        self._refresh_file_list()

    def _refresh_file_list(self):
        self.file_listbox.delete(0, tk.END)
        for f in self.selected_files:
            p = Path(f)
            size = p.stat().st_size if p.exists() else 0
            size_str = self._format_size(size)
            self.file_listbox.insert(tk.END, f"  {p.name}  ({size_str})  —  {p.parent}")
        count = len(self.selected_files)
        self.file_count_label.configure(
            text=f"{count} archivo{'s' if count != 1 else ''}"
        )

    def _toggle_password(self, event=None):
        self.show_pass = not self.show_pass
        char = "" if self.show_pass else "●"
        self.password_entry.configure(show=char)
        self.toggle_btn.configure(text="🔒" if self.show_pass else "👁")

    def _update_strength(self, *args):
        password = self.password_var.get()
        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if any(c.isupper() for c in password) and any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for c in password):
            score += 1

        self.strength_bar.delete("all")
        w = self.strength_bar.winfo_width()
        if w <= 1:
            w = 400

        colors = ["#ef476f", "#f77f00", "#ffd166", "#06d6a0", "#06d6a0"]
        labels = ["Muy débil", "Débil", "Aceptable", "Fuerte", "Muy fuerte"]

        if password:
            bar_w = int(w * (score / 5))
            color = colors[min(score, 4) - 1] if score > 0 else colors[0]
            self.strength_bar.create_rectangle(0, 0, bar_w, 4, fill=color, outline="")
            self.strength_label.configure(text=labels[min(score, 4) - 1] if score > 0 else labels[0])
        else:
            self.strength_label.configure(text="")

    def _execute(self):
        if self.is_processing:
            return

        # Validations
        if not self.selected_files:
            messagebox.showwarning("Sin archivos", "Selecciona al menos un archivo o carpeta.")
            return

        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Sin clave", "Ingresa una clave maestra.")
            return

        if len(password) < 4:
            messagebox.showwarning("Clave muy corta", "La clave debe tener al menos 4 caracteres.")
            return

        mode = self.mode.get()
        if mode == "encrypt":
            confirm = self.confirm_var.get()
            if password != confirm:
                messagebox.showerror("Error", "Las claves no coinciden.")
                return

            # Confirm action
            count = len(self.selected_files)
            if not messagebox.askyesno(
                "Confirmar encriptación",
                f"¿Encriptar {count} archivo{'s' if count != 1 else ''}?\n\n"
                "⚠️ Los archivos originales serán eliminados.\n"
                "Asegúrate de recordar tu clave maestra.",
            ):
                return
        else:
            count = len(self.selected_files)
            if not messagebox.askyesno(
                "Confirmar desencriptación",
                f"¿Desencriptar {count} archivo{'s' if count != 1 else ''}?",
            ):
                return

        # Run in background thread
        self.is_processing = True
        self.action_btn.configure(bg=Theme.TEXT_DIM)
        threading.Thread(target=self._process_files, args=(mode, password), daemon=True).start()

    def _process_files(self, mode: str, password: str):
        total = len(self.selected_files)
        success = 0
        errors = []

        for i, filepath in enumerate(self.selected_files[:]):
            filename = Path(filepath).name
            self._update_status(f"{'Encriptando' if mode == 'encrypt' else 'Desencriptando'}: {filename}")
            self._update_progress((i / total) * 100)

            try:
                if mode == "encrypt":
                    CryptoEngine.encrypt_file(filepath, password)
                else:
                    CryptoEngine.decrypt_file(filepath, password)
                success += 1
            except Exception as e:
                errors.append(f"{filename}: {e}")

        self._update_progress(100)

        # Summary
        action = "encriptados" if mode == "encrypt" else "desencriptados"
        msg = f"✅ {success}/{total} archivos {action} exitosamente."
        if errors:
            msg += f"\n\n❌ {len(errors)} error(es):\n" + "\n".join(errors[:10])

        self.root.after(0, lambda: self._finish_processing(msg, len(errors) == 0))

    def _finish_processing(self, message: str, all_ok: bool):
        self.is_processing = False
        self._on_mode_change()  # Reset button
        self._clear_files()
        self.password_var.set("")
        self.confirm_var.set("")
        self._update_status("Listo")
        self._update_progress(0)

        if all_ok:
            messagebox.showinfo("Completado", message)
        else:
            messagebox.showwarning("Completado con errores", message)

    def _update_status(self, text: str):
        self.root.after(0, lambda: self.status_label.configure(text=text))

    def _update_progress(self, value: float):
        self.root.after(0, lambda: self.progress.configure(value=value))

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        for unit in ["KB", "MB", "GB"]:
            size_bytes /= 1024
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
        return f"{size_bytes:.1f} TB"

    def run(self):
        self.root.mainloop()


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = SecureVaultApp()
    app.run()
