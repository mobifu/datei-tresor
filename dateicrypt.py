import base64
import hashlib
import io
import json
import os
import pathlib
import secrets
import shutil
import string
import subprocess
import sys
import threading
import traceback
import urllib.request
import webbrowser
import zipfile
from tkinter import filedialog, messagebox

import customtkinter
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from packaging.version import parse as parse_version

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    DND_FILES = None

    class _MockDnDWrapper:
        pass

    class TkinterDnD:
        DnDWrapper = _MockDnDWrapper


from secure_memory import SecureString  # NEU: Import der sicheren String-Klasse

# --- Logik ---

# --- Konstanten ---
COMPANY_NAME = "© Agentur Schölzke 2025"
COMPANY_URL = "https://www.agentur-schoelzke.de"
DONATE_URL = "https://paypal.me/kaischoelzke"
VERSION_INFO = "v1.4.1"  # Die aktuelle Version dieser Anwendung

# URL zur Textdatei, die die neueste Versionsnummer enthält (z.B. "v1.0.1")
VERSION_CHECK_URL = "https://www.agentur-schoelzke.de/daten_tresor/version.txt"  # BITTE ANPASSEN
UPDATE_URL = "https://www.agentur-schoelzke.de/daten_tresor/download.php"  # URL zum Zähler-Skript


# --- NEU: Key-Caching für bessere Performance ---
class KeyCache:
    """
    Ein einfacher Cache, der abgeleitete Schlüssel sicher im Speicher hält,
    um die wiederholte, langsame PBKDF2-Berechnung zu vermeiden.
    Die Schlüssel werden als SecureString-Objekte gespeichert.
    """

    def __init__(self):
        self._cache = {}  # Speichert {password_hash: secure_key_object}

    def get_key(self, password, salt):
        """Holt einen Schlüssel aus dem Cache oder leitet ihn neu ab und speichert ihn."""
        # Wenn kein Salt übergeben wird (beim Verschlüsseln), muss zuerst einer generiert werden.
        is_new_salt = salt is None
        if is_new_salt:
            salt = secrets.token_bytes(16)

        # Wir hashen das Passwort, um es nicht im Klartext als Key zu verwenden
        password_hash = hashlib.sha256(password.encode() + salt).hexdigest()

        if password_hash in self._cache:
            # Der Wert im Cache ist base64-kodiert, wir müssen ihn dekodieren, um die rohen Bytes zu erhalten.
            key_b64 = self._cache[password_hash].get_value()
            return base64.urlsafe_b64decode(key_b64), salt

        # Schlüssel ist nicht im Cache, also neu ableiten
        key, _ = get_key_from_password(password, salt)  # Der Salt wurde bereits oben generiert/übergeben

        # Speichere den abgeleiteten Schlüssel als Base64-String im SecureString
        self._cache[password_hash] = SecureString(base64.urlsafe_b64encode(key).decode())
        return key, salt


# --- Profile Management Logic ---
PROFILE_FILE = "profiles.dat"  # Datei zum Speichern der verschlüsselten Profile


class ProfileManager:
    def __init__(self):
        self.profiles = {}  # Speichert entschlüsselte Profile: {"profil_name": "passwort_fuer_dateien"}
        self.master_salt = None  # Salt für das Master-Passwort
        self.profile_file_path = os.path.join(os.path.dirname(sys.argv[0]), PROFILE_FILE)

    def has_master_password_set(self):
        """Prüft, ob eine Profildatei existiert, was auf ein gesetztes Master-Passwort hindeutet."""
        return os.path.exists(self.profile_file_path)

    def _get_master_key_from_password(self, master_password, salt):
        """Leitet einen Schlüssel aus dem Master-Passwort und dessen Salt ab."""
        # Vereinheitlicht: Nutzt jetzt die zentrale Funktion zur Schlüsselableitung.
        key_bytes, _ = get_key_from_password(master_password, salt)
        return base64.urlsafe_b64encode(key_bytes)

    def load_profiles(self, master_password):
        """Lädt und entschlüsselt Profile mit dem Master-Passwort."""
        if not self.has_master_password_set():
            self.profiles = {}  # Sicherstellen, dass die Profile leer sind
            self.master_salt = None
            return True, "Keine Profildatei gefunden, starte ohne Profile."

        try:
            with open(self.profile_file_path, "rb") as f:
                file_content = f.read()

            self.master_salt = file_content[:16]
            encrypted_profile_data = file_content[16:]

            master_key = self._get_master_key_from_password(master_password, self.master_salt)
            fernet = Fernet(master_key)
            decrypted_data_json = fernet.decrypt(encrypted_profile_data).decode("utf-8")
            self.profiles = json.loads(decrypted_data_json)
            return True, "Profile erfolgreich geladen."
        except Exception as e:
            self.profiles = {}  # Profile bei Fehler löschen
            self.master_salt = None
            return False, f"Fehler beim Laden der Profile: Falsches Master-Passwort oder beschädigte Datei. ({e})"

    def save_profiles(self, master_password):
        """Verschlüsselt und speichert die aktuellen Profile mit dem Master-Passwort."""
        # Wenn keine Profile mehr vorhanden sind, die Profildatei löschen.
        if not self.profiles:
            if os.path.exists(self.profile_file_path):
                os.remove(self.profile_file_path)
            self.master_salt = None  # Salt zurücksetzen (bleibt hier, falls später wieder aktiviert)
            self.profiles = {}  # Sicherstellen, dass die Profile leer sind
            return True, "Alle Profile gelöscht. Master-Passwort wurde entfernt."

        try:
            if self.master_salt is None:
                self.master_salt = secrets.token_bytes(
                    16
                )  # Neuen Salt generieren, falls nicht gesetzt (erste Speicherung)

            # Wenn das Passwort ein SecureString-Objekt ist, den Wert extrahieren.
            pw_to_use = (
                master_password.get_value().decode("utf-8")
                if isinstance(master_password, SecureString)
                else master_password
            )

            master_key = self._get_master_key_from_password(pw_to_use, self.master_salt)
            fernet = Fernet(master_key)

            profile_data_json = json.dumps(self.profiles)
            encrypted_profile_data = fernet.encrypt(profile_data_json.encode("utf-8"))

            with open(self.profile_file_path, "wb") as f:
                f.write(self.master_salt + encrypted_profile_data)
            return True, "Profile erfolgreich gespeichert."
        except Exception as e:
            return False, f"Fehler beim Speichern der Profile: {e}"

    def add_profile(self, name, password):
        """Fügt ein neues Profil hinzu."""
        if name in self.profiles:
            return False, "Profilname existiert bereits."
        self.profiles[name] = password
        return True, "Profil hinzugefügt."

    def update_profile(self, old_name, new_name, new_password):
        """Aktualisiert ein bestehendes Profil."""
        if old_name not in self.profiles:
            return False, "Profil nicht gefunden."
        if (
            old_name != new_name and new_name in self.profiles
        ):  # Name change not allowed in current UI, but good for robustness
            return False, "Neuer Profilname existiert bereits."

        self.profiles[new_name] = new_password  # Update password, name is assumed to be the same
        return True, "Profil aktualisiert."

    def delete_profile(self, name):
        """Löscht ein Profil."""
        if name not in self.profiles:
            return False, "Profil nicht gefunden."
        del self.profiles[name]
        return True, "Profil gelöscht."

    def change_master_password(self, old_master_password, new_master_password):
        """Ändert das Master-Passwort."""
        # Wenn das alte Passwort ein SecureString ist, den Wert extrahieren.
        old_pw_str = (
            old_master_password.get_value().decode("utf-8")
            if isinstance(old_master_password, SecureString)
            else old_master_password
        )

        # Lade zuerst die Profile mit dem alten Passwort, um sicherzustellen, dass es korrekt ist.
        success, _ = self.load_profiles(old_pw_str)
        if not success:
            return False, "Das alte Master-Passwort ist nicht korrekt."

        # Speichere die geladenen Profile mit dem neuen Passwort.
        # Das neue Passwort ist hier immer ein String.
        return self.save_profiles(new_master_password)


def get_key_from_password(password, salt=None):
    """Erstellt einen Fernet-Key aus einem Passwort."""
    if salt is None:
        salt = secrets.token_bytes(16)  # Neuer Salt für Verschlüsselung

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,  # Erhöht für mehr Sicherheit gegen Brute-Force
    )
    with SecureString(password) as secure_pass:
        # WICHTIG: derive() gibt die rohen Bytes zurück. Base64-Encoding erfolgt erst bei Bedarf.
        key_bytes = kdf.derive(secure_pass.get_value())
        return key_bytes, salt


def process_file(mode, filepath, password):
    """
    mode: 'encrypt' oder 'decrypt'
    filepath: Pfad zur Datei
    password: Das Passwort als String
    """
    try:
        # Diese Funktion wird jetzt nur noch für die Legacy-Entschlüsselung verwendet.
        # Neue Verschlüsselung und Entschlüsselung laufen über process_file_stream.
        if mode == "encrypt":
            return False, "Veralteter Codepfad für Verschlüsselung aufgerufen."

        elif mode == "decrypt":
            if not filepath.endswith(".crypted"):
                return False, "Fehler: Bitte eine .crypted Datei auswählen."

            with open(filepath, "rb"):
                # Diese Funktion wird nur noch für Legacy-Fernet-Dateien aufgerufen.
                return _decrypt_legacy_fernet(filepath, password)

    except Exception as e:
        return False, str(e)


def process_file_stream(mode, filepath, password, progress_callback):
    """
    Ver- und entschlüsselt eine Datei im Streaming-Verfahren mit AES-GCM.
    """
    CHUNK_SIZE = 1024 * 1024  # 1 MB Chunks

    try:
        if mode == "encrypt":
            output_path = filepath + ".crypted"
            key, salt = get_key_from_password(password)
            nonce = secrets.token_bytes(12)  # GCM empfiehlt 12 bytes

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
            encryptor = cipher.encryptor()

            with open(filepath, "rb") as infile, open(output_path, "wb") as outfile:
                # Schreibe Header: Salt, Nonce
                outfile.write(salt)
                outfile.write(nonce)

                total_size = os.path.getsize(filepath)
                bytes_processed = 0

                while True:
                    chunk = infile.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = encryptor.update(chunk)
                    outfile.write(encrypted_chunk)
                    bytes_processed += len(chunk)
                    progress_callback(bytes_processed / total_size if total_size > 0 else 1)

                # Finalisiere die Verschlüsselung und schreibe den Authentifizierungs-Tag
                outfile.write(encryptor.finalize())
                outfile.write(encryptor.tag)

            return True, f"Datei verschlüsselt gespeichert als:\n{output_path}"

        elif mode == "decrypt":
            if not filepath.endswith(".crypted"):
                return False, "Fehler: Bitte eine .crypted Datei auswählen."

            # VERSUCH 1: Neues Verfahren (AES-GCM)
            try:
                with open(filepath, "rb") as infile:
                    salt = infile.read(16)
                    nonce = infile.read(12)

                    # Wenn Nonce zu kurz ist, ist es sicher kein GCM -> Exception für Fallback
                    if len(nonce) < 12:
                        raise ValueError("Datei zu kurz für GCM")

                    key, _ = get_key_from_password(password, salt)

                    # Der Authentifizierungs-Tag ist die letzten 16 Bytes der Datei
                    file_size = os.path.getsize(filepath)
                    tag_position = file_size - 16

                    if tag_position < 16 + 12:
                        raise ValueError("Datei ungültig")

                    infile.seek(tag_position)
                    tag = infile.read(16)

                    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                    decryptor = cipher.decryptor()

                    # Temporäre In-Memory-Datei für die entschlüsselten Daten
                    decrypted_stream = io.BytesIO()

                    infile.seek(16 + 12)  # Gehe zum Anfang der verschlüsselten Daten
                    total_size = tag_position - (16 + 12)
                    bytes_processed = 0

                    while True:
                        # Lese bis zum nächsten Chunk oder bis zum Tag
                        bytes_to_read = min(CHUNK_SIZE, tag_position - infile.tell())
                        if bytes_to_read <= 0:
                            break

                        chunk = infile.read(bytes_to_read)
                        decrypted_chunk = decryptor.update(chunk)
                        decrypted_stream.write(decrypted_chunk)

                        bytes_processed += len(chunk)
                        progress_callback(bytes_processed / total_size if total_size > 0 else 1)

                    # Finalize wird hier aufgerufen, um den Tag zu verifizieren. Löst bei Fehler eine Exception aus.
                    decrypted_stream.write(decryptor.finalize())
                    decrypted_stream.seek(0)
                    return _handle_decrypted_data(decrypted_stream, filepath)

            except Exception:
                # Fallback: Wenn AES-GCM fehlschlägt (z.B. alte Datei), versuchen wir das alte Format
                return _decrypt_legacy_fernet(filepath, password, progress_callback)

    except Exception as e:
        # Bei GCM kann eine Exception "InvalidTag" bedeuten, dass das Passwort falsch ist.
        if "InvalidTag" in str(e):
            return False, "Falsches Passwort oder beschädigte Datei."
        return False, f"Ein Fehler ist aufgetreten: {e}"


def _decrypt_legacy_fernet(filepath, password, progress_callback=None):
    """Entschlüsselt alte, mit Fernet erstellte Dateien."""
    if progress_callback:
        progress_callback(0.1)
    with open(filepath, "rb") as f:
        file_content = f.read()

    salt = file_content[:16]
    encrypted_data = file_content[16:]

    # Wir versuchen sowohl die alte (100k) als auch die neue (600k) Iterationszahl,
    # falls es Zwischenversionen gab, die Fernet mit 600k nutzten.
    iterations_to_try = [100000, 600000]

    for iterations in iterations_to_try:
        try:
            if progress_callback:
                progress_callback(0.3)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
            )
            pw_bytes = password.get_value() if isinstance(password, SecureString) else password.encode("utf-8")
            key_bytes = kdf.derive(pw_bytes)

            fernet = Fernet(base64.urlsafe_b64encode(key_bytes))

            if progress_callback:
                progress_callback(0.6)
            decrypted_data = fernet.decrypt(encrypted_data)
            if progress_callback:
                progress_callback(0.8)
            decrypted_stream = io.BytesIO(decrypted_data)
            return _handle_decrypted_data(decrypted_stream, filepath)
        except InvalidToken:
            continue
        except Exception as e:
            print(f"Fehler bei Legacy-Entschlüsselung (Iterationen: {iterations}): {e}")
            continue

    return False, "Falsches Passwort oder beschädigte Datei (Legacy-Format)."


def _handle_decrypted_data(decrypted_stream, original_filepath):
    """Verarbeitet entschlüsselte Daten, entpackt ZIPs oder speichert Dateien."""
    try:
        # NEU: Prüfen, ob die Datei überhaupt als ZIP-Archiv (.zip) markiert war.
        # Verhindert, dass Office-Dateien (.odt, .docx), die technisch ZIPs sind, entpackt werden.
        if not original_filepath.lower().endswith(".zip.crypted"):
            raise zipfile.BadZipFile("Keine .zip Datei, überspringe Entpacken.")

        # Versuche, die Daten als ZIP-Archiv zu behandeln
        with zipfile.ZipFile(decrypted_stream, "r") as zf:
            if zf.testzip() is not None:
                raise zipfile.BadZipFile("Kein gültiges ZIP-Archiv.")

            decrypted_stream.seek(0)  # Wichtig: Stream für das Entpacken zurücksetzen
            output_folder_path = original_filepath.replace(".crypted", "").replace(".zip", "")
            target_dir = pathlib.Path(output_folder_path).resolve()
            for member in zf.infolist():
                member_path = (target_dir / member.filename).resolve()
                if not member_path.is_relative_to(target_dir):
                    raise ValueError(f"Sicherheitsrisiko: Ungültiger Pfad im Archiv ({member.filename})")
            zf.extractall(path=target_dir)
            return True, f"Ordner entschlüsselt und wiederhergestellt in:\n{target_dir}"
    except (shutil.ReadError, zipfile.BadZipFile):
        final_output_path = original_filepath.replace(".crypted", "").replace("_archive.zip", "")
        if os.path.exists(final_output_path):
            name, ext = os.path.splitext(final_output_path)
            final_output_path = f"{name}_decrypted{ext}"

        with open(final_output_path, "wb") as f:
            f.write(decrypted_stream.getvalue())
        return True, f"Datei entschlüsselt gespeichert als:\n{final_output_path}"


def process_folder(mode, folderpath, password):
    """
    Verschlüsselt oder entschlüsselt einen ganzen Ordner.
    mode: 'encrypt' oder 'decrypt'
    folderpath: Pfad zum Ordner (für encrypt) oder zur .crypted-Datei (für decrypt)
    password: Das Passwort als String
    """
    # Diese Funktion wird jetzt nur noch zum Packen von Ordnern vor der Verschlüsselung verwendet.
    # Die eigentliche Verschlüsselung und Entschlüsselung wird von den Streaming-Funktionen gehandhabt.
    if mode == "encrypt":
        try:
            archive_name = shutil.make_archive(
                base_name=f"{folderpath}_archive",
                format="zip",
                root_dir=os.path.dirname(folderpath),
                base_dir=os.path.basename(folderpath),
            )
            # Die Funktion gibt jetzt den Pfad zum temporären Archiv zurück.
            # Die Verschlüsselung und das Löschen erfolgen im aufrufenden Code.
            return True, archive_name
        except Exception as e:
            return False, f"Ein Fehler beim Packen des Ordners ist aufgetreten: {e}"
    else:  # Decrypt-Modus
        return False, "Interne Logik fehlerhaft: process_folder für Entschlüsselung aufgerufen."


# --- GUI ---


class App(customtkinter.CTk, TkinterDnD.DnDWrapper):
    def __init__(self):
        super().__init__()
        # Diese Zeile ist für die Initialisierung von tkinterdnd2 erforderlich
        try:
            self.TkdndVersion = TkinterDnD._require(self)
        except Exception as e:
            # Fängt einen seltenen Fehler ab, der auf manchen Systemen auftreten kann.
            print(f"Warnung: Konnte TkinterDND nicht initialisieren: {e}")
            messagebox.showwarning("Warnung", "Drag-and-Drop-Funktionalität konnte nicht initialisiert werden.")

        self.title("Datei Tresor")
        self.geometry("500x350")
        # Setze das Erscheinungsbild (z.B. "System", "Dark", "Light")
        customtkinter.set_appearance_mode("System")
        customtkinter.set_default_color_theme("blue")

        # Header
        lbl_title = customtkinter.CTkLabel(
            self, text="Universal Datei-Verschlüsselung", font=customtkinter.CTkFont(size=16, weight="bold")
        )
        lbl_title.pack(pady=(15, 2))

        self.lbl_hinweis = customtkinter.CTkLabel(
            self, text="Dateien hierher ziehen oder Buttons verwenden.", font=customtkinter.CTkFont(size=12)
        )
        self.lbl_hinweis.pack(pady=(0, 10))

        # NEU: Überarbeitetes Overlay für die Drag-and-Drop-Zone
        self.drop_zone_frame = customtkinter.CTkFrame(
            self, corner_radius=12, border_width=3, border_color=("gray70", "gray35")
        )
        self.drop_zone_label = customtkinter.CTkLabel(
            self.drop_zone_frame, text="Datei hier ablegen", font=customtkinter.CTkFont(size=24, weight="bold")
        )
        self.drop_zone_label.pack(expand=True)

        self.key_cache = KeyCache()  # NEU: Initialisiere den Key-Cache
        self.profile_manager = ProfileManager()
        self.active_profile_name = None  # Aktuell ausgewähltes Profil für Ver-/Entschlüsselung

        # Profil Auswahl UI (nach oben verschoben)
        frame_profile_selection = customtkinter.CTkFrame(self)
        frame_profile_selection.pack(padx=20, pady=5, fill="x")

        customtkinter.CTkLabel(frame_profile_selection, text="Aktives Profil:").pack(side="left", padx=(10, 10))
        self.profile_option_menu = customtkinter.CTkOptionMenu(
            frame_profile_selection, values=["Kein Profil ausgewählt"], command=self._on_profile_selected
        )
        self.profile_option_menu.pack(side="left", expand=True, fill="x", pady=10)

        btn_manage_profiles = customtkinter.CTkButton(
            frame_profile_selection, text="Profile verwalten", command=self.show_profile_manager_dialog
        )
        btn_manage_profiles.pack(side="right", padx=(10, 10), pady=10)

        # Passwort
        frame_pw = customtkinter.CTkFrame(self, fg_color="transparent")
        frame_pw.pack(padx=20, pady=5, fill="x")
        frame_pw.grid_columnconfigure(0, weight=1)  # Lässt das Eingabefeld wachsen

        self.entry_pw = customtkinter.CTkEntry(
            frame_pw, show="*", placeholder_text="Passwort hier eingeben...", height=30
        )
        self.entry_pw.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="ew")

        # NEU: Checkbox zum Anzeigen des Passworts
        show_pw_checkbox = customtkinter.CTkCheckBox(
            frame_pw, text="Zeigen", command=lambda: self._toggle_password_visibility(self.entry_pw, show_pw_checkbox)
        )
        show_pw_checkbox.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="w")

        # Aktionen
        frame_actions = customtkinter.CTkFrame(self)
        frame_actions.pack(pady=20)

        self.btn_enc = customtkinter.CTkButton(
            frame_actions, text="🔒 Verschlüsseln", command=lambda: self.run_action("encrypt")
        )
        self.btn_enc.pack(side="left", padx=10, pady=10)

        self.btn_dec = customtkinter.CTkButton(
            frame_actions, text="🔓 Entschlüsseln", command=lambda: self.run_action("decrypt")
        )
        self.btn_dec.pack(side="left", padx=10, pady=10)

        # --- NEU: Fortschrittsanzeige im Hauptfenster ---
        self.frame_progress = customtkinter.CTkFrame(self, fg_color="transparent")
        # .pack() wird bei Bedarf aufgerufen, um es anzuzeigen

        self.lbl_progress_status = customtkinter.CTkLabel(self.frame_progress, text="")
        self.lbl_progress_status.pack(pady=(0, 2))

        self.progress_bar = customtkinter.CTkProgressBar(self.frame_progress, width=360)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", pady=(2, 2), padx=20)

        self.lbl_progress_percent = customtkinter.CTkLabel(self.frame_progress, text="0%")
        self.lbl_progress_percent.pack(pady=(0, 5))

        # Referenz zum Action-Frame für die Platzierung der Fortschrittsanzeige
        self.frame_actions_ref = frame_actions

        # --- Footer ---
        frame_footer = customtkinter.CTkFrame(self, fg_color="transparent")
        frame_footer.pack(side="bottom", fill="x", padx=20, pady=(0, 10))

        lbl_version = customtkinter.CTkLabel(frame_footer, text=VERSION_INFO, font=customtkinter.CTkFont(size=12))
        lbl_version.pack(side="left")

        # Lizenz-Link
        link_font = customtkinter.CTkFont(size=12, underline=True)
        lbl_license = customtkinter.CTkLabel(
            frame_footer, text="Lizenz", font=link_font, text_color="#6495ED", cursor="hand2"
        )
        lbl_license.pack(side="left", padx=20)
        lbl_license.bind("<Button-1>", lambda e: self.show_license_info())

        # Hyperlink-Label für die Firma
        lbl_company = customtkinter.CTkLabel(
            frame_footer, text=COMPANY_NAME, font=link_font, text_color="#6495ED", cursor="hand2"
        )
        lbl_company.pack(side="right")
        lbl_company.bind("<Button-1>", lambda e: self.open_link(COMPANY_URL))

        # Spenden-Button (Dezent im Footer)
        btn_donate = customtkinter.CTkButton(
            frame_footer,
            text="☕ Spenden",
            width=80,
            height=20,
            font=customtkinter.CTkFont(size=11),
            fg_color="transparent",
            border_width=1,
            border_color=("gray60", "gray40"),
            text_color=("gray10", "gray90"),
            hover_color=("gray80", "gray30"),
            command=lambda: self.open_link(DONATE_URL),
        )
        btn_donate.pack(side="right", padx=(0, 15))

        self.current_master_password_in_session = None  # Speichert das Master-Passwort als SecureString-Objekt
        # Platzhalter, um Lizenz und Firma auseinanderzuhalten
        customtkinter.CTkLabel(frame_footer, text="").pack(side="left", expand=True)

        self.selected_path = None
        self.selection_type = None  # 'file' oder 'folder'

        # --- Initialisierungslogik ---
        # Set up a global exception handler
        # WICHTIG: traceback muss importiert sein, damit dies funktioniert
        sys.excepthook = self._handle_exception

        # Prüfen, ob bereits Profile (und damit ein Master-Passwort) existieren.
        if self.profile_manager.has_master_password_set():
            # Wenn ein Master-Passwort existiert, verstecken wir das Hauptfenster manuell, bevor der Passwort-Dialog erscheint.
            self.withdraw()
            # Wenn ja, das Master-Passwort abfragen, um die Profile zu laden.
            self._ask_for_master_password_on_startup()
        else:
            # Wenn kein Master-Passwort existiert, bleibt das Fenster einfach sichtbar
            # und wir finalisieren den Start.
            self._finalize_startup()  # UI initialisieren und Updates prüfen

        # Binde den ersten Update-Check an das Ereignis, wenn das Fenster den Fokus erhält.
        self.bind("<FocusIn>", self._run_first_update_check, add="+")

        # Drag-and-Drop-Events für das gesamte Fenster registrieren
        # Reihenfolge ist wichtig: Enter/Leave vor Drop
        self.drop_target_register(DND_FILES)
        self.dnd_bind("<<DragEnter>>", self._on_drag_enter)
        self.dnd_bind("<<Drop>>", self._handle_drop)
        self.dnd_bind("<<DragLeave>>", self._on_drag_leave)

    def open_link(self, url):  # Korrigierte Einrückung
        webbrowser.open_new(url)

    def _toggle_password_visibility(self, entry_widget, checkbox_widget):
        """Schaltet die Sichtbarkeit des Passworts in einem Eingabefeld um."""
        if checkbox_widget.get() == 1:  # Checkbox ist aktiviert
            entry_widget.configure(show="")
        else:
            entry_widget.configure(show="*")

    # Die Methoden select_file und select_folder werden nicht mehr direkt von Buttons aufgerufen,
    # sondern über einen neuen Dialog.

    def select_file(self):  # Korrigierte Einrückung
        file = filedialog.askopenfilename()
        if file:
            self.selected_path = file
            self.selection_type = "file"
            return file

    def select_folder(self):  # Korrigierte Einrückung
        folder = filedialog.askdirectory()
        if folder:
            self.selected_path = folder
            self.selection_type = "folder"
            return folder

    def _on_profile_selected(self, choice):  # Korrigierte Einrückung
        """Callback, wenn ein Profil aus dem Dropdown ausgewählt wird."""
        if choice == "Kein Profil ausgewählt":
            self.active_profile_name = None
            self.entry_pw.configure(state="normal")
            self.entry_pw.delete(0, "end")
            self.entry_pw.configure(placeholder_text="Passwort hier eingeben...")
        else:
            self.active_profile_name = choice
            self.entry_pw.delete(0, "end")
            self.entry_pw.configure(placeholder_text=f"Passwort von Profil '{choice}' wird verwendet", state="disabled")

    def _update_profile_selection_ui(self):  # Korrigierte Einrückung
        """Aktualisiert das Profilauswahl-Dropdown mit den aktuellen Profilen."""
        profile_names = list(self.profile_manager.profiles.keys())

        # Die Liste für das Dropdown-Menü immer mit der manuellen Option beginnen
        dropdown_values = ["Kein Profil ausgewählt"] + sorted(profile_names)
        self.profile_option_menu.configure(values=dropdown_values)

        # Prüfen, ob ein gültiges Profil aktiv bleiben soll (z.B. nach dem Bearbeiten/Löschen)
        if self.active_profile_name and self.active_profile_name in profile_names:
            self.profile_option_menu.set(self.active_profile_name)
            # Der Callback _on_profile_selected wird hierdurch NICHT automatisch ausgelöst, daher manuell den Zustand setzen
            self.entry_pw.configure(
                placeholder_text=f"Passwort von Profil '{self.active_profile_name}' wird verwendet", state="disabled"
            )
        else:
            # Standardverhalten: Manuelle Eingabe ist vorausgewählt
            self.profile_option_menu.set("Kein Profil ausgewählt")
            self._on_profile_selected("Kein Profil ausgewählt")  # Zustand explizit setzen

    def run_action(self, mode):  # Korrigierte Einrückung
        pw = self.entry_pw.get()

        password_to_use = pw
        if self.active_profile_name:
            # Das Passwort aus dem Profil holen.
            # Es wird als normaler String behandelt, da es für die Dateiverschlüsselung
            # ohnehin in den KeyCache und dann in SecureString geht.
            password_to_use = self.profile_manager.profiles.get(self.active_profile_name, "")
        elif not pw:  # Wenn kein Profil ausgewählt UND kein Passwort manuell eingegeben wurde
            messagebox.showwarning("Achtung", "Bitte ein Passwort eingeben oder ein Profil auswählen.")
            return

        if mode == "encrypt":
            self._show_encryption_selection_dialog(password_to_use)
            # Die weitere Logik (Erfolgs-/Fehlermeldung) wird vom Dialog selbst gehandhabt.
            return
        elif mode == "decrypt":
            file_to_decrypt = filedialog.askopenfilename(
                title="Wählen Sie die zu entschlüsselnde Datei",
                filetypes=[("Verschlüsselte Dateien", "*.crypted"), ("Alle Dateien", "*.*")],
            )
            self._perform_decryption_action(file_to_decrypt, password_to_use)
        else:
            messagebox.showerror("Fehler", "Unbekannte Aktion.")

    def _handle_drop(self, event):
        """Verarbeitet eine per Drag-and-Drop fallengelassene Datei."""
        self._on_drag_leave(event)  # Versteckt das Drop-Zone-Label
        # event.data kann eine Liste von Dateipfaden sein, die durch Leerzeichen getrennt sind.
        # Pfade mit Leerzeichen sind in {} eingeschlossen. Wir nehmen die erste Datei.
        path = event.data.strip()
        if path.startswith("{") and path.endswith("}"):
            path = path[1:-1]
        else:
            # Wenn mehrere Dateien abgelegt werden, nehmen wir nur die erste.
            path = path.split(" ")[0]

        if not os.path.exists(path):
            messagebox.showerror("Fehler", f"Der Pfad '{path}' existiert nicht.")
            return

        # Passwort aus dem UI holen (wie bei run_action)
        pw = self.entry_pw.get()
        password_to_use = pw
        if self.active_profile_name:
            password_to_use = self.profile_manager.profiles.get(self.active_profile_name, "")
        elif not pw:
            messagebox.showwarning(
                "Achtung", "Bitte ein Passwort eingeben oder ein Profil auswählen, bevor Sie eine Datei ablegen."
            )
            return

        # Aktion basierend auf dem Dateityp bestimmen
        if path.endswith(".crypted"):
            # Entschlüsselung
            self._perform_decryption_action(path, password_to_use)
        else:
            # Verschlüsselung
            selection_type = "folder" if os.path.isdir(path) else "file"

            # Erstelle ein Dummy-Dialog-Objekt, das sofort zerstört wird,
            # da wir den Auswahl-Dialog überspringen.
            dummy_dialog = customtkinter.CTkToplevel(self)
            dummy_dialog.withdraw()
            self._perform_encryption_action(selection_type, path, password_to_use, dummy_dialog)

    def _on_drag_enter(self, event):
        """Wird aufgerufen, wenn eine Datei über das Fenster gezogen wird. Zeigt die Drop-Zone an."""
        # Verhindert, dass die Drop-Zone angezeigt wird, wenn eine Operation läuft
        if self.btn_enc.cget("state") == "disabled":
            return
        # Setze die Hintergrundfarbe des Rahmens auf die Fensterfarbe, um einen "durchsichtigen" Effekt zu erzielen
        self.drop_zone_frame.configure(fg_color=self.cget("fg_color"))
        self.drop_zone_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.9, relheight=0.9)
        self.drop_zone_frame.lift()

    def _on_drag_leave(self, event):
        """Wird aufgerufen, wenn die Datei das Fenster verlässt. Versteckt die Drop-Zone."""
        # Das event-Argument wird von der dnd-Bibliothek benötigt, aber hier nicht verwendet.
        self.drop_zone_frame.place_forget()

    def _show_encryption_selection_dialog(self, password_to_use):  # Korrigierte Einrückung
        """Zeigt einen Dialog zur Auswahl, ob Datei oder Ordner verschlüsselt werden soll."""
        dialog = customtkinter.CTkToplevel(self)
        dialog.title("Verschlüsselung")
        dialog.geometry("300x150")
        dialog.transient(self)
        dialog.grab_set()

        customtkinter.CTkLabel(dialog, text="Was möchten Sie verschlüsseln?").pack(pady=(15, 10))

        def _select_and_encrypt(selection_type):
            path = None
            if selection_type == "file":
                path = filedialog.askopenfilename(parent=dialog)
            elif selection_type == "folder":
                path = filedialog.askdirectory(parent=dialog)

            if path:
                # Führe die Verschlüsselung im Haupt-Thread aus, um UI-Updates zu ermöglichen
                self.after(0, lambda: self._perform_encryption_action(selection_type, path, password_to_use, dialog))
            else:
                # Benutzer hat die Auswahl abgebrochen, Dialog bleibt offen
                pass

        frame_buttons = customtkinter.CTkFrame(dialog, fg_color="transparent")
        frame_buttons.pack(pady=5)

        btn_file = customtkinter.CTkButton(
            frame_buttons, text="Datei auswählen", command=lambda: _select_and_encrypt("file")
        )
        btn_file.pack(side="left", padx=5)

        btn_folder = customtkinter.CTkButton(
            frame_buttons, text="Ordner auswählen", command=lambda: _select_and_encrypt("folder")
        )
        btn_folder.pack(side="right", padx=5)

        # Schließen-Button für den Dialog
        btn_close = customtkinter.CTkButton(dialog, text="Abbrechen", command=dialog.destroy)
        btn_close.pack(pady=(10, 0))

    def _perform_encryption_action(
        self, selection_type, path, password_to_use, parent_dialog
    ):  # Korrigierte Einrückung
        """Startet die Verschlüsselung in einem Thread und zeigt den Fortschrittsdialog."""
        parent_dialog.destroy()  # Auswahl-Dialog schließen

        is_temp_archive = False
        file_to_encrypt = path

        if selection_type == "folder":
            # Ordner zuerst packen
            success, result = process_folder("encrypt", path, password_to_use)
            if not success:
                messagebox.showerror("Fehler", result)
                return
            file_to_encrypt = result
            is_temp_archive = True

        # Fortschrittsdialog anzeigen und Thread starten
        self._start_progress_ui(f"Verschlüssle: {os.path.basename(file_to_encrypt)}")

        def task():
            success, msg = process_file_stream("encrypt", file_to_encrypt, password_to_use, self._update_progress_ui)
            if is_temp_archive:
                os.remove(file_to_encrypt)  # Temporäres ZIP-Archiv löschen
            self.after(0, lambda: self._finalize_operation(success, msg))

        threading.Thread(target=task, daemon=True).start()

    def _perform_decryption_action(self, path, password_to_use):
        """Startet die Entschlüsselung in einem Thread und zeigt den Fortschrittsdialog."""
        if not path:
            return  # Benutzer hat abgebrochen

        self._start_progress_ui(f"Entschlüssle: {os.path.basename(path)}")

        def task():
            success, msg = process_file_stream("decrypt", path, password_to_use, self._update_progress_ui)
            self.after(0, lambda: self._finalize_operation(success, msg))

        threading.Thread(target=task, daemon=True).start()

    def _start_progress_ui(self, message):
        """Bereitet die GUI für eine laufende Operation vor und zeigt die Fortschrittsanzeige an."""
        self.geometry("500x450")  # Fenster vergrößern
        self.frame_progress.pack(fill="x", padx=20, pady=5, after=self.frame_actions_ref)
        self.lbl_progress_status.configure(text=message)
        self.btn_enc.configure(state="disabled")
        self.btn_dec.configure(state="disabled")
        self.profile_option_menu.configure(state="disabled")
        self._update_progress_ui(0)  # Zurücksetzen

    def _update_progress_ui(self, value):
        """Aktualisiert die Fortschrittsanzeige im Hauptfenster."""
        self.after(0, lambda: self.progress_bar.set(value))
        self.after(0, lambda: self.lbl_progress_percent.configure(text=f"{int(value * 100)}%"))

    def _finalize_operation(self, success, msg):
        """Beendet eine Operation, versteckt die Fortschrittsanzeige und zeigt das Ergebnis."""
        self.frame_progress.pack_forget()  # Fortschrittsanzeige ausblenden
        self.geometry("500x350")  # Fenstergröße zurücksetzen
        self.btn_enc.configure(state="normal")
        self.btn_dec.configure(state="normal")
        self.profile_option_menu.configure(state="normal")

        if success:
            messagebox.showinfo("Erfolg", msg)
            if not self.active_profile_name:  # Nur leeren, wenn kein Profil verwendet wird
                self.entry_pw.delete(0, "end")
        else:
            messagebox.showerror("Fehler", msg)

    def _ask_for_master_password_on_startup(self):  # Korrigierte Einrückung
        """Zeigt einen Dialog zur Eingabe des Master-Passworts beim Start an."""
        dialog = customtkinter.CTkToplevel(self)
        dialog.title("Master-Passwort erforderlich")
        dialog.geometry("350x150")
        dialog.transient(self)
        dialog.grab_set()
        dialog.protocol("WM_DELETE_WINDOW", self._on_master_pw_dialog_close)  # App beenden bei Schließen

        customtkinter.CTkLabel(dialog, text="Bitte geben Sie Ihr Master-Passwort ein,\num die Profile zu laden.").pack(
            pady=(15, 10)
        )

        pw_frame = customtkinter.CTkFrame(dialog, fg_color="transparent")
        pw_frame.pack(pady=5)

        entry_master_pw = customtkinter.CTkEntry(pw_frame, show="*", width=220)
        entry_master_pw.pack(side="left", padx=(0, 5))
        dialog.after(
            100, entry_master_pw.focus_set
        )  # Stellt sicher, dass der Cursor im Feld aktiv ist, nachdem das Fenster gerendert wurde (mit kleiner Verzögerung)

        show_pw_checkbox = customtkinter.CTkCheckBox(
            pw_frame, text="Zeigen", command=lambda: self._toggle_password_visibility(entry_master_pw, show_pw_checkbox)
        )
        show_pw_checkbox.pack(side="left")

        def _try_login(event=None):
            master_pw_attempt = entry_master_pw.get()
            if not master_pw_attempt:
                messagebox.showwarning("Achtung", "Bitte Master-Passwort eingeben.", parent=dialog)
                return

            success, msg = self.profile_manager.load_profiles(master_pw_attempt)
            entry_master_pw.delete(0, "end")  # Passwort sofort aus dem Feld löschen
            if success:
                # Passwort sicher als SecureString für die Sitzung speichern
                self.current_master_password_in_session = SecureString(master_pw_attempt)
                dialog.destroy()
                self.deiconify()  # Hauptfenster anzeigen
                self._finalize_startup()  # UI initialisieren und Updates prüfen
            else:
                messagebox.showerror("Fehler", "Falsches Master-Passwort.", parent=dialog)

        btn_login = customtkinter.CTkButton(dialog, text="Anmelden", command=_try_login)
        btn_login.pack(pady=10)
        dialog.bind("<Return>", lambda event: _try_login())

    def _on_master_pw_dialog_close(self):  # Korrigierte Einrückung
        """Wird aufgerufen, wenn der Master-Passwort-Dialog geschlossen wird."""
        self.quit()
        self.destroy()

    def _finalize_startup(self):  # Korrigierte Einrückung
        """Wird aufgerufen, nachdem das Hauptfenster sichtbar ist, um die UI zu initialisieren."""
        try:
            self._update_profile_selection_ui()
        except Exception as e:
            print(f"Fehler beim Aktualisieren der Profilauswahl: {e}")
        # Die Update-Prüfung wird jetzt durch das <FocusIn>-Ereignis ausgelöst, nicht mehr hier.

    def _run_first_update_check(self, event=None):  # Korrigierte Einrückung
        """Führt die Update-Prüfung einmalig aus und entfernt dann das Binding."""
        self.check_for_updates()
        # Entferne das Binding, damit die Prüfung nicht bei jedem Fokus erneut startet.
        self.unbind("<FocusIn>")

    def _is_password_complex_enough(self, password):
        """Prüft die Komplexität eines Passworts und gibt ein Tupel (bool, str) zurück."""
        if len(password) < 12:
            return False, "Das Passwort muss mindestens 12 Zeichen lang sein."
        if not any(char.isdigit() for char in password):
            return False, "Das Passwort muss mindestens eine Ziffer enthalten."
        if not any(char.islower() for char in password):
            return False, "Das Passwort muss mindestens einen Kleinbuchstaben enthalten."
        if not any(char.isupper() for char in password):
            return False, "Das Passwort muss mindestens einen Großbuchstaben enthalten."
        return True, "Passwort ist ausreichend komplex."

    def _handle_exception(self, exc_type, exc_value, exc_traceback):  # Korrigierte Einrückung
        """Global exception handler to catch unhandled errors."""
        if issubclass(exc_type, KeyboardInterrupt):
            # Don't catch KeyboardInterrupt, let it terminate the program normally
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return

        error_message = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        print(f"Ein unerwarteter Fehler ist aufgetreten:\n{error_message}")  # Also print to console

        # Try to show an error message box, but be careful not to crash again
        try:
            # WICHTIG: Sicherstellen, dass das Hauptfenster sichtbar ist, bevor eine Fehlermeldung
            # angezeigt wird, da die Anwendung sonst im Hintergrund "hängen" könnte.
            self.deiconify()
            messagebox.showerror(
                "Unerwarteter Fehler",
                f"Ein unerwarteter Fehler ist aufgetreten. Die Anwendung wird beendet.\n\nDetails:\n{error_message}",
                parent=self,
            )
        except Exception:
            # Fallback if messagebox itself fails
            pass
        # VORÜBERGEHEND DEAKTIVIERT ZUM DEBUGGEN: Verhindert, dass sich die App sofort schließt,
        # damit die Fehlermeldung sichtbar bleibt.
        # finally:
        #     self.quit()
        #     self.destroy()

    def _create_complexity_view(self, parent):
        """Erstellt die UI-Elemente für die visuelle Passwort-Komplexitätsprüfung."""
        frame = customtkinter.CTkFrame(parent, fg_color="transparent")

        # Farben definieren, die im hellen und dunklen Modus funktionieren
        fail_color = ("#DC143C", "#FF6347")  # Crimson, Tomato

        labels = {
            "length": customtkinter.CTkLabel(frame, text="Mindestens 12 Zeichen", text_color=fail_color, anchor="w"),
            "lower": customtkinter.CTkLabel(
                frame, text="Mindestens ein Kleinbuchstabe", text_color=fail_color, anchor="w"
            ),
            "upper": customtkinter.CTkLabel(
                frame, text="Mindestens ein Großbuchstabe", text_color=fail_color, anchor="w"
            ),
            "digit": customtkinter.CTkLabel(frame, text="Mindestens eine Ziffer", text_color=fail_color, anchor="w"),
        }

        labels["length"].pack(fill="x")
        labels["lower"].pack(fill="x")
        labels["upper"].pack(fill="x")
        labels["digit"].pack(fill="x")

        return frame, labels

    def _update_complexity_view(self, entry_widget, requirement_labels):
        """Aktualisiert die visuelle Passwort-Komplexitätsprüfung basierend auf der Eingabe."""
        password = entry_widget.get()
        success_color = ("#2E8B57", "#3CB371")
        fail_color = ("#DC143C", "#FF6347")

        # Länge
        is_long = len(password) >= 12
        requirement_labels["length"].configure(
            text=f"{'✓' if is_long else '✗'} Mindestens 12 Zeichen", text_color=success_color if is_long else fail_color
        )
        # Kleinbuchstaben
        has_lower = any(c.islower() for c in password)
        requirement_labels["lower"].configure(
            text=f"{'✓' if has_lower else '✗'} Mindestens ein Kleinbuchstabe",
            text_color=success_color if has_lower else fail_color,
        )
        # Großbuchstaben
        has_upper = any(c.isupper() for c in password)
        requirement_labels["upper"].configure(
            text=f"{'✓' if has_upper else '✗'} Mindestens ein Großbuchstabe",
            text_color=success_color if has_upper else fail_color,
        )
        # Ziffern
        has_digit = any(c.isdigit() for c in password)
        requirement_labels["digit"].configure(
            text=f"{'✓' if has_digit else '✗'} Mindestens eine Ziffer",
            text_color=success_color if has_digit else fail_color,
        )

    def show_profile_manager_dialog(self):  # Korrigierte Einrückung
        """Öffnet den Dialog zur Profilverwaltung."""
        dialog = customtkinter.CTkToplevel(self)
        dialog.title("Profilverwaltung")
        dialog.geometry("450x450")
        dialog.transient(self)
        dialog.grab_set()

        # Wenn noch kein Master-Passwort gesetzt ist (erster Aufruf)
        if not self.profile_manager.has_master_password_set():
            messagebox.showinfo(
                "Info", "Es ist noch kein Master-Passwort gesetzt. Bitte legen Sie jetzt eines an.", parent=dialog
            )
            # Rufe den Dialog zum Setzen des Passworts auf und übergebe eine Callback-Funktion
            self._show_set_master_password_dialog(dialog, lambda: self._show_profile_list_ui(dialog))
            return

        self._show_profile_list_ui(dialog)

    def _show_profile_list_ui(self, parent_dialog):  # Korrigierte Einrückung
        """Baut die UI zur Anzeige und Verwaltung der Profile auf."""
        # Alle vorherigen Widgets im Elterndialog zerstören, falls vorhanden
        for widget in parent_dialog.winfo_children():
            widget.destroy()

        # Placeholder für die Profilliste (wird nach erfolgreicher Master-Passwort-Eingabe angezeigt)
        frame_profile_list_container = customtkinter.CTkFrame(parent_dialog)
        frame_profile_list_container.pack(padx=20, pady=10, fill="both", expand=True)

        # Scrollbarer Frame für Profile
        scrollable_profiles_frame = customtkinter.CTkScrollableFrame(
            frame_profile_list_container, label_text="Gespeicherte Profile"
        )
        scrollable_profiles_frame.pack(fill="both", expand=True, pady=(0, 10))

        profile_buttons = []  # Speichert Referenzen zu Profil-Buttons
        selected_profile_for_actions = customtkinter.StringVar(
            value=""
        )  # Speichert den Namen des in der Liste ausgewählten Profils

        def _select_profile_for_edit_delete(profile_name):
            # Einfacher Auswahlmechanismus
            for btn in profile_buttons:
                btn.configure(fg_color=customtkinter.ThemeManager.theme["CTkButton"]["fg_color"])  # Farbe zurücksetzen
            # Ausgewählten Button finden und hervorheben
            for btn in profile_buttons:
                if btn.cget("text") == profile_name:
                    btn.configure(fg_color=customtkinter.ThemeManager.theme["CTkButton"]["hover_color"])  # Hervorheben
                    break
            selected_profile_for_actions.set(profile_name)

        def _refresh_profile_display():
            for widget in scrollable_profiles_frame.winfo_children():
                widget.destroy()  # Vorhandene Buttons löschen
            profile_buttons.clear()

            for name in sorted(self.profile_manager.profiles.keys()):
                btn = customtkinter.CTkButton(
                    scrollable_profiles_frame, text=name, command=lambda n=name: _select_profile_for_edit_delete(n)
                )
                btn.pack(fill="x", pady=2, padx=5)
                profile_buttons.append(btn)
            self._update_profile_selection_ui()  # Dropdown im Hauptfenster aktualisieren

        _refresh_profile_display()

        # Aktions-Buttons für Profile
        frame_profile_actions = customtkinter.CTkFrame(frame_profile_list_container, fg_color="transparent")
        frame_profile_actions.pack(fill="x", pady=(0, 10))

        btn_add = customtkinter.CTkButton(
            frame_profile_actions,
            text="Profil hinzufügen",
            command=lambda: self._show_add_edit_profile_dialog(parent_dialog, _refresh_profile_display),
        )
        btn_add.pack(side="left", padx=(0, 5))

        btn_edit = customtkinter.CTkButton(
            frame_profile_actions,
            text="Profil bearbeiten",
            command=lambda: self._edit_selected_profile(
                parent_dialog, selected_profile_for_actions.get(), _refresh_profile_display
            ),
        )
        btn_edit.pack(side="left", padx=(5, 5))

        btn_delete = customtkinter.CTkButton(
            frame_profile_actions,
            text="Profil löschen",
            command=lambda: self._delete_selected_profile(
                parent_dialog, selected_profile_for_actions.get(), _refresh_profile_display
            ),
        )
        btn_delete.pack(side="left", padx=(5, 0))

        btn_change_master_pw = customtkinter.CTkButton(
            frame_profile_list_container,
            text="Master-Passwort ändern",
            command=lambda: self._show_change_master_password_dialog(parent_dialog, _refresh_profile_display),
        )
        btn_change_master_pw.pack(pady=(10, 0))

    def _show_set_master_password_dialog(self, parent_dialog, on_success_callback):  # Korrigierte Einrückung
        set_pw_dialog = customtkinter.CTkToplevel(parent_dialog)
        set_pw_dialog.title("Master-Passwort festlegen")
        set_pw_dialog.geometry("380x380")
        set_pw_dialog.transient(parent_dialog)
        set_pw_dialog.grab_set()

        customtkinter.CTkLabel(set_pw_dialog, text="Neues Master-Passwort:").pack(pady=(5, 0))
        pw1_frame = customtkinter.CTkFrame(set_pw_dialog, fg_color="transparent")
        pw1_frame.pack(pady=(0, 5))
        entry_new_master_pw = customtkinter.CTkEntry(pw1_frame, show="*")
        entry_new_master_pw.pack(side="left")

        show_pw1_checkbox = customtkinter.CTkCheckBox(
            pw1_frame,
            text="Zeigen",
            command=lambda: self._toggle_password_visibility(entry_new_master_pw, show_pw1_checkbox),
        )
        show_pw1_checkbox.pack(side="left", padx=5)

        # NEU: Visuelle Komplexitätsprüfung
        complexity_frame, complexity_labels = self._create_complexity_view(set_pw_dialog)
        complexity_frame.pack(pady=5, padx=20, fill="x")
        entry_new_master_pw.bind(
            "<KeyRelease>", lambda event: self._update_complexity_view(entry_new_master_pw, complexity_labels)
        )

        customtkinter.CTkLabel(set_pw_dialog, text="Master-Passwort wiederholen:").pack(pady=(10, 0))
        pw2_frame = customtkinter.CTkFrame(set_pw_dialog, fg_color="transparent")
        pw2_frame.pack(pady=(0, 10))
        entry_confirm_master_pw = customtkinter.CTkEntry(pw2_frame, show="*")
        entry_confirm_master_pw.pack(side="left")
        show_pw2_checkbox = customtkinter.CTkCheckBox(
            pw2_frame,
            text="Zeigen",
            command=lambda: self._toggle_password_visibility(entry_confirm_master_pw, show_pw2_checkbox),
        )
        show_pw2_checkbox.pack(side="left", padx=5)

        # Initialer Aufruf, um die ✗-Symbole anzuzeigen
        self._update_complexity_view(entry_new_master_pw, complexity_labels)

        def _save_new_master_password():
            new_pw = entry_new_master_pw.get()
            confirm_pw = entry_confirm_master_pw.get()

            if not new_pw or not confirm_pw:
                messagebox.showwarning("Achtung", "Bitte beide Felder ausfüllen.", parent=set_pw_dialog)
                return

            is_complex, msg = self._is_password_complex_enough(new_pw)
            if not is_complex:
                messagebox.showwarning("Passwort zu schwach", msg, parent=set_pw_dialog)
                return

            if new_pw != confirm_pw:
                messagebox.showwarning("Achtung", "Passwörter stimmen nicht überein.", parent=set_pw_dialog)
                return

            # Das neue Master-Passwort sicher für die aktuelle Sitzung speichern
            self.current_master_password_in_session = SecureString(new_pw)
            messagebox.showinfo(
                "Erfolg",
                "Master-Passwort erfolgreich gesetzt. Sie können nun Ihr erstes Profil anlegen.",
                parent=set_pw_dialog,
            )
            set_pw_dialog.destroy()
            on_success_callback()  # Führe die übergebene Funktion aus (z.B. zeige Profilliste)

        btn_save = customtkinter.CTkButton(set_pw_dialog, text="Speichern", command=_save_new_master_password)
        btn_save.pack(pady=(10, 0))

    def _generate_secure_password(self, length=16):
        """Generiert ein sicheres, zufälliges Passwort, das die Komplexitätsanforderungen erfüllt."""
        lower = string.ascii_lowercase
        upper = string.ascii_uppercase
        digits = string.digits
        # Eine Auswahl an Sonderzeichen, die in der Regel unproblematisch sind
        punctuation = "!@#$%^&*()_+-=[]{}|"

        # Stelle sicher, dass wir von jeder Sorte mindestens einen haben
        password_chars = [
            secrets.choice(lower),
            secrets.choice(upper),
            secrets.choice(digits),
            secrets.choice(punctuation),
        ]

        # Fülle den Rest des Passworts mit einer zufälligen Mischung aus allen Zeichen
        all_chars = lower + upper + digits + punctuation
        password_chars += [secrets.choice(all_chars) for _ in range(length - len(password_chars))]

        secrets.SystemRandom().shuffle(password_chars)  # Mische die Zeichen
        return "".join(password_chars)

    def _show_add_edit_profile_dialog(
        self, parent_dialog, refresh_callback, profile_name_to_edit=None
    ):  # Korrigierte Einrückung
        add_edit_dialog = customtkinter.CTkToplevel(parent_dialog)
        add_edit_dialog.title("Profil hinzufügen/bearbeiten")
        add_edit_dialog.geometry("350x480")
        add_edit_dialog.transient(parent_dialog)
        add_edit_dialog.grab_set()

        lbl_name = customtkinter.CTkLabel(add_edit_dialog, text="Profilname:")
        lbl_name.pack(pady=(10, 0))
        entry_name = customtkinter.CTkEntry(add_edit_dialog)
        entry_name.pack(pady=(0, 5))

        lbl_password = customtkinter.CTkLabel(add_edit_dialog, text="Passwort für Dateien:")
        lbl_password.pack(pady=(10, 0))
        pw1_frame = customtkinter.CTkFrame(add_edit_dialog, fg_color="transparent")
        pw1_frame.pack(pady=(0, 5))
        entry_password = customtkinter.CTkEntry(pw1_frame, show="*")
        entry_password.pack(side="left")
        show_pw1_checkbox = customtkinter.CTkCheckBox(
            pw1_frame,
            text="Zeigen",
            command=lambda: self._toggle_password_visibility(entry_password, show_pw1_checkbox),
        )
        show_pw1_checkbox.pack(side="left", padx=5)

        # NEU: Visuelle Komplexitätsprüfung
        complexity_frame, complexity_labels = self._create_complexity_view(add_edit_dialog)
        complexity_frame.pack(pady=5, padx=20, fill="x")
        entry_password.bind(
            "<KeyRelease>", lambda event: self._update_complexity_view(entry_password, complexity_labels)
        )

        lbl_confirm_password = customtkinter.CTkLabel(add_edit_dialog, text="Passwort wiederholen:")
        lbl_confirm_password.pack(pady=(10, 0))
        pw2_frame = customtkinter.CTkFrame(add_edit_dialog, fg_color="transparent")
        pw2_frame.pack(pady=(0, 10))
        entry_confirm_password = customtkinter.CTkEntry(pw2_frame, show="*")
        entry_confirm_password.pack(side="left")
        show_pw2_checkbox = customtkinter.CTkCheckBox(
            pw2_frame,
            text="Zeigen",
            command=lambda: self._toggle_password_visibility(entry_confirm_password, show_pw2_checkbox),
        )
        show_pw2_checkbox.pack(side="left", padx=5)

        # Initialer Aufruf, um die ✗-Symbole anzuzeigen
        self._update_complexity_view(entry_password, complexity_labels)

        def _generate_and_set_password():
            new_password = self._generate_secure_password()
            entry_password.delete(0, "end")
            entry_password.insert(0, new_password)
            entry_confirm_password.delete(0, "end")
            entry_confirm_password.insert(0, new_password)

        btn_generate = customtkinter.CTkButton(
            add_edit_dialog, text="Zufälliges Passwort generieren", command=_generate_and_set_password
        )
        btn_generate.pack(pady=(10, 0))

        if profile_name_to_edit:
            add_edit_dialog.title(f"Profil bearbeiten: {profile_name_to_edit}")
            entry_name.insert(0, profile_name_to_edit)
            entry_name.configure(state="disabled")  # Name kann hier nicht direkt geändert werden
            entry_password.insert(0, self.profile_manager.profiles[profile_name_to_edit])
            entry_confirm_password.insert(0, self.profile_manager.profiles[profile_name_to_edit])

        def _save_profile():
            name = entry_name.get()
            password = entry_password.get()
            confirm_password = entry_confirm_password.get()

            if not name or not password or not confirm_password:
                messagebox.showwarning("Achtung", "Bitte alle Felder ausfüllen.", parent=add_edit_dialog)
                return

            is_complex, msg = self._is_password_complex_enough(password)
            if not is_complex:
                messagebox.showwarning("Passwort zu schwach", msg, parent=add_edit_dialog)
                return

            if password != confirm_password:
                messagebox.showwarning("Achtung", "Passwörter stimmen nicht überein.", parent=add_edit_dialog)
                return

            success = False
            msg = ""
            if profile_name_to_edit:
                success, msg = self.profile_manager.update_profile(profile_name_to_edit, name, password)
            else:
                success, msg = self.profile_manager.add_profile(name, password)

            if success:
                self.profile_manager.save_profiles(self.current_master_password_in_session)  # Änderungen speichern
                messagebox.showinfo("Erfolg", msg, parent=add_edit_dialog)
                refresh_callback()
                add_edit_dialog.destroy()
            else:
                messagebox.showerror("Fehler", msg, parent=add_edit_dialog)

        btn_save = customtkinter.CTkButton(add_edit_dialog, text="Speichern", command=_save_profile)
        btn_save.pack(pady=(10, 0))

    def _edit_selected_profile(self, parent_dialog, profile_name, refresh_callback):  # Korrigierte Einrückung
        if not profile_name:
            messagebox.showwarning("Achtung", "Bitte ein Profil zum Bearbeiten auswählen.", parent=parent_dialog)
            return
        self._show_add_edit_profile_dialog(parent_dialog, refresh_callback, profile_name)

    def _delete_selected_profile(self, parent_dialog, profile_name, refresh_callback):  # Korrigierte Einrückung
        if not profile_name:
            messagebox.showwarning("Achtung", "Bitte ein Profil zum Löschen auswählen.", parent=parent_dialog)
            return

        if messagebox.askyesno(
            "Profil löschen", f"Möchten Sie das Profil '{profile_name}' wirklich löschen?", parent=parent_dialog
        ):
            success, msg = self.profile_manager.delete_profile(profile_name)
            if success:
                self.profile_manager.save_profiles(self.current_master_password_in_session)  # Änderungen speichern
                messagebox.showinfo("Erfolg", msg, parent=parent_dialog)
                refresh_callback()
            else:
                messagebox.showerror("Fehler", msg, parent=parent_dialog)

    def _show_change_master_password_dialog(self, parent_dialog, refresh_callback):  # Korrigierte Einrückung
        change_pw_dialog = customtkinter.CTkToplevel(parent_dialog)
        change_pw_dialog.title("Master-Passwort ändern")
        change_pw_dialog.geometry("380x420")
        change_pw_dialog.transient(parent_dialog)
        change_pw_dialog.grab_set()

        customtkinter.CTkLabel(change_pw_dialog, text="Altes Master-Passwort:").pack(pady=(10, 0))
        old_pw_frame = customtkinter.CTkFrame(change_pw_dialog, fg_color="transparent")
        old_pw_frame.pack(pady=(0, 5))
        entry_old_master_pw = customtkinter.CTkEntry(old_pw_frame, show="*")
        entry_old_master_pw.pack(side="left")
        show_old_pw_checkbox = customtkinter.CTkCheckBox(
            old_pw_frame,
            text="Zeigen",
            command=lambda: self._toggle_password_visibility(entry_old_master_pw, show_old_pw_checkbox),
        )
        show_old_pw_checkbox.pack(side="left", padx=5)

        customtkinter.CTkLabel(change_pw_dialog, text="Neues Master-Passwort:").pack(pady=(10, 0))
        new_pw1_frame = customtkinter.CTkFrame(change_pw_dialog, fg_color="transparent")
        new_pw1_frame.pack(pady=(0, 5))
        entry_new_master_pw = customtkinter.CTkEntry(new_pw1_frame, show="*")
        entry_new_master_pw.pack(side="left")
        show_new_pw1_checkbox = customtkinter.CTkCheckBox(
            new_pw1_frame,
            text="Zeigen",
            command=lambda: self._toggle_password_visibility(entry_new_master_pw, show_new_pw1_checkbox),
        )
        show_new_pw1_checkbox.pack(side="left", padx=5)

        # NEU: Visuelle Komplexitätsprüfung
        complexity_frame, complexity_labels = self._create_complexity_view(change_pw_dialog)
        complexity_frame.pack(pady=5, padx=20, fill="x")
        entry_new_master_pw.bind(
            "<KeyRelease>", lambda event: self._update_complexity_view(entry_new_master_pw, complexity_labels)
        )

        customtkinter.CTkLabel(change_pw_dialog, text="Neues Master-Passwort wiederholen:").pack(pady=(10, 0))
        new_pw2_frame = customtkinter.CTkFrame(change_pw_dialog, fg_color="transparent")
        new_pw2_frame.pack(pady=(0, 10))
        entry_confirm_new_master_pw = customtkinter.CTkEntry(new_pw2_frame, show="*")
        entry_confirm_new_master_pw.pack(side="left")
        show_new_pw2_checkbox = customtkinter.CTkCheckBox(
            new_pw2_frame,
            text="Zeigen",
            command=lambda: self._toggle_password_visibility(entry_confirm_new_master_pw, show_new_pw2_checkbox),
        )
        show_new_pw2_checkbox.pack(side="left", padx=5)

        # Initialer Aufruf, um die ✗-Symbole anzuzeigen
        self._update_complexity_view(entry_new_master_pw, complexity_labels)

        def _generate_and_set_password():
            new_password = self._generate_secure_password()
            entry_new_master_pw.delete(0, "end")
            entry_new_master_pw.insert(0, new_password)
            entry_confirm_new_master_pw.delete(0, "end")
            entry_confirm_new_master_pw.insert(0, new_password)

        btn_generate = customtkinter.CTkButton(
            change_pw_dialog, text="Zufälliges Passwort generieren", command=_generate_and_set_password
        )
        btn_generate.pack(pady=(10, 0))

        def _save_new_master_password():
            old_pw_entered = entry_old_master_pw.get()
            new_pw = entry_new_master_pw.get()
            confirm_new_pw = entry_confirm_new_master_pw.get()

            if not old_pw_entered or not new_pw or not confirm_new_pw:
                messagebox.showwarning("Achtung", "Bitte alle Felder ausfüllen.", parent=change_pw_dialog)
                return

            is_complex, msg = self._is_password_complex_enough(new_pw)
            if not is_complex:
                messagebox.showwarning("Passwort zu schwach", msg, parent=change_pw_dialog)
                return

            if new_pw != confirm_new_pw:
                messagebox.showwarning("Achtung", "Neue Passwörter stimmen nicht überein.", parent=change_pw_dialog)
                return

            success, msg = self.profile_manager.change_master_password(old_pw_entered, new_pw)
            if success:
                messagebox.showinfo("Erfolg", "Master-Passwort erfolgreich geändert.", parent=change_pw_dialog)
                # Master-Passwort in der Session sicher aktualisieren
                self.current_master_password_in_session = SecureString(new_pw)
                refresh_callback()
                change_pw_dialog.destroy()
            else:
                messagebox.showerror("Fehler", msg, parent=change_pw_dialog)

        btn_save = customtkinter.CTkButton(change_pw_dialog, text="Speichern", command=_save_new_master_password)
        btn_save.pack(pady=(10, 0))

    def show_license_info(self):  # Korrigierte Einrückung
        """Öffnet ein Fenster zur Anzeige der Lizenzinformationen. Fängt Fehler selbst ab."""
        try:
            # Bestimmt den Pfad zur Lizenzdatei, relativ zum Skript
            # sys.argv[0] ist zuverlässiger, wenn die App als .exe verpackt ist
            base_path = os.path.dirname(sys.argv[0])
            license_path = os.path.join(base_path, "LICENSE.txt")

            with open(license_path, encoding="utf-8") as f:
                license_text = f.read()

            # Erstelle ein neues Toplevel-Fenster
            dialog = customtkinter.CTkToplevel(self)
            dialog.title("Lizenz und Nutzungsbedingungen")
            dialog.geometry("600x450")
            dialog.transient(self)
            dialog.grab_set()

            # Textbox für den Lizenztext
            textbox = customtkinter.CTkTextbox(dialog, wrap="word")
            textbox.pack(expand=True, fill="both", padx=15, pady=15)
            textbox.insert("1.0", license_text)
            textbox.configure(state="disabled")  # Nur-Lese-Modus

            # Schließen-Button
            btn_close = customtkinter.CTkButton(dialog, text="Schließen", command=dialog.destroy)
            btn_close.pack(pady=(0, 15))
        except FileNotFoundError:
            messagebox.showerror("Fehler", "Die Lizenzdatei 'LICENSE.txt' wurde nicht gefunden.", parent=self)
        except Exception as e:
            messagebox.showerror("Fehler", f"Ein unerwarteter Fehler ist aufgetreten:\n{e}", parent=self)

    def check_for_updates(self):  # Korrigierte Einrückung
        """Startet die Update-Prüfung in einem separaten Thread."""
        # Die print-Anweisung für das Debugging wurde entfernt.
        # Der try-except-Block ist hier nicht notwendig, da die Thread-Erstellung selbst selten fehlschlägt.
        update_thread = threading.Thread(target=self._perform_update_check, daemon=True)
        update_thread.start()

    def _perform_update_check(self):  # Korrigierte Einrückung
        """Führt die eigentliche Update-Prüfung durch."""
        # Diese Funktion läuft in einem separaten Thread.
        # Es ist entscheidend, dass alle Ausnahmen hier abgefangen werden,
        # damit ein Fehler (z.B. keine Internetverbindung) nicht die gesamte Anwendung beendet.
        try:
            # Lese die neueste Version von der URL
            latest_version_str = None
            expected_hash = None
            with urllib.request.urlopen(VERSION_CHECK_URL, timeout=5) as response:  # nosec B310
                # decode('utf-8-sig') entfernt BOM, falls vorhanden (wichtig bei Windows-Editoren)
                version_data = response.read().decode("utf-8-sig").strip()

            # Parse die Antwort. Wir unterstützen jetzt '+' für Abwärtskompatibilität.
            # Format: "version+hash" (neu) oder "version;hash" (altes Konzept)
            if "+" in version_data:
                parts = version_data.split("+", 1)
                latest_version_str = parts[0].strip()
                if len(parts) > 1:
                    expected_hash = parts[1].strip()
            elif ";" in version_data:
                parts = version_data.split(";", 1)
                latest_version_str = parts[0].strip()
                if len(parts) > 1:
                    expected_hash = parts[1].strip()
            else:
                # Fallback, falls nur die Version vorhanden ist (alte Methode)
                latest_version_str = version_data.strip()

            # Vergleiche die Versionen mit dem 'packaging'-Modul
            if latest_version_str and parse_version(latest_version_str) > parse_version(VERSION_INFO):
                # Stelle sicher, dass GUI-Änderungen im Hauptthread ausgeführt werden
                self.after(0, self.show_update_notification, latest_version_str, expected_hash)

        except Exception as e:
            # Fehler bei der Update-Prüfung werden bewusst ignoriert, um die App nicht zu stören.
            # Der Fehler wird nur in der Konsole für Debugging-Zwecke ausgegeben, falls eine läuft.
            print(f"Info: Update-Prüfung im Hintergrund fehlgeschlagen (dies ist oft normal): {e}")

    def show_update_notification(self, new_version, expected_hash):  # Korrigierte Einrückung
        """Zeigt ein modales Fenster mit der Update-Info."""
        dialog = customtkinter.CTkToplevel(self)
        dialog.title("Update verfügbar")
        dialog.geometry("350x180")  # Etwas mehr Platz für die Statuszeile
        dialog.transient(self)  # Hält das Fenster im Vordergrund
        dialog.grab_set()  # Modal machen

        lbl_info = customtkinter.CTkLabel(
            dialog,
            text=f"Eine neue Version ({new_version}) ist verfügbar!\nIhre aktuelle Version ist {VERSION_INFO}.",
            font=customtkinter.CTkFont(size=14),
        )
        lbl_info.pack(pady=(20, 10), padx=20)

        # Frame für den Download-Button und die Fortschrittsanzeige
        frame_download = customtkinter.CTkFrame(dialog, fg_color="transparent")
        frame_download.pack(fill="x", padx=20, pady=10)

        btn_update = customtkinter.CTkButton(
            frame_download,
            text="Jetzt herunterladen",
            command=lambda: self.start_download(dialog, progress_bar, lbl_status, btn_update, expected_hash),
        )
        btn_update.pack()

        lbl_status = customtkinter.CTkLabel(frame_download, text="")
        lbl_status.pack(pady=(5, 0))

        progress_bar = customtkinter.CTkProgressBar(frame_download)
        progress_bar.set(0)
        # Wird erst bei Bedarf sichtbar gemacht

    def start_download(self, dialog, progress_bar, status_label, button, expected_hash):  # Korrigierte Einrückung
        """Startet den Download-Prozess in einem separaten Thread."""
        button.configure(state="disabled")  # Button deaktivieren
        progress_bar.pack(fill="x", pady=(5, 0))  # Fortschrittsanzeige einblenden
        status_label.configure(text="Download wird gestartet...")

        download_thread = threading.Thread(
            target=self._download_update_file, args=(dialog, progress_bar, status_label, expected_hash), daemon=True
        )
        download_thread.start()

    def _download_update_file(self, dialog, progress_bar, status_label, expected_hash):  # Korrigierte Einrückung
        """Lädt die Update-Datei herunter und aktualisiert die GUI."""
        try:
            with urllib.request.urlopen(UPDATE_URL, timeout=10) as response:  # nosec B310
                # Dateinamen aus dem 'Content-Disposition'-Header extrahieren
                content_disposition = response.getheader("Content-Disposition")
                suggested_filename = "DateiTresor_Update.exe"  # Fallback-Name
                if content_disposition:
                    parts = content_disposition.split(";")
                    for part in parts:
                        if part.strip().startswith("filename="):
                            suggested_filename = part.split("=")[1].strip('"')
                            break

                # Dialog "Speichern unter" erst jetzt anzeigen, mit dem korrekten Dateinamen
                destination_path = filedialog.asksaveasfilename(
                    parent=dialog,  # Stellt sicher, dass der Dialog über dem Update-Fenster liegt
                    title="Update speichern unter...",
                    initialfile=suggested_filename,
                    defaultextension=".exe",
                    filetypes=[("Executable files", "*.exe"), ("All files", "*.*")],
                )

                # Wenn der Benutzer den Dialog abbricht, den Thread beenden
                if not destination_path:
                    self.after(0, dialog.destroy)  # Schließt das Update-Fenster
                    return

                total_size = int(response.getheader("Content-Length", 0))
                chunk_size = 8192
                bytes_read = 0

                with open(destination_path, "wb") as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        bytes_read += len(chunk)

                        # Fortschritt aktualisieren
                        progress = bytes_read / total_size if total_size > 0 else 0
                        # MB-Anzeige nur bei bekannter Gesamtgröße
                        size_text = f"{(bytes_read / 1024**2):.1f} MB"
                        if total_size > 0:
                            size_text += f" / {(total_size / 1024**2):.1f} MB"

                        self.after(0, lambda p=progress: progress_bar.set(p))
                        self.after(0, lambda t=size_text: status_label.configure(text=t))

            # --- START: HASH-VERIFIZIERUNG ---
            if expected_hash:
                self.after(0, lambda: status_label.configure(text="Überprüfe Datei-Integrität..."))

                hasher = hashlib.sha256()
                with open(destination_path, "rb") as f:
                    for block in iter(lambda: f.read(4096), b""):
                        hasher.update(block)

                downloaded_file_hash = hasher.hexdigest()

                if downloaded_file_hash != expected_hash:
                    # Hashes stimmen nicht überein! Datei löschen und Fehler anzeigen.
                    os.remove(destination_path)
                    error_message = "Sicherheitswarnung: Die Integrität der heruntergeladenen Datei konnte nicht verifiziert werden. Der Hash stimmt nicht überein. Die Datei wurde gelöscht."
                    self.after(0, lambda: messagebox.showerror("Fehler", error_message, parent=dialog))
                    self.after(0, dialog.destroy)
                    return
            # --- ENDE: HASH-VERIFIZIERUNG ---

            # Erfolgsmeldung im Hauptthread anzeigen
            self.after(0, lambda: self._show_download_complete(dialog, destination_path))

        except Exception as e:
            error_message = f"Download fehlgeschlagen:\n\n{e}"
            self.after(0, lambda: messagebox.showerror("Fehler", error_message, parent=dialog))
            # GUI im Dialog zurücksetzen, falls er noch offen ist
            try:
                self.after(0, lambda: status_label.configure(text="Fehler!", text_color="red"))
                self.after(0, lambda: progress_bar.pack_forget())
            except Exception:
                pass  # Dialog könnte schon geschlossen sein

    def _show_download_complete(self, dialog, path):  # Korrigierte Einrückung
        """Zeigt eine Erfolgsmeldung nach dem Download an."""
        dialog.destroy()  # Update-Dialog schließen

        msg_box = messagebox.askyesno(
            "Download abgeschlossen",
            f"Die neue Version wurde erfolgreich heruntergeladen nach:\n{path}\n\nMöchten Sie den Ordner jetzt öffnen?",
            icon="info",
        )
        if msg_box:
            # Öffnet den Ordner und markiert die Datei (funktioniert am besten unter Windows)
            try:
                if os.name == "nt":  # Windows
                    os.startfile(os.path.dirname(path))  # nosec B606
                elif os.uname().sysname == "Darwin":  # macOS
                    subprocess.run(["open", "-R", str(path)], check=False)
                else:  # Linux
                    subprocess.run(["xdg-open", str(os.path.dirname(path))], check=False)
            except Exception as e:
                messagebox.showwarning("Fehler", f"Konnte den Ordner nicht öffnen:\n{e}")


if __name__ == "__main__":
    app = App()
    app.mainloop()
