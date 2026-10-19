import base64
import io
import os
import pathlib
import secrets
import tempfile
import zipfile
from datetime import datetime

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from dateicrypt import (
    COMPANY_NAME,
    KeyCache,
    ProfileManager,
    _handle_decrypted_data,
    get_key_from_password,
    process_file,
    process_file_stream,
    process_folder,
)


def test_get_key_from_password_deterministic():
    """Prüft, dass get_key_from_password bei identischem Passwort und Salt denselben Schlüssel erzeugt."""
    salt = b"0123456789abcdef"
    key1, salt1 = get_key_from_password("geheimes_passwort", salt=salt)
    key2, salt2 = get_key_from_password("geheimes_passwort", salt=salt)

    assert key1 == key2
    assert salt1 == salt2 == salt
    assert len(key1) == 32


def test_get_key_from_password_new_salt():
    """Prüft, dass ohne übergebenen Salt ein neuer 16-Byte-Salt generiert wird."""
    key1, salt1 = get_key_from_password("test_passwort")
    key2, salt2 = get_key_from_password("test_passwort")

    assert len(salt1) == 16
    assert len(salt2) == 16
    assert salt1 != salt2
    assert key1 != key2


def test_key_cache_hit_and_miss():
    """Prüft Cache-Miss und Cache-Hit Verhalten der KeyCache-Klasse."""
    cache = KeyCache()
    salt = b"test_salt_123456"

    # Erster Aufruf: Cache-Miss
    key1, s1 = cache.get_key("mein_passwort", salt)
    assert s1 == salt

    # Zweiter Aufruf: Cache-Hit
    key2, s2 = cache.get_key("mein_passwort", salt)
    assert key1 == key2
    assert s2 == salt

    # Anderes Passwort: Cache-Miss
    key3, _ = cache.get_key("anderes_passwort", salt)
    assert key3 != key1


def test_profile_manager_lifecycle():
    """Testet den vollständigen Lebenszyklus von Profilen: Erstellen, Speichern, Laden und Ändern."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = ProfileManager()
        profile_file = pathlib.Path(tmpdir) / "test_profiles.dat"
        manager.profile_file_path = str(profile_file)

        assert not manager.has_master_password_set()

        # Profil hinzufügen
        ok, _ = manager.add_profile("Arbeit", "arbeits_pw_123")
        assert ok
        # Duplikat verhindern
        ok_dup, _ = manager.add_profile("Arbeit", "anderes_pw")
        assert not ok_dup

        # Profile speichern mit Master-Passwort
        ok_save, _ = manager.save_profiles("master123")
        assert ok_save
        assert profile_file.exists()
        assert manager.has_master_password_set()

        # Neuer Manager zum Testen des Ladens
        loader = ProfileManager()
        loader.profile_file_path = str(profile_file)

        # Falsches Master-Passwort
        ok_wrong, _ = loader.load_profiles("falsches_master_pw")
        assert not ok_wrong
        assert loader.profiles == {}

        # Richtiges Master-Passwort
        ok_right, _ = loader.load_profiles("master123")
        assert ok_right
        assert loader.profiles.get("Arbeit") == "arbeits_pw_123"

        # Profil aktualisieren
        ok_upd, _ = loader.update_profile("Arbeit", "Arbeit", "neues_arbeits_pw")
        assert ok_upd
        assert loader.profiles["Arbeit"] == "neues_arbeits_pw"
        loader.save_profiles("master123")

        # Master-Passwort ändern
        ok_change, _ = loader.change_master_password("master123", "neues_master_456")
        assert ok_change

        # Mit neuem Master-Passwort laden
        verifier = ProfileManager()
        verifier.profile_file_path = str(profile_file)
        ok_verify, _ = verifier.load_profiles("neues_master_456")
        assert ok_verify
        assert verifier.profiles.get("Arbeit") == "neues_arbeits_pw"

        # Profil löschen
        ok_del, _ = verifier.delete_profile("Arbeit")
        assert ok_del
        assert "Arbeit" not in verifier.profiles

        # Wenn alle Profile gelöscht sind, wird Profildatei beim Speichern entfernt
        verifier.save_profiles("neues_master_456")
        assert not profile_file.exists()


def test_process_file_stream_roundtrip():
    """Testet Ver- und Entschlüsselung einer Datei mit AES-GCM (Streaming)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_file = pathlib.Path(tmpdir) / "daten.txt"
        test_payload = b"Sehr geheime Daten fuer den Tresor!" * 500
        original_file.write_bytes(test_payload)

        progress_values = []

        def track_progress(val):
            progress_values.append(val)

        # 1. Verschlüsseln
        ok_enc, msg_enc = process_file_stream(
            "encrypt",
            str(original_file),
            "super_sicheres_passwort_123",
            track_progress,
        )
        assert ok_enc
        crypted_file = pathlib.Path(str(original_file) + ".crypted")
        assert crypted_file.exists()
        assert len(progress_values) > 0

        # Originaldatei umbenennen/löschen vor Entschlüsselung
        original_file.unlink()

        # 2. Entschlüsseln
        progress_values.clear()
        ok_dec, msg_dec = process_file_stream(
            "decrypt",
            str(crypted_file),
            "super_sicheres_passwort_123",
            track_progress,
        )
        assert ok_dec
        assert original_file.exists()
        assert original_file.read_bytes() == test_payload


def test_process_file_stream_wrong_password():
    """Testet, dass Entschlüsselung mit falschem Passwort fehlschlägt."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_file = pathlib.Path(tmpdir) / "dokument.pdf"
        original_file.write_bytes(b"%PDF-1.4 Mock Inhalt")

        def dummy_progress(v):
            pass

        ok_enc, _ = process_file_stream("encrypt", str(original_file), "passwort_A", dummy_progress)
        assert ok_enc
        crypted_file = pathlib.Path(str(original_file) + ".crypted")

        # Entschlüsseln mit falschem Passwort
        ok_dec, msg_dec = process_file_stream("decrypt", str(crypted_file), "passwort_B", dummy_progress)
        assert not ok_dec
        assert "Passwort" in msg_dec or "Fehler" in msg_dec


def test_process_file_stream_tampered_file():
    """Testet, dass manipulierte verschlüsselte Daten erkannt und abgewiesen werden (AES-GCM Auth Tag)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_file = pathlib.Path(tmpdir) / "vertrag.docx"
        original_file.write_bytes(b"Vertragsinhalt unverfaelscht")

        def dummy_progress(v):
            pass

        ok_enc, _ = process_file_stream("encrypt", str(original_file), "geheim", dummy_progress)
        assert ok_enc
        crypted_file = pathlib.Path(str(original_file) + ".crypted")

        # Datei manipulieren (Bit-Flip in der Chiffre)
        content = bytearray(crypted_file.read_bytes())
        # Chiffredaten liegen nach Salt (16) und Nonce (12)
        content[20] ^= 0xFF
        crypted_file.write_bytes(content)

        ok_dec, msg_dec = process_file_stream("decrypt", str(crypted_file), "geheim", dummy_progress)
        assert not ok_dec


def test_process_folder():
    """Testet das Packen eines Ordners zu einem temporären Archiv."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_dir = pathlib.Path(tmpdir) / "mein_ordner"
        test_dir.mkdir()
        (test_dir / "datei1.txt").write_text("Hallo", encoding="utf-8")
        (test_dir / "datei2.txt").write_text("Welt", encoding="utf-8")

        ok, archive_path = process_folder("encrypt", str(test_dir), "passwort")
        assert ok
        assert os.path.exists(archive_path)
        assert archive_path.endswith(".zip")
        if os.path.exists(archive_path):
            os.remove(archive_path)


def test_zip_slip_protection():
    """Prüft, dass Archive mit ungültigen Pfadsequenzen (Zip-Slip) abgewehrt werden."""
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("../evil.txt", "böser inhalt")

        zip_buffer.seek(0)
        crypted_target = str(pathlib.Path(tmpdir) / "archiv.zip.crypted")

        with pytest.raises(ValueError, match="Sicherheitsrisiko"):
            _handle_decrypted_data(zip_buffer, crypted_target)


def test_company_name_contains_current_year():
    """Prüft, dass der Firmenname dynamisch das aktuelle Jahr beinhaltet."""
    current_year = str(datetime.now().year)
    assert current_year in COMPANY_NAME
    assert COMPANY_NAME.startswith("© Agentur Schölzke")


def test_process_file_stream_legacy_fernet_fallback():
    """Prüft, dass alte mit Fernet verschlüsselte Dateien erfolgreich per Fallback entschlüsselt werden."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_payload = b"Alte Fernet verschluesselte Daten!"
        salt = secrets.token_bytes(16)
        password = "altes_geheimes_passwort"

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key_bytes = kdf.derive(password.encode("utf-8"))
        fernet = Fernet(base64.urlsafe_b64encode(key_bytes))
        encrypted_token = fernet.encrypt(test_payload)

        legacy_file = pathlib.Path(tmpdir) / "altes_dokument.txt.crypted"
        legacy_file.write_bytes(salt + encrypted_token)

        def dummy_progress(v):
            pass

        ok_dec, msg_dec = process_file_stream("decrypt", str(legacy_file), password, dummy_progress)
        assert ok_dec
        restored_file = pathlib.Path(tmpdir) / "altes_dokument.txt"
        assert restored_file.exists()
        assert restored_file.read_bytes() == test_payload


def test_process_file_stream_destination_collision():
    """Prüft, dass bei bereits existierender Zieldatei mit _decrypted-Suffix kollisionsfrei gespeichert wird."""
    with tempfile.TemporaryDirectory() as tmpdir:
        original_file = pathlib.Path(tmpdir) / "notizen.txt"
        secret_content = b"Geheimer Originalinhalt"
        original_file.write_bytes(secret_content)

        def dummy_progress(v):
            pass

        ok_enc, _ = process_file_stream("encrypt", str(original_file), "kollisions_passwort", dummy_progress)
        assert ok_enc

        # Zieldatei existiert bereits mit anderem Inhalt
        original_file.write_bytes(b"Bestehende andere Datei")
        crypted_file = pathlib.Path(str(original_file) + ".crypted")

        ok_dec, _ = process_file_stream("decrypt", str(crypted_file), "kollisions_passwort", dummy_progress)
        assert ok_dec

        collision_file = pathlib.Path(tmpdir) / "notizen_decrypted.txt"
        assert collision_file.exists()
        assert collision_file.read_bytes() == secret_content
        assert original_file.read_bytes() == b"Bestehende andere Datei"


def test_process_file_stream_invalid_extension():
    """Prüft, dass Dateien ohne .crypted-Endung bei der Entschlüsselung abgelehnt werden."""

    def dummy_progress(v):
        pass

    ok, msg = process_file_stream("decrypt", "datei.txt", "passwort", dummy_progress)
    assert not ok
    assert ".crypted" in msg


def test_process_file_stream_truncated_file():
    """Prüft, dass korrupte/abgeschnittene Dateien (< 44 Bytes Header) sicher abgewiesen werden."""
    with tempfile.TemporaryDirectory() as tmpdir:
        truncated_file = pathlib.Path(tmpdir) / "defekt.txt.crypted"
        truncated_file.write_bytes(b"zu_kurz")

        def dummy_progress(v):
            pass

        ok, msg = process_file_stream("decrypt", str(truncated_file), "passwort", dummy_progress)
        assert not ok


def test_process_file_obsolete_and_invalid():
    """Prüft die Fehlerbehandlung in der alten process_file-Funktion."""
    ok_enc, msg_enc = process_file("encrypt", "irgendwas.txt", "passwort")
    assert not ok_enc
    assert "Veralteter Codepfad" in msg_enc

    ok_dec, msg_dec = process_file("decrypt", "nicht_crypted.txt", "passwort")
    assert not ok_dec
    assert ".crypted" in msg_dec


def test_process_folder_invalid_mode():
    """Prüft, dass process_folder mit invalidem Modus sauber abbricht."""
    ok, msg = process_folder("decrypt", "ordner_pfad", "passwort")
    assert not ok
    assert "Interne Logik fehlerhaft" in msg
