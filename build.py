import ast
import hashlib
import logging
import os
import platform
import secrets
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from setuptools import Extension, setup

# Konfiguration
SOURCE_DIR = "."  # Stammverzeichnis des Python-Codes
MAIN_SCRIPT = "dateicrypt.py"  # Hauptskript, das als Startpunkt für die Anwendung dient
APP_NAME = "DateiTresor"  # Name der ausführbaren Datei

# NEU: Dynamische Verzeichnisnamen mit Zeitstempel
TIMESTAMP = datetime.now().strftime("%Y%m%d-%H%M%S")
BUILD_TEMP = f"build_temp_{TIMESTAMP}"
DIST_DIR = f"dist_{TIMESTAMP}"
# NEU: Verzeichnis für den bereinigten Quellcode
STRIPPED_SOURCE_DIR = os.path.join(BUILD_TEMP, "stripped_src")

# Logging konfigurieren
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# Funktion zum Extrahieren der Version aus der Hauptdatei
def get_version_from_script(script_path):
    """Liest die VERSION_INFO aus der angegebenen Python-Datei."""
    logging.info(f"Lese Versionsnummer aus '{script_path}'...")
    with open(script_path, encoding="utf-8") as f:
        for line in f:
            if line.strip().startswith("VERSION_INFO"):
                # Wert nach dem Gleichheitszeichen holen
                value = line.split("=", 1)[1].strip()
                # Kommentare entfernen (alles ab #)
                if "#" in value:
                    value = value.split("#", 1)[0].strip()
                # Anführungszeichen entfernen
                version = value.strip("\"'")
                logging.info(f"Version gefunden: {version}")
                return version
    raise ValueError("VERSION_INFO konnte in der Hauptdatei nicht gefunden werden.")


# Funktion zum Finden aller Python-Dateien der eigentlichen Anwendung
def find_all_python_files(directory):
    python_files = []
    excluded_dir_names = {
        "venv",
        ".venv",
        "env",
        "tests",
        "test",
        "build",
        "__pycache__",
        "server",
    }
    excluded_file_names = {
        "build.py",
        "sichern.py",
        "audit.py",
    }
    for root, dirs, files in os.walk(directory):
        # Ignoriere versteckte Ordner (.git, .pre-commit-cache, etc.), temporäre Ordner und Versionen
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".")
            and not d.startswith("build_temp_")
            and not d.startswith("dist_")
            and not d.startswith("1.")
            and d.lower() not in excluded_dir_names
        ]
        for file in files:
            if file.endswith(".py") and not file.startswith("test_") and file not in excluded_file_names:
                python_files.append(os.path.join(root, file))
    return python_files


# Cython-Erweiterungen erstellen
def create_cython_extensions(python_files):
    extensions = []
    for py_file in python_files:
        # Normalisiere den Pfad, um führende './' oder '.\' zu entfernen
        normalized_path = os.path.normpath(py_file)
        if normalized_path.startswith("." + os.sep):
            normalized_path = normalized_path[2:]
        module_name = os.path.splitext(normalized_path)[0].replace(os.sep, ".")
        extensions.append(Extension(module_name, [py_file]))
    return extensions


# Funktion zum Beenden eines laufenden Prozesses (Windows-spezifisch)
def kill_process_if_running(process_name):
    """Versucht, einen Prozess anhand seines Namens zu beenden (plattformunabhängig)."""
    system = platform.system()
    if system == "Windows":
        # Windows verwendet .exe und taskkill
        process_name_os = f"{process_name}.exe"
        command = ["taskkill", "/F", "/IM", process_name_os]
    elif system == "Linux" or system == "Darwin":  # Darwin ist macOS
        # Linux/macOS haben keine .exe-Endung
        process_name_os = process_name
        command = ["pkill", "-f", process_name_os]
    else:
        logging.warning(f"Unbekanntes Betriebssystem '{system}'. Überspringe das Beenden des Prozesses.")
        return

    logging.info(f"Prüfe, ob '{process_name_os}' noch läuft und beende es bei Bedarf...")
    try:
        # Die Ausgabe wird umgeleitet, um die Konsole nicht mit Meldungen zu füllen.
        subprocess.run(command, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.info(f"Befehl zum Beenden von '{process_name_os}' ausgeführt. Warte kurz...")
        time.sleep(2)
    except FileNotFoundError:
        logging.warning(f"Befehl '{command[0]}' nicht gefunden. Kann Prozess nicht automatisch beenden.")
    except Exception as e:
        logging.error(f"Fehler beim Versuch, den Prozess zu beenden: {e}")


# Temporäres Verzeichnis erstellen
def create_build_directories():
    os.makedirs(BUILD_TEMP, exist_ok=True)
    os.makedirs(DIST_DIR, exist_ok=True)


# NEU: Funktion zum Entfernen von Kommentaren und Docstrings
def strip_comments_and_docstrings(source_path, target_path):
    """Liest eine Python-Datei, entfernt Kommentare und Docstrings und schreibt das Ergebnis in eine Zieldatei."""
    try:
        with open(source_path, encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=source_path)

        for node in ast.walk(tree):
            if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                if (
                    node.body
                    and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)
                ):
                    if len(node.body) == 1 and not isinstance(node, ast.Module):
                        node.body[0] = ast.Pass()
                    else:
                        node.body.pop(0)

        cleaned_code = ast.unparse(tree)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(cleaned_code)
    except Exception as e:
        logging.warning(f"Konnte Kommentare nicht aus '{source_path}' entfernen: {e}. Kopiere Datei unverändert.")
        shutil.copy2(source_path, target_path)


# NEU: Funktion zum sicheren Löschen von Dateien
def secure_delete_file(path, passes=3):
    """Überschreibt eine Datei mehrmals mit zufälligen Daten, bevor sie gelöscht wird."""
    try:
        with open(path, "r+b") as f:
            length = f.tell()
            f.seek(0)  # Gehe zum Anfang der Datei
            length = f.seek(0, 2)  # Finde die Dateigröße heraus
            f.seek(0)  # Zurück zum Anfang
            for _ in range(passes):
                # Schreibe zufällige Bytes
                f.write(secrets.token_bytes(length))
                f.flush()
                os.fsync(f.fileno())
                f.seek(0)
    except Exception as e:
        logging.warning(f"Fehler beim sicheren Überschreiben von {path}: {e}. Die Datei wird normal gelöscht.")
    finally:
        os.remove(path)


# NEU: Funktion zum sicheren Löschen von Verzeichnissen
def secure_rmtree(path):
    """Löscht ein Verzeichnis und alle darin enthaltenen Dateien sicher."""
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            secure_delete_file(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir(path)


# Alte Build-Dateien entfernen
def cleanup_build_files():
    """Entfernt alle alten Build-Verzeichnisse und temporären Dateien."""
    logging.info("Suche nach alten Build-Verzeichnissen (build, build_temp_*, dist_*)...")
    # Lösche alle alten build_temp_* und dist_* Ordner
    for item in os.listdir(SOURCE_DIR):
        if os.path.isdir(item) and (item.startswith("build_temp_") or item.startswith("dist_")):
            try:
                secure_rmtree(item)
                logging.info(f"Altes Verzeichnis entfernt: {item}")
            except Exception as e:
                logging.error(f"Fehler beim Entfernen von {item}: {e}")

    # Lösche den Standard 'build'-Ordner von setuptools
    if os.path.exists("build"):
        try:
            secure_rmtree("build")
            logging.info("Verzeichnis 'build' entfernt.")
        except Exception as e:
            logging.error(f"Fehler beim Entfernen von 'build': {e}")


# PyInstaller-Befehl erstellen
def create_pyinstaller_command(main_script, app_name):
    command = [
        "pyinstaller",
        "--onefile",
        "--name",
        app_name,
        "--windowed",  # Erstellt eine fensterbasierte Anwendung (ohne Konsole)
        "--clean",
        "--log-level",
        "INFO",
        main_script,
        "--distpath",
        DIST_DIR,
        "--workpath",
        BUILD_TEMP,
    ]

    # Icon ist eine Windows-spezifische Option
    if platform.system() == "Windows" and os.path.exists("favicon.ico"):
        command.extend(["--add-data", "favicon.ico;.", "--icon", "favicon.ico"])

    return command


# Funktion zum Aufräumen nach dem Build
def final_cleanup():
    """Räumt nach dem erfolgreichen Build die temporären Dateien auf."""
    logging.info("Starte finales Aufräumen...")
    # Lösche den temporären Build-Ordner dieses Laufs
    if os.path.exists(BUILD_TEMP):
        secure_rmtree(BUILD_TEMP)
        logging.info(f"Temporäres Verzeichnis '{BUILD_TEMP}' entfernt.")

    # Lösche den Standard 'build'-Ordner von setuptools
    if os.path.exists("build"):
        try:
            secure_rmtree("build")
            logging.info("Verzeichnis 'build' entfernt.")
        except Exception as e:
            logging.error(f"Fehler beim Entfernen von 'build': {e}")

    # Lösche die .spec-Datei
    spec_file = f"{APP_NAME}.spec"
    if os.path.exists(spec_file):
        secure_delete_file(spec_file)
        logging.info(f"Spezifikationsdatei '{spec_file}' entfernt.")

    # NEU: Räume von Cython generierte .c und .pyd Dateien im Quellverzeichnis auf
    logging.info("Suche nach von Cython generierten Dateien (.c, .pyd) zum Entfernen...")
    deleted_cython_files_count = 0
    for root, dirs, files in os.walk(SOURCE_DIR):
        # Verhindere das Betreten von Dot-Directories, Build-Ordnern und virtuellen Umgebungen
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".")
            and not d.startswith("build_temp_")
            and not d.startswith("dist_")
            and not d.startswith("1.")
            and d not in {"venv", ".venv", "build", "__pycache__", "tests"}
        ]
        # Bestimme die plattformspezifische Dateiendung für kompilierte Module
        compiled_ext = ".pyd" if platform.system() == "Windows" else ".so"
        for file in files:
            if file.endswith((".c", compiled_ext)):
                file_path = os.path.join(root, file)
                secure_delete_file(file_path)
                deleted_cython_files_count += 1
                logging.debug(f"Entfernt: {file_path}")
    if deleted_cython_files_count > 0:
        logging.info(f"Insgesamt {deleted_cython_files_count} von Cython generierte Datei(en) entfernt.")


# Funktion zum Erstellen der Hash-Datei
def generate_hash_file(executable_path, version_info):
    """Berechnet den SHA-256-Hash der ausführbaren Datei und speichert ihn zusammen mit der Version."""
    logging.info(f"Berechne SHA-256 Hash für '{executable_path}'...")
    try:
        hasher = hashlib.sha256()
        with open(executable_path, "rb") as f:
            # Lese die Datei in Blöcken, um den Speicher zu schonen
            for block in iter(lambda: f.read(4096), b""):
                hasher.update(block)

        file_hash = hasher.hexdigest()
        logging.info(f"SHA-256 Hash: {file_hash}")

        # Schreibe Version und Hash in die version.txt im DIST_DIR
        version_file_path = os.path.join(os.path.dirname(executable_path), "version.txt")
        with open(version_file_path, "w", encoding="utf-8") as f:
            # WICHTIG: Wir nutzen '+' statt ';'. Das ist PEP-440 konform.
            # Alte Versionen erkennen dies als "v1.4.0 mit Zusatz" und stürzen nicht ab.
            f.write(f"{version_info}+{file_hash}")
        logging.info(f"Datei 'version.txt' erfolgreich in '{version_file_path}' erstellt.")
    except Exception as e:
        raise Exception(f"Fehler beim Erstellen der Hash-Datei: {e}") from e


# Funktion zum Ausführen des Vulnerability Scans
def run_vulnerability_scan():
    """Führt einen Vulnerability Scan mit pip-audit aus und bricht den Build bei Fund ab."""
    logging.info("Starte Vulnerability Scan mit pip-audit...")
    try:
        # Führe pip-audit aus. check=True sorgt dafür, dass bei einem non-zero return code
        # (also bei gefundenen Lücken) eine CalledProcessError ausgelöst wird.
        subprocess.run(
            ["pip-audit"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",  # Stellt korrekte Dekodierung der Ausgabe sicher
            timeout=30,  # Timeout nach 30 Sekunden, damit der Build nicht hängt
        )
        logging.info("Vulnerability Scan erfolgreich: Keine bekannten Sicherheitslücken gefunden.")

    except FileNotFoundError:
        logging.warning("Befehl 'pip-audit' nicht gefunden. Der Vulnerability Scan wird übersprungen.")
        logging.warning("Für eine automatische Sicherheitsüberprüfung, bitte 'pip install pip-audit' ausführen.")
    except subprocess.TimeoutExpired:
        logging.warning(
            "Vulnerability Scan hat zu lange gedauert (Timeout > 30s). Überspringe Scan und setze Build fort."
        )
    except subprocess.CalledProcessError as e:
        # Dieser Block wird ausgeführt, wenn pip-audit Sicherheitslücken findet.
        logging.error("!!! Sicherheitslücken gefunden !!!")
        logging.error("pip-audit hat die folgenden Probleme gemeldet:\n" + e.stdout)
        logging.info(
            "TIPP: Führen Sie 'pip install --upgrade <paketname>' aus, um die betroffenen Pakete zu aktualisieren."
        )


# Funktion zum Ausführen der Pre-Commit-Prüfungen
def run_pre_commit_checks():
    """Führt statische Code-Analyse und Tests via pre-commit aus."""
    logging.info("Starte Pre-Commit-Prüfungen (Linting, Security, Tests)...")
    try:
        env = os.environ.copy()
        if "PRE_COMMIT_HOME" not in env:
            env["PRE_COMMIT_HOME"] = str((Path(__file__).resolve().parent / ".pre-commit-cache").resolve())

        result = subprocess.run(
            [sys.executable, "-m", "pre_commit", "run", "--all-files"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env,
        )
        logging.info("Pre-Commit-Prüfungen erfolgreich bestanden.")
        if result.stdout:
            logging.info(result.stdout)
    except FileNotFoundError:
        logging.warning("pre-commit ist nicht installiert oder nicht im PATH verfügbar.")
    except subprocess.CalledProcessError as e:
        logging.error("!!! Pre-Commit-Prüfungen fehlgeschlagen !!!")
        if e.stdout:
            logging.error("Ausgabe:\n" + e.stdout)
        if e.stderr:
            logging.error("Fehler:\n" + e.stderr)
        raise Exception("Build wegen fehlgeschlagener Pre-Commit-Prüfungen abgebrochen.") from e


# Build-Prozess ausführen
def run_build_process(main_script, app_name):
    try:
        # 1. Pre-Commit-Prüfungen (Linting, Formatierung, Security, Tests)
        run_pre_commit_checks()

        # 2. Sicherheitsüberprüfung
        run_vulnerability_scan()

        # 3. Laufenden Prozess beenden
        kill_process_if_running(app_name)

        # 3. Aufräumen alter Build-Dateien
        logging.info("Starte Aufräumen alter Build-Dateien...")
        cleanup_build_files()

        # 4. Python-Dateien finden
        logging.info("Suche nach Python-Dateien...")
        python_files = find_all_python_files(SOURCE_DIR)

        # Das Build-Skript selbst von der Kompilierung ausschließen
        script_name = os.path.basename(__file__)
        python_files = [f for f in python_files if os.path.basename(f) != script_name]

        if not python_files:
            raise ValueError("Keine Python-Dateien im Quellverzeichnis gefunden (außer dem Build-Skript).")

        # 5. Build-Verzeichnisse erstellen (vorgezogen, da STRIPPED_SOURCE_DIR benötigt wird)
        logging.info("Erstelle Build-Verzeichnisse...")
        create_build_directories()

        # NEUER SCHRITT: 5b. Code bereinigen und in ein temporäres Verzeichnis kopieren
        logging.info(f"Entferne Kommentare/Docstrings und kopiere nach '{STRIPPED_SOURCE_DIR}'...")
        stripped_python_files = []
        for py_file in python_files:
            relative_path = os.path.relpath(py_file, SOURCE_DIR)
            target_path = os.path.join(STRIPPED_SOURCE_DIR, relative_path)

            # Stelle sicher, dass das Zielverzeichnis existiert
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            strip_comments_and_docstrings(py_file, target_path)
            stripped_python_files.append(target_path)

        # 6. Cython-Erweiterungen aus dem BEREINIGTEN Code erstellen
        logging.info("Erstelle Cython-Erweiterungen...")
        # Wichtig: Wir müssen das Arbeitsverzeichnis ändern, damit die Modulpfade stimmen
        original_cwd = os.getcwd()
        os.chdir(STRIPPED_SOURCE_DIR)
        extensions = create_cython_extensions([os.path.relpath(f, STRIPPED_SOURCE_DIR) for f in stripped_python_files])

        # 7. Setup-Funktion aufrufen, um die .c- und .so-Dateien im bereinigten Verzeichnis zu erstellen
        logging.info("Starte Cython-Kompilierung...")
        setup(
            name=app_name,
            ext_modules=extensions,
            script_args=["build_ext", "--inplace"],  # wichtig für korrekte Pfade
        )
        os.chdir(original_cwd)  # Arbeitsverzeichnis zurücksetzen

        # 8. PyInstaller-Befehl erstellen (verweist auf das bereinigte Hauptskript)
        logging.info("Erstelle PyInstaller-Befehl...")
        stripped_main_script = os.path.join(STRIPPED_SOURCE_DIR, main_script)
        pyinstaller_command = create_pyinstaller_command(stripped_main_script, app_name)

        # 9. PyInstaller ausführen
        logging.info("Starte PyInstaller...")
        subprocess.check_call(pyinstaller_command)

        # 10. Hash-Datei für das Update generieren
        executable_path = os.path.join(original_cwd, DIST_DIR, f"{app_name}.exe")
        if not os.path.exists(executable_path):
            raise FileNotFoundError(f"Die von PyInstaller erstellte Datei wurde nicht gefunden: {executable_path}")
        version = get_version_from_script(main_script)
        generate_hash_file(executable_path, version)

        # 11. Finales Aufräumen
        final_cleanup()

        logging.info(f"Build abgeschlossen! Ausführbare Datei befindet sich in '{DIST_DIR}'.")

    except Exception as e:
        logging.error(f"Build fehlgeschlagen: {e}")


if __name__ == "__main__":
    run_build_process(MAIN_SCRIPT, APP_NAME)
