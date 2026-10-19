import pathlib
import subprocess
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from build import (
    create_pyinstaller_command,
    find_all_python_files,
    generate_hash_file,
    generate_license_file,
    get_version_from_script,
    prompt_version_update,
    run_pre_commit_checks,
    set_version_in_script,
    strip_comments_and_docstrings,
)


def test_get_version_from_script():
    """Prüft das Auslesen der Versionsnummer aus einer Skriptdatei."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = pathlib.Path(tmpdir) / "version_test.py"
        test_file.write_text('VERSION_INFO = "v1.9.9" # Kommentar\n', encoding="utf-8")
        assert get_version_from_script(str(test_file)) == "v1.9.9"


def test_get_version_from_script_missing():
    """Prüft den Fehlerfall bei fehlender VERSION_INFO."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = pathlib.Path(tmpdir) / "empty.py"
        test_file.write_text('print("hello")\n', encoding="utf-8")
        with pytest.raises(ValueError, match="VERSION_INFO konnte in der Hauptdatei nicht gefunden werden"):
            get_version_from_script(str(test_file))


def test_strip_comments_and_docstrings():
    """Prüft das Entfernen von Kommentaren aus Quellcode."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src = pathlib.Path(tmpdir) / "source.py"
        target = pathlib.Path(tmpdir) / "target.py"
        src.write_text(
            '# Das ist ein Kommentar\ndef add(a, b):\n    """Docstring"""\n    return a + b\n',
            encoding="utf-8",
        )

        strip_comments_and_docstrings(str(src), str(target))
        content = target.read_text(encoding="utf-8")
        assert "# Das ist ein Kommentar" not in content
        assert "return a + b" in content


def test_run_pre_commit_checks_success():
    """Prüft erfolgreichen Durchlauf von run_pre_commit_checks."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        run_pre_commit_checks()
        mock_run.assert_called_once()


def test_run_pre_commit_checks_failure():
    """Prüft Abbruch bei fehlgeschlagenen Pre-Commit Checks."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(returncode=1, cmd="pre-commit", output="Error")
        with pytest.raises(Exception, match="Build wegen fehlgeschlagener Pre-Commit-Prüfungen abgebrochen"):
            run_pre_commit_checks()


def test_find_all_python_files_excludes_caches_and_tools():
    """Prüft, dass find_all_python_files nur Quellcode der App und keine Caches, Tests oder Build-Skripte findet."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base = pathlib.Path(tmpdir)
        # Echte App-Dateien
        (base / "dateicrypt.py").write_text("# app", encoding="utf-8")
        (base / "secure_memory.py").write_text("# module", encoding="utf-8")

        # Auszuschließende Dateien und Verzeichnisse
        (base / "build.py").write_text("# build", encoding="utf-8")
        (base / "audit.py").write_text("# audit", encoding="utf-8")
        (base / "sichern.py").write_text("# backup", encoding="utf-8")

        # Caches und Ordner
        cache_dir = base / ".pre-commit-cache" / "repo123"
        cache_dir.mkdir(parents=True)
        (cache_dir / "setup.py").write_text("# cache", encoding="utf-8")

        test_dir = base / "tests"
        test_dir.mkdir()
        (test_dir / "test_app.py").write_text("# test", encoding="utf-8")

        temp_build_dir = base / "build_temp_123"
        temp_build_dir.mkdir()
        (temp_build_dir / "temp.py").write_text("# temp", encoding="utf-8")

        found = find_all_python_files(str(base))
        found_basenames = {pathlib.Path(f).name for f in found}

        assert found_basenames == {"dateicrypt.py", "secure_memory.py"}


def test_set_version_in_script():
    """Prüft das erfolgreiche Ersetzen der Version in einer Skriptdatei."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = pathlib.Path(tmpdir) / "app.py"
        test_file.write_text('VERSION_INFO = "v1.0.0"  # Kommentar\nOTHER = 123\n', encoding="utf-8")

        new_ver = set_version_in_script(str(test_file), "v1.4.2")
        assert new_ver == "v1.4.2"
        assert 'VERSION_INFO = "v1.4.2"  # Kommentar' in test_file.read_text(encoding="utf-8")

        # Prüfe automatische 'v'-Präfix Ergänzung
        new_ver2 = set_version_in_script(str(test_file), "1.5.0")
        assert new_ver2 == "v1.5.0"
        assert 'VERSION_INFO = "v1.5.0"  # Kommentar' in test_file.read_text(encoding="utf-8")


def test_set_version_in_script_missing():
    """Prüft Fehlerfall, wenn VERSION_INFO nicht im Skript existiert."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = pathlib.Path(tmpdir) / "app.py"
        test_file.write_text('FOO = "bar"\n', encoding="utf-8")

        with pytest.raises(ValueError, match="VERSION_INFO konnte in .* nicht gefunden oder ersetzt werden"):
            set_version_in_script(str(test_file), "v2.0.0")


def test_prompt_version_update():
    """Prüft Versionsanpassung mit expliziter Übergabe und interaktiver Eingabe."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = pathlib.Path(tmpdir) / "app.py"
        test_file.write_text('VERSION_INFO = "v1.0.0"\n', encoding="utf-8")

        # 1. Direkte Übergabe von target_version
        result = prompt_version_update(str(test_file), target_version="v2.0.0", interactive=False)
        assert result == "v2.0.0"
        assert get_version_from_script(str(test_file)) == "v2.0.0"

        # 2. Interaktive Eingabe über Mock (neue Version)
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="v2.1.0"):
            result2 = prompt_version_update(str(test_file), interactive=True)
            assert result2 == "v2.1.0"
            assert get_version_from_script(str(test_file)) == "v2.1.0"

        # 3. Interaktive Eingabe leer gelassen (Enter) -> behält alte Version
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value=""):
            result3 = prompt_version_update(str(test_file), interactive=True)
            assert result3 == "v2.1.0"
            assert get_version_from_script(str(test_file)) == "v2.1.0"


def test_generate_license_file():
    """Prüft die korrekte Erstellung der LICENSE.txt Datei."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dist_dir = pathlib.Path(tmpdir) / "dist_test"
        license_path = generate_license_file(dist_dir, year="2026", author="Agentur Schölzke")

        assert license_path.exists()
        content = license_path.read_text(encoding="utf-8")
        assert "MIT License" in content
        assert "Copyright (c) 2026 Agentur Schölzke" in content
        assert "--- Nutzungsbedingungen ---" in content


def test_create_pyinstaller_command_bundles_license():
    """Prüft, dass der PyInstaller-Befehl LICENSE.txt bündelt, wenn vorhanden."""
    cmd = create_pyinstaller_command("main.py", "TestApp")
    assert "--onefile" in cmd
    assert "TestApp" in cmd
    if pathlib.Path("LICENSE.txt").exists():
        assert "--add-data" in cmd
        assert any("LICENSE.txt" in arg for arg in cmd)


def test_generate_hash_file_saves_to_target_dir():
    """Prüft, dass generate_hash_file den SHA-256 Hash berechnet und in target_dir speichert."""
    with tempfile.TemporaryDirectory() as tmpdir:
        exe_file = pathlib.Path(tmpdir) / "TestApp.exe"
        exe_file.write_bytes(b"binary content for hashing")
        server_dir = pathlib.Path(tmpdir) / "server"

        file_hash = generate_hash_file(str(exe_file), "v1.4.2", target_dir=str(server_dir))
        version_txt = server_dir / "version.txt"

        assert version_txt.exists()
        content = version_txt.read_text(encoding="utf-8")
        assert content == f"v1.4.2+{file_hash}"
