import pathlib
import subprocess
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from build import find_all_python_files, get_version_from_script, run_pre_commit_checks, strip_comments_and_docstrings


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
