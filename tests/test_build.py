import pathlib
import subprocess
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from build import get_version_from_script, run_pre_commit_checks, strip_comments_and_docstrings


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
