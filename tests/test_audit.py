from unittest.mock import MagicMock, patch

from audit import get_python_executable, run_automated_tests, run_codebase_audit, run_security_audit, run_step


def test_get_python_executable():
    """Prüft, dass get_python_executable einen gültigen Pfad liefert."""
    exe = get_python_executable()
    assert isinstance(exe, str)
    assert len(exe) > 0


def test_run_step_success():
    """Prüft erfolgreiche Ausführung eines Befehls mit run_step."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        assert run_step("Test-Schritt", ["echo", "test"]) is True


def test_run_step_failure():
    """Prüft Fehlerbehandlung bei nicht-null Exit-Code."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        assert run_step("Fehlerschritt", ["fail"]) is False


def test_run_step_optional_failure():
    """Prüft, dass optionale Schritte bei Fehler True (Warnung) zurückgeben."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        assert run_step("Optionaler Schritt", ["fail"], optional=True) is True


def test_run_codebase_audit_dispatch():
    """Prüft, dass run_codebase_audit Ruff Linter und Formatter aufruft."""
    with patch("audit.run_step", return_value=True) as mock_step:
        assert run_codebase_audit("python") is True
        assert mock_step.call_count == 2


def test_run_security_audit_dispatch():
    """Prüft, dass run_security_audit Bandit und Pip-Audit aufruft."""
    with patch("audit.run_step", return_value=True) as mock_step:
        assert run_security_audit("python") is True
        assert mock_step.call_count == 2


def test_run_automated_tests_dispatch():
    """Prüft, dass run_automated_tests Pytest aufruft."""
    with patch("audit.run_step", return_value=True) as mock_step:
        assert run_automated_tests("python") is True
        mock_step.assert_called_once()
