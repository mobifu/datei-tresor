import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from audit import (
    get_python_executable,
    main,
    run_automated_tests,
    run_codebase_audit,
    run_security_audit,
    run_step,
)


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


def test_run_step_timeout_expired():
    """Prüft Fehlerbehandlung bei Zeitüberschreitung."""
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="test", timeout=5)):
        assert run_step("Timeout-Schritt", ["test"], timeout=5) is False


def test_run_step_timeout_expired_optional():
    """Prüft, dass Timeouts bei optionalen Schritten als Warnung toleriert werden."""
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="test", timeout=5)):
        assert run_step("Optionaler Timeout", ["test"], timeout=5, optional=True) is True


def test_run_step_file_not_found():
    """Prüft Fehlerbehandlung, wenn ein Befehl nicht gefunden wird."""
    with patch("subprocess.run", side_effect=FileNotFoundError("Tool nicht gefunden")):
        assert run_step("Fehlendes Tool", ["nicht_vorhanden"]) is False


def test_run_step_file_not_found_optional():
    """Prüft, dass fehlende optionale Tools toleriert werden."""
    with patch("subprocess.run", side_effect=FileNotFoundError("Tool nicht gefunden")):
        assert run_step("Optionales Tool", ["nicht_vorhanden"], optional=True) is True


def test_run_step_generic_exception():
    """Prüft Fehlerbehandlung bei unerwarteten Exceptions."""
    with patch("subprocess.run", side_effect=RuntimeError("Unerwarteter Fehler")):
        assert run_step("Exception Schritt", ["crash"]) is False


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


def test_main_all_passed():
    """Prüft den fehlerfreien Gesamtdurchlauf von main() mit Exit-Code 0."""
    with (
        patch.object(sys, "argv", ["audit.py"]),
        patch("audit.run_codebase_audit", return_value=True),
        patch("audit.run_security_audit", return_value=True),
        patch("audit.run_automated_tests", return_value=True),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()
    assert exc_info.value.code == 0


def test_main_failure_exits_1():
    """Prüft, dass main() mit Exit-Code 1 beendet wird, wenn ein Teil fehlschlägt."""
    with (
        patch.object(sys, "argv", ["audit.py"]),
        patch("audit.run_codebase_audit", return_value=False),
        patch("audit.run_security_audit", return_value=True),
        patch("audit.run_automated_tests", return_value=True),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()
    assert exc_info.value.code == 1


def test_main_selective_flags():
    """Prüft die Ausführung einzelner Abschnitte via CLI-Flags."""
    with (
        patch.object(sys, "argv", ["audit.py", "--only-codebase"]),
        patch("audit.run_codebase_audit", return_value=True) as mock_codebase,
        patch("audit.run_security_audit", return_value=True) as mock_sec,
        patch("audit.run_automated_tests", return_value=True) as mock_tests,
        pytest.raises(SystemExit) as exc_info,
    ):
        main()
    assert exc_info.value.code == 0
    mock_codebase.assert_called_once()
    mock_sec.assert_not_called()
    mock_tests.assert_not_called()
