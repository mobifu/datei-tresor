"""Zentrales Audit- und Test-Skript für das DateiTresor-Projekt.

Führt automatisiert durch:
1. Codebase Audit: Ruff (Linting & Formatierung)
2. Security Audit: Bandit (statischer Krypto-/Code-Scan) & Pip-Audit (Abhängigkeiten)
3. Automatisierte Tests: Pytest
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path


def run_step(step_name: str, command: list[str], timeout: int = 60, optional: bool = False) -> bool:
    """Führt einen Audit-Einzelschritt aus und liefert True bei Erfolg."""
    print(f"\n{'=' * 60}")
    print(f"[*] Starte: {step_name}")
    print(f"[*] Befehl: {' '.join(command)}")
    print(f"{'=' * 60}")

    try:
        result = subprocess.run(
            command,
            cwd=str(Path(__file__).parent.resolve()),
            text=True,
            capture_output=False,
            timeout=timeout,
        )
        if result.returncode == 0:
            print(f"[OK] {step_name} erfolgreich.")
            return True
        else:
            if optional:
                print(f"[WARNUNG] {step_name} mit Status {result.returncode} beendet (optional).")
                return True
            print(f"[FEHLER] {step_name} fehlgeschlagen (Exit-Code: {result.returncode}).")
            return False
    except subprocess.TimeoutExpired:
        if optional:
            print(f"[WARNUNG] {step_name} hat Zeitlimit ({timeout}s) überschritten (optional).")
            return True
        print(f"[FEHLER] Zeitüberschreitung ({timeout}s) bei: {step_name}")
        return False
    except FileNotFoundError as e:
        if optional:
            print(f"[WARNUNG] Tool für {step_name} nicht gefunden: {e} (optional).")
            return True
        print(f"[FEHLER] Befehl nicht gefunden: {e}")
        return False
    except Exception as e:
        print(f"[FEHLER] Unerwarteter Fehler bei {step_name}: {e}")
        return False


def get_python_executable() -> str:
    """Ermittelt den Pfad zum aktuellen Python-Interpreter."""
    return sys.executable


def run_codebase_audit(py_exe: str) -> bool:
    """Führt statische Code- und Stilprüfungen mit Ruff durch."""
    print("\n--- TEIL 1: CODEBASE AUDIT (Linting & Formatierung) ---")
    step1 = run_step("Ruff Linter", [py_exe, "-m", "ruff", "check", "."])
    step2 = run_step("Ruff Formatter Check", [py_exe, "-m", "ruff", "format", "--check", "."])
    return step1 and step2


def run_security_audit(py_exe: str) -> bool:
    """Führt Sicherheitsprüfungen mit Bandit und Pip-Audit durch."""
    print("\n--- TEIL 2: SECURITY AUDIT (Statische Analyse & CVEs) ---")
    source_files = ["dateicrypt.py", "build.py", "secure_memory.py", "sichern.py", "audit.py"]
    existing_files = [f for f in source_files if os.path.exists(f)]

    step1 = run_step(
        "Bandit Security Scan",
        [py_exe, "-m", "bandit", "-c", "pyproject.toml"] + existing_files,
    )
    step2 = run_step(
        "Pip-Audit Dependency Scan",
        [py_exe, "-m", "pip_audit", "-r", "requirements.txt", "--timeout", "15"],
        timeout=20,
        optional=True,  # Optional wg. möglicher Offline- / Netzwerkbeschränkungen
    )
    return step1 and step2


def run_automated_tests(py_exe: str) -> bool:
    """Führt die automatisierte Test-Suite mit Pytest aus."""
    print("\n--- TEIL 3: AUTOMATISIERTE TESTS (Pytest) ---")
    return run_step("Pytest Test-Suite", [py_exe, "-m", "pytest", "-v"])


def main():
    parser = argparse.ArgumentParser(description="Zentrales Audit- und Test-Runner-Skript.")
    parser.add_argument("--only-codebase", action="store_true", help="Nur Codebase Audit (Ruff) ausführen.")
    parser.add_argument(
        "--only-security", action="store_true", help="Nur Security Audit (Bandit & Pip-Audit) ausführen."
    )
    parser.add_argument("--only-tests", action="store_true", help="Nur automatisierte Tests (Pytest) ausführen.")
    args = parser.parse_args()

    py_exe = get_python_executable()
    results = {}

    run_all = not (args.only_codebase or args.only_security or args.only_tests)

    if run_all or args.only_codebase:
        results["Codebase Audit"] = run_codebase_audit(py_exe)

    if run_all or args.only_security:
        results["Security Audit"] = run_security_audit(py_exe)

    if run_all or args.only_tests:
        results["Automatisierte Tests"] = run_automated_tests(py_exe)

    # Zusammenfassung
    print("\n" + "=" * 60)
    print("AUDIT ZUSAMMENFASSUNG")
    print("=" * 60)
    all_passed = True
    for area, passed in results.items():
        status = "[OK] BESTANDEN" if passed else "[X] FEHLGESCHLAGEN"
        print(f"  {area:30}: {status}")
        if not passed:
            all_passed = False
    print("=" * 60)

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
