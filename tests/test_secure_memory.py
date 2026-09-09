import pytest

from secure_memory import SecureString


def test_secure_string_basic():
    """Prüft das Erstellen und Auslesen eines SecureString."""
    sec = SecureString("geheimnis123")
    try:
        assert sec.get_value() == b"geheimnis123"
    finally:
        sec.clear()


def test_secure_string_clear():
    """Prüft, dass nach clear() kein Zugriff mehr möglich ist."""
    sec = SecureString("topsecret")
    sec.clear()
    with pytest.raises(ValueError, match="Der sichere Speicher wurde bereits freigegeben"):
        sec.get_value()


def test_secure_string_context_manager():
    """Prüft die Verwendung als Kontext-Manager."""
    with SecureString("passwort_test") as sec:
        assert sec.get_value() == b"passwort_test"

    with pytest.raises(ValueError, match="Der sichere Speicher wurde bereits freigegeben"):
        sec.get_value()
