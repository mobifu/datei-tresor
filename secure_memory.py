import ctypes
import os
import platform

# Betriebssystem-spezifische Funktionen laden
if platform.system() == "Windows":
    # Windows: VirtualLock, VirtualUnlock, RtlZeroMemory
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    VirtualLock = kernel32.VirtualLock
    VirtualUnlock = kernel32.VirtualUnlock
    RtlZeroMemory = ctypes.windll.kernel32.RtlZeroMemory

    VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    VirtualLock.restype = ctypes.c_bool
    VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    VirtualUnlock.restype = ctypes.c_bool
    RtlZeroMemory.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    RtlZeroMemory.restype = None

else:
    # Linux/macOS: mlock, munlock
    libc = ctypes.CDLL(None, use_errno=True)
    mlock = libc.mlock
    munlock = libc.munlock

    mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    mlock.restype = ctypes.c_int
    munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    munlock.restype = ctypes.c_int


class SecureString:
    """
    Eine Klasse zur sicheren Handhabung von sensiblen Daten im Speicher.

    Verwendet ctypes, um den Speicher zu sperren (verhindert Swapping auf die Festplatte)
    und stellt sicher, dass der Speicher nach Gebrauch explizit genullt wird.
    """

    def __init__(self, initial_value: str):
        self._value_bytes = initial_value.encode("utf-8")
        self._size = len(self._value_bytes)

        # Erstellt einen veränderbaren Puffer und kopiert die Daten
        self._buffer = ctypes.create_string_buffer(self._value_bytes)
        self._ptr = ctypes.addressof(self._buffer)

        # Speicher sperren
        self._lock_memory()

    def _lock_memory(self):
        if platform.system() == "Windows":
            if not VirtualLock(self._ptr, self._size):
                raise OSError(f"VirtualLock fehlgeschlagen: {ctypes.get_last_error()}")
        else:
            if mlock(self._ptr, self._size) != 0:
                errno = ctypes.get_errno()
                raise OSError(errno, os.strerror(errno), "mlock fehlgeschlagen")

    def _unlock_memory(self):
        if platform.system() == "Windows":
            if not VirtualUnlock(self._ptr, self._size):
                print(f"Warnung: VirtualUnlock fehlgeschlagen: {ctypes.get_last_error()}")
        else:
            if munlock(self._ptr, self._size) != 0:
                errno = ctypes.get_errno()
                print(f"Warnung: munlock fehlgeschlagen: {errno} - {os.strerror(errno)}")

    def get_value(self) -> bytes:
        """Gibt den Wert als bytes zurück."""
        if self._buffer is None:
            raise ValueError("Der sichere Speicher wurde bereits freigegeben.")
        return ctypes.string_at(self._ptr, self._size)

    def clear(self):
        """Überschreibt den Speicher sicher mit Nullen und gibt ihn frei."""
        if self._buffer is not None:
            if platform.system() == "Windows":
                RtlZeroMemory(self._ptr, self._size)
            else:
                for i in range(self._size):
                    self._buffer[i] = b"\x00"[0]
            self._unlock_memory()
            self._buffer = None
            self._ptr = None
            self._value_bytes = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()
