# Datei Tresor

**Ihre Daten, Ihre Kontrolle: Machen Sie das Internet sicherer – mit einem Klick.**

Der Datei-Tresor ist eine kostenlose Desktop-Anwendung für Windows, mit der Sie jede Art von Datei oder Ordner mit einem Passwort schützen können. Die Software verwendet eine starke, nach Industriestandard anerkannte Verschlüsselung, um Ihre Daten unlesbar zu machen. Nur mit dem korrekten Passwort können die Daten wieder entschlüsselt werden.

**[JETZT KOSTENLOS HERUNTERLADEN](https://www.agentur-schoelzke.de/daten_tresor/download.php)**

## Features

*   **Moderne, starke Verschlüsselung:** Nutzt `cryptography` für eine robuste Verschlüsselung im AES-256-GCM-Modus.
    *   **Algorithmus:** AES mit 256-Bit-Schlüsseln im Galois/Counter Mode (GCM). Dieser Modus bietet sowohl Vertraulichkeit als auch Authentizität und ist hoch performant.
    *   **Streaming-Fähig:** Verarbeitet Dateien blockweise, was die Verschlüsselung sehr großer Dateien mit geringem Speicherverbrauch ermöglicht.
    *   **Abwärtskompatibel:** Die Abwärtskompatibilität wird immer gewahrt. Ältere, mit der Fernet-Implementierung (AES-128-CBC) erstellte Dateien können weiterhin entschlüsselt werden.
*   **Datei- & Ordner-Unterstützung:** Verschlüsseln Sie einzelne Dateien oder ganze Ordnerstrukturen. Ordner werden dabei automatisch als ZIP-Archiv gepackt.
*   **Sicheres Profil-Management:** Speichern Sie häufig genutzte Passwörter in verschlüsselten Profilen, geschützt durch ein einziges Master-Passwort.
*   **Intuitive Drag-and-Drop-Funktion:** Ziehen Sie Dateien oder Ordner direkt auf das Anwendungsfenster, um die Ver- oder Entschlüsselung zu starten. Eine visuelle Drop-Zone erleichtert die Bedienung.
*   **Passwort-Assistenten:** Erstellen Sie auf Knopfdruck kryptografisch sichere Passwörter. Erhalten Sie beim Tippen visuelles Echtzeit-Feedback zur Passwortstärke und machen Sie die Eingabe zur Kontrolle sichtbar.
*   **Erzwungene Passwort-Komplexität:** Das Master-Passwort muss strenge Kriterien erfüllen, um die Sicherheit zu maximieren:
    *   Mindestens 12 Zeichen
    *   Mindestens ein Groß- und ein Kleinbuchstabe
    *   Mindestens eine Ziffer
*   **Sichere Passwort-Handhabung im Arbeitsspeicher:** Passwörter und Schlüssel werden in einem gesicherten Speicherbereich gehalten, der mittels `mlock` (Linux/macOS) oder `VirtualLock` (Windows) vor dem Auslagern auf die Festplatte (Swapping) geschützt wird. Nach der Verwendung wird der Speicher explizit genullt, um Memory-Scraping-Angriffe zu erschweren.
*   **Sicherer Auto-Updater:** Die Anwendung sucht nach neuen Versionen und verifiziert heruntergeladene Updates mittels SHA-256-Hash, um Manipulationen zu verhindern.
*   **Code-Verschleierung:** Während des Build-Prozesses werden automatisch alle Kommentare und Docstrings aus dem Quellcode entfernt, um die Analyse der fertigen Anwendung zu erschweren.
*   **Performance-Optimierung durch Key-Caching:** Die langsame und sichere Schlüsselableitung aus einem Passwort wird nur einmal pro Sitzung durchgeführt. Der abgeleitete Schlüssel wird sicher im Arbeitsspeicher zwischengespeichert, was nachfolgende Ver- und Entschlüsselungsvorgänge mit demselben Passwort erheblich beschleunigt.
*   **Plattformunabhängiger Code:** Kernlogik in Python geschrieben, mit einer GUI mittels `CustomTkinter`.
*   **Automatischer Build-Prozess:** Ein `build.py`-Skript automatisiert die Kompilierung mit Cython und das Packen mit PyInstaller.
*   **Integrierter Sicherheits-Scan:** Der Build-Prozess prüft automatisch mit `pip-audit` auf bekannte Sicherheitslücken in den Abhängigkeiten.

## Warum Datei-Tresor?

*   **Absolute Sicherheit:** AES-256 Verschlüsselung schützt Ihre Daten nach heutigem Stand der Technik.
*   **Volle Kontrolle:** Ihr Passwort wird nirgendwo gespeichert. Es gibt keine Hintertüren.
*   **Universell:** Sichern Sie E-Mail-Anhänge, Cloud-Uploads (Dropbox, Google Drive, etc.) oder USB-Sticks.
*   **Kostenlos:** Sicherheit sollte kein Luxus sein.

## Technologie-Stack

*   **Sprache:** Python 3
*   **GUI:** `customtkinter`
*   **Verschlüsselung:** `cryptography`
*   **Kompilierung (optional):** `Cython`
*   **Packaging:** `PyInstaller`

## Einrichtung für Entwickler

1.  **Repository klonen:**
    ```bash
    git clone <repository-url>
    cd "dateien verschluesseln"
    ```

2.  **Virtuelle Umgebung erstellen und aktivieren:**
    ```bash
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Abhängigkeiten installieren:**
    Installieren Sie die notwendigen Pakete mit der `requirements.txt`-Datei:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Pre-Commit-Hooks aktivieren:**
    Aktivieren Sie die automatischen Qualitäts- und Sicherheitsprüfungen vor jedem Commit:
    ```bash
    pre-commit install
    ```
    Manuelle Prüfung aller Dateien:
    ```bash
    pre-commit run --all-files
    ```

5.  **Qualitäts- & Sicherheits-Audit sowie Tests ausführen:**
    Führen Sie das zentrale Audit-Skript aus, um Linter, Formatierer, Security-Scanner und alle Unittests gesammelt zu prüfen:
    ```bash
    python audit.py
    ```
    Alternativ können einzelne Teilbereiche separat geprüft werden:
    ```bash
    python audit.py --only-codebase   # Ruff Linter & Formatierung
    python audit.py --only-security   # Bandit & Pip-Audit
    python audit.py --only-tests      # Pytest Test-Suite (50 Tests)
    ```
    Direkter Testaufruf mit `pytest`:
    ```bash
    pytest -v
    ```

6.  **Anwendung starten:**
    Führen Sie das Hauptskript aus, um die Anwendung im Entwicklungsmodus zu starten:
    ```bash
    python dateicrypt.py
    ```

## Code-Qualität & Sicherheit

Das Projekt setzt auf dreistufige automatisierte Qualitätssicherung:
*   **Codebase Audit:** Ruff-Linter mit Regelsätzen für Fehler- und Stilprüfung (`E`, `F`, `W`, `I`, `B` für Bugbear, `UP` für PyUpgrade) sowie automatische Formatierung.
*   **Security Audit:** Statische Sicherheitsanalyse mit Bandit auf den Kern-Quelldateien sowie Schwachstellen-Scans der Abhängigkeiten mit `pip-audit`. Härtung gegen Path-Traversal (Zip-Slip) und strikte kryptografische Zufallsquellen (`secrets.token_bytes`).
*   **Automatisierte Tests:** Vollständige Testabdeckung (50 Tests) für die Streaming-AES-256-GCM-Verschlüsselung, Integritäts- und Bit-Flip-Erkennung, Legacy-Fernet-Fallback (Abwärtskompatibilität), Kollisionsbehandlung, sicheres Schlüssel-Caching (`KeyCache`) mit automatischem RAM-Wipe, Throttling des UI-Fortschritts, atomaren Update-Download, Profilverwaltung (`ProfileManager`), Arbeitsspeicherverwaltung (`SecureString`), Audit-Fehlerbehandlung und Build-Routinen.
*   **Pre-Commit-Hooks:** Automatische Ausführung aller Prüfungen vor jedem Git-Commit.

## Build-Prozess

Das Projekt enthält ein `build.py`-Skript, das den gesamten Prozess von der Code-Verschleierung mittels Cython bis zur Erstellung einer einzelnen `.exe`-Datei automatisiert.

Um einen Build zu starten, führen Sie einfach das Skript aus:

```bash
python build.py
```

Optional kann eine Version direkt per Parameter übergeben oder der interaktive Modus gesteuert werden:

```bash
python build.py --version v1.4.2
python build.py --no-interactive
```

Der Prozess führt folgende Schritte aus:
1.  **Versionsabfrage:** Ermöglicht die interaktive Eingabe oder Übernahme einer neuen Versionsnummer, die automatisch in `dateicrypt.py` aktualisiert wird.
2.  **Pre-Commit-Prüfungen:** Führt automatisiert alle Linter-, Formatierungs-, Sicherheits- und Testprüfungen (`ruff`, `bandit`, `pytest`) aus und bricht bei Fehlern ab.
3.  **Vulnerability Scan:** Prüft die installierten Pakete mit `pip-audit` auf Sicherheitslücken.
4.  **Laufenden Prozess beenden:** Schließt eine eventuell bereits geöffnete Instanz der Anwendung.
5.  **Aufräumen:** Entfernt alte Build-Artefakte.
6.  **Code-Bereinigung:** Entfernt Kommentare und Docstrings aus dem Quellcode für die Kompilierung.
7.  **Cythonize:** Konvertiert die bereinigten `.py`-Dateien in `.c`-Dateien und kompiliert sie zu `.pyd`-Modulen.
8.  **PyInstaller:** Bündelt alle Module, die Lizenzdatei (`LICENSE.txt`) und das Icon direkt in eine einzige, in sich geschlossene Datei (`DateiTresor.exe`).
9.  **Server-Update-Datei:** Erstellt die Datei `version.txt` mit dem PEP-440-Prüfstring (`<Version>+<SHA256>`) im Ordner `server/` für den Webserver-Upload.
10. **Sicheres finales Aufräumen:** Entfernt alle temporären Build-Dateien und überschreibt sie vorher mehrfach mit Zufallsdaten, um eine Wiederherstellung zu verhindern.

Die fertige Standalone-Anwendung `DateiTresor.exe` befindet sich anschließend ohne überflüssige Begleitdateien direkt im Verzeichnis `dist_YYYYMMDD-HHMMSS`.



## Geplante Features & Ideen für die Zukunft

Hier ist eine Sammlung von Ideen, die darauf abzielen, den Datei-Tresor noch intuitiver und benutzerfreundlicher zu gestalten, ohne die Kernprinzipien der Einfachheit und Abwärtskompatibilität zu verletzen.

*   **Integration in das Windows Explorer Kontext-Menü:**
    *   **Ziel:** Direkt im Windows Explorer per Rechtsklick auf eine Datei oder einen Ordner die Option "Mit Datei-Tresor verschlüsseln/entschlüsseln" anbieten.
    *   **Vorteil:** Dies würde den Arbeitsablauf erheblich beschleunigen, da die Anwendung nicht mehr manuell gestartet werden muss. Die Funktion integriert sich nahtlos in die gewohnte Umgebung des Nutzers.

*   **"Portable Mode" (USB-Stick Edition):**
    *   **Ziel:** Eine spezielle `.exe`-Version anbieten, die ohne Installation direkt von einem USB-Stick oder einem anderen externen Laufwerk gestartet werden kann.
    *   **Vorteil:** Perfekt für den Einsatz an fremden Computern, da keine Administratorrechte benötigt werden und keine Spuren (wie Registry-Einträge) auf dem Gastsystem hinterlassen werden. Daten können direkt auf dem Stick ver- und entschlüsselt werden.

*   **Verbessertes visuelles Feedback (statt Handbuch):**
    *   **Ziel:** Die Anwendung noch selbsterklärender machen.
    *   **Ideen:**
        *   **Tooltips:** Kleine Hilfetexte, die erscheinen, wenn man mit der Maus über einen Button oder ein Eingabefeld fährt (z.B. "Erstellt eine geschützte .crypted Kopie Ihrer Datei.").
        *   **Fortschrittsanzeige:** Ein visueller Ladebalken, der bei der Ver- und Entschlüsselung großer Dateien den Fortschritt anzeigt und dem Nutzer signalisiert, dass das Programm arbeitet.
        *   **Drag & Drop Overlay:** Wenn eine Datei über das Anwendungsfenster gezogen wird, könnte sich der Hintergrund oder der Rahmen farblich ändern, um dem Nutzer zu signalisieren: "Hier kannst du die Datei fallen lassen."

## Projekt unterstützen

Diese Software ist und bleibt zu 100% kostenlos. Wenn Ihnen der Datei-Tresor gefällt und Sie die Weiterentwicklung unterstützen möchten, können Sie mir gerne einen Kaffee ausgeben:

**[☕ Jetzt spenden](https://paypal.me/kaischoelzke)**

## Lizenz

Dieses Projekt steht unter der **MIT-Lizenz**. Die Details finden Sie in der `LICENSE.txt`-Datei.

---

***Nutzungsbedingungen:*** *Die Nutzung dieser Software erfolgt auf eigenes Risiko. Die Autoren übernehmen keine Haftung für Datenverlust oder andere Schäden, die durch die direkte oder indirekte Nutzung dieser Anwendung entstehen. Es wird dringend empfohlen, vor der Verschlüsselung wichtiger Daten Backups zu erstellen.*
