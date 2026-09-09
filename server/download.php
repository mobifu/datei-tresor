<?php
// Der Dateipfad zur eigentlichen Download-Datei
$file = 'DateiTresor.exe';

// Der Dateipfad zur Zähler-Datei
$counterFile = 'counter.txt';

// --- Zähler erhöhen ---
// Sperrt die Datei, liest den Wert, erhöht ihn und schreibt ihn zurück.
// Das verhindert Fehler, wenn mehrere Benutzer gleichzeitig herunterladen.
$fp = fopen($counterFile, 'r+');
if (flock($fp, LOCK_EX)) {
    $count = (int)fread($fp, filesize($counterFile) ?: 1);
    $count++;

    ftruncate($fp, 0); // Kürzt die Datei auf 0
    rewind($fp);      // Setzt den Zeiger an den Anfang
    fwrite($fp, $count);

    flock($fp, LOCK_UN); // Gibt die Sperre frei
}
fclose($fp);

// --- Optional: Download in einer Log-Datei protokollieren ---
$logFile = 'download_log.txt';
$logEntry = "Download am: " . date('Y-m-d H:i:s') . " | Neuer Zählerstand: " . $count . "\n";
file_put_contents($logFile, $logEntry, FILE_APPEND);

// --- Datei zum Download bereitstellen ---
// Stellt sicher, dass der Browser/Client die Datei als Download behandelt.
if (file_exists($file)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($file).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file));
    readfile($file); // Liest die Datei und sendet sie an den Client
    exit;
} else {
    http_response_code(404);
    echo "Fehler: Datei nicht gefunden.";
}
?>
