<?php
// Datei: Einfache Ausgabe wichtiger Env-Variablen (Debug)
header('Content-Type: text/plain; charset=utf-8'); // Textausgabe
echo "CLIENT_ID: " . getenv('BENUTZER_GOOGLE_CLIENT_ID') . PHP_EOL; // Client ID Rohwert
echo "CLIENT_SECRET: " . (getenv('BENUTZER_GOOGLE_CLIENT_SECRET') ? "[gesetzt]" : "[leer]") . PHP_EOL; // Nur Status
echo "BASE_URL: " . getenv('BENUTZER_BASE_URL') . PHP_EOL; // Basis-URL