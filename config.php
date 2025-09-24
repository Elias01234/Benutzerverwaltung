<?php
// Datei: Basis-Konfiguration / Konstanten

// Funktion: Umgebungsvariable oder Default holen
function env(string $key, ?string $default = null): ?string {
    $v = getenv($key);
    if ($v === false) return $default;
    return $v;
}

// Basis-URL
if (!defined('BASE_URL')) {
    define('BASE_URL', env('BENUTZER_BASE_URL', 'http://localhost'));
}
// Google OAuth Client ID
if (!defined('GOOGLE_CLIENT_ID')) {
    define('GOOGLE_CLIENT_ID', (string)(env('BENUTZER_GOOGLE_CLIENT_ID', '') ?? ''));
}
// Google OAuth Client Secret
if (!defined('GOOGLE_CLIENT_SECRET')) {
    define('GOOGLE_CLIENT_SECRET', (string)(env('BENUTZER_GOOGLE_CLIENT_SECRET', '') ?? ''));
}
// Callback URL
if (!defined('GOOGLE_REDIRECT_URI')) {
    define('GOOGLE_REDIRECT_URI', BASE_URL . '/google_callback.php');
}
// Session-Key für OAuth State
if (!defined('OAUTH2_STATE_KEY')) {
    define('OAUTH2_STATE_KEY', 'oauth2_google_state');
}
