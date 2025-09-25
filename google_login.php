<?php
// Datei: Start Google OAuth Flow
session_start();
require_once __DIR__ . '/config.php';

// Konfiguration prüfen
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  $_SESSION['oauth_error'] = 'Google OAuth ist nicht konfiguriert. Bitte Umgebungsvariablen BENUTZER_GOOGLE_CLIENT_ID und BENUTZER_GOOGLE_CLIENT_SECRET setzen.';
  header('Location: login.php');
  exit;
}

// CSRF-State erzeugen
$state = bin2hex(random_bytes(16));
$_SESSION[OAUTH2_STATE_KEY] = $state;

// OAuth2 Parameter
$params = [
  'client_id' => GOOGLE_CLIENT_ID,
  'redirect_uri' => GOOGLE_REDIRECT_URI,
  'response_type' => 'code',
  'scope' => 'openid email profile',
  'state' => $state,
  'access_type' => 'online',
  'prompt' => 'select_account',
];

$authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query($params); // Ziel-URL

header('Location: ' . $authUrl); // Weiterleiten
exit;
