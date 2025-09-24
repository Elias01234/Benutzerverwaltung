<?php
// Datei: OAuth Callback (Google) – tauscht Code gegen Token, meldet Nutzer an
session_start();
require_once __DIR__ . '/config.php';

// Konfiguration prüfen
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  $_SESSION['oauth_error'] = 'Google OAuth ist nicht konfiguriert. Bitte Umgebungsvariablen setzen.';
  header('Location: login.php');
  exit;
}

// http_post_json: POST Form-Data, liefert Body+Header
// Hilfsfunktion: POST Request
function http_post_json($url, $data, $headers = []) {
  $opts = [
    'http' => [
      'method' => 'POST',
      'header' => array_merge(['Content-Type: application/x-www-form-urlencoded'], $headers),
      'content' => http_build_query($data),
      'ignore_errors' => true,
      'timeout' => 15,
    ]
  ];
  $context = stream_context_create($opts);
  $resp = @file_get_contents($url, false, $context);
  return [$resp, $http_response_header ?? []];
}

// http_get_json: GET Request, liefert Body+Header
// Hilfsfunktion: GET Request
function http_get_json($url, $headers = []) {
  $opts = [
    'http' => [
      'method' => 'GET',
      'header' => $headers,
      'ignore_errors' => true,
      'timeout' => 15,
    ]
  ];
  $context = stream_context_create($opts);
  $resp = @file_get_contents($url, false, $context);
  return [$resp, $http_response_header ?? []];
}

// Abbruch durch Nutzer oder Fehler von Google
if (isset($_GET['error'])) {
  $_SESSION['oauth_error'] = 'Anmeldung mit Google abgebrochen oder fehlgeschlagen (' . htmlspecialchars((string)$_GET['error']) . ').';
  header('Location: login.php');
  exit;
}

$code = $_GET['code'] ?? null;
$state = $_GET['state'] ?? null;

// State / Code validieren (CSRF-Schutz)
if (!$code || !$state || !isset($_SESSION[OAUTH2_STATE_KEY]) || !hash_equals($_SESSION[OAUTH2_STATE_KEY], $state)) {
  $_SESSION['oauth_error'] = 'Ungültiger OAuth-Callback. Bitte erneut versuchen.';
  header('Location: login.php');
  exit;
}
unset($_SESSION[OAUTH2_STATE_KEY]);

// Autorisierungscode gegen Access Token tauschen
[$tokenBody] = http_post_json('https://oauth2.googleapis.com/token', [
  'code' => $code,
  'client_id' => GOOGLE_CLIENT_ID,
  'client_secret' => GOOGLE_CLIENT_SECRET,
  'redirect_uri' => GOOGLE_REDIRECT_URI,
  'grant_type' => 'authorization_code',
]);

// Token-Daten auswerten
$token = json_decode($tokenBody ?: 'null', true);
if (!$token || empty($token['access_token'])) {
  $_SESSION['oauth_error'] = 'Token konnte nicht abgerufen werden.';
  header('Location: login.php');
  exit;
}

$accessToken = $token['access_token'];
$idToken = $token['id_token'] ?? null;

// Benutzerinfo laden
[$userResp] = http_get_json('https://www.googleapis.com/oauth2/v3/userinfo', [
  'Authorization: Bearer ' . $accessToken,
]);

$userinfo = json_decode($userResp ?: 'null', true);
if (!$userinfo || empty($userinfo['sub'])) {
  $_SESSION['oauth_error'] = 'Benutzerinformationen konnten nicht geladen werden.';
  header('Location: login.php');
  exit;
}

$googleSub = $userinfo['sub'];
$email = $userinfo['email'] ?? null;
$emailVerified = $userinfo['email_verified'] ?? false;
$name = $userinfo['name'] ?? ($userinfo['given_name'] ?? '');

// E-Mail muss verifiziert sein
if (!$email || !$emailVerified) {
  $_SESSION['oauth_error'] = 'Ihr Google-Konto liefert keine verifizierte E-Mail-Adresse.';
  header('Location: login.php');
  exit;
}

mysqli_report(MYSQLI_REPORT_OFF);
// DB-Verbindung
$conn = new mysqli('localhost', 'root', '', 'benutzerverwaltung');
if ($conn->connect_error) {
  $_SESSION['oauth_error'] = 'DB-Verbindung fehlgeschlagen.';
  header('Location: login.php');
  exit;
}
$conn->set_charset('utf8mb4');
$conn->select_db('benutzerverwaltung');

$hasCol = false;
// Prüfen ob google_sub Spalte existiert
if ($res = $conn->query("SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'google_sub' LIMIT 1")) {
  $hasCol = (bool)$res->fetch_row();
  $res->close();
}
// Falls nicht vorhanden -> hinzufügen (ignoriert Fehler)
if (!$hasCol) {@$conn->query("ALTER TABLE users ADD COLUMN google_sub VARCHAR(64) NULL UNIQUE AFTER password");}

// Login über google_sub versuchen
$stmt = $conn->prepare("SELECT id, username, role FROM users WHERE google_sub = ? LIMIT 1");
if ($stmt) {
  $stmt->bind_param('s', $googleSub);
  $stmt->execute();
  $stmt->bind_result($uid, $uname, $urole);
  if ($stmt->fetch()) {
    $stmt->close();
  // Login (Treffer)
  session_regenerate_id(true);
  $_SESSION['user_id'] = (int)$uid;
  $_SESSION['username'] = $uname;
  $_SESSION['role'] = $urole ?: 'user';
  $_SESSION['flash'] = ['type' => 'success', 'msg' => 'Erfolgreich mit Google angemeldet.'];
  $conn->close();
  header('Location: index.php');
  exit;
  }
  $stmt->close();
}

// Falls kein google_sub: über E-Mail matchen
$stmt = $conn->prepare("SELECT id, username, role FROM users WHERE email = ? LIMIT 1");
if ($stmt) {
  $stmt->bind_param('s', $email);
  $stmt->execute();
  $stmt->bind_result($uid, $uname, $urole);
  if ($stmt->fetch()) {
    $stmt->close();
  // Bestehendes Konto verknüpfen
    if ($upd = $conn->prepare("UPDATE users SET google_sub = ? WHERE id = ? LIMIT 1")) {
      $upd->bind_param('si', $googleSub, $uid);
      $upd->execute();
      $upd->close();
    }
  session_regenerate_id(true);
  $_SESSION['user_id'] = (int)$uid;
  $_SESSION['username'] = $uname;
  $_SESSION['role'] = $urole ?: 'user';
  $_SESSION['flash'] = ['type' => 'success', 'msg' => 'Google-Konto verknüpft und angemeldet.'];
  $conn->close();
  header('Location: index.php');
  exit;
  }
  $stmt->close();
}

// Basis-Username ermitteln
$usernameBase = $name ?: (strpos($email, '@') !== false ? substr($email, 0, strpos($email, '@')) : 'user');
$usernameBase = preg_replace('/[^A-Za-z0-9_\-\.]/', '', $usernameBase);
if ($usernameBase === '') { $usernameBase = 'user'; }
$username = $usernameBase;
$try = 0;
// Eindeutigen Username finden (max 20 Versuche)
while ($try < 20) {
  $stmt = $conn->prepare("SELECT 1 FROM users WHERE username = ? LIMIT 1");
  if ($stmt) {
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $exists = (bool)$stmt->get_result()->fetch_row();
    $stmt->close();
    if (!$exists) break;
  }
  $try++;
  $username = $usernameBase . ($try + 1);
}

// Platzhalter-Passwort (wird nicht genutzt)
$nullPwd = password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT);
// Neues Konto anlegen
$stmt = $conn->prepare("INSERT INTO users (email, username, password, role, google_sub) VALUES (?, ?, ?, 'user', ?)");
if ($stmt) {
  $stmt->bind_param('ssss', $email, $username, $nullPwd, $googleSub);
  if ($stmt->execute()) {
    $newId = $stmt->insert_id;
    $stmt->close();

  session_regenerate_id(true);
  $_SESSION['user_id'] = (int)$newId;
  $_SESSION['username'] = $username;
  $_SESSION['role'] = 'user';
  $_SESSION['flash'] = ['type' => 'success', 'msg' => 'Konto über Google erstellt und angemeldet.'];
  $conn->close();
  header('Location: index.php');
  exit;
  }
  $stmt->close();
}

$conn->close();
$_SESSION['oauth_error'] = 'Google-Anmeldung konnte nicht abgeschlossen werden.';
header('Location: login.php');
exit;
