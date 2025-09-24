<?php
// Datei: Benutzer abmelden
session_start();
// Session-Inhalt löschen
$_SESSION = [];
// Session-Cookie invalidieren (falls genutzt)
if (ini_get('session.use_cookies')) {
  $params = session_get_cookie_params();
  setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
}
// Session beenden
session_destroy();
// Weiter zur Login-Seite
header('Location: login.php?logged_out=1');
exit;