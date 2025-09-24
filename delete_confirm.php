<?php
// Datei: Bestätigung Konto-Löschung per Token
session_start();

mysqli_report(MYSQLI_REPORT_OFF);
// DB verbinden
$conn = new mysqli('localhost', 'root', '', 'Benutzerverwaltung');
if ($conn->connect_error) {
  $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'DB-Verbindung fehlgeschlagen.'];
  header('Location: index.php');
  exit;
}
$conn->set_charset('utf8mb4');
$conn->select_db('benutzerverwaltung');

// Token aus Query lesen
$token = $_GET['token'] ?? '';
if (!is_string($token) || strlen($token) < 64) {
  $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Ungültiger oder fehlender Token.'];
  header('Location: index.php');
  exit;
}
// Hash für Vergleich
$tokenHash = hash('sha256', $token);

// Token-Datensatz suchen
$stmt = $conn->prepare("
  SELECT user_id
  FROM user_deletion_tokens
  WHERE token_hash = ?
    AND consumed_at IS NULL
    AND expires_at > NOW()
  LIMIT 1
");
if (!$stmt) {
  $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Aktion derzeit nicht möglich.'];
  header('Location: index.php');
  exit;
}
$stmt->bind_param('s', $tokenHash);
$stmt->execute();
$res = $stmt->get_result();
$row = $res ? $res->fetch_assoc() : null;
$stmt->close();

if (!$row) {
  $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Dieser Bestätigungslink ist ungültig oder abgelaufen.'];
  header('Location: index.php');
  exit;
}

// Zielnutzer identifizieren
$userId = (int)$row['user_id'];
$deletingOwn = isset($_SESSION['user_id']) && (int)$_SESSION['user_id'] === $userId;

// Transaktion starten
$conn->begin_transaction();

try {
  // Benutzer löschen
  $del = $conn->prepare("DELETE FROM users WHERE id = ? LIMIT 1");
  if (!$del) {
    throw new Exception('DELETE prepare failed');
  }
  $del->bind_param('i', $userId);
  $del->execute();
  $affected = $del->affected_rows;
  $del->close();

  if ($affected !== 1) {
    throw new Exception('Benutzer konnte nicht gelöscht werden.');
  }

  
  // Verwendetes Token markieren
  $cons = $conn->prepare("UPDATE user_deletion_tokens SET consumed_at = NOW() WHERE token_hash = ? LIMIT 1");
  if ($cons) {
    $cons->bind_param('s', $tokenHash);
    $cons->execute();
    $cons->close();
  }
  // Verbleibende Tokens löschen
  $cleanup = $conn->prepare("DELETE FROM user_deletion_tokens WHERE user_id = ?");
  if ($cleanup) {
    $cleanup->bind_param('i', $userId);
    $cleanup->execute();
    $cleanup->close();
  }

  // Erfolgreich
  $conn->commit();

  
  if ($deletingOwn) {
    unset($_SESSION['user_id'], $_SESSION['username']);
  }
  $_SESSION['flash'] = ['type' => 'success', 'msg' => 'Ihr Benutzerkonto wurde gelöscht.'];
} catch (Throwable $e) {
  $conn->rollback();
  $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Löschen fehlgeschlagen.'];
}

header('Location: index.php');
exit;