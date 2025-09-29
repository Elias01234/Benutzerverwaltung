<?php
// Datei: Passwort vergessen (Anforderung Reset-Link)
// Sicherheit TODOs:
// - Rate Limiting / IP Throttling einführen (z.B. Speicherung von Anzahl Anfragen pro IP/E-Mail)
// - Logging verdächtiger Aktivitäten (häufige Requests)
// - CAPTCHA optional hinzufügen bei vielen Versuchen
session_start();
require_once __DIR__ . '/mail.php';

mysqli_report(MYSQLI_REPORT_OFF);
$conn = new mysqli('localhost', 'root', '', 'benutzerverwaltung');
$successMsg = null; // Konkrete Erfolgsmeldung nur wenn E-Mail existiert
$sent = false; $error = null; $emailFound = false;
if ($conn->connect_error) {
    $error = 'Datenbankfehler.';
} else {
    $conn->set_charset('utf8mb4');
    $conn->select_db('benutzerverwaltung');
    // Tabelle für Tokens sicherstellen (einfach, idempotent)
    $conn->query("CREATE TABLE IF NOT EXISTS password_reset_tokens (\n        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,\n        user_id INT UNSIGNED NOT NULL,\n        token_hash CHAR(64) NOT NULL,\n        expires_at DATETIME NOT NULL,\n        consumed_at DATETIME NULL,\n        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n        INDEX (user_id),\n        UNIQUE KEY uniq_token_hash (token_hash),\n        CONSTRAINT fk_prt_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE\n      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci");

  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $emailInput = trim($_POST['email'] ?? '');
    $email = filter_var($emailInput, FILTER_VALIDATE_EMAIL);
    if (!$email) {
      $error = 'Bitte geben Sie eine gültige E-Mail-Adresse ein.';
    } else {
      if ($stmt = $conn->prepare('SELECT id, username FROM users WHERE email = ? LIMIT 1')) {
        $stmt->bind_param('s', $email);
        if ($stmt->execute() && ($res = $stmt->get_result()) && ($row = $res->fetch_assoc())) {
          $emailFound = true;
          $userId = (int)$row['id'];
          $uname = $row['username'];
          if ($del = $conn->prepare('DELETE FROM password_reset_tokens WHERE user_id = ?')) { $del->bind_param('i', $userId); $del->execute(); $del->close(); }
          $token = bin2hex(random_bytes(32));
          $tokenHash = hash('sha256', $token);
          if ($ins = $conn->prepare('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 60 MINUTE))')) {
            $ins->bind_param('is', $userId, $tokenHash);
            if ($ins->execute()) {
              $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
              $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
              $basePath = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
              $resetUrl = $scheme . '://' . $host . $basePath . '/reset_password.php?token=' . urlencode($token);
              sendPasswordResetMail($email, $uname, $resetUrl);
              $successMsg = 'Ein Link zum Zurücksetzen wurde an die angegebene E-Mail-Adresse gesendet.';
            } else {
              $error = 'Aktion derzeit nicht möglich.';
            }
            $ins->close();
          }
        } else {
          $error = 'Diese E-Mail-Adresse ist nicht registriert.';
        }
        $stmt->close();
      } else {
        $error = 'Aktion derzeit nicht möglich.';
      }
    }
    $sent = true;
  }
}
?>
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Passwort vergessen</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div class="container py-5 app-container">
    <div class="row justify-content-center">
      <div class="col-md-7 col-lg-6">
        <div class="card">
          <div class="card-body p-4">
            <h1 class="h4 mb-3">Passwort vergessen</h1>
            <?php if($error && !$sent): ?>
              <div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <?php if($sent): ?>
              <div class="alert <?= $successMsg ? 'alert-success' : 'alert-danger' ?>" role="alert">
                <?= htmlspecialchars($successMsg ?? ($error ?? 'Aktion fehlgeschlagen.')) ?>
              </div>
              <?php if($successMsg): ?>
                <p class="mb-0"><a href="login.php" class="btn btn-primary mt-2">Zurück zum Login</a></p>
              <?php else: ?>
                <p class="mb-0"><a href="forgot_password.php" class="btn btn-secondary mt-2">Erneut versuchen</a></p>
              <?php endif; ?>
            <?php else: ?>
              <form method="post" novalidate>
                <div class="mb-3">
                  <label for="email" class="form-label">E-Mail-Adresse</label>
                  <input type="email" class="form-control" id="email" name="email" required autocomplete="email">
                  <div class="form-text">Sie erhalten (falls vorhanden) einen Link zum Zurücksetzen.</div>
                </div>
                <button type="submit" class="btn btn-primary w-100"><i class="bi bi-envelope me-1"></i>Link anfordern</button>
              </form>
              <p class="text-center mt-3 mb-0"><a href="login.php">Zurück zur Anmeldung</a></p>
            <?php endif; ?>
          </div>
        </div>
      </div>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
  
</body>
</html>