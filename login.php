<?php
// Datei: Login Formular + Verarbeitung
session_start();

// Statusvariablen
$success = null;
$error = null;
$oauthError = $_SESSION['oauth_error'] ?? null;
unset($_SESSION['oauth_error']);

// Flash aus Query
if (isset($_GET['registered'])) {
  $success = 'Registrierung erfolgreich. Bitte melden Sie sich an.';
}
if (isset($_GET['logged_out'])) {
  $success = 'Sie wurden abgemeldet.';
}

mysqli_report(MYSQLI_REPORT_OFF);
// DB-Verbindung (später DB wählen)
$conn = new mysqli('localhost', 'root', '', '');
if ($conn->connect_error) {
  $error = 'DB-Verbindung fehlgeschlagen.';
} else {
  $conn->set_charset('utf8mb4');
  $conn->select_db('benutzerverwaltung');
  
  // Formular abgeschickt?
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

  // Grundvalidierung
  if (mb_strlen($username) < 3 || mb_strlen($username) > 50 || mb_strlen($password) < 8) {
      $error = 'Ungültige Anmeldedaten.';
    } else {
    // Nutzer abrufen
    $stmt = $conn->prepare("SELECT id, username, password, role FROM users WHERE username = ? LIMIT 1");
      if (!$stmt) {
        $error = 'Anmeldung derzeit nicht möglich.';
      } else {
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $stmt->bind_result($id, $dbUser, $hash, $dbRole);
  if ($stmt->fetch() && password_verify($password, $hash)) { // Passwort prüfen
          session_regenerate_id(true); // Session erneuern
          $_SESSION['user_id'] = $id;
          $_SESSION['username'] = $dbUser;
          $_SESSION['role'] = $dbRole ?: 'user';
          $stmt->close();
          $conn->close();
          header('Location: index.php'); // Weiter zur Startseite
          exit;
        } else {
          $error = 'Ungültige Anmeldedaten.';
        }
        $stmt->close();
      }
    }
  }
}
?>
<!doctype html>
<html lang="de">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Anmelden</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
  </head>
  <body>
    <div class="container py-5 app-container">
      
      <div class="toast-container position-fixed top-0 end-0 p-3" id="toastContainer" role="region" aria-live="polite" aria-atomic="true"></div>
      <div class="row justify-content-center">
        <div class="col-md-7 col-lg-6">
          <div class="card">
            <div class="card-body p-4">
              <h1 class="h4 mb-3">Anmelden</h1>

              <?php if ($success || $error || $oauthError): ?>
                <div id="serverFlash" data-type="<?php echo $success ? 'success' : ($error || $oauthError ? 'danger' : 'info'); ?>" data-msg="<?php echo htmlspecialchars($success ?: ($error ?: $oauthError)); ?>" hidden></div>
              <?php endif; ?>

              <form class="needs-validation" novalidate method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
                <div class="mb-3">
                  <label for="username" class="form-label">Benutzername</label>
                  <input
                    type="text"
                    class="form-control"
                    id="username"
                    name="username"
                    required
                    minlength="3"
                    maxlength="50"
                    autocomplete="username"
                    value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>"
                  />
                  <div class="invalid-feedback">Benutzername benötigt.</div>
                </div>

                <div class="mb-1">
                  <label for="password" class="form-label">Passwort</label>
                  <input
                    type="password"
                    class="form-control"
                    id="password"
                    name="password"
                    required
                    minlength="8"
                    autocomplete="current-password"
                  />
                  <div class="invalid-feedback">Passwort benötigt.</div>
                </div>
                <div class="mb-3 text-end">
                  <a href="forgot_password.php" class="small">Passwort vergessen?</a>
                </div>
                <button type="submit" class="btn btn-primary w-100 mb-2">
                  <i class="bi bi-box-arrow-in-right me-1"></i>Anmelden
                </button>
              </form>

              <div class="text-center my-3 text-muted">oder</div>

              <a href="google_login.php" class="btn btn-outline-dark w-100">
                <img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" alt="Google" width="20" height="20" class="me-2"/>
                Mit Google anmelden
              </a>

              <p class="text-center mt-3 mb-0 text-muted">
                Noch kein Konto?
                <a href="register.php">Jetzt registrieren</a>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
  
  <script>
      function showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        const id = 't' + Date.now();
        const bg = type === 'success' ? 'bg-success' : (type === 'danger' ? 'bg-danger' : 'bg-info');
        const text = type === 'info' ? 'text-dark' : 'text-white';
        const wrapper = document.createElement('div');
        wrapper.innerHTML = `
          <div id="${id}" class="toast align-items-center ${bg} ${text} border-0" role="status" aria-live="assertive" aria-atomic="true" data-bs-delay="4500">
            <div class="d-flex">
              <div class="toast-body">${message}</div>
              <button type="button" class="btn-close ${type === 'info' ? '' : 'btn-close-white'} me-2 m-auto" data-bs-dismiss="toast" aria-label="Schließen"></button>
            </div>
          </div>`;
        const el = wrapper.firstElementChild;
        container.appendChild(el);
        const toast = new bootstrap.Toast(el);
        toast.show();
        el.addEventListener('hidden.bs.toast', () => el.remove());
      }
      (function(){ const n = document.getElementById('serverFlash'); if (n) showToast(n.dataset.msg || '', n.dataset.type || 'info'); })();
      (function(){ document.addEventListener('submit', function(e){ const btn = e.target.querySelector('[type="submit"]'); if (btn && !btn.dataset.loading) { btn.dataset.loading = '1'; btn.disabled = true; const original = btn.innerHTML; btn.dataset.original = original; btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Bitte warten…'; } }, true); })();
    </script>
  </body>
</html>