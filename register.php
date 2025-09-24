<?php
// Registrierung: Validierung, Benutzer speichern, Mail senden
session_start(); // Session für Flash / spätere Nutzung
require_once __DIR__ . '/config.php'; // Basis-Konfiguration / Konstanten
require_once __DIR__ . '/mail.php'; // Mail-Helfer

$success = null; // Erfolgstext (derzeit ungenutzt, Platzhalter)
$error = null;   // Fehlermeldung für Ausgabe

mysqli_report(MYSQLI_REPORT_OFF);

// DB verbinden
$conn = new mysqli('localhost', 'root', '', 'benutzerverwaltung');
if ($conn->connect_error) {
  $error = 'DB-Verbindung fehlgeschlagen.';
} else {
  $conn->set_charset('utf8mb4');

  // Datenbank & Tabelle sicherstellen
  if (!$conn->query("CREATE DATABASE IF NOT EXISTS benutzerverwaltung DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")) {
    $error = 'Datenbank konnte nicht erstellt/ausgewählt werden.';
  } elseif (!$conn->select_db('benutzerverwaltung')) {
    $error = 'Datenbank konnte nicht ausgewählt werden.';
  } else {
    $createSql = "
      CREATE TABLE IF NOT EXISTS users (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role ENUM('admin','user') NOT NULL DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
    ";
    if (!$conn->query($createSql)) {
      $error = 'Tabelle users konnte nicht erstellt werden.';
    } else {
      // POST prüfen (Formular abgeschickt?)
      if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Eingaben holen + validieren
        $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if (!$email) {
          $error = 'Ungültige E-Mail.';
        } elseif (mb_strlen($username) < 3 || mb_strlen($username) > 50) {
          $error = 'Benutzername muss 3 bis 50 Zeichen lang sein.';
        } elseif (mb_strlen($password) < 8) {
          $error = 'Passwort muss min. 8 Zeichen lang sein.';
        } else {
          // Passwort hashen + vorbereiten
          $hash = password_hash($password, PASSWORD_DEFAULT);

          // Einfügen vorbereiten
          $stmt = $conn->prepare("INSERT INTO users (email, username, password) VALUES (?, ?, ?)");
          if (!$stmt) {
            $error = 'Fehler beim Speichern.';
          } else {
            $stmt->bind_param('sss', $email, $username, $hash);
            if ($stmt->execute()) {
              // Login-Link (Info-Mail) erstellen
              $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
              $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
              $basePath = rtrim(dirname($_SERVER['REQUEST_URI']), '/\\');
              $loginUrl = $scheme . '://' . $host . $basePath . '/login.php';

              // Mail senden (Fehler nur loggen)
              try {
                sendLoginMail($email, $username, $loginUrl);
              } catch (Throwable $e) {
                error_log('Mailversand fehlgeschlagen: ' . $e->getMessage());
              }

              // Erfolg → Weiterleitung mit Hinweis
              $_SESSION['flash_success'] = 'Wir haben Ihnen eine E-Mail mit einem Link gesendet. Bitte prüfen Sie Ihr Postfach (ggf. Spam-Ordner).';
              header('Location: email-sent.php');
              exit;
            } else {
              // Duplicate / generischer Fehler
              if ($conn->errno === 1062) {
                $dupMsg = 'Eintrag bereits vorhanden.';
                if (strpos($conn->error, 'email') !== false) {
                  $dupMsg = 'Diese E-Mail ist bereits registriert.';
                } elseif (strpos($conn->error, 'username') !== false) {
                  $dupMsg = 'Dieser Benutzername ist bereits vergeben.';
                }
                $error = $dupMsg;
              } else {
                $error = 'Fehler beim Speichern.';
              }
            }
            $stmt->close();
          }
        }
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
    <title>Registrieren</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
  </head>
  <body>
    <div class="container py-5 app-container">
      <!-- Toast-Container für dynamische Meldungen -->
      <div class="toast-container position-fixed top-0 end-0 p-3" id="toastContainer" role="region" aria-live="polite" aria-atomic="true"></div>
      <div class="row justify-content-center">
        <div class="col-md-7 col-lg-6">
          <div class="card">
            <div class="card-body p-4">
              <h1 class="h4 mb-3">Registrieren</h1>

              <?php if ($success || $error): ?>
                <!-- Server-Flash (wird via JS als Toast gezeigt) -->
                <div id="serverFlash" data-type="<?php echo $success ? 'success' : 'danger'; ?>" data-msg="<?php echo htmlspecialchars($success ?: $error); ?>" hidden></div>
              <?php endif; ?>

              <!-- Registrierungsformular -->
              <form class="needs-validation" novalidate method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
                <div class="mb-3">
                  <label for="email" class="form-label">E-Mail</label>
                  <input
                    type="email"
                    class="form-control"
                    id="email"
                    name="email"
                    required
                    autocomplete="email"
                    pattern="[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+"
                    title="Bitte eine gültige E‑Mail-Adresse eingeben (z. B. name@domain.tld)."
                    value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>"
                  />
                  <div class="invalid-feedback">Bitte eine gültige E‑Mail-Adresse im Format name@domain.tld eingeben.</div>
                </div>

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
                  <div class="invalid-feedback">Benutzername muss 3 bis 50 Zeichen lang sein.</div>
                </div>

                <div class="mb-3">
                  <label for="password" class="form-label">Passwort</label>
                  <input
                    type="password"
                    class="form-control"
                    id="password"
                    name="password"
                    required
                    minlength="8"
                    pattern="(?=.*[a-z])(?=.*[A-Z]).{8,}"
                    title="Mindestens 8 Zeichen"
                    autocomplete="new-password"
                    data-strength
                  />
                  <div class="invalid-feedback">Mindestens 8 Zeichen</div>
                </div>

                <button type="submit" class="btn btn-primary w-100">
                  <i class="bi bi-person-plus me-1"></i>Registrieren
                </button>
              </form>

              <?php if (defined('GOOGLE_CLIENT_ID') && GOOGLE_CLIENT_ID !== '' && defined('GOOGLE_CLIENT_SECRET') && GOOGLE_CLIENT_SECRET !== ''): // Google-Button nur wenn OAuth konfiguriert ?>
                <div class="text-center my-3 text-muted">oder</div>
                <a href="google_login.php" class="btn btn-outline-dark w-100">
                  <img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" alt="Google" width="20" height="20" class="me-2"/>
                  Mit Google registrieren
                </a>
              <?php endif; ?>

              <p class="text-center mt-3 mb-0 text-muted">
                Schon ein Konto?
                <a href="login.php">Jetzt anmelden</a>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js" integrity="sha512-+O0Z0H2cG+o3B7qZq9Uu4lI0d2hLrV8Q8Q+qkK0QWc7kKZkz9Jw1KQn2bDqgkD2c2VZQ0QmHnQy0z6Zl6k9b8g==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
  <script>
      // Toast-Helfer + sofortige Anzeige von Server-Flash
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
      (function(){ const n = document.getElementById('serverFlash'); if (n) showToast(n.dataset.msg || '', n.dataset.type || 'info'); })(); // Server-Flash
      (function(){ // Submit-Button Sperre
        document.addEventListener('submit', function(e){ const btn = e.target.querySelector('[type="submit"]'); if (btn && !btn.dataset.loading) { btn.dataset.loading = '1'; btn.disabled = true; const original = btn.innerHTML; btn.dataset.original = original; btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Bitte warten…'; } }, true);
      })();
      (function(){ // Passwort-Stärke-Anzeige
        function createMeter(input){
          const meter = document.createElement('div');
          meter.className = 'mt-1';
          meter.innerHTML = '<div class="progress" style="height:6px;" aria-hidden="true">\
                               <div class="progress-bar" role="progressbar" style="width:0%"></div>\
                             </div>\
                             <small class="form-text text-muted" aria-live="polite"></small>';
          input.after(meter);
          return meter;
        }
        // Simple local fallback scorer when zxcvbn is unavailable
        function fallbackScore(pw){
          let score = 0;
          const len = pw.length;
          const hasLower = /[a-z]/.test(pw);
          const hasUpper = /[A-Z]/.test(pw);
          const hasDigit = /\d/.test(pw);
          const hasSymbol = /[^A-Za-z0-9]/.test(pw);
          if (len >= 8) score++;
          if (len >= 12) score++;
          if (hasLower && hasUpper) score++;
          if (hasDigit) score++;
          if (hasSymbol) score++;
          if (score > 4) score = 4;
          return score;
        }
        function updateMeter(input, meter){
          const val = input.value || '';
          const pb = meter.querySelector('.progress-bar');
          const txt = meter.querySelector('small');
          if (!val){ pb.style.width = '0%'; pb.className = 'progress-bar'; txt.textContent = ''; return; }
          let score = 0;
          try {
            if (typeof zxcvbn === 'function') {
              const res = zxcvbn(val);
              if (res && typeof res.score === 'number') score = res.score; else score = fallbackScore(val);
            } else {
              score = fallbackScore(val);
            }
          } catch(e){ score = fallbackScore(val); }
          const widths = [10,25,50,75,100];
          const classes = ['bg-danger','bg-danger','bg-warning','bg-info','bg-success'];
          pb.style.width = widths[score] + '%';
          pb.className = 'progress-bar ' + classes[score];
          const labels = ['Sehr schwach','Schwach','Okay','Gut','Sehr stark'];
          txt.textContent = 'Passwortstärke: ' + labels[score];
        }
        document.querySelectorAll('input[type="password"][data-strength]').forEach(function(inp){ // Init für alle Passwortfelder
          const meter = createMeter(inp);
          updateMeter(inp, meter);
          inp.addEventListener('input', function(){ updateMeter(inp, meter); });
          inp.addEventListener('change', function(){ updateMeter(inp, meter); });
        });
      })();
    </script>
  </body>
</html>