<?php
// Startseite / Dashboard: Benutzer anzeigen & CRUD Aktionen
session_start(); // Session für Login-Status / CSRF
require_once __DIR__ . '/mail.php'; // Mail-Funktionen

// Erstbesuch → Cookie setzen und zu Login leiten (Onboarding)
if (!isset($_SESSION['user_id'])) {
  if (empty($_COOKIE['first_visit_done'])) {
    setcookie('first_visit_done', '1', time() + 365*24*60*60, '/', '', false, true);
    header('Location: login.php', true, 302);
    exit;
  }
}


// Flash einmalig entnehmen
$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);

// Benutzerkontext
$username = $_SESSION['username'] ?? null;
$role = $_SESSION['role'] ?? 'user';
$isAdmin = ($role === 'admin');


mysqli_report(MYSQLI_REPORT_OFF); // Keine Exceptions
$dbError = null;
$conn = new mysqli('localhost', 'root', '', 'Benutzerverwaltung'); // Verbindung
if ($conn->connect_error) {
  $dbError = 'DB-Verbindung fehlgeschlagen.';
} else {
  $conn->set_charset('utf8mb4');
  if (!$conn->select_db('benutzerverwaltung')) {
    $dbError = 'Datenbank nicht gefunden.';
  }
}

// Falls noch kein Admin existiert: Ersten eingeloggten Nutzer hochstufen
if (!$dbError && isset($_SESSION['user_id'])) {
  $res = $conn->query("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'");
  if ($res && ($row = $res->fetch_assoc()) && (int)$row['c'] === 0) {
    $uid = (int)$_SESSION['user_id'];
    if ($stmt = $conn->prepare("UPDATE users SET role = 'admin' WHERE id = ? LIMIT 1")) {
      $stmt->bind_param('i', $uid);
      if ($stmt->execute()) {
        $_SESSION['role'] = 'admin';
        $_SESSION['flash'] = ['type' => 'success', 'msg' => 'Sie sind jetzt Admin (Erstkonfiguration).'];
      }
      $stmt->close();
    }
  }
}


// CSRF Token bereitstellen
if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_SESSION['user_id']) && !$dbError) {
  // CSRF prüfen
  if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
    $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Ungültiges Formular-Token.'];
    header('Location: index.php');
    exit;
  }

  $action = $_POST['action'] ?? '';

  // Benutzer erstellen
  if ($action === 'create_user') {
    if (!$isAdmin) { $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Nicht erlaubt.']; header('Location: index.php'); exit; }
    $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
    $uname = trim($_POST['username'] ?? '');
    $pwd = $_POST['password'] ?? '';
    $newRole = in_array($_POST['role'] ?? 'user', ['admin','user'], true) ? $_POST['role'] : 'user';

    if (!$email) {
      $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Ungültige E-Mail.'];
    } elseif (mb_strlen($uname) < 3 || mb_strlen($uname) > 50) {
      $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Benutzername 3–50 Zeichen.'];
    } elseif (mb_strlen($pwd) < 8) {
      $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Passwort mindestens 8 Zeichen.'];
    } else {
      $hash = password_hash($pwd, PASSWORD_DEFAULT);
      $stmt = $conn->prepare("INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, ?)");
      if ($stmt) {
        $stmt->bind_param('ssss', $email, $uname, $hash, $newRole);
        if ($stmt->execute()) {
          $_SESSION['flash'] = ['type' => 'success', 'msg' => 'Benutzer angelegt.'];
        } else {
          if ($conn->errno === 1062) {
            $dup = 'Eintrag bereits vorhanden.';
            if (strpos($conn->error, 'email') !== false) $dup = 'E-Mail bereits registriert.';
            if (strpos($conn->error, 'username') !== false) $dup = 'Benutzername bereits vergeben.';
            $_SESSION['flash'] = ['type' => 'danger', 'msg' => $dup];
          } else {
            $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Speichern fehlgeschlagen.'];
          }
        }
        $stmt->close();
      } else {
        $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Speichern derzeit nicht möglich.'];
      }
    }
    header('Location: index.php'); exit;
  }

  // Benutzer aktualisieren
  if ($action === 'update_user') {
    $id = (int)($_POST['id'] ?? 0);
    if (!$isAdmin && $id !== (int)$_SESSION['user_id']) { $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Nicht erlaubt.']; header('Location: index.php'); exit; }

    $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
    $uname = trim($_POST['username'] ?? '');
    $pwd = $_POST['password'] ?? '';
    $postedRole = $_POST['role'] ?? null;
    $newRole = $isAdmin && $postedRole && in_array($postedRole, ['admin','user'], true) ? $postedRole : null;

    if ($id <= 0) {
      $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Ungültige Benutzer-ID.'];
    } elseif (!$email) {
      $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Ungültige E-Mail.'];
    } elseif (mb_strlen($uname) < 3 || mb_strlen($uname) > 50) {
      $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Benutzername 3–50 Zeichen.'];
    } else {
      if ($pwd !== '') {
        if (mb_strlen($pwd) < 8) {
          $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Passwort mindestens 8 Zeichen.'];
          header('Location: index.php'); exit;
        }
        $hash = password_hash($pwd, PASSWORD_DEFAULT);
        if ($isAdmin && $newRole !== null) {
          $stmt = $conn->prepare("UPDATE users SET email = ?, username = ?, password = ?, role = ? WHERE id = ?");
          if ($stmt) $stmt->bind_param('ssssi', $email, $uname, $hash, $newRole, $id);
        } else {
          $stmt = $conn->prepare("UPDATE users SET email = ?, username = ?, password = ? WHERE id = ?");
          if ($stmt) $stmt->bind_param('sssi', $email, $uname, $hash, $id);
        }
      } else {
        if ($isAdmin && $newRole !== null) {
          $stmt = $conn->prepare("UPDATE users SET email = ?, username = ?, role = ? WHERE id = ?");
          if ($stmt) $stmt->bind_param('sssi', $email, $uname, $newRole, $id);
        } else {
          $stmt = $conn->prepare("UPDATE users SET email = ?, username = ? WHERE id = ?");
          if ($stmt) $stmt->bind_param('ssi', $email, $uname, $id);
        }
      }

      if ($stmt) {
        if ($stmt->execute()) {
          if ((int)$_SESSION['user_id'] === $id) {
            $_SESSION['username'] = $uname;
            // eigene Rolle nie aus Form übernehmen, nur wenn Admin sich selbst editiert
            if ($isAdmin && $newRole !== null) {
              $_SESSION['role'] = $newRole;
            }
          }
          $_SESSION['flash'] = ['type' => 'success', 'msg' => 'Benutzer aktualisiert.'];
        } else {
          if ($conn->errno === 1062) {
            $dup = 'Eintrag bereits vorhanden.';
            if (strpos($conn->error, 'email') !== false) $dup = 'E-Mail bereits registriert.';
            if (strpos($conn->error, 'username') !== false) $dup = 'Benutzername bereits vergeben.';
            $_SESSION['flash'] = ['type' => 'danger', 'msg' => $dup];
          } else {
            $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Aktualisierung fehlgeschlagen.'];
          }
        }
        $stmt->close();
      } else {
        $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Aktualisierung derzeit nicht möglich.'];
      }
    }
    header('Location: index.php'); exit;
  }

  // Benutzer löschen / Löschtoken versenden
  if ($action === 'delete_user') {
    $id = (int)($_POST['id'] ?? 0);
    if ($id <= 0) {
      $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Ungültige Benutzer-ID.'];
    } elseif ((int)$_SESSION['user_id'] === $id) {
      $stmt = $conn->prepare("SELECT email, username FROM users WHERE id = ?");
      if ($stmt) {
        $stmt->bind_param('i', $id);
        if ($stmt->execute() && ($res = $stmt->get_result()) && ($userRow = $res->fetch_assoc())) {
          $email = $userRow['email']; $uname = $userRow['username'];
          if ($delOld = $conn->prepare("DELETE FROM user_deletion_tokens WHERE user_id = ?")) {
            $delOld->bind_param('i', $id); $delOld->execute(); $delOld->close();
          }
          $token = bin2hex(random_bytes(32));
          $tokenHash = hash('sha256', $token);
          $stmtTok = $conn->prepare("INSERT INTO user_deletion_tokens (user_id, token_hash, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 24 HOUR))");
          if ($stmtTok) {
            $stmtTok->bind_param('is', $id, $tokenHash);
            if ($stmtTok->execute()) {
              $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
              $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
              $basePath = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
              $confirmUrl = $scheme . '://' . $host . $basePath . '/delete_confirm.php?token=' . urlencode($token);
              sendAccountDeletionConfirmationMail($email, $uname, $confirmUrl);
              $_SESSION['flash'] = ['type' => 'success', 'msg' => 'E-Mail zur Bestätigung der Löschung gesendet.'];
            } else {
              $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Löschbestätigung konnte nicht vorbereitet werden.'];
            }
            $stmtTok->close();
          } else {
            $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Löschbestätigung derzeit nicht möglich.'];
          }
        } else {
          $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Benutzer nicht gefunden.'];
        }
        $stmt->close();
      } else {
        $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Löschbestätigung derzeit nicht möglich.'];
      }
    } else {
      if ($isAdmin) {
        $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
        if ($stmt) {
          $stmt->bind_param('i', $id);
          $_SESSION['flash'] = $stmt->execute()
            ? ['type' => 'success', 'msg' => 'Benutzer gelöscht.']
            : ['type' => 'danger', 'msg' => 'Löschen fehlgeschlagen.'];
          $stmt->close();
        } else {
          $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Löschen derzeit nicht möglich.'];
        }
      } else {
        $_SESSION['flash'] = ['type' => 'danger', 'msg' => 'Nicht erlaubt.'];
      }
    }
    header('Location: index.php'); exit;
  }
}

// Nutzerliste laden (Admin = alle, sonst eigener Datensatz)
$users = [];
if ($username && !$dbError) {
  if ($isAdmin) {
    $res = $conn->query("SELECT id, email, username, role, created_at FROM users ORDER BY id DESC");
  } else {
    $uid = (int)$_SESSION['user_id'];
    $res = $conn->query("SELECT id, email, username, role, created_at FROM users WHERE id = {$uid} LIMIT 1");
  }
  if ($res) {
    while ($row = $res->fetch_assoc()) { $users[] = $row; }
    $res->free();
  }
}
require_once __DIR__ . '/mail.php';
?>
<!doctype html>
<html lang="de">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Startseite</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
  </head>
  <body>
    <div class="container py-5 app-container">
      <!-- Toast-Container für dynamische Feedbackmeldungen -->
      <div class="toast-container position-fixed top-0 end-0 p-3" id="toastContainer" role="region" aria-live="polite" aria-atomic="true"></div>
      <?php if ($flash): ?>
        <div id="serverFlash" data-type="<?php echo htmlspecialchars($flash['type']); ?>" data-msg="<?php echo htmlspecialchars($flash['msg']); ?>" hidden></div>
      <?php endif; ?>

      <?php if ($username): ?>
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h1 class="mb-0">
            Willkommen, <?php echo htmlspecialchars($username); ?>
            <span class="badge bg-<?php echo $isAdmin ? 'primary' : 'secondary'; ?> ms-2"><?php echo htmlspecialchars($role); ?></span>
          </h1>
          <div><a class="btn btn-secondary" href="logout.php">Abmelden</a></div>
        </div>

        <?php if ($dbError): ?>
          <div class="alert alert-danger" role="alert"><?php echo htmlspecialchars($dbError); ?></div>
        <?php else: ?>

          

          <?php if ($isAdmin): ?>
          <div class="card mb-4">
            <div class="card-header">Neuen Benutzer anlegen</div>
            <div class="card-body">
              <form method="post" class="row g-3">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf); ?>">
                <input type="hidden" name="action" value="create_user">
                <div class="col-md-3">
                  <label class="form-label">E-Mail</label>
                  <input type="email" name="email" class="form-control" required>
                </div>
                <div class="col-md-3">
                  <label class="form-label">Benutzername</label>
                  <input type="text" name="username" class="form-control" required minlength="3" maxlength="50">
                </div>
                <div class="col-md-3">
                  <label class="form-label">Passwort</label>
                  <input type="password" name="password" class="form-control" required minlength="8" data-strength>
                </div>
                <div class="col-md-3">
                  <label class="form-label">Rolle</label>
                  <select name="role" class="form-select" required>
                    <option value="user" selected>User</option>
                    <option value="admin">Admin</option>
                  </select>
                </div>
                <div class="col-12">
                  <button class="btn btn-primary" type="submit">Anlegen</button>
                </div>
              </form>
            </div>
          </div>
          <?php endif; ?>

          <div class="card">
            <div class="card-header">Benutzer verwalten</div>
            <div class="card-body p-0">
              <div class="table-responsive">
                <table class="table mb-0 align-middle">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>E-Mail</th>
                      <th>Benutzername</th>
                      <th>Rolle</th>
                      <th>Erstellt</th>
                      <th style="width: 260px;">Aktionen</th>
                    </tr>
                  </thead>
                  <tbody>
                    <?php if (empty($users)): ?>
                      <tr><td colspan="6" class="text-center p-4">Keine Benutzer vorhanden.</td></tr>
                    <?php else: ?>
                      <?php foreach ($users as $u): ?>
                        <tr>
                          <td><?php echo (int)$u['id']; ?></td>
                          <td><?php echo htmlspecialchars($u['email']); ?></td>
                          <td><?php echo htmlspecialchars($u['username']); ?></td>
                          <td><?php echo htmlspecialchars($u['role']); ?></td>
                          <td><?php echo htmlspecialchars($u['created_at']); ?></td>
                          <td>
                            <button class="btn btn-sm btn-outline-primary" type="button" data-bs-toggle="collapse" data-bs-target="#edit-<?php echo (int)$u['id']; ?>">Bearbeiten</button>
                            <form method="post" class="d-inline" onsubmit="return confirm('Diesen Benutzer wirklich löschen?');">
                              <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf); ?>">
                              <input type="hidden" name="action" value="delete_user">
                              <input type="hidden" name="id" value="<?php echo (int)$u['id']; ?>">
                              <button class="btn btn-sm btn-outline-danger" type="submit" <?php echo (!$isAdmin && (int)$u['id'] !== (int)$_SESSION['user_id']) ? 'disabled' : ''; ?>>Löschen</button>
                            </form>
                          </td>
                        </tr>
                        <tr class="collapse" id="edit-<?php echo (int)$u['id']; ?>">
                          <td colspan="6">
                            <!-- Bearbeitungsformular für Benutzer -->
                            <form method="post" class="row g-2 px-3 pb-3">
                              <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf); ?>">
                              <input type="hidden" name="action" value="update_user">
                              <input type="hidden" name="id" value="<?php echo (int)$u['id']; ?>">
                              <div class="col-md-3">
                                <label class="form-label">E-Mail</label>
                                <input type="email" name="email" class="form-control" required value="<?php echo htmlspecialchars($u['email']); ?>">
                              </div>
                              <div class="col-md-3">
                                <label class="form-label">Benutzername</label>
                                <input type="text" name="username" class="form-control" required minlength="3" maxlength="50" value="<?php echo htmlspecialchars($u['username']); ?>">
                              </div>
                              <div class="col-md-3">
                                <label class="form-label">Neues Passwort (optional)</label>
                                <input type="password" name="password" class="form-control" minlength="8" placeholder="leer lassen, um Passwort zu behalten" data-strength>
                              </div>
                              <?php if ($isAdmin): ?>
                              <div class="col-md-3">
                                <label class="form-label">Rolle</label>
                                <select name="role" class="form-select">
                                  <option value="user" <?php echo ($u['role'] === 'user') ? 'selected' : ''; ?>>User</option>
                                  <option value="admin" <?php echo ($u['role'] === 'admin') ? 'selected' : ''; ?>>Admin</option>
                                </select>
                              </div>
                              <?php endif; ?>
                              <div class="col-12">
                                <button class="btn btn-sm btn-primary" type="submit" <?php echo (!$isAdmin && (int)$u['id'] !== (int)$_SESSION['user_id']) ? 'disabled' : ''; ?>>Speichern</button>
                              </div>
                            </form>
                          </td>
                        </tr>
                      <?php endforeach; ?>
                    <?php endif; ?>
                  </tbody>
                </table>
              </div>
            </div>
          </div>

        <?php endif; ?>
      <?php else: ?>
        <h1 class="mb-3">Startseite</h1>
        <p class="mb-3">Sie sind nicht angemeldet.</p>
        <a class="btn btn-primary" href="login.php">Anmelden</a>
        <a class="btn btn-link" href="register.php">Registrieren</a>
      <?php endif; ?>
    </div>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js" integrity="sha512-+O0Z0H2cG+o3B7qZq9Uu4lI0d2hLrV8Q8Q+qkK0QWc7kKZkz9Jw1KQn2bDqgkD2c2VZQ0QmHnQy0z6Zl6k9b8g==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
  
  <script>
  // Toast-Helfer (Bootstrap)
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

  // Server-Flash in Toast verwandeln
      (function(){
        const node = document.getElementById('serverFlash');
        if (!node) return;
        showToast(node.dataset.msg || '', node.dataset.type || 'info');
      })();
  

  // Passwort-Stärkeanzeige (zxcvbn + Fallback)
      (function(){
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
        document.querySelectorAll('input[type="password"][data-strength]').forEach(function(inp){
          const meter = createMeter(inp);
          updateMeter(inp, meter);
          inp.addEventListener('input', function(){ updateMeter(inp, meter); });
          inp.addEventListener('change', function(){ updateMeter(inp, meter); });
        });
      })();
    </script>
  </body>
</html>
<?php if (isset($conn) && $conn instanceof mysqli) { $conn->close(); } ?>