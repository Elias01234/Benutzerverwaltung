<?php
// Datei: Passwort zurücksetzen mittels Token
// - Optional Logging fehlerhafter Tokenversuche
// - Session invalidieren / alle aktiven Sessions des Nutzers invalidieren (zusätzliche Tabelle nötig)
// - Passwort-Historie verhindern (optional)
// - Multi-Faktor-Authentifizierung nach Passwortwechsel erneut erzwingen (falls vorhanden)
session_start();
mysqli_report(MYSQLI_REPORT_OFF);
$conn = new mysqli('localhost', 'root', '', 'benutzerverwaltung');
$error = null; $done = false; $tokenValid = false; $showForm = false; $token = $_GET['token'] ?? '';
$userId = null; $username = null;
if ($conn->connect_error) {
    $error = 'Datenbankfehler.';
} else {
    $conn->set_charset('utf8mb4');
    $conn->select_db('benutzerverwaltung');
    if (!is_string($token) || strlen($token) < 64) {
        $error = 'Ungültiger oder fehlender Token.';
    } else {
        $tokenHash = hash('sha256', $token);
        // Token + Nutzer holen
        $sql = "SELECT prt.user_id, u.username FROM password_reset_tokens prt JOIN users u ON u.id = prt.user_id WHERE prt.token_hash = ? AND prt.consumed_at IS NULL AND prt.expires_at > NOW() LIMIT 1";
        if ($stmt = $conn->prepare($sql)) {
            $stmt->bind_param('s', $tokenHash);
            if ($stmt->execute() && ($res = $stmt->get_result()) && ($row = $res->fetch_assoc())) {
                $userId = (int)$row['user_id'];
                $username = $row['username'];
                $tokenValid = true;
            } else {
                $error = 'Dieser Link ist ungültig oder abgelaufen.';
            }
            $stmt->close();
        } else {
            $error = 'Aktion derzeit nicht möglich.';
        }
    }
    // Formular abgeschickt
    if ($tokenValid && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $pwd = $_POST['password'] ?? '';
        $pwd2 = $_POST['password_confirm'] ?? '';
        if (mb_strlen($pwd) < 8) {
            $error = 'Passwort muss mindestens 8 Zeichen lang sein.';
        } elseif (!hash_equals($pwd, $pwd2)) {
            $error = 'Passwörter stimmen nicht überein.';
        } else {
            $hash = password_hash($pwd, PASSWORD_DEFAULT);
            $conn->begin_transaction();
            try {
                if ($up = $conn->prepare('UPDATE users SET password = ? WHERE id = ? LIMIT 1')) {
                    $up->bind_param('si', $hash, $userId);
                    $up->execute();
                    if ($up->affected_rows !== 1) throw new Exception('Update fehlgeschlagen');
                    $up->close();
                } else { throw new Exception('Update prepare fehlgeschlagen'); }
                if ($cons = $conn->prepare('UPDATE password_reset_tokens SET consumed_at = NOW() WHERE token_hash = ? LIMIT 1')) {
                    $cons->bind_param('s', $tokenHash); $cons->execute(); $cons->close();
                }
                if ($clean = $conn->prepare('DELETE FROM password_reset_tokens WHERE user_id = ? AND consumed_at IS NULL')) { $clean->bind_param('i', $userId); $clean->execute(); $clean->close(); }
                $conn->commit();
                $done = true; $tokenValid = false;
            } catch (Throwable $e) {
                $conn->rollback();
                $error = 'Passwort konnte nicht gesetzt werden.';
            }
        }
    }
    $showForm = $tokenValid && !$done;
}
?>
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Passwort zurücksetzen</title>
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
            <h1 class="h4 mb-3">Passwort zurücksetzen</h1>
            <?php if($error): ?><div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div><?php endif; ?>
            <?php if($done): ?>
              <div class="alert alert-success" role="alert">Neues Passwort wurde gespeichert. Sie können sich jetzt anmelden.</div>
              <p><a href="login.php" class="btn btn-primary">Zum Login</a></p>
            <?php elseif($showForm): ?>
              <p class="text-muted mb-3">Konto: <strong><?= htmlspecialchars($username) ?></strong></p>
              <form method="post" novalidate>
                <div class="mb-3">
                  <label for="password" class="form-label">Neues Passwort</label>
                  <input type="password" class="form-control" id="password" name="password" required minlength="8" data-strength autocomplete="new-password">
                </div>
                <div class="mb-3">
                  <label for="password_confirm" class="form-label">Passwort bestätigen</label>
                  <input type="password" class="form-control" id="password_confirm" name="password_confirm" required minlength="8" autocomplete="new-password">
                </div>
                <button type="submit" class="btn btn-primary w-100"><i class="bi bi-key me-1"></i>Passwort setzen</button>
              </form>
            <?php else: ?>
              <?php if(!$error): ?><div class="alert alert-info">Bitte verwenden Sie den Link aus Ihrer E-Mail.</div><?php endif; ?>
              <p><a href="forgot_password.php">Neuen Link anfordern</a></p>
            <?php endif; ?>
          </div>
        </div>
      </div>
    </div>
  </div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js" integrity="sha512-+O0Z0H2cG+o3B7qZq9Uu4lI0d2hLrV8Q8Q+qkK0QWc7kKZkz9Jw1KQn2bDqgkD2c2VZQ0QmHnQy0z6Zl6k9b8g==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
  
  <script>
  // Passwort-Stärke (wie in anderen Seiten)
  (function(){
    function createMeter(input){
      const meter = document.createElement('div');
      meter.className = 'mt-1';
      meter.innerHTML = '<div class="progress" style="height:6px;" aria-hidden="true"><div class="progress-bar" role="progressbar" style="width:0%"></div></div><small class="form-text text-muted" aria-live="polite"></small>';
      input.after(meter); return meter;
    }
    function fallbackScore(pw){ let s=0; if(pw.length>=8)s++; if(pw.length>=12)s++; if(/[a-z]/.test(pw)&&/[A-Z]/.test(pw))s++; if(/\d/.test(pw))s++; if(/[^A-Za-z0-9]/.test(pw))s++; return s>4?4:s; }
    function updateMeter(inp,m){ const v=inp.value||''; const pb=m.querySelector('.progress-bar'); const t=m.querySelector('small'); if(!v){pb.style.width='0%';pb.className='progress-bar';t.textContent='';return;} let sc=0; try{ if(typeof zxcvbn==='function'){ const r=zxcvbn(v); sc= typeof r.score==='number'? r.score: fallbackScore(v);} else sc=fallbackScore(v);}catch(e){sc=fallbackScore(v);} const widths=[10,25,50,75,100]; const classes=['bg-danger','bg-danger','bg-warning','bg-info','bg-success']; pb.style.width=widths[sc]+'%'; pb.className='progress-bar '+classes[sc]; const labels=['Sehr schwach','Schwach','Okay','Gut','Sehr stark']; t.textContent='Passwortstärke: '+labels[sc]; }
    document.querySelectorAll('input[type="password"][data-strength]').forEach(function(inp){ const m=createMeter(inp); updateMeter(inp,m); inp.addEventListener('input', function(){updateMeter(inp,m);}); });
  })();
  </script>
</body>
</html>