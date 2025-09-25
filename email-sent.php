<?php
session_start();
$message = $_SESSION['flash_success'] ?? 'Wir haben Ihnen eine E-Mail gesendet. Bitte prüfen Sie Ihr Postfach.';
unset($_SESSION['flash_success']);
?>
<!doctype html>
<html lang="de">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>E-Mail gesendet</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
  </head>
  <body>
    <div class="container py-5 app-container">
      
      <div class="row justify-content-center">
        <div class="col-md-7 col-lg-6">
          <div class="card">
            <div class="card-body p-4 text-center">
              <i class="bi bi-envelope-check display-4 text-success"></i>
              <h1 class="h4 mt-3 mb-2">E-Mail gesendet</h1>
              <p class="text-muted mb-4"><?php echo htmlspecialchars($message); ?></p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
    
    <script></script>
  </body>
</html>