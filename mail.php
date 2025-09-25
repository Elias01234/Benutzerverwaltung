<?php
// Datei: Mailversand (Login & Löschbestätigung)

// sendLoginMail: Hinweis nach Registrierung
function sendLoginMail(string $toEmail, string $toName, string $loginUrl): void {
    $subject = 'Registrierung erfolgreich'; // Betreff
    // Text
    $body  = "Hallo {$toName},\n\n";
    $body .= "vielen Dank für Ihre Registrierung.\n\n";
    $body .= "Sie können sich hier anmelden:\n{$loginUrl}\n\n";
    // Header
    $headers = 'From: Benutzerverwaltung <noreply@Benutzerverwaltung.at>' . "\r\n" .
               'Reply-To: noreply@Benutzerverwaltung.at' . "\r\n" .
               'Content-Type: text/plain; charset=UTF-8' . "\r\n" .
               'X-Mailer: PHP/' . phpversion();
    // Versand
    if (!@mail($toEmail, $subject, $body, $headers)) {
        error_log("E-Mail-Versand an {$toEmail} mit mail() fehlgeschlagen.");
    }
}

// sendAccountDeletionConfirmationMail: Bestätigungslink für Konto-Löschung
function sendAccountDeletionConfirmationMail(string $toEmail, string $toName, string $confirmUrl): void {
    $subject = 'Bestätigung: Benutzerkonto löschen'; // Betreff
    // Text
    $body  = "Hallo {$toName},\n\n";
    $body .= "Sie haben das Löschen Ihres Benutzerkontos angefordert.\n";
    $body .= "Wenn Sie das wirklich möchten, bestätigen Sie den Vorgang über folgenden Link:\n";
    $body .= "{$confirmUrl}\n\n";
    $body .= "Hinweis: Der Link ist 24 Stunden lang gültig. Wenn Sie diese Aktion nicht ausgelöst haben, ignorieren Sie diese E-Mail.\n";
    // Header
    $headers = 'From: Benutzerverwaltung <noreply@Benutzerverwaltung.at>' . "\r\n" .
               'Reply-To: noreply@Benutzerverwaltung.at' . "\r\n" .
               'Content-Type: text/plain; charset=UTF-8' . "\r\n" .
               'X-Mailer: PHP/' . phpversion();
    // Versand
    if (!@mail($toEmail, $subject, $body, $headers)) {
        error_log("E-Mail-Versand (Account-Löschbestätigung) an {$toEmail} fehlgeschlagen.");
    }
}

// sendPasswordResetMail: Link zum Zurücksetzen des Passworts
function sendPasswordResetMail(string $toEmail, string $toName, string $resetUrl): void {
    $subject = 'Passwort zurücksetzen';
    $body  = "Hallo {$toName},\n\n";
    $body .= "für Ihr Konto wurde ein Zurücksetzen des Passworts angefordert.\n";
    $body .= "Sie können ein neues Passwort vergeben, indem Sie diesen Link öffnen:\n{$resetUrl}\n\n";
    $body .= "Wenn Sie dies nicht angefordert haben, ignorieren Sie diese E-Mail einfach. Der Link verfällt nach 60 Minuten.\n";
    $headers = 'From: Benutzerverwaltung <noreply@Benutzerverwaltung.at>' . "\r\n" .
               'Reply-To: noreply@Benutzerverwaltung.at' . "\r\n" .
               'Content-Type: text/plain; charset=UTF-8' . "\r\n" .
               'X-Mailer: PHP/' . phpversion();
    if (!@mail($toEmail, $subject, $body, $headers)) {
        error_log("E-Mail-Versand (Passwort-Reset) an {$toEmail} fehlgeschlagen.");
    }
}