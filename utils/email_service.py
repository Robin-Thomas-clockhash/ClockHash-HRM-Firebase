"""
Email service for sending salary slip decryption passwords.

Uses Gmail SMTP with an App Password so credentials never leave the server.
The password is only sent over TLS and is never logged or returned via API.
"""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587  # STARTTLS

EMAIL_SUBJECT = "Your ClockHash Salary Slip Decryption Password"

EMAIL_BODY_PLAIN = """\
Dear Employee,

Your salary slip decryption password is ready.

Password: {password}

Please use this password to open your encrypted salary slip PDF.
Keep this password confidential and do not share it with anyone.

If you did not request this, please contact your HR administrator immediately.

Regards,
ClockHash HR Team
"""

EMAIL_BODY_HTML = """\
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <style>
    body {{ font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; }}
    .container {{ max-width: 560px; margin: 40px auto; background: #ffffff;
                  border-radius: 8px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
    .header {{ font-size: 20px; font-weight: bold; color: #1a1a2e; margin-bottom: 16px; }}
    .password-box {{ background: #f0f4ff; border: 1px solid #c7d3f7;
                     border-radius: 6px; padding: 16px; margin: 24px 0;
                     text-align: center; }}
    .password-label {{ font-size: 12px; color: #666; margin-bottom: 6px; }}
    .password-value {{ font-size: 22px; font-weight: bold; letter-spacing: 2px;
                       color: #2c51e0; font-family: monospace; }}
    .note {{ font-size: 13px; color: #555; margin-top: 20px; }}
    .footer {{ margin-top: 32px; font-size: 12px; color: #999; border-top: 1px solid #eee;
               padding-top: 16px; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">&#128274; Salary Slip Decryption Password</div>
    <p>Dear Employee,</p>
    <p>Your salary slip decryption password has been generated. Use this password to open your encrypted salary slip PDF.</p>
    <div class="password-box">
      <div class="password-label">YOUR PASSWORD</div>
      <div class="password-value">{password}</div>
    </div>
    <p class="note">&#x26A0;&#xFE0F; <strong>Keep this password confidential.</strong> Do not share it with anyone. If you did not request this, please contact your HR administrator immediately.</p>
    <div class="footer">
      Regards,<br/>
      <strong>ClockHash HR Team</strong><br/>
      This is an automated message &mdash; please do not reply to this email.
    </div>
  </div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def send_password_email(
    *,
    recipient_email: str,
    employee_id: str,
    password: str,
    smtp_user: str,
    smtp_password: str,
) -> None:
    """
    Send the decryption password to *recipient_email* via Gmail SMTP (STARTTLS).

    Args:
        recipient_email: Destination email address.
        employee_id:     Used only for logging (password value is never logged).
        password:        The plaintext decryption password to embed in the email.
        smtp_user:       Gmail address used as sender (noreply@clockhash.com).
        smtp_password:   Gmail App Password for smtp_user.

    Raises:
        RuntimeError: If the email cannot be sent (SMTP error, auth failure, etc.)
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = EMAIL_SUBJECT
    msg["From"] = f"ClockHash HRM <{smtp_user}>"
    msg["To"] = recipient_email

    plain_part = MIMEText(
        EMAIL_BODY_PLAIN.format(password=password), "plain", "utf-8"
    )
    html_part = MIMEText(
        EMAIL_BODY_HTML.format(password=password), "html", "utf-8"
    )

    # Clients try the last MIME part first — prefer HTML
    msg.attach(plain_part)
    msg.attach(html_part)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, [recipient_email], msg.as_bytes())

        # ⚠️  Do NOT log the password value
        logger.info(
            "Password email sent for employee_id=%s to=%s",
            employee_id, recipient_email,
        )

    except smtplib.SMTPAuthenticationError as exc:
        logger.error("SMTP authentication failed: %s", exc)
        raise RuntimeError("Email authentication failed. Check SMTP credentials.") from exc

    except smtplib.SMTPException as exc:
        logger.error("SMTP error while sending password email: %s", exc)
        raise RuntimeError(f"Failed to send email: {exc}") from exc

    except Exception as exc:
        logger.error("Unexpected error sending password email: %s", exc)
        raise RuntimeError(f"Email delivery error: {exc}") from exc
