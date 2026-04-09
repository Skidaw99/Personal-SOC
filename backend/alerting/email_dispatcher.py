import aiosmtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from models.alert import FraudAlert, AlertCategory
from models.account import SocialAccount
from config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()

SEVERITY_COLORS = {
    "critical": "#FF2D2D",
    "high":     "#FF6B00",
    "medium":   "#F5A623",
    "low":      "#4A90E2",
    "info":     "#7B8794",
}

CATEGORY_ICONS = {
    AlertCategory.UNAUTHORIZED_LOGIN:  "🔐",
    AlertCategory.ACCOUNT_TAKEOVER:    "🚨",
    AlertCategory.API_TOKEN_MISUSE:    "🔑",
    AlertCategory.SUSPICIOUS_ACTIVITY: "⚠️",
}


def _build_html_email(alert: FraudAlert, account: SocialAccount) -> str:
    severity_label = _risk_to_severity_label(alert.risk_score)
    color = SEVERITY_COLORS.get(severity_label, "#7B8794")
    icon = CATEGORY_ICONS.get(alert.category, "⚠️")
    evidence_rows = ""
    if alert.evidence:
        for k, v in alert.evidence.items():
            evidence_rows += f"<tr><td style='padding:6px 12px;color:#9CA3AF;'>{k.replace('_',' ').title()}</td><td style='padding:6px 12px;color:#F9FAFB;'>{v}</td></tr>"

    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0F172A;font-family:'Courier New',monospace;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0F172A;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#1E293B;border-radius:12px;overflow:hidden;border:1px solid #334155;">
        <!-- Header -->
        <tr>
          <td style="background:{color};padding:24px 32px;">
            <p style="margin:0;color:#fff;font-size:11px;letter-spacing:3px;text-transform:uppercase;opacity:0.8;">Social Fraud Detector</p>
            <h1 style="margin:8px 0 0;color:#fff;font-size:22px;">{icon} {alert.title}</h1>
          </td>
        </tr>
        <!-- Meta -->
        <tr>
          <td style="padding:24px 32px;border-bottom:1px solid #334155;">
            <table width="100%">
              <tr>
                <td style="color:#9CA3AF;font-size:12px;">PLATFORM</td>
                <td style="color:#F9FAFB;font-size:12px;text-align:right;">{account.platform.value.upper()}</td>
              </tr>
              <tr>
                <td style="color:#9CA3AF;font-size:12px;">ACCOUNT</td>
                <td style="color:#F9FAFB;font-size:12px;text-align:right;">@{account.username}</td>
              </tr>
              <tr>
                <td style="color:#9CA3AF;font-size:12px;">RISK SCORE</td>
                <td style="color:{color};font-size:12px;text-align:right;font-weight:bold;">{alert.risk_score:.0f} / 100</td>
              </tr>
              <tr>
                <td style="color:#9CA3AF;font-size:12px;">DETECTED AT</td>
                <td style="color:#F9FAFB;font-size:12px;text-align:right;">{alert.created_at.strftime('%Y-%m-%d %H:%M UTC')}</td>
              </tr>
            </table>
          </td>
        </tr>
        <!-- Description -->
        <tr>
          <td style="padding:24px 32px;border-bottom:1px solid #334155;">
            <p style="margin:0 0 8px;color:#9CA3AF;font-size:11px;letter-spacing:2px;text-transform:uppercase;">What happened</p>
            <p style="margin:0;color:#F9FAFB;font-size:14px;line-height:1.6;">{alert.description}</p>
          </td>
        </tr>
        <!-- Evidence -->
        {f'''<tr><td style="padding:24px 32px;border-bottom:1px solid #334155;">
            <p style="margin:0 0 12px;color:#9CA3AF;font-size:11px;letter-spacing:2px;text-transform:uppercase;">Evidence</p>
            <table width="100%" style="border-collapse:collapse;">{evidence_rows}</table>
          </td></tr>''' if evidence_rows else ""}
        <!-- Recommended Action -->
        <tr>
          <td style="padding:24px 32px;border-bottom:1px solid #334155;background:#162032;">
            <p style="margin:0 0 8px;color:#9CA3AF;font-size:11px;letter-spacing:2px;text-transform:uppercase;">Recommended Action</p>
            <p style="margin:0;color:#F9FAFB;font-size:13px;line-height:1.8;white-space:pre-line;">{alert.recommended_action}</p>
          </td>
        </tr>
        <!-- Footer -->
        <tr>
          <td style="padding:16px 32px;">
            <p style="margin:0;color:#475569;font-size:11px;">Alert ID: {alert.id} — Social Fraud Detector © {datetime.utcnow().year}</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
"""


def _risk_to_severity_label(risk_score: float) -> str:
    if risk_score >= 75:
        return "critical"
    if risk_score >= 55:
        return "high"
    if risk_score >= 35:
        return "medium"
    if risk_score >= 15:
        return "low"
    return "info"


async def send_fraud_alert_email(alert: FraudAlert, account: SocialAccount) -> bool:
    """
    Dispatches a branded HTML fraud alert email via Gmail SMTP.
    Returns True on success, False on failure.
    """
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[FRAUD ALERT] {alert.title}"
        msg["From"] = settings.alert_from_email
        msg["To"] = settings.alert_to_email

        plain_text = (
            f"FRAUD ALERT: {alert.title}\n\n"
            f"Platform: {account.platform.value}\n"
            f"Account: @{account.username}\n"
            f"Risk Score: {alert.risk_score:.0f}/100\n"
            f"Detected: {alert.created_at.strftime('%Y-%m-%d %H:%M UTC')}\n\n"
            f"Description:\n{alert.description}\n\n"
            f"Recommended Action:\n{alert.recommended_action}\n\n"
            f"Alert ID: {alert.id}"
        )

        msg.attach(MIMEText(plain_text, "plain"))
        msg.attach(MIMEText(_build_html_email(alert, account), "html"))

        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password,
            start_tls=True,
        )

        logger.info("alert_email_sent", alert_id=str(alert.id), to=settings.alert_to_email)
        return True

    except Exception as e:
        logger.error("alert_email_failed", alert_id=str(alert.id), error=str(e))
        return False
