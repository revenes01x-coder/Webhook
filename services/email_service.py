import logging
import smtplib
from datetime import datetime, timezone
from html import escape as html_escape
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid

from smartlpr.config import (
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_APP_PASSWORD, EMAIL_FROM_NAME, OTP_EXPIRE_MINUTES,
)

# ---------------------------------------------------------------------------
# Design tokens — จุดเดียวที่คุมหน้าตาอีเมลทั้งระบบ (สี/ชื่อแบรนด์/ข้อความ footer)
# แก้ธีมทีเดียวตรงนี้ ทุกอีเมลที่ส่งผ่าน _send_templated_email() จะเปลี่ยนตามหมด
# ---------------------------------------------------------------------------
_BRAND_NAME = EMAIL_FROM_NAME or "SmartLPR"
_FOOTER_NOTE = "อีเมลฉบับนี้ส่งโดยระบบอัตโนมัติ กรุณาอย่าตอบกลับอีเมลฉบับนี้โดยตรง"

# accent ใช้แยกโทนสีตามลักษณะเนื้อหา (แถบบน + หัวข้อ) ให้ผู้รับแยกความสำคัญได้ไวจากสีล้วนๆ
# ก่อนอ่านเนื้อหาเลยด้วยซ้ำ — brand=ปกติ/OTP, success=อนุมัติ-เปิดใช้งาน, danger=ปฏิเสธ-ระงับ,
# warning=แจ้งเตือนล่วงหน้า/ต้องระวัง
_ACCENT_COLORS = {
    "brand": "#2563EB",
    "success": "#16A34A",
    "danger": "#DC2626",
    "warning": "#D97706",
}

_TEXT_COLOR = "#0F172A"
_MUTED_COLOR = "#64748B"
_BORDER_COLOR = "#E2E8F0"
_BG_COLOR = "#F1F5F9"
_CARD_COLOR = "#FFFFFF"


def _esc(value: str) -> str:
    return html_escape(str(value))


def _render_html(
    heading: str,
    intro_lines: list[str],
    *,
    accent: str = "brand",
    highlight: str | None = None,
    highlight_caption: str | None = None,
    detail_rows: list[tuple[str, str]] | None = None,
    note_lines: list[str] | None = None,
    preheader: str | None = None,
) -> str:
    """
    Layout เดียวที่ทุกอีเมลในระบบใช้ร่วมกัน (table-based เพื่อความเข้ากันได้กับ email client
    ที่ยังไม่รองรับ CSS สมัยใหม่ เช่น Outlook desktop) ทุกค่าที่มาจากภายนอก (OTP, URL, เหตุผล
    ที่ admin กรอก ฯลฯ) ถูก escape รวมศูนย์ที่ฟังก์ชันนี้จุดเดียว — caller ส่ง raw string มาได้เลย
    ไม่ต้อง html_escape() เองที่ทุกจุดเรียก กันเคสลืม escape แล้วเกิด HTML injection หลุดไปที่
    บาง endpoint แต่ไม่หลุดที่บางอัน
    """
    accent_color = _ACCENT_COLORS.get(accent, _ACCENT_COLORS["brand"])
    year = datetime.now(timezone.utc).year
    preheader_text = _esc(preheader or (intro_lines[0] if intro_lines else heading))

    intro_html = "".join(
        f'<p style="margin:0 0 12px 0;font-size:15px;line-height:1.6;color:{_TEXT_COLOR};">{_esc(line)}</p>'
        for line in intro_lines
    )

    highlight_html = ""
    if highlight:
        caption_html = (
            f'<p style="margin:0 0 8px 0;font-size:13px;color:{_MUTED_COLOR};">{_esc(highlight_caption)}</p>'
            if highlight_caption else ""
        )
        highlight_html = f"""
        <div style="margin:20px 0;padding:20px;background:{_BG_COLOR};border-radius:10px;text-align:center;">
          {caption_html}
          <span style="font-size:32px;font-weight:700;letter-spacing:8px;color:{accent_color};font-family:'Courier New',monospace;">{_esc(highlight)}</span>
        </div>
        """

    detail_html = ""
    if detail_rows:
        rows = "".join(
            f"""
            <tr>
              <td style="padding:8px 0;font-size:14px;color:{_MUTED_COLOR};white-space:nowrap;vertical-align:top;">{_esc(label)}</td>
              <td style="padding:8px 0 8px 16px;font-size:14px;color:{_TEXT_COLOR};word-break:break-all;">{_esc(value)}</td>
            </tr>
            """
            for label, value in detail_rows
        )
        detail_html = f"""
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:16px 0;border-top:1px solid {_BORDER_COLOR};border-bottom:1px solid {_BORDER_COLOR};">
          {rows}
        </table>
        """

    note_html = "".join(
        f'<p style="margin:12px 0 0 0;font-size:14px;line-height:1.6;color:{_MUTED_COLOR};">{_esc(line)}</p>'
        for line in (note_lines or [])
    )

    return f"""\
<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(heading)}</title>
</head>
<body style="margin:0;padding:0;background:{_BG_COLOR};font-family:-apple-system,'Segoe UI',Roboto,'Sarabun',sans-serif;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;">{preheader_text}</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{_BG_COLOR};padding:32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:{_CARD_COLOR};border-radius:14px;overflow:hidden;box-shadow:0 1px 3px rgba(15,23,42,0.08);">
          <tr>
            <td style="height:6px;background:{accent_color};font-size:0;line-height:0;">&nbsp;</td>
          </tr>
          <tr>
            <td style="padding:28px 32px 8px 32px;">
              <p style="margin:0;font-size:13px;font-weight:700;letter-spacing:0.5px;color:{accent_color};text-transform:uppercase;">{_esc(_BRAND_NAME)}</p>
            </td>
          </tr>
          <tr>
            <td style="padding:8px 32px 0 32px;">
              <h1 style="margin:0 0 16px 0;font-size:20px;font-weight:700;color:{_TEXT_COLOR};">{_esc(heading)}</h1>
              {intro_html}
              {highlight_html}
              {detail_html}
              {note_html}
            </td>
          </tr>
          <tr>
            <td style="padding:28px 32px 32px 32px;">
              <p style="margin:0;font-size:12px;line-height:1.6;color:{_MUTED_COLOR};border-top:1px solid {_BORDER_COLOR};padding-top:16px;">
                {_esc(_FOOTER_NOTE)}<br>&copy; {year} {_esc(_BRAND_NAME)}
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""


def _render_plain_text(
    heading: str,
    intro_lines: list[str],
    *,
    highlight: str | None = None,
    highlight_caption: str | None = None,
    detail_rows: list[tuple[str, str]] | None = None,
    note_lines: list[str] | None = None,
) -> str:
    """เวอร์ชัน plain-text คู่กับ HTML เสมอทุกฉบับ (multipart/alternative) — ไม่ใช่แค่ความสวยงาม
    แต่เป็นมาตรฐานของอีเมลจริง: ลด spam score, รองรับ text-only client/screen reader, และเป็น
    fallback ให้อ่านได้ถ้า HTML renderer ของฝั่งผู้รับพังหรือถูกปิดไว้"""
    lines = [heading, "=" * len(heading), "", *intro_lines]

    if highlight:
        lines.append("")
        if highlight_caption:
            lines.append(highlight_caption)
        lines.append(highlight)

    if detail_rows:
        lines.append("")
        lines.extend(f"{label}: {value}" for label, value in detail_rows)

    if note_lines:
        lines.append("")
        lines.extend(note_lines)

    lines.extend(["", _FOOTER_NOTE])
    return "\n".join(lines)


def _send_email(to_email: str, subject: str, html_body: str, plain_body: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = formataddr((_BRAND_NAME, SMTP_USER))
    msg["To"] = to_email
    # Date + Message-ID: header มาตรฐานตาม RFC 5322 ที่อีเมล transactional ควรมีเสมอ (ช่วยเรื่อง
    # deliverability/spam score และทำให้ track ย้อนหลังใน mail log ได้ง่ายขึ้น) ของเดิมไม่มี 2 อันนี้
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=SMTP_HOST)

    # ลำดับสำคัญ: แนบ plain text ก่อน แล้วค่อย html (multipart/alternative ให้ client เลือกเวอร์ชัน
    # "ดีที่สุด" ที่ตัวเองรองรับ โดยเรียงจากธรรมดาสุด -> ริชสุด)
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        # ใช้ SMTP_SSL ตรง 465 ก็ได้ แต่ 587 + starttls() เป็นค่ามาตรฐานที่ Gmail รองรับดีสุด
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_APP_PASSWORD)
            server.sendmail(SMTP_USER, [to_email], msg.as_string())
    except smtplib.SMTPAuthenticationError as e:
        logging.error(f"Gmail SMTP auth ล้มเหลว (เช็ค SMTP_USER/SMTP_APP_PASSWORD): {e}")
        raise RuntimeError(
            "ส่งอีเมลไม่สำเร็จ: ยืนยันตัวตนกับ Gmail ไม่ผ่าน กรุณาตรวจสอบ App Password"
        ) from e
    except Exception as e:
        logging.error(f"ส่งอีเมลไปยัง {to_email} ไม่สำเร็จ: {e}")
        raise RuntimeError("ส่งอีเมลไม่สำเร็จ กรุณาลองใหม่อีกครั้ง") from e


def _send_templated_email(
    to_email: str,
    subject: str,
    heading: str,
    intro_lines: list[str],
    *,
    accent: str = "brand",
    highlight: str | None = None,
    highlight_caption: str | None = None,
    detail_rows: list[tuple[str, str]] | None = None,
    note_lines: list[str] | None = None,
) -> None:
    """จุดเดียวที่ฟังก์ชัน send_xxx_email() ด้านล่างทั้งหมดเรียกใช้ — ประกอบ HTML + plain text
    จาก template เดียวกันแล้วยิงออก กัน markup ของแต่ละอีเมลเพี้ยนไปคนละแบบเหมือนของเดิมที่แต่ละ
    ฟังก์ชันเขียน <div style="..."> ซ้ำเองทั้งหมด"""
    html_body = _render_html(
        heading, intro_lines, accent=accent, highlight=highlight,
        highlight_caption=highlight_caption, detail_rows=detail_rows, note_lines=note_lines,
    )
    plain_body = _render_plain_text(
        heading, intro_lines, highlight=highlight,
        highlight_caption=highlight_caption, detail_rows=detail_rows, note_lines=note_lines,
    )
    _send_email(to_email, subject, html_body, plain_body)


# ---------------------------------------------------------------------------
# Public API — signature เดิมทุกตัว (routers/auth.py, routers/admin.py, worker.py เรียกอยู่)
# ข้างในแค่ประกาศ "เนื้อหา" แล้วส่งให้ _send_templated_email() จัดการ markup ให้
# ---------------------------------------------------------------------------

def send_otp_email(to_email: str, otp: str) -> None:
    _send_templated_email(
        to_email,
        subject="รหัสยืนยันตัวตน (OTP) - SmartLPR",
        heading="ยืนยันตัวตนของคุณ",
        intro_lines=["กรุณาใช้รหัสด้านล่างเพื่อยืนยันตัวตนและเปิดใช้งานบัญชีของคุณ"],
        accent="brand",
        highlight=otp,
        highlight_caption=f"รหัสจะหมดอายุภายใน {OTP_EXPIRE_MINUTES} นาที",
        note_lines=["หากคุณไม่ได้เป็นผู้ทำรายการนี้ กรุณาเพิกเฉยต่ออีเมลฉบับนี้"],
    )


def send_password_reset_otp_email(to_email: str, otp: str) -> None:
    _send_templated_email(
        to_email,
        subject="รหัสยืนยันสำหรับตั้งรหัสผ่านใหม่ (OTP) - SmartLPR",
        heading="คำขอตั้งรหัสผ่านใหม่",
        intro_lines=["คุณได้ขอตั้งรหัสผ่านใหม่สำหรับบัญชี SmartLPR ของคุณ ใช้รหัสด้านล่างเพื่อยืนยันตัวตน"],
        accent="warning",
        highlight=otp,
        highlight_caption=f"รหัสจะหมดอายุภายใน {OTP_EXPIRE_MINUTES} นาที",
        note_lines=["หากคุณไม่ได้เป็นผู้ทำรายการนี้ กรุณาเพิกเฉยต่ออีเมลฉบับนี้ และรหัสผ่านของคุณจะไม่ถูกเปลี่ยนแปลง"],
    )


def send_access_approved_email(to_email: str) -> None:
    _send_templated_email(
        to_email,
        subject="คำขอใช้งานได้รับการอนุมัติแล้ว - SmartLPR",
        heading="คำขอใช้งานได้รับการอนุมัติ",
        intro_lines=[
            "คำขอใช้งานระบบ SmartLPR ของคุณได้รับการอนุมัติเรียบร้อยแล้ว",
            "ตอนนี้คุณสามารถเข้าสู่ระบบและตั้งค่า Webhook URL เพื่อรับข้อมูลป้ายทะเบียนได้ทันที",
        ],
        accent="success",
    )


def send_access_rejected_email(to_email: str, admin_note: str) -> None:
    _send_templated_email(
        to_email,
        subject="คำขอใช้งานไม่ได้รับการอนุมัติ - SmartLPR",
        heading="คำขอใช้งานไม่ได้รับการอนุมัติ",
        intro_lines=["ขออภัย คำขอใช้งานระบบ SmartLPR ของคุณไม่ได้รับการอนุมัติ"],
        accent="danger",
        detail_rows=[("เหตุผล", admin_note)],
        note_lines=["หากต้องการส่งคำขอใหม่ สามารถกรอกแบบฟอร์มขออนุญาตใช้งานได้อีกครั้ง"],
    )


def send_webhook_endpoint_unhealthy_email(to_email: str, target_url: str) -> None:
    _send_templated_email(
        to_email,
        subject="แจ้งเตือน: Webhook Endpoint ของท่านมีปัญหา - SmartLPR",
        heading="Webhook Endpoint มีปัญหา",
        intro_lines=["ระบบพยายามส่งข้อมูลไปยัง Webhook Endpoint ของท่านหลายครั้งแล้วแต่ไม่สำเร็จ"],
        accent="warning",
        detail_rows=[("URL ที่มีปัญหา", target_url)],
        note_lines=[
            "ระบบได้หยุดส่งข้อมูลไปยัง Endpoint นี้ชั่วคราว และจะทำการทดสอบเชื่อมต่อซ้ำให้อัตโนมัติทุก 30 นาที",
            "เมื่อ Endpoint ของท่านกลับมาใช้งานได้ปกติ ข้อมูลที่ค้างอยู่จะถูกส่งให้ทันทีโดยไม่ต้องดำเนินการใดๆ เพิ่มเติม",
            "กรุณาตรวจสอบว่าเซิร์ฟเวอร์ปลายทางของท่านทำงานปกติและตอบกลับ 200 OK ได้ภายในเวลาที่กำหนด",
        ],
    )


def send_account_suspended_email(to_email: str, reason: str | None) -> None:
    detail_rows = [("เหตุผล", reason)] if reason else None
    note_lines = [] if reason else ["ไม่มีการระบุเหตุผลเพิ่มเติม"]
    note_lines.extend([
        "ระหว่างที่ถูกระงับ ท่านจะไม่สามารถเพิ่ม Webhook Endpoint, ขอ/ออก API Key ใหม่, หรือ"
        "เพิ่มกล้องผ่าน API ได้ (ยังเข้าสู่ระบบและดูข้อมูลเดิมของท่านได้ตามปกติ)",
        "หากมีข้อสงสัย กรุณาติดต่อผู้ดูแลระบบเพื่อสอบถามรายละเอียดเพิ่มเติม",
    ])
    _send_templated_email(
        to_email,
        subject="แจ้งเตือน: บัญชีของท่านถูกระงับการใช้งานชั่วคราว - SmartLPR",
        heading="บัญชีถูกระงับการใช้งานชั่วคราว",
        intro_lines=["บัญชี SmartLPR ของท่านถูกผู้ดูแลระบบระงับการใช้งานชั่วคราว"],
        accent="danger",
        detail_rows=detail_rows,
        note_lines=note_lines,
    )


def send_account_unsuspended_email(to_email: str) -> None:
    _send_templated_email(
        to_email,
        subject="บัญชีของท่านกลับมาใช้งานได้ตามปกติแล้ว - SmartLPR",
        heading="บัญชีกลับมาใช้งานได้ตามปกติ",
        intro_lines=["บัญชี SmartLPR ของท่านถูกปลดระงับแล้ว และสามารถใช้งานทุกฟังก์ชันได้ตามปกติ"],
        accent="success",
        note_lines=["หากมีข้อสงสัย กรุณาติดต่อผู้ดูแลระบบเพื่อสอบถามรายละเอียดเพิ่มเติม"],
    )


def send_webhook_disabled_email(to_email: str, target_url: str, reason: str | None) -> None:
    detail_rows = [("URL", target_url)]
    if reason:
        detail_rows.append(("เหตุผล", reason))

    note_lines = [] if reason else ["ไม่มีการระบุเหตุผลเพิ่มเติม"]
    note_lines.extend([
        "ระหว่างที่ถูกปิดใช้งาน ระบบจะไม่ส่งข้อมูลป้ายทะเบียนใหม่ไปยัง endpoint นี้ จะหยุดส่งข้อมูลที่ค้างอยู่ในคิว"
        "ชั่วคราว (ข้อมูลจะไม่หายไปไหน จะถูกส่งต่อเมื่อเปิดใช้งานอีกครั้ง) และกล้องทุกตัวที่ผูกกับ endpoint นี้"
        "จะหยุดทำงานชั่วคราวด้วยเช่นกัน",
        "หากมีข้อสงสัย กรุณาติดต่อผู้ดูแลระบบเพื่อสอบถามรายละเอียดเพิ่มเติม",
    ])
    _send_templated_email(
        to_email,
        subject="แจ้งเตือน: Webhook Endpoint ของท่านถูกปิดใช้งานโดยผู้ดูแลระบบ - SmartLPR",
        heading="Webhook Endpoint ถูกปิดใช้งาน",
        intro_lines=["Webhook Endpoint ต่อไปนี้ของท่านถูกผู้ดูแลระบบปิดใช้งานชั่วคราว"],
        accent="danger",
        detail_rows=detail_rows,
        note_lines=note_lines,
    )


def send_webhook_enabled_email(to_email: str, target_url: str) -> None:
    _send_templated_email(
        to_email,
        subject="Webhook Endpoint ของท่านกลับมาใช้งานได้ตามปกติแล้ว - SmartLPR",
        heading="Webhook Endpoint กลับมาใช้งานได้แล้ว",
        intro_lines=["Webhook Endpoint ต่อไปนี้ของท่านถูกผู้ดูแลระบบเปิดใช้งานกลับมาแล้ว"],
        accent="success",
        detail_rows=[("URL", target_url)],
        note_lines=[
            "ระบบจะเริ่มส่งข้อมูลป้ายทะเบียนไปยัง endpoint นี้ตามปกติ รวมถึงข้อมูลที่ค้างอยู่ในคิวระหว่างที่ถูก"
            "ปิดใช้งานด้วย และกล้องที่ผูกกับ endpoint นี้จะกลับมาทำงานเองโดยอัตโนมัติเช่นกัน",
            "หากมีข้อสงสัย กรุณาติดต่อผู้ดูแลระบบเพื่อสอบถามรายละเอียดเพิ่มเติม",
        ],
    )


def send_password_changed_email(to_email: str) -> None:
    _send_templated_email(
        to_email,
        subject="แจ้งเตือน: รหัสผ่านบัญชีของท่านถูกเปลี่ยนแปลง - SmartLPR",
        heading="รหัสผ่านถูกเปลี่ยนแปลง",
        intro_lines=[
            "รหัสผ่านสำหรับเข้าสู่ระบบ SmartLPR ของท่านเพิ่งถูกเปลี่ยนแปลงสำเร็จผ่านขั้นตอนลืมรหัสผ่าน",
            "เพื่อความปลอดภัย ระบบได้บังคับให้ทุกอุปกรณ์ที่เคยเข้าสู่ระบบไว้ต้องเข้าสู่ระบบใหม่อีกครั้ง",
        ],
        accent="danger",
        note_lines=["หากท่านไม่ได้เป็นผู้ทำรายการนี้ กรุณาติดต่อผู้ดูแลระบบทันที เนื่องจากอาจมีบุคคลอื่นเข้าถึงอีเมลหรือบัญชีของท่านโดยไม่ได้รับอนุญาต"],
    )