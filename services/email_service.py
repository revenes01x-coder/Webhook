import logging
import smtplib
from html import escape as html_escape
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from smartlpr.config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_APP_PASSWORD, EMAIL_FROM_NAME, OTP_EXPIRE_MINUTES


def _send_email(to_email: str, subject: str, html_body: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{EMAIL_FROM_NAME} <{SMTP_USER}>"
    msg["To"] = to_email
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


def send_otp_email(to_email: str, otp: str) -> None:
    subject = "รหัสยืนยันตัวตน (OTP) - SmartLPR"
    html = f"""
    <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
      <p>รหัสยืนยันตัวตน (OTP) ของคุณคือ</p>
      <p style="font-size: 32px; font-weight: bold; letter-spacing: 6px;">{otp}</p>
      <p>รหัสนี้จะหมดอายุภายใน {OTP_EXPIRE_MINUTES} นาที</p>
      <p>หากคุณไม่ได้เป็นผู้ทำรายการนี้ กรุณาเพิกเฉยต่ออีเมลฉบับนี้</p>
    </div>
    """
    _send_email(to_email, subject, html)


def send_password_reset_otp_email(to_email: str, otp: str) -> None:
    subject = "รหัสยืนยันสำหรับตั้งรหัสผ่านใหม่ (OTP) - SmartLPR"
    html = f"""
    <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
      <p>คุณได้ขอตั้งรหัสผ่านใหม่สำหรับบัญชี SmartLPR ของคุณ</p>
      <p>รหัสยืนยันตัวตน (OTP) ของคุณคือ</p>
      <p style="font-size: 32px; font-weight: bold; letter-spacing: 6px;">{otp}</p>
      <p>รหัสนี้จะหมดอายุภายใน {OTP_EXPIRE_MINUTES} นาที</p>
      <p>หากคุณไม่ได้เป็นผู้ทำรายการนี้ กรุณาเพิกเฉยต่ออีเมลฉบับนี้ และรหัสผ่านของคุณจะไม่ถูกเปลี่ยนแปลง</p>
    </div>
    """
    _send_email(to_email, subject, html)


def send_access_approved_email(to_email: str) -> None:
    subject = "คำขอใช้งานได้รับการอนุมัติแล้ว - SmartLPR"
    html = """
    <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
      <p>คำขอใช้งานระบบ SmartLPR ของคุณได้รับการอนุมัติเรียบร้อยแล้ว</p>
      <p>ตอนนี้คุณสามารถเข้าสู่ระบบและตั้งค่า Webhook URL เพื่อรับข้อมูลป้ายทะเบียนได้ทันที</p>
    </div>
    """
    _send_email(to_email, subject, html)


def send_access_rejected_email(to_email: str, admin_note: str) -> None:
    subject = "คำขอใช้งานไม่ได้รับการอนุมัติ - SmartLPR"
    # admin_note เป็นข้อความอิสระที่แอดมินพิมพ์เอง escape ก่อนใส่ลง HTML กัน injection
    safe_note = html_escape(admin_note)
    html = f"""
    <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
      <p>ขออภัย คำขอใช้งานระบบ SmartLPR ของคุณไม่ได้รับการอนุมัติ</p>
      <p><strong>เหตุผล:</strong> {safe_note}</p>
      <p>หากต้องการส่งคำขอใหม่ สามารถกรอกแบบฟอร์มขออนุญาตใช้งานได้อีกครั้ง</p>
    </div>
    """
    _send_email(to_email, subject, html)

def send_webhook_endpoint_unhealthy_email(to_email: str, target_url: str) -> None:

    subject = "แจ้งเตือน: Webhook Endpoint ของท่านมีปัญหา - SmartLPR"
    safe_url = html_escape(target_url)
    html = f"""
    <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
      <p>ระบบพยายามส่งข้อมูลไปยัง Webhook Endpoint ของท่านหลายครั้งแล้วแต่ไม่สำเร็จ</p>
      <p><strong>URL ที่มีปัญหา:</strong> {safe_url}</p>
      <p>ระบบได้หยุดส่งข้อมูลไปยัง Endpoint นี้ชั่วคราว และจะทำการทดสอบเชื่อมต่อซ้ำให้อัตโนมัติทุก 30 นาที</p>
      <p>เมื่อ Endpoint ของท่านกลับมาใช้งานได้ปกติ ข้อมูลที่ค้างอยู่จะถูกส่งให้ทันทีโดยไม่ต้องดำเนินการใดๆ เพิ่มเติม</p>
      <p>กรุณาตรวจสอบว่าเซิร์ฟเวอร์ปลายทางของท่านทำงานปกติและตอบกลับ 200 OK ได้ภายในเวลาที่กำหนด</p>
    </div>
    """
    _send_email(to_email, subject, html)


def send_account_suspended_email(to_email: str, reason: str | None) -> None:
    """แจ้ง user ว่าบัญชีถูกระงับ พร้อมเหตุผลถ้า admin ระบุมา (ไม่ระบุ -> ข้อความกลางๆ)
    เรียกจาก routers/admin.py: set_user_suspend_status หลัง db.commit() สำเร็จเท่านั้น
    (ตาม pattern เดียวกับ send_access_approved_email/send_access_rejected_email —
    ส่งเมลพังไม่ rollback สถานะระงับ แค่ log error ทิ้ง)"""
    subject = "แจ้งเตือน: บัญชีของท่านถูกระงับการใช้งานชั่วคราว - SmartLPR"
    safe_reason = html_escape(reason) if reason else None
    reason_html = (
        f"<p><strong>เหตุผล:</strong> {safe_reason}</p>"
        if safe_reason
        else "<p>ไม่มีการระบุเหตุผลเพิ่มเติม</p>"
    )
    html = f"""
    <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
      <p>บัญชี SmartLPR ของท่านถูกผู้ดูแลระบบระงับการใช้งานชั่วคราว</p>
      {reason_html}
      <p>ระหว่างที่ถูกระงับ ท่านจะไม่สามารถเพิ่ม Webhook Endpoint, ขอ/ออก API Key ใหม่, หรือ
      เพิ่มกล้องผ่าน API ได้ (ยังเข้าสู่ระบบและดูข้อมูลเดิมของท่านได้ตามปกติ)</p>
      <p>หากมีข้อสงสัย กรุณาติดต่อผู้ดูแลระบบเพื่อสอบถามรายละเอียดเพิ่มเติม</p>
    </div>
    """
    _send_email(to_email, subject, html)


def send_account_unsuspended_email(to_email: str) -> None:
    """แจ้ง user ว่าบัญชีถูกปลดระงับแล้ว กลับมาใช้งานได้ปกติ
    เรียกคู่กับ send_account_suspended_email จากจุดเดียวกัน (set_user_suspend_status)"""
    subject = "บัญชีของท่านกลับมาใช้งานได้ตามปกติแล้ว - SmartLPR"
    html = """
    <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
      <p>บัญชี SmartLPR ของท่านถูกปลดระงับแล้ว และสามารถใช้งานทุกฟังก์ชันได้ตามปกติ</p>
      <p>หากมีข้อสงสัย กรุณาติดต่อผู้ดูแลระบบเพื่อสอบถามรายละเอียดเพิ่มเติม</p>
    </div>
    """
    _send_email(to_email, subject, html)