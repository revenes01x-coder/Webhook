import socket
import ipaddress


class SSRFBlockedError(Exception):
    """Raised เมื่อ hostname resolve ไปยัง IP ที่ไม่อนุญาต (private/loopback/link-local)
    หรือ resolve ไม่ได้เลย — เป็น exception ธรรมดา ไม่ผูกกับ FastAPI โดยตั้งใจ เพื่อให้เรียกใช้ได้
    ทั้งใน request context (ssrf_guard.py, camera_url_guard.py ตอนสร้าง endpoint/กล้องใหม่)
    และใน background context ที่ไม่มี request object เลย (worker.py, camera_worker.py ตอนยิง/
    เชื่อมต่อจริง) — แต่ละฝั่งเลือกเองว่าจะแปลงเป็น HTTPException หรือแค่ log แล้ว retry/ข้าม"""
    pass


def resolve_and_check_ip(hostname: str) -> str:
    """Resolve hostname -> IP (DNS ใหม่ทุกครั้งที่เรียก ไม่มี cache ใดๆ) แล้วเช็คว่าไม่ใช่
    private/loopback/link-local ก่อนคืนค่า IP กลับไปเป็น string

    ใช้ร่วมกันทั้ง:
    - ตอนสร้าง (POST /webhook/add, POST /my/cameras) ผ่าน ssrf_guard.py / camera_url_guard.py
    - ตอนยิง/เชื่อมต่อจริงทุกครั้ง (worker.py, camera_worker.py) เพื่อกัน DNS rebinding —
      โดเมนที่ตอนสมัคร resolve ไปยัง public IP (ผ่านการเช็ค) แต่ภายหลังเจ้าของโดเมนเปลี่ยน
      DNS record ให้ชี้เข้า internal IP แทน (classic TOCTOU)
    """
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
    except socket.gaierror:
        raise SSRFBlockedError(f"ไม่สามารถค้นหาที่อยู่ IP ของโดเมน '{hostname}' ได้")

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        raise SSRFBlockedError(
            f"โดเมน '{hostname}' resolve ไปยัง IP ภายในเครือข่าย ({ip}) ซึ่งไม่อนุญาต (Private/Loopback IP)"
        )

    return ip