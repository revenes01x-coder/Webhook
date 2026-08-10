import socket
import ipaddress


class SSRFBlockedError(Exception):
    """Raised เมื่อ hostname resolve ไปยัง IP ที่ไม่อนุญาต (private/loopback/link-local)
    หรือ resolve ไม่ได้เลย — เป็น exception ธรรมดา ไม่ผูกกับ FastAPI โดยตั้งใจ เพื่อให้เรียกใช้ได้
    ทั้งใน request context (ssrf_guard.py, camera_url_guard.py ตอนสร้าง endpoint/กล้องใหม่)
    และใน background context ที่ไม่มี request object เลย (worker.py, camera_worker.py ตอนยิง/
    เชื่อมต่อจริง) — แต่ละฝั่งเลือกเองว่าจะแปลงเป็น HTTPException หรือแค่ log แล้ว retry/ข้าม"""
    pass


def _is_blocked_ip(ip_obj) -> bool:
    """เช็ค private/loopback/link-local ของ IP เดียว (รองรับทั้ง IPv4Address/IPv6Address)
    รวมเคส IPv4-mapped IPv6 (เช่น ::ffff:127.0.0.1) ด้วย — is_private/is_loopback ของ
    IPv6Address เพียวๆ เช็คแค่ range ของ IPv6 เอง ไม่แปลงกลับไปเช็คส่วน IPv4 ที่ฝังอยู่
    ข้างในให้ ถ้าไม่เช็คแยกเคสนี้ จะมีช่องโหว่ให้ IPv6-mapped address หลุดผ่าน guard ไปได้"""
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return True

    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        mapped = ip_obj.ipv4_mapped
        if mapped.is_private or mapped.is_loopback or mapped.is_link_local:
            return True

    return False


def resolve_and_check_ip(hostname: str) -> str:
    """Resolve hostname -> IP (DNS ใหม่ทุกครั้งที่เรียก ไม่มี cache ใดๆ) แล้วเช็คว่าไม่ใช่
    private/loopback/link-local ก่อนคืนค่า IP กลับไปเป็น string

    ใช้ getaddrinfo() แทน gethostbyname() เดิม เพราะ gethostbyname() คืนเฉพาะ IPv4
    (A record) เท่านั้น — ถ้าโดเมนมีทั้ง A record (public, ผ่านการเช็ค) และ AAAA record
    (private/internal) การเช็คแค่ A record ตัวเดียวจะหลุดช่องโหว่ SSRF ผ่าน IPv6 ทันที
    เพราะ client จริงตอนยิง (httpx/requests หรือ FFmpeg ฝั่ง RTSP) อาจ resolve แล้วเลือกใช้
    AAAA record แทนก็ได้ (ขึ้นกับ resolver/getaddrinfo order ของระบบ ไม่ใช่สิ่งที่คุมได้ 100%)

    เช็คทุก IP ที่ resolve ได้ (ทั้ง IPv4 และ IPv6) ไม่ใช่แค่ตัวแรก — ถ้าเจอตัวไหนต้องห้าม
    block ทั้ง hostname ทันที ต่อให้มีตัวอื่นที่ปลอดภัยปนอยู่ก็ตาม (กันกรณี DNS ตอบหลาย
    record ปนกัน โดยตัวที่ปลอดภัยมาก่อนตัวที่ต้องห้าม)

    ใช้ร่วมกันทั้ง:
    - ตอนสร้าง (POST /webhook/add, POST /my/cameras) ผ่าน ssrf_guard.py / camera_url_guard.py
    - ตอนยิง/เชื่อมต่อจริงทุกครั้ง (worker.py, camera_worker.py) เพื่อกัน DNS rebinding —
      โดเมนที่ตอนสมัคร resolve ไปยัง public IP (ผ่านการเช็ค) แต่ภายหลังเจ้าของโดเมนเปลี่ยน
      DNS record ให้ชี้เข้า internal IP แทน (classic TOCTOU)

    คืน IP ตัวแรกที่ resolve ได้ (string) — ใช้ต่อสำหรับ caller ที่ต้อง pin IP เช่น
    camera_url_guard.resolve_rtsp_url_pinned ถ้าเป็น IPv6 ให้ caller เป็นคนครอบ bracket []
    เองตอนประกอบกลับเป็น URL (ดู camera_url_guard.py)
    """
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise SSRFBlockedError(f"ไม่สามารถค้นหาที่อยู่ IP ของโดเมน '{hostname}' ได้")

    # dedupe เพราะ getaddrinfo อาจคืน entry ซ้ำกัน (คนละ socktype/proto แต่ IP เดียวกัน)
    resolved_ips = []
    seen = set()
    for info in addr_info:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            resolved_ips.append(ip)

    first_safe_ip = None
    for ip in resolved_ips:
        ip_obj = ipaddress.ip_address(ip)
        if _is_blocked_ip(ip_obj):
            raise SSRFBlockedError(
                f"โดเมน '{hostname}' resolve ไปยัง IP ภายในเครือข่าย ({ip}) ซึ่งไม่อนุญาต (Private/Loopback IP)"
            )
        if first_safe_ip is None:
            first_safe_ip = ip

    return first_safe_ip