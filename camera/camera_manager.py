"""
Camera Manager — process กลางตัวเดียวที่ดูแลกล้องทุกตัว
แทนที่การรันไฟล์กล้องแยกทีละไฟล์ (main_rtsp2.py) แบบเดิม

การทำงาน:
1. ดึงรายชื่อกล้อง active จากตาราง Camera ในฐานข้อมูลทุก 30 วินาที
2. สำหรับกล้องแต่ละตัวที่ active, spawn เป็น 1 multiprocessing.Process แยกกัน
   (ใช้ process ไม่ใช่ thread เพราะ YOLO inference เป็นงาน CPU-heavy ที่ thread
   ทำงานพร้อมกันจริงไม่ได้เนื่องจาก GIL)
3. Monitor: ถ้า process ของกล้องไหน crash/ตาย -> restart อัตโนมัติในรอบถัดไป
4. ถ้า admin ปิดใช้งานกล้องไหน (is_active=False) -> terminate process นั้นในรอบถัดไป
5. ถ้า rtsp_url ของกล้องถูกแก้ไข -> restart process ด้วย url ใหม่ในรอบถัดไป

วิธีรัน: python camera_manager.py
Deploy จริงรันผ่าน systemd หรือ nohup ก็เพียงพอสำหรับ scale 2-3 กล้อง
"""
import time
import logging
import multiprocessing as mp

import models
import camera.camera_worker as camera_worker
from smartlpr.database import SessionLocal

POLL_INTERVAL_SECONDS = 30
TERMINATE_TIMEOUT_SECONDS = 10

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("camera_manager")


def get_active_cameras() -> dict[str, str]:
    """คืน {camera_id: rtsp_url} เฉพาะกล้องที่ is_active=True และเจ้าของยังไม่ถูกระงับ

    [Suspend Guard]: join กับตาราง users กรอง is_suspended=False ด้วย — พอ admin กดระงับ
    user คนไหน กล้องที่กำลัง active/รันอยู่ของ user นั้นจะหายไปจากผลลัพธ์ทันทีในรอบ poll ถัดไป
    (สูงสุด POLL_INTERVAL_SECONDS วิ) ทำให้ main() มองว่าเป็นกรณีเดียวกับ "กล้องถูกปิดใช้งาน"
    (ดู main(): ข้อ 1 running_ids - active_ids -> terminate) แล้ว terminate process ให้เองอัตโนมัติ
    ไม่ต้องรอ user เข้ามาปิดกล้องเอง — ถ้าภายหลังปลดระงับ กล้องจะกลับมา spawn ใหม่เองในรอบถัดไปเช่นกัน
    (ตราบใดที่ Camera.is_active ยังเป็น True อยู่)
    """
    db = SessionLocal()
    try:
        cameras = (
            db.query(models.Camera)
            .join(models.User, models.Camera.owner_user_id == models.User.id)
            .filter(
                models.Camera.is_active == True,      # noqa: E712
                models.User.is_suspended == False,     # noqa: E712
            )
            .all()
        )
        # แปลงเป็น dict ธรรมดาก่อนปิด session กัน DetachedInstanceError ตอนใช้งานนอก session
        return {c.id: c.rtsp_url for c in cameras}
    finally:
        db.close()


def spawn_camera_process(camera_id: str, rtsp_url: str) -> mp.Process:
    process = mp.Process(
        target=camera_worker.run,
        args=(camera_id, rtsp_url),
        name=f"camera-{camera_id}",
        daemon=True,
    )
    process.start()
    logger.info(f"เริ่ม process สำหรับกล้อง {camera_id} (pid={process.pid})")
    return process


def _terminate(camera_id: str, process: mp.Process, reason: str):
    if process.is_alive():
        logger.info(f"กล้อง {camera_id}: {reason} -> terminate process (pid={process.pid})")
        process.terminate()
        process.join(timeout=TERMINATE_TIMEOUT_SECONDS)
        if process.is_alive():
            logger.warning(f"กล้อง {camera_id}: process (pid={process.pid}) ไม่ยอมหยุด -> kill")
            process.kill()
            process.join(timeout=TERMINATE_TIMEOUT_SECONDS)


def main():
    running: dict[str, mp.Process] = {}   # camera_id -> Process ที่กำลังรันอยู่
    current_urls: dict[str, str] = {}     # camera_id -> rtsp_url ที่ process ปัจจุบันใช้อยู่

    logger.info("Camera Manager เริ่มทำงาน...")

    while True:
        try:
            active_cameras = get_active_cameras()
        except Exception as e:
            logger.error(f"ดึงรายชื่อกล้องจาก DB ไม่สำเร็จ: {e}")
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        active_ids = set(active_cameras.keys())
        running_ids = set(running.keys())

        # 1. กล้องที่ถูกปิดใช้งานหรือถูกลบไปแล้ว -> terminate process
        for camera_id in running_ids - active_ids:
            process = running.pop(camera_id)
            current_urls.pop(camera_id, None)
            _terminate(camera_id, process, "ถูกปิดใช้งาน/ลบออกจากระบบ")

        # 2. กล้องที่ rtsp_url เปลี่ยน (admin แก้ไข) -> restart ด้วย url ใหม่
        for camera_id in running_ids & active_ids:
            if current_urls.get(camera_id) != active_cameras[camera_id]:
                _terminate(camera_id, running[camera_id], "rtsp_url เปลี่ยน")
                running[camera_id] = spawn_camera_process(camera_id, active_cameras[camera_id])
                current_urls[camera_id] = active_cameras[camera_id]

        # 3. กล้องที่ process ตายไปเอง (crash) -> restart
        for camera_id in running_ids & active_ids:
            process = running[camera_id]
            if not process.is_alive():
                logger.warning(f"กล้อง {camera_id}: process หยุดทำงานไม่คาดคิด (crash) -> restart")
                running[camera_id] = spawn_camera_process(camera_id, active_cameras[camera_id])
                current_urls[camera_id] = active_cameras[camera_id]

        # 4. กล้องใหม่ที่ active แต่ยังไม่มี process -> spawn
        for camera_id in active_ids - running_ids:
            running[camera_id] = spawn_camera_process(camera_id, active_cameras[camera_id])
            current_urls[camera_id] = active_cameras[camera_id]

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()