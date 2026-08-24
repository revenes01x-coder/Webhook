import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"   # ซ่อน log ของ TensorFlow (INFO/WARNING/oneDNN ฯลฯ)
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"  # กัน warning เรื่อง oneDNN round-off เฉยๆ
os.environ["YOLO_VERBOSE"] = "False"       # ซ่อน banner/log ของ Ultralytics ตอนโหลดโมเดล

import re
import time
import uuid
import json
import logging
import difflib
import datetime

import cv2 as cv
import numpy as np
import requests
from ultralytics import YOLO
from camera.plate_ocr import predict as ocr_predict
from security.camera_url_guard import resolve_rtsp_url_pinned
from security.ip_guard import SSRFBlockedError

from smartlpr.config import (
    PLATE_YOLO_MODEL_PATH,
    CAR_DETECTOR_MODEL_PATH,
    CAR_COLOR_MODEL_PATH,
    CAR_COLOR_CLASSNAMES_PATH,
    CAPTURES_SAVE_DIR,
    CAPTURE_EVENT_WEBHOOK_URL,
    CAPTURE_EVENT_SECRET,   # [Internal Auth] secret กลาง ยิงคู่กับ backend ผ่าน header
)

import tensorflow as tf
tf.get_logger().setLevel("ERROR")  # ซ่อน log ระดับ absl ที่ TF_CPP_MIN_LOG_LEVEL เก็บไม่หมด
from tensorflow.keras.applications.efficientnet import preprocess_input as color_model_preprocess

_missing = [
    name for name, value in (
        ("PLATE_YOLO_MODEL_PATH", PLATE_YOLO_MODEL_PATH),
        ("CAR_COLOR_MODEL_PATH", CAR_COLOR_MODEL_PATH),
        ("CAR_COLOR_CLASSNAMES_PATH", CAR_COLOR_CLASSNAMES_PATH),
    ) if not value
]
if _missing:
    raise RuntimeError(
        "camera/camera_worker.py ต้องการ Environment Variable ต่อไปนี้ใน .env: "
        f"{', '.join(_missing)} (ดูตัวอย่างค่าที่ต้องตั้งใน .env.example)"
    )

YOLO_MODEL_PATH = PLATE_YOLO_MODEL_PATH                 # YOLO หาป้ายทะเบียน (เทรนเอง)
CAR_CLASS_IDS = [2, 3, 5, 7]  # COCO class id: 2=car, 3=motorcycle, 5=bus, 7=truck
CAR_BOX_EXPAND_RATIO = 0.025  # ขยายกรอบรถออกก่อนหาป้าย กันป้ายโดนตัดขาดถ้าอยู่ขอบกรอบพอดี

COLOR_MODEL_PATH = CAR_COLOR_MODEL_PATH
COLOR_CLASSNAMES_PATH = CAR_COLOR_CLASSNAMES_PATH
COLOR_IMG_SIZE = (224, 224)  # ต้องตรงกับตอนเทรน (IMG_SIZE ใน train_car_color.py)
COLOR_MIN_CONFIDENCE = 0.3   # ถ้าโมเดลมั่นใจต่ำกว่านี้ ให้ตอบ "unknown" แทน

SAVE_DIR_ROOT   = CAPTURES_SAVE_DIR                     # ดีฟอลต์ "captures" (relative, อยู่ใน .gitignore)
WEBHOOK_URL     = CAPTURE_EVENT_WEBHOOK_URL             # ดีฟอลต์ "http://localhost:8000/capture-event"

YOLO_CONF        = 0.6
MIN_ASPECT_RATIO = 0.8
MIN_WIDTH        = 50
RESIZE_FACTOR    = 3
PADDING          = 10
COOLDOWN_SEC     = 10  # เดิม 3 → เพิ่มเป็น 10 (ลดความถี่การประมวลผลเฟรมโดยรวม)
RECONNECT_SEC    = 3   # วินาทีที่รอก่อน reconnect กล้อง
OCR_MIN_CONFIDENCE = 0.10
PLATE_DEDUP_WINDOW_SEC = 60
# ============================================================

THAI_PROVINCES = [
    "กรุงเทพมหานคร", "กระบี่", "กาญจนบุรี", "กาฬสินธุ์", "กำแพงเพชร", "ขอนแก่น", "จันทบุรี",
    "ฉะเชิงเทรา", "ชลบุรี", "ชัยนาท", "ชัยภูมิ", "ชุมพร", "เชียงราย", "เชียงใหม่", "ตรัง",
    "ตราด", "ตาก", "นครนายก", "นครปฐม", "นครพนม", "นครราชสีมา", "นครศรีธรรมราช",
    "นครสวรรค์", "นนทบุรี", "นราธิวาส", "น่าน", "บึงกาฬ", "บุรีรัมย์", "ปทุมธานี",
    "ประจวบคีรีขันธ์", "ปราจีนบุรี", "ปัตตานี", "พระนครศรีอยุธยา", "พะเยา", "พังงา",
    "พัทลุง", "พิจิตร", "พิษณุโลก", "เพชรบุรี", "เพชรบูรณ์", "แพร่", "ภูเก็ต",
    "มหาสารคาม", "มุกดาหาร", "แม่ฮ่องสอน", "ยโสธร", "ยะลา", "ร้อยเอ็ด", "ระนอง",
    "ระยอง", "ราชบุรี", "ลพบุรี", "ลำปาง", "ลำพูน", "เลย", "ศรีสะเกษ", "สกลนคร",
    "สงขลา", "สตูล", "สมุทรปราการ", "สมุทรสงคราม", "สมุทรสาคร", "สระแก้ว", "สระบุรี",
    "สิงห์บุรี", "สุโขทัย", "สุพรรณบุรี", "สุราษฎร์ธานี", "สุรินทร์", "หนองคาย",
    "หนองบัวลำภู", "อ่างทอง", "อำนาจเจริญ", "อุดรธานี", "อุตรดิตถ์", "อุทัยธานี", "อุบลราชธานี", "เบตง"
]


def detect_car_color(color_model, class_names, car_img, logger, min_confidence=COLOR_MIN_CONFIDENCE):
    """ทายสีรถจากภาพที่ครอปมาแล้ว คืนชื่อสี (capitalize) หรือ 'unknown'"""
    if car_img is None or car_img.size == 0:
        return "unknown"

    try:
        img = cv.resize(car_img, COLOR_IMG_SIZE)
        img = cv.cvtColor(img, cv.COLOR_BGR2RGB)  # ตอนเทรนใช้ ImageDataGenerator ซึ่งอ่านภาพเป็น RGB

        batch = np.expand_dims(img.astype(np.float32), axis=0)
        batch = color_model_preprocess(batch)

        preds = color_model.predict(batch, verbose=0)[0]  # softmax probs ต่อ class
        best_idx = int(np.argmax(preds))
        best_color = class_names[best_idx]
        best_confidence = float(preds[best_idx])

        if best_confidence < min_confidence:
            return "unknown"
        return best_color.capitalize()
    except Exception as e:
        logger.warning(f"ทายสีรถผิดพลาด: {e}")
        return "unknown"


def fixformat(text):
    match = re.match(r'^([0-9A-Za-z]?[\u0E00-\u0E7F]+)(.*)$', text)
    if match:
        char_part = match.group(1)
        num_part = match.group(2)
    else:
        if any('\u0E00' <= c <= '\u0E7F' for c in text):
            char_part, num_part = text, ""
        else:
            char_part, num_part = "", text

    is_standard = re.fullmatch(r'^[0-9lIoOSzZ]?[ก-ฮ]{1,2}$', char_part)
    if is_standard and len(char_part) > 1 and char_part[0] in '|lIoOSzZ':
        prefix_fixes = {'l': '1', 'I': '1', 'o': '0', 'O': '0', 'S': '5', 'z': '2', 'Z': '2'}
        char_part = prefix_fixes.get(char_part[0], char_part[0]) + char_part[1:]

    num_fixes = {'|': '1', 'o': '0', 'O': '0', 'l': '1', 'I': '1', 'S': '5', 's': '5',
                 'G': '6', 'B': '8', 'Z': '2', 'z': '2', 'A': '4', 'q': '9', 'ง': '3'}
    fixed_num = ''.join([num_fixes.get(c, c) for c in num_part])
    return char_part + fixed_num


def autocorrect_province(text):
    if len(text) < 3 or any(c.isdigit() for c in text):
        return text
    matches = difflib.get_close_matches(text, THAI_PROVINCES, n=1, cutoff=0.4)
    return matches[0] if matches else text


def preprocess_plate(img, x1, y1, x2, y2):
    h, w = img.shape[:2]
    y1, y2 = max(0, y1 - PADDING), min(h, y2 + PADDING)
    x1, x2 = max(0, x1 - PADDING), min(w, x2 + PADDING)
    plate_crop = img[y1:y2, x1:x2]
    if plate_crop.size == 0:
        return img, img
    h_new = plate_crop.shape[0] * RESIZE_FACTOR
    w_new = plate_crop.shape[1] * RESIZE_FACTOR
    plate_crop = cv.resize(plate_crop, (w_new, h_new), interpolation=cv.INTER_CUBIC)
    gray = cv.cvtColor(plate_crop, cv.COLOR_BGR2GRAY)
    clahe = cv.createCLAHE(clipLimit=1.0, tileGridSize=(8, 8))
    enhanced_gray = clahe.apply(gray)
    return plate_crop, enhanced_gray


def read_plate(plate_crop, enhanced_gray, logger):
    """อ่านป้ายทะเบียน ลองภาพที่ enhance (CLAHE) ก่อน แล้วลองภาพ crop สีปกติเทียบด้วยเสมอ
    ถ้าอันไหนมั่นใจกว่าก็ใช้อันนั้น (บางครั้ง enhance กลับทำให้อ่านยากขึ้นในบางสภาพแสง)

    ถ้าผลลัพธ์ที่มั่นใจที่สุดยังต่ำกว่า OCR_MIN_CONFIDENCE (หรืออ่านได้ค่าว่าง) ถือว่าอ่านไม่ได้
    -> คืนค่าว่าง ("", "") ไม่ส่งข้อมูลที่ไม่น่าเชื่อถือออกไปยิง webhook"""
    text, confidence = ocr_predict(enhanced_gray)
    source = "enhanced_gray"

    fallback_text, fallback_confidence = ocr_predict(plate_crop)
    if fallback_text and fallback_confidence > confidence:
        text, confidence, source = fallback_text, fallback_confidence, "plate_crop"

    if not text or confidence < OCR_MIN_CONFIDENCE:
        logger.info(
            f"ข้ามป้าย: อ่านได้ '{text}' มั่นใจ {confidence:.2f} ต่ำกว่าเกณฑ์ "
            f"{OCR_MIN_CONFIDENCE} (แหล่งที่มั่นใจสุด: {source})"
        )
        return "", ""

    text = text.replace('.', '').replace(',', '').replace('-', '').strip()
    parts = text.split(' ', 1)
    plate_part = fixformat(parts[0].strip())
    province_part = "unknown"

    if len(parts) > 1:
        corrected = autocorrect_province(parts[1].strip())
        if corrected in THAI_PROVINCES:
            province_part = corrected

    return plate_part, province_part


def _setup_logger(camera_id: str) -> logging.Logger:
    os.makedirs("logs", exist_ok=True)
    logger = logging.getLogger(f"camera_{camera_id}")
    logger.setLevel(logging.INFO)
    # กัน handler ซ้ำถ้า process ถูก restart แล้วเรียก run() ใหม่ในตัวเดิม (ปกติไม่เกิดเพราะเป็น process ใหม่ทุกครั้ง)
    if not logger.handlers:
        handler = logging.FileHandler(f"logs/camera_{camera_id}.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(handler)
    return logger


def send_to_webhook(camera_id, path_full, path_crop, plate, province, color, ts_display, logger):
    try:
        data = {
            "camera_id": camera_id,
            "event_id": uuid.uuid4().hex,  # สร้างรหัสเหตุการณ์ที่ไม่ซ้ำกันเองฝั่งกล้อง
            "plate": plate,
            "province": province,
            "color": color,
            "timestamp": ts_display,
            "full_image_path": path_full,
            "crop_image_path": path_crop,
        }

        # [Internal Auth]: แนบ secret กลางไปด้วยทุกครั้ง — backend (/capture-event)
        # จะปฏิเสธ request ที่ไม่มี header นี้หรือค่าไม่ตรง (ดู smartlpr/security.py:
        # require_capture_event_secret) กันคนนอกที่รู้ camera_id ยิงข้อมูล/path ปลอมเข้ามา
        response = requests.post(
            WEBHOOK_URL,
            data=data,
            headers={"X-Capture-Secret": CAPTURE_EVENT_SECRET},
            timeout=5,
        )

        if response.status_code == 200:
            logger.info("ส่ง webhook สำเร็จ")
        elif response.status_code == 401:
            logger.error("webhook ปฏิเสธ (401) — CAPTURE_EVENT_SECRET ไม่ตรงกับฝั่ง backend เช็ค .env ทั้งสองฝั่ง")
        else:
            logger.warning(f"webhook ตอบกลับ: {response.status_code}")

    except requests.exceptions.ConnectionError:
        logger.warning("เชื่อมต่อ webhook ไม่ได้ — เซฟเฉพาะไฟล์ local")
    except requests.exceptions.Timeout:
        logger.warning("webhook หมดเวลา — เซฟเฉพาะไฟล์ local")
    except Exception as e:
        logger.error(f"ส่ง webhook ผิดพลาด: {e}")


def save_capture(camera_id, frame, plate_crop, plate, province, color, save_dir_full, save_dir_crop, logger):
    now = datetime.datetime.now()
    ts_file = now.strftime("%Y%m%d_%H%M%S")
    ts_display = now.strftime("%Y/%m/%d %H:%M:%S")
    
    prov_str = f"_{province}" if province and province != "unknown" else ""

    fname_full = f"{ts_file}_{plate}{prov_str}_full.jpg"
    path_full = os.path.join(save_dir_full, fname_full)
    cv.imwrite(path_full, frame)

    fname_crop = f"{ts_file}_{plate}{prov_str}_crop.jpg"
    path_crop = os.path.join(save_dir_crop, fname_crop)
    cv.imwrite(path_crop, plate_crop)

    logger.info(f"เซฟรูป full: {path_full}")
    logger.info(f"เซฟรูป crop: {path_crop}")

    send_to_webhook(camera_id, path_full, path_crop, plate, province, color, ts_display, logger)

def open_stream(url, logger):
    """เปิด RTSP stream ด้วย IP ที่ resolve + เช็คแล้วเท่านั้น (pin IP กัน DNS rebinding)

    เหตุผลที่ต้อง "แทน IP ตรงๆ ใน URL" ก่อนส่งให้ cv.VideoCapture แทนที่จะแค่เช็คแล้วปล่อยผ่าน
    hostname เดิม: cv.VideoCapture เปิด RTSP ผ่าน FFmpeg (C library) ซึ่ง resolve DNS เองอีกรอบ
    ไม่ผ่าน Python เลย ต่อให้ฝั่ง Python เช็คแล้วว่า IP ปลอดภัย ก็ไม่การันตีว่า FFmpeg จะได้ IP
    เดียวกัน (ดู camera_url_guard.resolve_rtsp_url_pinned สำหรับรายละเอียดเต็ม)

    คืน None ถ้า host ไม่ผ่านการตรวจสอบ (SSRF) หรือ resolve ไม่ได้ — caller (_open_stream_with_retry)
    จะรอแล้ว retry เอง เหมือนเวลา stream ต่อไม่ติดด้วยเหตุผลอื่น ไม่ crash process ทิ้ง"""
    try:
        pinned_url = resolve_rtsp_url_pinned(url)
    except SSRFBlockedError as e:
        logger.warning(f"[SSRF Guard] ปฏิเสธการเชื่อมต่อ RTSP: {e}")
        return None

    cap = cv.VideoCapture(pinned_url)
    cap.set(cv.CAP_PROP_BUFFERSIZE, 1)
    return cap


def _open_stream_with_retry(rtsp_url, logger):
    """เรียก open_stream() วนซ้ำจนกว่าจะสำเร็จ (ไม่ปล่อย None ออกไปให้ caller เห็นเลย)
    ใช้ทั้งตอนเริ่ม process ครั้งแรกและตอน reconnect หลัง stream หลุด — ถ้าถูก SSRF guard ปฏิเสธ
    (เช่น rtsp_url โดน DNS rebinding ไปชี้ IP ภายในแล้ว) จะวนรอเหมือนกรณี stream ต่อไม่ติดปกติ
    ไม่ crash หรือหยุดทำงานไปเฉยๆ"""
    cap = open_stream(rtsp_url, logger)
    while cap is None:
        logger.warning(f"เชื่อมต่อ RTSP ไม่ได้ (URL ไม่ผ่าน SSRF guard หรือต่อไม่ติด) — รอ {RECONNECT_SEC} วินาทีแล้วลองใหม่...")
        time.sleep(RECONNECT_SEC)
        cap = open_stream(rtsp_url, logger)
    return cap


def run(camera_id: str, rtsp_url: str):
    """
    Entry point ที่ camera_manager.py เรียกผ่าน
    multiprocessing.Process(target=run, args=(camera_id, rtsp_url))
    ฟังก์ชันนี้ loop ไม่มีวันจบ (จบก็ต่อเมื่อ process ถูก terminate จาก manager)
    """
    logger = _setup_logger(camera_id)

    save_dir_full = os.path.join(SAVE_DIR_ROOT, f"camera_{camera_id}", "full")
    save_dir_crop = os.path.join(SAVE_DIR_ROOT, f"camera_{camera_id}", "crop")
    os.makedirs(save_dir_full, exist_ok=True)
    os.makedirs(save_dir_crop, exist_ok=True)

    logger.info("กำลังโหลด YOLO model (ป้ายทะเบียน)...")
    yolo_model = YOLO(YOLO_MODEL_PATH)

    logger.info("กำลังโหลด YOLO model (ตรวจจับรถทั้งคัน)...")
    car_detector = YOLO(CAR_DETECTOR_MODEL_PATH)

    logger.info("กำลังโหลดโมเดลแยกสีรถ...")
    color_model = tf.keras.models.load_model(COLOR_MODEL_PATH)
    with open(COLOR_CLASSNAMES_PATH, "r", encoding="utf-8") as f:
        color_class_names = json.load(f)

    logger.info(f"เชื่อมต่อ RTSP: {rtsp_url}")
    cap = _open_stream_with_retry(rtsp_url, logger)

    last_detect_time = 0.0
    recent_plates: dict[str, float] = {}  # {plate: เวลา (time.time()) ล่าสุดที่เจอป้ายนี้} — กันยิง webhook ซ้ำรถคันเดิม

    logger.info("เริ่มทำงาน")

    while True:
        ret, frame = cap.read()

        if not ret:
            logger.warning(f"Stream หลุด — รอ {RECONNECT_SEC} วินาทีแล้ว reconnect...")
            cap.release()
            time.sleep(RECONNECT_SEC)
            cap = _open_stream_with_retry(rtsp_url, logger)
            continue

        now = time.time()

        # Cooldown ระดับเฟรม กันตรวจจับรัวๆ ทุกเฟรมตอนรถคันเดิมยังอยู่ในกล้องหลายเฟรมติดกัน
        # (ถ้าเฟรมนี้ผ่าน cooldown แล้ว จะประมวลผลรถ "ทุกคัน" ที่เจอในเฟรมนั้น ไม่ใช่แค่คันเดียว)
        if (now - last_detect_time) <= COOLDOWN_SEC:
            continue

        h_frame, w_frame = frame.shape[:2]

        # ขั้นที่ 1: หา "รถ/มอเตอร์ไซค์" ทั้งเฟรมก่อน ด้วย YOLO pretrained (COCO)
        car_results = car_detector(frame, verbose=False)

        frame_had_detection = False

        for car_result in car_results:
            for car_box_raw in car_result.boxes:
                cls_id = int(car_box_raw.cls[0])
                if cls_id not in CAR_CLASS_IDS:
                    continue

                cx1, cy1, cx2, cy2 = map(int, car_box_raw.xyxy[0])
                car_w, car_h = cx2 - cx1, cy2 - cy1

                # ขยายกรอบรถแบบสัดส่วน ก่อนไปหาป้าย กันป้ายโดนตัดขาดถ้าอยู่ขอบกรอบพอดี
                pad_x = int(car_w * CAR_BOX_EXPAND_RATIO)
                pad_y = int(car_h * CAR_BOX_EXPAND_RATIO)
                ex1 = max(0, cx1 - pad_x)
                ey1 = max(0, cy1 - pad_y)
                ex2 = min(w_frame, cx2 + pad_x)
                ey2 = min(h_frame, cy2 + pad_y)

                car_crop = frame[ey1:ey2, ex1:ex2]
                if car_crop.size == 0:
                    continue

                # ขั้นที่ 2: หาป้ายทะเบียน "เฉพาะในกรอบรถ" ด้วย YOLO ที่เทรนเอง
                # ตัดปัญหาไปจับป้ายอื่นที่ไม่ใช่ของรถคันนี้
                plate_results = yolo_model(car_crop, verbose=False)

                valid_plates = []
                for plate_result in plate_results:
                    for pbox in plate_result.boxes:
                        px1, py1, px2, py2 = map(int, pbox.xyxy[0])
                        conf = pbox.conf[0].item()
                        width, height = px2 - px1, py2 - py1
                        aspect = width / height if height > 0 else 0

                        if aspect < MIN_ASPECT_RATIO or width < MIN_WIDTH:
                            continue
                        if conf <= YOLO_CONF:
                            continue

                        valid_plates.append((px1, py1, px2, py2))

                if not valid_plates:
                    continue  # รถคันนี้ไม่เจอป้าย ข้ามไปเลย ไม่เสียเวลาทายสี

                # ขั้นที่ 3: ทายสีรถ — ทำเฉพาะตอนเจอป้ายแล้วเท่านั้น (ประหยัดเวลา)
                color = detect_car_color(color_model, color_class_names, car_crop, logger)

                for px1, py1, px2, py2 in valid_plates:
                    plate_crop, enhanced_gray = preprocess_plate(car_crop, px1, py1, px2, py2)
                    plate, province = read_plate(plate_crop, enhanced_gray ,logger)

                    if plate:
                        # [กันจับซ้ำ]: ป้ายนี้เพิ่งถูกบันทึกไปเมื่อไม่นานมานี้หรือไม่ (ถือเป็นรถคันเดิม
                        # ที่ยังอยู่ในเฟรม เช่น จอดติดไฟแดง/ไม้กั้น) ถ้าใช่ -> ข้าม ไม่ยิง webhook ซ้ำ
                        last_seen = recent_plates.get(plate)
                        if last_seen is not None and (now - last_seen) < PLATE_DEDUP_WINDOW_SEC:
                            logger.info(
                                f"ข้ามป้าย {plate} — ซ้ำกับที่เพิ่งบันทึกไป "
                                f"{now - last_seen:.1f} วิ ก่อนหน้า (ยังไม่ครบ {PLATE_DEDUP_WINDOW_SEC} วิ)"
                            )
                            continue

                        recent_plates[plate] = now
                        frame_had_detection = True
                        logger.info(f"เจอป้าย: {plate} {province} | สี: {color}".strip())
                        save_capture(
                            camera_id, frame, plate_crop, plate, province, color,
                            save_dir_full, save_dir_crop, logger,
                        )

        if frame_had_detection:
            last_detect_time = now

        # [กันจับซ้ำ]: ล้าง entry ที่เก่าเกิน PLATE_DEDUP_WINDOW_SEC ทิ้งเป็นระยะ กัน recent_plates
        # โตขึ้นเรื่อยๆ ไม่มีที่สิ้นสุดถ้ากล้องรันยาวนานเป็นวันๆ (ทำนอก if ด้านบน เพื่อให้เคลียร์
        # ได้ทุกรอบที่ผ่าน cooldown ไม่ใช่แค่ตอนมี detection ใหม่)
        if recent_plates:
            recent_plates = {
                p: t for p, t in recent_plates.items()
                if now - t < PLATE_DEDUP_WINDOW_SEC
            }


if __name__ == "__main__":
    raise SystemExit(
        "ห้ามรันไฟล์นี้ตรงๆ — ไฟล์นี้ถูกออกแบบให้ camera_manager.py เป็นคน spawn เท่านั้น "
        "ถ้าต้องการรันดูภาพสดทีละกล้อง ให้ใช้ main_rtsp2.py หรือ test_model4.py แทน"
    )