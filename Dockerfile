# ใช้ Python 3.11 slim เป็นฐานเพื่อให้ขนาดไฟล์ไม่ใหญ่เกินไป
FROM python:3.11-slim-bookworm

# ตั้งค่า Working Directory
WORKDIR /app

# ติดตั้ง System dependencies ที่จำเป็นสำหรับไลบรารีประมวลผลภาพ (OpenCV, etc.)
RUN apt-get update && apt-get install -y \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# คัดลอก requirements.txt และติดตั้งแพ็กเกจ
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# คัดลอกโค้ดทั้งหมด (รวมโมเดล yolo11n.pt) เข้ามาใน Container
COPY . .

# เปิดพอร์ต 8000
EXPOSE 8000

# คำสั่งเริ่มต้นสำหรับรันเซิร์ฟเวอร์ FastAPI
CMD ["uvicorn", "smartlpr.main:app", "--host", "0.0.0.0", "--port", "8000"]
