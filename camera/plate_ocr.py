import torch
import torch.nn.functional as F
from PIL import Image
import numpy as np
import cv2
import sys
sys.path.insert(0, r'C:\Users\ACER\Downloads\MyProject\PlateDetection\deep-text-recognition-benchmark')

from model import Model
from utils import CTCLabelConverter, AttnLabelConverter

# ============================================================
#  CONFIG
# ============================================================
MODEL_PATH = r'C:\Users\ACER\Downloads\MyProject\PlateDetection\custom_model\thai_platev1.pth'
CHAR_FILE   = r'C:\Users\ACER\Downloads\MyProject\PlateDetection\thai_plate_chars.txt'

IMG_H        = 32
IMG_W        = 100
HIDDEN_SIZE  = 512
OUTPUT_CH    = 512
BATCH_MAX_LEN = 30
# ============================================================

with open(CHAR_FILE, encoding='utf-8') as f:
    characters = f.read().rstrip('\n').rstrip('\r')

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

converter = AttnLabelConverter(characters)
num_class = len(converter.character)

class Opt:
    Transformation   = 'TPS'
    FeatureExtraction = 'ResNet'
    SequenceModeling  = 'BiLSTM'
    Prediction        = 'Attn'
    num_fiducial      = 20
    imgH              = IMG_H
    imgW              = IMG_W
    input_channel     = 1
    output_channel    = OUTPUT_CH
    hidden_size       = HIDDEN_SIZE
    num_class         = num_class
    batch_max_length  = BATCH_MAX_LEN

opt = Opt()

model = Model(opt)
model = torch.nn.DataParallel(model).to(device)
state = torch.load(MODEL_PATH, map_location=device)
model.load_state_dict(state)
model.eval()
print(f' โหลด model สำเร็จ | device: {device}')


def preprocess(img_input):
    if isinstance(img_input, str):
        img = cv2.imread(img_input)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    else:
        if len(img_input.shape) == 2:
            gray = img_input                                    # grayscale อยู่แล้ว
        else:
            gray = cv2.cvtColor(img_input, cv2.COLOR_BGR2GRAY) # BGR แปลงก่อน

    gray = cv2.resize(gray, (IMG_W, IMG_H))
    gray = gray.astype(np.float32) / 127.5 - 1.0
    tensor = torch.FloatTensor(gray).unsqueeze(0).unsqueeze(0).to(device)
    return tensor


def predict(img_input):
    """รับรูปป้าย คืน string ที่อ่านได้"""
    tensor = preprocess(img_input)
    batch_size = tensor.size(0)
    length_for_pred = torch.IntTensor([BATCH_MAX_LEN] * batch_size).to(device)
    text_for_pred = torch.LongTensor(batch_size, BATCH_MAX_LEN + 1).fill_(0).to(device)

    with torch.no_grad():
        preds = model(tensor, text_for_pred, is_train=False)
        _, preds_index = preds.max(2)
        preds_str = converter.decode(preds_index, length_for_pred)

    pred = preds_str[0]
    pred = pred[:pred.find('[s]')]  # ตัด end token ออก
    return pred
