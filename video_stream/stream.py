import cv2
from video_stream.yolo_model import YOLOModel
from config import IP_CAMERA_URL

# 初始化 YOLO 模型
model = YOLOModel()

def generate_frames():
    cap = cv2.VideoCapture(IP_CAMERA_URL)
    while cap.isOpened():
        success, frame = cap.read()
        if not success:
            break

        # 运行 YOLO 推理并获取注释帧
        annotated_frame = model.run_inference(frame)

        # 将帧编码为 JPEG 格式
        _, buffer = cv2.imencode('.jpg', annotated_frame)
        frame_bytes = buffer.tobytes()

        # 通过 yield 生成 MJPEG 数据流
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
    cap.release()
