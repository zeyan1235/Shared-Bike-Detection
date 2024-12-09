from ultralytics import YOLO
from config import YOLO_MODEL_PATH

class YOLOModel:
    def __init__(self):
        # 加载 YOLO 模型
        self.model = YOLO(YOLO_MODEL_PATH)

    def run_inference(self, frame):
        # 运行推理并返回注释帧
        results = self.model(frame)
        return results[0].plot()
