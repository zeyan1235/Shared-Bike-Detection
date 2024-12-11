import time
import json
from ultralytics import YOLO
from config import YOLO_MODEL_PATH, ALERT_FRAMES_THRESHOLD, ALERT_COOLDOWN_TIME

# 递归查找包含 "shared" 的键或值，并统计数量
def find_shared_in_dict(data, search_key="shared"):
    count = 0
    if isinstance(data, dict):  # 如果是字典
        for key, value in data.items():
            if search_key in key:  # 在键中查找
                print(f"Found in key: {key}")
                count += 1
            if isinstance(value, (dict, list)):
                count += find_shared_in_dict(value, search_key)  # 递归查找
            elif search_key in str(value):  # 在值中查找
                print(f"Found in value: {value}")
                count += 1
    elif isinstance(data, list):  # 如果是列表
        for item in data:
            count += find_shared_in_dict(item, search_key)
    return count

class YOLOModel:
    def __init__(self):
        # 加载 YOLO 模型
        self.model = YOLO(YOLO_MODEL_PATH)
        self.alert_counter = 0  # 连续检测计数
        self.last_alert_time = 0  # 上次警报时间

    

    def run_inference(self, frame):
        # 运行推理并返回注释帧
        results = self.model(frame)
        # Convert result to JSON
        json_result = results[0].to_json()

        # Parse JSON result
        result_dict = json.loads(json_result)

        # Find and count "shared",检查是否检测到目标
        detected = find_shared_in_dict(result_dict, search_key="shared")

        # 连续检测逻辑
        current_time = time.time()
        if detected:
            self.alert_counter += 1
        else:
            self.alert_counter = 0

        # 检测到目标并触发警报
        if self.alert_counter >= ALERT_FRAMES_THRESHOLD and current_time - self.last_alert_time > ALERT_COOLDOWN_TIME:
            self.trigger_alert()
            self.alert_counter = 0
            self.last_alert_time = current_time
        return results[0].plot()
    def trigger_alert(self):
        print("警报：检测到共享单车！")
        with open("alerts.log", "a") as log_file:
            log_file.write(f"警报触发时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n") #警报在这里
