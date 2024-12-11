from flask import Flask, jsonify, Response, render_template
from video_stream.stream import generate_frames

app = Flask(__name__)

# 视频流路由
@app.route('/video_feed')
def video_feed():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

# 主页面路由
@app.route('/')
def index():
    return render_template('index.html')
#视频展示
@app.route('/detect')
def detect():
    return render_template('detect.html')
#学习更多
@app.route('/learn')
def learn():
    return render_template('learn.html')

#监控报警
@app.route('/msg')
def msg():
    try:
        with open('alerts.log', 'r', encoding='utf-8') as log_file:
            lines = log_file.readlines()  # 读取所有行
            rlt = [line.strip() for line in lines] # 返回去掉换行符的行数组
    except FileNotFoundError:
        print(f"Error: 文件  不存在。")
        rlt = []
    except Exception as e:
        print(f"Error: 无法读取文件 。原因: {e}")
        rlt = []
    return jsonify({"code":200,"msg":rlt})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
