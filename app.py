from flask import Flask, Response, render_template
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
