import os
import json
import threading
import logging
import datetime
from typing import Dict, List, Any, Optional, Callable, Tuple
from queue import Queue
from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS

logger = logging.getLogger(__name__)

class HTTPServer:
    """HTTP服务器，用于提供Web界面查看对话流和手动输入符号信息"""
    
    def __init__(self, port: int = 8080):
        self.port = port
        self.app = Flask(__name__, static_url_path='', static_folder='.', template_folder='templates')
        CORS(self.app)
        
        # 对话流队列
        self.conversation_queue = Queue()
        
        # 用户输入队列和事件
        self.user_input_queue = Queue()
        self.user_input_event = threading.Event()
        
        # 流式消息状态
        self.has_active_stream = False
        self.current_stream_message = ""
        
        # 当前任务状态
        self.current_task = {
            "status": "idle",  # idle, running, waiting_input
            "task_type": None,  # get_symbol, find_refs
            "symbol_name": None,
            "messages": []
        }
        
        # 注册路由
        self.register_routes()
    
    def register_routes(self):
        """注册Flask路由"""
        @self.app.route('/')
        def index():
            return render_template('stream.html')
        
        @self.app.route('/api/status')
        def get_status():
            return jsonify(self.current_task)
        
        @self.app.route('/api/conversation')
        def get_conversation():
            return jsonify({"messages": self.current_task["messages"]})
        
        @self.app.route('/api/stream')
        def stream():
            def generate():
                while True:
                    # 获取新消息
                    try:
                        message = self.conversation_queue.get(timeout=1)
                        # 所有类型的消息都直接传递给前端
                        yield f"data: {json.dumps(message)}\n\n"
                    except Exception:
                        # 发送心跳保持连接
                        yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
            
            return Response(generate(), mimetype='text/event-stream')
        
        @self.app.route('/api/input', methods=['POST'])
        def submit_input():
            data = request.json
            if not data or 'input' not in data:
                return jsonify({"error": "缺少输入内容"}), 400
            
            user_input = data['input']
            is_json = data.get('is_json', False)
            
            # 将用户输入放入队列
            self.user_input_queue.put((user_input, is_json))
            # 设置事件，通知等待线程
            self.user_input_event.set()
            
            # 添加用户消息到对话历史
            self.add_message('user', user_input)
            
            return jsonify({"status": "success"})
    
    def start(self):
        """在后台线程启动HTTP服务器"""
        threading.Thread(target=self._run_server, daemon=True).start()
        logger.info(f"HTTP服务器已启动，访问 http://localhost:{self.port} 查看界面")
    
    def _run_server(self):
        """运行Flask服务器"""
        self.app.run(host='0.0.0.0', port=self.port, debug=False, threaded=True)
    
    def update_task_status(self, status: str, task_type: Optional[str] = None, symbol_name: Optional[str] = None):
        """更新当前任务状态"""
        self.current_task["status"] = status
        if task_type:
            self.current_task["task_type"] = task_type
        if symbol_name:
            self.current_task["symbol_name"] = symbol_name
        
        # 将状态更新发送到流
        self.conversation_queue.put({
            "type": "status_update",
            "status": self.current_task["status"],
            "task_type": self.current_task["task_type"],
            "symbol_name": self.current_task["symbol_name"]
        })
    
    def add_message(self, role: str, content: str):
        """添加完整消息到对话历史"""
        # 添加时间戳
        timestamp = datetime.datetime.now().isoformat()
        message = {"role": role, "content": content, "timestamp": timestamp}
        self.current_task["messages"].append(message)
        
        # 将消息发送到流
        self.conversation_queue.put({
            "type": "message",
            "message": message
        })
        
    def add_message_chunk(self, role: str, content_chunk: str):
        """添加消息块到流式对话
        
        Args:
            role: 消息角色（assistant, user, system）
            content_chunk: 消息内容块
        """
        # 如果是第一个块，开始一个新的流式消息
        if not self.has_active_stream:
            self.has_active_stream = True
            self.current_stream_message = content_chunk
            timestamp = datetime.datetime.now().isoformat()
            
            # 创建一个初始消息并添加到历史
            message = {"role": role, "content": self.current_stream_message, "timestamp": timestamp}
            self.current_task["messages"].append(message)
            
            # 发送消息开始事件
            self.conversation_queue.put({
                "type": "message_start",
                "message": {
                    "role": role,
                    "content": content_chunk,
                    "timestamp": timestamp
                }
            })
        else:
            # 更新当前流式消息内容
            self.current_stream_message += content_chunk
            
            # 更新历史中的最后一条消息
            if self.current_task["messages"]:
                self.current_task["messages"][-1]["content"] = self.current_stream_message
            
            # 发送消息块事件
            self.conversation_queue.put({
                "type": "message_chunk",
                "chunk": content_chunk
            })
        
        # 检查是否是消息结束（通常由调用方在完成后调用 finish_stream_message）
        if content_chunk.endswith("}") or len(content_chunk) > 100:
            # 可能是JSON结束，但不确定，所以不自动结束流
            pass
    
    def finish_stream_message(self):
        """结束当前流式消息"""
        if self.has_active_stream:
            # 发送消息结束事件
            self.conversation_queue.put({
                "type": "message_end"
            })
            
            # 重置流式消息状态
            self.has_active_stream = False
            self.current_stream_message = ""
    
    def wait_for_user_input(self, task_type: str, symbol_name: str) -> Any:
        """等待用户输入
        
        Args:
            task_type: 任务类型，如 'get_symbol' 或 'find_refs'
            symbol_name: 符号名称
            
        Returns:
            如果用户提交的是JSON格式，则返回解析后的JSON对象；否则返回字符串
        """
        # 更新状态为等待输入
        self.update_task_status("waiting_input", task_type, symbol_name)
        
        # 清除之前的事件状态
        self.user_input_event.clear()
        
        # 等待用户输入
        self.user_input_event.wait()
        
        # 获取用户输入和格式标志
        user_input, is_json = self.user_input_queue.get()
        
        # 更新状态为运行中
        self.update_task_status("running")
        
        # 如果是JSON格式，尝试解析
        if is_json:
            try:
                return json.loads(user_input)
            except json.JSONDecodeError as e:
                logger.error(f"JSON解析错误: {str(e)}")
                # 解析失败时返回原始字符串
                return user_input
        
        return user_input