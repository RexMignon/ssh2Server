import os
import sys
import signal
import threading
import time
import webbrowser
import argparse
import logging
import concurrent.futures
from typing import List, Optional, Dict, Tuple, Union
from flask import Flask, render_template, request, jsonify, Response, g, send_from_directory
from flask_socketio import SocketIO
import sshtunnel
from dataclasses import dataclass, field, asdict
import json
from collections import defaultdict
from mignonFramework import JsonConfigManager, injectJson, Logger

RECONNECT_DELAY_SECONDS = 5

# --- 核心路径逻辑修改 START ---

def get_base_path() -> str:
    """
    直接获取当前执行文件（.py脚本或.exe）所在的绝对目录。

    对于打包后的应用（如.exe），sys.argv[0]通常指向可执行文件本身，
    我们使用其目录作为所有资源的基础路径。
    """
    if getattr(sys, 'frozen', False):
        # 如果是打包后的可执行文件，通常 sys.executable 更可靠地指向 .exe
        return os.path.dirname(sys.executable)

    # 对于 .py 脚本或未识别的打包环境，使用 sys.argv[0]
    try:
        if sys.argv[0]:
            return os.path.dirname(os.path.abspath(sys.argv[0]))
    except Exception:
        pass

    # 最终回退
    return os.path.abspath('.')

# 使用最简单粗暴的绝对路径获取方式
BASE_PATH_ROOT = get_base_path()

# 1. 确定所有资源的根目录
BASE_DIR = BASE_PATH_ROOT.replace('\\', '/')
# 2. 确定配置文件的路径（它应该在 resources/config 目录下）
CONFIG_FILE_PATH = os.path.join(BASE_DIR, "resources", "config", "config.json")
CONNECTION_POOL_SIZE = 5

# 3. 显式指定 Flask 的模板和静态文件目录
TEMPLATE_FOLDER = os.path.join(BASE_PATH_ROOT, 'templates')
STATIC_FOLDER = os.path.join(BASE_PATH_ROOT, 'static')

app = Flask(
    __name__,
    template_folder=TEMPLATE_FOLDER,
    static_folder=STATIC_FOLDER
)
app.config['SECRET_KEY'] = 'mignon-rex-is-the-best'
socketio = SocketIO(app, async_mode='gevent')
# --- 核心路径逻辑修改 END ---

# --- Bridge for UI Logging & Notifications ---
class SocketIOHandler(logging.Handler):
    def emit(self, record):
        print(record.getMessage())
        log_entry = self.format(record)
        socketio.emit('log_message', {'data': log_entry})
        if record.levelno >= logging.WARNING:
            socketio.emit('notification', {
                'type': 'warning' if record.levelno == logging.WARNING else 'error',
                'message': record.getMessage()
            })

# --- Logger Setup ---
# 确保 Logger 模块使用修改后的 BASE_DIR
log = Logger(True, os.path.join(BASE_DIR, "resources", "log"))
ui_logger = logging.getLogger('ssh_tunnel_manager_ui')
ui_logger.setLevel(logging.INFO)
if not ui_logger.handlers:
    socketio_handler = SocketIOHandler()
    formatter = logging.Formatter('%(asctime)s | %(levelname)-7s | %(message)s', '%Y-%m-%d %H:%M:%S')
    socketio_handler.setFormatter(formatter)
    ui_logger.addHandler(socketio_handler)

# --- Configuration Management ---
manager = JsonConfigManager(CONFIG_FILE_PATH)

# --- Data Models (Schema) ---
@dataclass
class SSHConnectionConfig:
    ssh_server_host: str = "127.0.0.1"
    ssh_server_port: int = 22
    ssh_username: str = "root"
    ssh_password: str = ""

@dataclass
class ForwardRule:
    id: str = ""
    local_host: str = "127.0.0.1"
    local_port: int = 10086
    remote_host: str = "127.0.0.1"
    remote_port: int = 10086
    comment: Optional[str] = ""
    enabled: bool = True

@dataclass
class ServerGroup:
    id: str = ""
    name: str = "New Server Group"
    ssh_connection: SSHConnectionConfig = field(default_factory=SSHConnectionConfig)
    forwards: List[ForwardRule] = field(default_factory=list)
    enabled: bool = True

@injectJson(manager)
@dataclass
class AppConfig:
    server_groups: List[ServerGroup] = field(default_factory=list)

# --- Global State (Refactored for Central Monitoring) ---
# 存储 sshtunnel 实例，而不是线程
active_tunnels: Dict[str, sshtunnel.SSHTunnelForwarder] = {}
tunnel_lock = threading.Lock()
app_config = AppConfig()

# 单一监控线程和线程池
monitor_service: Optional['TunnelMonitorService'] = None
connection_executor: concurrent.futures.ThreadPoolExecutor = concurrent.futures.ThreadPoolExecutor(
    max_workers=CONNECTION_POOL_SIZE
)

# --- Helper Function ---
def object_to_dict(obj):
    if hasattr(obj, '_data'): # Handle framework's proxy objects first
        return object_to_dict(obj._data)
    if hasattr(obj, '__dataclass_fields__'): # Handle dataclass instances
        return asdict(obj)
    if isinstance(obj, dict):
        return {k: object_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [object_to_dict(i) for i in i]
    return obj

def generate_unique_id():
    """生成一个基于当前时间的毫秒级时间戳字符串，确保唯一性。"""
    time.sleep(0.001)
    return str(int(time.time() * 1000))

def convert_forward_config(input_data: dict) -> dict:
    """
    将旧格式的SSH转发配置JSON转换为按服务器分组的新格式。
    （保留此函数以兼容旧配置迁移）
    """
    server_map = defaultdict(list)
    for forward_rule in input_data.get("forwards", []):
        ssh_conn = forward_rule.get("ssh_connection")
        if not ssh_conn: continue
        server_key = (
            ssh_conn.get("ssh_server_host"),
            ssh_conn.get("ssh_server_port"),
            ssh_conn.get("ssh_username")
        )
        server_map[server_key].append({"forward_details": forward_rule, "ssh_connection_details": ssh_conn})

    output_data = {"server_groups": []}
    for server_key, forwards_list in server_map.items():
        shared_ssh_connection = forwards_list[0]["ssh_connection_details"]
        server_group = {
            "id": generate_unique_id(),
            "name": server_key[0] or "unnamed_server",
            "ssh_connection": shared_ssh_connection,
            "forwards": [],
            "enabled": True
        }
        for item in forwards_list:
            original_rule = item["forward_details"]
            new_forward_rule = {
                "id": generate_unique_id(),
                "local_host": original_rule.get("local_host"),
                "local_port": original_rule.get("local_port"),
                "remote_host": original_rule.get("remote_host"),
                "remote_port": original_rule.get("remote_port"),
                "comment": original_rule.get("comment"),
                "enabled": True
            }
            server_group["forwards"].append(new_forward_rule)
        output_data["server_groups"].append(server_group)
    return output_data


# --- Core Tunnel Logic (Centralized Monitoring) ---

def attempt_connection(tunnel_id: str, server_group: ServerGroup, rule: ForwardRule, is_reconnect: bool = False):
    """
    阻塞式地尝试建立并启动SSH隧道。此函数在线程池中执行。
    """
    server: Optional[sshtunnel.SSHTunnelForwarder] = None

    # 1. 尝试获取或创建隧道实例
    with tunnel_lock:
        server = active_tunnels.get(tunnel_id)

    # 如果实例不存在，或者是在重连时需要重新创建（为了捕获最新的配置，虽然sshtunnel允许动态配置，但安全起见）
    # 在这个重构中，我们依赖 MonitorService 在配置变更时调用 stop_tunnel 来替换实例。
    if server is None:
        try:
            conn = server_group.ssh_connection
            server = sshtunnel.SSHTunnelForwarder(
                (conn.ssh_server_host, conn.ssh_server_port),
                ssh_username=conn.ssh_username,
                ssh_password=conn.ssh_password,
                local_bind_address=(rule.local_host, rule.local_port),
                remote_bind_address=(rule.remote_host, rule.remote_port),
                set_keepalive=30.0
            )
        except Exception as e:
            ui_logger.error(f"隧道 '{rule.comment}' 创建实例失败: {e}")
            return # 无法创建实例，直接返回

    # 2. 尝试启动 (这是阻塞操作)
    try:
        if not server.is_active:
            ui_logger.info(f"隧道 '{rule.comment}' 正在尝试 {'(重)' if is_reconnect else ''}连接...")
            socketio.emit('notification', {'type': 'info', 'message': f"正在连接: {rule.comment}"})
            server.start()

            with tunnel_lock:
                active_tunnels[tunnel_id] = server # 确保实例被存储

            ui_logger.info(f"隧道 '{rule.comment}' ({rule.local_host}:{rule.local_port}) 连接成功。")

    except Exception as e:
        ui_logger.error(f"隧道 '{rule.comment}' 连接失败: {e}")
        if server and server.is_active:
            try: server.stop()
            except Exception: pass
        # 连接失败后，保持实例在 active_tunnels 中，等待 MonitorService 下一轮重连

def start_tunnel(server_group: ServerGroup, rule: ForwardRule):
    """外部调用：注册隧道并尝试立即启动连接。"""
    tunnel_id = f"{server_group.id}_{rule.id}"

    with tunnel_lock:
        if tunnel_id in active_tunnels:
            # 隧道已存在，可能只是连接断开，无需重复启动
            ui_logger.warning(f"隧道 {rule.comment} 已在管理中，不重复添加。")
            return

    # 提交到执行器中进行阻塞式连接尝试
    connection_executor.submit(attempt_connection, tunnel_id, server_group, rule, False)


def stop_tunnel(server_group_id: str, rule_id: str):
    """外部调用：安全停止隧道并从管理中移除。"""
    tunnel_id = f"{server_group_id}_{rule_id}"

    server = None
    with tunnel_lock:
        # 移除 sshtunnel 实例
        server = active_tunnels.pop(tunnel_id, None)

    if server:
        ui_logger.info(f"正在停止隧道 {tunnel_id} ('{server.local_bind_address[1]}')...")
        try:
            if server.is_active:
                server.stop()
            ui_logger.info(f"隧道 {tunnel_id} 已安全停止。")
        except Exception as e:
            # 停止一个可能已经处于异常状态的隧道时，可能会抛出异常
            ui_logger.error(f"停止隧道 {tunnel_id} 时出错: {e}")


def stop_all_tunnels_for_group(server_group_id: str):
    """停止一个服务器组下的所有隧道。"""
    group = next((g for g in app_config.server_groups if g.id == server_group_id), None)
    if group:
        # 注意：这里需要对副本进行操作，因为 stop_tunnel 会修改 forwards 列表
        for f in list(group.forwards):
            stop_tunnel(group.id, f.id)

class TunnelMonitorService(threading.Thread):
    """
    单一的、永久运行的线程，负责监控所有已注册隧道的连接状态，并处理重连。
    """
    def __init__(self, check_interval: int):
        super().__init__(daemon=True)
        self.check_interval = check_interval
        self._stop_event = threading.Event()

    def stop(self):
        """设置停止事件，主循环将退出。"""
        self._stop_event.set()

    def run(self):
        """监控主循环。"""
        ui_logger.info("隧道监控服务已启动。")
        while not self._stop_event.is_set():
            tunnels_to_reconnect = []

            # 复制 active_tunnels 列表以避免在迭代时被修改
            with tunnel_lock:
                current_active_tunnels = list(active_tunnels.items())

            for tunnel_id, server in current_active_tunnels:
                # 1. 检查配置是否仍然存在且启用
                try:
                    group_id, rule_id = tunnel_id.split('_')
                except ValueError:
                    ui_logger.error(f"无效的隧道ID格式: {tunnel_id}")
                    stop_tunnel(group_id, rule_id)
                    continue

                group = next((g for g in app_config.server_groups if g.id == group_id), None)
                if not group or not group.enabled:
                    stop_tunnel(group_id, rule_id)
                    continue

                rule = next((f for f in group.forwards if f.id == rule_id), None)
                if not rule or not rule.enabled:
                    stop_tunnel(group_id, rule_id)
                    continue

                # 2. 检查隧道状态
                if not server.is_active:
                    # 发现非活动隧道，添加到重连列表
                    tunnels_to_reconnect.append((tunnel_id, group, rule))

            # 3. 提交重连任务到线程池
            for tunnel_id, group, rule in tunnels_to_reconnect:
                # 将重连操作提交给线程池执行，避免阻塞监控线程
                connection_executor.submit(attempt_connection, tunnel_id, group, rule, True)

            # 休息，等待下一轮检查
            self._stop_event.wait(self.check_interval)

# --- Flask API & WebSocket Endpoints (Use new start/stop functions) ---

@socketio.on('connect')
def handle_connect():
    if not hasattr(g, 'is_connected'):
        print("前端 WebSocket 连接成功")
        g.is_connected = True

@app.route('/')
def index() -> str:
    return render_template('index.html', server_groups=app_config.server_groups)

@app.route('/logs')
def logs() -> str:
    return render_template('logs.html')

@app.route('/api/servers/<string:server_id>', methods=['GET'])
def get_server(server_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group:
        return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    return jsonify({'status': 'success', 'group': object_to_dict(group)})

@app.route('/api/tunnels/<string:server_id>/<string:rule_id>', methods=['GET'])
def get_tunnel(server_id: str, rule_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group:
        return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    rule = next((f for f in group.forwards if f.id == rule_id), None)
    if not rule:
        return jsonify({'status': 'error', 'message': '未找到隧道'}), 404
    return jsonify({'status': 'success', 'rule': object_to_dict(rule)})

@app.route('/api/servers/test', methods=['POST'])
def test_server_connection() -> Response | tuple[Response, int]:
    data = request.json
    host = data.get('ssh_host')
    port = int(data.get('ssh_port', 22))
    user = data.get('ssh_user')
    password = data.get('ssh_pass')

    if not all([host, user, password]):
        return jsonify({'status': 'error', 'message': '缺少连接参数'}), 400

    server = None
    try:
        server = sshtunnel.SSHTunnelForwarder(
            (host, port), ssh_username=user, ssh_password=password, set_keepalive=5.0
        )
        server.start()
        server.stop()
        return jsonify({'status': 'success', 'message': 'SSH 连接成功!'})
    except Exception as e:
        if server:
            try:
                server.stop()
            except Exception:
                pass
        return jsonify({'status': 'error', 'message': f'连接失败: {e}'}), 400

@app.route('/api/servers', methods=['POST'])
def add_server() -> Response:
    data = request.json
    new_group = ServerGroup(
        id=generate_unique_id(),
        name=data['name'],
        ssh_connection=SSHConnectionConfig(
            ssh_server_host=data['ssh_host'],
            ssh_server_port=int(data['ssh_port']),
            ssh_username=data['ssh_user'],
            ssh_password=data['ssh_pass']
        ),
        forwards=[],
        enabled=True
    )
    app_config.server_groups.append(new_group)
    return jsonify({'status': 'success', 'message': '服务器组已添加', 'group': object_to_dict(new_group)})

@app.route('/api/servers/<string:server_id>', methods=['PUT'])
def edit_server(server_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group: return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    data = request.json
    group.name = data['name']
    conn = group.ssh_connection
    conn.ssh_server_host = data['ssh_host']; conn.ssh_server_port = int(data['ssh_port'])
    conn.ssh_username = data['ssh_user']
    if data.get('ssh_pass'):
        conn.ssh_password = data['ssh_pass']
    ui_logger.info(f"服务器组 '{group.name}' 配置已更新。")

    # 因为连接配置可能已更改，我们需要重启所有依赖的隧道
    restart_server_tunnels(server_id)
    return jsonify({'status': 'success', 'message': '服务器组已更新', 'group': object_to_dict(group)})

@app.route('/api/servers/<string:server_id>', methods=['DELETE'])
def delete_server(server_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if group:
        stop_all_tunnels_for_group(server_id)
        app_config.server_groups.remove(group)
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404

@app.route('/api/servers/toggle/<string:server_id>', methods=['POST'])
def toggle_server(server_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group: return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    group.enabled = not group.enabled
    if group.enabled:
        ui_logger.info(f"服务器组 '{group.name}' 已启用，尝试启动子隧道。")
        for f in group.forwards:
            if f.enabled: start_tunnel(group, f)
    else:
        ui_logger.warning(f"服务器组 '{group.name}' 已禁用，正在停止所有子隧道。")
        stop_all_tunnels_for_group(group.id)
    return jsonify({'status': 'success', 'enabled': group.enabled})

@app.route('/api/servers/restart/<string:server_id>', methods=['POST'])
def restart_server_tunnels(server_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group: return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    if not group.enabled: return jsonify({'status': 'error', 'message': '禁用的服务器组无法重启'}), 400
    ui_logger.info(f"正在重启服务器组 '{group.name}' 的所有隧道...")
    stop_all_tunnels_for_group(server_id)
    time.sleep(1) # 给时间让端口释放
    for f in group.forwards:
        if f.enabled: start_tunnel(group, f)
    return jsonify({'status': 'success'})

@app.route('/api/tunnels', methods=['POST'])
def add_tunnel() -> Union[Response, Tuple[Response, int]]:
    data = request.json
    server_id = str(data['server_id'])
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group: return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    new_rule = ForwardRule(
        id=generate_unique_id(),
        local_host=data['local_host'], local_port=int(data['local_port']),
        remote_host=data['remote_host'], remote_port=int(data['remote_port']),
        comment=data['comment'], enabled=True
    )
    group.forwards.append(new_rule)
    if group.enabled and new_rule.enabled: start_tunnel(group, new_rule)
    return jsonify({'status': 'success', 'message': '隧道已添加', 'rule': object_to_dict(new_rule)})

@app.route('/api/tunnels/<string:server_id>/<string:rule_id>', methods=['PUT'])
def edit_tunnel(server_id: str, rule_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group: return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    rule = next((f for f in group.forwards if f.id == rule_id), None)
    if not rule: return jsonify({'status': 'error', 'message': '未找到隧道'}), 404
    data = request.json

    # 检查是否有需要重启的配置更改 (端口, 地址)
    needs_restart = (
            rule.local_host != data['local_host'] or
            rule.local_port != int(data['local_port']) or
            rule.remote_host != data['remote_host'] or
            rule.remote_port != int(data['remote_port'])
    )

    rule.local_host = data['local_host']; rule.local_port = int(data['local_port'])
    rule.remote_host = data['remote_host']; rule.remote_port = int(data['remote_port'])
    rule.comment = data['comment']

    if needs_restart and group.enabled:
        ui_logger.info(f"隧道 '{rule.comment}' 配置已更改 (需要重启)。")
        stop_tunnel(server_id, rule_id)
        time.sleep(0.5)
        if rule.enabled: start_tunnel(group, rule)
    else:
        ui_logger.info(f"隧道 '{rule.comment}' 注释已更新，无需重启。")

    return jsonify({'status': 'success', 'message': '隧道已更新', 'rule': object_to_dict(rule)})

@app.route('/api/tunnels/<string:server_id>/<string:rule_id>', methods=['DELETE'])
def delete_tunnel(server_id: str, rule_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if group:
        rule = next((f for f in group.forwards if f.id == rule_id), None)
        if rule:
            stop_tunnel(server_id, rule_id)
            group.forwards.remove(rule)
            return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': '未找到隧道'}), 404

@app.route('/api/tunnels/toggle/<string:server_id>/<string:rule_id>', methods=['POST'])
def toggle_tunnel(server_id: str, rule_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group: return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    rule = next((f for f in group.forwards if f.id == rule_id), None)
    if not rule: return jsonify({'status': 'error', 'message': '未找到转发规则'}), 404

    rule.enabled = not rule.enabled

    if group.enabled and rule.enabled:
        start_tunnel(group, rule)
    else:
        stop_tunnel(group.id, rule.id)

    return jsonify({'status': 'success', 'enabled': rule.enabled})



@app.route('/favicon.ico')
def facico():
    directory = os.path.join(STATIC_FOLDER, 'ico')
    filename = 'favicon.ico'
    return send_from_directory(directory, filename)











@app.route('/api/control/toggle_all/<action>', methods=['POST'])
def toggle_all_tunnels(action: str) -> Union[Response, Tuple[Response, int]]:
    enable = action == 'enable'
    for group in app_config.server_groups:
        group.enabled = enable
        if enable:
            for f in group.forwards:
                if f.enabled: start_tunnel(group, f)
        else: stop_all_tunnels_for_group(group.id)
    return jsonify({'status': 'success'})

# --- Application Startup ---
def load_and_start_all_tunnels():
    """初始化时启动所有已配置且启用的隧道。"""
    global monitor_service
    ui_logger.info("正在启动所有已配置且启用的隧道...")
    for group in app_config.server_groups:
        if group.enabled:
            for rule in group.forwards:
                if rule.enabled:
                    # 将连接尝试提交给线程池
                    connection_executor.submit(attempt_connection, f"{group.id}_{rule.id}", group, rule, False)
    ui_logger.info("所有初始隧道任务已派发。")

    # 启动单一监控服务线程
    monitor_service = TunnelMonitorService(RECONNECT_DELAY_SECONDS)
    monitor_service.start()
    ui_logger.info("中央隧道监控服务已启动。")


def shutdown_handler(signum, frame):
    """安全关闭所有隧道、线程池和监控服务。"""
    print("\n[*] 收到退出信号，正在关闭所有隧道和监控服务...")

    # 1. 停止中央监控服务
    if monitor_service:
        monitor_service.stop()
        monitor_service.join(timeout=3)

    # 2. 停止所有活跃的隧道
    with tunnel_lock:
        tunnel_ids = list(active_tunnels.keys())

    for tunnel_id in tunnel_ids:
        try:
            group_id, rule_id = tunnel_id.split('_')
            stop_tunnel(group_id, rule_id)
        except Exception as e:
            print(f"关闭隧道 {tunnel_id} 时发生错误: {e}")

    # 3. 关闭线程池
    connection_executor.shutdown(wait=True)

    print("[*] 程序退出。")
    sys.exit(0)


def main():
    try:
        # 兼容旧的 config.json 文件
        if os.path.exists("./config.json"):
            with open("./config.json", "r", encoding="utf-8") as f:
                data = f.read()
                data = json.loads(data)
                data = convert_forward_config(data)

                # 确保 resources/config 目录存在
                config_dir = os.path.dirname(CONFIG_FILE_PATH)
                os.makedirs(config_dir, exist_ok=True)

                with open(CONFIG_FILE_PATH, "w", encoding="utf-8") as fi:
                    fi.write(json.dumps(data, indent=4, ensure_ascii=False))
            os.remove("./config.json")
            ui_logger.info("成功从旧格式 config.json 迁移配置。")
    except Exception as e:
        # 打印迁移错误，但不阻止程序继续运行
        print(f"配置迁移过程中出现错误: {e}")

    parser = argparse.ArgumentParser(description="SSH 隧道 Web 管理器")
    parser.add_argument('--host', type=str, default='127.0.0.1', help='指定启动的 Host')
    parser.add_argument('--port', type=int, default=2592, help='指定启动的端口')
    args = parser.parse_args()

    logging.getLogger('werkzeug').disabled = True
    logging.getLogger('geventwebsocket.handler').disabled = True

    load_and_start_all_tunnels()

    url = f"http://{args.host}:{args.port}"
    print(f"在浏览器中打开: {url}")
    webbrowser.open_new(url)

    print("SSH Tunnel Manager 已启动。")
    # 使用 gevent 运行 Flask 和 SocketIO
    socketio.run(app, host=args.host, port=args.port, debug=False)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    main()
