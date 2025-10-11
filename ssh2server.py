import os
import sys
import signal
import threading
import time
import webbrowser
import argparse
import logging
import concurrent.futures
from typing import List, Optional, Dict, Tuple, Union, Set
from flask import Flask, render_template, request, jsonify, Response, g, send_from_directory
from flask_socketio import SocketIO
import sshtunnel
from dataclasses import dataclass, field, asdict
import json
from collections import defaultdict
from mignonFramework import JsonConfigManager, injectJson, Logger
import paramiko
import socket
RECONNECT_DELAY_SECONDS = 5


def get_base_path() -> str:
    """
    直接获取当前执行文件（.py脚本或.exe）所在的绝对目录。

    对于打包后的应用（如.exe），sys.argv[0]通常指向可执行文件本身，
    我们使用其目录作为所有资源的基础路径。
    """
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)

    try:
        if sys.argv[0]:
            return os.path.dirname(os.path.abspath(sys.argv[0]))
    except Exception:
        pass

    # 最终回退
    return os.path.abspath('.')

BASE_PATH_ROOT = get_base_path()

# 1. 确定所有资源的根目录
BASE_DIR = BASE_PATH_ROOT.replace('\\', '/')
# 2. 确定配置文件的路径（它应该在 resources/config 目录下）
CONFIG_FILE_PATH = os.path.join(BASE_DIR, "resources", "config", "config.json")
CONNECTION_POOL_SIZE = 10 # 适当增加线程池大小以应对可能的阻塞

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

class SocketIOHandler(logging.Handler):
    def emit(self, record):
        try:
            print(record.getMessage())
            log_entry = self.format(record)
            socketio.emit('log_message', {'data': log_entry})
            if record.levelno >= logging.WARNING:
                socketio.emit('notification', {
                    'type': 'warning' if record.levelno == logging.WARNING else 'error',
                    'message': record.getMessage()
                })
        except Exception:
            # 在socket连接不可用时，防止日志系统崩溃
            pass

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
active_tunnels: Dict[str, sshtunnel.SSHTunnelForwarder] = {}
tunnels_being_stopped: Set[str] = set() # BUGFIX: 新增集合来标记正在停止的隧道
tunnel_lock = threading.Lock()
app_config = AppConfig()

monitor_service: Optional['TunnelMonitorService'] = None
connection_executor: concurrent.futures.ThreadPoolExecutor = concurrent.futures.ThreadPoolExecutor(
    max_workers=CONNECTION_POOL_SIZE
)

# --- Helper Function ---
def object_to_dict(obj):
    if hasattr(obj, '_data'):
        return object_to_dict(obj._data)
    if hasattr(obj, '__dataclass_fields__'):
        return asdict(obj)
    if isinstance(obj, dict):
        return {k: object_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [object_to_dict(i) for i in obj]
    return obj

def generate_unique_id():
    time.sleep(0.001)
    return str(int(time.time() * 1000))

def convert_forward_config(input_data: dict) -> dict:
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
    with tunnel_lock:
        if tunnel_id in tunnels_being_stopped:
            ui_logger.info(f"隧道 '{rule.comment}' 的连接尝试被中止，因为它已被标记为停止。")
            tunnels_being_stopped.discard(tunnel_id)
            return

    server: Optional[sshtunnel.SSHTunnelForwarder] = None
    try:
        conn = server_group.ssh_connection
        # BUGFIX: 移除了不存在的 ssh_timeout 参数
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
        return

    try:
        with tunnel_lock:
            if tunnel_id in tunnels_being_stopped:
                ui_logger.info(f"隧道 '{rule.comment}' 的启动被中止，因为它在实例创建后被标记为停止。")
                tunnels_being_stopped.discard(tunnel_id)
                return

        ui_logger.info(f"隧道 '{rule.comment}' 正在尝试 {'(重)' if is_reconnect else ''}连接...")
        socketio.emit('notification', {'type': 'info', 'message': f"正在连接: {rule.comment}"})
        server.start()

        with tunnel_lock:
            if tunnel_id in tunnels_being_stopped:
                ui_logger.warning(f"隧道 '{rule.comment}' 在连接成功后立即被停止。")
                server.stop()
                tunnels_being_stopped.discard(tunnel_id)
                return
            active_tunnels[tunnel_id] = server

        ui_logger.info(f"隧道 '{rule.comment}' ({rule.local_host}:{rule.local_port}) 连接成功。")

    except Exception as e:
        error_message = str(e)
        if "Authentication failed" in error_message:
            ui_logger.error(f"隧道 '{rule.comment}' 认证失败，请检查用户名和密码。")
        elif "Could not resolve hostname" in error_message:
            ui_logger.error(f"隧道 '{rule.comment}' 无法解析SSH主机名。")
        else:
            ui_logger.error(f"隧道 '{rule.comment}' 连接失败: {error_message}")

        if is_reconnect:
            time.sleep(RECONNECT_DELAY_SECONDS)

        if server and server.is_active:
            try: server.stop()
            except Exception: pass
    finally:
        with tunnel_lock:
            if tunnel_id in tunnels_being_stopped:
                if server and server.is_active:
                    try: server.stop()
                    except Exception as e:
                        ui_logger.error(f"在 finally 块中停止隧道 '{rule.comment}' 时出错: {e}")
                tunnels_being_stopped.discard(tunnel_id)


def start_tunnel(server_group: ServerGroup, rule: ForwardRule):
    """外部调用：注册隧道并尝试立即启动连接。"""
    tunnel_id = f"{server_group.id}_{rule.id}"

    with tunnel_lock:
        if tunnel_id in active_tunnels:
            ui_logger.warning(f"隧道 '{rule.comment}' 已在管理中，不重复添加。")
            return
        tunnels_being_stopped.discard(tunnel_id)

    connection_executor.submit(attempt_connection, tunnel_id, server_group, rule, False)


def stop_tunnel(server_group_id: str, rule_id: str):
    """外部调用：安全停止隧道并从管理中移除。"""
    tunnel_id = f"{server_group_id}_{rule_id}"

    server = None
    with tunnel_lock:
        tunnels_being_stopped.add(tunnel_id)
        server = active_tunnels.pop(tunnel_id, None)

    if server:
        def do_stop():
            rule = next((f for g in app_config.server_groups if g.id == server_group_id for f in g.forwards if f.id == rule_id), None)
            comment = rule.comment if rule else tunnel_id
            ui_logger.info(f"正在停止隧道 '{comment}'...")
            try:
                if server.is_active:
                    server.stop()
                ui_logger.info(f"隧道 '{comment}' 已安全停止。")
            except Exception as e:
                ui_logger.error(f"停止隧道 '{comment}' 时出错: {e}")
            finally:
                with tunnel_lock:
                    tunnels_being_stopped.discard(tunnel_id)
        connection_executor.submit(do_stop)
    else:
        ui_logger.info(f"隧道 {tunnel_id} 未处于活动状态，但已标记为停止，连接尝试将被中止。")


def stop_all_tunnels_for_group(server_group_id: str):
    """停止一个服务器组下的所有隧道。"""
    group = next((g for g in app_config.server_groups if g.id == server_group_id), None)
    if group:
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
        self._stop_event.set()

    def run(self):
        ui_logger.info("隧道监控服务已启动。")
        while not self._stop_event.is_set():
            tunnels_to_reconnect = []

            with tunnel_lock:
                # 创建当前受管隧道的快照以进行迭代
                managed_tunnels_snapshot = list(active_tunnels.items())

            for tunnel_id, server in managed_tunnels_snapshot:
                if tunnel_id in tunnels_being_stopped:
                    continue # 如果隧道正在被手动停止，则跳过检查

                if not server.is_active:
                    try:
                        group_id, rule_id = tunnel_id.split('_')
                        group = next((g for g in app_config.server_groups if g.id == group_id), None)
                        if group:
                            rule = next((f for f in group.forwards if f.id == rule_id), None)
                            if rule and group.enabled and rule.enabled:
                                ui_logger.warning(f"监控服务发现隧道 '{rule.comment}' 已断开，准备重连。")
                                tunnels_to_reconnect.append((tunnel_id, group, rule))
                    except (ValueError, StopIteration):
                        # 如果解析ID或查找配置失败，说明配置已过时，将其移除
                        ui_logger.error(f"无法找到隧道 {tunnel_id} 的配置，将停止并移除。")
                        stop_tunnel(*tunnel_id.split('_'))

            # 现在处理需要重连的隧道
            for tunnel_id, group, rule in tunnels_to_reconnect:
                old_server = None
                with tunnel_lock:
                    if tunnel_id in tunnels_being_stopped:
                        continue
                    # 采用“销毁并重建”策略，先移除旧的、失效的实例
                    old_server = active_tunnels.pop(tunnel_id, None)

                # BUGFIX: 在锁之外，显式停止旧的实例以释放资源
                if old_server:
                    try:
                        old_server.stop()
                    except Exception as e:
                        ui_logger.info(f"在清理旧隧道实例 '{rule.comment}' 时出现错误(可忽略): {e}")

                # 提交一个全新的连接任务
                connection_executor.submit(attempt_connection, tunnel_id, group, rule, True)

            self._stop_event.wait(self.check_interval)

# --- Flask API & WebSocket Endpoints ---

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
def test_server_connection_with_paramiko() -> Union[Response, Tuple[Response, int]]:
    """
    使用 paramiko 库测试 SSH 服务器连接，并显式设置超时。
    """
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': '请求体为空'}), 400

    host = data.get('ssh_host')
    port = int(data.get('ssh_port', 22))
    user = data.get('ssh_user')
    password = data.get('ssh_pass')

    if not all([host, user]): # 密码可以为空
        return jsonify({'status': 'error', 'message': '缺少必要的连接参数 (ssh_host, ssh_user)'}), 400

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh_client.connect(
            hostname=host,
            port=port,
            username=user,
            password=password,
            timeout=10,
            look_for_keys=False,
            allow_agent=False
        )
        return jsonify({'status': 'success', 'message': 'SSH 连接成功!'})
    except socket.timeout:
        error_message = f'连接超时，服务器 {host}:{port} 在指定时间内没有响应。'
        return jsonify({'status': 'error', 'message': error_message}), 400
    except paramiko.AuthenticationException:
        error_message = f'认证失败，请检查用户名和密码。'
        return jsonify({'status': 'error', 'message': error_message}), 400
    except paramiko.SSHException as e:
        error_message = f'SSH 连接错误: {e}'
        return jsonify({'status': 'error', 'message': error_message}), 400
    except Exception as e:
        error_message = f'发生未知错误: {e}'
        return jsonify({'status': 'error', 'message': error_message}), 400
    finally:
        try:
            ssh_client.close()
        except Exception:
            pass


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
    conn.ssh_server_host = data['ssh_host']
    conn.ssh_server_port = int(data['ssh_port'])
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

    needs_restart = (
            rule.local_host != data['local_host'] or
            rule.local_port != int(data['local_port']) or
            rule.remote_host != data['remote_host'] or
            rule.remote_port != int(data['remote_port'])
    )

    rule.local_host = data['local_host']
    rule.local_port = int(data['local_port'])
    rule.remote_host = data['remote_host']
    rule.remote_port = int(data['remote_port'])
    rule.comment = data['comment']

    if needs_restart and group.enabled and rule.enabled:
        ui_logger.info(f"隧道 '{rule.comment}' 配置已更改 (需要重启)。")
        stop_tunnel(server_id, rule_id)
        time.sleep(0.5)
        start_tunnel(group, rule)
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
                    connection_executor.submit(attempt_connection, f"{group.id}_{rule.id}", group, rule, False)
    ui_logger.info("所有初始隧道任务已派发。")

    monitor_service = TunnelMonitorService(RECONNECT_DELAY_SECONDS)
    monitor_service.start()


def shutdown_handler(signum, frame):
    """安全关闭所有隧道、线程池和监控服务。"""
    print("\n[*] 收到退出信号，正在关闭所有隧道和监控服务...")

    if monitor_service:
        monitor_service.stop()
        monitor_service.join(timeout=3)

    with tunnel_lock:
        tunnel_ids = list(active_tunnels.keys())

    for tunnel_id in tunnel_ids:
        try:
            group_id, rule_id = tunnel_id.split('_')
            stop_tunnel(group_id, rule_id)
        except Exception as e:
            print(f"关闭隧道 {tunnel_id} 时发生错误: {e}")

    # 等待停止任务完成
    time.sleep(2)
    connection_executor.shutdown(wait=True)

    print("[*] 程序退出。")
    sys.exit(0)


def main():
    try:
        if os.path.exists("./config.json"):
            with open("./config.json", "r", encoding="utf-8") as f:
                data = f.read()
                data = json.loads(data)
                data = convert_forward_config(data)

                config_dir = os.path.dirname(CONFIG_FILE_PATH)
                os.makedirs(config_dir, exist_ok=True)

                with open(CONFIG_FILE_PATH, "w", encoding="utf-8") as fi:
                    fi.write(json.dumps(data, indent=4, ensure_ascii=False))
            os.remove("./config.json")
            ui_logger.info("成功从旧格式 config.json 迁移配置。")
    except Exception as e:
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
    try:
        webbrowser.open_new(url)
    except Exception:
        print("无法自动打开浏览器，请手动访问上面的地址。")

    print("Mignon SSH Tunnel Manager 已启动。")
    socketio.run(app, host=args.host, port=args.port, debug=False)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    main()
