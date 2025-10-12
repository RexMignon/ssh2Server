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
from mignonFramework import JsonConfigManager, injectJson, Logger
import paramiko
import socket
import select

RECONNECT_DELAY_SECONDS = 5


def get_base_path() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    try:
        if sys.argv[0]:
            return os.path.dirname(os.path.abspath(sys.argv[0]))
    except Exception:
        pass
    return os.path.abspath('.')


BASE_PATH_ROOT = get_base_path()
BASE_DIR = BASE_PATH_ROOT.replace('\\', '/')
CONFIG_FILE_PATH = os.path.join(BASE_DIR, "resources", "config", "config.json")
CONNECTION_POOL_SIZE = 20
TEMPLATE_FOLDER = os.path.join(BASE_PATH_ROOT, 'templates')
STATIC_FOLDER = os.path.join(BASE_PATH_ROOT, 'static')

app = Flask(__name__, template_folder=TEMPLATE_FOLDER, static_folder=STATIC_FOLDER)
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
            pass


log = Logger(True, os.path.join(BASE_DIR, "resources", "log"))
ui_logger = logging.getLogger('ssh_tunnel_manager_ui')
ui_logger.setLevel(logging.INFO)
if not ui_logger.handlers:
    socketio_handler = SocketIOHandler()
    formatter = logging.Formatter('%(asctime)s | %(levelname)-7s | %(message)s', '%Y-%m-%d %H:%M:%S')
    socketio_handler.setFormatter(formatter)
    ui_logger.addHandler(socketio_handler)

manager = JsonConfigManager(CONFIG_FILE_PATH)


@dataclass
class SSHConnectionConfig:
    ssh_server_host: str = "127.0.0.1"
    ssh_server_port: int = 22
    ssh_username: str = "root"
    ssh_password: str = ""


@dataclass
class ForwardRule:
    id: str = ""
    tunnel_type: str = "forward"
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


active_tunnels: Dict[str, Union[sshtunnel.SSHTunnelForwarder, 'ReverseTunnelThread']] = {}
tunnels_being_stopped: Set[str] = set()
tunnel_lock = threading.Lock()
app_config = AppConfig()
monitor_service: Optional['TunnelMonitorService'] = None
connection_executor: concurrent.futures.ThreadPoolExecutor = concurrent.futures.ThreadPoolExecutor(
    max_workers=CONNECTION_POOL_SIZE)


def object_to_dict(obj):
    if hasattr(obj, '_data'): return object_to_dict(obj._data)
    if hasattr(obj, '__dataclass_fields__'): return asdict(obj)
    if isinstance(obj, dict): return {k: object_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, list): return [object_to_dict(i) for i in obj]
    return obj


def generate_unique_id():
    time.sleep(0.001)
    return str(int(time.time() * 1000))


# --- Mignon: 新增的反向隧道专用处理类 ---
class ReverseTunnelThread(threading.Thread):
    def __init__(self, server_info, remote_info, local_info, comment):
        super().__init__(daemon=True)
        self.server_info = server_info
        self.remote_info = remote_info
        self.local_info = local_info
        self.comment = comment
        self.client = None
        self._stop_event = threading.Event()
        self._is_really_active = False

    def _log(self, level, message):
        log_func = getattr(ui_logger, level.lower(), ui_logger.info)
        log_func(f"反向隧道 '{self.comment}': {message}")

    def stop(self):
        self._log('info', '停止指令已接收。')
        self._stop_event.set()
        try:
            if self.client and self.client.get_transport() and self.client.get_transport().is_active():
                self._log('info', f"正在请求服务器取消端口转发 {self.remote_info[0]}:{self.remote_info[1]}...")
                transport = self.client.get_transport()
                transport.cancel_port_forward(self.remote_info[0], self.remote_info[1])
                self._log('info', "取消请求已发送。")
        except Exception as e:
            self._log('warning', f"取消端口转发时出错 (可能是良性错误，例如连接已关闭): {e}")
        finally:
            if self.client:
                self.client.close()

    @property
    def is_active(self):
        if self.client and self.client.get_transport():
            return self._is_really_active and self.client.get_transport().is_active() and not self._stop_event.is_set()
        return False

    def run(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.WarningPolicy())
            self._log('info', f"正在连接到SSH服务器 {self.server_info['host']}:{self.server_info['port']}...")
            self.client.connect(
                hostname=self.server_info['host'], port=self.server_info['port'],
                username=self.server_info['user'], password=self.server_info['pass'],
                timeout=10, look_for_keys=False, allow_agent=False, auth_timeout=30
            )
            transport = self.client.get_transport()

            remote_host, remote_port = self.remote_info

            self._log('info', f"请求在远程服务器上转发端口 {remote_host}:{remote_port}...")

            try:
                transport.request_port_forward(remote_host, remote_port)
            except paramiko.SSHException as e:
                if "TCP forwarding request denied" in str(e):
                    print('warning', "服务器返回 'TCP forwarding request denied'，但这可能是假失败，将继续尝试运行。")
                else:
                    raise

            ui_logger.info(
                f"反向隧道 '{self.comment}' 连接成功。现在访问 {self.server_info['host']}:{remote_port} 将转发到 {self.local_info[0]}:{self.local_info[1]}。")
            self._is_really_active = True

            while not self._stop_event.is_set() and transport.is_active():
                chan = transport.accept(timeout=1)
                if chan is None: continue
                handler = threading.Thread(target=self.handle_channel, args=(chan,), daemon=True)
                handler.start()

        except Exception as e:
            error_message = str(e)
            if "Authentication failed" in error_message:
                self._log('error', "认证失败，请检查用户名和密码。")
            elif "Could not resolve hostname" in error_message:
                self._log('error', "无法解析SSH主机名。")
            elif "Administratively prohibited" in error_message or "bind failed" in error_message:
                self._log('error',
                          f"绑定远程端口失败。请检查：1. 远程端口 {self.remote_info[1]} 是否已被占用。 2. SSH服务器配置 /etc/ssh/sshd_config 中是否已设置 GatewayPorts yes。")
            elif "TCP forwarding request denied" not in error_message:
                self._log('error', f"发生错误: {error_message}")
        finally:
            self._is_really_active = False
            self._log('info', "线程已终止。")
            if self.client: self.client.close()

    def handle_channel(self, chan):
        local_host, local_port = self.local_info
        peer_address = chan.getpeername()
        local_socket = None
        try:
            local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            local_socket.connect((local_host, local_port))
            while not self._stop_event.is_set():
                r, w, x = select.select([chan, local_socket], [], [], 0.1)
                if chan in r:
                    data = chan.recv(1024)
                    if not data: break
                    local_socket.send(data)
                if local_socket in r:
                    data = local_socket.recv(1024)
                    if not data: break
                    chan.send(data)
        except Exception as e:
            self._log('warning', f"处理来自 {peer_address} 的连接时出错: {e}")
        finally:
            if chan: chan.close()
            if local_socket: local_socket.close()


def attempt_connection(tunnel_id: str, server_group: ServerGroup, rule: ForwardRule, is_reconnect: bool = False):
    with tunnel_lock:
        if tunnel_id in tunnels_being_stopped:
            ui_logger.info(f"隧道 '{rule.comment}' 的连接尝试被中止，因为它已被标记为停止。")
            tunnels_being_stopped.discard(tunnel_id)
            return

    server: Optional[Union[sshtunnel.SSHTunnelForwarder, ReverseTunnelThread]] = None
    try:
        conn = server_group.ssh_connection

        if rule.tunnel_type == 'reverse':
            server_info = {'host': conn.ssh_server_host, 'port': conn.ssh_server_port, 'user': conn.ssh_username,
                           'pass': conn.ssh_password}
            remote_info = (rule.remote_host, rule.remote_port)
            local_info = (rule.local_host, rule.local_port)
            server = ReverseTunnelThread(server_info, remote_info, local_info, rule.comment)
        else:
            ui_logger.info(
                f"准备创建 [正向] 隧道 '{rule.comment}': 本地 {rule.local_host}:{rule.local_port} -> 远程 {rule.remote_host}:{rule.remote_port}")
            server = sshtunnel.SSHTunnelForwarder(
                (conn.ssh_server_host, conn.ssh_server_port),
                ssh_username=conn.ssh_username, ssh_password=conn.ssh_password,
                local_bind_address=(rule.local_host, rule.local_port),
                remote_bind_address=(rule.remote_host, rule.remote_port),
                set_keepalive=30.0
            )

        with tunnel_lock:
            if tunnel_id in tunnels_being_stopped:
                return
            active_tunnels[tunnel_id] = server

        if isinstance(server, sshtunnel.SSHTunnelForwarder):
            ui_logger.info(f"隧道 '{rule.comment}' 正在尝试 {'(重)' if is_reconnect else ''}连接...")
            socketio.emit('notification', {'type': 'info', 'message': f"正在连接: {rule.comment}"})
            server.start()
            ui_logger.info(
                f"正向隧道 '{rule.comment}' 连接成功。现在访问 {rule.local_host}:{rule.local_port} 将转发到 {rule.remote_host}:{rule.remote_port}。")
        else:
            server.start()

    except Exception as e:
        with tunnel_lock:
            active_tunnels.pop(tunnel_id, None)
        error_message = str(e)
        if "Authentication failed" in error_message:
            ui_logger.error(f"隧道 '{rule.comment}' 认证失败，请检查用户名和密码。")
        elif "Could not resolve hostname" in error_message:
            ui_logger.error(f"隧道 '{rule.comment}' 无法解析SSH主机名。")
        else:
            ui_logger.error(f"隧道 '{rule.comment}' 连接失败: {error_message}")
        if is_reconnect: time.sleep(RECONNECT_DELAY_SECONDS)


def start_tunnel(server_group: ServerGroup, rule: ForwardRule):
    tunnel_id = f"{server_group.id}_{rule.id}"
    with tunnel_lock:
        if tunnel_id in active_tunnels:
            ui_logger.warning(f"隧道 '{rule.comment}' 已在管理中，不重复添加。")
            return
        tunnels_being_stopped.discard(tunnel_id)
    connection_executor.submit(attempt_connection, tunnel_id, server_group, rule, False)


def stop_tunnel(server_group_id: str, rule_id: str):
    tunnel_id = f"{server_group_id}_{rule_id}"
    server = None
    with tunnel_lock:
        tunnels_being_stopped.add(tunnel_id)
        server = active_tunnels.pop(tunnel_id, None)
    if server:
        rule = next(
            (f for g in app_config.server_groups if g.id == server_group_id for f in g.forwards if f.id == rule_id),
            None)
        comment = rule.comment if rule else tunnel_id
        ui_logger.info(f"正在停止隧道 '{comment}'...")
        try:
            server.stop()
            if isinstance(server, threading.Thread):
                server.join(timeout=2)
            ui_logger.info(f"隧道 '{comment}' 已安全停止。")
        except Exception as e:
            ui_logger.error(f"停止隧道 '{comment}' 时出错: {e}")
        finally:
            with tunnel_lock:
                tunnels_being_stopped.discard(tunnel_id)
    else:
        ui_logger.info(f"隧道 {tunnel_id} 未处于活动状态，但已标记为停止，连接尝试将被中止。")


def stop_all_tunnels_for_group(server_group_id: str):
    group = next((g for g in app_config.server_groups if g.id == server_group_id), None)
    if group:
        for f in list(group.forwards):
            stop_tunnel(group.id, f.id)


class TunnelMonitorService(threading.Thread):
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
                managed_tunnels_snapshot = list(active_tunnels.items())
            for tunnel_id, server in managed_tunnels_snapshot:
                if tunnel_id in tunnels_being_stopped: continue
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
                        ui_logger.error(f"无法找到隧道 {tunnel_id} 的配置，将停止并移除。")
                        stop_tunnel(*tunnel_id.split('_'))
            for tunnel_id, group, rule in tunnels_to_reconnect:
                with tunnel_lock:
                    if tunnel_id in tunnels_being_stopped: continue
                    active_tunnels.pop(tunnel_id, None)
                connection_executor.submit(attempt_connection, tunnel_id, group, rule, True)
            self._stop_event.wait(self.check_interval)


@socketio.on('connect')
def handle_connect():
    if not hasattr(g, 'is_connected'): print("前端 WebSocket 连接成功")
    g.is_connected = True


@app.route('/')
def index_page() -> str: return render_template('index.html', server_groups=app_config.server_groups)


@app.route('/logs')
def logs_page() -> str: return render_template('logs.html')


@app.route('/api/servers/<string:server_id>', methods=['GET'])
def get_server(server_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group: return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    return jsonify({'status': 'success', 'group': object_to_dict(group)})


@app.route('/api/tunnels/<string:server_id>/<string:rule_id>', methods=['GET'])
def get_tunnel(server_id: str, rule_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group: return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    rule = next((f for f in group.forwards if f.id == rule_id), None)
    if not rule: return jsonify({'status': 'error', 'message': '未找到隧道'}), 404
    return jsonify({'status': 'success', 'rule': object_to_dict(rule)})


@app.route('/api/servers/test', methods=['POST'])
def test_server_connection_with_paramiko() -> Union[Response, Tuple[Response, int]]:
    data = request.json
    if not data: return jsonify({'status': 'error', 'message': '请求体为空'}), 400
    host, port, user, password = data.get('ssh_host'), int(data.get('ssh_port', 22)), data.get('ssh_user'), data.get(
        'ssh_pass')
    if not all([host, user]): return jsonify({'status': 'error', 'message': '缺少主机和用户'}), 400
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, port=port, username=user, password=password, timeout=10, look_for_keys=False,
                       allow_agent=False)
        return jsonify({'status': 'success', 'message': 'SSH 连接成功!'})
    except socket.timeout:
        return jsonify({'status': 'error', 'message': f'连接超时: {host}:{port}'}), 400
    except paramiko.AuthenticationException:
        return jsonify({'status': 'error', 'message': '认证失败'}), 400
    except paramiko.SSHException as e:
        return jsonify({'status': 'error', 'message': f'SSH 错误: {e}'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'未知错误: {e}'}), 400
    finally:
        try:
            client.close()
        except Exception:
            pass


@app.route('/api/servers', methods=['POST'])
def add_server() -> Response:
    data = request.json
    new_group = ServerGroup(id=generate_unique_id(), name=data['name'],
                            ssh_connection=SSHConnectionConfig(ssh_server_host=data['ssh_host'],
                                                               ssh_server_port=int(data['ssh_port']),
                                                               ssh_username=data['ssh_user'],
                                                               ssh_password=data['ssh_pass']), forwards=[],
                            enabled=True)
    app_config.server_groups.append(new_group)
    return jsonify({'status': 'success', 'message': '服务器组已添加', 'group': object_to_dict(new_group)})


@app.route('/api/servers/<string:server_id>', methods=['PUT'])
def edit_server(server_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group: return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    data = request.json
    group.name = data['name']
    conn = group.ssh_connection
    conn.ssh_server_host, conn.ssh_server_port, conn.ssh_username = data['ssh_host'], int(data['ssh_port']), data[
        'ssh_user']
    if data.get('ssh_pass'): conn.ssh_password = data['ssh_pass']
    ui_logger.info(f"服务器组 '{group.name}' 配置已更新，将重启其下所有隧道。")
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
    ui_logger.info(f"服务器组 '{group.name}' 已 {'启用' if group.enabled else '禁用'}.")
    if group.enabled:
        for f in group.forwards:
            if f.enabled: start_tunnel(group, f)
    else:
        stop_all_tunnels_for_group(group.id)
    return jsonify({'status': 'success', 'enabled': group.enabled})


@app.route('/api/servers/restart/<string:server_id>', methods=['POST'])
def restart_server_tunnels(server_id: str) -> Union[Response, Tuple[Response, int]]:
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group: return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    if not group.enabled: return jsonify({'status': 'error', 'message': '禁用的服务器组无法重启'}), 400
    ui_logger.info(f"正在重启服务器组 '{group.name}' 的所有隧道...")
    stop_all_tunnels_for_group(server_id)
    time.sleep(1)
    for f in group.forwards:
        if f.enabled: start_tunnel(group, f)
    return jsonify({'status': 'success'})


@app.route('/api/tunnels', methods=['POST'])
def add_tunnel() -> Union[Response, Tuple[Response, int]]:
    data = request.json
    server_id = str(data['server_id'])
    group = next((g for g in app_config.server_groups if g.id == server_id), None)
    if not group: return jsonify({'status': 'error', 'message': '未找到服务器组'}), 404
    tunnel_type = data.get('tunnel_type', 'forward')
    if tunnel_type not in ['forward', 'reverse']: return jsonify({'status': 'error', 'message': '无效的隧道类型'}), 400
    new_rule = ForwardRule(id=generate_unique_id(), tunnel_type=tunnel_type, local_host=data['local_host'],
                           local_port=int(data['local_port']), remote_host=data['remote_host'],
                           remote_port=int(data['remote_port']), comment=data['comment'], enabled=True)
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
    new_tunnel_type = data.get('tunnel_type', 'forward')
    if new_tunnel_type not in ['forward', 'reverse']: return jsonify(
        {'status': 'error', 'message': '无效的隧道类型'}), 400
    needs_restart = (rule.local_host != data['local_host'] or rule.local_port != int(
        data['local_port']) or rule.remote_host != data['remote_host'] or rule.remote_port != int(
        data['remote_port']) or rule.tunnel_type != new_tunnel_type)
    rule.tunnel_type, rule.local_host, rule.local_port, rule.remote_host, rule.remote_port, rule.comment = new_tunnel_type, \
        data['local_host'], int(data['local_port']), data['remote_host'], int(data['remote_port']), data['comment']
    if needs_restart and group.enabled and rule.enabled:
        ui_logger.info(f"隧道 '{rule.comment}' 配置已更改，正在重启。")
        stop_tunnel(server_id, rule_id)
        time.sleep(0.5)
        start_tunnel(group, rule)
    return jsonify({'status': 'success', 'message': '隧道已更新', 'rule': object_to_dict(rule), 'ssh_connection': object_to_dict(group.ssh_connection)})


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
    ui_logger.info(f"隧道 '{rule.comment}' 已 {'启用' if rule.enabled else '禁用'}.")
    if group.enabled and rule.enabled:
        start_tunnel(group, rule)
    else:
        stop_tunnel(group.id, rule.id)
    return jsonify({'status': 'success', 'enabled': rule.enabled})


@app.route('/favicon.ico')
def facico():
    return send_from_directory(os.path.join(STATIC_FOLDER, 'ico'), 'favicon.ico')


@app.route('/api/control/toggle_all/<action>', methods=['POST'])
def toggle_all_tunnels(action: str) -> Union[Response, Tuple[Response, int]]:
    enable = action == 'enable'
    for group in app_config.server_groups:
        group.enabled = enable
        if enable:
            for f in group.forwards:
                if f.enabled: start_tunnel(group, f)
        else:
            stop_all_tunnels_for_group(group.id)
    return jsonify({'status': 'success'})


def load_and_start_all_tunnels():
    global monitor_service
    ui_logger.info("正在启动所有已配置且启用的隧道...")
    for group in app_config.server_groups:
        if group.enabled:
            for rule in group.forwards:
                if rule.enabled:
                    if rule.tunnel_type == 'reverse':
                        rule.enabled = False
                        continue
                    start_tunnel(group, rule)  # Use the unified starter function
    ui_logger.info("所有初始隧道任务已派发。")
    monitor_service = TunnelMonitorService(RECONNECT_DELAY_SECONDS)
    monitor_service.start()


def shutdown_handler(signum, frame):
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
    time.sleep(2)
    connection_executor.shutdown(wait=True)
    print("[*] 程序退出。")
    sys.exit(0)


def main():
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
