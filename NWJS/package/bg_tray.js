/**
 * bg_tray.js
 * NW.js 后台脚本：用于创建和管理系统托盘图标，确保其生命周期独立于页面导航。
 */

// --- 配置参数 (请根据实际情况调整) ---
const TARGET_URL = 'http://127.0.0.1:2592';
const TRAY_ICON_PATH = 'rex.png'; // 相对于应用根目录
const APP_TITLE = 'SSH RelayTrack';

// --- 引入必需的 Node/NW.js 模块 ---
// 在后台脚本中，require('nw.gui') 和 require('http') 可以直接使用
const gui = require('nw.gui');
const http = require('http');

// 全局变量来持有托盘实例，防止垃圾回收 (这是后台脚本的核心!)
let global_tray_instance = null;
let mainWindow = null;

/**
 * 设置 NW.js 系统托盘图标及其右键菜单。
 */
function setupTrayIcon() {

    // 如果托盘已创建，则不再执行
    if (global_tray_instance) return;

    // 确保 Menu, MenuItem, Tray 构造函数可用
    const Menu = gui.Menu;
    const MenuItem = gui.MenuItem;
    const Tray = gui.Tray;


    mainWindow = gui.Window.get();

    // 2. 创建右键菜单
    const menu = new Menu();

    menu.append(new MenuItem({
        label: '显示窗口',
        click: function() {
                mainWindow.show();
                mainWindow.focus();
        }
    }));

    // 菜单项：退出程序
    menu.append(new MenuItem({
        type: 'separator'
    }));
    menu.append(new MenuItem({
        label: '退出程序',
        click: function() {
            console.log("Tray Click: Sending shutdown signal to backend...");

            // 使用 Node.js HTTP 模块发送信号
            try {
                const url = new URL(TARGET_URL + '/shutdown');
                const req = http.request({
                    host: url.hostname,
                    port: url.port,
                    path: url.pathname,
                    method: 'GET',
                    timeout: 500
                });

                req.on('error', (e) => {
                    console.warn("Shutdown signal failed:", e.message);
                });
                req.end();

            } catch(e) {
                console.error("Error setting up shutdown request:", e);
            }

            // 立即退出 NW.js 进程 (给 HTTP 请求 50ms 时间)
            setTimeout(() => {
                gui.App.quit();
            }, 50);
        }
    }));

    // 3. 创建托盘图标
    const tray = new Tray({
        title: APP_TITLE,
        icon: TRAY_ICON_PATH,
        iconsAreTemplates: false
    });

    // 将实例赋值给全局变量
    global_tray_instance = tray;

    // 4. 绑定事件
    tray.menu = menu;
    tray.on('click', function() {
        if (mainWindow.visible) {
            mainWindow.hide();
        } else {
            mainWindow.show();
            mainWindow.focus();
        }
    });

    // 5. 监听主窗口关闭事件，确保清理托盘
    mainWindow.on('close', function() {
        if (global_tray_instance) {
            global_tray_instance.remove();
            global_tray_instance = null;
        }
        // 当主窗口被关闭时，也应该退出整个应用
        gui.App.quit();
    });

    console.log("Tray icon setup complete.");
}

setTimeout(setupTrayIcon, 100);

