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
from rtsp_crack import RTSPConfig, RTSPCracker
import time

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
        self.root.geometry("1000x800")  # 增加窗口默认大小
        
        # 创建配置
        self.config = RTSPConfig()
        
        # 创建界面
        self.create_gui()
        
        # 创建RTSP破解器实例
        self.cracker = None
        
        # 标记是否正在运行
        self.is_running = False
        
        # 添加线程控制
        self.max_threads = 5  # 默认最大线程数
        self.active_threads = []
        self.thread_lock = threading.Lock()

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
            config = RTSPConfig()
            config.server_ip = ip
            config.server_port = self.config.server_port
            config.uri_file = self.config.uri_file
            config.username_file = self.config.username_file
            config.password_file = self.config.password_file
            config.brute_force_method = self.config.brute_force_method
            
            cracker = RTSPCracker(config)
            print(f"[*] 开始破解目标: {ip}")
            cracker.brute_force()
            print(f"[*] 完成目标: {ip}")
            
        except Exception as e:
            print(f"[-] 破解 {ip} 时发生错误: {str(e)}")
        finally:
            with self.thread_lock:
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
        self.is_running = False
        print("[*] 正在停止所有任务...")
        # 等待所有线程完成
        for thread in self.active_threads:
            thread.join()
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
                        return
                    # 清理已完成的线程
                    self.active_threads = [t for t in self.active_threads if t.is_alive()]
                    time.sleep(0.1)
                
                # 创建新线程
                thread = threading.Thread(target=self.crack_single_target, args=(ip,))
                self.active_threads.append(thread)
                thread.start()
            
            # 等待所有线程完成
            for thread in self.active_threads:
                thread.join()
                
        except Exception as e:
            print(f"[-] 错误: {str(e)}")
        finally:
            self.is_running = False
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

def main():
    root = tk.Tk()
    app = RTSPCrackerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 