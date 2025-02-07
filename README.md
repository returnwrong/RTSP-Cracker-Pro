# 🎯 RTSP Cracker Pro

> 一款颜值与实力并存的RTSP设备安全测试工具

RTSP Cracker Pro 是一个用于RTSP设备安全测试的现代化图形工具。告别命令行的繁琐操作，让安全测试变得简单优雅。无论你是安全研究人员、网络工程师，还是安全爱好者，这都将是你的得力助手。

![RTSP Cracker Pro](screenshot.png)

## ✨ 为什么选择 RTSP Cracker Pro？

- 🎨 **颜值即正义** - 现代化UI设计，简洁优雅的操作界面
- 🚀 **快如闪电** - 多线程并发处理，效率提升数倍
- 🛠️ **功能强大** - 支持多种认证方式，自动URI探测
- 🎯 **精准可靠** - 实时显示破解进度，结果一目了然
- 📦 **开箱即用** - 无需安装依赖，纯Python标准库实现
- 🔄 **持续更新** - 定期维护更新，解决用户反馈

## 🔧 功能特点

- 💫 支持Basic和Digest双认证模式
- 📝 支持批量导入IP列表
- 🔍 智能URI路径探测
- 📊 实时进度显示
- 💾 一键导出结果
- 🔗 快捷RTSP链接生成
- 📋 剪贴板快速复制
- 🎨 现代化界面设计

## 🚀 快速开始

### 环境要求

- Python 3.7+
- 无需任何第三方库！

### 三步开始使用

1️⃣ 克隆仓库：

```bash
git clone https://github.com/yourusername/rtsp-cracker-pro.git
cd rtsp-cracker-pro
```

2️⃣ 运行程序：

```bash
python rtsp_crack_gui.py
```

3️⃣ 开始破解！

## 📚 使用指南

### 🎯 基本配置

1. **目标配置**

   - 🔹 单个IP测试：直接输入目标IP
   - 🔹 批量IP测试：导入IP列表文件
   - 🔹 自定义端口：默认554，可按需修改
2. **字典配置**

   - 🔹 URI字典：设备访问路径字典
   - 🔹 用户名字典：可能的用户名列表
   - 🔹 密码字典：可能的密码列表
3. **认证方式**

   - 🔹 Digest认证：默认模式，更安全
   - 🔹 Basic认证：兼容老设备

### 🎮 操作流程

1. 设置目标IP（单个/批量）
2. 选择字典文件（URI/用户名/密码）
3. 选择认证方式
4. 点击开始，坐等结果！

### 📊 结果管理

- 📋 实时查看破解结果
- 💾 导出RTSP链接
- 📎 一键复制到剪贴板
- 📑 详细信息导出

## 📝 字典文件格式

简单直观的纯文本格式：

```text
# uri.txt - URI路径字典
/
/11
/12
/h264/ch1/main/av_stream
/cam/realmonitor

# username.txt - 用户名字典
admin
root
supervisor

# password.txt - 密码字典
12345
admin123
password
```

## 🎬 使用技巧

- 💡 合理控制线程数，建议5-10个
- 💡 定期更新字典库，提高成功率
- 💡 使用前先测试单个IP
- 💡 注意保存重要的破解结果

## ⚠️ 注意事项

- 🚫 仅用于授权的安全测试
- 📌 建议备份重要字典文件
- ⚡ 注意控制并发数量
- 🔒 遵守相关法律法规

## 👥 关于我们

- 🧙‍♂️ **xxtt** - *核心开发*
- 🎨 **地图大师returnwrong**- *核心开发*

## 🤝 参与贡献

我们欢迎各种形式的贡献：

- 🐛 提交Bug报告
- 💡 新功能建议
- 📝 完善文档
- 🔧 提交代码

## 📜 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## ⚠️ 免责声明

本工具仅供安全研究和授权测试使用。任何未经授权的测试行为造成的后果，需自行承担全部责任。

---

如果觉得这个工具对你有帮助，请给个 Star ⭐️ 支持一下！

[反馈问题](https://github.com/yourusername/rtsp-cracker-pro/issues) | [功能建议](https://github.com/yourusername/rtsp-cracker-pro/issues)
