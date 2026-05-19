# ⚡ NetPulse

<p align="center">
  <strong>轻量级终端网络流量监控与智能分析引擎</strong><br>
  <strong>Lightweight Terminal Network Traffic Monitor & Intelligent Analysis Engine</strong><br>
  <strong>輕量級終端網路流量監控與智慧分析引擎</strong>
</p>

<p align="center">
  <a href="#简体中文">简体中文</a> |
  <a href="#繁體中文">繁體中文</a> |
  <a href="#english">English
</p>

---

## 简体中文

### 🎉 项目介绍

**NetPulse** 是一款轻量级终端网络流量监控与智能分析引擎，专为开发者和系统管理员设计。它提供实时的网络流量监控、连接追踪、协议分析和带宽可视化功能，全部在终端中以精美的TUI（文本用户界面）呈现。

**灵感来源**：在排查网络问题和监控系统性能时，我们发现需要一个零依赖、跨平台、轻量级的网络监控工具，能够直接在终端中运行，无需复杂的配置和图形界面。

**自研差异化亮点**：
- 🚀 **零依赖**：仅使用Python标准库，无需安装任何第三方包
- 🎨 **精美TUI**：实时带宽图表、连接列表、流量统计
- 🔧 **跨平台**：支持Linux、macOS和Windows
- 📊 **智能分析**：自动识别协议、端口服务、流量模式
- 💾 **数据导出**：支持JSON格式导出统计报告

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 📈 **实时带宽监控** | 动态ASCII图表显示上下行带宽 |
| 🔗 **连接追踪** | 实时显示TCP/UDP连接状态 |
| 📊 **流量统计** | 协议分布、端口使用、IP排名 |
| 📦 **包捕获** | 显示最近的数据包详情 |
| 🎨 **彩色界面** | 终端颜色自动检测，支持禁用 |
| 💾 **数据导出** | JSON格式导出完整统计报告 |
| ⌨️ **键盘交互** | 支持多种视图切换和快捷操作 |

### 🚀 快速开始

#### 环境要求

- Python 3.8+
- 终端支持（支持ANSI颜色更佳）

#### 安装

```bash
# 克隆仓库
git clone https://github.com/gitstq/netpulse.git
cd netpulse

# 直接运行（无需安装依赖）
python netpulse.py
```

#### 基本使用

```bash
# 启动交互式TUI监控
python netpulse.py

# 监控特定网卡
python netpulse.py --interface eth0

# 导出统计报告
python netpulse.py --export report.json --duration 60

# 禁用颜色输出
python netpulse.py --no-color
```

### 📖 详细使用指南

#### 键盘控制

| 按键 | 功能 |
|------|------|
| `q` | 退出程序 |
| `?` | 显示/隐藏帮助 |
| `r` | 重置统计数据 |
| `d` | 仪表板视图 |
| `c` | 连接列表视图 |
| `p` | 数据包视图 |

#### 界面说明

**仪表板包含以下区域：**
1. **带宽图表** - 实时显示上下行带宽使用情况的ASCII图表
2. **流量摘要** - 总流量、包数量、连接数等统计信息
3. **协议排行** - 按流量排序的协议分布
4. **端口排行** - 按流量排序的端口使用情况
5. **活动连接** - 当前活动的网络连接列表

### 💡 设计思路与迭代规划

**技术选型原因**：
- 使用纯Python标准库，确保零依赖和跨平台兼容性
- TUI界面使用ANSI转义码，无需ncurses等库
- 模块化设计，便于扩展和维护

**后续功能迭代计划**：
- [ ] 支持PCAP文件读取和分析
- [ ] 添加过滤器功能（按IP、端口、协议过滤）
- [ ] 支持告警阈值设置
- [ ] 历史数据持久化和趋势分析
- [ ] Web界面支持

**社区贡献方向**：
- 更多平台原生支持
- 协议解析器扩展
- 性能优化
- 文档翻译

### 📦 打包与部署指南

#### 单文件可执行程序

使用PyInstaller打包：

```bash
# 安装PyInstaller
pip install pyinstaller

# 打包为单文件
pyinstaller --onefile --name netpulse netpulse.py

# 打包后的可执行文件在 dist/ 目录
```

#### 系统安装

```bash
# 安装到系统路径
sudo cp netpulse.py /usr/local/bin/netpulse
sudo chmod +x /usr/local/bin/netpulse

# 现在可以直接运行
netpulse
```

### 🤝 贡献指南

欢迎提交Issue和Pull Request！

- 提交Issue请描述清楚问题和复现步骤
- 提交PR请确保代码符合PEP 8规范
- 新增功能请同步更新文档

### 📄 开源协议

本项目采用 [MIT License](LICENSE) 开源协议。

---

## 繁體中文

### 🎉 專案介紹

**NetPulse** 是一款輕量級終端網路流量監控與智慧分析引擎，專為開發者和系統管理員設計。它提供即時的網路流量監控、連線追蹤、協定分析和頻寬視覺化功能，全部在終端機中以精美的TUI（文字使用者介面）呈現。

**自研差異化亮點**：
- 🚀 **零依賴**：僅使用Python標準函式庫
- 🎨 **精美TUI**：即時頻寬圖表、連線列表、流量統計
- 🔧 **跨平台**：支援Linux、macOS和Windows
- 📊 **智慧分析**：自動識別協定、連接埠服務、流量模式

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 📈 **即時頻寬監控** | 動態ASCII圖表顯示上下行頻寬 |
| 🔗 **連線追蹤** | 即時顯示TCP/UDP連線狀態 |
| 📊 **流量統計** | 協定分布、連接埠使用、IP排名 |
| 💾 **資料匯出** | JSON格式匯出完整統計報告 |

### 🚀 快速開始

```bash
# 克隆倉庫
git clone https://github.com/gitstq/netpulse.git
cd netpulse

# 直接運行
python netpulse.py
```

### 📄 開源協議

[MIT License](LICENSE)

---

## English

### 🎉 Introduction

**NetPulse** is a lightweight terminal network traffic monitor and intelligent analysis engine designed for developers and system administrators. It provides real-time network traffic monitoring, connection tracking, protocol analysis, and bandwidth visualization - all presented in a beautiful TUI (Text User Interface) within your terminal.

**Differentiation Highlights**:
- 🚀 **Zero Dependencies**: Uses only Python standard library
- 🎨 **Beautiful TUI**: Real-time bandwidth charts, connection lists, traffic statistics
- 🔧 **Cross-Platform**: Supports Linux, macOS, and Windows
- 📊 **Intelligent Analysis**: Auto-detect protocols, port services, traffic patterns

### ✨ Core Features

| Feature | Description |
|---------|-------------|
| 📈 **Real-time Bandwidth** | Dynamic ASCII charts for up/down bandwidth |
| 🔗 **Connection Tracking** | Live TCP/UDP connection status |
| 📊 **Traffic Statistics** | Protocol distribution, port usage, IP ranking |
| 💾 **Data Export** | Export full statistics in JSON format |

### 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/gitstq/netpulse.git
cd netpulse

# Run directly
python netpulse.py
```

### 📄 License

[MIT License](LICENSE)

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/gitstq">gitstq</a>
</p>
