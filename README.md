# 数据可视化程序 / Data Visualization Program

一个基于Flask的交互式数据可视化平台，支持多种图表类型和灵活的仪表盘布局。

## 功能特点

- 📊 **多种图表类型**：折线图、柱状图、饼图、散点图、瀑布图、词云图、地图、旭日图、联合图等
- 📋 **数据表格**：支持清单表和交叉表
- 🎨 **多主题支持**：10种内置配色主题
- 🌐 **中英文切换**：完整的国际化支持
- 📐 **两种模式**：
  - 经典模式：传统的拖拽字段生成图表
  - ![Uploading image.png…]()

  - 仪表盘模式：自由布局的可视化仪表盘
- 🔐 **用户系统**：注册、登录、数据隔离
- 📁 **文件管理**：支持Excel和CSV文件上传

## 技术栈

- **后端**: Python 3.x, Flask, SQLAlchemy
- **前端**: HTML5, CSS3, JavaScript (原生)
- **可视化**: ECharts, pyecharts
- **数据处理**: pandas, numpy

## 安装和运行

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 启动程序

**Windows系统：**
```bash
启动程序.bat
```

**或者手动启动：**
```bash
python app.py
```

### 3. 访问应用

打开浏览器访问：`http://localhost:5000`

## 使用说明

1. **注册/登录**：首次使用需要注册账号
2. **上传数据**：支持.xlsx和.csv格式
3. **选择模式**：
   - 经典模式：适合快速生成单个图表
   - 仪表盘模式：适合创建多图表的综合看板
4. **生成可视化**：
   - 拖拽字段到相应区域
   - 选择图表类型和主题
   - 点击生成按钮

## 项目结构

```
Data_Visualization_Program/
├── app.py                  # Flask主程序
├── language_config.py      # 国际化配置
├── requirements.txt        # Python依赖
├── 启动程序.bat           # Windows启动脚本
├── templates/             # HTML模板
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html     # 经典模式
│   └── dashboard_new.html # 仪表盘模式
├── static/               # 静态资源
│   ├── css/
│   ├── js/
│   ├── charts/          # 生成的图表
│   └── tables/          # 生成的表格
└── uploads/             # 用户上传的文件

```

## 截图

（这里可以添加应用截图）

## 许可证

MIT License

## 作者

Your Name

## 贡献

欢迎提交Issue和Pull Request！

## 更新日志

### v1.0.0 (2025-11-16)
- 初始版本发布
- 支持10+种图表类型
- 完整的中英文国际化
- 经典模式和仪表盘模式


