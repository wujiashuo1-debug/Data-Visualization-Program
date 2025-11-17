"""
数据可视化程序 - 主应用文件
提供用户注册、登录、注销、文件上传和数据可视化功能
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import pandas as pd
from datetime import datetime
import matplotlib
matplotlib.use('Agg')  # 使用非GUI后端
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
from io import BytesIO
import base64
import numpy as np
from pyecharts import options as opts
from pyecharts.charts import Map, Sunburst
from pyecharts.globals import ThemeType
import json as json_module
from wordcloud import WordCloud
import jieba
from PIL import Image, ImageDraw
from language_config import get_all_texts

# 创建Flask应用实例
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
# 使用绝对路径确保数据库在项目根目录（Flask-SQLAlchemy 3.x 默认在 instance 文件夹）
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 文件上传配置
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 限制最大16MB

# 确保上传文件夹存在
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 图表生成配置
CHARTS_FOLDER = 'charts'
if not os.path.exists(CHARTS_FOLDER):
    os.makedirs(CHARTS_FOLDER)

# 配置matplotlib中文字体
plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans', 'Arial Unicode MS', 'sans-serif']
plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题

# 初始化数据库
db = SQLAlchemy(app)

# 初始化登录管理器
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录以访问此页面'


# 用户数据库模型
class User(UserMixin, db.Model):
    """用户数据模型"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    # 建立与数据文件的关系
    data_files = db.relationship('DataFile', backref='owner', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        """设置密码（加密存储）"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """验证密码"""
        return check_password_hash(self.password_hash, password)


# 数据文件模型
class DataFile(db.Model):
    """数据文件模型"""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    original_filename = db.Column(db.String(200), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_type = db.Column(db.String(10), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    columns_info = db.Column(db.Text)  # 存储列信息的JSON字符串


@login_manager.user_loader
def load_user(user_id):
    """加载用户回调函数"""
    return db.session.get(User, int(user_id))


@app.route('/')
def index():
    """首页路由 - 重定向到登录页面或主页"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/set_language/<lang>')
def set_language(lang):
    """设置语言"""
    if lang in ['zh', 'en']:
        session['language'] = lang
    return redirect(request.referrer or url_for('index'))


@app.route('/api/set_language/<lang>', methods=['POST'])
def api_set_language(lang):
    """API：设置语言（不刷新页面）"""
    if lang in ['zh', 'en']:
        session['language'] = lang
        return jsonify({
            'success': True,
            'language': lang,
            'texts': get_all_texts(lang)
        })
    return jsonify({'success': False, 'message': 'Invalid language'}), 400


@app.route('/register', methods=['GET', 'POST'])
def register():
    """用户注册路由"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # 确保session中有语言设置
    if 'language' not in session:
        session['language'] = 'zh'
    
    # 获取当前语言
    lang = session.get('language', 'zh')
    texts = get_all_texts(lang)
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # 验证输入
        if not username or not email or not password:
            flash('所有字段都是必填的！' if lang == 'zh' else 'All fields are required!', 'error')
            return render_template('register.html', texts=texts, lang=lang)

        if password != confirm_password:
            flash('两次输入的密码不一致！' if lang == 'zh' else 'Passwords do not match!', 'error')
            return render_template('register.html', texts=texts, lang=lang)

        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            flash('用户名已被注册！' if lang == 'zh' else 'Username already registered!', 'error')
            return render_template('register.html', texts=texts, lang=lang)

        # 检查邮箱是否已存在
        if User.query.filter_by(email=email).first():
            flash('邮箱已被注册！' if lang == 'zh' else 'Email already registered!', 'error')
            return render_template('register.html', texts=texts, lang=lang)

        # 创建新用户
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('注册成功！请登录。' if lang == 'zh' else 'Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('注册失败，请稍后重试。' if lang == 'zh' else 'Registration failed. Please try again.', 'error')
            return render_template('register.html', texts=texts, lang=lang)

    return render_template('register.html', texts=texts, lang=lang)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录路由"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # 确保session中有语言设置
    if 'language' not in session:
        session['language'] = 'zh'
    
    # 获取当前语言
    lang = session.get('language', 'zh')
    texts = get_all_texts(lang)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # 验证输入
        if not username or not password:
            flash('请输入用户名和密码！' if lang == 'zh' else 'Please enter username and password!', 'error')
            return render_template('login.html', texts=texts, lang=lang)

        # 查找用户
        user = User.query.filter_by(username=username).first()

        # 验证用户和密码
        if user and user.check_password(password):
            login_user(user)
            flash('登录成功！' if lang == 'zh' else 'Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('dashboard'))
        else:
            flash('用户名或密码错误！' if lang == 'zh' else 'Invalid username or password!', 'error')
            return render_template('login.html', texts=texts, lang=lang)

    return render_template('login.html', texts=texts, lang=lang)


@app.route('/dashboard')
@login_required
def dashboard():
    """主页面路由 - 需要登录"""
    # 确保session中有语言设置
    if 'language' not in session:
        session['language'] = 'zh'
    
    # 获取当前语言
    lang = session.get('language', 'zh')
    texts = get_all_texts(lang)
    
    # 验证texts是字典且包含必要的键
    if not isinstance(texts, dict) or 'values' not in texts:
        texts = get_all_texts('zh')
    
    # 获取当前用户的所有数据文件
    data_files = DataFile.query.filter_by(user_id=current_user.id).order_by(DataFile.upload_time.desc()).all()
    return render_template('dashboard.html', username=current_user.username, data_files=data_files, texts=texts, lang=lang)


@app.route('/dashboard-new')
@login_required
def dashboard_new():
    """新仪表盘界面 - 类似Tableau的拖拽式仪表盘"""
    # 确保session中有语言设置
    if 'language' not in session:
        session['language'] = 'zh'
    
    # 获取当前语言
    lang = session.get('language', 'zh')
    texts = get_all_texts(lang)
    
    # 验证texts是字典且包含必要的键
    if not isinstance(texts, dict) or 'values' not in texts:
        texts = get_all_texts('zh')
    
    # 获取当前用户的所有数据文件
    data_files = DataFile.query.filter_by(user_id=current_user.id).order_by(DataFile.upload_time.desc()).all()
    return render_template('dashboard_new.html', username=current_user.username, data_files=data_files, texts=texts, lang=lang)


def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """文件上传路由"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '没有选择文件'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': '没有选择文件'}), 400
    
    if file and allowed_file(file.filename):
        try:
            # 生成安全的文件名
            original_filename = file.filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{current_user.id}_{timestamp}_{secure_filename(original_filename)}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # 保存文件
            file.save(file_path)
            
            # 读取文件获取列信息
            file_ext = original_filename.rsplit('.', 1)[1].lower()
            df = None
            
            if file_ext in ['xlsx', 'xls']:
                # 智能读取 Excel 文件，自动尝试不同引擎
                engines = []
                if file_ext == 'xlsx':
                    engines = ['openpyxl', 'xlrd']  # 优先使用 openpyxl
                else:
                    engines = ['xlrd', 'openpyxl']  # .xls 优先使用 xlrd
                
                # 尝试不同的引擎读取文件
                last_error = None
                for engine in engines:
                    try:
                        df = pd.read_excel(file_path, engine=engine)
                        break  # 成功读取，退出循环
                    except Exception as e:
                        last_error = e
                        continue
                
                if df is None:
                    raise Exception(f"无法读取 Excel 文件。请确保文件未损坏且未加密。错误: {str(last_error)}")
            else:  # csv
                df = pd.read_csv(file_path)
            
            # 分析列的类型（数值型 vs 分类型）
            columns_info = {}
            for col in df.columns:
                if pd.api.types.is_numeric_dtype(df[col]):
                    columns_info[col] = 'measure'  # 度量
                else:
                    columns_info[col] = 'dimension'  # 维度
            
            # 保存文件信息到数据库
            import json
            new_file = DataFile(
                filename=filename,
                original_filename=original_filename,
                file_path=file_path,
                file_type=file_ext,
                user_id=current_user.id,
                columns_info=json.dumps(columns_info, ensure_ascii=False)
            )
            db.session.add(new_file)
            db.session.commit()
            
            flash(f'文件 {original_filename} 上传成功！', 'success')
            return jsonify({
                'success': True, 
                'message': '文件上传成功',
                'file_id': new_file.id,
                'filename': original_filename
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': f'文件上传失败: {str(e)}'}), 500
    else:
        return jsonify({'success': False, 'message': '不支持的文件格式，请上传 Excel 或 CSV 文件'}), 400


@app.route('/api/file/<int:file_id>/columns')
@login_required
def get_file_columns(file_id):
    """获取文件的列信息"""
    data_file = DataFile.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not data_file:
        return jsonify({'success': False, 'message': '文件不存在'}), 404
    
    try:
        import json
        columns_info = json.loads(data_file.columns_info)
        
        # 分类维度和度量
        dimensions = [col for col, type in columns_info.items() if type == 'dimension']
        measures = [col for col, type in columns_info.items() if type == 'measure']
        
        return jsonify({
            'success': True,
            'filename': data_file.original_filename,
            'dimensions': dimensions,
            'measures': measures,
            'all_columns': columns_info
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'获取列信息失败: {str(e)}'}), 500


@app.route('/api/file/<int:file_id>/preview')
@login_required
def preview_file(file_id):
    """预览文件数据"""
    data_file = DataFile.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not data_file:
        return jsonify({'success': False, 'message': '文件不存在'}), 404
    
    try:
        # 读取数据文件
        file_ext = data_file.file_type
        df = None
        
        if file_ext in ['xlsx', 'xls']:
            engines = ['openpyxl', 'xlrd'] if file_ext == 'xlsx' else ['xlrd', 'openpyxl']
            for engine in engines:
                try:
                    df = pd.read_excel(data_file.file_path, engine=engine)
                    break
                except:
                    continue
        else:
            df = pd.read_csv(data_file.file_path)
        
        if df is None:
            return jsonify({'success': False, 'message': '无法读取数据文件'}), 500
        
        # 获取预览数据（前100行）
        preview_df = df.head(100)
        
        return jsonify({
            'success': True,
            'filename': data_file.original_filename,
            'columns': preview_df.columns.tolist(),
            'data': preview_df.fillna('').values.tolist(),
            'total_rows': len(df),
            'total_columns': len(df.columns),
            'displayed_rows': len(preview_df)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'预览失败: {str(e)}'}), 500


@app.route('/api/file/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    """删除文件"""
    data_file = DataFile.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not data_file:
        return jsonify({'success': False, 'message': '文件不存在'}), 404
    
    try:
        # 删除物理文件
        if os.path.exists(data_file.file_path):
            os.remove(data_file.file_path)
        
        # 删除数据库记录
        db.session.delete(data_file)
        db.session.commit()
        
        return jsonify({'success': True, 'message': '文件删除成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'文件删除失败: {str(e)}'}), 500


@app.route('/api/table/generate', methods=['POST'])
@login_required
def generate_table():
    """生成清单表或交叉表"""
    try:
        data = request.get_json()
        file_id = data.get('file_id')
        table_type = data.get('table_type')  # 'list' 或 'cross'
        rows = data.get('rows', [])  # 行字段
        columns = data.get('columns', [])  # 列字段
        values = data.get('values', [])  # 值字段
        
        # 验证文件
        data_file = DataFile.query.filter_by(id=file_id, user_id=current_user.id).first()
        if not data_file:
            return jsonify({'success': False, 'message': '文件不存在'}), 404
        
        # 读取数据文件
        file_ext = data_file.file_type
        df = None
        
        if file_ext in ['xlsx', 'xls']:
            engines = ['openpyxl', 'xlrd'] if file_ext == 'xlsx' else ['xlrd', 'openpyxl']
            for engine in engines:
                try:
                    df = pd.read_excel(data_file.file_path, engine=engine)
                    break
                except:
                    continue
        else:
            df = pd.read_csv(data_file.file_path)
        
        if df is None:
            return jsonify({'success': False, 'message': '无法读取数据文件'}), 500
        
        result = {}
        
        if table_type == 'list':
            # 生成清单表
            selected_cols = rows + columns + values
            if not selected_cols:
                # 如果没有选择字段，显示所有列的前100行
                result_df = df.head(100)
            else:
                # 只显示选择的列
                available_cols = [col for col in selected_cols if col in df.columns]
                result_df = df[available_cols].head(100)
            
            # 转换为JSON格式
            result = {
                'success': True,
                'table_type': 'list',
                'columns': result_df.columns.tolist(),
                'data': result_df.fillna('').values.tolist(),
                'total_rows': len(df),
                'displayed_rows': len(result_df)
            }
            
        elif table_type == 'cross':
            # 生成交叉表（透视表）
            if not rows and not columns:
                return jsonify({'success': False, 'message': '请至少选择一个行字段或列字段'}), 400
            
            if not values:
                return jsonify({'success': False, 'message': '请选择至少一个度量字段'}), 400
            
            # 创建透视表
            pivot_index = rows if rows else None
            pivot_columns = columns if columns else None
            pivot_values = values[0]  # 暂时只支持一个度量
            
            try:
                if pivot_index and pivot_columns:
                    # 行和列都有
                    pivot_table = pd.pivot_table(
                        df,
                        values=pivot_values,
                        index=pivot_index,
                        columns=pivot_columns,
                        aggfunc='sum',
                        fill_value=0
                    )
                elif pivot_index:
                    # 只有行
                    pivot_table = df.groupby(pivot_index)[pivot_values].sum().reset_index()
                else:
                    # 只有列
                    pivot_table = df.groupby(pivot_columns)[pivot_values].sum().reset_index()
                
                # 转换为适合前端显示的格式
                if isinstance(pivot_table, pd.DataFrame):
                    if isinstance(pivot_table.columns, pd.MultiIndex):
                        # 多级列索引
                        columns_list = [' - '.join(map(str, col)) if isinstance(col, tuple) else str(col) 
                                       for col in pivot_table.columns]
                    else:
                        columns_list = pivot_table.columns.tolist()
                    
                    # 重置索引以便显示
                    pivot_table_reset = pivot_table.reset_index() if hasattr(pivot_table, 'index') and len(pivot_table.index.names) > 0 else pivot_table
                    
                    result = {
                        'success': True,
                        'table_type': 'cross',
                        'columns': pivot_table_reset.columns.tolist(),
                        'data': pivot_table_reset.fillna(0).values.tolist(),
                        'total_rows': len(pivot_table_reset)
                    }
                else:
                    result = {
                        'success': True,
                        'table_type': 'cross',
                        'columns': ['字段', '汇总'],
                        'data': [[str(k), float(v)] for k, v in pivot_table.items()],
                        'total_rows': len(pivot_table)
                    }
                    
            except Exception as e:
                return jsonify({'success': False, 'message': f'生成透视表失败: {str(e)}'}), 500
        else:
            return jsonify({'success': False, 'message': '不支持的表格类型'}), 400
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'生成表格失败: {str(e)}'}), 500


@app.route('/api/chart/generate', methods=['POST'])
@login_required
def generate_chart():
    """生成图表（柱状图、瀑布图、地图等）"""
    try:
        data = request.get_json()
        file_id = data.get('file_id')
        chart_type = data.get('chart_type')  # 'bar', 'waterfall', 'map'
        x_axis = data.get('x_axis')  # X轴字段（地图中为地区字段）
        y_axis = data.get('y_axis')  # Y轴字段（度量）
        
        # 自定义文字
        custom_title = data.get('custom_title', '')  # 自定义标题
        custom_xlabel = data.get('custom_xlabel', '')  # 自定义X轴标签
        custom_ylabel = data.get('custom_ylabel', '')  # 自定义Y轴标签
        
        # 轴配置
        x_axis_config = data.get('x_axis_config', {
            'aggregation': 'sum',
            'sort': 'none',
            'format': 'number',
            'log_scale': False,
            'axis_name': ''
        })
        y_axis_config = data.get('y_axis_config', {
            'aggregation': 'sum',
            'sort': 'none',
            'format': 'number',
            'log_scale': False,
            'axis_name': ''
        })
        
        # 主题颜色
        theme = data.get('theme', 'purple')  # 默认紫色系
        
        # 现代化主题颜色配置 - 使用渐变和高级配色
        theme_colors = {
            'purple': {'primary': '#667eea', 'secondary': '#764ba2', 'multi': ['#a78bfa', '#8b5cf6', '#7c3aed', '#6d28d9', '#5b21b6', '#4c1d95']},
            'blue': {'primary': '#3b82f6', 'secondary': '#1e40af', 'multi': ['#60a5fa', '#3b82f6', '#2563eb', '#1d4ed8', '#1e40af', '#1e3a8a']},
            'green': {'primary': '#10b981', 'secondary': '#047857', 'multi': ['#6ee7b7', '#34d399', '#10b981', '#059669', '#047857', '#065f46']},
            'red': {'primary': '#ef4444', 'secondary': '#b91c1c', 'multi': ['#f87171', '#ef4444', '#dc2626', '#b91c1c', '#991b1b', '#7f1d1d']},
            'orange': {'primary': '#f97316', 'secondary': '#c2410c', 'multi': ['#fb923c', '#f97316', '#ea580c', '#c2410c', '#9a3412', '#7c2d12']},
            'pink': {'primary': '#ec4899', 'secondary': '#be185d', 'multi': ['#f472b6', '#ec4899', '#db2777', '#be185d', '#9f1239', '#831843']},
            'teal': {'primary': '#14b8a6', 'secondary': '#0f766e', 'multi': ['#5eead4', '#2dd4bf', '#14b8a6', '#0d9488', '#0f766e', '#115e59']},
            'sunset': {'primary': '#f093fb', 'secondary': '#f5576c', 'multi': ['#fbc2eb', '#f093fb', '#f57b94', '#f5576c', '#d63447', '#c02040']},
            'ocean': {'primary': '#667eea', 'secondary': '#00c9ff', 'multi': ['#8b9aed', '#667eea', '#4395e6', '#00b9e3', '#00c9ff', '#00e5ff']},
            'forest': {'primary': '#56ab2f', 'secondary': '#a8e063', 'multi': ['#6bc248', '#56ab2f', '#75b94d', '#92c96e', '#a8e063', '#c0e87f']}
        }
        
        # 获取当前主题颜色
        colors = theme_colors.get(theme, theme_colors['purple'])
        
        # 验证文件
        data_file = DataFile.query.filter_by(id=file_id, user_id=current_user.id).first()
        if not data_file:
            return jsonify({'success': False, 'message': '文件不存在'}), 404
        
        # 读取数据文件
        file_ext = data_file.file_type
        df = None
        
        if file_ext in ['xlsx', 'xls']:
            engines = ['openpyxl', 'xlrd'] if file_ext == 'xlsx' else ['xlrd', 'openpyxl']
            for engine in engines:
                try:
                    df = pd.read_excel(data_file.file_path, engine=engine)
                    break
                except:
                    continue
        else:
            df = pd.read_csv(data_file.file_path)
        
        if df is None:
            return jsonify({'success': False, 'message': '无法读取数据文件'}), 500
        
        # 验证字段
        if not x_axis or not y_axis:
            return jsonify({'success': False, 'message': '请选择X轴和Y轴字段'}), 400
        
        if x_axis not in df.columns or y_axis not in df.columns:
            return jsonify({'success': False, 'message': '选择的字段不存在'}), 400
        
        # 根据Y轴聚合方式处理数据
        agg_func = y_axis_config['aggregation']
        agg_map = {
            'sum': 'sum',
            'avg': 'mean',
            'count': 'count',
            'max': 'max',
            'min': 'min'
        }
        pandas_agg = agg_map.get(agg_func, 'sum')
        
        # 聚合数据
        chart_data = df.groupby(x_axis)[y_axis].agg(pandas_agg).reset_index()
        
        # 根据排序配置排序
        if y_axis_config['sort'] == 'asc':
            chart_data = chart_data.sort_values(by=y_axis, ascending=True)
        elif y_axis_config['sort'] == 'desc':
            chart_data = chart_data.sort_values(by=y_axis, ascending=False)
        
        # 限制显示数量
        chart_data = chart_data.head(20)
        
        # 获取轴标签（优先使用自定义，再使用配置，最后使用字段名）
        xlabel = custom_xlabel if custom_xlabel else (x_axis_config['axis_name'] if x_axis_config['axis_name'] else x_axis)
        ylabel = custom_ylabel if custom_ylabel else (y_axis_config['axis_name'] if y_axis_config['axis_name'] else y_axis)
        
        # 创建图表
        fig, ax = plt.subplots(figsize=(12, 6))
        
        if chart_type == 'line':
            # 折线图
            ax.plot(range(len(chart_data)), chart_data[y_axis], 
                   color=colors['primary'], linewidth=2.5, marker='o', markersize=8, 
                   markerfacecolor=colors['secondary'], markeredgecolor='white', markeredgewidth=2)
            ax.set_xticks(range(len(chart_data)))
            ax.set_xticklabels(chart_data[x_axis], rotation=45, ha='right')
            
            # 使用配置的标签
            title = custom_title if custom_title else f'{x_axis} - {y_axis} 趋势图'
            
            ax.set_xlabel(xlabel, fontsize=12, fontweight='bold')
            ax.set_ylabel(ylabel, fontsize=12, fontweight='bold')
            ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
            
            # 应用对数轴
            if y_axis_config['log_scale']:
                ax.set_yscale('log')
            
            # 在数据点上显示数值
            for i, (x, y) in enumerate(zip(range(len(chart_data)), chart_data[y_axis])):
                ax.text(x, y, f'{y:,.0f}',
                       ha='center', va='bottom', fontsize=9, 
                       bbox=dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='gray', alpha=0.7))
            
            # 添加网格线
            ax.grid(True, linestyle='--', alpha=0.3, axis='y')
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            
        elif chart_type == 'bar':
            # 柱状图
            bars = ax.bar(range(len(chart_data)), chart_data[y_axis], 
                          color=colors['primary'], edgecolor=colors['secondary'], linewidth=1.5)
            ax.set_xticks(range(len(chart_data)))
            ax.set_xticklabels(chart_data[x_axis], rotation=45, ha='right')
            
            # 使用配置的标签
            title = custom_title if custom_title else f'{x_axis} - {y_axis} 柱状图'
            
            ax.set_xlabel(xlabel, fontsize=12, fontweight='bold')
            ax.set_ylabel(ylabel, fontsize=12, fontweight='bold')
            ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
            
            # 应用对数轴
            if y_axis_config['log_scale']:
                ax.set_yscale('log')
            
            # 在柱子上显示数值
            for i, bar in enumerate(bars):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:,.0f}',
                       ha='center', va='bottom', fontsize=9)
        
        elif chart_type == 'area':
            # 面积图
            x_values = range(len(chart_data))
            y_values = chart_data[y_axis]
            
            # 绘制面积图
            ax.fill_between(x_values, y_values, 
                           color=colors['primary'], alpha=0.3, label=y_axis)
            # 绘制边界线
            ax.plot(x_values, y_values, 
                   color=colors['primary'], linewidth=2.5, marker='o', markersize=8,
                   markerfacecolor=colors['secondary'], markeredgecolor='white', markeredgewidth=2)
            
            ax.set_xticks(x_values)
            ax.set_xticklabels(chart_data[x_axis], rotation=45, ha='right')
            
            # 使用配置的标签
            title = custom_title if custom_title else f'{x_axis} - {y_axis} 面积图'
            
            ax.set_xlabel(xlabel, fontsize=12, fontweight='bold')
            ax.set_ylabel(ylabel, fontsize=12, fontweight='bold')
            ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
            
            # 应用对数轴
            if y_axis_config['log_scale']:
                ax.set_yscale('log')
            
            # 在数据点上显示数值
            for i, (x, y) in enumerate(zip(x_values, y_values)):
                ax.text(x, y, f'{y:,.0f}',
                       ha='center', va='bottom', fontsize=9,
                       bbox=dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='gray', alpha=0.7))
            
            # 添加网格线
            ax.grid(True, linestyle='--', alpha=0.3, axis='y')
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
        
        elif chart_type == 'scatter':
            # 散点图
            # 获取分组字段（可选，用于控制点的大小）
            group_field = data.get('group_field')
            
            # 聚合数据 - 散点图不聚合，使用原始数据点
            # 但为了性能，限制最多显示1000个点
            scatter_df = df[[x_axis, y_axis]].copy()
            if group_field and group_field in df.columns:
                scatter_df[group_field] = df[group_field]
            
            # 移除包含空值的行
            scatter_df = scatter_df.dropna()
            
            # 限制数据点数量
            if len(scatter_df) > 1000:
                scatter_df = scatter_df.sample(n=1000, random_state=42)
            
            x_values = scatter_df[x_axis].values
            y_values = scatter_df[y_axis].values
            
            # 使用配置的标签（散点图已经定义了xlabel和ylabel）
            title = custom_title if custom_title else f'{x_axis} vs {y_axis} 散点图'
            
            if group_field and group_field in scatter_df.columns:
                # 气泡图模式 - 用点的大小表示第三个维度的数值
                size_values = scatter_df[group_field].values
                
                # 检查分组字段是否为数值类型
                if pd.api.types.is_numeric_dtype(scatter_df[group_field]):
                    # 数值类型 - 使用数值大小映射点的大小
                    # 归一化大小值到合理范围 (50-500)
                    min_size = size_values.min()
                    max_size = size_values.max()
                    
                    if max_size == min_size:
                        # 所有值相同，使用统一大小
                        sizes = np.full(len(size_values), 200)
                    else:
                        # 线性映射到 50-500 的范围
                        sizes = 50 + (size_values - min_size) / (max_size - min_size) * 450
                    
                    # 绘制散点图
                    scatter = ax.scatter(
                        x_values,
                        y_values,
                        c=colors['primary'],
                        s=sizes,
                        alpha=0.6,
                        edgecolors='white',
                        linewidth=1.5
                    )
                    
                    # 添加大小图例（显示最小、中间、最大值）
                    legend_sizes = [min_size, (min_size + max_size) / 2, max_size]
                    legend_labels = [f'{val:,.0f}' for val in legend_sizes]
                    legend_sizes_visual = [50, 250, 450]
                    
                    # 创建图例元素
                    legend_elements = []
                    for label, size in zip(legend_labels, legend_sizes_visual):
                        legend_elements.append(
                            plt.Line2D([0], [0], marker='o', color='w', 
                                     markerfacecolor=colors['primary'], markersize=np.sqrt(size/10),
                                     alpha=0.6, label=label, markeredgecolor='white', markeredgewidth=1.5)
                        )
                    
                    # 添加图例
                    legend = ax.legend(handles=legend_elements, title=f'{group_field}\n(点大小)',
                                     loc='upper left', framealpha=0.9, fontsize=9)
                    legend.get_title().set_fontsize(10)
                    legend.get_title().set_fontweight('bold')
                    
                else:
                    # 非数值类型 - 按分类用不同颜色
                    groups = scatter_df[group_field].unique()
                    
                    # 为每个分组分配颜色
                    group_colors = {}
                    theme_multi = colors['multi']
                    for i, group in enumerate(groups):
                        if i < len(theme_multi):
                            group_colors[group] = theme_multi[i]
                        else:
                            group_colors[group] = theme_multi[i % len(theme_multi)]
                    
                    # 绘制每个分组
                    for group in groups:
                        group_data = scatter_df[scatter_df[group_field] == group]
                        ax.scatter(
                            group_data[x_axis],
                            group_data[y_axis],
                            c=group_colors[group],
                            label=str(group),
                            alpha=0.6,
                            s=150,
                            edgecolors='white',
                            linewidth=1.5
                        )
                    
                    # 添加图例
                    ax.legend(title=group_field, loc='best', framealpha=0.9, fontsize=9)
            else:
                # 单色散点图
                ax.scatter(
                    x_values,
                    y_values,
                    c=colors['primary'],
                    alpha=0.6,
                    s=100,
                    edgecolors='white',
                    linewidth=1.5
                )
            
            ax.set_xlabel(xlabel, fontsize=12, fontweight='bold')
            ax.set_ylabel(ylabel, fontsize=12, fontweight='bold')
            ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
            
            # 应用对数轴
            if x_axis_config['log_scale']:
                ax.set_xscale('log')
            if y_axis_config['log_scale']:
                ax.set_yscale('log')
            
            # 添加网格线
            ax.grid(True, linestyle='--', alpha=0.3)
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
        
        elif chart_type == 'pie':
            # 饼图
            labels = chart_data[x_axis].astype(str)
            sizes = chart_data[y_axis]
            
            # 根据主题生成渐变色系
            # 使用主题的多色配置生成渐变
            theme_multi = colors['multi']
            if len(labels) <= len(theme_multi):
                pie_colors = theme_multi[:len(labels)]
            else:
                # 如果标签数量多于主题颜色数，生成更多渐变色
                import matplotlib.colors as mcolors
                cmap = mcolors.LinearSegmentedColormap.from_list('custom', theme_multi)
                pie_colors = [cmap(i / len(labels)) for i in range(len(labels))]
            
            # 计算百分比
            total = sizes.sum()
            
            # 绘制饼图
            wedges, texts, autotexts = ax.pie(
                sizes, 
                labels=labels,
                colors=pie_colors,
                autopct=lambda pct: f'{pct:.1f}%\n({int(pct/100*total):,})',
                startangle=90,
                pctdistance=0.85,
                explode=[0.05] * len(labels)  # 稍微分离每个扇区
            )
            
            # 设置文字样式
            for text in texts:
                text.set_fontsize(11)
                text.set_fontweight('bold')
            
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontsize(9)
                autotext.set_fontweight('bold')
            
            # 使用配置的标题
            title = custom_title if custom_title else f'{x_axis} - {y_axis} 分布图'
            ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
            
            # 确保饼图是圆形
            ax.axis('equal')
        
        # 对于折线图、柱状图、面积图、饼图和散点图，统一保存图表
        if chart_type in ['line', 'bar', 'area', 'pie', 'scatter']:
            # 美化图表
            plt.tight_layout()
            
            # 保存图表为base64
            buffer = BytesIO()
            plt.savefig(buffer, format='png', dpi=100, bbox_inches='tight')
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode()
            plt.close(fig)
            
            # 同时保存到文件（用于下载）
            chart_filename = f"{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{chart_type}.png"
            chart_path = os.path.join(CHARTS_FOLDER, chart_filename)
            
            buffer.seek(0)
            with open(chart_path, 'wb') as f:
                f.write(buffer.getvalue())
            
            return jsonify({
                'success': True,
                'chart_type': chart_type,
                'image': f'data:image/png;base64,{image_base64}',
                'filename': chart_filename
            })
            
        elif chart_type == 'waterfall':
            # 瀑布图
            values = chart_data[y_axis].values
            categories = chart_data[x_axis].values
            
            # 计算累计值
            cumulative = np.zeros(len(values) + 1)
            cumulative[1:] = np.cumsum(values)
            
            # 绘制瀑布图 - 正值用主色，负值用对比色
            waterfall_colors = [colors['primary'] if v >= 0 else '#f5576c' for v in values]
            
            for i in range(len(values)):
                # 绘制柱子
                ax.bar(i, values[i], bottom=cumulative[i], 
                      color=waterfall_colors[i], edgecolor='white', linewidth=1.5)
                
                # 添加连接线
                if i < len(values) - 1:
                    ax.plot([i + 0.4, i + 0.6], 
                           [cumulative[i+1], cumulative[i+1]], 
                           'k--', linewidth=1, alpha=0.5)
                
                # 添加数值标签
                ax.text(i, cumulative[i] + values[i]/2, 
                       f'{values[i]:,.0f}',
                       ha='center', va='center', fontsize=9, fontweight='bold',
                       color='white')
            
            # 添加总计柱 - 使用副色
            ax.bar(len(values), cumulative[-1], 
                  color=colors['secondary'], edgecolor='white', linewidth=1.5, alpha=0.8)
            ax.text(len(values), cumulative[-1]/2, 
                   f'总计\n{cumulative[-1]:,.0f}',
                   ha='center', va='center', fontsize=10, fontweight='bold',
                   color='white')
            
            # 设置X轴
            labels = list(categories) + ['总计']
            ax.set_xticks(range(len(labels))) 
            ax.set_xticklabels(labels, rotation=45, ha='right')
            
            # 使用配置的标签
            title = custom_title if custom_title else f'{x_axis} - {y_axis} 瀑布图'
            
            ax.set_xlabel(xlabel, fontsize=12, fontweight='bold')
            ax.set_ylabel(ylabel, fontsize=12, fontweight='bold')
            ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
            
            # 应用对数轴
            if y_axis_config['log_scale']:
                ax.set_yscale('log')
            
            # 美化图表
            ax.grid(axis='y', linestyle='--', alpha=0.3)
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            plt.tight_layout()
            
            # 保存图表为base64
            buffer = BytesIO()
            plt.savefig(buffer, format='png', dpi=100, bbox_inches='tight')
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode()
            plt.close(fig)
            
            # 同时保存到文件（用于下载）
            chart_filename = f"{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{chart_type}.png"
            chart_path = os.path.join(CHARTS_FOLDER, chart_filename)
            
            buffer.seek(0)
            with open(chart_path, 'wb') as f:
                f.write(buffer.getvalue())
            
            return jsonify({
                'success': True,
                'chart_type': chart_type,
                'image': f'data:image/png;base64,{image_base64}',
                'filename': chart_filename
            })
        
        elif chart_type == 'map':
            # 中国地图热力图 - 重新从原始数据处理
            title = custom_title if custom_title else f'{x_axis} - {y_axis} 地图'
            
            # 省份名称标准化函数 - 转换为GeoJSON地图需要的格式（带省/市/自治区后缀）
            def normalize_province(name):
                """将各种格式的省份名称标准化为GeoJSON地图格式"""
                if pd.isna(name):
                    return None
                
                name = str(name).strip()
                
                # 先移除常见后缀和民族名称
                name = name.replace('省', '').replace('市', '').replace('自治区', '').replace('特别行政区', '')
                name = name.replace('壮族', '').replace('回族', '').replace('维吾尔', '')
                name = name.strip()
                
                # 标准省份名称映射（GeoJSON格式：带省/市/自治区后缀）
                province_standard = {
                    # 直辖市（带"市"）
                    '北京': '北京市',
                    '天津': '天津市', 
                    '上海': '上海市', 
                    '重庆': '重庆市',
                    # 省份（带"省"）
                    '河北': '河北省',
                    '山西': '山西省',
                    '辽宁': '辽宁省',
                    '吉林': '吉林省',
                    '黑龙江': '黑龙江省',
                    '江苏': '江苏省',
                    '浙江': '浙江省',
                    '安徽': '安徽省',
                    '福建': '福建省',
                    '江西': '江西省',
                    '山东': '山东省',
                    '河南': '河南省',
                    '湖北': '湖北省',
                    '湖南': '湖南省',
                    '广东': '广东省',
                    '海南': '海南省',
                    '四川': '四川省',
                    '贵州': '贵州省',
                    '云南': '云南省',
                    '陕西': '陕西省',
                    '甘肃': '甘肃省',
                    '青海': '青海省',
                    '台湾': '台湾省',
                    # 自治区（带"自治区"）
                    '内蒙古': '内蒙古自治区',
                    '内蒙': '内蒙古自治区',
                    '广西': '广西壮族自治区',
                    '西藏': '西藏自治区',
                    '宁夏': '宁夏回族自治区',
                    '新疆': '新疆维吾尔自治区',
                    # 特别行政区
                    '香港': '香港特别行政区',
                    '澳门': '澳门特别行政区'
                }
                
                return province_standard.get(name, name)
            
            # 从原始数据重新处理（不使用前面已处理的chart_data）
            map_df = df[[x_axis, y_axis]].copy()
            
            # 确保数值列是数值类型
            map_df[y_axis] = pd.to_numeric(map_df[y_axis], errors='coerce')
            
            # 标准化地区名称
            map_df[x_axis] = map_df[x_axis].map(normalize_province)
            
            # 过滤掉空值（同时过滤省份和数值的空值）
            map_df = map_df.dropna(subset=[x_axis, y_axis])
            
            print(f"\n=== 数据处理前检查 ===")
            print(f"map_df内容:\n{map_df}")
            print(f"数据类型: {map_df[y_axis].dtype}")
            print("=" * 50)
            
            # 按省份聚合数据（求和）
            map_data_grouped = map_df.groupby(x_axis, as_index=False)[y_axis].sum()
            
            # 打印调试信息
            print(f"\n=== 地图数据调试信息 ===")
            print(f"原始数据行数: {len(df)}")
            print(f"标准化后行数: {len(map_df)}")
            print(f"聚合后省份数: {len(map_data_grouped)}")
            print(f"省份列表: {map_data_grouped[x_axis].tolist()}")
            print(f"对应数值: {map_data_grouped[y_axis].tolist()}")
            print(f"数值范围: {map_data_grouped[y_axis].min()} - {map_data_grouped[y_axis].max()}")
            
            # 准备地图数据 - 确保格式完全正确
            map_data = []
            for idx, row in map_data_grouped.iterrows():
                province_name = str(row[x_axis]).strip()
                value = row[y_axis]
                
                # 确保值是有效的数字
                if pd.notna(value):
                    try:
                        # 转换为int（pyecharts可能对整数支持更好）
                        value_num = int(float(value))
                        # 使用tuple而不是list
                        map_data.append((province_name, value_num))
                        print(f"  {province_name}: {value_num} (类型: {type(value_num).__name__})")
                    except (ValueError, TypeError) as e:
                        print(f"  警告: {province_name} 的值 {value} 转换失败: {e}")
                else:
                    print(f"  警告: {province_name} 的值为NaN，跳过")
            
            print(f"\n最终地图数据: {map_data}")
            print(f"数据条数: {len(map_data)}")
            
            # 验证数据格式
            print("\n数据格式验证:")
            for item in map_data:
                print(f"  省份: '{item[0]}' (长度:{len(item[0])}), 数值: {item[1]} (类型:{type(item[1]).__name__})")
            
            print("=" * 50)
            
            # 如果没有有效数据，返回错误
            if len(map_data) == 0:
                return jsonify({'success': False, 'message': '没有有效的地图数据'}), 400
            
            # 计算数值范围，确保有合适的对比度
            values = [item[1] for item in map_data]
            min_val = min(values)
            max_val = max(values)
            
            print(f"数值范围: {min_val} - {max_val}")
            
            # 如果所有数值相同，稍微调整范围
            if min_val == max_val:
                min_val = min_val * 0.9 if min_val > 0 else -1
                max_val = max_val * 1.1 if max_val > 0 else 1
                print(f"调整后范围: {min_val} - {max_val}")
            
            # 创建地图（白色背景 + 蓝色深浅渐变）
            print(f"\n开始创建pyecharts地图...")
            print(f"传递给pyecharts 的data_pair: {map_data}")
            
            map_chart = Map(init_opts=opts.InitOpts(
                width="100%", 
                height="100%",
                bg_color="white"
            ))
            
            map_chart.add(
                series_name=str(y_axis),
                data_pair=map_data,
                maptype="china",
                is_map_symbol_show=False,
                label_opts=opts.LabelOpts(
                    is_show=True, 
                    font_size=9,
                    color="#333333",
                    formatter="{b}"  # 只显示省份名称
                ),
                itemstyle_opts=opts.ItemStyleOpts(
                    border_color="#DDDDDD",
                    border_width=0.8
                )
            )
            
            print("pyecharts Map.add() 调用成功")
            
            map_chart.set_global_opts(
                title_opts=opts.TitleOpts(
                    title=title,
                    pos_left="center",
                    pos_top="2%",
                    title_textstyle_opts=opts.TextStyleOpts(
                        font_size=18, 
                        font_weight="bold",
                        color="#333333"
                    )
                ),
                visualmap_opts=opts.VisualMapOpts(
                    min_=min_val,
                    max_=max_val,
                    is_piecewise=False,
                    pos_left="2%",
                    pos_bottom="5%",
                    orient="vertical",
                    range_color=colors['multi'] + [colors['secondary']],  # 使用主题颜色渐变
                    textstyle_opts=opts.TextStyleOpts(color="#333333", font_size=11),
                    border_color="#999999",
                    border_width=1,
                    item_width=15,
                    item_height=100
                ),
                tooltip_opts=opts.TooltipOpts(
                    is_show=True,
                    formatter="{b}: {c}",
                    textstyle_opts=opts.TextStyleOpts(font_size=12)
                )
            )
            
            # 保存HTML文件
            chart_filename = f"{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{chart_type}.html"
            chart_path = os.path.join(CHARTS_FOLDER, chart_filename)
            
            print(f"\n准备保存地图到: {chart_path}")
            map_chart.render(chart_path)
            print(f"render()调用完成")
            
            # 验证文件是否真的生成了
            if not os.path.exists(chart_path):
                print(f"错误：文件没有生成！路径: {chart_path}")
                return jsonify({'success': False, 'message': '地图HTML文件生成失败，请确认已安装echarts地图包'}), 500
            
            print(f"文件生成成功，大小: {os.path.getsize(chart_path)} 字节")
            
            # 修复HTML文件，使用本地地图文件
            try:
                with open(chart_path, 'r', encoding='utf-8') as f:
                    html_content = f.read()
                
                # 替换为本地ECharts文件
                html_content = html_content.replace(
                    '<script type="text/javascript" src="https://assets.pyecharts.org/assets/v5/echarts.min.js"></script>',
                    '<script type="text/javascript" src="/static/js/echarts.min.js"></script>'
                )
                
                # 移除原来的地图脚本标签，改用fetch加载JSON
                html_content = html_content.replace(
                    '<script type="text/javascript" src="https://assets.pyecharts.org/assets/v5/maps/china.js"></script>',
                    ''
                )
                
                # 添加自适应样式（在</head>之前插入）
                adaptive_style = '''<style>
    html, body {
        margin: 0;
        padding: 0;
        width: 100%;
        height: 100%;
        overflow: hidden;
    }
    #container {
        width: 100% !important;
        height: 100% !important;
    }
</style>
'''
                head_close_pos = html_content.find('</head>')
                if head_close_pos > 0:
                    html_content = html_content[:head_close_pos] + adaptive_style + html_content[head_close_pos:]
                
                # 找到图表初始化代码，在它之前插入地图加载脚本
                # 找到 var chart_ 开始的位置
                chart_init_pos = html_content.find('var chart_')
                if chart_init_pos > 0:
                    # 在图表初始化之前插入地图加载和注册代码
                    map_loader_script = '''        // 同步加载中国地图GeoJSON数据
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/static/js/china.json', false);  // false = 同步请求
        xhr.send();
        if (xhr.status === 200) {
            var chinaJson = JSON.parse(xhr.responseText);
            echarts.registerMap('china', chinaJson);
            console.log('✅ 中国地图数据加载成功');
        } else {
            console.error('❌ 地图数据加载失败:', xhr.status);
        }
        
'''
                    html_content = html_content[:chart_init_pos] + map_loader_script + html_content[chart_init_pos:]
                
                # 添加窗口resize事件监听，使地图能够响应容器大小变化
                resize_script = '''
    // 监听窗口大小变化，重新调整图表大小
    window.addEventListener('resize', function() {
        var charts = document.querySelectorAll('[_echarts_instance_]');
        charts.forEach(function(chartDom) {
            var chartInstance = echarts.getInstanceByDom(chartDom);
            if (chartInstance) {
                chartInstance.resize();
            }
        });
    });
    
    // 页面加载完成后也调整一次大小
    window.addEventListener('load', function() {
        setTimeout(function() {
            var charts = document.querySelectorAll('[_echarts_instance_]');
            charts.forEach(function(chartDom) {
                var chartInstance = echarts.getInstanceByDom(chartDom);
                if (chartInstance) {
                    chartInstance.resize();
                }
            });
        }, 100);
    });
'''
                body_close_pos = html_content.find('</body>')
                if body_close_pos > 0:
                    html_content = html_content[:body_close_pos] + '<script>' + resize_script + '</script>' + html_content[body_close_pos:]
                
                with open(chart_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                print(f"已优化HTML文件，使用本地地图文件并添加自适应样式")
            except Exception as e:
                print(f"警告：优化HTML文件失败: {e}")
            
            return jsonify({
                'success': True,
                'chart_type': chart_type,
                'chart_url': f'/charts/{chart_filename}',
                'filename': chart_filename,
                'is_html': True
            })
        
        elif chart_type == 'sunburst':
            # 旭日图 - 需要多个维度字段
            # 从请求中获取所有维度字段（rows字段）
            rows = data.get('rows', [])
            values_field = data.get('values', [])
            
            if not rows or not values_field:
                return jsonify({'success': False, 'message': '旭日图需要至少一个维度字段（行）和一个度量字段（值）'}), 400
            
            # 如果只有一个维度，使用它加上一个虚拟的总计层
            if len(rows) == 1:
                # 添加一个总计根节点
                dimension_cols = ['总计'] + rows
            else:
                dimension_cols = rows
            
            value_col = values_field[0] if values_field else y_axis
            
            # 检查所需列是否存在
            required_cols = rows + [value_col]
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                return jsonify({'success': False, 'message': f'缺少必需的列: {", ".join(missing_cols)}'}), 400
            
            # 准备数据
            sunburst_df = df[rows + [value_col]].copy()
            sunburst_df[value_col] = pd.to_numeric(sunburst_df[value_col], errors='coerce')
            sunburst_df = sunburst_df.dropna()
            
            # 如果只有一个维度，添加总计列
            if len(rows) == 1:
                sunburst_df['总计'] = '总计'
                dimension_cols = ['总计'] + rows
            
            # 聚合数据
            grouped_data = sunburst_df.groupby(dimension_cols)[value_col].sum().reset_index()
            
            # 构建层次结构数据
            def build_tree(data, dimensions, value_col, parent_filter=None):
                """递归构建树形结构数据"""
                if not dimensions:
                    return []
                
                current_dim = dimensions[0]
                remaining_dims = dimensions[1:]
                
                # 过滤当前层级的数据
                if parent_filter:
                    current_data = data
                    for col, val in parent_filter.items():
                        current_data = current_data[current_data[col] == val]
                else:
                    current_data = data
                
                # 按当前维度分组
                if remaining_dims:
                    # 还有子层级
                    groups = current_data.groupby(current_dim)[value_col].sum()
                    result = []
                    for name, value in groups.items():
                        new_filter = parent_filter.copy() if parent_filter else {}
                        new_filter[current_dim] = name
                        children = build_tree(data, remaining_dims, value_col, new_filter)
                        
                        node = {
                            "name": str(name),
                            "value": float(value)
                        }
                        if children:
                            node["children"] = children
                        result.append(node)
                    return result
                else:
                    # 最后一层
                    result = []
                    for idx, row in current_data.iterrows():
                        result.append({
                            "name": str(row[current_dim]),
                            "value": float(row[value_col])
                        })
                    return result
            
            # 构建树形数据
            tree_data = build_tree(grouped_data, dimension_cols, value_col)
            
            # 使用自定义标题或默认值
            title = custom_title if custom_title else f'{" - ".join(rows)} 分布旭日图'
            
            # 创建旭日图
            sunburst_chart = Sunburst(init_opts=opts.InitOpts(
                width="1200px",
                height="700px",
                bg_color="white"
            ))
            
            sunburst_chart.add(
                series_name="",
                data_pair=tree_data,
                radius=["10%", "90%"],
                label_opts=opts.LabelOpts(
                    rotate="radial",
                    font_size=11,
                    color="#000"
                ),
            )
            
            sunburst_chart.set_global_opts(
                title_opts=opts.TitleOpts(
                    title=title,
                    pos_left="center",
                    pos_top="20",
                    title_textstyle_opts=opts.TextStyleOpts(
                        font_size=22,
                        font_weight="bold",
                        color="#333333"
                    )
                ),
                tooltip_opts=opts.TooltipOpts(
                    trigger="item",
                    formatter="{b}: {c}"
                )
            )
            
            # 保存HTML文件
            chart_filename = f"{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{chart_type}.html"
            chart_path = os.path.join(CHARTS_FOLDER, chart_filename)
            
            sunburst_chart.render(chart_path)
            
            # 修复HTML文件，使用本地echarts文件
            try:
                with open(chart_path, 'r', encoding='utf-8') as f:
                    html_content = f.read()
                
                html_content = html_content.replace(
                    '<script type="text/javascript" src="https://assets.pyecharts.org/assets/v5/echarts.min.js"></script>',
                    '<script type="text/javascript" src="/static/js/echarts.min.js"></script>'
                )
                
                with open(chart_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            except Exception as e:
                print(f"警告：优化HTML文件失败: {e}")
            
            return jsonify({
                'success': True,
                'chart_type': chart_type,
                'chart_url': f'/charts/{chart_filename}',
                'filename': chart_filename,
                'is_html': True
            })
        
        else:
            return jsonify({'success': False, 'message': '不支持的图表类型'}), 400
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'生成图表失败: {str(e)}'}), 500


@app.route('/charts/<filename>')
@login_required
def serve_chart(filename):
    """提供图表文件访问"""
    try:
        # 验证文件名（安全检查）
        if not filename or '/' in filename or '\\' in filename:
            return "无效的文件名", 400
        
        # 检查文件是否属于当前用户
        if not filename.startswith(f"{current_user.id}_"):
            return "无权访问该文件", 403
        
        chart_path = os.path.join(CHARTS_FOLDER, filename)
        
        if not os.path.exists(chart_path):
            return "文件不存在", 404
        
        # 根据文件类型返回不同的mimetype
        if filename.endswith('.html'):
            return send_file(chart_path, mimetype='text/html')
        else:
            return send_file(chart_path, mimetype='image/png')
        
    except Exception as e:
        return f"访问失败: {str(e)}", 500


@app.route('/api/chart/combo/generate', methods=['POST'])
@login_required
def generate_combo_chart():
    """生成联合图（单Y或双Y）"""
    try:
        data = request.get_json()
        file_id = data.get('file_id')
        chart_type = data.get('chart_type')  # 'combo_single' 或 'combo_dual'
        dimension = data.get('dimension')  # 维度字段（X轴）
        measures = data.get('measures', [])  # 度量配置列表
        theme = data.get('theme', 'purple')
        
        # 现代化主题颜色配置 - 使用渐变和高级配色
        theme_colors = {
            'purple': {'primary': '#667eea', 'secondary': '#764ba2', 'multi': ['#a78bfa', '#8b5cf6', '#7c3aed', '#6d28d9', '#5b21b6', '#4c1d95']},
            'blue': {'primary': '#3b82f6', 'secondary': '#1e40af', 'multi': ['#60a5fa', '#3b82f6', '#2563eb', '#1d4ed8', '#1e40af', '#1e3a8a']},
            'green': {'primary': '#10b981', 'secondary': '#047857', 'multi': ['#6ee7b7', '#34d399', '#10b981', '#059669', '#047857', '#065f46']},
            'red': {'primary': '#ef4444', 'secondary': '#b91c1c', 'multi': ['#f87171', '#ef4444', '#dc2626', '#b91c1c', '#991b1b', '#7f1d1d']},
            'orange': {'primary': '#f97316', 'secondary': '#c2410c', 'multi': ['#fb923c', '#f97316', '#ea580c', '#c2410c', '#9a3412', '#7c2d12']},
            'pink': {'primary': '#ec4899', 'secondary': '#be185d', 'multi': ['#f472b6', '#ec4899', '#db2777', '#be185d', '#9f1239', '#831843']},
            'teal': {'primary': '#14b8a6', 'secondary': '#0f766e', 'multi': ['#5eead4', '#2dd4bf', '#14b8a6', '#0d9488', '#0f766e', '#115e59']},
            'sunset': {'primary': '#f093fb', 'secondary': '#f5576c', 'multi': ['#fbc2eb', '#f093fb', '#f57b94', '#f5576c', '#d63447', '#c02040']},
            'ocean': {'primary': '#667eea', 'secondary': '#00c9ff', 'multi': ['#8b9aed', '#667eea', '#4395e6', '#00b9e3', '#00c9ff', '#00e5ff']},
            'forest': {'primary': '#56ab2f', 'secondary': '#a8e063', 'multi': ['#6bc248', '#56ab2f', '#75b94d', '#92c96e', '#a8e063', '#c0e87f']}
        }
        colors = theme_colors.get(theme, theme_colors['purple'])
        
        # 验证文件
        data_file = DataFile.query.filter_by(id=file_id, user_id=current_user.id).first()
        if not data_file:
            return jsonify({'success': False, 'message': '文件不存在'}), 404
        
        # 读取数据文件
        file_ext = data_file.file_type
        df = None
        
        if file_ext in ['xlsx', 'xls']:
            engines = ['openpyxl', 'xlrd'] if file_ext == 'xlsx' else ['xlrd', 'openpyxl']
            for engine in engines:
                try:
                    df = pd.read_excel(data_file.file_path, engine=engine)
                    break
                except:
                    continue
        else:
            df = pd.read_csv(data_file.file_path)
        
        if df is None:
            return jsonify({'success': False, 'message': '无法读取数据文件'}), 500
        
        # 验证字段
        if not dimension or len(measures) == 0:
            return jsonify({'success': False, 'message': '请选择维度和至少一个度量字段'}), 400
        
        if dimension not in df.columns:
            return jsonify({'success': False, 'message': f'维度字段 {dimension} 不存在'}), 400
        
        for measure in measures:
            if measure['field'] not in df.columns:
                return jsonify({'success': False, 'message': f'度量字段 {measure["field"]} 不存在'}), 400
        
        # 创建图表
        fig, ax1 = plt.subplots(figsize=(14, 7))
        
        # 处理数据
        x_categories = df[dimension].unique()[:20]  # 限制20个类别
        x_pos = np.arange(len(x_categories))
        
        # 聚合方式映射
        agg_map = {'sum': 'sum', 'avg': 'mean', 'count': 'count', 'max': 'max', 'min': 'min'}
        
        # 单Y联合图
        if chart_type == 'combo_single':
            for i, measure in enumerate(measures):
                field = measure['field']
                agg_func = agg_map.get(measure['aggregation'], 'sum')
                chart_type_name = measure['chart_type']
                
                # 聚合数据
                measure_data = df.groupby(dimension)[field].agg(agg_func).reindex(x_categories, fill_value=0).values
                
                color = colors['multi'][i % len(colors['multi'])]
                
                if chart_type_name == 'bar':
                    # 柱状图 - 使用不同的宽度和位置
                    width = 0.8 / len(measures)
                    offset = width * (i - len(measures)/2 + 0.5)
                    ax1.bar(x_pos + offset, measure_data, width, label=field, color=color, alpha=0.8)
                elif chart_type_name == 'line':
                    # 折线图
                    ax1.plot(x_pos, measure_data, label=field, color=color, linewidth=2.5, marker='o', markersize=8)
                elif chart_type_name == 'area':
                    # 面积图
                    ax1.fill_between(x_pos, measure_data, alpha=0.3, color=color, label=field)
                    ax1.plot(x_pos, measure_data, color=color, linewidth=2)
            
            ax1.set_xlabel(dimension, fontsize=12, fontweight='bold')
            ax1.set_ylabel('数值', fontsize=12, fontweight='bold')
            ax1.set_xticks(x_pos)
            ax1.set_xticklabels(x_categories, rotation=45, ha='right')
            ax1.legend(loc='upper left', framealpha=0.9)
            ax1.grid(True, linestyle='--', alpha=0.3, axis='y')
        
        # 双Y联合图
        elif chart_type == 'combo_dual':
            # 左轴度量（前一半）
            left_measures = measures[:len(measures)//2 + len(measures)%2]
            # 右轴度量（后一半）
            right_measures = measures[len(measures)//2 + len(measures)%2:]
            
            # 绘制左轴
            for i, measure in enumerate(left_measures):
                field = measure['field']
                agg_func = agg_map.get(measure['aggregation'], 'sum')
                chart_type_name = measure['chart_type']
                
                measure_data = df.groupby(dimension)[field].agg(agg_func).reindex(x_categories, fill_value=0).values
                color = colors['multi'][i % len(colors['multi'])]
                
                if chart_type_name == 'bar':
                    width = 0.4 / max(len(left_measures), 1)
                    offset = width * (i - len(left_measures)/2 + 0.5)
                    ax1.bar(x_pos + offset - 0.2, measure_data, width, label=field, color=color, alpha=0.8)
                elif chart_type_name == 'line':
                    ax1.plot(x_pos, measure_data, label=field, color=color, linewidth=2.5, marker='o', markersize=8)
                elif chart_type_name == 'area':
                    ax1.fill_between(x_pos, measure_data, alpha=0.3, color=color, label=field)
                    ax1.plot(x_pos, measure_data, color=color, linewidth=2)
            
            ax1.set_xlabel(dimension, fontsize=12, fontweight='bold')
            ax1.set_ylabel('左轴', fontsize=12, fontweight='bold')
            ax1.set_xticks(x_pos)
            ax1.set_xticklabels(x_categories, rotation=45, ha='right')
            ax1.tick_params(axis='y', labelcolor=colors['primary'])
            
            # 绘制右轴
            if right_measures:
                ax2 = ax1.twinx()
                
                for i, measure in enumerate(right_measures):
                    field = measure['field']
                    agg_func = agg_map.get(measure['aggregation'], 'sum')
                    chart_type_name = measure['chart_type']
                    
                    measure_data = df.groupby(dimension)[field].agg(agg_func).reindex(x_categories, fill_value=0).values
                    color = colors['multi'][(i + len(left_measures)) % len(colors['multi'])]
                    
                    if chart_type_name == 'bar':
                        width = 0.4 / max(len(right_measures), 1)
                        offset = width * (i - len(right_measures)/2 + 0.5)
                        ax2.bar(x_pos + offset + 0.2, measure_data, width, label=field, color=color, alpha=0.8)
                    elif chart_type_name == 'line':
                        ax2.plot(x_pos, measure_data, label=field, color=color, linewidth=2.5, marker='s', markersize=8, linestyle='--')
                    elif chart_type_name == 'area':
                        ax2.fill_between(x_pos, measure_data, alpha=0.2, color=color, label=field)
                        ax2.plot(x_pos, measure_data, color=color, linewidth=2, linestyle='--')
                
                ax2.set_ylabel('右轴', fontsize=12, fontweight='bold')
                ax2.tick_params(axis='y', labelcolor=colors['secondary'])
                
                # 合并图例
                lines1, labels1 = ax1.get_legend_handles_labels()
                lines2, labels2 = ax2.get_legend_handles_labels()
                ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', framealpha=0.9)
            else:
                ax1.legend(loc='upper left', framealpha=0.9)
            
            ax1.grid(True, linestyle='--', alpha=0.3, axis='y')
        
        # 标题
        title = f'{dimension} - 联合图'
        ax1.set_title(title, fontsize=14, fontweight='bold', pad=20)
        
        # 美化
        ax1.spines['top'].set_visible(False)
        plt.tight_layout()
        
        # 保存图表
        buffer = BytesIO()
        plt.savefig(buffer, format='png', dpi=100, bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close(fig)
        
        # 保存到文件
        chart_filename = f"{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{chart_type}.png"
        chart_path = os.path.join(CHARTS_FOLDER, chart_filename)
        
        buffer.seek(0)
        with open(chart_path, 'wb') as f:
            f.write(buffer.getvalue())
        
        return jsonify({
            'success': True,
            'chart_type': chart_type,
            'image': f'data:image/png;base64,{image_base64}',
            'filename': chart_filename
        })
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'生成联合图失败: {str(e)}'}), 500


def create_shape_mask(shape, width=1200, height=600):
    """创建不同形状的遮罩图片"""
    # 创建一个白色背景的图片
    mask = Image.new('RGB', (width, height), 'white')
    draw = ImageDraw.Draw(mask)
    
    center_x, center_y = width // 2, height // 2
    
    if shape == 'circle':
        # 圆形
        radius = min(width, height) // 2 - 50
        draw.ellipse([center_x - radius, center_y - radius, 
                     center_x + radius, center_y + radius], fill='black')
    
    elif shape == 'cloud':
        # 云形（多个圆组合）
        # 主圆
        r1 = min(width, height) // 3
        draw.ellipse([center_x - r1, center_y - r1//2, 
                     center_x + r1, center_y + r1//2], fill='black')
        # 左圆
        r2 = r1 // 2
        draw.ellipse([center_x - r1, center_y - r2, 
                     center_x - r1//2, center_y + r2], fill='black')
        # 右圆
        draw.ellipse([center_x + r1//2, center_y - r2, 
                     center_x + r1, center_y + r2], fill='black')
        # 上圆
        draw.ellipse([center_x - r2, center_y - r1//2, 
                     center_x + r2, center_y + r2//2], fill='black')
    
    elif shape == 'star':
        # 星形（五角星）
        import math
        radius = min(width, height) // 2 - 50
        inner_radius = radius // 2.5
        points = []
        for i in range(10):
            angle = math.pi / 2 + (2 * math.pi * i / 10)
            r = radius if i % 2 == 0 else inner_radius
            x = center_x + r * math.cos(angle)
            y = center_y - r * math.sin(angle)
            points.append((x, y))
        draw.polygon(points, fill='black')
    
    elif shape == 'heart':
        # 心形
        import math
        points = []
        for t in range(0, 360):
            angle = math.radians(t)
            x = 16 * math.sin(angle) ** 3
            y = -(13 * math.cos(angle) - 5 * math.cos(2*angle) - 
                  2 * math.cos(3*angle) - math.cos(4*angle))
            # 缩放并移动到中心
            scale = min(width, height) // 35
            points.append((center_x + x * scale, center_y + y * scale))
        draw.polygon(points, fill='black')
    
    elif shape == 'diamond':
        # 菱形
        size = min(width, height) // 2 - 50
        points = [
            (center_x, center_y - size),  # 上
            (center_x + size, center_y),  # 右
            (center_x, center_y + size),  # 下
            (center_x - size, center_y)   # 左
        ]
        draw.polygon(points, fill='black')
    
    else:  # rectangle 或默认
        # 矩形（整个画布）
        draw.rectangle([50, 50, width-50, height-50], fill='black')
    
    return np.array(mask)


@app.route('/api/chart/wordcloud/generate', methods=['POST'])
@login_required
def generate_wordcloud():
    """生成词云图"""
    try:
        data = request.get_json()
        file_id = data.get('file_id')
        text_field = data.get('text_field')  # 文本字段
        weight_field = data.get('weight_field')  # 权重字段（可选）
        shape = data.get('shape', 'rectangle')  # 形状
        theme = data.get('theme', 'purple')
        
        # 现代化主题颜色配置 - 词云图专用
        theme_colors = {
            'purple': '#667eea',
            'blue': '#3b82f6',
            'green': '#10b981',
            'red': '#ef4444',
            'orange': '#f97316',
            'pink': '#ec4899',
            'teal': '#14b8a6',
            'sunset': '#f093fb',
            'ocean': '#667eea',
            'forest': '#56ab2f'
        }
        color = theme_colors.get(theme, theme_colors['purple'])
        
        # 验证文件
        data_file = DataFile.query.filter_by(id=file_id, user_id=current_user.id).first()
        if not data_file:
            return jsonify({'success': False, 'message': '文件不存在'}), 404
        
        # 读取数据文件
        file_ext = data_file.file_type
        df = None
        
        if file_ext in ['xlsx', 'xls']:
            engines = ['openpyxl', 'xlrd'] if file_ext == 'xlsx' else ['xlrd', 'openpyxl']
            for engine in engines:
                try:
                    df = pd.read_excel(data_file.file_path, engine=engine)
                    break
                except:
                    continue
        else:
            df = pd.read_csv(data_file.file_path)
        
        if df is None:
            return jsonify({'success': False, 'message': '无法读取数据文件'}), 500
        
        # 验证字段
        if not text_field or text_field not in df.columns:
            return jsonify({'success': False, 'message': '文本字段不存在'}), 400
        
        if weight_field and weight_field not in df.columns:
            return jsonify({'success': False, 'message': '权重字段不存在'}), 400
        
        # 准备文本数据
        if weight_field:
            # 使用权重字段
            word_freq = {}
            for idx, row in df.iterrows():
                text = str(row[text_field])
                weight = float(row[weight_field]) if pd.notna(row[weight_field]) else 0
                
                # 分词
                words = jieba.cut(text)
                for word in words:
                    word = word.strip()
                    if len(word) > 1:  # 过滤单字
                        word_freq[word] = word_freq.get(word, 0) + weight
        else:
            # 不使用权重，按词频统计
            text_data = ' '.join(df[text_field].astype(str).tolist())
            words = jieba.cut(text_data)
            word_freq = {}
            for word in words:
                word = word.strip()
                if len(word) > 1:  # 过滤单字
                    word_freq[word] = word_freq.get(word, 0) + 1
        
        if not word_freq:
            return jsonify({'success': False, 'message': '没有可用的文本数据'}), 400
        
        # 生成词云
        # 设置中文字体
        font_path = None
        # Windows系统字体路径
        if os.name == 'nt':
            font_path = 'C:/Windows/Fonts/msyh.ttc'  # 微软雅黑
            if not os.path.exists(font_path):
                font_path = 'C:/Windows/Fonts/simhei.ttf'  # 黑体
        
        # 生成形状遮罩
        mask_array = create_shape_mask(shape, width=1200, height=600)
        
        wordcloud = WordCloud(
            width=1200,
            height=600,
            background_color='white',
            font_path=font_path,
            mask=mask_array,
            colormap='viridis',
            relative_scaling=0.5,
            min_font_size=10,
            max_font_size=100,
            contour_width=0,
            contour_color='white'
        ).generate_from_frequencies(word_freq)
        
        # 创建图表
        fig, ax = plt.subplots(figsize=(14, 7))
        ax.imshow(wordcloud, interpolation='bilinear')
        ax.axis('off')
        
        # 形状名称映射
        shape_names = {
            'rectangle': '矩形',
            'circle': '圆形',
            'cloud': '云形',
            'star': '星形',
            'heart': '心形',
            'diamond': '菱形'
        }
        shape_name = shape_names.get(shape, '矩形')
        ax.set_title(f'{text_field} - 词云图 ({shape_name})', fontsize=14, fontweight='bold', pad=20)
        
        plt.tight_layout()
        
        # 保存图表
        buffer = BytesIO()
        plt.savefig(buffer, format='png', dpi=100, bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close(fig)
        
        # 保存到文件
        chart_filename = f"{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_wordcloud.png"
        chart_path = os.path.join(CHARTS_FOLDER, chart_filename)
        
        buffer.seek(0)
        with open(chart_path, 'wb') as f:
            f.write(buffer.getvalue())
        
        return jsonify({
            'success': True,
            'chart_type': 'wordcloud',
            'image': f'data:image/png;base64,{image_base64}',
            'filename': chart_filename
        })
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'生成词云图失败: {str(e)}'}), 500


@app.route('/api/chart/download/<filename>')
@login_required
def download_chart(filename):
    """下载图表"""
    try:
        # 验证文件名（安全检查）
        if not filename or '/' in filename or '\\' in filename:
            return jsonify({'success': False, 'message': '无效的文件名'}), 400
        
        # 检查文件是否属于当前用户
        if not filename.startswith(f"{current_user.id}_"):
            return jsonify({'success': False, 'message': '无权访问该文件'}), 403
        
        chart_path = os.path.join(CHARTS_FOLDER, filename)
        
        if not os.path.exists(chart_path):
            return jsonify({'success': False, 'message': '文件不存在'}), 404
        
        # 根据文件类型返回
        if filename.endswith('.html'):
            return send_file(chart_path, mimetype='text/html', as_attachment=True,
                           download_name=f'map_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html')
        else:
            return send_file(chart_path, mimetype='image/png', as_attachment=True, 
                            download_name=f'chart_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png')
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'下载失败: {str(e)}'}), 500


@app.route('/logout')
@login_required
def logout():
    """用户注销路由"""
    logout_user()
    flash('您已成功注销！', 'success')
    return redirect(url_for('login'))


# 创建数据库表
def init_db():
    """初始化数据库"""
    with app.app_context():
        db.create_all()
        print("数据库初始化完成！")
        
        # 创建默认管理员账号
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com'
            )
            admin.set_password('111111')
            db.session.add(admin)
            db.session.commit()
            print("已创建默认管理员账号: admin / 111111")
        else:
            print("管理员账号已存在")


if __name__ == '__main__':
    # 确保数据库存在
    if not os.path.exists('database.db'):
        init_db()
    else:
        # 数据库存在时，确保管理员账号存在
        with app.app_context():
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    email='admin@example.com'
                )
                admin.set_password('111111')
                db.session.add(admin)
                db.session.commit()
                print("已创建默认管理员账号: admin / 111111")
    
    # 运行应用
    print("启动数据可视化程序...")
    print("访问地址: http://127.0.0.1:5000")
    print("\n=== 管理员登录信息 ===")
    print("用户名: admin")
    print("密码: 111111")
    print("=====================\n")
    app.run(debug=True, host='127.0.0.1', port=5000)

