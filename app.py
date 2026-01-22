"""
Flask Web用户系统
主应用文件，包含所有路由和业务逻辑
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import os
from functools import wraps

# 初始化Flask应用
app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'  # 用于session加密，生产环境请更改

# 数据库文件路径
DATABASE = 'user_system.db'

# 管理员账户信息（在实际项目中应该存储在数据库中或环境变量中）
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'


def get_db_connection():
    """
    获取数据库连接
    返回: sqlite3连接对象
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # 使查询结果可以通过列名访问
    return conn


def init_db():
    """
    初始化数据库，创建用户信息表和日记表
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 创建用户信息表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone TEXT NOT NULL
        )
    ''')
    
    # 创建日记表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS diaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            diary TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users(username)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("数据库初始化完成！")


def isRightPhoneNum(phone):
    """
    验证手机号格式是否正确
    要求：1开头的11位数字
    参数: phone - 手机号字符串
    返回: True表示格式正确，False表示格式错误
    """
    if not phone:
        return False
    # 检查是否为1开头且长度为11位的纯数字
    if phone.startswith('1') and len(phone) == 11 and phone.isdigit():
        return True
    return False


def isRightPassword(password):
    """
    验证密码格式是否正确
    要求：6位以上，由字母和数字组成（至少包含一个字母和一个数字）
    参数: password - 密码字符串
    返回: True表示格式正确，False表示格式错误
    """
    if not password:
        return False
    
    # 检查密码长度是否至少6位
    if len(password) < 6:
        return False
    
    # 检查是否包含字母和数字
    has_letter = False  # 是否包含字母
    has_digit = False    # 是否包含数字
    
    # 遍历密码中的每个字符
    for char in password:
        if char.isalpha():  # 如果是字母
            has_letter = True
        elif char.isdigit():  # 如果是数字
            has_digit = True
    
    # 必须同时包含字母和数字
    return has_letter and has_digit


def isAlreadyIn(username):
    """
    检查用户名是否已存在于数据库中
    参数: username - 要检查的用户名
    返回: True表示用户名已存在，False表示用户名不存在
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 查询数据库中是否存在该用户名
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    
    conn.close()
    
    # 如果查询到结果，说明用户名已存在
    return result is not None


def login_required(f):
    """
    装饰器：要求用户登录后才能访问
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    装饰器：要求管理员登录后才能访问
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('is_admin') != True:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# ==================== 路由定义 ====================

@app.route('/')
def index():
    """
    首页，重定向到登录页面
    """
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    用户注册功能
    GET: 显示注册页面
    POST: 处理注册请求
    """
    if request.method == 'POST':
        # 获取表单数据
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        phone = request.form.get('phone', '').strip()
        
        # 验证1: 检查密码和确认密码是否相同
        if password != confirm_password:
            return render_template('register.html', 
                                 error='密码和确认密码不一致，请重新输入！',
                                 username=username, phone=phone)
        
        # 验证2: 检查密码格式是否正确（6位以上，由字母和数字组成）
        if not isRightPassword(password):
            return render_template('register.html', 
                                 error='密码格式错误！请输入6位以上由字母和数字合成的密码！',
                                 username=username, phone=phone)
        
        # 验证3: 检查手机号格式是否正确
        if not isRightPhoneNum(phone):
            return render_template('register.html', 
                                 error='手机号格式错误！请输入1开头的11位数字！',
                                 username=username)
        
        # 验证4: 检查用户名是否已存在
        if isAlreadyIn(username):
            return render_template('register.html', 
                                 error='用户名已存在，请选择其他用户名！',
                                 phone=phone)
        
        # 所有验证通过，将用户信息存入数据库
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password, phone) VALUES (?, ?, ?)',
                         (username, password, phone))
            conn.commit()
            conn.close()
            
            # 注册成功，重定向到登录页面
            return redirect(url_for('login', success='注册成功，请登录！'))
        except sqlite3.IntegrityError:
            # 如果出现唯一性约束错误（虽然我们已经检查过，但以防并发情况）
            return render_template('register.html', 
                                 error='注册失败，用户名可能已存在！',
                                 username=username, phone=phone)
        except Exception as e:
            return render_template('register.html', 
                                 error=f'注册失败：{str(e)}',
                                 username=username, phone=phone)
    
    # GET请求，显示注册页面
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    用户登录功能
    GET: 显示登录页面
    POST: 处理登录请求
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # 检查是否是管理员登录
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['username'] = username
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        
        # 普通用户登录验证
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                     (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # 登录成功
            session['username'] = username
            session['is_admin'] = False
            return redirect(url_for('user_dashboard'))
        else:
            # 登录失败
            return render_template('login.html', 
                                 error='用户名或密码错误',
                                 username=username)
    
    # GET请求，显示登录页面
    success_msg = request.args.get('success', '')
    return render_template('login.html', success=success_msg)


@app.route('/logout')
def logout():
    """
    用户登出功能
    """
    session.clear()
    return redirect(url_for('login'))


@app.route('/user_dashboard')
@login_required
def user_dashboard():
    """
    普通用户界面
    只有普通用户（非管理员）可以访问
    显示该用户的所有日记
    """
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    
    username = session.get('username')
    
    # 查询该用户在数据库日记表中的所有日记
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, diary FROM diaries WHERE username = ? ORDER BY id DESC', (username,))
    diaries = cursor.fetchall()
    conn.close()
    
    return render_template('user_dashboard.html', username=username, diaries=diaries)


@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    """
    管理员界面
    显示所有用户信息，并提供删除和修改功能
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 查询所有用户（排除管理员账户）
    cursor.execute('SELECT username, password, phone FROM users WHERE username != ?',
                 (ADMIN_USERNAME,))
    users = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html', users=users)


@app.route('/admin/delete_user', methods=['POST'])
@admin_required
def delete_user():
    """
    删除用户功能
    删除用户信息表中的用户，同时删除日记表中该用户的所有数据
    """
    username = request.form.get('username')
    
    if not username:
        return jsonify({'success': False, 'message': '用户名不能为空'})
    
    # 防止删除管理员账户
    if username == ADMIN_USERNAME:
        return jsonify({'success': False, 'message': '不能删除管理员账户'})
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 先删除日记表中的数据
        cursor.execute('DELETE FROM diaries WHERE username = ?', (username,))
        
        # 再删除用户信息表中的数据
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': '删除成功'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'删除失败：{str(e)}'})


@app.route('/admin/edit_user/<username>', methods=['GET', 'POST'])
@admin_required
def edit_user(username):
    """
    修改用户信息界面
    GET: 显示修改用户信息页面
    POST: 处理修改用户信息请求
    """
    if request.method == 'POST':
        # 获取表单数据
        new_username = request.form.get('username', '').strip()
        new_password = request.form.get('password', '').strip()
        new_phone = request.form.get('phone', '').strip()
        
        # 如果用户名被修改，检查新用户名是否已存在
        if new_username != username:
            if isAlreadyIn(new_username):
                # 获取原用户信息用于回显
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
                user = cursor.fetchone()
                conn.close()
                
                if user:
                    return render_template('edit_user.html',
                                         username=username,
                                         original_username=user['username'],
                                         original_password=user['password'],
                                         original_phone=user['phone'],
                                         error='已存在该用户名，请更改用户名')
                else:
                    return redirect(url_for('admin_dashboard'))
        
        # 验证密码格式是否正确（6位以上，由字母和数字组成）
        if not isRightPassword(new_password):
            # 获取原用户信息用于回显
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            conn.close()
            
            if user:
                return render_template('edit_user.html',
                                     username=username,
                                     original_username=user['username'],
                                     original_password=user['password'],
                                     original_phone=user['phone'],
                                     error='密码格式错误！请输入6位以上由字母和数字合成的密码！')
            else:
                return redirect(url_for('admin_dashboard'))
        
        # 验证手机号格式
        if not isRightPhoneNum(new_phone):
            # 获取原用户信息用于回显
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            conn.close()
            
            if user:
                return render_template('edit_user.html',
                                     username=username,
                                     original_username=user['username'],
                                     original_password=user['password'],
                                     original_phone=user['phone'],
                                     error='手机号格式错误！请输入1开头的11位数字！')
            else:
                return redirect(url_for('admin_dashboard'))
        
        # 更新用户信息
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 如果用户名改变，需要更新日记表中的用户名
            if new_username != username:
                cursor.execute('UPDATE diaries SET username = ? WHERE username = ?',
                             (new_username, username))
            
            # 更新用户信息
            cursor.execute('''
                UPDATE users 
                SET username = ?, password = ?, phone = ? 
                WHERE username = ?
            ''', (new_username, new_password, new_phone, username))
            
            conn.commit()
            conn.close()
            
            # 修改成功，重定向到管理员界面
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            # 获取原用户信息用于回显
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            conn.close()
            
            if user:
                return render_template('edit_user.html',
                                     username=username,
                                     original_username=user['username'],
                                     original_password=user['password'],
                                     original_phone=user['phone'],
                                     error=f'修改失败：{str(e)}')
            else:
                return redirect(url_for('admin_dashboard'))
    
    # GET请求，显示修改用户信息页面
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return redirect(url_for('admin_dashboard'))
    
    return render_template('edit_user.html',
                         username=username,
                         original_username=user['username'],
                         original_password=user['password'],
                         original_phone=user['phone'])


@app.route('/user/add_diary', methods=['POST'])
@login_required
def add_diary():
    """
    添加日记功能
    将用户提交的日记保存到数据库的日记表中
    """
    # 检查是否是管理员（管理员不应该使用这个功能）
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    
    username = session.get('username')
    diary_content = request.form.get('diary', '').strip()
    
    # 验证日记内容不能为空
    if not diary_content:
        # 如果日记为空，重定向回用户界面并显示错误
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, diary FROM diaries WHERE username = ? ORDER BY id DESC', (username,))
        diaries = cursor.fetchall()
        conn.close()
        return render_template('user_dashboard.html', 
                             username=username, 
                             diaries=diaries,
                             error='日记内容不能为空！')
    
    # 将日记保存到数据库
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO diaries (username, diary) VALUES (?, ?)',
                     (username, diary_content))
        conn.commit()
        conn.close()
        
        # 添加成功，重定向回用户界面
        return redirect(url_for('user_dashboard'))
    except Exception as e:
        # 如果保存失败，返回错误信息
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, diary FROM diaries WHERE username = ? ORDER BY id DESC', (username,))
        diaries = cursor.fetchall()
        conn.close()
        return render_template('user_dashboard.html', 
                             username=username, 
                             diaries=diaries,
                             error=f'保存日记失败：{str(e)}')


if __name__ == '__main__':
    # 初始化数据库
    if not os.path.exists(DATABASE):
        init_db()
    else:
        # 即使数据库存在，也确保表结构正确
        init_db()
    
    # 运行Flask应用
    app.run(debug=True, host='0.0.0.0', port=5000)
