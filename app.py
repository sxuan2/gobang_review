import sqlite3
import datetime
import json
import random
import string
import io
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, abort
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- 配置 ---
SECRET_KEY = 'secret key' # 上线前请改为复杂的随机字符串
DB_FILE = 'game.db'

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='eventlet')

# --- 登录组件初始化 ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # 未登录自动跳到这个路由

# --- 用户类 (配合 Flask-Login) ---
class User(UserMixin):
    def __init__(self, id, username, is_admin=False):
        self.id = id
        self.username = username
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'], bool(user['is_admin']))
    return None

# --- 数据库操作 ---

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_and_migrate_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # 1. 用户表 (新增)
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  username TEXT UNIQUE,
                  password_hash TEXT,
                  is_admin INTEGER DEFAULT 0)''')

    # 2. 检查是否有管理员，如果没有，创建一个默认的
    admin = c.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
    if not admin:
        print(">>> 初始化：创建默认管理员 admin / admin123")
        pw_hash = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)", 
                  ('admin', pw_hash))

    # 3. 房间表
    c.execute('''CREATE TABLE IF NOT EXISTS rooms
                 (id TEXT PRIMARY KEY, name TEXT, password TEXT, created_at TEXT, creator TEXT)''')
    
    # 4. 棋局表 (兼容迁移)
    c.execute('''CREATE TABLE IF NOT EXISTS games
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, start_time TEXT, name TEXT)''')
    cursor = c.execute("PRAGMA table_info(games)")
    columns = [row['name'] for row in cursor.fetchall()]
    if 'room_id' not in columns:
        print(">>> 执行数据库迁移...")
        c.execute("ALTER TABLE games ADD COLUMN room_id TEXT")
        c.execute("UPDATE games SET room_id = 'default'")
        # 补一个默认房间
        c.execute("INSERT OR IGNORE INTO rooms (id, name, password, created_at, creator) VALUES (?, ?, ?, ?, ?)",
                  ('default', "历史归档大厅", "123456", datetime.datetime.now(), "system"))
        conn.commit()

    # 5. 棋子表
    c.execute('''CREATE TABLE IF NOT EXISTS moves
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, game_id INTEGER, x INTEGER, y INTEGER, color INTEGER, timestamp TEXT)''')
    
    conn.commit()
    conn.close()

# --- 装饰器：仅管理员可见 ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403) # 禁止访问
        return f(*args, **kwargs)
    return decorated_function

# --- 核心业务逻辑 (复用之前的大部分) ---
def create_room_record(name, password, creator_name):
    conn = get_db_connection()
    while True:
        room_id = ''.join(random.choices(string.digits, k=6))
        if not conn.execute("SELECT 1 FROM rooms WHERE id = ?", (room_id,)).fetchone():
            break
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("INSERT INTO rooms (id, name, password, created_at, creator) VALUES (?, ?, ?, ?, ?)",
                 (room_id, name, password, now, creator_name))
    conn.commit()
    conn.close()
    return room_id

def create_new_game(room_id, custom_name=None):
    conn = get_db_connection()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    name = custom_name if custom_name else f"研讨记录 {now}"
    cursor = conn.execute("INSERT INTO games (start_time, name, room_id) VALUES (?, ?, ?)", (now, name, room_id))
    gid = cursor.lastrowid
    conn.commit()
    conn.close()
    return gid

# --- 路由：认证部分 ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            login_user(User(user['id'], user['username'], bool(user['is_admin'])))
            return redirect(url_for('portal'))
        else:
            flash('用户名或密码错误')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- 路由：管理后台 (你的核心需求) ---

@app.route('/admin_panel', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_panel():
    conn = get_db_connection()
    if request.method == 'POST':
        # 添加新用户
        new_user = request.form['username']
        new_pwd = request.form['password']
        if new_user and new_pwd:
            try:
                p_hash = generate_password_hash(new_pwd)
                conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (new_user, p_hash))
                conn.commit()
                flash(f"用户 {new_user} 创建成功")
            except sqlite3.IntegrityError:
                flash("用户名已存在")
    
    users = conn.execute("SELECT id, username, is_admin FROM users").fetchall()
    conn.close()
    return render_template('admin.html', users=users)

# --- 添加在 app.py 的 admin_panel 路由之后 ---

@app.route('/api/reset_password', methods=['POST'])
@login_required
@admin_required
def reset_password():
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')
    
    if not user_id or not new_password:
        flash("信息不完整")
        return redirect(url_for('admin_panel'))

    conn = get_db_connection()
    # 生成新哈希
    pw_hash = generate_password_hash(new_password)
    try:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, user_id))
        conn.commit()
        flash(f"ID:{user_id} 的密码已重置")
    except Exception as e:
        flash(f"修改失败: {str(e)}")
    finally:
        conn.close()
        
    return redirect(url_for('admin_panel'))

@app.route('/api/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        return "不能删除自己", 400
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel'))

# --- 路由：业务部分 (全部加 @login_required) ---

@app.route('/')
@login_required
def portal():
    return render_template('portal.html', user=current_user)

@app.route('/lobby')
@login_required
def lobby():
    conn = get_db_connection()
    rooms = conn.execute("SELECT * FROM rooms ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('lobby.html', rooms=rooms, user=current_user)

@app.route('/api/create_room', methods=['POST'])
@login_required
def api_create_room():
    data = request.json
    name = data.get('name')
    password = data.get('password')
    # 限制：只有登录用户能创建 (代码已由 login_required 保证)
    if not name or not password or len(password) != 6 or not password.isdigit():
        return jsonify({'error': '无效输入'}), 400
    room_id = create_room_record(name, password, current_user.username)
    return jsonify({'room_id': room_id})

@app.route('/room/<room_id>')
@login_required
def room_page(room_id):
    conn = get_db_connection()
    room = conn.execute("SELECT name FROM rooms WHERE id = ?", (room_id,)).fetchone()
    conn.close()
    if not room: return "房间不存在", 404
    return render_template('room.html', room_id=room_id, room_name=room['name'], user=current_user)

# --- 导入导出 (逻辑保持不变，加权限验证) ---
@app.route('/api/export_game/<int:game_id>')
@login_required
def export_game(game_id):
    # (保持之前的代码不变)
    conn = get_db_connection()
    game = conn.execute("SELECT * FROM games WHERE id = ?", (game_id,)).fetchone()
    moves = conn.execute("SELECT x, y, color, timestamp FROM moves WHERE game_id = ? ORDER BY id ASC", (game_id,)).fetchall()
    conn.close()
    if not game: return "Not found", 404
    data = {
        "version": "1.0",
        "game_meta": {"id": game['id'], "name": game['name'], "room_id": game['room_id'], "start_time": game['start_time']},
        "moves": [dict(m) for m in moves]
    }
    mem = io.BytesIO()
    mem.write(json.dumps(data, indent=2, ensure_ascii=False).encode('utf-8'))
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name=f"gobang_{game_id}.json", mimetype='application/json')

@app.route('/api/import_game', methods=['POST'])
@login_required
def import_game():
    # (保持之前的代码不变，略微省略)
    if 'file' not in request.files: return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    room_id = request.form.get('room_id')
    try:
        content = json.load(file)
        moves = content.get('moves', [])
        old_meta = content.get('game_meta', {})
        new_name = f"[导入] {old_meta.get('name', '未知')}"
        new_gid = create_new_game(room_id, new_name)
        conn = get_db_connection()
        for m in moves:
            conn.execute("INSERT INTO moves (game_id, x, y, color, timestamp) VALUES (?,?,?,?,?)",
                         (new_gid, m['x'], m['y'], m['color'], m.get('timestamp','')))
        conn.commit()
        conn.close()
        emit_update_room(room_id, force_game_id=new_gid)
        return jsonify({'success': True, 'game_id': new_gid})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/gobang/review')
@login_required
def gobang_review():
    """五子棋专属复盘播放器页面"""
    # 这里的 current_user 由 Flask-Login 自动提供
    return render_template('review_gobang.html', user=current_user)

# --- Socket 逻辑 (增加断线验证) ---

@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        disconnect() # 拒绝未登录的 WebSocket 连接

@socketio.on('join_room')
def handle_join_room(data):
    # 这里我们只验证房间密码，不需要再验证用户密码，因为连上来肯定是登录过的
    room_id = data.get('room_id')
    password = data.get('password')
    
    conn = get_db_connection()
    room = conn.execute("SELECT password FROM rooms WHERE id = ?", (room_id,)).fetchone()
    conn.close()
    
    if room and room['password'] == password:
        join_room(room_id)
        emit('auth_success', {'message': 'Authorized'})
        emit_update_room(room_id)
    else:
        emit('auth_fail', {'message': '房间密码错误'})

# (其他 Socket 事件 place_move, undo_move 等保持原样，无需修改，
#  因为 handle_connect 已经保证了只有登录用户才能触发这些事件)
#  ... (这里请直接复用上一版代码中的 socketio 事件函数，并在最后加上 emit_update_room 定义)

def get_current_game_id(room_id):
    conn = get_db_connection()
    game = conn.execute("SELECT id FROM games WHERE room_id = ? ORDER BY id DESC LIMIT 1", (room_id,)).fetchone()
    conn.close()
    return game['id'] if game else create_new_game(room_id)

def get_game_moves(game_id):
    conn = get_db_connection()
    rows = conn.execute("SELECT x, y, color FROM moves WHERE game_id = ? ORDER BY id ASC", (game_id,)).fetchall()
    conn.close()
    return [{'x': r['x'], 'y': r['y'], 'color': r['color']} for r in rows]

def get_room_games(room_id):
    conn = get_db_connection()
    games = conn.execute("SELECT id, name FROM games WHERE room_id = ? ORDER BY id DESC", (room_id,)).fetchall()
    conn.close()
    return [{'id': g['id'], 'name': g['name']} for g in games]

def emit_update_room(room_id, force_game_id=None):
    if force_game_id: current_id = force_game_id
    else: current_id = get_current_game_id(room_id)
    moves = get_game_moves(current_id)
    games = get_room_games(room_id)
    socketio.emit('update_board', {'moves': moves, 'game_id': current_id, 'games_list': games}, room=room_id)

# 将之前所有的 socketio 事件函数（place_move, undo_move, new_game, load_game, delete_game）
# 复制粘贴回来，保持逻辑不变即可。

# ... [此处插入原有的 socketio 事件代码] ...
@socketio.on('place_move')
def handle_move(data):
    # 稍微修改一下，记录日志可以使用 current_user.username
    room_id = data.get('room_id')
    game_id = data.get('game_id')
    conn = get_db_connection()
    # 校验略...
    # 插入逻辑保持不变
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # 可以在这里做一些防刷校验，比如判断是不是轮到该颜色下，这里暂且保持简单
    conn.execute("INSERT INTO moves (game_id, x, y, color, timestamp) VALUES (?, ?, ?, ?, ?)",
                    (game_id, data['x'], data['y'], data['color'], now))
    conn.commit()
    conn.close()
    emit_update_room(room_id, force_game_id=game_id)
    
@socketio.on('undo_move')
def handle_undo(data):
    room_id = data.get('room_id')
    game_id = data.get('game_id')
    conn = get_db_connection()
    row = conn.execute("SELECT id FROM moves WHERE game_id = ? ORDER BY id DESC LIMIT 1", (game_id,)).fetchone()
    if row:
        conn.execute("DELETE FROM moves WHERE id = ?", (row['id'],))
        conn.commit()
    conn.close()
    emit_update_room(room_id, force_game_id=game_id)

@socketio.on('new_game')
def handle_new_game(data):
    room_id = data.get('room_id')
    new_id = create_new_game(room_id)
    emit_update_room(room_id, force_game_id=new_id)

@socketio.on('load_game')
def handle_load_game(data):
    emit_update_room(data.get('room_id'), force_game_id=int(data['game_id']))

@socketio.on('delete_game')
def handle_delete(data):
    room_id = data.get('room_id')
    game_id = data.get('game_id')
    conn = get_db_connection()
    conn.execute("DELETE FROM moves WHERE game_id = ?", (game_id,))
    conn.execute("DELETE FROM games WHERE id = ?", (game_id,))
    conn.commit()
    conn.close()
    emit_update_room(room_id)


if __name__ == '__main__':
    init_and_migrate_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)