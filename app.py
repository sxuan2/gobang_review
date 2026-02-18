import numpy as np
import struct
import sqlite3
import datetime
import json
import random
import string
import io
from functools import wraps

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, abort
from flask_socketio import SocketIO, emit, join_room, disconnect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from ai import GomokuAI

# --- 配置 ---
SECRET_KEY = 'secret key'  # 上线前请改为复杂的随机字符串
DB_FILE = 'game.db'

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='eventlet')

ai_engine = GomokuAI()

# --- 登录组件初始化 ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # 未登录自动跳到这个路由

# --- 用户类 (配合 Flask-Login) ---
class User(UserMixin):
    def __init__(self, id, username, is_admin=False):
        self.id = id
        self.username = username
        self.is_admin = is_admin


# =========================
# 工具：强制类型转换（修复 bytes / numpy.int64 / str）
# =========================
def _to_int(v):
    if v is None:
        return 0
    if isinstance(v, (int, np.integer)):
        return int(v)
    if isinstance(v, str):
        return int(v.strip())
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        # 常见：sqlite 里意外写入了 little-endian 整数 blob
        if len(b) == 8:
            return struct.unpack("<q", b)[0]
        if len(b) == 4:
            return struct.unpack("<i", b)[0]
        # 兜底：当作 utf-8 文本
        try:
            return int(b.decode("utf-8").strip())
        except Exception:
            raise ValueError(f"cannot convert bytes to int: {b!r}")
    return int(v)


# --- 数据库操作 ---
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_and_migrate_db():
    conn = get_db_connection()
    c = conn.cursor()

    # 1. 用户表
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password_hash TEXT,
                  is_admin INTEGER DEFAULT 0)''')

    # 2. 默认管理员
    admin = c.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
    if not admin:
        print(">>> 初始化：创建默认管理员 admin / admin123")
        pw_hash = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                  ('admin', pw_hash))

    # 3. 房间表
    c.execute('''CREATE TABLE IF NOT EXISTS rooms
                 (id TEXT PRIMARY KEY, name TEXT, password TEXT, created_at TEXT, creator TEXT)''')

    # 4. 棋局表（兼容迁移）
    c.execute('''CREATE TABLE IF NOT EXISTS games
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, start_time TEXT, name TEXT)''')
    cursor = c.execute("PRAGMA table_info(games)")
    columns = [row['name'] for row in cursor.fetchall()]
    if 'room_id' not in columns:
        print(">>> 执行数据库迁移...")
        c.execute("ALTER TABLE games ADD COLUMN room_id TEXT")
        c.execute("UPDATE games SET room_id = 'default'")
        c.execute("INSERT OR IGNORE INTO rooms (id, name, password, created_at, creator) VALUES (?, ?, ?, ?, ?)",
                  ('default', "历史归档大厅", "123456", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "system"))
        conn.commit()

    # 5. 棋子表
    c.execute('''CREATE TABLE IF NOT EXISTS moves
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, game_id INTEGER, x INTEGER, y INTEGER, color INTEGER, timestamp TEXT)''')

    conn.commit()
    conn.close()


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (_to_int(user_id),)).fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'], bool(user['is_admin']))
    return None


# --- 装饰器：仅管理员可见 ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# =========================
# 核心业务逻辑
# =========================
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


def get_current_game_id(room_id):
    conn = get_db_connection()
    game = conn.execute("SELECT id FROM games WHERE room_id = ? ORDER BY id DESC LIMIT 1", (room_id,)).fetchone()
    conn.close()
    return _to_int(game['id']) if game else create_new_game(room_id)


def get_game_moves(game_id):
    """所有出口统一清洗成 Python int，避免 ArrayBuffer / numpy.int64 / bytes."""
    gid = _to_int(game_id)
    conn = get_db_connection()
    rows = conn.execute("SELECT x, y, color FROM moves WHERE game_id = ? ORDER BY id ASC", (gid,)).fetchall()
    conn.close()
    moves = []
    for r in rows:
        moves.append({
            'x': _to_int(r['x']),
            'y': _to_int(r['y']),
            'color': _to_int(r['color'])
        })
    return moves


def load_board_to_ai(game_id):
    """ai.py 已约定 board[y][x] 语义。"""
    ai_engine.reset()
    moves = get_game_moves(game_id)
    for m in moves:
        x = _to_int(m['x'])
        y = _to_int(m['y'])
        c = _to_int(m['color'])
        if 0 <= x < 15 and 0 <= y < 15:
            ai_engine.board[y][x] = c
    return moves


def get_room_games(room_id):
    conn = get_db_connection()
    games = conn.execute("SELECT id, name FROM games WHERE room_id = ? ORDER BY id DESC", (room_id,)).fetchall()
    conn.close()
    return [{'id': _to_int(g['id']), 'name': g['name']} for g in games]


def emit_update_room(room_id, force_game_id=None):
    current_id = _to_int(force_game_id) if force_game_id else _to_int(get_current_game_id(room_id))
    moves = get_game_moves(current_id)  # 已清洗
    games = get_room_games(room_id)

    socketio.emit(
        'update_board',
        {'moves': moves, 'game_id': int(current_id), 'games_list': games},
        room=room_id
    )


# =========================
# 路由：认证
# =========================
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


# =========================
# 路由：管理后台
# =========================
@app.route('/admin_panel', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_panel():
    conn = get_db_connection()

    if request.method == 'POST':
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
    pw_hash = generate_password_hash(new_password)
    try:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, _to_int(user_id)))
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
    conn.execute("DELETE FROM users WHERE id = ?", (_to_int(user_id),))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel'))


# =========================
# 路由：业务
# =========================
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
    data = request.json or {}
    name = data.get('name')
    password = data.get('password')
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
    if not room:
        return "房间不存在", 404
    return render_template('room.html', room_id=room_id, room_name=room['name'], user=current_user)


# --- 导入导出 ---
@app.route('/api/export_game/<int:game_id>')
@login_required
def export_game(game_id):
    conn = get_db_connection()
    game = conn.execute("SELECT * FROM games WHERE id = ?", (_to_int(game_id),)).fetchone()
    moves = conn.execute(
        "SELECT x, y, color, timestamp FROM moves WHERE game_id = ? ORDER BY id ASC",
        (_to_int(game_id),)
    ).fetchall()
    conn.close()

    if not game:
        return "Not found", 404

    data = {
        "version": "1.0",
        "game_meta": {
            "id": _to_int(game['id']),
            "name": game['name'],
            "room_id": game['room_id'],
            "start_time": game['start_time']
        },
        "moves": [{
            "x": _to_int(m["x"]),
            "y": _to_int(m["y"]),
            "color": _to_int(m["color"]),
            "timestamp": m["timestamp"]
        } for m in moves]
    }

    mem = io.BytesIO()
    mem.write(json.dumps(data, indent=2, ensure_ascii=False).encode('utf-8'))
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name=f"gobang_{game_id}.json", mimetype='application/json')


@app.route('/api/import_game', methods=['POST'])
@login_required
def import_game():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400

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
            conn.execute(
                "INSERT INTO moves (game_id, x, y, color, timestamp) VALUES (?,?,?,?,?)",
                (_to_int(new_gid), _to_int(m['x']), _to_int(m['y']), _to_int(m['color']), m.get('timestamp', ''))
            )
        conn.commit()
        conn.close()

        emit_update_room(room_id, force_game_id=new_gid)
        return jsonify({'success': True, 'game_id': int(new_gid)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/gobang/review')
@login_required
def gobang_review():
    return render_template('review_gobang.html', user=current_user)


# =========================
# AI 接口
# =========================
@app.route('/api/ai/move', methods=['POST'])
@login_required
def ai_move():
    data = request.json or {}
    room_id = data.get('room_id')
    game_id = data.get('game_id')
    time_limit = float(data.get('time_limit', 10))
    max_candidates = int(data.get('max_candidates', 15))

    if not game_id:
        return jsonify({'status': 'error', 'message': '缺少 game_id'}), 400

    gid = _to_int(game_id)
    moves = load_board_to_ai(gid)
    current_color = 1 if len(moves) % 2 == 0 else 2

    try:
        (x, y), score = ai_engine.get_best_move(current_color, time_limit=time_limit, max_candidates=max_candidates)
        x, y, score = int(x), int(y), int(score)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

    conn = get_db_connection()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO moves (game_id, x, y, color, timestamp) VALUES (?, ?, ?, ?, ?)",
        (gid, x, y, int(current_color), now)
    )
    conn.commit()
    conn.close()

    emit_update_room(room_id, force_game_id=gid)

    return jsonify({'status': 'success', 'x': x, 'y': y, 'score': score})


@app.route('/api/ai/hint', methods=['POST'])
@login_required
def ai_hint():
    data = request.json or {}
    game_id = data.get('game_id')

    if not game_id:
        return jsonify({'status': 'error'}), 400

    gid = _to_int(game_id)
    moves = load_board_to_ai(gid)
    current_color = 1 if len(moves) % 2 == 0 else 2

    try:
        (x, y), score = ai_engine.get_best_move(current_color, time_limit=5, max_candidates=10)
        x, y, score = int(x), int(y), int(score)
    except Exception:
        return jsonify({'status': 'error'})

    win_rate = min(99, max(1, int(abs(score) / 10000)))
    return jsonify({'status': 'success', 'x': x, 'y': y, 'win_rate': win_rate})


# =========================
# Socket 逻辑
# =========================
@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        disconnect()


@socketio.on('join_room')
def handle_join_room(data):
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


@socketio.on('place_move')
def handle_move(data):
    room_id = data.get('room_id')
    game_id = _to_int(data.get('game_id'))

    x = _to_int(data.get('x'))
    y = _to_int(data.get('y'))
    color = _to_int(data.get('color'))

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO moves (game_id, x, y, color, timestamp) VALUES (?, ?, ?, ?, ?)",
        (game_id, x, y, color, now)
    )
    conn.commit()
    conn.close()

    emit_update_room(room_id, force_game_id=game_id)


@socketio.on('undo_move')
def handle_undo(data):
    room_id = data.get('room_id')
    game_id = _to_int(data.get('game_id'))

    conn = get_db_connection()
    row = conn.execute(
        "SELECT id FROM moves WHERE game_id = ? ORDER BY id DESC LIMIT 1",
        (game_id,)
    ).fetchone()

    if row:
        conn.execute("DELETE FROM moves WHERE id = ?", (_to_int(row['id']),))
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
    room_id = data.get('room_id')
    game_id = _to_int(data.get('game_id'))
    emit_update_room(room_id, force_game_id=game_id)


@socketio.on('delete_game')
def handle_delete(data):
    room_id = data.get('room_id')
    game_id = _to_int(data.get('game_id'))

    conn = get_db_connection()
    conn.execute("DELETE FROM moves WHERE game_id = ?", (game_id,))
    conn.execute("DELETE FROM games WHERE id = ?", (game_id,))
    conn.commit()
    conn.close()

    emit_update_room(room_id)


if __name__ == '__main__':
    init_and_migrate_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
