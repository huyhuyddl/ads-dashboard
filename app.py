from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import sqlite3, hashlib, os, json
from datetime import datetime, timedelta
import random
import urllib.request
import urllib.parse
from dotenv import load_dotenv

load_dotenv()

# ── ENV ───────────────────────────────────────────────────────────────────────
FB_ACCESS_TOKEN    = os.getenv("FB_ACCESS_TOKEN")
FB_AD_ACCOUNT_ID   = os.getenv("FB_AD_ACCOUNT_ID")
FB_APP_ID          = os.getenv("FB_APP_ID")          # Dùng để refresh token
FB_APP_SECRET      = os.getenv("FB_APP_SECRET")      # Dùng để refresh token

app = Flask(__name__)
app.secret_key = 'ads-dashboard-secret-key-2024'
DB = 'instance/dashboard.db'

# ── DB SETUP ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs('instance', exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now')),
            last_login TEXT
        );
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            detail TEXT,
            ip TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS budgets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            channel TEXT,
            monthly_limit REAL,
            month TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    ''')

    def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

    users = [
        ('admin',        'admin@ads.com',      hash_pw('admin123'), 'admin'),
        ('nguyen_van_a', 'vana@company.com',   hash_pw('user123'),  'user'),
        ('tran_thi_b',   'thib@agency.com',    hash_pw('user123'),  'user'),
        ('le_van_c',     'vanc@shop.com',       hash_pw('user123'),  'user'),
    ]
    for u in users:
        try:
            c.execute('INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)', u)
        except: pass

    months = datetime.now().strftime('%Y-%m')
    budgets = [
        # nguyen_van_a (id=2) — có ngân sách → có dữ liệu ads
        (2, 'facebook', 50000000, months),
        (2, 'google',   50000000, months),
        (2, 'tiktok',   17000000, months),
        # tran_thi_b (id=3) — có ngân sách
        (3, 'facebook', 30000000, months),
        (3, 'google',   20000000, months),
        # le_van_c (id=4) — KHÔNG có ngân sách → sẽ hiện popup no_ads
    ]
    for b in budgets:
        try:
            c.execute('INSERT INTO budgets (user_id,channel,monthly_limit,month) VALUES (?,?,?,?)', b)
        except: pass

    conn.commit()
    conn.close()

# ── AUTH ──────────────────────────────────────────────────────────────────────
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def log_activity(user_id, action, detail=''):
    conn = get_db()
    conn.execute(
        'INSERT INTO activity_logs (user_id,action,detail,ip) VALUES (?,?,?,?)',
        (user_id, action, detail, request.remote_addr)
    )
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        if session.get('role') != 'admin':
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated

# ── FACEBOOK TOKEN MANAGEMENT ─────────────────────────────────────────────────
_fb_token_cache = {
    'token': None,
    'expires_at': None,
}

def get_valid_fb_token():
    """
    Trả về token hợp lệ. Nếu token sắp hết hạn (<7 ngày), tự động refresh.
    Yêu cầu FB_APP_ID + FB_APP_SECRET trong .env để refresh.
    """
    global _fb_token_cache

    # Dùng token từ env làm gốc nếu cache chưa có
    current_token = _fb_token_cache['token'] or FB_ACCESS_TOKEN
    if not current_token:
        return None

    expires_at = _fb_token_cache.get('expires_at')
    needs_refresh = (
        expires_at is None or
        datetime.now() > expires_at - timedelta(days=7)
    )

    if needs_refresh and FB_APP_ID and FB_APP_SECRET:
        refreshed = _refresh_fb_token(current_token)
        if refreshed:
            current_token = refreshed['token']
            _fb_token_cache['token'] = refreshed['token']
            _fb_token_cache['expires_at'] = refreshed['expires_at']
            print(f"[FB Token] Đã refresh — hết hạn: {refreshed['expires_at']}")
        else:
            print("[FB Token] Không thể refresh, dùng token cũ")

    return current_token

def _refresh_fb_token(short_token):
    """
    Đổi short-lived token → long-lived token (60 ngày) qua FB endpoint.
    Trả về dict {'token': ..., 'expires_at': datetime} hoặc None nếu lỗi.
    """
    if not FB_APP_ID or not FB_APP_SECRET:
        return None

    params = urllib.parse.urlencode({
        'grant_type':        'fb_exchange_token',
        'client_id':         FB_APP_ID,
        'client_secret':     FB_APP_SECRET,
        'fb_exchange_token': short_token,
    })
    url = f'https://graph.facebook.com/v18.0/oauth/access_token?{params}'

    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        new_token   = data.get('access_token')
        expires_in  = data.get('expires_in', 5184000)  # default 60 ngày
        expires_at  = datetime.now() + timedelta(seconds=int(expires_in))
        return {'token': new_token, 'expires_at': expires_at}
    except Exception as e:
        print(f'[FB Token Refresh Error] {e}')
        return None

def check_fb_token_status():
    """Kiểm tra trạng thái token — trả về dict để hiện trong admin."""
    token = get_valid_fb_token()
    if not token:
        return {'valid': False, 'reason': 'Chưa cấu hình token'}

    url = f'https://graph.facebook.com/v18.0/me?access_token={token}'
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        if 'error' in data:
            return {'valid': False, 'reason': data['error'].get('message', 'Token lỗi')}
        expires_at = _fb_token_cache.get('expires_at')
        days_left  = (expires_at - datetime.now()).days if expires_at else '?'
        return {'valid': True, 'name': data.get('name', ''), 'days_left': days_left}
    except Exception as e:
        return {'valid': False, 'reason': str(e)}

# ── FACEBOOK REAL API ─────────────────────────────────────────────────────────
def fetch_fb_data(days=7):
    """Gọi Facebook Marketing API thật, trả về None nếu lỗi/chưa có token."""
    token = get_valid_fb_token()
    if not token or not FB_AD_ACCOUNT_ID:
        return None

    date_end   = datetime.now().strftime('%Y-%m-%d')
    date_start = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
    fields     = 'spend,impressions,clicks,ctr,cpc,actions,action_values'

    url = (
        f'https://graph.facebook.com/v18.0/{FB_AD_ACCOUNT_ID}/insights'
        f'?fields={fields}'
        f'&time_range={{"since":"{date_start}","until":"{date_end}"}}'
        f'&time_increment=1'
        f'&access_token={token}'
    )

    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            result = json.loads(resp.read().decode())

        if 'error' in result:
            err = result['error']
            print(f"[FB API Error] code={err.get('code')} msg={err.get('message')}")
            # Nếu token hết hạn → thử refresh ngay
            if err.get('code') in (190, 102):
                print("[FB API] Token hết hạn, thử refresh...")
                refreshed = _refresh_fb_token(token)
                if refreshed:
                    _fb_token_cache['token']      = refreshed['token']
                    _fb_token_cache['expires_at'] = refreshed['expires_at']
                    return fetch_fb_data(days)  # Thử lại sau khi refresh
            return None

        data = result.get('data', [])
        if not data:
            return None

        labels, spend_list, clicks_list, impressions_list = [], [], [], []
        total_spend = 0
        total_revenue = 0

        for day in data:
            labels.append(day.get('date_start', '')[-5:].replace('-', '/'))
            sp = float(day.get('spend', 0)) * 23000  # USD → VND
            spend_list.append(round(sp / 1000000, 2))
            total_spend   += sp
            clicks_list.append(int(day.get('clicks', 0)))
            impressions_list.append(int(day.get('impressions', 0)))
            for av in day.get('action_values', []):
                if av['action_type'] == 'purchase':
                    total_revenue += float(av['value']) * 23000

        roas = round(total_revenue / total_spend, 2) if total_spend else 0
        roi  = round((total_revenue - total_spend) / total_spend * 100, 1) if total_spend else 0
        total_clicks = sum(clicks_list)
        cpa  = round(total_spend / total_clicks) if total_clicks else 0

        return {
            'source': 'facebook_api',
            'labels': labels,
            'spend_series': {'facebook': spend_list, 'google': [], 'tiktok': []},
            'total_spend':   round(total_spend),
            'total_revenue': round(total_revenue),
            'roas': roas, 'roi': roi, 'cpa': cpa,
            'channel_stats': {
                'facebook': {
                    'spend':       round(total_spend),
                    'roas':        roas,
                    'clicks':      total_clicks,
                    'impressions': sum(impressions_list),
                    'ctr':         round(sum(clicks_list) / max(sum(impressions_list), 1) * 100, 2),
                },
                'google':  {'spend': 0, 'roas': 0, 'clicks': 0, 'impressions': 0, 'ctr': 0},
                'tiktok':  {'spend': 0, 'roas': 0, 'clicks': 0, 'impressions': 0, 'ctr': 0},
            }
        }
    except Exception as e:
        print(f'[FB API Error] {e}')
        return None

# ── MOCK DATA ─────────────────────────────────────────────────────────────────
def generate_mock_data(user_id, days=7):
    random.seed(user_id * 13)
    channels = {
        'facebook': {'base_spend': 6200000, 'roas_base': 3.1},
        'google':   {'base_spend': 4500000, 'roas_base': 4.2},
        'tiktok':   {'base_spend': 1800000, 'roas_base': 3.8},
    }
    labels = []
    spend_series = {ch: [] for ch in channels}
    for i in range(days):
        d = datetime.now() - timedelta(days=days - 1 - i)
        labels.append(d.strftime('%d/%m'))
        for ch, cfg in channels.items():
            v = cfg['base_spend'] * random.uniform(0.7, 1.3)
            spend_series[ch].append(round(v / 1000000, 2))

    total_spend   = sum(sum(v) for v in spend_series.values()) * 1000000
    total_revenue = total_spend * random.uniform(3.0, 4.2)
    roas = round(total_revenue / total_spend, 2)
    roi  = round((total_revenue - total_spend) / total_spend * 100, 1)
    cpa  = round(total_spend / random.randint(400, 800))

    channel_stats = {}
    for ch, cfg in channels.items():
        sp = sum(spend_series[ch]) * 1000000
        channel_stats[ch] = {
            'spend':       round(sp),
            'roas':        round(cfg['roas_base'] * random.uniform(0.85, 1.15), 2),
            'clicks':      random.randint(1200, 8000),
            'impressions': random.randint(80000, 500000),
            'ctr':         round(random.uniform(1.2, 4.5), 2),
        }
    return {
        'source': 'mock',
        'labels': labels,
        'spend_series': spend_series,
        'total_spend':   round(total_spend),
        'total_revenue': round(total_revenue),
        'roas': roas, 'roi': roi, 'cpa': cpa,
        'channel_stats': channel_stats,
    }

def user_has_ads_data(user_id):
    """
    Kiểm tra xem user có dữ liệu ads thực không.
    Hiện tại dựa trên việc có ngân sách tháng hay không.
    Bạn có thể mở rộng: kiểm tra bảng ad_accounts, v.v.
    """
    conn = get_db()
    count = conn.execute(
        'SELECT COUNT(*) as c FROM budgets WHERE user_id=?', (user_id,)
    ).fetchone()['c']
    conn.close()
    return count > 0

# ── PAGES ─────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_page'))
        return redirect(url_for('dashboard_page'))
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard_page():
    return render_template('dashboard.html',
        username=session['username'], role=session['role'])

@app.route('/admin')
@login_required
def admin_page():
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard_page'))
    return render_template('admin.html', username=session['username'])

# ── API: AUTH ─────────────────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE username=? AND password=? AND is_active=1',
        (data['username'], hash_pw(data['password']))
    ).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'Sai tài khoản hoặc mật khẩu'}), 401

    session.update({'user_id': user['id'], 'username': user['username'], 'role': user['role']})
    conn2 = get_db()
    conn2.execute('UPDATE users SET last_login=? WHERE id=?',
                  (datetime.now().isoformat(), user['id']))
    conn2.commit()
    conn2.close()
    log_activity(user['id'], 'LOGIN', 'Đăng nhập thành công')
    return jsonify({'role': user['role'], 'username': user['username']})

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    log_activity(session['user_id'], 'LOGOUT', 'Đăng xuất')
    session.clear()
    return jsonify({'ok': True})

# ── API: DASHBOARD DATA ───────────────────────────────────────────────────────
@app.route('/api/dashboard-data')
@login_required
def api_dashboard_data():
    days       = int(request.args.get('days', 7))
    force_mock = request.args.get('force_mock', '0') == '1'
    user_id    = session['user_id']

    # Kiểm tra user có dữ liệu ads không (trừ admin)
    if session.get('role') != 'admin' and not force_mock:
        if not user_has_ads_data(user_id):
            # Trả flag để frontend hiện popup
            return jsonify({'no_ads_data': True})

    # Ưu tiên FB API thật → fallback mock
    if force_mock:
        data = generate_mock_data(user_id, days)
    else:
        data = fetch_fb_data(days)
        if data is None:
            data = generate_mock_data(user_id, days)

    # Gắn ngân sách
    conn = get_db()
    budgets = conn.execute(
        'SELECT channel, monthly_limit FROM budgets WHERE user_id=?', (user_id,)
    ).fetchall()
    conn.close()
    data['budgets'] = {b['channel']: b['monthly_limit'] for b in budgets}

    log_activity(user_id, 'VIEW_DASHBOARD',
                 f'Xem dashboard {days} ngày [{data["source"]}]{"[MOCK]" if force_mock else ""}')
    return jsonify(data)

# ── API: ADMIN — PREVIEW DASHBOARD CỦA USER ──────────────────────────────────
@app.route('/api/admin/preview-dashboard')
@admin_required
def api_admin_preview_dashboard():
    """Admin xem dashboard của một user bất kỳ."""
    uid  = request.args.get('user_id', type=int)
    days = int(request.args.get('days', 7))
    if not uid:
        return jsonify({'error': 'Missing user_id'}), 400

    # Luôn dùng mock cho preview (tránh gọi FB API với user_id khác)
    data = generate_mock_data(uid, days)

    conn = get_db()
    budgets = conn.execute(
        'SELECT channel, monthly_limit FROM budgets WHERE user_id=?', (uid,)
    ).fetchall()
    conn.close()
    data['budgets'] = {b['channel']: b['monthly_limit'] for b in budgets}
    data['source']  = 'mock_preview'

    log_activity(session['user_id'], 'VIEW_DASHBOARD',
                 f'Admin xem preview dashboard của user #{uid}')
    return jsonify(data)

# ── API: ADMIN — FB TOKEN STATUS ──────────────────────────────────────────────
@app.route('/api/admin/fb-token-status')
@admin_required
def api_fb_token_status():
    """Kiểm tra và tự refresh token nếu cần."""
    status = check_fb_token_status()
    return jsonify(status)

@app.route('/api/admin/fb-token-refresh', methods=['POST'])
@admin_required
def api_fb_token_refresh():
    """Force refresh FB token ngay lập tức."""
    token = _fb_token_cache.get('token') or FB_ACCESS_TOKEN
    if not token:
        return jsonify({'ok': False, 'error': 'Chưa có token để refresh'}), 400

    result = _refresh_fb_token(token)
    if result:
        _fb_token_cache['token']      = result['token']
        _fb_token_cache['expires_at'] = result['expires_at']
        log_activity(session['user_id'], 'FB_TOKEN_REFRESH', 'Refresh FB token thành công')
        return jsonify({
            'ok': True,
            'expires_at': result['expires_at'].isoformat(),
            'days_left':  (result['expires_at'] - datetime.now()).days
        })
    return jsonify({'ok': False, 'error': 'Refresh thất bại — kiểm tra FB_APP_ID và FB_APP_SECRET'}), 400

# ── API: ADMIN — USERS / LOGS / STATS ────────────────────────────────────────
@app.route('/api/admin/users')
@admin_required
def api_admin_users():
    conn  = get_db()
    users = conn.execute(
        'SELECT id, username, email, role, is_active, created_at, last_login FROM users ORDER BY id'
    ).fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/api/admin/users/<int:uid>/toggle', methods=['POST'])
@admin_required
def api_toggle_user(uid):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
    new_status = 0 if user['is_active'] else 1
    conn.execute('UPDATE users SET is_active=? WHERE id=?', (new_status, uid))
    conn.commit()
    conn.close()
    action = 'Mở khóa' if new_status else 'Khóa'
    log_activity(session['user_id'], 'TOGGLE_USER', f'{action} user {user["username"]}')
    return jsonify({'is_active': new_status})

@app.route('/api/admin/users', methods=['POST'])
@admin_required
def api_create_user():
    data = request.json
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)',
            (data['username'], data['email'], hash_pw(data['password']), data.get('role', 'user'))
        )
        conn.commit()
        log_activity(session['user_id'], 'CREATE_USER', f'Tạo user {data["username"]}')
        return jsonify({'ok': True})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username hoặc email đã tồn tại'}), 400
    finally:
        conn.close()

@app.route('/api/admin/users/<int:uid>/role', methods=['POST'])
@admin_required
def api_change_role(uid):
    data = request.json
    role = data.get('role')
    if role not in ('admin', 'user'):
        return jsonify({'error': 'Invalid role'}), 400
    conn = get_db()
    conn.execute('UPDATE users SET role=? WHERE id=?', (role, uid))
    conn.commit()
    conn.close()
    log_activity(session['user_id'], 'CHANGE_ROLE', f'Đổi role user #{uid} → {role}')
    return jsonify({'ok': True})

@app.route('/api/admin/logs')
@admin_required
def api_admin_logs():
    uid  = request.args.get('user_id')
    conn = get_db()
    if uid:
        logs = conn.execute(
            '''SELECT l.*, u.username FROM activity_logs l
               JOIN users u ON l.user_id=u.id
               WHERE l.user_id=? ORDER BY l.created_at DESC LIMIT 100''', (uid,)
        ).fetchall()
    else:
        logs = conn.execute(
            '''SELECT l.*, u.username FROM activity_logs l
               JOIN users u ON l.user_id=u.id
               ORDER BY l.created_at DESC LIMIT 200'''
        ).fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs])

@app.route('/api/admin/stats')
@admin_required
def api_admin_stats():
    conn         = get_db()
    total        = conn.execute('SELECT COUNT(*) as c FROM users WHERE role="user"').fetchone()['c']
    active       = conn.execute('SELECT COUNT(*) as c FROM users WHERE role="user" AND is_active=1').fetchone()['c']
    today_logins = conn.execute(
        'SELECT COUNT(*) as c FROM activity_logs WHERE action="LOGIN" AND date(created_at)=date("now")'
    ).fetchone()['c']
    conn.close()
    total_spend = sum(generate_mock_data(i, 30)['total_spend'] for i in range(2, 5))
    return jsonify({
        'total_users':   total,
        'active_users':  active,
        'today_logins':  today_logins,
        'total_spend':   total_spend,
    })

# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)