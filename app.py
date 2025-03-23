import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'  # 실제 운영 시 안전하게 관리
DATABASE = 'market.db'
socketio = SocketIO(app)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """테이블 생성 및 필요한 컬럼 추가."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 기존 테이블 생성(존재하지 않을 경우)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)

        # user 테이블 ALTER
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN is_admin INTEGER DEFAULT 0")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN balance REAL DEFAULT 0")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN blocked INTEGER DEFAULT 0")
        except:
            pass

        # product 테이블 ALTER
        try:
            cursor.execute("ALTER TABLE product ADD COLUMN blocked INTEGER DEFAULT 0")
        except:
            pass

        db.commit()

def create_admin_user():
    """
    username='admin', password='admin' 인 관리자 계정이 없으면 생성.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM user WHERE username = 'admin'")
    existing = cursor.fetchone()
    if existing is None:
        admin_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO user (id, username, password, bio, is_admin, balance, blocked)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (admin_id, 'admin', 'admin', '관리자 계정입니다.', 1, 0, 0))
        db.commit()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        # 중복 유저 검사
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO user (id, username, password, is_admin, balance, blocked) VALUES (?, ?, ?, 0, 0, 0)",
            (user_id, username, password)
        )
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()

        if user:
            # 차단된 유저인지 확인
            if user['blocked']:
                flash('해당 계정은 차단되었습니다.')
                return redirect(url_for('login'))
            # 로그인
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# -----------------
#  DASHBOARD
# -----------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 차단되지 않은 상품만 조회
    cursor.execute("SELECT * FROM product WHERE blocked = 0")
    all_products = cursor.fetchall()

    return render_template('dashboard.html', products=all_products, user=current_user)

# -----------------
#  PRODUCT
# -----------------
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT blocked FROM user WHERE id = ?", (session['user_id'],))
    blocked_flag = cursor.fetchone()['blocked']
    if blocked_flag:
        flash('차단된 사용자는 상품을 등록할 수 없습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']

        product_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO product (id, title, description, price, seller_id, blocked)
            VALUES (?, ?, ?, ?, ?, 0)
        """, (product_id, title, description, price, session['user_id']))
        db.commit()

        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html')

@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    if product['blocked']:
        flash('해당 상품은 접근할 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()

    return render_template('view_product.html', product=product, seller=seller)

# -----------------
#  SEARCH
# -----------------
@app.route('/search', methods=['GET'])
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    query = request.args.get('q', '').strip()
    db = get_db()
    cursor = db.cursor()

    if not query:
        results = []
    else:
        like_q = f"%{query}%"
        cursor.execute("""
            SELECT * FROM product
            WHERE blocked = 0
              AND (title LIKE ? OR description LIKE ?)
        """, (like_q, like_q))
        results = cursor.fetchall()

    return render_template('search.html', query=query, results=results)

# -----------------
#  REPORT
# -----------------
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']

        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO report (id, reporter_id, target_id, reason)
            VALUES (?, ?, ?, ?)
        """, (report_id, session['user_id'], target_id, reason))
        db.commit()

        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')

# -----------------
#  PROFILE
# -----------------
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# -----------------
#  BALANCE / TRANSFER
# -----------------
@app.route('/charge', methods=['GET', 'POST'])
def charge():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    if request.method == 'POST':
        amount = float(request.form['amount'])
        if amount <= 0:
            flash('충전 금액이 유효하지 않습니다.')
            return redirect(url_for('charge'))

        new_balance = current_user['balance'] + amount
        cursor.execute("UPDATE user SET balance = ? WHERE id = ?", (new_balance, session['user_id']))
        db.commit()

        flash(f'{amount} 만큼 충전되었습니다. 현재 잔액: {new_balance}')
        return redirect(url_for('profile'))

    return render_template('charge.html', user=current_user)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    if request.method == 'POST':
        receiver_username = request.form['receiver_username']
        amount = float(request.form['amount'])

        if amount <= 0:
            flash('송금 금액이 유효하지 않습니다.')
            return redirect(url_for('transfer'))
        if current_user['balance'] < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer'))

        cursor.execute("SELECT * FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()
        if not receiver:
            flash('존재하지 않는 사용자입니다.')
            return redirect(url_for('transfer'))

        # 송금 처리
        new_sender_balance = current_user['balance'] - amount
        new_receiver_balance = receiver['balance'] + amount
        cursor.execute("UPDATE user SET balance = ? WHERE id = ?", (new_sender_balance, current_user['id']))
        cursor.execute("UPDATE user SET balance = ? WHERE id = ?", (new_receiver_balance, receiver['id']))
        db.commit()

        flash(f'{receiver_username}님에게 {amount} 송금 완료.')
        return redirect(url_for('profile'))

    return render_template('transfer.html', user=current_user)

# -----------------
#  ADMIN
# -----------------
def is_admin():
    if 'user_id' not in session:
        return False
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    row = cursor.fetchone()
    return (row and row['is_admin'] == 1)

@app.route('/admin')
def admin_dashboard():
    if not is_admin():
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('index'))
    return render_template('admin_dashboard.html')

@app.route('/admin/users')
def admin_users():
    if not is_admin():
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()
    return render_template('admin_users.html', users=users)

@app.route('/admin/products')
def admin_products():
    if not is_admin():
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()
    return render_template('admin_products.html', products=products)

@app.route('/admin/block_user/<user_id>', methods=['POST'])
def block_user(user_id):
    if not is_admin():
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT blocked FROM user WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin_users'))

    new_value = 0 if row['blocked'] else 1
    cursor.execute("UPDATE user SET blocked = ? WHERE id = ?", (new_value, user_id))
    db.commit()

    flash('사용자 상태를 변경했습니다.')
    return redirect(url_for('admin_users'))

@app.route('/admin/block_product/<product_id>', methods=['POST'])
def block_product(product_id):
    if not is_admin():
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT blocked FROM product WHERE id = ?", (product_id,))
    row = cursor.fetchone()
    if not row:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('admin_products'))

    new_value = 0 if row['blocked'] else 1
    cursor.execute("UPDATE product SET blocked = ? WHERE id = ?", (new_value, product_id))
    db.commit()

    flash('상품 상태를 변경했습니다.')
    return redirect(url_for('admin_products'))

# -----------------
#  REALTIME CHAT
# -----------------
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

# -----------------
#  APP RUN
# -----------------
if __name__ == '__main__':
    with app.app_context():
        init_db()
        create_admin_user()
    socketio.run(app, debug=True)
