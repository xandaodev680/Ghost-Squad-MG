from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'chave_secreta_mude_isso_2026'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['BIND_UPLOAD_FOLDER'] = 'uploads/binds'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['BIND_UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE,
                  password TEXT NOT NULL,
                  profile_photo TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS binds
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  titulo TEXT NOT NULL,
                  codigo TEXT NOT NULL,
                  categoria TEXT,
                  foto TEXT,
                  data DATETIME DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS friendships
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  from_user_id INTEGER NOT NULL,
                  to_user_id INTEGER NOT NULL,
                  status TEXT DEFAULT 'pending',  -- pending, accepted, rejected
                  data DATETIME DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(from_user_id) REFERENCES users(id),
                  FOREIGN KEY(to_user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

init_db()

@app.context_processor
def inject_current_year():
    return dict(current_year=datetime.now().year)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/uploads/binds/<path:filename>')
def uploaded_bind_file(filename):
    return send_from_directory(app.config['BIND_UPLOAD_FOLDER'], filename)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/armas')
def armas():
    return render_template('armas.html')

@app.route('/binds', methods=['GET', 'POST'])
def binds():
    search_query = request.form.get('search', '') if request.method == 'POST' else ''
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if search_query:
        c.execute('''SELECT binds.id, binds.titulo, binds.codigo, binds.foto, binds.data, users.username, binds.categoria
                     FROM binds JOIN users ON binds.user_id = users.id
                     WHERE binds.titulo LIKE ? OR binds.codigo LIKE ? OR binds.categoria LIKE ?
                     ORDER BY binds.data DESC''', (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))
    else:
        c.execute('''SELECT binds.id, binds.titulo, binds.codigo, binds.foto, binds.data, users.username, binds.categoria
                     FROM binds JOIN users ON binds.user_id = users.id
                     ORDER BY binds.data DESC''')
    binds_list = c.fetchall()
    conn.close()
    return render_template('binds.html', binds_list=binds_list, search_query=search_query)

@app.route('/delete_bind/<int:bind_id>', methods=['POST'])
def delete_bind(bind_id):
    if 'user_id' not in session:
        flash('Você precisa estar logado.', 'danger')
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT user_id FROM binds WHERE id = ?", (bind_id,))
    bind = c.fetchone()
    if bind and bind[0] == session['user_id']:
        c.execute("DELETE FROM binds WHERE id = ?", (bind_id,))
        conn.commit()
        flash('Bind deletada com sucesso!', 'success')
    else:
        flash('Você não pode deletar essa bind.', 'danger')
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/post_bind', methods=['GET', 'POST'])
def post_bind():
    if 'user_id' not in session:
        flash('Você precisa estar logado para postar binds.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        titulo = request.form.get('titulo')
        codigo = request.form.get('codigo')
        categoria = request.form.get('categoria')  # .get() evita erro se não vier
        foto = None
        
        if not titulo or not codigo or not categoria:
            flash('Preencha todos os campos obrigatórios (título, código e categoria).', 'danger')
            return redirect(url_for('post_bind'))
        
        if 'foto' in request.files:
            file = request.files['foto']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['BIND_UPLOAD_FOLDER'], filename))
                foto = filename
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO binds (user_id, titulo, codigo, categoria, foto) VALUES (?, ?, ?, ?, ?)",
                  (session['user_id'], titulo, codigo, categoria, foto))
        conn.commit()
        conn.close()
        flash('Bind postada com sucesso!', 'success')
        return redirect(url_for('binds'))
    
    # GET: só mostra o form vazio
    return render_template('post_bind.html')

@app.route('/search_users', methods=['GET', 'POST'])
def search_users():
    search_query = request.form.get('search', '') if request.method == 'POST' else ''
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if search_query:
        c.execute("SELECT id, username, profile_photo FROM users WHERE username LIKE ? AND id != ?",
                  (f'%{search_query}%', session.get('user_id', 0)))
    else:
        c.execute("SELECT id, username, profile_photo FROM users WHERE id != ?", (session.get('user_id', 0),))
    users = c.fetchall()
    conn.close()
    return render_template('search_users.html', users=users, search_query=search_query)

@app.route('/send_friend_request/<int:to_user_id>', methods=['POST'])
def send_friend_request(to_user_id):
    if 'user_id' not in session:
        flash('Você precisa estar logado.', 'danger')
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM friendships WHERE (from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?)",
              (session['user_id'], to_user_id, to_user_id, session['user_id']))
    if c.fetchone():
        flash('Pedido de amizade já existe ou amizade aceita.', 'danger')
    else:
        c.execute("INSERT INTO friendships (from_user_id, to_user_id) VALUES (?, ?)",
                  (session['user_id'], to_user_id))
        conn.commit()
        flash('Pedido de amizade enviado!', 'success')
    conn.close()
    return redirect(url_for('search_users'))

@app.route('/accept_friend_request/<int:from_user_id>', methods=['POST'])
def accept_friend_request(from_user_id):
    if 'user_id' not in session:
        flash('Você precisa estar logado.', 'danger')
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("UPDATE friendships SET status = 'accepted' WHERE from_user_id = ? AND to_user_id = ? AND status = 'pending'",
              (from_user_id, session['user_id']))
    conn.commit()
    flash('Amizade aceita!', 'success')
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/reject_friend_request/<int:from_user_id>', methods=['POST'])
def reject_friend_request(from_user_id):
    if 'user_id' not in session:
        flash('Você precisa estar logado.', 'danger')
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("UPDATE friendships SET status = 'rejected' WHERE from_user_id = ? AND to_user_id = ? AND status = 'pending'",
              (from_user_id, session['user_id']))
    conn.commit()
    flash('Pedido de amizade rejeitado.', 'info')
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/ranker')
def ranker():
    rankings = [
        {'posicao': 1, 'usuario': 'xandao gamer - 🥇', 'pontos': 1500, 'rank': 'Global Elite'},
        {'posicao': 2, 'usuario': 'xandao gamer - 🥈', 'pontos': 1400, 'rank': 'Supreme'},
        {'posicao': 3, 'usuario': 'xandao gamer - 🥉', 'pontos': 1200, 'rank': 'LEM'},
    ]
    return render_template('ranker.html', rankings=rankings)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, password))
            conn.commit()
            flash('Cadastro feito! Faça login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Usuário ou email já existe.', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Login realizado!', 'success')
            return redirect(url_for('dashboard'))
        flash('Credenciais inválidas.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT username, email, profile_photo FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    c.execute('''SELECT binds.id, binds.titulo, binds.codigo, binds.foto, binds.data, binds.categoria
                 FROM binds WHERE user_id = ? ORDER BY data DESC''', (session['user_id'],))
    my_binds = c.fetchall()
    c.execute('''SELECT u.username, f.id, f.from_user_id
                 FROM friendships f JOIN users u ON f.from_user_id = u.id
                 WHERE f.to_user_id = ? AND f.status = 'pending' ''', (session['user_id'],))
    pending_requests = c.fetchall()
    conn.close()
    return render_template('dashboard.html', user=user, my_binds=my_binds, pending_requests=pending_requests)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        profile_photo = None
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_photo = filename
        query = "UPDATE users SET username = ?, email = ?"
        params = [username, email]
        if profile_photo:
            query += ", profile_photo = ?"
            params.append(profile_photo)
        query += " WHERE id = ?"
        params.append(session['user_id'])
        c.execute(query, params)
        conn.commit()
        flash('Perfil atualizado com sucesso!', 'success')
        return redirect(url_for('dashboard'))
    c.execute("SELECT username, email, profile_photo FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    return render_template('edit_profile.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)