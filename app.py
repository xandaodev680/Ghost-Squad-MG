from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'chave_secreta_mude_isso_2026'
socketio = SocketIO(app)

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
                  status TEXT DEFAULT 'pending',
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
        categoria = request.form.get('categoria')
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
    
    return render_template('post_bind.html')

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        flash('Você precisa estar logado para acessar o chat.', 'danger')
        return redirect(url_for('login'))
    return render_template('chat.html')

@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        emit('message', {'msg': f'{session["username"]} entrou no chat', 'username': 'Sistema'}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        emit('message', {'msg': f'{session["username"]} saiu do chat', 'username': 'Sistema'}, broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    msg = data['msg']
    username = session.get('username', 'Anônimo')
    emit('message', {'msg': msg, 'username': username}, broadcast=True)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT username, email, profile_photo FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    
    # Suas binds
    c.execute('''SELECT binds.id, binds.titulo, binds.codigo, binds.foto, binds.data, binds.categoria
                 FROM binds WHERE user_id = ? ORDER BY data DESC''', (session['user_id'],))
    my_binds = c.fetchall()
    
    # Pedidos pendentes
    c.execute('''SELECT u.username, f.id, f.from_user_id, u.profile_photo
                 FROM friendships f JOIN users u ON f.from_user_id = u.id
                 WHERE f.to_user_id = ? AND f.status = 'pending' ''', (session['user_id'],))
    pending_requests = c.fetchall()
    
    # Amigos aceitos
    c.execute('''SELECT u.id, u.username, u.profile_photo
                 FROM friendships f JOIN users u ON 
                     (CASE WHEN f.from_user_id = ? THEN f.to_user_id ELSE f.from_user_id END) = u.id
                 WHERE (f.from_user_id = ? OR f.to_user_id = ?) AND f.status = 'accepted' ''',
              (session['user_id'], session['user_id'], session['user_id']))
    friends = c.fetchall()
    
    conn.close()
    return render_template('dashboard.html', user=user, my_binds=my_binds, pending_requests=pending_requests, friends=friends)

# Mantenha as outras rotas que você já tem (register, login, edit_profile, logout, search_users, send_friend_request, accept, reject, etc.)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)