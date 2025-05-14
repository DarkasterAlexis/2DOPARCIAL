from flask import Flask,render_template,redirect,url_for,request,session,flash
from flask_login import LoginManager,login_user,login_required,logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash,check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'clave_secreta'
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

def get_db_connection():
    conn = sqlite3.connect('tareas.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            completed INTEGER DEFAULT 0,
            user_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    conn.commit()
    conn.close()
    
class User(UserMixin):
    def __init__(self, id, username, password_hash,created_at):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.created_at = created_at
    @staticmethod
    def get_by_id(user_id):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone()
        conn.close()
        if user:
            return User(user['id'], user['username'], user['password_hash'], user['created_at'])
        return None
    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        conn.close()
        if user:
            return User(user['id'], user['username'],user['password_hash'], user['created_at'])
        return None    
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

@app.route('/')
def index():
    conn = get_db_connection()
    tasks = conn.execute('SELECT title, description, completed FROM tasks').fetchall()
    conn.close()
    return render_template('index.html', tasks=tasks)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password_hash']
        password_hash = generate_password_hash(password)
        conn = get_db_connection()
        
        try:
            conn.execute(
                'INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)',(username, password_hash)
                )
            conn.commit()
            flash('Usuario registrado exitosamente. Iniciar sesion','success')
            return redirect(url_for('login'))
        except sqlite3.ImportError:
            flash('Error este nombre de usuario ya está en uso.','danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_by_username(username)
        if user and user.check_password(password):
            login_user(user)
            flash('INICIO DE SESION EXITOSO','success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña inválidos.','danger')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    conn = get_db_connection()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        conn.execute('INSERT INTO tasks (title, description, completed, user_id, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)',
                     (title, description, False, current_user.id))
        conn.commit()

    tasks = conn.execute('SELECT * FROM tasks WHERE user_id = ?', (current_user.id,)).fetchall()
    conn.close()
    return render_template('dashboard.html', tasks=tasks)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    conn = get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', (task_id, current_user.id)).fetchone()

    if not task:
        conn.close()
        return 'Tarea no encontrada o no autorizada', 404

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        completed = 'completed' in request.form
        conn.execute('UPDATE tasks SET title = ?, description = ?, completed = ? WHERE id = ?',
                     (title, description, completed, task_id))
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('edit_task.html', task=task)

@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', (task_id, current_user.id))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)