from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
import os
from datetime import timedelta
from functools import wraps

app = Flask(__name__)
# Fetch secret key from environment variable
app.secret_key = os.environ.get('FLASK_SECRET_KEY')
app.permanent_session_lifetime = timedelta(minutes=30)

# Database initialization
def init_db():
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP
            )
        ''')
        conn.commit()

# Password validation
def is_password_valid(password):
    if len(password) < 12:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('SELECT password_hash, failed_attempts FROM users WHERE username = ?', 
                     (username,))
            result = c.fetchone()
            
            if result and result[1] >= 5:
                flash('Account temporarily locked. Please try again later.', 'error')
                return render_template('login.html')
            
            if result and check_password_hash(result[0], password):
                # Reset failed attempts on successful login
                c.execute('UPDATE users SET failed_attempts = 0 WHERE username = ?', 
                         (username,))
                conn.commit()
                
                session.permanent = True
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                if result:
                    c.execute('''UPDATE users 
                               SET failed_attempts = failed_attempts + 1,
                                   last_attempt = CURRENT_TIMESTAMP 
                               WHERE username = ?''', (username,))
                    conn.commit()
                flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not username or not password or not confirm_password:
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        if not is_password_valid(password):
            flash('Password must be at least 12 characters long and contain uppercase, '
                  'lowercase, numbers, and special characters', 'error')
            return render_template('register.html')
        
        password_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')
        
        try:
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                         (username, password_hash))
                conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='127.0.0.1', port=5000)