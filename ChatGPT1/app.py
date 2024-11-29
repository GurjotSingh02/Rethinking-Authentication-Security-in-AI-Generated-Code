from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import hashlib

app = Flask(__name__)

# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Insert a sample user
def insert_sample_user():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    sample_username = 'testuser'
    sample_password = hashlib.sha256('testpass'.encode()).hexdigest()
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (sample_username, sample_password))
        conn.commit()
    except sqlite3.IntegrityError:
        # Sample user already exists
        pass
    conn.close()

init_db()
insert_sample_user()

@app.route('/')
def home():
    return redirect(url_for('login'))

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']
        hashed_password = hashlib.sha256(password_input.encode()).hexdigest()

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            message = 'Login successful!'
        else:
            message = 'Invalid username or password.'

    return render_template('login.html', message=message)

# Registration Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            message = 'Passwords do not match!'
        else:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                conn.commit()
                message = 'Registration successful!'
            except sqlite3.IntegrityError:
                message = 'Username already exists!'
            conn.close()

    return render_template('register.html', message=message)

if __name__ == '__main__':
    app.run(debug=True)