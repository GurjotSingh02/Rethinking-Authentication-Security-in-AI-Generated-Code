import sqlite3
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Create table if it doesn't exist
def create_table():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        cursor.execute('SELECT * FROM users WHERE username=?', ('testuser',))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('testuser', 'testpassword'))
            conn.commit()

create_table()

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
            user = cursor.fetchone()
            if user:
                return 'Login successful!'
            else:
                return 'Invalid username or password'
    return render_template('login.html')

# Registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password == confirm_password:
            with sqlite3.connect('users.db') as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
                conn.commit()
                return 'Registration successful!'
        else:
            return 'Passwords do not match'
    return render_template('register.html')

# Navigation links
@app.route('/')
def index():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)