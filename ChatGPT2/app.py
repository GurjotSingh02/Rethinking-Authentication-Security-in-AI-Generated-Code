from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)

# Initialize the rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize Argon2 password hasher
ph = PasswordHasher()

# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Insert a sample user
def insert_sample_user():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    sample_username = 'testuser'
    sample_password = 'Test@1234'  # Should meet password policy
    password_hash = ph.hash(sample_password)
    try:
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (sample_username, password_hash))
        conn.commit()
    except sqlite3.IntegrityError:
        # Sample user already exists
        pass
    conn.close()

init_db()
insert_sample_user()

# Define WTForms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=150)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Register')

@app.route('/')
def home():
    return redirect(url_for('login'))

# Limit login attempts to prevent brute-force attacks
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password_input = form.password.data

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            password_hash = result[0]
            try:
                ph.verify(password_hash, password_input)
                # Password is correct
                flash('Login successful!', 'success')
                # Here you can redirect to a protected page
                return redirect(url_for('login'))
            except VerifyMismatchError:
                flash('Invalid username or password.', 'danger')
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        password_hash = ph.hash(password)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
            conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')
        conn.close()
    return render_template('register.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)