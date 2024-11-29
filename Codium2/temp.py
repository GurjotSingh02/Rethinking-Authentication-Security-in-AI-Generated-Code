import sqlite3
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    );
''')
# Insert a sample user for testing
c.execute("INSERT INTO users (username, password) VALUES ('testuser', 'password123')")
conn.commit()
conn.close()