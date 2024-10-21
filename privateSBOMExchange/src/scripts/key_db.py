import sqlite3

def create_table():
    conn = sqlite3.connect('keys.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS user_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id TEXT UNIQUE NOT NULL,
                        key TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def store_key(user_id, key):
    conn = sqlite3.connect('keys.db')
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO user_keys (user_id, key) VALUES (?, ?)", (user_id, str(key)))
        conn.commit()
    except sqlite3.IntegrityError:
        cursor.execute("UPDATE user_keys SET key = ? WHERE user_id = ?", (str(key), user_id))
        conn.commit()
    conn.close()

def get_key(user_id):
    conn = sqlite3.connect('keys.db')
    cursor = conn.cursor()
    cursor.execute("SELECT key FROM user_keys WHERE user_id=?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None
