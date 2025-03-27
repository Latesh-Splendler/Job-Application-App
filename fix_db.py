import sqlite3

conn = sqlite3.connect("job_portal.db", check_same_thread=False)
cursor = conn.cursor()

# Drop and recreate the users table to fix the issue
cursor.execute("DROP TABLE IF EXISTS users")
conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    user_type TEXT CHECK(user_type IN ('admin', 'employer', 'job_seeker'))
)
""")
conn.commit()

# Insert admin user
cursor.execute("INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)",
               ('admin_user', 'Latesh@01100100446001', 'admin'))
conn.commit()

conn.close()
print("Database fixed successfully!")
