import sqlite3
from werkzeug.security import generate_password_hash

# Connect to the database
conn = sqlite3.connect("job_portal.db")
cursor = conn.cursor()

# Define admin credentials
username = "admin_user"
password = "Latesh@01100100446001"

# Hash the password
hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

# Insert into the database
cursor.execute("INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)", 
               (username, hashed_password, "admin"))
conn.commit()
print("Admin user registered successfully!")

# Close the connection
conn.close()
