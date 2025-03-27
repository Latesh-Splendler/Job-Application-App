import sqlite3

# Connect to the database
conn = sqlite3.connect("job_portal.db")
cursor = conn.cursor()

# Delete admin user
cursor.execute("DELETE FROM users WHERE user_type = 'admin'")
conn.commit()

print("Admin user deleted successfully!")

# Close the connection
conn.close()
