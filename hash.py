from werkzeug.security import generate_password_hash

password = "Latesh@01100100446001"
hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

print("Hashed Password:", hashed_password)
