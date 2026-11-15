
import os
import pymysql
from pathlib import Path
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from getpass import getpass

load_dotenv(Path(__file__).with_name(".env"))

bcrypt = Bcrypt()

username = input("Enter Admin Username: ").strip()
password = getpass("Enter Admin Password: ")

if not username or not password:
    print("Username and password cannot be empty.")
    raise SystemExit(1)

if len(password) < 8:
    print("Password must contain at least 8 characters.")
    raise SystemExit(1)

password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

connection = pymysql.connect(
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME"),
    port=int(os.getenv("DB_PORT", 3306))
)

try:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (%s, %s, 'Admin')
            """,
            (username, password_hash)
        )
    connection.commit()
    print("Admin account created successfully!")

except pymysql.err.IntegrityError:
    print("Username already exists. Choose another username.")

finally:
    connection.close()
