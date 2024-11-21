#!/usr/bin/env python3
"""
Main file
"""

from user import User
from db import DB
from auth import Auth, _hash_password
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound


# ---------------------------
# Section 1: Inspect User Table
# ---------------------------
print(User.__tablename__)

for column in User.__table__.columns:
    print("{}: {}".format(column, column.type))


# ------------------------------
# Section 2: Interact with DB
# ------------------------------
my_db = DB()

# Add a new user
user = my_db.add_user("test@test.com", "PwdHashed")
print(user.id)

# Find user by email
find_user = my_db.find_user_by(email="test@test.com")
print(find_user.id)

# Try to find a non-existing user
try:
    find_user = my_db.find_user_by(email="test2@test.com")
    print(find_user.id)
except NoResultFound:
    print("Not found")

# Invalid request test
try:
    find_user = my_db.find_user_by(no_email="test@test.com")
    print(find_user.id)
except InvalidRequestError:
    print("Invalid")


# -------------------------------
# Section 3: Update User's Password
# -------------------------------
email = 'test@test.com'
hashed_password = "hashedPwd"

user = my_db.add_user(email, hashed_password)
print(user.id)

try:
    my_db.update_user(user.id, hashed_password='NewPwd')
    print("Password updated")
except ValueError:
    print("Error")


# ------------------------
# Section 4: Hash a Password
# ------------------------
print(_hash_password("Hello Holberton"))


# --------------------------
# Section 5: Register User
# --------------------------
email = 'me@me.com'
password = 'mySecuredPwd'
auth = Auth()

# Try to register a user
try:
    user = auth.register_user(email, password)
    print("Successfully created a new user!")
except ValueError as err:
    print(f"Could not create a new user: {err}")

# Try to register the same user again
try:
    user = auth.register_user(email, password)
    print("Successfully created a new user!")
except ValueError as err:
    print(f"Could not create a new user: {err}")


# ------------------------
# Section 6: Valid Login
# ------------------------
email = 'bob@bob.com'
password = 'MyPwdOfBob'

auth.register_user(email, password)

# Valid login attempts
print(auth.valid_login(email, password))

# Invalid login attempts
print(auth.valid_login(email, "WrongPwd"))
print(auth.valid_login("unknown@email", password))


# --------------------------
# Section 7: Create Session
# --------------------------
print(auth.create_session(email))
print(auth.create_session("unknown@email.com"))

