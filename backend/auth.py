"""
auth.py

This file contains all the cryptography and authentication logic.
You wanted to learn how this works, so here is the breakdown:

1. PASSWORDS: We use `bcrypt`. Bcrypt is a hashing algorithm. 
   Hashing is a one-way mathematical function. It takes a password (e.g. "password123") 
   and turns it into a random string (e.g. "$2b$12$DkI..."). You cannot reverse a hash 
   back into the password. 
   When a user logs in, we hash the password they typed in, and check if it exactly 
   matches the hash stored in our database.

2. JWT (JSON Web Token): Once a user proves they know the password, we don't want 
   them to have to send their password on every single request. Instead, we give 
   them a temporary VIP badge: a JWT.
   A JWT contains information (like their username) and is digitally signed by the 
   server using a SECRET_KEY. If a user modifies the JWT on the client side, the 
   signature breaks, and our server will reject it.
"""

import bcrypt
from datetime import datetime, timedelta
import jwt

# 1. Password Hashing Setup
# We use the bcrypt library directly

def verify_password(plain_password, hashed_password):
    """Checks if the plain password matches the hashed version."""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password):
    """Converts a plain password into a secure bcrypt hash."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


# 2. JWT Configuration
# SECURITY NOTE: In a real app, NEVER hardcode this. It should be in a .env file!
# If a hacker gets this key, they can forge their own JWT tokens.
SECRET_KEY = "my_super_secret_learning_key_do_not_use_in_prod"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # Token lasts for 1 week

def create_access_token(data: dict):
    """
    Creates a JWT token.
    `data` usually contains {"sub": "username"}
    """
    to_encode = data.copy()
    
    # Calculate when this token should expire
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    
    # Actually sign the token with our secret key
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
