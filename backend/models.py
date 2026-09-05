"""
models.py

This defines our database tables. We are inheriting from the `Base` class 
we created in database.py.
"""
from sqlalchemy import Column, Integer, String
from database import Base

class User(Base):
    # The actual table name in SQLite
    __tablename__ = "users"

    # Define the columns in our table
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    
    # SECURITY NOTE: We NEVER store plain text passwords. 
    # We only store the hashed string output.
    hashed_password = Column(String, nullable=False)
