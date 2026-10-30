"""
database.py

This file is responsible for setting up the connection to our SQLite database.
We use SQLAlchemy, which is an ORM (Object-Relational Mapper). It allows us to 
interact with our database using Python classes instead of writing raw SQL queries.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

import settings

# The database lives in the per-user data directory resolved by settings.py, so a
# packaged app (whose install directory is read-only) and the Docker image (whose
# /data volume is mounted) both get a writable location.
SQLALCHEMY_DATABASE_URL = f"sqlite:///{settings.DB_PATH}"

# The 'engine' is the core interface to the database.
# `check_same_thread=False` is needed for SQLite in FastAPI because FastAPI can 
# handle multiple requests concurrently in different threads.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# A SessionLocal class is created. Each time we instantiate it, we get a new 
# database session (a conversation with the database).
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base is a class that all our future database models will inherit from.
# It tells SQLAlchemy that our classes are database tables.
Base = declarative_base()

# Dependency to easily get a database session in our FastAPI routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
