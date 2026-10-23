"""Database session and connection management for Spork-IDS."""
import os
from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from app.core.config import settings

# Ensure data directory exists if using SQLite
if settings.SPORK_DATABASE_URL.startswith("sqlite"):
    # Extract path from sqlite URL: sqlite:///./data/spork.db
    db_path_part = settings.SPORK_DATABASE_URL.replace("sqlite:///", "")
    db_dir = os.path.dirname(db_path_part)
    if db_dir:
        Path(db_dir).mkdir(parents=True, exist_ok=True)

connect_args = {"check_same_thread": False} if settings.SPORK_DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.SPORK_DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    echo=settings.SPORK_DEBUG,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency generator that yields a database session and safely closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Initializes all database tables registered with Base."""
    # Import models here to ensure they are registered with Base metadata
    from app.models import db_models  # noqa: F401
    Base.metadata.create_all(bind=engine)
