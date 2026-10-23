"""Spork-IDS Application Runner Script."""
import os
import sys
import uvicorn

if __name__ == "__main__":
    # Ensure current directory is on python path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)

    from app.core.config import settings

    print(f"==================================================")
    print(f"  Spork-IDS: Python Intrusion Detection System   ")
    print(f"==================================================")
    print(f" Server: http://{settings.SPORK_HOST}:{settings.SPORK_PORT}")
    print(f" API Docs: http://{settings.SPORK_HOST}:{settings.SPORK_PORT}/docs")
    print(f" Database: {settings.SPORK_DATABASE_URL}")
    print(f"==================================================")

    uvicorn.run(
        "app.main:app",
        host=settings.SPORK_HOST,
        port=settings.SPORK_PORT,
        reload=settings.SPORK_DEBUG,
        log_level="info",
    )
