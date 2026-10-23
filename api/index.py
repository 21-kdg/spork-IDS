"""Vercel Serverless Function entry point for Spork-IDS FastAPI backend."""
import os
import sys

# Ensure repository root is on sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Ensure Vercel environment flag is recognized
os.environ["VERCEL"] = "1"

from app.main import app  # noqa: E402, F401
