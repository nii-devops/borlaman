import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env')) # Load .env file

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess' # Fallback key
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') #or 'sqlite:///' + os.path.join(basedir, 'app.db') # Fallback to SQLite if needed
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BOOTSTRAP_SERVE_LOCAL = False # Use CDN for Bootstrap
    UPLOAD_FOLDER = 'app/static/uploads'