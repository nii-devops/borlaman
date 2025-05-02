import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bootstrap import Bootstrap5
from config import Config
from authlib.integrations.flask_client import OAuth
from flask_wtf.csrf import CSRFProtect


db = SQLAlchemy()
migrate = Migrate()
login = LoginManager()
login.login_view = 'main.login'
login.login_message = 'Please log in to access this page.'
bootstrap = Bootstrap5()
oauth = OAuth()
csrf = CSRFProtect()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login.init_app(app)
    bootstrap.init_app(app)
    oauth.init_app(app)
    csrf.init_app(app)

    # Register Blueprints
    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)

    return app