import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


class Config:
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-me')
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', f'sqlite:///{os.path.join(BASE_DIR, "cars.db")}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads', 'vehicles')
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.example.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
