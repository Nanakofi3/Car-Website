import os
from datetime import datetime

from flask import Flask, session
from dotenv import load_dotenv

from .config import Config, BASE_DIR
from .extensions import db, migrate, mail, csrf

load_dotenv()


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, 'templates'),
        static_folder=os.path.join(BASE_DIR, 'static'),
    )
    app.config.from_object(Config)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    csrf.init_app(app)

    from . import models  # noqa: F401 -- register models with SQLAlchemy metadata

    from .blueprints.main import bp as main_bp
    from .blueprints.auth import bp as auth_bp
    from .blueprints.vehicles import bp as vehicles_bp
    from .blueprints.dashboard import bp as dashboard_bp
    from .blueprints.admin import bp as admin_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(vehicles_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)

    from .cli import seed_vehicles_command, create_admin_command
    app.cli.add_command(seed_vehicles_command)
    app.cli.add_command(create_admin_command)

    with app.app_context():
        db.create_all()

    @app.context_processor
    def inject_globals():
        current_user = None
        if 'user_id' in session:
            current_user = models.User.query.get(session['user_id'])
        return {'current_user': current_user, 'current_year': datetime.utcnow().year}

    @app.after_request
    def add_header(response):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        return response

    return app
