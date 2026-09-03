bind = "0.0.0.0:5000"
workers = 3
preload_app = True


def post_fork(server, worker):
    from wsgi import app
    from app.extensions import db
    with app.app_context():
        db.engine.dispose()
