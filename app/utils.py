from functools import wraps
from urllib.parse import urlparse

from flask import session, redirect, url_for, flash


def is_safe_next(url):
    if not url:
        return False
    parsed = urlparse(url)
    return not parsed.netloc and not parsed.scheme and url.startswith('/')


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        from .models import User

        if 'user_id' not in session:
            flash('Please login to view this page', 'danger')
            return redirect(url_for('auth.login'))

        if not User.query.get(session['user_id']):
            session.pop('user_id', None)
            flash('Your session has expired. Please log in again.', 'danger')
            return redirect(url_for('auth.login'))

        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        from .models import User

        if 'user_id' not in session:
            flash('Please login to view this page', 'danger')
            return redirect(url_for('auth.login'))

        user = User.query.get(session['user_id'])
        if not user:
            session.pop('user_id', None)
            flash('Your session has expired. Please log in again.', 'danger')
            return redirect(url_for('auth.login'))

        if not user.is_admin:
            flash('You do not have permission to view this page', 'danger')
            return redirect(url_for('dashboard.dashboard'))

        return view(*args, **kwargs)
    return wrapped
