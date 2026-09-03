import secrets
from datetime import datetime, timedelta

from flask import Blueprint, render_template, request, redirect, url_for, flash, session

from ..extensions import db
from ..models import User, PasswordResetToken
from ..utils import is_safe_next

bp = Blueprint('auth', __name__)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    next_url = request.args.get('next') or request.form.get('next')
    next_url = next_url if is_safe_next(next_url) else None

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('auth.login', next=next_url))

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect(next_url or url_for('dashboard.dashboard'))

        flash('Invalid username or password', 'danger')
        return redirect(url_for('auth.login', next=next_url))

    return render_template('login.html', next=next_url)


@bp.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('auth.login'))


@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    next_url = request.args.get('next') or request.form.get('next')
    next_url = next_url if is_safe_next(next_url) else None

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('auth.signup', next=next_url))

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists', 'danger')
            return redirect(url_for('auth.signup', next=next_url))

        new_user = User(username=username, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please sign in.', 'success')
        return redirect(url_for('auth.login', next=next_url))

    return render_template('signup.html', next=next_url)


@bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(hours=1)

            reset_token = PasswordResetToken(
                user_id=user.id,
                token=token,
                expires_at=expires_at
            )
            db.session.add(reset_token)
            db.session.commit()

            reset_link = url_for('auth.reset_password', token=token, _external=True)
            flash(f'Password reset link sent (demo: {reset_link})', 'info')
        else:
            flash('No account found with that email', 'warning')
        return redirect(url_for('auth.forgot_password'))

    return render_template('forgot_password.html')


@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(token=token).first()

    if not reset_token or reset_token.used or reset_token.expires_at < datetime.utcnow():
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(request.url)

        user = User.query.get(reset_token.user_id)
        user.set_password(new_password)
        reset_token.used = True
        db.session.commit()

        flash('Password updated successfully!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html', token=token)
