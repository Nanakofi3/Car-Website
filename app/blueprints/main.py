from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_mail import Message

from ..extensions import mail

bp = Blueprint('main', __name__)


@bp.route('/')
def landing():
    return render_template('landing.html')


@bp.route('/features')
def features():
    return render_template('features.html')


@bp.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        user_email = request.form['email']
        message = request.form['message']

        try:
            msg = Message("New Contact Form Submission",
                          recipients=['your_email@example.com'])
            msg.body = f"Name: {name}\nEmail: {user_email}\nMessage: {message}"
            mail.send(msg)
            flash('Your message has been sent!', 'success')
        except Exception as e:
            flash('Failed to send message. Please try again later.', 'danger')
            current_app.logger.error(f"Mail send error: {str(e)}")

        return redirect(url_for('main.contact'))

    return render_template('contact.html')
