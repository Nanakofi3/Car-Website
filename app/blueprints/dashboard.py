from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app

from ..extensions import db
from ..models import User, Vehicle, Reservation
from ..forms import ReservationForm
from ..utils import login_required

bp = Blueprint('dashboard', __name__)


@bp.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])

    total_vehicles_count = Vehicle.query.count()
    available_vehicles_count = Vehicle.query.filter_by(status='Available').count()
    reservations_count = Reservation.query.count()

    return render_template('dashboard.html',
                            username=user.username,
                            total_vehicles=total_vehicles_count,
                            available_vehicles=available_vehicles_count,
                            reservations_count=reservations_count)


@bp.route('/reservations', methods=['GET', 'POST'])
@login_required
def reservations():
    form = ReservationForm()

    if form.validate_on_submit():
        new_reservation = Reservation(
            user_id=session['user_id'],
            vehicle_id=1,  # You'll need to implement vehicle selection logic
            reservation_date=datetime.utcnow(),
            status='Pending'
        )

        try:
            db.session.add(new_reservation)
            db.session.commit()
            flash('Reservation submitted successfully!', 'success')
            return redirect(url_for('dashboard.reservations'))
        except Exception as e:
            db.session.rollback()
            flash('Error submitting reservation', 'danger')
            current_app.logger.error(f"Reservation error: {str(e)}")

    page = request.args.get('page', 1, type=int)
    reservations = Reservation.query.filter_by(user_id=session['user_id']).paginate(page=page, per_page=10)

    return render_template('reservations.html',
                            form=form,
                            reservations=reservations)
