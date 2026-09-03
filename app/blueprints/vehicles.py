from flask import Blueprint, render_template, request, redirect, url_for, flash, session

from ..extensions import db
from ..models import Vehicle, Reservation
from ..utils import login_required, is_safe_next

bp = Blueprint('vehicles', __name__)


@bp.route('/browse')
def browse():
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', 'all')

    query = Vehicle.query
    if status in ('Available', 'Reserved', 'Sold'):
        query = query.filter_by(status=status)

    vehicles = query.order_by(Vehicle.id.desc()).paginate(page=page, per_page=9)
    return render_template('browse_vehicles.html', vehicles=vehicles, status=status)


@bp.route('/browse/<int:id>')
def browse_detail(id):
    vehicle = Vehicle.query.get_or_404(id)
    return render_template('browse_vehicle_detail.html', vehicle=vehicle)


@bp.route('/total-vehicles')
@login_required
def total_vehicles():
    page = request.args.get('page', 1, type=int)
    vehicles = Vehicle.query.paginate(page=page, per_page=10)
    return render_template('vehicles.html', title='Total Vehicles', vehicles=vehicles)


@bp.route('/available-vehicles')
@login_required
def available_vehicles():
    page = request.args.get('page', 1, type=int)
    vehicles = Vehicle.query.filter_by(status='Available').paginate(page=page, per_page=10)
    return render_template('vehicles.html', title='Available Vehicles', vehicles=vehicles)


@bp.route('/vehicle/<int:id>')
@login_required
def vehicle_details(id):
    vehicle = Vehicle.query.get_or_404(id)
    return render_template('vehicle_details.html', vehicle=vehicle)


@bp.route('/book/<int:vehicle_id>', methods=['POST'])
@login_required
def book_vehicle(vehicle_id):
    vehicle = Vehicle.query.get_or_404(vehicle_id)

    next_url = request.form.get('next')
    redirect_target = next_url if is_safe_next(next_url) else url_for('vehicles.vehicle_details', id=vehicle_id)

    if vehicle.status != 'Available':
        flash('This vehicle is not available for booking', 'warning')
        return redirect(redirect_target)

    new_reservation = Reservation(
        user_id=session['user_id'],
        vehicle_id=vehicle_id,
        status='Pending'
    )

    try:
        vehicle.status = 'Reserved'
        db.session.add(new_reservation)
        db.session.commit()
        flash('Reservation request submitted successfully!', 'success')
    except Exception:
        db.session.rollback()
        flash('Error processing reservation request', 'danger')

    return redirect(redirect_target)
