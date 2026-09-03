import os
import uuid

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app

from ..extensions import db
from ..models import Vehicle, Reservation
from ..utils import admin_required

bp = Blueprint('admin', __name__, url_prefix='/admin')

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}


class InvalidImageError(Exception):
    pass


def _allowed_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def _save_vehicle_image(file_storage):
    """Save an uploaded picture and return its public URL, or None if no file was given."""
    if not file_storage or not file_storage.filename:
        return None

    if not _allowed_image(file_storage.filename):
        raise InvalidImageError('Please upload a PNG, JPG, WEBP, or GIF picture.')

    ext = file_storage.filename.rsplit('.', 1)[1].lower()
    filename = f'{uuid.uuid4().hex}.{ext}'
    file_storage.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
    return f'/static/uploads/vehicles/{filename}'


def _delete_vehicle_image(image_url):
    if not image_url or not image_url.startswith('/static/uploads/vehicles/'):
        return
    path = os.path.join(current_app.config['UPLOAD_FOLDER'], image_url.rsplit('/', 1)[-1])
    if os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            pass


@bp.route('/')
@admin_required
def dashboard():
    stats = {
        'total': Vehicle.query.count(),
        'available': Vehicle.query.filter_by(status='Available').count(),
        'reserved': Vehicle.query.filter_by(status='Reserved').count(),
        'sold': Vehicle.query.filter_by(status='Sold').count(),
        'reservations': Reservation.query.count(),
        'pending': Reservation.query.filter_by(status='Pending').count(),
    }
    return render_template('admin_dashboard.html', stats=stats)


@bp.route('/vehicles')
@admin_required
def vehicles():
    page = request.args.get('page', 1, type=int)
    items = Vehicle.query.order_by(Vehicle.id.desc()).paginate(page=page, per_page=10)
    return render_template('admin_vehicles.html', vehicles=items)


def _vehicle_form_data():
    return dict(
        make=request.form.get('make', '').strip(),
        model=request.form.get('model', '').strip(),
        year=request.form.get('year', type=int),
        vin=request.form.get('vin', '').strip().upper(),
        price=request.form.get('price', type=float),
        mileage=request.form.get('mileage', type=int),
        status=request.form.get('status', 'Available'),
    )


def _vehicle_form_error(data):
    if not all([data['make'], data['model'], data['year'], data['vin'],
                data['price'] is not None, data['mileage'] is not None]):
        return 'Please fill in all required fields.'
    if len(data['vin']) > 17:
        return 'VIN must be 17 characters or fewer.'
    return None


@bp.route('/vehicles/new', methods=['GET', 'POST'])
@admin_required
def new_vehicle():
    if request.method == 'POST':
        data = _vehicle_form_data()

        error = _vehicle_form_error(data)
        if error:
            flash(error, 'danger')
            return render_template('admin_vehicle_form.html', vehicle=data, mode='new')

        if Vehicle.query.filter_by(vin=data['vin']).first():
            flash('A vehicle with that VIN already exists', 'danger')
            return render_template('admin_vehicle_form.html', vehicle=data, mode='new')

        try:
            image_url = _save_vehicle_image(request.files.get('image'))
        except InvalidImageError as e:
            flash(str(e), 'danger')
            return render_template('admin_vehicle_form.html', vehicle=data, mode='new')

        vehicle = Vehicle(image_url=image_url, **data)
        try:
            db.session.add(vehicle)
            db.session.commit()
        except Exception:
            db.session.rollback()
            _delete_vehicle_image(image_url)
            flash('Could not save this vehicle. Please check the values and try again.', 'danger')
            return render_template('admin_vehicle_form.html', vehicle=data, mode='new')

        flash(f'{vehicle.year} {vehicle.make} {vehicle.model} added to the fleet.', 'success')
        return redirect(url_for('admin.vehicles'))

    return render_template('admin_vehicle_form.html', vehicle=None, mode='new')


@bp.route('/vehicles/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_vehicle(id):
    vehicle = Vehicle.query.get_or_404(id)

    if request.method == 'POST':
        data = _vehicle_form_data()

        error = _vehicle_form_error(data)
        if error:
            flash(error, 'danger')
            data['image_url'] = vehicle.image_url
            return render_template('admin_vehicle_form.html', vehicle=data, mode='edit', vehicle_id=id)

        duplicate = Vehicle.query.filter(Vehicle.vin == data['vin'], Vehicle.id != id).first()
        if duplicate:
            flash('A vehicle with that VIN already exists', 'danger')
            data['image_url'] = vehicle.image_url
            return render_template('admin_vehicle_form.html', vehicle=data, mode='edit', vehicle_id=id)

        try:
            new_image_url = _save_vehicle_image(request.files.get('image'))
        except InvalidImageError as e:
            flash(str(e), 'danger')
            data['image_url'] = vehicle.image_url
            return render_template('admin_vehicle_form.html', vehicle=data, mode='edit', vehicle_id=id)

        old_image_url = vehicle.image_url
        for key, value in data.items():
            setattr(vehicle, key, value)
        if new_image_url:
            vehicle.image_url = new_image_url

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            if new_image_url:
                _delete_vehicle_image(new_image_url)
            flash('Could not save changes. Please check the values and try again.', 'danger')
            data['image_url'] = old_image_url
            return render_template('admin_vehicle_form.html', vehicle=data, mode='edit', vehicle_id=id)

        if new_image_url:
            _delete_vehicle_image(old_image_url)

        flash(f'{vehicle.year} {vehicle.make} {vehicle.model} updated.', 'success')
        return redirect(url_for('admin.vehicles'))

    return render_template('admin_vehicle_form.html', vehicle=vehicle, mode='edit', vehicle_id=id)


@bp.route('/vehicles/<int:id>/delete', methods=['POST'])
@admin_required
def delete_vehicle(id):
    vehicle = Vehicle.query.get_or_404(id)
    label = f'{vehicle.year} {vehicle.make} {vehicle.model}'
    image_url = vehicle.image_url
    db.session.delete(vehicle)
    db.session.commit()
    _delete_vehicle_image(image_url)
    flash(f'{label} removed from the fleet.', 'success')
    return redirect(url_for('admin.vehicles'))


@bp.route('/reservations')
@admin_required
def reservations():
    page = request.args.get('page', 1, type=int)
    items = Reservation.query.order_by(Reservation.id.desc()).paginate(page=page, per_page=10)
    return render_template('admin_reservations.html', reservations=items)


@bp.route('/reservations/<int:id>/status', methods=['POST'])
@admin_required
def update_reservation_status(id):
    reservation = Reservation.query.get_or_404(id)
    new_status = request.form.get('status')
    if new_status in ('Pending', 'Confirmed', 'Cancelled'):
        reservation.status = new_status
        db.session.commit()
        flash('Reservation status updated.', 'success')
    return redirect(url_for('admin.reservations'))
