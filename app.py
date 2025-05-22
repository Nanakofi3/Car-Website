from flask import Flask, render_template, request, redirect, url_for, flash, session 
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email
import bcrypt
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cars.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@example.com'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reservations = db.relationship('Reservation', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    make = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    vin = db.Column(db.String(17), unique=True, nullable=False)
    status = db.Column(db.String(20), default='Available')
    price = db.Column(db.Float, nullable=False)
    mileage = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(200))
    reservations = db.relationship('Reservation', backref='vehicle', lazy=True)

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=False)
    reservation_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending')

class ReservationForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', validators=[DataRequired()])
    vehicle_type = SelectField('Vehicle Type', choices=[
        ('sedan', 'Sedan'), 
        ('suv', 'SUV'), 
        ('truck', 'Truck')
    ], validators=[DataRequired()])
    pickup_date = DateField('Pickup Date', format='%Y-%m-%d', validators=[DataRequired()])
    return_date = DateField('Return Date', format='%Y-%m-%d', validators=[DataRequired()])
    special_requests = TextAreaField('Special Requests')
    submit = SubmitField('Submit Reservation')

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

# Create database tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/total-vehicles')
def total_vehicles():
    if 'user_id' not in session:
        flash('Please login to view this page', 'danger')
        return redirect(url_for('login'))
    
    # Get paginated vehicles
    page = request.args.get('page', 1, type=int)
    vehicles = Vehicle.query.paginate(page=page, per_page=10)
    
    return render_template('vehicles.html',
                         title='Total Vehicles',
                         vehicles=vehicles)

@app.route('/available-vehicles')
def available_vehicles():
    if 'user_id' not in session:
        flash('Please login to view this page', 'danger')
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    vehicles = Vehicle.query.filter_by(status='Available').paginate(page=page, per_page=10)
    return render_template('vehicles.html', 
                         title='Available Vehicles',
                         vehicles=vehicles)
@app.route('/reservations', methods=['GET', 'POST'])
def reservations():
    if 'user_id' not in session:
        flash('Please login to view this page', 'danger')
        return redirect(url_for('login'))
    
    form = ReservationForm()
    
    if form.validate_on_submit():
        # Process form data
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
            return redirect(url_for('reservations'))
        except Exception as e:
            db.session.rollback()
            flash('Error submitting reservation', 'danger')
            app.logger.error(f"Reservation error: {str(e)}")
    
    page = request.args.get('page', 1, type=int)
    reservations = Reservation.query.filter_by(user_id=session['user_id']).paginate(page=page, per_page=10)
    
    return render_template('reservations.html',
                         form=form,  # Pass form to template
                         reservations=reservations)


@app.route('/vehicle/<int:id>')
def vehicle_details(id):
    if 'user_id' not in session:
        flash('Please login to view this page', 'danger')
        return redirect(url_for('login'))
    
    vehicle = Vehicle.query.get_or_404(id)
    return render_template('vehicle_details.html', vehicle=vehicle)

@app.route('/book/<int:vehicle_id>', methods=['POST'])
def book_vehicle(vehicle_id):
    if 'user_id' not in session:
        flash('Please login to book a vehicle', 'danger')
        return redirect(url_for('login'))
    
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    if vehicle.status != 'Available':
        flash('This vehicle is not available for booking', 'warning')
        return redirect(url_for('vehicle_details', id=vehicle_id))
    
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
    except:
        db.session.rollback()
        flash('Error processing reservation request', 'danger')
    
    return redirect(url_for('vehicle_details', id=vehicle_id))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login to access the dashboard', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Get counts
    total_vehicles_count = Vehicle.query.count()
    available_vehicles_count = Vehicle.query.filter_by(status='Available').count()
    reservations_count = Reservation.query.count()
    
    return render_template('dashboard.html',
                         username=user.username,
                         total_vehicles=total_vehicles_count,
                         available_vehicles=available_vehicles_count,
                         reservations_count=reservations_count)
# Create database tables
with app.app_context():
    db.create_all()

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/features')
def features():
    return render_template('features.html')

mail = Mail(app)

# Rest of your existing configuration and routes...

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        user_email = request.form['email']  # Renamed to avoid conflict
        message = request.form['message']

        try:
            msg = Message("New Contact Form Submission",
                          recipients=['your_email@example.com'])  # Your receiving email
            msg.body = f"Name: {name}\nEmail: {user_email}\nMessage: {message}"
            mail.send(msg)
            flash('Your message has been sent!', 'success')
        except Exception as e:
            flash('Failed to send message. Please try again later.', 'danger')
            app.logger.error(f"Mail send error: {str(e)}")
        
        return redirect(url_for('contact'))
    
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password', 'danger')
        return redirect(url_for('login'))  # Redirect back on failure
    
    # GET request handling
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token
            token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(hours=1)
            
            # Save token to database
            reset_token = PasswordResetToken(
                user_id=user.id,
                token=token,
                expires_at=expires_at
            )
            db.session.add(reset_token)
            db.session.commit()
            
            # In production: Send email with reset link
            reset_link = url_for('reset_password', token=token, _external=True)
            flash(f'Password reset link sent (demo: {reset_link})', 'info')
        else:
            flash('No account found with that email', 'warning')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    
    if not reset_token or reset_token.used or reset_token.expires_at < datetime.utcnow():
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('forgot_password'))
    
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
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))
        
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists', 'danger')
            return redirect(url_for('signup'))
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/success')
def success():
    return "Login Successful!"


if __name__ == '__main__':
    app.run(debug=True)