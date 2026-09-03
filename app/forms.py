from flask_wtf import FlaskForm
from wtforms import StringField, DateField, SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email


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
