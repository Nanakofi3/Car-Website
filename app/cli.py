import click
from flask.cli import with_appcontext

from .extensions import db
from .models import Vehicle, User

SAMPLE_VEHICLES = [
    dict(make='BMW', model='M5 Competition', year=2023, vin='WBS73CH0507P00001',
         price=94999, mileage=8500, status='Available',
         image_url='https://images.unsplash.com/photo-1555215695-3004980ad54e?q=80&w=900&auto=format&fit=crop'),
    dict(make='Mercedes-Benz', model='G63 AMG', year=2022, vin='W1NYC7HJ7NX000002',
         price=178500, mileage=12400, status='Available',
         image_url='https://images.unsplash.com/photo-1520031441872-265e4ff70366?q=80&w=900&auto=format&fit=crop'),
    dict(make='Porsche', model='911 Carrera S', year=2023, vin='WP0AB2A99PS000003',
         price=132900, mileage=3100, status='Available',
         image_url='https://images.unsplash.com/photo-1503376780353-7e6692767b70?q=80&w=900&auto=format&fit=crop'),
    dict(make='Range Rover', model='Autobiography', year=2021, vin='SALGS2SE0MA000004',
         price=118750, mileage=21300, status='Reserved',
         image_url='https://images.unsplash.com/photo-1519641471654-76ce0107ad1b?q=80&w=900&auto=format&fit=crop'),
    dict(make='Tesla', model='Model S Plaid', year=2024, vin='5YJSA1E20PF000005',
         price=104990, mileage=1200, status='Available',
         image_url='https://images.unsplash.com/photo-1536700503339-1e4b06520771?q=80&w=900&auto=format&fit=crop'),
    dict(make='Audi', model='RS7 Sportback', year=2022, vin='WAUZZZF20NN000006',
         price=112400, mileage=9800, status='Sold',
         image_url='https://images.unsplash.com/photo-1614200187524-dc4b892acf16?q=80&w=900&auto=format&fit=crop'),
]


@click.command('seed-vehicles')
@with_appcontext
def seed_vehicles_command():
    if Vehicle.query.first():
        click.echo('Vehicles already exist, skipping seed.')
        return

    for data in SAMPLE_VEHICLES:
        db.session.add(Vehicle(**data))
    db.session.commit()
    click.echo(f'Seeded {len(SAMPLE_VEHICLES)} vehicles.')


@click.command('create-admin')
@click.argument('username')
@click.argument('email')
@click.argument('password')
@with_appcontext
def create_admin_command(username, email, password):
    existing = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing:
        existing.is_admin = True
        db.session.commit()
        click.echo(f'Promoted existing user "{existing.username}" to admin.')
        return

    user = User(username=username, email=email, is_admin=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo(f'Created admin user "{username}".')
