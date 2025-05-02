from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import db, login





class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(256)) # Increased length for stronger hashes
    
    is_manager = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    # Basic location fields (nullable for now)
    
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    role_id = db.Column(db.ForeignKey('role.id'))

    # Relationships
    role = db.relationship('Role', backref='user')
    jobs_posted = db.relationship('Job', foreign_keys='Job.client_id', backref='client', lazy='dynamic')
    jobs_accepted = db.relationship('Job', foreign_keys='Job.driver_id', backref='driver', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email} ({self.role})>'



class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)


class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(64), nullable=False)


class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Null until accepted
    description = db.Column(db.Text, nullable=False)
    location_text = db.Column(db.String(255), nullable=False) # Simple text location for MVP
    # Add lat/lon later for map integration
    # latitude = db.Column(db.Float, nullable=True)
    # longitude = db.Column(db.Float, nullable=True)
    image = db.Column(db.String(255), nullable=True)
    price = db.Column(db.Float, nullable=True) # Price offered by client

    status_id =  db.Column(db.ForeignKey('status.id'), nullable=True)
    status = db.relationship('Status', backref='job')

    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    accepted_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<Job {self.id} ({self.status})>'




# Flask-Login user loader
@login.user_loader
def load_user(id):
    return db.session.get(User, int(id)) # Use db.session.get for SQLAlchemy 3+