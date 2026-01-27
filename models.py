from datetime import datetime
from flask_login import UserMixin
from extensions import db
import uuid

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    files = db.relationship('File', backref='owner', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_path = db.Column(db.String(255), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shares = db.relationship('Share', backref='file', lazy=True)

class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    receiver_email = db.Column(db.String(120), nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False)
    otps = db.relationship('OTP', backref='share', lazy=True)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    share_id = db.Column(db.Integer, db.ForeignKey('share.id'), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_used = db.Column(db.Boolean, default=False)
