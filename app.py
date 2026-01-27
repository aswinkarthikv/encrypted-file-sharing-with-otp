import os
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db, login_manager
from models import User, File, Share, OTP
from utils import encrypt_file_content, decrypt_file_content, generate_otp

# Initialize App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_share.db'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize Extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password')
    return render_template('auth.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    
    user = User.query.filter_by(email=email).first()
    if user:
        flash('Email already exists')
        return redirect(url_for('login'))
    
    new_user = User(
        email=email,
        name=name,
        password_hash=generate_password_hash(password)
    )
    db.session.add(new_user)
    db.session.commit()
    
    login_user(new_user)
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_files = File.query.filter_by(owner_id=current_user.id).order_by(File.upload_time.desc()).all()
    # Fetch shares for files owned by the current user
    user_shares = Share.query.join(File).filter(File.owner_id == current_user.id).order_by(Share.id.desc()).all()
    return render_template('dashboard.html', name=current_user.name, files=user_files, shares=user_shares)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('dashboard'))

    if file:
        filename = secure_filename(file.filename)
        # Encrypt the file
        file_data = file.read()
        encrypted_data = encrypt_file_content(file_data)
        
        # Save encrypted file with a unique name to prevent collisions/guessing
        encrypted_filename = f"{uuid.uuid4()}_{filename}.enc"
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
            
        new_file = File(
            filename=filename,
            encrypted_path=encrypted_path,
            owner_id=current_user.id
        )
        db.session.add(new_file)
        db.session.commit()
        
        flash('File uploaded and encrypted successfully!')
        return redirect(url_for('dashboard'))

@app.route('/share', methods=['POST'])
@login_required
def share_file():
    file_id = request.form.get('file_id')
    receiver_email = request.form.get('email')
    
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('Unauthorized')
        return redirect(url_for('dashboard'))
    
    expiry = datetime.utcnow() + timedelta(hours=1) # Link valid for 1 hour
    
    share = Share(
        file_id=file.id,
        receiver_email=receiver_email,
        expiry_time=expiry
    )
    db.session.add(share)
    db.session.flush() 
    
    otp_code = generate_otp()
    otp = OTP(
        share_id=share.id,
        otp_code=otp_code
    )
    db.session.add(otp)
    db.session.commit()
    
    # Mock Sending OTP
    print(f"========================================")
    print(f" [MOCK EMAIL] To: {receiver_email}")
    print(f" File: {file.filename}")
    print(f" Share Link: {url_for('download_auth', token=share.token, _external=True)}")
    print(f" OTP: {otp_code}")
    print(f"========================================")
    
    flash(f'Share link created! OTP for {receiver_email} logged to console (simulated).')
    return redirect(url_for('dashboard'))

@app.route('/download/<token>', methods=['GET', 'POST'])
def download_auth(token):
    share = Share.query.filter_by(token=token).first_or_404()
    
    if datetime.utcnow() > share.expiry_time:
        return "This link has expired.", 410

    if request.method == 'POST':
        user_otp = request.form.get('otp')
        otp_record = OTP.query.filter_by(share_id=share.id, otp_code=user_otp).first()
        
        # Check if OTP matches and is not used (and maybe check expiry of OTP too if added later)
        if otp_record and not otp_record.is_used:
            # OTP Verified
            otp_record.is_used = True
            db.session.commit()
            
            # Decrypt and Serve File
            file = share.file
            try:
                with open(file.encrypted_path, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = decrypt_file_content(encrypted_data)
                
                from io import BytesIO
                return send_file(
                    BytesIO(decrypted_data),
                    as_attachment=True,
                    download_name=file.filename
                )
            except Exception as e:
                return f"Error decrypting file: {str(e)}", 500
        else:
            flash('Invalid, expired or already used OTP')
            
    return render_template('download.html', email=share.receiver_email)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
