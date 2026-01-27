
import os
import time
from app import app, db
from models import User, File, Share, OTP

# Configuration
TEST_EMAIL = "test_user_main@example.com"
TEST_PASSWORD = "secure_password"
TEST_FILE_NAME = "secret_plans_main.txt"
TEST_FILE_CONTENT = b"This is a top secret document in the main project."
RECEIVER_EMAIL = "receiver_main@example.com"

def run_internal_test():
    # Ensure clean DB for test
    with app.app_context():
        db.create_all()
        # Clean up previous test user if exists
        u = User.query.filter_by(email=TEST_EMAIL).first()
        if u:
            db.session.delete(u)
            db.session.commit()

    with app.test_client() as client:
        print("[1] Testing Registration...")
        resp = client.post('/register', data={"email": TEST_EMAIL, "name": "Main Agent", "password": TEST_PASSWORD}, follow_redirects=True)
        assert resp.status_code == 200
        print("    ✅ Registered successfully")
        
        print("[2] Testing Login...")
        resp = client.post('/login', data={"email": TEST_EMAIL, "password": TEST_PASSWORD}, follow_redirects=True)
        assert resp.status_code == 200
        print("    ✅ Logged in successfully")
        
        print("[3] Testing File Upload & Encryption...")
        from io import BytesIO
        data = {'file': (BytesIO(TEST_FILE_CONTENT), TEST_FILE_NAME)}
        
        resp = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
        assert resp.status_code == 200
        
        with app.app_context():
            f = File.query.filter_by(filename=TEST_FILE_NAME).order_by(File.upload_time.desc()).first()
            assert f is not None
            fid = f.id
            assert os.path.exists(f.encrypted_path)
        print("    ✅ File uploaded and encrypted on disk")
            
        print("[4] Testing Sharing & OTP Generation...")
        client.post('/share', data={"file_id": fid, "email": RECEIVER_EMAIL}, follow_redirects=True)
        
        with app.app_context():
            share = Share.query.filter_by(file_id=fid).first()
            token = share.token
            otp = OTP.query.filter_by(share_id=share.id).first()
            otp_code = otp.otp_code
            print(f"    ✅ Share Token: {token}")
            print(f"    ✅ OTP: {otp_code}")
            
        print("[5] Testing Download & Decryption...")
        resp = client.post(f'/download/{token}', data={"otp": otp_code})
        
        assert resp.data == TEST_FILE_CONTENT
        print("    ✅ File downloaded and decrypted correctly")
        
        print("\n✅ MAIN PROJECT MIGRATION VERIFIED SUCCESSFULLY")

if __name__ == "__main__":
    run_internal_test()
