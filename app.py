from flask import Flask, request, jsonify, url_for
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
import string
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)

# Config
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret')
app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # your Outlook email
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # your app password or normal password


mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

invites = {}

def generate_temp_password(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

@app.route('/send-invite', methods=['POST'])
def send_invite():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    temp_password = generate_temp_password()
    hashed_password = generate_password_hash(temp_password)
    token = serializer.dumps(email, salt='email-confirm')

    invites[email] = {
        'password': hashed_password,
        'token': token
    }

    link = url_for('access_portal', token=token, _external=True)
    msg = Message('Interview Invite',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    msg.body = f"""Hello,

You are invited to the Interview Screening Portal.

Link: {link}
Temporary Password: {temp_password}
Note: This link expires in 10 minutes.

Regards,  
InnoBit Team"""

    mail.send(msg)
    return jsonify({'message': f'Invitation sent to {email}'}), 200

@app.route('/access/<token>', methods=['GET', 'POST'])
def access_portal(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=600)
    except (SignatureExpired, BadSignature):
        return jsonify({'error': 'Invalid or expired link.'}), 403

    if request.method == 'POST':
        password = request.json.get('password')
        if not password:
            return jsonify({'error': 'Password required.'}), 400

        stored = invites.get(email)
        if stored and check_password_hash(stored['password'], password):
            return jsonify({'message': f'Access granted for {email}'}), 200
        else:
            return jsonify({'error': 'Invalid password'}), 401

    return jsonify({'message': 'POST your password to verify'}), 200

if __name__ == '__main__':
    app.run(debug=True)
