from flask import Blueprint, request, jsonify
from .models import User, File
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

main = Blueprint('main', __name__)

@main.route('/signup', methods=['POST'])
def signup():
    data = request.json
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=hashed_password,
        role='Client'
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message="User created successfully"), 201

@main.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify(message="Invalid credentials"), 401
    
    token = create_access_token(identity={'id': user.id, 'role': user.role})
    return jsonify(token=token), 200

@main.route('/upload-file', methods=['POST'])
@jwt_required()
def upload_file():
    current_user = get_jwt_identity()
    if current_user['role'] != 'Ops':
        return jsonify(message="Access forbidden"), 403

    file = request.files.get('file')
    if not file or file.filename.split('.')[-1] not in ['pptx', 'docx', 'xlsx']:
        return jsonify(message="Invalid file type"), 400

    file.save(f"./static/{file.filename}")
    new_file = File(file_name=file.filename, uploaded_by=current_user['id'])
    db.session.add(new_file)
    db.session.commit()

    return jsonify(message="File uploaded successfully"), 201
