from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import (
    JWTManager, create_access_token,
    verify_jwt_in_request, get_jwt, get_jwt_identity
)
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import timedelta

app = Flask(__name__)


#  CONFIG

app.config["JWT_SECRET_KEY"] = "super-secret-key"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1234@localhost/zerotrust'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

jwt = JWTManager(app)
db = SQLAlchemy(app)

#  DATABASE MODEL

class User(db.Model):
    __tablename__ = "users"

    username = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    last_ip = db.Column(db.String(50))


# PAGES

@app.route('/')
def home():
    return render_template("login.html")

@app.route('/signup-page')
def signup_page():
    return render_template("signup.html")

@app.route('/dashboard-page')
def dashboard_page():
    return render_template("dashboard.html")


# SIGNUP PAGE

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json

    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")

    # Check existing user
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "User already exists"}), 400

    # Admin registration requires existing admin
    if role == "admin":
        admin_username = data.get("admin_username")
        admin_password = data.get("admin_password")

        if not admin_username or not admin_password:
            return jsonify({"msg": "Admin credentials required"}), 400

        admin_user = User.query.filter_by(
            username=admin_username,
            role="admin"
        ).first()

        if not admin_user or admin_user.password != admin_password:
            return jsonify({"msg": "Invalid admin credentials"}), 403

    # Create new user
    new_user = User(
        username=username,
        password=password,
        role=role
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": f"{role.capitalize()} registered successfully"})

# LOGIN API

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"msg": "No data"}), 400

    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()

    if user and user.password == password:

        # ✅ Get IP safely
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        print("User IP:", ip)

        user.last_ip = ip
        db.session.commit()

        token = create_access_token(
            identity=user.username,
            additional_claims={"role": user.role}
        )

        return jsonify({
            "access_token": token,
            "msg": "Login successful"
        })

    return jsonify({"msg": "Invalid credentials"}), 401



#  ZERO TRUST MIDDLEWARE

def zero_trust_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()

        username = get_jwt_identity()
        claims = get_jwt()

        user = User.query.filter_by(username=username).first()

        # Device check
        if not request.headers.get("User-Agent"):
            return jsonify({"msg": "Unknown device"}), 403

        # (Optional) IP check disabled for smooth demo
        if user.last_ip != request.remote_addr:
            return jsonify({"msg": "Suspicious IP detected"}), 403

        print({
            "user": username,
            "role": claims.get("role"),
            "endpoint": request.path
        })

        return fn(*args, **kwargs)
    return wrapper



#  ROLE CHECK

def role_required(role):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            claims = get_jwt()

            if claims.get("role") != role:
                return jsonify({"msg": "Access denied"}), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


#  PROTECTED ROUTES

@app.route('/dashboard')
@zero_trust_required
def dashboard():
    return jsonify({"msg": "User Dashboard Access Granted"})


@app.route('/admin')
@zero_trust_required
@role_required("admin")
def admin():
    return jsonify({"msg": "Admin Access Granted"})


#  DELETE USER (ADMIN ONLY)

@app.route('/delete-user/<username>', methods=['DELETE'])
@zero_trust_required
@role_required("admin")
def delete_user(username):
    user_to_delete = User.query.filter_by(username=username).first()

    if not user_to_delete:
        return jsonify({"msg": "User not found"}), 404

    current_user = get_jwt_identity()

    # Prevent self-delete
    if username == current_user:
        return jsonify({"msg": "You cannot delete yourself"}), 400

    # Prevent deleting other admins
    if user_to_delete.role == "admin":
        return jsonify({"msg": "Cannot delete another admin"}), 403

    db.session.delete(user_to_delete)
    db.session.commit()

    return jsonify({"msg": f"User '{username}' deleted successfully"})



#  INIT DATABASE

@app.route('/init-db')
def init_db():
    db.create_all()

    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", password="123", role="admin")
        user = User(username="user", password="123", role="user")

        db.session.add(admin)
        db.session.add(user)
        db.session.commit()

    return "Database initialized!"


#  RUN

if __name__ == "__main__":
    app.run(debug=True)