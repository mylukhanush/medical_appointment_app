import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# --- APP CONFIGURATION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-very-secret-key-that-you-should-change'


# --- DATABASE CONFIGURATION (FINAL & CORRECTED FOR SPECIAL PASSWORD) ---
# The @ in your password has been correctly encoded to %40.
# This is the only change needed to fix the connection error.
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Bunny%401806@localhost/medical_app'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# --- DATABASE MODELS ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    appointments = db.relationship('Appointment', backref='patient', lazy=True, cascade="all, delete-orphan")


class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.Text, nullable=False)


# --- AUTHENTICATION DECORATORS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


# --- CORE ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists.', 'warning')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['name'] = user.name
            session['role'] = user.role
            flash('Logged in successfully!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# --- ADMIN ROUTES ---
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    all_users = User.query.filter_by(role='user').all()
    all_appointments = db.session.query(Appointment, User).join(User).all()
    return render_template('admin_dashboard.html', users=all_users, appointments=all_appointments)


# --- PATIENT/USER ROUTES ---
@app.route('/dashboard')
@login_required
def user_dashboard():
    if session['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))

    user_id = session['user_id']
    user = User.query.get_or_404(user_id)
    return render_template('user_dashboard.html', appointments=user.appointments)


@app.route('/book', methods=['POST'])
@login_required
def book_appointment():
    date = request.form.get('date')
    time = request.form.get('time')
    reason = request.form.get('reason')
    user_id = session['user_id']

    new_appointment = Appointment(user_id=user_id, date=date, time=time, reason=reason)
    db.session.add(new_appointment)
    db.session.commit()

    flash('Your appointment has been booked!', 'success')
    return redirect(url_for('user_dashboard'))


# --- SETUP FUNCTION ---
def setup_database(app):
    with app.app_context():
        db.create_all()
        # Create a default admin user if one doesn't exist
        if not User.query.filter_by(email='admin@app.com').first():
            hashed_password = generate_password_hash('adminpass', method='pbkdf2:sha256')
            admin = User(name='Admin', email='admin@app.com', password=hashed_password, role='admin')
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created.")
        print("Database tables are ready.")


# --- MAIN EXECUTION ---
if __name__ == '__main__':
    setup_database(app)
    app.run(debug=True, port=5001)