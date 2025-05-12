from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone  # Add this import for UTC timezone
import os
from markupsafe import Markup
from werkzeug.utils import secure_filename  # Make sure this import is included
import time

# Import the avatar handler
from avatar_handler import save_avatar, get_avatar, allowed_file

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gtrucks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Define the upload folder and allowed extensions
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'avatars')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Add this config to your Flask app configuration
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max file size

# Ensure the upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configure CSRF protection
# csrf = CSRFProtect(app)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # admin, user, collector
    address = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    barangay_id = db.Column(db.Integer, db.ForeignKey('barangay.id'))

class Barangay(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    district = db.Column(db.Integer, nullable=False)  # 1-6
    users = db.relationship('User', backref='barangay', lazy=True)
    collectors = db.relationship('Collector', backref='assigned_barangay', lazy=True)
    schedules = db.relationship('Schedule', backref='barangay', lazy=True)

class Collector(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    barangay_id = db.Column(db.Integer, db.ForeignKey('barangay.id'))
    vehicle_id = db.Column(db.String(50))
    is_active = db.Column(db.Boolean, default=True)
    current_lat = db.Column(db.Float)
    current_lng = db.Column(db.Float)
    last_updated = db.Column(db.DateTime)
    user = db.relationship('User', backref='collector_profile')

class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    barangay_id = db.Column(db.Integer, db.ForeignKey('barangay.id'), nullable=False)
    collector_id = db.Column(db.Integer, db.ForeignKey('collector.id'), nullable=False)
    day_of_week = db.Column(db.String(20), nullable=False)  # Monday, Tuesday, etc.
    time_start = db.Column(db.Time, nullable=False)
    time_end = db.Column(db.Time, nullable=False)
    status = db.Column(db.String(20), default='scheduled')  # scheduled, in-progress, completed
    collector = db.relationship('Collector', backref='schedules')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    is_read = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref='notifications')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create all database tables before first request
with app.app_context():
    db.create_all()
    # Check if admin exists
    admin = User.query.filter_by(user_type='admin').first()
    if not admin:
        # Create admin user
        admin = User(
            username='admin',
            email='admin@gtrucks.com',
            password=generate_password_hash('admin123'),
            user_type='admin'
        )
        db.session.add(admin)
        # Create districts and sample barangays
        districts = {
            1: ["Alicia", "Bagong Pag-asa", "Bahay Toro"],
            2: ["Bagumbayan", "Baesa", "Banlat"],
            3: ["Amihan", "Bagumbuhay", "Bagong Lipunan"],
            4: ["Bagong Silang", "Nagkaisang Nayon", "Novaliches Proper"],
            5: ["Bagbag", "Capri", "Fairview"],
            6: ["Apolonio Samson", "Baesa", "Balumbato"]
        }
        for district, barangays in districts.items():
            for barangay_name in barangays:
                barangay = Barangay(name=barangay_name, district=district)
                db.session.add(barangay)
        db.session.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.user_type == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.user_type == 'collector':
                return redirect(url_for('collector_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        barangay_id = request.form.get('barangay')
        # Check if user exists
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        user = User(
            username=username,
            email=email,
            password=hashed_password,
            user_type='user',
            barangay_id=barangay_id
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    try:
        barangays = Barangay.query.all()
        if not barangays:
            # If no barangays found, try initializing the database
            with app.app_context():
                from init_db import init_database
                init_database()
            barangays = Barangay.query.all()
    except Exception as e:
        flash(f'Error loading barangays: {str(e)}. Please try running init_db.py first.')
        barangays = []
    return render_template('register.html', barangays=barangays)

# Admin routes
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    users_count = User.query.filter_by(user_type='user').count()
    collectors_count = Collector.query.count()
    barangays_count = Barangay.query.count()
    return render_template('admin/dashboard.html', 
                          users_count=users_count, 
                          collectors_count=collectors_count, 
                          barangays_count=barangays_count)

@app.route('/admin/barangays', methods=['GET', 'POST'])
@login_required
def admin_barangays():
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form.get('name')
        district = request.form.get('district')
        barangay = Barangay(name=name, district=district)
        db.session.add(barangay)
        db.session.commit()
        flash('Barangay added successfully')
        return redirect(url_for('admin_barangays'))
    barangays = Barangay.query.all()
    return render_template('admin/barangays.html', barangays=barangays)

@app.route('/admin/barangays/edit/<int:barangay_id>', methods=['POST'])
@login_required
def admin_barangays_edit(barangay_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    barangay = Barangay.query.get_or_404(barangay_id)
    barangay.name = request.form.get('name')
    barangay.district = int(request.form.get('district'))
    db.session.commit()
    flash('Barangay updated successfully')
    return redirect(url_for('admin_barangays'))

@app.route('/admin/barangays/delete/<int:barangay_id>', methods=['POST'])
@login_required
def admin_barangays_delete(barangay_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    barangay = Barangay.query.get_or_404(barangay_id)
    # Check if barangay has associated users or collectors
    if barangay.users or barangay.collectors:
        flash('Cannot delete barangay with associated users or collectors')
        return redirect(url_for('admin_barangays'))
    db.session.delete(barangay)
    db.session.commit()
    flash('Barangay deleted successfully')
    return redirect(url_for('admin_barangays'))

@app.route('/admin/collectors', methods=['GET', 'POST'])
@login_required
def admin_collectors():
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        barangay_id = request.form.get('barangay')
        vehicle_id = request.form.get('vehicle_id')
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists')
            return redirect(url_for('admin_collectors'))
        hashed_password = generate_password_hash(password)
        user = User(
            username=username,
            email=email,
            password=hashed_password,
            user_type='collector',
            barangay_id=barangay_id
        )
        db.session.add(user)
        db.session.commit()
        collector = Collector(
            user_id=user.id,
            barangay_id=barangay_id,
            vehicle_id=vehicle_id
        )
        db.session.add(collector)
        db.session.commit()
        flash('Collector registered successfully')
        return redirect(url_for('admin_collectors'))
    collectors = Collector.query.all()
    barangays = Barangay.query.all()
    return render_template('admin/collectors.html', collectors=collectors, barangays=barangays)

@app.route('/admin/collectors/edit/<int:collector_id>', methods=['POST'])
@login_required
def admin_collectors_edit(collector_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    collector = Collector.query.get_or_404(collector_id)
    user = User.query.get(collector.user_id)
    # Update user email
    user.email = request.form.get('email')
    # Update collector info
    collector.barangay_id = request.form.get('barangay')
    collector.vehicle_id = request.form.get('vehicle_id')
    collector.is_active = request.form.get('status') == 'active'
    db.session.commit()
    flash('Collector information updated successfully')
    return redirect(url_for('admin_collectors'))

@app.route('/admin/collectors/delete/<int:collector_id>', methods=['POST'])
@login_required
def admin_collectors_delete(collector_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    collector = Collector.query.get_or_404(collector_id)
    user = User.query.get(collector.user_id)
    # Delete associated schedules first if they exist
    Schedule.query.filter_by(collector_id=collector.id).delete()
    # Delete collector
    db.session.delete(collector)
    # Delete associated user
    db.session.delete(user)
    db.session.commit()
    flash('Collector deleted successfully')
    return redirect(url_for('admin_collectors'))

@app.route('/admin/collectors/reset-password/<int:collector_id>', methods=['POST'])
@login_required
def admin_collectors_reset_password(collector_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    collector = Collector.query.get_or_404(collector_id)
    user = User.query.get(collector.user_id)
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    if new_password != confirm_password:
        flash('Passwords do not match')
        return redirect(url_for('admin_collectors'))
    user.password = generate_password_hash(new_password)
    db.session.commit()
    flash('Password reset successfully')
    return redirect(url_for('admin_collectors'))

@app.route('/admin/schedules', methods=['GET', 'POST'])
@login_required
def admin_schedules():
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    if request.method == 'POST':
        barangay_id = request.form.get('barangay')
        collector_id = request.form.get('collector')
        day_of_week = request.form.get('day_of_week')
        time_start = request.form.get('time_start')
        time_end = request.form.get('time_end')
        schedule = Schedule(
            barangay_id=barangay_id,
            collector_id=collector_id,
            day_of_week=day_of_week,
            time_start=datetime.strptime(time_start, '%H:%M').time(),
            time_end=datetime.strptime(time_end, '%H:%M').time()
        )
        db.session.add(schedule)
        db.session.commit()
        flash('Collection schedule added successfully')
        return redirect(url_for('admin_schedules'))
    schedules = Schedule.query.all()
    collectors = Collector.query.all()
    barangays = Barangay.query.all()
    return render_template('admin/schedules.html', schedules=schedules, collectors=collectors, barangays=barangays)

@app.route('/admin/schedules/edit/<int:schedule_id>', methods=['POST'])
@login_required
def admin_schedules_edit(schedule_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    schedule = Schedule.query.get_or_404(schedule_id)
    # Update schedule info
    schedule.barangay_id = request.form.get('barangay')
    schedule.collector_id = request.form.get('collector')
    schedule.day_of_week = request.form.get('day_of_week')
    schedule.time_start = datetime.strptime(request.form.get('time_start'), '%H:%M').time()
    schedule.time_end = datetime.strptime(request.form.get('time_end'), '%H:%M').time()
    schedule.status = request.form.get('status')
    db.session.commit()
    flash('Schedule updated successfully')
    return redirect(url_for('admin_schedules'))

@app.route('/admin/schedules/delete/<int:schedule_id>', methods=['POST'])
@login_required
def admin_schedules_delete(schedule_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    schedule = Schedule.query.get_or_404(schedule_id)
    db.session.delete(schedule)
    db.session.commit()
    flash('Schedule deleted successfully')
    return redirect(url_for('admin_schedules'))

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    users = User.query.filter_by(user_type='user').all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/add', methods=['POST'])
@login_required
def admin_users_add():
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    barangay_id = request.form.get('barangay')
    is_active = 'is_active' in request.form
    # Check if user exists
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        flash('Username or email already exists')
        return redirect(url_for('admin_users'))
    hashed_password = generate_password_hash(password)
    user = User(
        username=username,
        email=email,
        password=hashed_password,
        user_type='user',
        barangay_id=barangay_id,
        is_active=is_active
    )
    db.session.add(user)
    db.session.commit()
    flash('User added successfully')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/edit/<int:user_id>', methods=['POST'])
@login_required
def admin_users_edit(user_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    user = User.query.get_or_404(user_id)
    # Don't allow editing admins if not an admin
    if user.user_type == 'admin' and current_user.id != user.id:
        flash('You cannot edit admin users')
        return redirect(url_for('admin_users'))
    user.email = request.form.get('email')
    user.barangay_id = request.form.get('barangay')
    user.is_active = 'is_active' in request.form
    db.session.commit()
    flash('User updated successfully')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/reset-password/<int:user_id>', methods=['POST'])
@login_required
def admin_users_reset_password(user_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    user = User.query.get_or_404(user_id)
    # Don't allow resetting admin passwords if not an admin
    if user.user_type == 'admin' and current_user.id != user.id:
        flash('You cannot reset admin passwords')
        return redirect(url_for('admin_users'))
    new_password = request.form.get('new_password')
    user.password = generate_password_hash(new_password)
    db.session.commit()
    flash('Password reset successfully')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def admin_users_delete(user_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    user = User.query.get_or_404(user_id)
    # Don't allow deleting admins
    if user.user_type == 'admin':
        flash('Admin users cannot be deleted')
        return redirect(url_for('admin_users'))
    # Check if user is a collector and handle that relationship
    collector = Collector.query.filter_by(user_id=user.id).first()
    if collector:
        # Delete associated schedules
        Schedule.query.filter_by(collector_id=collector.id).delete()
        # Delete collector
        db.session.delete(collector)
    # Delete notifications
    Notification.query.filter_by(user_id=user.id).delete()
    # Finally delete user
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully')
    return redirect(url_for('admin_users'))

@app.route('/admin/tracking')
@login_required
def admin_tracking():
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    collectors = Collector.query.filter_by(is_active=True).all()
    return render_template('admin/tracking.html', collectors=collectors)

@app.route('/admin/reports')
@login_required
def admin_reports():
    if current_user.user_type != 'admin':
        return redirect(url_for('index'))
    return render_template('admin/reports.html')

# User routes
@app.route('/user')
@login_required
def user_dashboard():
    if current_user.user_type != 'user':
        return redirect(url_for('index'))
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    schedules = Schedule.query.filter_by(barangay_id=current_user.barangay_id).all()
    return render_template('user/dashboard.html', notifications=notifications, schedules=schedules)

@app.route('/user/profile')
@login_required
def user_profile():
    if current_user.user_type != 'user':
        return redirect(url_for('index'))
    # Get avatar path
    avatar_path = get_avatar(app.root_path, current_user.id)
    
    # Add timestamp for cache busting
    now = int(time.time())
    
    return render_template('user/profile.html', avatar_path=avatar_path, now=now)

@app.route('/user/tracking')
@login_required
def user_tracking():
    if current_user.user_type != 'user':
        return redirect(url_for('index'))
    
    collectors = Collector.query.filter_by(barangay_id=current_user.barangay_id, is_active=True).all()
    return render_template('user/tracking.html', collectors=collectors)

@app.route('/user/notifications')
@login_required
def user_notifications():
    if current_user.user_type != 'user':
        return redirect(url_for('index'))
    
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    
    # Mark notifications as read
    unread = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    for notification in unread:
        notification.is_read = True
    
    db.session.commit()
    
    return render_template('user/notifications.html', notifications=notifications)

@app.route('/user/schedule')
@login_required
def user_schedule():
    if current_user.user_type != 'user':
        return redirect(url_for('index'))
    
    # Get user's barangay
    barangay_id = current_user.barangay_id
    
    # Get all schedules for this user's barangay
    schedules = Schedule.query.filter_by(barangay_id=barangay_id).order_by(Schedule.day_of_week).all()
    
    return render_template('user/schedule.html', schedules=schedules)

# API routes
@app.route('/api/update-location', methods=['POST'])
@login_required
def update_location():
    if current_user.user_type != 'collector':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    collector = Collector.query.filter_by(user_id=current_user.id).first()
    
    if collector:
        collector.current_lat = data.get('lat')
        collector.current_lng = data.get('lng')
        collector.last_updated = datetime.now(timezone.utc)
        db.session.commit()
        
        # Notify users in the same barangay
        users = User.query.filter_by(barangay_id=collector.barangay_id, user_type='user').all()
        for user in users:
            notification = Notification(
                user_id=user.id,
                message=f"Waste collection truck is now at {data.get('location_name')}"
            )
            db.session.add(notification)
        
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Collector not found'}), 404

@app.route('/api/collectors-location')
def collectors_location():
    collectors = Collector.query.filter_by(is_active=True).all()
    result = []
    
    for collector in collectors:
        if collector.current_lat and collector.current_lng:
            user = User.query.get(collector.user_id)
            barangay = Barangay.query.get(collector.barangay_id)
            
            result.append({
                'id': collector.id,
                'name': user.username if user else 'Unknown',
                'vehicle_id': collector.vehicle_id,
                'barangay': barangay.name if barangay else 'Unassigned',
                'lat': collector.current_lat,
                'lng': collector.current_lng,
                'last_updated': collector.last_updated.strftime('%Y-%m-%d %H:%M:%S') if collector.last_updated else None
            })
    
    return jsonify(result)

# Collector routes
@app.route('/collector')
@login_required
def collector_dashboard():
    if current_user.user_type != 'collector':
        return redirect(url_for('index'))
    
    collector = Collector.query.filter_by(user_id=current_user.id).first()
    schedules = Schedule.query.filter_by(collector_id=collector.id).all()
    
    return render_template('collector/dashboard.html', collector=collector, schedules=schedules)

@app.route('/collector/update-status', methods=['POST'])
@login_required
def update_status():
    if current_user.user_type != 'collector':
        return redirect(url_for('index'))
    
    collector = Collector.query.filter_by(user_id=current_user.id).first()
    status = request.form.get('status')
    
    if status == 'active':
        collector.is_active = True
    else:
        collector.is_active = False
    
    db.session.commit()
    flash('Status updated successfully')
    return redirect(url_for('collector_dashboard'))

@app.route('/collector/schedules')
@login_required
def collector_schedules():
    if current_user.user_type != 'collector':
        return redirect(url_for('index'))
    
    collector = Collector.query.filter_by(user_id=current_user.id).first()
    if not collector:
        flash('Collector profile not found')
        return redirect(url_for('logout'))
    
    # Get all schedules for this collector
    schedules = Schedule.query.filter_by(collector_id=collector.id).order_by(Schedule.day_of_week).all()
    
    return render_template('collector/schedules.html', collector=collector, schedules=schedules)

@app.route('/collector/reports')
@login_required
def collector_reports():
    if current_user.user_type != 'collector':
        return redirect(url_for('index'))
    
    collector = Collector.query.filter_by(user_id=current_user.id).first()
    if not collector:
        flash('Profile not found. Please contact administrator.')
        return redirect(url_for('collector_dashboard'))
    
    # Add current date/time for the template
    now = datetime.now()
    
    # Get avatar using the helper function
    avatar_path = get_avatar(app.root_path, current_user.id) if 'get_avatar' in globals() else None
    
    return render_template('collector/reports.html', collector=collector, now=now, avatar_path=avatar_path)

# Update the collector_profile route to handle both GET and POST requests including password changes
@app.route('/collector/profile', methods=['GET', 'POST'])
@login_required
def collector_profile():
    if current_user.user_type != 'collector':
        return redirect(url_for('index'))
    
    collector = Collector.query.filter_by(user_id=current_user.id).first()
    if not collector:
        flash('Profile not found. Please contact administrator.')
        return redirect(url_for('collector_dashboard'))
    
    # Handle form submission
    if request.method == 'POST':
        try:
            # Check which form was submitted
            form_type = request.form.get('form_type', 'profile_update')
            
            if form_type == 'password_change':
                # Handle password change
                current_password = request.form.get('currentPassword')
                new_password = request.form.get('newPassword')
                confirm_password = request.form.get('confirmPassword')
                
                user = User.query.get(current_user.id)
                
                # Validate input
                if not current_password or not new_password or not confirm_password:
                    flash('All password fields are required')
                elif not check_password_hash(user.password, current_password):
                    flash('Current password is incorrect')
                elif new_password != confirm_password:
                    flash('New passwords do not match')
                else:
                    # Update password
                    user.password = generate_password_hash(new_password)
                    db.session.commit()
                    flash('Password updated successfully!')
            else:
                # Handle profile update (existing functionality)
                if 'name' in request.form:
                    collector.name = request.form.get('name')
                if 'phone' in request.form:
                    collector.phone = request.form.get('phone')
                # Add other fields as needed
                
                db.session.commit()
                flash('Profile updated successfully!')
                
        except Exception as e:
            flash(f'Error updating profile: {str(e)}')
            print(f"Error updating profile: {str(e)}")
            return redirect(url_for('collector_profile'))
    
    # Get avatar path
    avatar_path = get_avatar(app.root_path, current_user.id)
    print(f"Collector profile: avatar_path={avatar_path}")
    
    # Add timestamp for cache busting
    now = int(time.time())
    
    # Display the profile form (GET request)
    return render_template('collector/profile.html', collector=collector, avatar_path=avatar_path, now=now)

# Avatar upload route
@app.route('/upload-avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('No file part')
        return redirect(url_for('user_profile') if current_user.user_type == 'user' else url_for('collector_profile'))
    
    file = request.files['avatar']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('user_profile') if current_user.user_type == 'user' else url_for('collector_profile'))
    
    if file and allowed_file(file.filename):
        try:
            # Use avatar handler to save the file
            filename = save_avatar(app.root_path, current_user.id, file)
            
            if filename:
                flash('Avatar updated successfully!')
            else:
                flash('Error saving avatar. Please try again.')
                
        except Exception as e:
            flash(f'Error updating avatar: {str(e)}')
            print(f"Error saving avatar: {str(e)}")
    
        # Force browser to bypass cache by adding timestamp
        redirect_url = url_for(
            'user_profile' if current_user.user_type == 'user' else 'collector_profile', 
            _t=int(time.time())
        )
        return redirect(redirect_url)
    
    flash('Invalid file type. Please use JPG, PNG or GIF.')
    return redirect(url_for('user_profile') if current_user.user_type == 'user' else url_for('collector_profile'))

# API routes for collector
@app.route('/api/collector/update-location', methods=['POST'])
@login_required
def update_collector_location():
    if current_user.user_type != 'collector':
        return jsonify({'error': 'Unauthorized'}), 401
    
    collector = Collector.query.filter_by(user_id=current_user.id).first()
    if not collector:
        return jsonify({'error': 'Collector not found'}), 404
    
    data = request.json
    collector.current_lat = data.get('lat')
    collector.current_lng = data.get('lng')
    collector.last_updated = datetime.now(timezone.utc)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/collector/set-active', methods=['POST'])
@login_required
def set_collector_active():
    if current_user.user_type != 'collector':
        return jsonify({'error': 'Unauthorized'}), 401
    
    collector = Collector.query.filter_by(user_id=current_user.id).first()
    if not collector:
        return jsonify({'error': 'Collector not found'}), 404
    
    data = request.json
    collector.is_active = data.get('active', False)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/collector/update-schedule-status', methods=['POST'])
@login_required
def update_schedule_status():
    if current_user.user_type != 'collector':
        return jsonify({'error': 'Unauthorized'}), 401
    
    collector = Collector.query.filter_by(user_id=current_user.id).first()
    if not collector:
        return jsonify({'error': 'Collector not found'}), 404
    
    data = request.json
    schedule_id = data.get('schedule_id')
    status = data.get('status')
    schedule = Schedule.query.get(schedule_id)
    if not schedule or schedule.collector_id != collector.id:
        return jsonify({'error': 'Schedule not found or not authorized'}), 404
    
    schedule.status = status
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/collector/report-issue', methods=['POST'])
@login_required
def report_issue():
    if current_user.user_type != 'collector':
        return jsonify({'error': 'Unauthorized'}), 401
    
    collector = Collector.query.filter_by(user_id=current_user.id).first()
    if not collector:
        return jsonify({'error': 'Collector not found'}), 404
    
    # In a real implementation, we would save the issue to the database
    # For now, we'll just return success
    return jsonify({'success': True})

@app.route('/setup')
def setup():
    # Create database and tables
    db.create_all()
    
    # Check if admin exists
    admin = User.query.filter_by(user_type='admin').first()
    if not admin:
        # Create admin user
        admin = User(
            username='admin',
            email='admin@gtrucks.com',
            password=generate_password_hash('admin123'),
            user_type='admin'
        )
        db.session.add(admin)
        
        # Create districts and some sample barangays
        districts = {
            1: ["Alicia", "Bagong Pag-asa", "Bahay Toro", "Balingasa", "Damar", "Damayan", "Katipunan", "Mariblo", "Masambong", "Paltok", "Paraiso", "Phil-Am", "Project 6", "Ramon Magsaysay", "Saint Peter", "Talayan", "Tandang Sora", "Veterans Village", "West Triangle"],
            2: ["Bagumbayan", "Baesa", "Banlat", "Capri", "Central", "Commonwealth", "Culiat", "Damayang Lagi", "E. Rodriguez", "East Kamias", "Escopa 1", "Escopa 2", "Escopa 3", "Escopa 4", "Fair View", "Kalusugan", "Kamuning", "Kaunlaran", "Kristong Hari", "Krus Na Ligas", "Laging Handa", "Mangga", "Mariana", "Masagana", "Milagrosa", "New Era", "Novaliches Proper", "Obrero", "Old Capitol Site", "Pag-ibig sa Nayon", "Paligsahan", "Pinyahan", "Quirino 2-A", "Quirino 2-B", "Quirino 2-C", "Quirino 3-A", "Roxas", "Sacred Heart", "Saint Ignatius", "Salvacion", "San Isidro Galas", "San Jose", "San Martin de Porres", "San Roque", "Santa Cruz", "Santa Teresita", "Santo Domingo", "Santol", "Sienna", "Silangan", "Socorro", "South Triangle", "Tagumpay", "Teacher's Village East", "Teacher's Village West", "U.P. Campus", "U.P. Village", "Ugong Norte", "Valencia", "West Kamias"],
            3: ["Amihan", "Bagumbuhay", "Bagong Lipunan", "Bagong Silangan", "Batasan Hills", "Claro", "Commonwealth", "Fairview", "Nagkaisang Nayon", "Pasong Putik", "Payatas", "Matandang Balara", "Vatican", "Loyola Heights"],
            4: ["Bagong Silang", "Nagkaisang Nayon", "Novaliches Proper", "Pasong Putik", "Gulod", "Sta. Monica", "Kaligayahan", "Greater Lagro", "North Fairview", "Fairview", "San Agustin", "San Bartolome", "Tullahan"],
            5: ["Bagbag", "Capri", "Fairview", "Greater Lagro", "Guilod", "Kaligayahan", "Nagkaisang Nayon", "Novaliches Proper", "Pasong Putik", "San Bartolome", "Santa Lucia", "Santa Monica", "San Agustin"],
            6: ["Apolonio Samson", "Baesa", "Balumbato", "Culiat", "New Era", "Pasong Tamo", "Sangandaan", "Sauyo", "Talipapa", "Tandang Sora", "Unang Sigaw"]
        }
        for district, barangays in districts.items():
            for barangay_name in barangays:
                barangay = Barangay(name=barangay_name, district=district)
                db.session.add(barangay)
        
        db.session.commit()
        
        flash('Setup complete. Admin user created with username: admin, password: admin123')
    else:
        flash('Setup already completed')
    
    return redirect(url_for('index'))

# Define the allowed_file function
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Add a function to get the avatar path for a user
def get_user_avatar(user_id):
    # Get the avatar mapping
    map_file = os.path.join(app.root_path, 'static', 'uploads', 'avatars', 'avatar_mapping.json')
    if not os.path.exists(map_file):
        print(f"Avatar mapping file {map_file} not found")
        return None
    
    try:
        with open(map_file, 'r') as f:
            avatar_map = json.load(f)
            
        avatar_file = avatar_map.get(str(user_id))
        if avatar_file:
            # Verify the file exists
            avatar_path = os.path.join(app.root_path, 'static', 'uploads', 'avatars', avatar_file)
            if (os.path.exists(avatar_path)):
                print(f"Found avatar: {avatar_file}")
                return avatar_file
            else:
                print(f"Avatar file {avatar_path} not found on disk")
                return None
        else:
            print(f"No avatar mapping found for user {user_id}")
            return None
    except Exception as e:
        print(f"Error getting avatar: {str(e)}")
        return None

# Add a context processor to make avatar_path available in all templates
@app.context_processor
def inject_avatar_path():
    if current_user.is_authenticated:
        return {'user_avatar_path': get_user_avatar(current_user.id)}
    return {'user_avatar_path': None}

# Create a context processor to make avatar available in all templates
@app.context_processor
def inject_avatar():
    """Make avatar path available to all templates"""
    if current_user.is_authenticated:
        avatar = get_avatar(app.root_path, current_user.id)
        return {
            'avatar_path': avatar,
            'now': int(time.time())
        }
    return {
        'avatar_path': None, 
        'now': int(time.time())
    }

if __name__ == '__main__':
    app.run(debug=True)
