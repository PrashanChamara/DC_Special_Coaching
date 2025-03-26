import os
import json
import io
from datetime import datetime, date
from flask import (Flask, render_template, redirect, url_for, request, flash,
                   session, jsonify, make_response)
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import case, func, or_
import pandas as pd

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_with_a_strong_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///academy.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png','jpg','jpeg','gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------------------
# Models
# ---------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'sys_admin', 'admin', 'coach'
    full_name = db.Column(db.String(150))
    branch = db.Column(db.String(150))
    email = db.Column(db.String(150))
    profile_photo = db.Column(db.String(200))
    # For coaches only:
    experience = db.Column(db.String(150))
    qualification = db.Column(db.String(150))
    # For coaches: link to the admin officer
    assigned_admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    # Reverse relationship for admin who manage coaches
    coaches = db.relationship('User', backref='admin_officer', remote_side=[id], lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Player(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150))
    branch = db.Column(db.String(150))
    assigned_squad = db.Column(db.String(100))
    date_of_birth = db.Column(db.Date)
    key_features = db.Column(db.Text)
    monthly_review = db.Column(db.Text, default="")
    profile_photo = db.Column(db.String(200))
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payments = db.relationship('Payment', backref='player', lazy=True)
    attendances = db.relationship('Attendance', backref='player', lazy=True)


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey('player.id'), nullable=False)
    payment_number = db.Column(db.String(100), nullable=False)
    total_paid_classes = db.Column(db.Integer, nullable=False)
    payment_amount = db.Column(db.Float, nullable=False, default=0.0)
    classes_used = db.Column(db.Integer, default=0)
    free_extra_used = db.Column(db.Boolean, default=False)
    payment_date = db.Column(db.Date, default=date.today)


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey('player.id'), nullable=False)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    attendance_date = db.Column(db.DateTime, default=datetime.utcnow)
    attendance_type = db.Column(db.String(50), nullable=False)


class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)  # Who performed the action
    action = db.Column(db.String(50), nullable=False)  # "create", "edit", "delete"
    model_name = db.Column(db.String(50), nullable=False)  # "Player", "Payment", etc.
    record_id = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

# ---------------------
# Helper Functions
# ---------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filepath
    return None

def send_notification_email(recipient, subject, message):
    print(f"--- Email Notification ---\nTo: {recipient}\nSubject: {subject}\nMessage: {message}\n--------------------------")

def log_action(user_id, action, model_name, record_id, details):
    log = ActionLog(user_id=user_id, action=action, model_name=model_name,
                    record_id=record_id, details=details)
    db.session.add(log)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_tables():
    db.create_all()
    sys_admin = User.query.filter_by(username='System_Admin', role='sys_admin').first()
    if not sys_admin:
        sys_admin = User(username='System_Admin', role='sys_admin', full_name="System Administrator")
        sys_admin.set_password('Desert_123')
        db.session.add(sys_admin)
        db.session.commit()
        print("Default System_Admin created.")

# ---------------------
# Routes
# ---------------------
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'sys_admin':
        return redirect(url_for('dashboard_sysadmin'))
    elif current_user.role == 'admin':
        return redirect(url_for('dashboard_admin'))
    elif current_user.role == 'coach':
        return redirect(url_for('dashboard_coach'))
    else:
        flash("Role not recognized.", "danger")
        return redirect(url_for('login'))

# ---------------------
# System Admin Routes
# ---------------------
@app.route('/sysadmin/dashboard')
@login_required
def dashboard_sysadmin():
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    total_collections = db.session.query(func.sum(Payment.payment_amount)).scalar() or 0
    paid_total = db.session.query(func.sum(Payment.total_paid_classes)).scalar() or 0
    paid_sessions = db.session.query(func.sum(Payment.classes_used)).scalar() or 0

    unpaid_case = case(
        (Payment.classes_used > Payment.total_paid_classes,
         Payment.classes_used - Payment.total_paid_classes),
        else_=0
    )
    unpaid_sessions = db.session.query(func.sum(unpaid_case)).scalar() or 0

    remaining_case = case(
        (Payment.total_paid_classes > Payment.classes_used,
         Payment.total_paid_classes - Payment.classes_used),
        else_=0
    )
    remaining_sessions = db.session.query(func.sum(remaining_case)).scalar() or 0

    admin_count = User.query.filter(User.role.in_(['sys_admin','admin'])).count()

    return render_template(
        'dashboard_sysadmin.html',
        collections=total_collections,
        paid_total=paid_total,
        paid_sessions=paid_sessions,
        unpaid_sessions=unpaid_sessions,
        remaining_sessions=remaining_sessions,
        admin_count=admin_count
    )

@app.route('/sysadmin/create_admin', methods=['GET', 'POST'])
@login_required
def create_admin():
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        branch = request.form['branch']
        email_addr = request.form['email']
        file = request.files.get('profile_photo')
        photo_path = save_file(file) if file else None

        new_admin = User(username=username, role='admin', full_name=full_name,
                         branch=branch, email=email_addr, profile_photo=photo_path)
        new_admin.set_password(password)
        db.session.add(new_admin)
        db.session.commit()
        log_action(current_user.id, "create", "Admin", new_admin.id, "Created new admin")
        flash("Admin created successfully.", "success")
        return redirect(url_for('dashboard_sysadmin'))

    return render_template('create_admin.html')

# ---------- System Admin Detailed Report ----------
@app.route('/sysadmin/detailed_report', methods=['GET', 'POST'])
@login_required
def sysadmin_detailed_report():
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    start_date_str = request.args.get('start_date', '')
    end_date_str = request.args.get('end_date', '')
    coach_id = request.args.get('coach_id', type=int)
    branch_q = request.args.get('branch', '')

    start_date = None
    end_date = None
    try:
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    except ValueError:
        flash("Invalid date format for date filters.", "warning")

    # Base query
    query = db.session.query(
        Attendance.id.label('att_id'),
        Attendance.attendance_date,
        Attendance.attendance_type,
        Player.full_name.label('player_name'),
        Player.branch.label('player_branch'),
        Player.id.label('player_id'),
        User.full_name.label('coach_name')
    ).join(Player, Attendance.player_id == Player.id)\
     .join(User, Attendance.coach_id == User.id)

    if start_date:
        query = query.filter(func.date(Attendance.attendance_date) >= start_date)
    if end_date:
        query = query.filter(func.date(Attendance.attendance_date) <= end_date)
    if coach_id:
        query = query.filter(User.id == coach_id)
    if branch_q:
        query = query.filter(Player.branch.ilike(f"%{branch_q}%"))

    attendance_records = query.order_by(Attendance.attendance_date.asc()).all()

    from collections import defaultdict
    grouped_attendance = defaultdict(list)
    for row in attendance_records:
        grouped_attendance[row.player_id].append(row)

    data_rows = []
    for pid, att_list in grouped_attendance.items():
        att_list_sorted = sorted(att_list, key=lambda x: x.attendance_date)
        player_payments = Payment.query.filter_by(player_id=pid).order_by(Payment.payment_date.asc()).all()

        payment_allocation = []
        for pay in player_payments:
            payment_allocation.append([pay, pay.total_paid_classes])

        def get_cost_per_session(payment):
            return payment.payment_amount / payment.total_paid_classes if payment.total_paid_classes > 0 else 0

        for att in att_list_sorted:
            if payment_allocation:
                current_payment, available = payment_allocation[0]
                if available > 0:
                    paid_status = "Paid"
                    cost_per_session = get_cost_per_session(current_payment)
                    payment_number = current_payment.payment_number
                    available -= 1
                    payment_allocation[0][1] = available
                    if available == 0:
                        payment_allocation.pop(0)
                else:
                    paid_status = "Unpaid"
                    cost_per_session = 0
                    payment_number = ""
            else:
                paid_status = "Unpaid"
                cost_per_session = 0
                payment_number = ""

            data_rows.append({
                'attendance_date': att.attendance_date.strftime("%Y-%m-%d %H:%M"),
                'player_name': att.player_name,
                'player_branch': att.player_branch,
                'coach_name': att.coach_name,
                'paid_status': paid_status,
                'cost_per_session': round(cost_per_session, 2),
                'payment_number': payment_number
            })

    # Excel export
    if request.args.get('export') == 'excel':
        df = pd.DataFrame(data_rows)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False)

        excel_data = output.getvalue()
        response = make_response(excel_data)
        response.headers["Content-Disposition"] = "attachment; filename=sysadmin_detailed_report.xlsx"
        response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        return response

    coaches_list = User.query.filter_by(role='coach').all()
    return render_template(
        'sysadmin_detailed_report.html',
        data_rows=data_rows,
        start_date_str=start_date_str,
        end_date_str=end_date_str,
        coach_id=coach_id,
        branch=branch_q,
        coaches=coaches_list
    )

# ---------------------
# Admin Routes
# ---------------------
@app.route('/admin/dashboard')
@login_required
def dashboard_admin():
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    coaches = User.query.filter_by(role='coach').all()
    players = Player.query.all()
    coaches_count = len(coaches)
    players_count = len(players)
    today = date.today()
    current_month = today.month
    current_year = today.year

    monthly_collections = db.session.query(
        func.sum(Payment.payment_amount)
    ).filter(
        db.extract('month', Payment.payment_date) == current_month,
        db.extract('year', Payment.payment_date) == current_year
    ).scalar() or 0

    last_month = current_month - 1 if current_month > 1 else 12
    last_year = current_year if current_month > 1 else current_year - 1
    last_month_collections = db.session.query(
        func.sum(Payment.payment_amount)
    ).filter(
        db.extract('month', Payment.payment_date) == last_month,
        db.extract('year', Payment.payment_date) == last_year
    ).scalar() or 0

    return render_template(
        'dashboard_admin.html',
        coaches=coaches,
        coaches_count=coaches_count,
        players_count=players_count,
        monthly_collections=monthly_collections,
        last_month_collections=last_month_collections
    )

@app.route('/admin/coach_report', methods=['GET', 'POST'])
@login_required
def coach_report():
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard_admin'))

    search_q = request.args.get('q', '', type=str)
    page = request.args.get('page', 1, type=int)
    per_page = 10
    start_date_str = request.args.get('start_date', '')
    end_date_str = request.args.get('end_date', '')

    start_date = None
    end_date = None
    try:
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    except ValueError:
        flash("Invalid date format.", "warning")

    data = {}
    selected_coach = None

    if request.method == 'POST':
        coach_id = request.form.get('coach_id')
        return redirect(url_for('coach_report', coach_id=coach_id))

    coach_id = request.args.get('coach_id', type=int)
    if coach_id:
        selected_coach = User.query.get(coach_id)

    if selected_coach:
        query = Player.query.filter_by(coach_id=selected_coach.id)
        if search_q:
            query = query.filter(Player.full_name.ilike(f"%{search_q}%"))

        all_players = query.all()

        total_paid = 0
        total_used = 0
        total_collection = 0.0
        total_unpaid = 0
        total_remaining = 0

        players_data = []
        for player in all_players:
            p_paid = 0
            p_used = 0
            p_amount = 0.0

            payment_query = player.payments
            if start_date:
                payment_query = [p for p in payment_query if p.payment_date >= start_date]
            if end_date:
                payment_query = [p for p in payment_query if p.payment_date <= end_date]

            for payment in payment_query:
                p_paid += payment.total_paid_classes
                p_used += payment.classes_used
                p_amount += payment.payment_amount

            p_remaining = max(0, p_paid - p_used)
            p_unpaid = max(0, p_used - p_paid)

            total_paid += p_paid
            total_used += p_used
            total_collection += p_amount
            total_remaining += p_remaining
            total_unpaid += p_unpaid

            players_data.append({
                'player_id': player.id,
                'player_name': player.full_name,
                'total_paid': p_paid,
                'total_used': p_used,
                'remaining': p_remaining,
                'unpaid': p_unpaid,
                'amount_collected': p_amount
            })

        data = {
            'coach_name': selected_coach.full_name,
            'total_collections': total_collection,
            'paid_sessions': total_used,
            'unpaid_sessions': total_unpaid,
            'remaining_sessions': total_remaining,
            'players': players_data
        }

        # Excel export
        if request.args.get('export') == 'excel':
            df = pd.DataFrame(players_data)
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False)
            excel_data = output.getvalue()

            response = make_response(excel_data)
            response.headers["Content-Disposition"] = "attachment; filename=coach_report.xlsx"
            response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            return response

        total_records = len(players_data)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        players_data_page = players_data[start_idx:end_idx]

        data['players'] = players_data_page
        data['total_pages'] = (total_records + per_page - 1) // per_page
        data['current_page'] = page

    return render_template(
        'coach_report.html',
        data=data,
        coaches=User.query.filter_by(role='coach').all(),
        selected_coach=selected_coach
    )

@app.route('/admin/create_coach', methods=['GET', 'POST'])
@login_required
def create_coach():
    if current_user.role not in ['sys_admin', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        branch = request.form['branch']
        email_addr = request.form['email']
        experience = request.form['experience']
        qualification = request.form['qualification']
        file = request.files.get('profile_photo')
        photo_path = save_file(file) if file else None
        assigned_admin_id = request.form.get('assigned_admin_id')

        coach = User(
            username=username,
            role='coach',
            full_name=full_name,
            branch=branch,
            email=email_addr,
            experience=experience,
            qualification=qualification,
            profile_photo=photo_path,
            assigned_admin_id=assigned_admin_id if assigned_admin_id else None
        )
        coach.set_password(password)
        db.session.add(coach)
        db.session.commit()
        log_action(current_user.id, "create", "Coach", coach.id, "Created new coach")
        flash("Coach created successfully.", "success")
        return redirect(url_for('dashboard_admin'))

    admins = User.query.filter(User.role.in_(['sys_admin','admin'])).all()
    return render_template('create_coach.html', admins=admins)

@app.route('/admin/record_payment', methods=['GET', 'POST'])
@login_required
def record_payment():
    if current_user.role not in ['sys_admin', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        player_id = request.form['player_id']
        payment_number = request.form['payment_number']
        total_paid_classes = int(request.form['total_paid_classes'])
        payment_amount = float(request.form['payment_amount'])

        new_payment = Payment(
            player_id=player_id,
            payment_number=payment_number,
            total_paid_classes=total_paid_classes,
            payment_amount=payment_amount
        )
        db.session.add(new_payment)
        db.session.commit()
        log_action(current_user.id, "create", "Payment", new_payment.id, "Recorded new payment")
        flash("Payment recorded successfully.", "success")
        return redirect(url_for('dashboard_admin'))

    players = Player.query.all()
    return render_template('record_payment.html', players=players)

@app.route('/admin/create_player', methods=['GET', 'POST'])
@login_required
def admin_create_player():
    if current_user.role not in ['admin', 'sys_admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        full_name = request.form['full_name']
        email_addr = request.form['email']
        branch = request.form['branch']
        assigned_squad = request.form['assigned_squad']
        dob_str = request.form['date_of_birth']
        key_features = request.form['key_features']
        coach_id = request.form['coach_id']
        file = request.files.get('profile_photo')
        photo_path = save_file(file) if file else None

        try:
            date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Invalid date format for Date of Birth.", "danger")
            return redirect(url_for('admin_create_player'))

        new_player = Player(
            full_name=full_name,
            email=email_addr,
            branch=branch,
            assigned_squad=assigned_squad,
            date_of_birth=date_of_birth,
            key_features=key_features,
            profile_photo=photo_path,
            coach_id=coach_id
        )
        db.session.add(new_player)
        db.session.commit()
        log_action(current_user.id, "create", "Player", new_player.id, "Created new player")
        flash("Player created successfully.", "success")
        return redirect(url_for('dashboard_admin'))

    coaches = User.query.filter_by(role='coach').all()
    return render_template('create_player.html', coaches=coaches)

# ---------------------
# Coach Routes
# ---------------------
@app.route('/coach/dashboard')
@login_required
def dashboard_coach():
    if current_user.role != 'coach':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    players = Player.query.filter_by(coach_id=current_user.id).all()
    today = date.today()
    current_month = today.month
    current_year = today.year

    attendances = Attendance.query.filter_by(coach_id=current_user.id).all()
    current_month_count = sum(
        1 for a in attendances
        if a.attendance_date.month == current_month and a.attendance_date.year == current_year
    )

    last_month = current_month - 1 if current_month > 1 else 12
    last_year = current_year if current_month > 1 else current_year - 1
    last_month_count = sum(
        1 for a in attendances
        if a.attendance_date.month == last_month and a.attendance_date.year == last_year
    )

    payments = []
    for player in players:
        payments.extend(player.payments)

    payments_current = sum(
        p.payment_amount for p in payments
        if p.payment_date.month == current_month and p.payment_date.year == current_year
    )
    payments_last = sum(
        p.payment_amount for p in payments
        if p.payment_date.month == last_month and p.payment_date.year == last_year
    )

    return render_template(
        'dashboard_coach.html',
        players=players,
        current_month_count=current_month_count,
        last_month_count=last_month_count,
        payments_current=payments_current,
        payments_last=payments_last
    )

@app.route('/coach/create_player', methods=['GET', 'POST'])
@login_required
def create_player():
    if current_user.role != 'coach':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        full_name = request.form['full_name']
        email_addr = request.form['email']
        branch = request.form['branch']
        assigned_squad = request.form['assigned_squad']
        dob_str = request.form['date_of_birth']
        key_features = request.form['key_features']
        file = request.files.get('profile_photo')
        photo_path = save_file(file) if file else None

        try:
            date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Invalid date format.", "danger")
            return redirect(url_for('create_player'))

        new_player = Player(
            full_name=full_name,
            email=email_addr,
            branch=branch,
            assigned_squad=assigned_squad,
            date_of_birth=date_of_birth,
            key_features=key_features,
            profile_photo=photo_path,
            coach_id=current_user.id
        )
        db.session.add(new_player)
        db.session.commit()
        flash("Player created successfully.", "success")
        return redirect(url_for('dashboard_coach'))

    return render_template('create_player.html')

@app.route('/coach/player/<int:player_id>')
@login_required
def player_detail(player_id):
    if current_user.role != 'coach':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    player = Player.query.get_or_404(player_id)
    if player.coach_id != current_user.id:
        flash("You are not authorized to view this player.", "danger")
        return redirect(url_for('dashboard_coach'))

    payments = Payment.query.filter_by(player_id=player.id).all()
    attendances = Attendance.query.filter_by(player_id=player.id).all()

    payment_details = []
    for payment in payments:
        remaining = payment.total_paid_classes - payment.classes_used
        free_extra_available = (remaining <= 0 and not payment.free_extra_used)
        payment_details.append({
            'payment': payment,
            'remaining': remaining,
            'free_extra_available': free_extra_available,
            'total_used': payment.classes_used,
        })

    return render_template(
        'player_detail.html',
        player=player,
        payment_details=payment_details,
        attendances=attendances
    )

@app.route('/coach/record_attendance/<int:player_id>', methods=['GET', 'POST'])
@login_required
def record_attendance(player_id):
    if current_user.role != 'coach':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    player = Player.query.get_or_404(player_id)
    if player.coach_id != current_user.id:
        flash("You are not authorized to record attendance for this player.", "danger")
        return redirect(url_for('dashboard_coach'))

    if request.method == 'POST':
        selected_datetime_str = request.form.get('attendance_datetime')
        if selected_datetime_str:
            try:
                selected_datetime = datetime.strptime(selected_datetime_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                selected_datetime = datetime.utcnow()
        else:
            selected_datetime = datetime.utcnow()

        payments = Payment.query.filter_by(player_id=player.id).order_by(Payment.payment_date.asc()).all()
        active_payment = None
        attendance_type = None

        for pay in payments:
            if pay.classes_used < pay.total_paid_classes:
                active_payment = pay
                attendance_type = 'normal'
                break
            elif pay.classes_used >= pay.total_paid_classes and not pay.free_extra_used:
                active_payment = pay
                attendance_type = 'free_extra'
                break

        if not active_payment:
            flash("No active payment found. Please record a new payment.", "danger")
            return redirect(url_for('player_detail', player_id=player.id))

        if (active_payment.classes_used >= active_payment.total_paid_classes) and active_payment.free_extra_used:
            flash("Attendance blocked: Payment pending. Player has already used the free extra session.", "danger")
            return redirect(url_for('player_detail', player_id=player.id))

        new_attendance = Attendance(
            player_id=player.id,
            coach_id=current_user.id,
            attendance_type=attendance_type,
            attendance_date=selected_datetime
        )
        db.session.add(new_attendance)
        active_payment.classes_used += 1

        if attendance_type == 'free_extra':
            active_payment.free_extra_used = True
            subject = "Extra Session Used"
            message = f"Player {player.full_name} has used the free extra session. Please update payment."
            send_notification_email(player.email, subject, message)
            if current_user.assigned_admin_id:
                admin = User.query.get(current_user.assigned_admin_id)
                send_notification_email(admin.email, subject, message)
        else:
            remaining = active_payment.total_paid_classes - active_payment.classes_used
            if remaining == 1:
                subject = "Low Paid Sessions Warning"
                message = f"Player {player.full_name} has only 1 paid session left."
                send_notification_email(player.email, subject, message)
                if current_user.assigned_admin_id:
                    admin = User.query.get(current_user.assigned_admin_id)
                    send_notification_email(admin.email, subject, message)

        db.session.commit()
        flash("Attendance recorded successfully.", "success")
        return redirect(url_for('player_detail', player_id=player.id))

    return render_template('record_attendance.html', player=player)

@app.route('/coach/update_review/<int:player_id>', methods=['GET', 'POST'])
@login_required
def update_review(player_id):
    if current_user.role != 'coach':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    player = Player.query.get_or_404(player_id)
    if player.coach_id != current_user.id:
        flash("Not authorized.", "danger")
        return redirect(url_for('dashboard_coach'))

    if request.method == 'POST':
        review = request.form.get('monthly_review')
        player.monthly_review = review
        db.session.commit()
        flash("Monthly review updated.", "success")
        return redirect(url_for('player_detail', player_id=player.id))

    return render_template('coach_update_review.html', player=player)

@app.route('/admin/player/<int:player_id>', methods=['GET'])
@login_required
def admin_player_detail(player_id):
    if current_user.role not in ['admin', 'sys_admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    player = Player.query.get_or_404(player_id)

    start_date_str = request.args.get('start_date', '')
    end_date_str = request.args.get('end_date', '')
    start_date = None
    end_date = None
    try:
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    except ValueError:
        flash("Invalid date format.", "warning")

    payments_query = player.payments
    if start_date:
        payments_query = [p for p in payments_query if p.payment_date >= start_date]
    if end_date:
        payments_query = [p for p in payments_query if p.payment_date <= end_date]

    payment_list = []
    total_paid = 0
    total_used = 0
    for pay in payments_query:
        total_paid += pay.total_paid_classes
        total_used += pay.classes_used
        payment_list.append({
            'payment_number': pay.payment_number,
            'payment_date': pay.payment_date.strftime('%Y-%m-%d'),
            'total_paid_classes': pay.total_paid_classes,
            'classes_used': pay.classes_used,
            'payment_amount': pay.payment_amount
        })

    remaining = max(0, total_paid - total_used)
    unpaid = max(0, total_used - total_paid)

    attendance_query = player.attendances
    if start_date:
        attendance_query = [a for a in attendance_query if a.attendance_date.date() >= start_date]
    if end_date:
        attendance_query = [a for a in attendance_query if a.attendance_date.date() <= end_date]

    attendance_list = []
    for att in attendance_query:
        attendance_list.append({
            'attendance_date': att.attendance_date.strftime('%Y-%m-%d %H:%M:%S'),
            'attendance_type': att.attendance_type
        })

    export_type = request.args.get('export')
    if export_type == 'payments':
        # Export Payment DataFrame
        df = pd.DataFrame(payment_list)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False)
        excel_data = output.getvalue()
        response = make_response(excel_data)
        response.headers["Content-Disposition"] = "attachment; filename=player_payments.xlsx"
        response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        return response

    elif export_type == 'attendance':
        # Export Attendance DataFrame
        df = pd.DataFrame(attendance_list)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False)
        excel_data = output.getvalue()
        response = make_response(excel_data)
        response.headers["Content-Disposition"] = "attachment; filename=player_attendance.xlsx"
        response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        return response

    return render_template(
        'admin_player_detail.html',
        player=player,
        payment_list=payment_list,
        attendance_list=attendance_list,
        total_paid=total_paid,
        total_used=total_used,
        remaining=remaining,
        unpaid=unpaid,
        start_date_str=start_date_str,
        end_date_str=end_date_str
    )

# ---------------------
# System Admin: Logs and Manage Records, Edit/Delete Routes
# ---------------------
@app.route('/sysadmin/logs', methods=['GET'])
@login_required
def sysadmin_logs():
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    start_date_str = request.args.get('start_date', '')
    end_date_str = request.args.get('end_date', '')
    model_filter = request.args.get('model', '')
    start_date = None
    end_date = None
    try:
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
    except ValueError:
        flash("Invalid date format.", "warning")

    query = ActionLog.query
    if start_date:
        query = query.filter(ActionLog.timestamp >= start_date)
    if end_date:
        query = query.filter(ActionLog.timestamp <= end_date)
    if model_filter:
        query = query.filter(ActionLog.model_name.ilike(f"%{model_filter}%"))

    logs = query.order_by(ActionLog.timestamp.desc()).all()
    return render_template('logs.html', logs=logs,
                           start_date_str=start_date_str,
                           end_date_str=end_date_str,
                           model_filter=model_filter)

@app.route('/sysadmin/manage_records', methods=['GET', 'POST'])
@login_required
def manage_records():
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    record_type = request.args.get('record_type', 'Player')
    search_term = request.args.get('search', '')
    start_date_str = request.args.get('start_date', '')
    end_date_str = request.args.get('end_date', '')

    start_date = None
    end_date = None
    try:
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    except ValueError:
        flash("Invalid date format.", "warning")

    results = []

    if record_type == 'Player':
        query = Player.query
        if search_term:
            query = query.filter(Player.full_name.ilike(f"%{search_term}%"))
        if start_date and end_date:
            query = query.filter(Player.date_of_birth.between(start_date, end_date))
        results = query.all()

    elif record_type == 'Payment':
        query = Payment.query
        if start_date and end_date:
            query = query.filter(Payment.payment_date.between(start_date, end_date))
        results = query.all()

    elif record_type == 'Admin':
        query = User.query.filter(User.role.in_(['sys_admin','admin']))
        if search_term:
            query = query.filter(User.full_name.ilike(f"%{search_term}%"))
        results = query.all()

    elif record_type == 'Attendance':
        query = Attendance.query
        if start_date and end_date:
            query = query.filter(func.date(Attendance.attendance_date).between(start_date, end_date))
        results = query.all()

    elif record_type == 'Coach':
        query = User.query.filter(User.role == 'coach')
        if search_term:
            query = query.filter(User.full_name.ilike(f"%{search_term}%"))
        results = query.all()

    return render_template('manage_records.html',
                           record_type=record_type,
                           search_term=search_term,
                           start_date_str=start_date_str,
                           end_date_str=end_date_str,
                           results=results)

# Edit/Delete Routes
@app.route('/sysadmin/edit_admin/<int:admin_id>', methods=['GET', 'POST'])
@login_required
def edit_admin(admin_id):
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    admin_obj = User.query.get_or_404(admin_id)
    if admin_obj.role not in ['sys_admin','admin']:
        flash("Cannot edit this user here.", "danger")
        return redirect(url_for('manage_records', record_type='Admin'))

    if request.method == 'POST':
        admin_obj.full_name = request.form['full_name']
        admin_obj.branch = request.form['branch']
        admin_obj.email = request.form['email']

        new_password = request.form.get('new_password', '').strip()
        if new_password:
            admin_obj.set_password(new_password)

        file = request.files.get('profile_photo')
        if file:
            admin_obj.profile_photo = save_file(file)

        db.session.commit()
        log_action(current_user.id, "edit", "Admin", admin_obj.id, "Edited admin details (possibly reset password)")
        flash("Admin updated successfully.", "success")
        return redirect(url_for('manage_records', record_type='Admin'))

    return render_template('edit_admin.html', admin=admin_obj)

@app.route('/sysadmin/delete_admin/<int:admin_id>', methods=['POST'])
@login_required
def delete_admin(admin_id):
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    admin_obj = User.query.get_or_404(admin_id)
    db.session.delete(admin_obj)
    db.session.commit()
    log_action(current_user.id, "delete", "Admin", admin_obj.id, "Deleted admin")
    flash("Admin deleted successfully.", "success")
    return redirect(url_for('manage_records', record_type='Admin'))

@app.route('/sysadmin/edit_player/<int:player_id>', methods=['GET', 'POST'])
@login_required
def edit_player(player_id):
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    player = Player.query.get_or_404(player_id)
    if request.method == 'POST':
        player.full_name = request.form['full_name']
        player.email = request.form['email']
        player.branch = request.form['branch']
        player.assigned_squad = request.form['assigned_squad']

        dob_str = request.form['date_of_birth']
        try:
            player.date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Invalid date format.", "danger")
            return redirect(url_for('edit_player', player_id=player_id))

        player.key_features = request.form['key_features']
        file = request.files.get('profile_photo')
        if file:
            player.profile_photo = save_file(file)

        db.session.commit()
        log_action(current_user.id, "edit", "Player", player.id, "Edited player details")
        flash("Player updated successfully.", "success")
        return redirect(url_for('manage_records', record_type='Player'))

    return render_template('edit_player.html', player=player)

@app.route('/sysadmin/delete_player/<int:player_id>', methods=['POST'])
@login_required
def delete_player(player_id):
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    player = Player.query.get_or_404(player_id)
    db.session.delete(player)
    db.session.commit()
    log_action(current_user.id, "delete", "Player", player.id, "Deleted player")
    flash("Player deleted successfully.", "success")
    return redirect(url_for('manage_records', record_type='Player'))

@app.route('/sysadmin/edit_coach/<int:coach_id>', methods=['GET', 'POST'])
@login_required
def edit_coach(coach_id):
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    coach_obj = User.query.get_or_404(coach_id)
    if coach_obj.role != 'coach':
        flash("Cannot edit non-coach user here.", "danger")
        return redirect(url_for('manage_records', record_type='Coach'))

    if request.method == 'POST':
        coach_obj.full_name = request.form['full_name']
        coach_obj.branch = request.form['branch']
        coach_obj.email = request.form['email']
        coach_obj.experience = request.form['experience']
        coach_obj.qualification = request.form['qualification']

        new_password = request.form.get('new_password', '').strip()
        if new_password:
            coach_obj.set_password(new_password)

        file = request.files.get('profile_photo')
        if file:
            coach_obj.profile_photo = save_file(file)

        db.session.commit()
        log_action(current_user.id, "edit", "Coach", coach_obj.id, "Edited coach details (possibly reset password)")
        flash("Coach updated successfully.", "success")
        return redirect(url_for('manage_records', record_type='Coach'))

    return render_template('edit_coach.html', coach=coach_obj)

@app.route('/sysadmin/delete_coach/<int:coach_id>', methods=['POST'])
@login_required
def delete_coach(coach_id):
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    coach_obj = User.query.get_or_404(coach_id)
    db.session.delete(coach_obj)
    db.session.commit()
    log_action(current_user.id, "delete", "Coach", coach_obj.id, "Deleted coach")
    flash("Coach deleted successfully.", "success")
    return redirect(url_for('manage_records', record_type='Coach'))

@app.route('/sysadmin/edit_payment/<int:payment_id>', methods=['GET', 'POST'])
@login_required
def edit_payment(payment_id):
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    payment = Payment.query.get_or_404(payment_id)
    if request.method == 'POST':
        payment.payment_number = request.form['payment_number']
        payment.total_paid_classes = int(request.form['total_paid_classes'])
        payment.payment_amount = float(request.form['payment_amount'])
        try:
            payment.payment_date = datetime.strptime(request.form['payment_date'], '%Y-%m-%d').date()
        except ValueError:
            flash("Invalid date format.", "danger")
            return redirect(url_for('edit_payment', payment_id=payment_id))

        db.session.commit()
        log_action(current_user.id, "edit", "Payment", payment.id, "Edited payment details")
        flash("Payment updated successfully.", "success")
        return redirect(url_for('manage_records', record_type='Payment'))

    return render_template('edit_payment.html', payment=payment)

@app.route('/sysadmin/delete_payment/<int:payment_id>', methods=['POST'])
@login_required
def delete_payment(payment_id):
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    payment = Payment.query.get_or_404(payment_id)
    db.session.delete(payment)
    db.session.commit()
    log_action(current_user.id, "delete", "Payment", payment.id, "Deleted payment")
    flash("Payment deleted successfully.", "success")
    return redirect(url_for('manage_records', record_type='Payment'))

@app.route('/sysadmin/edit_attendance/<int:attendance_id>', methods=['GET', 'POST'])
@login_required
def edit_attendance(attendance_id):
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    attendance = Attendance.query.get_or_404(attendance_id)
    if request.method == 'POST':
        date_str = request.form['attendance_date']
        try:
            attendance.attendance_date = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            flash("Invalid date format.", "danger")
            return redirect(url_for('edit_attendance', attendance_id=attendance_id))

        attendance.attendance_type = request.form['attendance_type']
        db.session.commit()
        log_action(current_user.id, "edit", "Attendance", attendance.id, "Edited attendance")
        flash("Attendance updated successfully.", "success")
        return redirect(url_for('manage_records', record_type='Attendance'))

    return render_template('edit_attendance.html', attendance=attendance)

@app.route('/sysadmin/delete_attendance/<int:attendance_id>', methods=['POST'])
@login_required
def delete_attendance(attendance_id):
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    attendance = Attendance.query.get_or_404(attendance_id)
    db.session.delete(attendance)
    db.session.commit()
    log_action(current_user.id, "delete", "Attendance", attendance.id, "Deleted attendance")
    flash("Attendance deleted successfully.", "success")
    return redirect(url_for('manage_records', record_type='Attendance'))

@app.route('/sysadmin/edit_monthly_review/<int:player_id>', methods=['GET', 'POST'])
@login_required
def edit_monthly_review(player_id):
    if current_user.role != 'sys_admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    player = Player.query.get_or_404(player_id)
    if request.method == 'POST':
        player.monthly_review = request.form['monthly_review']
        db.session.commit()
        log_action(current_user.id, "edit", "MonthlyReview", player.id, "Edited monthly review")
        flash("Monthly review updated.", "success")
        return redirect(url_for('manage_records', record_type='Player'))

    return render_template('edit_monthly_review.html', player=player)

# ---------------------
# PWA Files
# ---------------------
@app.route('/manifest.json')
def manifest():
    return app.send_static_file('manifest.json')

@app.route('/service-worker.js')
def service_worker():
    return app.send_static_file('service-worker.js')

if __name__ == '__main__':
    with app.app_context():
        create_tables()
    app.run(debug=True)
