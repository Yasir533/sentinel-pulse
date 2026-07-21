from datetime import datetime
import re
from flask import render_template, redirect, url_for, flash, request, Response
from flask_login import login_user, logout_user, login_required, current_user
from app.blueprints.auth import auth_bp
from app.models.user import User
from app.extensions import db
from app.utils import role_required

# Simple regex for email validation
EMAIL_REGEX = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

@auth_bp.route('/register', methods=['GET', 'POST'])
def register() -> str | Response:
    """Handle new operator registration."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # 1. Server-side validations
        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template('auth/register.html')

        if not EMAIL_REGEX.match(email):
            flash("Invalid email address format.", "danger")
            return render_template('auth/register.html')

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template('auth/register.html')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('auth/register.html')

        # 2. Check duplicate username
        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash("Username is already taken.", "danger")
            return render_template('auth/register.html')

        # 3. Check duplicate email
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash("Email address is already registered.", "danger")
            return render_template('auth/register.html')

        # 4. Create and save new user
        new_user = User(username=username, email=email, role='Viewer')
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('auth.login'))
        except Exception:
            db.session.rollback()
            flash("An error occurred during registration. Please try again.", "danger")

    return render_template('auth/register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login() -> str | Response:
    """Handle operator authentication and session creation."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember_me'))

        if not username_or_email or not password:
            flash("Please fill in all fields.", "danger")
            return render_template('auth/login.html')

        # Query user by username or email
        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()

        if user is None or not user.check_password(password):
            from app.services.audit import AuditService
            AuditService.log('User Login Failed', username_or_email, status='Failed')
            flash("Invalid username/email or password.", "danger")
            return render_template('auth/login.html')

        if not user.is_active:
            from app.services.audit import AuditService
            AuditService.log('User Login Blocked (Deactivated)', user.username,
                             status='Failed', username=user.username, role=user.role)
            flash("Your account has been deactivated.", "warning")
            return render_template('auth/login.html')

        # Authenticate and create session
        login_user(user, remember=remember)

        # Update last login timestamp
        user.last_login_at = datetime.utcnow()
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

        from app.services.audit import AuditService
        AuditService.log('User Login', user.username, status='Success',
                         username=user.username, role=user.role)

        flash(f"Welcome back, {user.username}!", "success")
        return redirect(url_for('dashboard.index', show_intro=1))

    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout() -> Response:
    """Terminate the active user session."""
    from app.services.audit import AuditService
    AuditService.log('User Logout', current_user.username, status='Success')
    logout_user()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('auth.login'))

@auth_bp.route('/admin-only')
@login_required
@role_required('Admin')
def admin_only() -> str:
    """RBAC verification endpoint — confirms Admin clearance is enforced."""
    return "Admin Access Granted"
