import os
from flask import Flask, render_template
from app.config import config_by_name
from app.extensions import db, migrate, login_manager, jwt, cors, mail, make_celery

def create_app(config_name=None):
    """
    Application Factory pattern for initializing Sentinel Pulse.
    """
    # 1. Initialize Flask Application
    app = Flask(__name__, instance_relative_config=True)
    
    # 2. Determine configuration environment
    if not config_name:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    # Load configuration
    app.config.from_object(config_by_name[config_name])
    
    # Ensure instance path directory exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
        
    # 3. Initialize Extensions
    db.init_app(app)
    
    # Configure SQLite pragmas for concurrency
    with app.app_context():
        if "sqlite" in app.config.get("SQLALCHEMY_DATABASE_URI", ""):
            from sqlalchemy import event
            from sqlalchemy.engine import Engine
            import sqlite3
            
            @event.listens_for(Engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                if isinstance(dbapi_connection, sqlite3.Connection):
                    cursor = dbapi_connection.cursor()
                    try:
                        cursor.execute("PRAGMA journal_mode=WAL")
                        cursor.execute("PRAGMA busy_timeout=5000")
                    except sqlite3.OperationalError:
                        pass
                    finally:
                        cursor.close()

    migrate.init_app(app, db)
    login_manager.init_app(app)
    jwt.init_app(app)
    cors.init_app(app, resources=app.config.get('CORS_RESOURCES', {r"/*": {"origins": "*"}}))
    mail.init_app(app)
    
    # Initialize Celery with Flask context
    make_celery(app)
    
    # Configure login manager defaults
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User
        return db.session.get(User, int(user_id))
    
    # 4. Register Blueprints
    from app.blueprints.auth import auth_bp
    from app.blueprints.dashboard import dashboard_bp
    from app.blueprints.threats import threats_bp
    from app.blueprints.incidents import incidents_bp
    from app.blueprints.alerts import alerts_bp
    from app.blueprints.reports import reports_bp
    from app.blueprints.api import api_bp
    from app.blueprints.notifications import notifications_bp
    from app.blueprints.mobile import mobile_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/')
    app.register_blueprint(threats_bp, url_prefix='/threats')
    app.register_blueprint(incidents_bp, url_prefix='/incidents')
    app.register_blueprint(alerts_bp, url_prefix='/alerts')
    app.register_blueprint(reports_bp, url_prefix='/reports')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(notifications_bp, url_prefix='/notifications')
    app.register_blueprint(mobile_bp, url_prefix='/mobile')
    
    # Ensure database tables (like notifications) are created
    with app.app_context():
        from app.models.notification import Notification
        from app.models.report import Report
        from app.models.audit_log import AuditLog
        from app.models.report_schedule import ReportSchedule
        from app.models.mobile_security import MobileSubmission, ThreatIntel
        db.create_all()
        
        # Ensure SQLite tables have the new columns dynamically
        if "sqlite" in app.config.get("SQLALCHEMY_DATABASE_URI", ""):
            try:
                db.session.execute(db.text("ALTER TABLE users ADD COLUMN last_seen_at DATETIME"))
                db.session.commit()
            except Exception:
                db.session.rollback()
            try:
                db.session.execute(db.text("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0 NOT NULL"))
                db.session.commit()
            except Exception:
                db.session.rollback()
            try:
                db.session.execute(db.text("ALTER TABLE users ADD COLUMN lockout_until DATETIME"))
                db.session.commit()
            except Exception:
                db.session.rollback()

    # 5. Register Error Handlers
    register_error_handlers(app)
    
    @app.context_processor
    def inject_notifications():
        from flask_login import current_user
        if current_user and current_user.is_authenticated:
            try:
                from app.services.notification import NotificationService
                unread_count = NotificationService.get_unread_count(current_user.id)
                recent_notifications = NotificationService.get_recent_notifications(current_user.id, limit=5)
                return {
                    'unread_count': unread_count,
                    'notifications': recent_notifications
                }
            except Exception:
                pass
        return {
            'unread_count': 0,
            'notifications': []
        }

    # Custom CSRF Protection
    import secrets
    from flask import session, request, abort

    def generate_csrf_token():
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']

    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=generate_csrf_token)

    @app.context_processor
    def inject_device_mode():
        from flask import session
        from flask_login import current_user
        
        mode = 'desktop'
        if current_user and current_user.is_authenticated:
            if current_user.role == 'Admin':
                mode = session.get('device_mode', 'desktop')
            elif current_user.role in ['Analyst', 'Viewer']:
                mode = 'desktop'
            else:
                mode = 'mobile'
        else:
            mode = session.get('device_mode', 'desktop')
        return dict(device_mode=mode)

    @app.before_request
    def update_last_seen():
        from flask_login import current_user
        from datetime import datetime
        if current_user and current_user.is_authenticated:
            try:
                current_user.last_seen_at = datetime.utcnow()
                db.session.commit()
            except Exception:
                db.session.rollback()

    @app.before_request
    def enforce_device_mode_restrictions():
        from flask import request, redirect, url_for, session, current_app
        from flask_login import current_user
        
        if current_app.config.get('TESTING'):
            return
        if not request.endpoint:
            return
        if request.endpoint in ['static', 'auth.login', 'auth.register', 'auth.logout', 'notifications.poll_notifications', 'dashboard.toggle_device_mode', 'dashboard.realtime_dashboard_api']:
            return
        if request.blueprint in ['api', 'auth']:
            return
        if not current_user or not current_user.is_authenticated:
            return
            
        mode = 'desktop'
        if current_user.role == 'Admin':
            mode = session.get('device_mode', 'desktop')
        elif current_user.role in ['Analyst', 'Viewer']:
            mode = 'desktop'
        else:
            mode = 'mobile'
            
        if mode == 'desktop' and request.blueprint == 'mobile':
            return redirect(url_for('dashboard.index'))
        elif mode == 'mobile' and request.blueprint in ['dashboard', 'threats', 'incidents', 'alerts', 'reports']:
            return redirect(url_for('mobile.dashboard'))

    @app.before_request
    def check_csrf():
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Skip during testing if CSRF protection is disabled
            if app.config.get('TESTING') and not app.config.get('WTF_CSRF_ENABLED', True):
                return
            if request.blueprint == 'api':
                return
            
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            expected_token = session.get('csrf_token')
            
            if not expected_token or not token or not secrets.compare_digest(expected_token, token):
                abort(400, "CSRF token missing or invalid")

    return app


def register_error_handlers(app):
    """Register application-wide error templates."""
    @app.errorhandler(403)
    def forbidden_error(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('errors/500.html'), 500
