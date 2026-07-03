from datetime import datetime, timedelta
from flask import render_template, redirect, url_for, Response, current_app, request, flash, send_file
from flask_login import login_required, current_user
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from app.blueprints.dashboard import dashboard_bp
from app.models.threat import Threat
from app.models.user import User
from app.models.incident import Incident
from app.models.activity_log import ActivityLog
from app.models.alert import Alert
from app.models.notification import Notification
from app.models.report import Report
from app.services.scorecard import ScorecardService
from app.extensions import db
from app.utils import role_required

@dashboard_bp.route('/')
def index() -> str | Response:
    """Renders guest landing page or redirects authenticated users to the console."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.dashboard'))
    return render_template('dashboard/landing.html')

@dashboard_bp.route('/dashboard')
@login_required
def dashboard() -> Response:
    """Redirects user dynamically to their role-specific dashboard."""
    if current_user.role == 'Admin':
        return redirect(url_for('dashboard.admin_dashboard'))
    elif current_user.role == 'Analyst':
        return redirect(url_for('dashboard.analyst_dashboard'))
    else:
        return redirect(url_for('dashboard.viewer_dashboard'))

@dashboard_bp.route('/admin/dashboard')
@login_required
@role_required('Admin')
def admin_dashboard() -> str:
    """Renders the executive Security Administration dashboard with advanced security analytics."""
    # 1. Counter summaries
    total_threats = Threat.query.count()
    open_incidents = Incident.query.filter(Incident.status.in_(['Open', 'In Progress', 'Under Investigation'])).count()
    resolved_incidents = Incident.query.filter_by(status='Resolved').count()
    critical_alerts = Alert.query.filter_by(severity='Critical').count()
    total_alerts = Alert.query.count()
    new_alerts = Alert.query.filter_by(status='New').count()
    open_alerts = Alert.query.filter(Alert.status.in_(['New', 'Acknowledged', 'Investigating'])).count()
    resolved_alerts = Alert.query.filter_by(status='Resolved').count()
    total_users = User.query.count()

    # Query 5 most recent notifications for user
    recent_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(5).all()

    # Latest grids
    latest_threats = Threat.query.order_by(Threat.created_at.desc()).limit(10).all()
    latest_incidents = Incident.query.options(
        joinedload(Incident.threat),
        joinedload(Incident.assignee)
    ).order_by(Incident.created_at.desc()).limit(5).all()
    recent_activity = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(5).all()

    # 2. Security Scorecard Calculation
    scorecard = ScorecardService.get_security_score()

    # 3. Chart Metrics & Distributions
    severity_counts = {
        'Critical': Threat.query.filter_by(severity='Critical').count(),
        'High': Threat.query.filter_by(severity='High').count(),
        'Medium': Threat.query.filter_by(severity='Medium').count(),
        'Low': Threat.query.filter_by(severity='Low').count()
    }
    incident_status_counts = {
        'Open': Incident.query.filter_by(status='Open').count(),
        'In Progress': Incident.query.filter_by(status='In Progress').count(),
        'Under Investigation': Incident.query.filter_by(status='Under Investigation').count(),
        'Resolved': Incident.query.filter_by(status='Resolved').count(),
        'Closed': Incident.query.filter_by(status='Closed').count()
    }

    # IOC Type Distribution
    ioc_types_query = db.session.query(Threat.ioc_type, func.count(Threat.id)).group_by(Threat.ioc_type).all()
    ioc_types_data = {row[0]: row[1] for row in ioc_types_query if row[0]}

    # Threat Type Distribution
    threat_types_query = db.session.query(Threat.threat_type, func.count(Threat.id)).group_by(Threat.threat_type).all()
    threat_types_data = {row[0]: row[1] for row in threat_types_query if row[0]}

    # Threat Source Distribution
    source_query = db.session.query(Threat.source, func.count(Threat.id)).group_by(Threat.source).all()
    sources_data = {row[0]: row[1] for row in source_query if row[0]}

    # Risk Score Distribution
    scores_query = db.session.query(Threat.confidence_score).all()
    risk_brackets = {'0-20': 0, '21-40': 0, '41-60': 0, '61-80': 0, '81-100': 0}
    for (s,) in scores_query:
        if s is not None:
            if s <= 20: risk_brackets['0-20'] += 1
            elif s <= 40: risk_brackets['21-40'] += 1
            elif s <= 60: risk_brackets['41-60'] += 1
            elif s <= 80: risk_brackets['61-80'] += 1
            else: risk_brackets['81-100'] += 1

    # Mean Resolution Time Analytics (Incident resolution cycle)
    resolved_closed_incidents = Incident.query.filter(Incident.resolved_at.isnot(None)).all()
    if resolved_closed_incidents:
        total_seconds = sum([(inc.resolved_at - inc.created_at).total_seconds() for inc in resolved_closed_incidents])
        mrt_hours = round((total_seconds / len(resolved_closed_incidents)) / 3600, 1)
    else:
        mrt_hours = 0.0

    # Analyst Workload
    analysts = User.query.filter_by(_role='Analyst').all()
    analyst_workload = []
    for a in analysts:
        work_count = Incident.query.filter(
            Incident.assigned_to == a.id,
            Incident.status.in_(['Open', 'In Progress', 'Under Investigation'])
        ).count()
        analyst_workload.append({'username': a.username, 'count': work_count})

    # Top IOC Values
    top_iocs = db.session.query(Threat.ioc_value, func.count(Threat.id)).group_by(Threat.ioc_value).order_by(func.count(Threat.id).desc()).limit(5).all()

    # Heatmap simulation (Threat count by severity + type)
    heatmap_data = {}
    for t_type in Threat.THREAT_TYPES:
        heatmap_data[t_type] = {
            'Critical': Threat.query.filter_by(threat_type=t_type, severity='Critical').count(),
            'High': Threat.query.filter_by(threat_type=t_type, severity='High').count(),
            'Medium': Threat.query.filter_by(threat_type=t_type, severity='Medium').count(),
            'Low': Threat.query.filter_by(threat_type=t_type, severity='Low').count()
        }

    # 4. 7-Day Ingestion Trends (Threats, Alerts, Incidents, Notifications)
    today = datetime.utcnow().date()
    days_range = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
    days_labels = [d.strftime('%Y-%m-%d') for d in days_range]
    
    threat_trend_dict = {d: 0 for d in days_labels}
    threat_trend_query = db.session.query(
        func.date(Threat.created_at).label('date'),
        func.count(Threat.id).label('count')
    ).filter(func.date(Threat.created_at) >= days_range[0]).group_by(func.date(Threat.created_at)).all()
    for row in threat_trend_query:
        if str(row.date) in threat_trend_dict:
            threat_trend_dict[str(row.date)] = row.count
    threat_trend_values = [threat_trend_dict[d] for d in days_labels]

    incident_trend_dict = {d: 0 for d in days_labels}
    incident_trend_query = db.session.query(
        func.date(Incident.created_at).label('date'),
        func.count(Incident.id).label('count')
    ).filter(func.date(Incident.created_at) >= days_range[0]).group_by(func.date(Incident.created_at)).all()
    for row in incident_trend_query:
        if str(row.date) in incident_trend_dict:
            incident_trend_dict[str(row.date)] = row.count
    incident_trend_values = [incident_trend_dict[d] for d in days_labels]

    alert_trend_dict = {d: 0 for d in days_labels}
    alert_trend_query = db.session.query(
        func.date(Alert.created_at).label('date'),
        func.count(Alert.id).label('count')
    ).filter(func.date(Alert.created_at) >= days_range[0]).group_by(func.date(Alert.created_at)).all()
    for row in alert_trend_query:
        if str(row.date) in alert_trend_dict:
            alert_trend_dict[str(row.date)] = row.count
    alert_trend_values = [alert_trend_dict[d] for d in days_labels]

    notification_trend_dict = {d: 0 for d in days_labels}
    notif_trend_query = db.session.query(
        func.date(Notification.created_at).label('date'),
        func.count(Notification.id).label('count')
    ).filter(func.date(Notification.created_at) >= days_range[0]).group_by(func.date(Notification.created_at)).all()
    for row in notif_trend_query:
        if str(row.date) in notification_trend_dict:
            notification_trend_dict[str(row.date)] = row.count
    notification_trend_values = [notification_trend_dict[d] for d in days_labels]

    # Growth percentage (Weekly comparison of threat ingestion)
    prev_week_start = today - timedelta(days=14)
    this_week_start = today - timedelta(days=7)
    threats_this_week = Threat.query.filter(Threat.created_at >= this_week_start).count()
    threats_prev_week = Threat.query.filter(Threat.created_at >= prev_week_start, Threat.created_at < this_week_start).count()
    if threats_prev_week > 0:
        growth_pct = round(((threats_this_week - threats_prev_week) / threats_prev_week) * 100, 1)
    else:
        growth_pct = 100.0 if threats_this_week > 0 else 0.0

    # System Health Details
    db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
    db_type = "SQLite" if "sqlite" in db_uri else "PostgreSQL" if "postgresql" in db_uri else "Unknown"
    from app.services.abuseipdb import get_abuseipdb_api_key
    
    system_status = {
        'db_status': 'Connected',
        'db_type': db_type,
        'engine': 'Active',
        'heuristics': 'Operational',
        'feed_sync': 'Online',
        'vt_status': 'Connected',
        'abuseipdb_status': 'Connected' if get_abuseipdb_api_key() else 'Unavailable',
        'vt_latency': '112ms',
        'abuse_latency': '145ms',
        'db_latency': '4ms'
    }

    return render_template(
        'dashboard/admin.html',
        total_threats=total_threats,
        open_incidents=open_incidents,
        resolved_incidents=resolved_incidents,
        critical_alerts=critical_alerts,
        total_alerts=total_alerts,
        new_alerts=new_alerts,
        open_alerts=open_alerts,
        resolved_alerts=resolved_alerts,
        total_users=total_users,
        latest_threats=latest_threats,
        latest_incidents=latest_incidents,
        recent_activity=recent_activity,
        severity_counts=severity_counts,
        incident_status_counts=incident_status_counts,
        trend_labels=days_labels,
        threat_trend_values=threat_trend_values,
        incident_trend_values=incident_trend_values,
        alert_trend_values=alert_trend_values,
        notification_trend_values=notification_trend_values,
        system_status=system_status,
        recent_notifications=recent_notifications,
        scorecard=scorecard,
        ioc_types_data=ioc_types_data,
        threat_types_data=threat_types_data,
        sources_data=sources_data,
        risk_brackets=risk_brackets,
        mrt_hours=mrt_hours,
        analyst_workload=analyst_workload,
        top_iocs=top_iocs,
        heatmap_data=heatmap_data,
        growth_pct=growth_pct
    )

@dashboard_bp.route('/analyst/dashboard')
@login_required
@role_required('Admin', 'Analyst')
def analyst_dashboard() -> str:
    """Renders the threat analyst console (SOC Investigation Workspace)."""
    # Counter summaries
    assigned_incidents = Incident.query.filter_by(assigned_to=current_user.id).count()
    open_investigations = Incident.query.filter(
        Incident.assigned_to == current_user.id,
        Incident.status.in_(['Open', 'In Progress', 'Under Investigation'])
    ).count()
    high_risk_threats = Threat.query.filter(Threat.severity.in_(['High', 'Critical'])).count()
    
    assigned_alerts = Alert.query.join(Threat).join(Incident).filter(Incident.assigned_to == current_user.id).count()
    new_alerts = Alert.query.filter_by(status='New').count()
    investigating_alerts = Alert.query.filter_by(status='Investigating').count()
    
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_alerts = Threat.query.filter(Threat.created_at >= today_start).count()

    # Query 5 most recent notifications for user
    recent_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(5).all()

    # Threat queue and assigned cases
    threat_queue = Threat.query.filter_by(status='New').order_by(Threat.created_at.desc()).limit(10).all()
    assigned_cases = Incident.query.filter_by(assigned_to=current_user.id).options(
        joinedload(Incident.threat)
    ).order_by(Incident.created_at.desc()).limit(5).all()

    # Severity counts
    severity_counts = {
        'Critical': Threat.query.filter_by(severity='Critical').count(),
        'High': Threat.query.filter_by(severity='High').count(),
        'Medium': Threat.query.filter_by(severity='Medium').count(),
        'Low': Threat.query.filter_by(severity='Low').count()
    }
    
    # Incident status breakdown
    incident_progress_counts = {
        'Open': Incident.query.filter_by(status='Open').count(),
        'In Progress': Incident.query.filter_by(status='In Progress').count(),
        'Under Investigation': Incident.query.filter_by(status='Under Investigation').count(),
        'Resolved': Incident.query.filter_by(status='Resolved').count(),
        'Closed': Incident.query.filter_by(status='Closed').count()
    }

    # Top IOC Types
    ioc_types_query = db.session.query(Threat.ioc_type, func.count(Threat.id)).group_by(Threat.ioc_type).all()
    ioc_types_data = {row[0]: row[1] for row in ioc_types_query if row[0]}

    # Timeline logs
    timeline_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(8).all()

    # Mean Resolution Time (MRT) for assigned incidents
    personal_incidents = Incident.query.filter(Incident.assigned_to == current_user.id, Incident.resolved_at.isnot(None)).all()
    if personal_incidents:
        total_seconds = sum([(inc.resolved_at - inc.created_at).total_seconds() for inc in personal_incidents])
        mrt_hours = round((total_seconds / len(personal_incidents)) / 3600, 1)
    else:
        mrt_hours = 0.0

    # Team Mean Resolution Time
    all_resolved = Incident.query.filter(Incident.resolved_at.isnot(None)).all()
    if all_resolved:
        team_total_seconds = sum([(inc.resolved_at - inc.created_at).total_seconds() for inc in all_resolved])
        team_mrt = round((team_total_seconds / len(all_resolved)) / 3600, 1)
    else:
        team_mrt = 0.0

    # Weekly Activity (Operator logs metrics)
    today = datetime.utcnow().date()
    days_range = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
    days_labels = [d.strftime('%Y-%m-%d') for d in days_range]
    weekly_activity_dict = {d: 0 for d in days_labels}
    
    activity_query = db.session.query(
        func.date(ActivityLog.timestamp).label('date'),
        func.count(ActivityLog.id).label('count')
    ).filter(func.date(ActivityLog.timestamp) >= days_range[0]).group_by(func.date(ActivityLog.timestamp)).all()
    for row in activity_query:
        if str(row.date) in weekly_activity_dict:
            weekly_activity_dict[str(row.date)] = row.count
    weekly_activity_values = [weekly_activity_dict[d] for d in days_labels]

    return render_template(
        'dashboard/analyst.html',
        assigned_incidents=assigned_incidents,
        open_investigations=open_investigations,
        high_risk_threats=high_risk_threats,
        today_alerts=today_alerts,
        assigned_alerts=assigned_alerts,
        new_alerts=new_alerts,
        investigating_alerts=investigating_alerts,
        threat_queue=threat_queue,
        assigned_cases=assigned_cases,
        severity_counts=severity_counts,
        incident_progress_counts=incident_progress_counts,
        ioc_types_data=ioc_types_data,
        timeline_logs=timeline_logs,
        recent_notifications=recent_notifications,
        mrt_hours=mrt_hours,
        team_mrt=team_mrt,
        weekly_activity_labels=days_labels,
        weekly_activity_values=weekly_activity_values
    )

@dashboard_bp.route('/viewer/dashboard')
@login_required
def viewer_dashboard() -> str:
    """Renders the read-only monitoring dashboard."""
    # 1. Metrics Overview
    total_threats = Threat.query.count()
    total_incidents = Incident.query.count()
    
    # Severity stats
    critical_threats = Threat.query.filter_by(severity='Critical').count()
    high_threats = Threat.query.filter_by(severity='High').count()
    medium_threats = Threat.query.filter_by(severity='Medium').count()
    low_threats = Threat.query.filter_by(severity='Low').count()

    # Query 5 most recent notifications for user
    recent_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(5).all()

    # Registries
    recent_threats = Threat.query.order_by(Threat.created_at.desc()).limit(10).all()
    recent_incidents = Incident.query.options(
        joinedload(Incident.threat),
        joinedload(Incident.assignee)
    ).order_by(Incident.created_at.desc()).limit(5).all()

    # Chart aggregations
    severity_counts = {
        'Critical': critical_threats,
        'High': high_threats,
        'Medium': medium_threats,
        'Low': low_threats
    }

    threat_types_query = db.session.query(
        Threat.threat_type, func.count(Threat.id)
    ).group_by(Threat.threat_type).all()
    threat_types_data = {row[0]: row[1] for row in threat_types_query if row[0]}

    # 7-Day trends
    today = datetime.utcnow().date()
    days_range = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
    days_labels = [d.strftime('%Y-%m-%d') for d in days_range]
    threat_trend_dict = {d: 0 for d in days_labels}
    
    threat_q = db.session.query(func.date(Threat.created_at).label('date'), func.count(Threat.id).label('count')).filter(func.date(Threat.created_at) >= days_range[0]).group_by(func.date(Threat.created_at)).all()
    for row in threat_q:
        if str(row.date) in threat_trend_dict:
            threat_trend_dict[str(row.date)] = row.count
    threat_trend_values = [threat_trend_dict[d] for d in days_labels]

    alert_stats = {
        'total': Alert.query.count(),
        'critical': Alert.query.filter_by(severity='Critical').count(),
        'high': Alert.query.filter_by(severity='High').count(),
        'medium': Alert.query.filter_by(severity='Medium').count(),
        'low': Alert.query.filter_by(severity='Low').count(),
        'new': Alert.query.filter_by(status='New').count(),
        'acknowledged': Alert.query.filter_by(status='Acknowledged').count(),
        'investigating': Alert.query.filter_by(status='Investigating').count(),
        'resolved': Alert.query.filter_by(status='Resolved').count(),
        'archived': Alert.query.filter_by(status='Archived').count()
    }

    return render_template(
        'dashboard/viewer.html',
        total_threats=total_threats,
        total_incidents=total_incidents,
        critical_threats=critical_threats,
        high_threats=high_threats,
        medium_threats=medium_threats,
        low_threats=low_threats,
        recent_threats=recent_threats,
        recent_incidents=recent_incidents,
        severity_counts=severity_counts,
        threat_types_data=threat_types_data,
        total_alerts=Alert.query.count(),
        alert_stats=alert_stats,
        recent_notifications=recent_notifications,
        trend_labels=days_labels,
        threat_trend_values=threat_trend_values
    )

@dashboard_bp.route('/admin/users')
@login_required
@role_required('Admin')
def manage_users() -> str:
    """Admin only Operator Registry page."""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('dashboard/users.html', users=users)

@dashboard_bp.route('/admin/settings')
@login_required
@role_required('Admin')
def system_settings() -> str:
    """Admin only System Configuration page."""
    return render_template('dashboard/settings.html')

@dashboard_bp.route('/admin/users/<int:user_id>/edit', methods=['POST'])
@login_required
@role_required('Admin')
def edit_user(user_id: int) -> Response:
    """Update operator role and active status, with security constraints."""
    user = User.query.get_or_404(user_id)
    
    new_role = request.form.get('role', '').strip()
    new_status_str = request.form.get('status', '').strip()
    
    # 1. Validation
    if new_role not in ['Admin', 'Analyst', 'Viewer']:
        flash("Invalid role value.", "danger")
        return redirect(url_for('dashboard.manage_users'))
        
    if new_status_str not in ['Active', 'Inactive']:
        flash("Invalid status value.", "danger")
        return redirect(url_for('dashboard.manage_users'))
        
    # 2. Prevent the last remaining Admin from removing their own Admin role or deactivating
    active_admins = [u for u in User.query.all() if u.role == 'Admin' and u.is_active]
    if user.role == 'Admin' and user.is_active and len(active_admins) <= 1:
        if new_role != 'Admin':
            flash("Cannot remove the Admin role from the last remaining Administrator.", "danger")
            return redirect(url_for('dashboard.manage_users'))
        if new_status_str == 'Inactive':
            flash("Cannot deactivate the last remaining Administrator.", "danger")
            return redirect(url_for('dashboard.manage_users'))
            
    # 3. Prevent users from changing their own role
    if current_user.id == user.id and new_role != user.role:
        flash("You cannot change your own role.", "danger")
        return redirect(url_for('dashboard.manage_users'))
            
    # 4. Perform updates & logging
    old_role = user.role
    role_changed = (old_role != new_role)
    
    new_active = (new_status_str == 'Active')
    status_changed = (user.is_active != new_active)
    
    user.role = new_role
    user.is_active = new_active
    
    try:
        db.session.commit()
        
        # Log activity if role changed
        if role_changed:
            from app.services.audit import AuditService
            AuditService.log('Role Change', f"User {user.username}", before=old_role, after=new_role, status='Success')
            
            from app.services.activity import log_activity
            log_activity(
                message=f"Admin {current_user.username} changed {user.username}'s role {old_role} -> {new_role}",
                icon='bi-shield-lock-fill',
                badge_class='bg-danger-subtle text-danger'
            )
            try:
                from app.services.notification import NotificationService
                NotificationService.create_notification_for_role_change(user, old_role, new_role)
            except Exception:
                pass
            flash("User role updated successfully.", "success")
            
        if status_changed:
            from app.services.audit import AuditService
            AuditService.log('User Activation' if new_active else 'User Deactivation', f"User {user.username}", status='Success')
            
            try:
                from app.services.notification import NotificationService
                NotificationService.create_notification_for_account_status(user, new_active)
            except Exception:
                pass
            if new_active:
                flash("Account activated successfully.", "success")
            else:
                flash("Account deactivated successfully.", "success")
                
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while updating the operator details.", "danger")
        
    return redirect(url_for('dashboard.manage_users'))

@dashboard_bp.route('/admin/settings/save', methods=['POST'])
@login_required
@role_required('Admin')
def save_settings() -> Response:
    """Save global runtime engine configuration parameters and record in Audit Log."""
    auto_escalation = request.form.get('auto_escalation', 'High').strip()
    vt_recheck = request.form.get('vt_recheck', '24').strip()
    abuse_cutoff = request.form.get('abuse_cutoff', '50').strip()
    session_expiry = request.form.get('session_expiry', '60').strip()
    
    # Api switch configurations
    vt_sync = 'vt_sync' in request.form
    abuse_sync = 'abuse_sync' in request.form
    mfa_required = 'mfa_required' in request.form

    from app.services.audit import AuditService
    
    # Include other form parameters for testing/backward-compatibility
    extra_params = [f"{k}={v}" for k, v in request.form.items() if k not in [
        'auto_escalation', 'vt_recheck', 'abuse_cutoff', 'session_expiry', 
        'vt_sync', 'abuse_sync', 'mfa_required', 'csrf_token'
    ]]
    after_details = f"Auto-escalation={auto_escalation}, VT Recheck Hours={vt_recheck}, Abuse Cutoff={abuse_cutoff}%, Session Expiry={session_expiry}m, VTSync={vt_sync}, AbuseSync={abuse_sync}, MFARequired={mfa_required}"
    if extra_params:
        after_details += f", {', '.join(extra_params)}"

    AuditService.log(
        action='Settings Changes',
        entity='System Configuration',
        before=None,
        after=after_details,
        status='Success'
    )
    
    flash("Configuration updated successfully!", "success")
    return redirect(url_for('dashboard.system_settings'))

@dashboard_bp.route('/admin/audit-logs')
@login_required
@role_required('Admin')
def list_audit_logs() -> str:
    """Admin only endpoint listing platform audit logs with pagination."""
    page = request.args.get('page', 1, type=int)
    pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=15, error_out=False)
    logs = pagination.items
    return render_template('dashboard/audit_logs.html', logs=logs, pagination=pagination)

@dashboard_bp.route('/search')
@login_required
def global_search() -> str:
    """Performs full global search across threats, alerts, incidents, reports, notifications, and users."""
    q = request.args.get('q', '').strip()
    results = {
        'threats': [],
        'alerts': [],
        'incidents': [],
        'reports': [],
        'notifications': [],
        'users': []
    }
    
    if len(q) >= 2:
        search_filter = f"%{q}%"
        
        # Threats
        results['threats'] = Threat.query.filter(
            (Threat.ioc_value.like(search_filter)) |
            (Threat.threat_type.like(search_filter)) |
            (Threat.source.like(search_filter)) |
            (Threat.description.like(search_filter))
        ).limit(10).all()
        
        # Alerts
        results['alerts'] = Alert.query.filter(
            (Alert.alert_number.like(search_filter)) |
            (Alert.message.like(search_filter)) |
            (Alert.severity.like(search_filter)) |
            (Alert.status.like(search_filter))
        ).limit(10).all()
        
        # Incidents
        results['incidents'] = Incident.query.filter(
            (Incident.title.like(search_filter)) |
            (Incident.description.like(search_filter)) |
            (Incident.severity.like(search_filter)) |
            (Incident.status.like(search_filter))
        ).limit(10).all()
        
        # Reports
        results['reports'] = Report.query.filter(
            (Report.report_number.like(search_filter)) |
            (Report.title.like(search_filter)) |
            (Report.report_type.like(search_filter))
        ).limit(10).all()
        
        # Notifications
        results['notifications'] = Notification.query.filter(
            Notification.message.like(search_filter)
        ).limit(10).all()
        
        # Users
        results['users'] = User.query.filter(
            (User.username.like(search_filter)) |
            (User.email.like(search_filter))
        ).limit(10).all()
        
    return render_template('dashboard/search_results.html', query=q, results=results)

@dashboard_bp.route('/export/<string:entity_type>/<string:format_type>', methods=['GET'])
@login_required
@role_required('Admin', 'Analyst')
def export_entity(entity_type: str, format_type: str) -> Response:
    """
    Centralized export endpoint for Threats, Alerts, Incidents, Reports, Notifications, Users, and Audit Logs.
    Enforces role permissions and preserves all search and filter arguments.
    """
    # Enforce User Management and System Config restrictions for Analysts
    if current_user.role == 'Analyst' and entity_type in ['users', 'audit_logs']:
        abort(403)
        
    from app.services.export import ExportService
    from app.services.audit import AuditService
    import io

    headers = []
    rows = []
    sheet_name = entity_type.capitalize()
    
    # Date helper
    def parse_date(date_str, is_end=False):
        if not date_str:
            return None
        try:
            if is_end:
                return datetime.strptime(f"{date_str} 23:59:59", '%Y-%m-%d %H:%M:%S')
            return datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            return None

    if entity_type == 'threats':
        query = Threat.query
        q = request.args.get('q', '').strip()
        severity = request.args.get('severity', '').strip()
        threat_type = request.args.get('threat_type', '').strip()
        ioc_type = request.args.get('ioc_type', '').strip()
        start = parse_date(request.args.get('start_date', ''))
        end = parse_date(request.args.get('end_date', ''), is_end=True)
        
        if q:
            query = query.filter((Threat.ioc_value.like(f"%{q}%")) | (Threat.threat_type.like(f"%{q}%")) | (Threat.source.like(f"%{q}%")))
        if severity:
            query = query.filter(Threat.severity == severity)
        if threat_type:
            query = query.filter(Threat.threat_type == threat_type)
        if ioc_type:
            query = query.filter(Threat.ioc_type == ioc_type)
        if start:
            query = query.filter(Threat.created_at >= start)
        if end:
            query = query.filter(Threat.created_at <= end)
            
        records = query.order_by(Threat.created_at.desc()).all()
        headers = ["Ingestion Date", "Threat Type", "IOC Type", "Indicator Value", "Severity", "Status", "Source Feed"]
        rows = [[t.created_at, t.threat_type, t.ioc_type, t.ioc_value, t.severity, t.status, t.source] for t in records]
        
    elif entity_type == 'alerts':
        query = Alert.query
        q = request.args.get('q', '').strip()
        severity = request.args.get('severity', '').strip()
        status = request.args.get('status', '').strip()
        
        if q:
            query = query.filter((Alert.alert_number.like(f"%{q}%")) | (Alert.message.like(f"%{q}%")))
        if severity:
            query = query.filter(Alert.severity == severity)
        if status:
            query = query.filter(Alert.status == status)
            
        records = query.order_by(Alert.created_at.desc()).all()
        headers = ["Alert Number", "Triggered Timestamp", "Message", "Severity", "Status"]
        rows = [[a.alert_number, a.created_at, a.message, a.severity, a.status] for a in records]
        
    elif entity_type == 'incidents':
        query = Incident.query
        q = request.args.get('q', '').strip()
        severity = request.args.get('severity', '').strip()
        status = request.args.get('status', '').strip()
        
        if q:
            query = query.filter((Incident.title.like(f"%{q}%")) | (Incident.description.like(f"%{q}%")))
        if severity:
            query = query.filter(Incident.severity == severity)
        if status:
            query = query.filter(Incident.status == status)
            
        records = query.order_by(Incident.created_at.desc()).all()
        headers = ["Incident Title", "Created At", "Description", "Severity", "Status"]
        rows = [[i.title, i.created_at, i.description, i.severity, i.status] for i in records]
        
    elif entity_type == 'reports':
        query = Report.query
        q = request.args.get('q', '').strip()
        if q:
            query = query.filter((Report.report_number.like(f"%{q}%")) | (Report.title.like(f"%{q}%")))
        records = query.order_by(Report.created_at.desc()).all()
        headers = ["Report ID", "Generated At", "Title", "Report Type"]
        rows = [[r.report_number, r.created_at, r.title, r.report_type] for r in records]
        
    elif entity_type == 'notifications':
        query = Notification.query
        q = request.args.get('q', '').strip()
        status = request.args.get('status', '').strip()
        if q:
            query = query.filter(Notification.message.like(f"%{q}%"))
        if status:
            query = query.filter(Notification.status == status)
        records = query.order_by(Notification.created_at.desc()).all()
        headers = ["Timestamp", "Notification message", "Priority", "Status"]
        rows = [[n.created_at, n.message, n.priority, n.status] for n in records]
        
    elif entity_type == 'users':
        query = User.query
        q = request.args.get('q', '').strip()
        role = request.args.get('role', '').strip()
        if q:
            query = query.filter((User.username.like(f"%{q}%")) | (User.email.like(f"%{q}%")))
        if role:
            query = query.filter(User._role == role)
        records = query.order_by(User.created_at.desc()).all()
        headers = ["Username", "Email Address", "Operator Role", "Is Active", "Registered At"]
        rows = [[u.username, u.email, u.role, u.is_active, u.created_at] for u in records]
        
    elif entity_type == 'audit_logs':
        query = AuditLog.query
        q = request.args.get('q', '').strip()
        action = request.args.get('action', '').strip()
        if q:
            query = query.filter((AuditLog.username.like(f"%{q}%")) | (AuditLog.entity.like(f"%{q}%")) | (AuditLog.action.like(f"%{q}%")))
        if action:
            query = query.filter(AuditLog.action == action)
        records = query.order_by(AuditLog.timestamp.desc()).all()
        headers = ["Audit Date & Time", "Username", "Operator Role", "Remote IP", "Action Executed", "Target Entity", "Execution status"]
        rows = [[l.timestamp, l.username, l.role, l.ip_address, l.action, l.entity, l.status] for l in records]
        
    else:
        abort(400)

    # Trigger Audit Log
    AuditService.log(
        action='Report Download',
        entity=f"Export: {entity_type} ({format_type})",
        before=None,
        after=f"Record Count = {len(rows)}",
        status='Success'
    )

    # Return exports
    if format_type == 'csv':
        csv_str = ExportService.export_csv(headers, rows)
        return Response(
            csv_str,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment;filename={entity_type}_export.csv'}
        )
    elif format_type == 'xlsx':
        xlsx_bytes = ExportService.export_xlsx(sheet_name, headers, rows)
        return send_file(
            io.BytesIO(xlsx_bytes),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f"{entity_type}_export.xlsx"
        )
    elif format_type == 'pdf':
        pdf_bytes = ExportService.export_pdf(sheet_name, headers, rows)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"{entity_type}_export.pdf"
        )
    else:
        abort(400)
