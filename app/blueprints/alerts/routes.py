from datetime import datetime
from flask import render_template, redirect, url_for, flash, request, Response
from flask_login import login_required, current_user
from app.blueprints.alerts import alerts_bp
from app.models.alert import Alert
from app.extensions import db
from app.utils import role_required

@alerts_bp.route('/')
@login_required
def list_alerts() -> str:
    """Renders active system alerts with advanced search and filters."""
    q = request.args.get('q', '').strip()
    severity = request.args.get('severity', '').strip()
    status = request.args.get('status', '').strip()
    threat_type = request.args.get('threat_type', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    alert_number = request.args.get('alert_number', '').strip()

    from app.models.threat import Threat

    # Base query joining Threat model to allow filtering by IOC value/type
    query = Alert.query.join(Threat)

    # Search: Alert Number or IOC Value
    if q:
        search_filter = f"%{q}%"
        query = query.filter(
            (Alert.alert_number.like(search_filter)) |
            (Threat.ioc_value.like(search_filter))
        )

    # Filter: Alert Number
    if alert_number:
        query = query.filter(Alert.alert_number.like(f"%{alert_number}%"))

    # Filter: Severity
    if severity:
        query = query.filter(Alert.severity == severity)

    # Filter: Status
    if status:
        query = query.filter(Alert.status == status)

    # Filter: Threat Type
    if threat_type:
        query = query.filter(Threat.threat_type == threat_type)

    # Filter: Date Range
    if start_date:
        try:
            dt_start = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(Alert.created_at >= dt_start)
        except ValueError:
            flash("Invalid start date format.", "warning")
    if end_date:
        try:
            dt_end = datetime.strptime(f"{end_date} 23:59:59", '%Y-%m-%d %H:%M:%S')
            query = query.filter(Alert.created_at <= dt_end)
        except ValueError:
            flash("Invalid end date format.", "warning")

    # Order newest first
    alerts = query.order_by(Alert.created_at.desc()).all()
    critical_count = Alert.query.filter_by(severity='Critical').count()

    return render_template(
        'alerts/list.html',
        alerts=alerts,
        critical_count=critical_count,
        threat_types=Threat.THREAT_TYPES,
        severities=Alert.SEVERITIES,
        statuses=Alert.STATUSES,
        search_query=q,
        selected_severity=severity,
        selected_status=status,
        selected_threat_type=threat_type,
        start_date=start_date,
        end_date=end_date,
        selected_alert_number=alert_number
    )

@alerts_bp.route('/<int:alert_id>')
@login_required
def view_alert(alert_id: int) -> str:
    """View details of a specific alert."""
    alert = db.get_or_404(Alert, alert_id)
    
    # Record Activity Log: Alert Viewed
    try:
        from app.services.activity import log_activity
        log_activity(
            message=f"Operator {current_user.username} viewed Alert {alert.alert_number}",
            icon="bi-eye-fill",
            badge_class="bg-secondary-subtle text-muted"
        )
    except Exception:
        pass
        
    from app.services.threat_summary import calculate_overall_risk, generate_summary, generate_recommendation
    overall_risk = calculate_overall_risk(alert.threat)
    summary = generate_summary(alert.threat)
    recommendations = generate_recommendation(alert.threat)
    
    # Check if incident already exists
    from app.models.incident import Incident
    incident_exists = Incident.query.filter_by(threat_id=alert.threat_id).first() is not None
    
    return render_template(
        'alerts/details.html',
        alert=alert,
        overall_risk=overall_risk,
        summary=summary,
        recommendations=recommendations,
        incident_exists=incident_exists
    )

@alerts_bp.route('/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
@role_required('Admin', 'Analyst')
def acknowledge_alert(alert_id: int) -> Response:
    """Acknowledge a system alert."""
    alert = db.get_or_404(Alert, alert_id)
    
    if alert.status == 'New':
        alert.status = 'Acknowledged'
        alert.acknowledged_at = datetime.utcnow()
        alert.acknowledged_by = current_user.id
        
        try:
            db.session.commit()
            
            # Publish Real-time SSE Event
            try:
                from app.services.realtime_event_service import RealtimeEventService
                RealtimeEventService.publish('alert.updated', alert.to_dict(), target_role='Analyst')
            except Exception:
                pass

            from app.services.audit import AuditService
            AuditService.log('Alert Status Changes', f"Alert {alert.alert_number}", before='New', after='Acknowledged', status='Success')

            # Record activity log
            from app.services.activity import log_activity
            log_activity(
                message=f"Operator {current_user.username} acknowledged Alert {alert.alert_number}",
                icon="bi-check2-circle",
                badge_class="bg-success-subtle text-success"
            )
            flash(f"Alert {alert.alert_number} acknowledged successfully.", "success")
        except Exception:
            db.session.rollback()
            flash("An error occurred while acknowledging the alert.", "danger")
    else:
        flash("Alert must be in New status to be acknowledged.", "danger")
            
    return redirect(url_for('alerts.view_alert', alert_id=alert.id))

@alerts_bp.route('/<int:alert_id>/investigate', methods=['POST'])
@login_required
@role_required('Admin', 'Analyst')
def investigate_alert(alert_id: int) -> Response:
    """Transition alert status to Investigating."""
    alert = db.get_or_404(Alert, alert_id)
    
    if alert.status == 'Acknowledged':
        alert.status = 'Investigating'
        try:
            db.session.commit()
            
            try:
                from app.services.realtime_event_service import RealtimeEventService
                RealtimeEventService.publish('alert.updated', alert.to_dict(), target_role='Analyst')
            except Exception:
                pass

            from app.services.audit import AuditService
            AuditService.log('Alert Status Changes', f"Alert {alert.alert_number}", before='Acknowledged', after='Investigating', status='Success')

            from app.services.activity import log_activity
            log_activity(
                message=f"Operator {current_user.username} moved Alert {alert.alert_number} to Investigating",
                icon="bi-hourglass-split",
                badge_class="bg-warning-subtle text-warning"
            )
            flash(f"Alert {alert.alert_number} status changed to Investigating.", "success")
        except Exception:
            db.session.rollback()
            flash("An error occurred while starting investigation.", "danger")
    else:
        flash("Alert must be Acknowledged before starting investigation.", "danger")
        
    return redirect(url_for('alerts.view_alert', alert_id=alert.id))

@alerts_bp.route('/<int:alert_id>/resolve', methods=['POST'])
@login_required
@role_required('Admin')
def resolve_alert(alert_id: int) -> Response:
    """Transition alert status to Resolved."""
    alert = db.get_or_404(Alert, alert_id)
    
    if alert.status == 'Investigating':
        alert.status = 'Resolved'
        alert.resolved_at = datetime.utcnow()
        try:
            db.session.commit()
            
            try:
                from app.services.realtime_event_service import RealtimeEventService
                RealtimeEventService.publish('alert.updated', alert.to_dict(), target_role='Analyst')
            except Exception:
                pass

            from app.services.audit import AuditService
            AuditService.log('Alert Status Changes', f"Alert {alert.alert_number}", before='Investigating', after='Resolved', status='Success')

            from app.services.activity import log_activity
            log_activity(
                message=f"Administrator {current_user.username} resolved Alert {alert.alert_number}",
                icon="bi-check-circle-fill",
                badge_class="bg-success-subtle text-success"
            )
            flash(f"Alert {alert.alert_number} resolved successfully.", "success")
        except Exception:
            db.session.rollback()
            flash("An error occurred while resolving the alert.", "danger")
    else:
        flash("Alert must be in Investigating status to be resolved.", "danger")
        
    return redirect(url_for('alerts.view_alert', alert_id=alert.id))

@alerts_bp.route('/<int:alert_id>/archive', methods=['POST'])
@login_required
@role_required('Admin')
def archive_alert(alert_id: int) -> Response:
    """Transition alert status to Archived."""
    alert = db.get_or_404(Alert, alert_id)
    
    if alert.status == 'Resolved':
        alert.status = 'Archived'
        try:
            db.session.commit()
            
            from app.services.audit import AuditService
            AuditService.log('Alert Status Changes', f"Alert {alert.alert_number}", before='Resolved', after='Archived', status='Success')

            from app.services.activity import log_activity
            log_activity(
                message=f"Administrator {current_user.username} archived Alert {alert.alert_number}",
                icon="bi-archive-fill",
                badge_class="bg-secondary-subtle text-muted"
            )
            flash(f"Alert {alert.alert_number} archived successfully.", "success")
        except Exception:
            db.session.rollback()
            flash("An error occurred while archiving the alert.", "danger")
    else:
        flash("Alert must be in Resolved status to be archived.", "danger")
        
    return redirect(url_for('alerts.view_alert', alert_id=alert.id))

@alerts_bp.route('/new', methods=['GET', 'POST'])
@login_required
@role_required('Admin', 'Analyst')
def new_alert() -> str | Response:
    """Manually trigger/create a new alert associated with a Threat."""
    from app.models.threat import Threat
    from app.services.alert import AlertService
    
    if request.method == 'POST':
        threat_id_val = request.form.get('threat_id')
        severity = request.form.get('severity', 'Medium').strip()
        message = request.form.get('message', '').strip()
        
        if not threat_id_val or not message:
            flash("Threat and alert message are required.", "danger")
            return redirect(url_for('alerts.list_alerts'))
            
        try:
            threat_id = int(threat_id_val)
            threat = db.get_or_404(Threat, threat_id)
            
            alert_number = AlertService.generate_next_alert_number()
            alert = Alert(
                alert_number=alert_number,
                threat_id=threat.id,
                severity=severity,
                status='New',
                message=message,
                ai_risk=severity.upper()
            )
            
            db.session.add(alert)
            db.session.commit()
            
            from app.services.audit import AuditService
            AuditService.log('Alert Generation', f"Alert {alert.alert_number}", after=f"Severity={alert.severity}, Message={alert.message}", status='Success')
            
            # Dispatch notification
            try:
                from app.services.notification import NotificationService
                NotificationService.create_notification_for_alert(alert)
            except Exception:
                pass
                
            from app.services.activity import log_activity
            log_activity(
                message=f"Operator {current_user.username} manually created Alert {alert.alert_number}",
                icon='bi-bell-fill',
                badge_class='bg-warning-subtle text-warning'
            )
            flash("Alert created successfully.", "success")
            return redirect(url_for('alerts.list_alerts'))
        except Exception as e:
            db.session.rollback()
            flash(f"Failed to create alert: {str(e)}", "danger")
            
    # For GET, fetch threats to link to
    threats = Threat.query.order_by(Threat.created_at.desc()).all()
    return render_template('alerts/new.html', threats=threats)

@alerts_bp.route('/<int:alert_id>/delete', methods=['POST'])
@login_required
@role_required('Admin')
def delete_alert(alert_id: int) -> Response:
    """Admin-only endpoint to delete a system alert."""
    alert = db.get_or_404(Alert, alert_id)
    try:
        db.session.delete(alert)
        db.session.commit()
        
        from app.services.audit import AuditService
        AuditService.log('Alert Deletion', f"Alert {alert.alert_number}", status='Success')
        
        from app.services.activity import log_activity
        log_activity(
            message=f"Administrator {current_user.username} deleted Alert {alert.alert_number}",
            icon='bi-trash-fill',
            badge_class='bg-danger-subtle text-danger'
        )
        flash("Alert deleted successfully.", "success")
    except Exception:
        db.session.rollback()
        flash("An error occurred while deleting the alert.", "danger")
        
    return redirect(url_for('alerts.list_alerts'))
