from datetime import datetime
from flask import render_template, redirect, url_for, flash, request, abort, Response, current_app
from flask_login import login_required, current_user
from app.blueprints.threats import threats_bp
from app.models.threat import Threat
from app.extensions import db
from app.utils import role_required

@threats_bp.route('/', methods=['GET'])
@login_required
def list_threats() -> str:
    """List threat intelligence indicators with advanced search and filters."""
    # Get parameters
    q = request.args.get('q', '').strip()
    threat_type = request.args.get('threat_type', '').strip()
    severity = request.args.get('severity', '').strip()
    status = request.args.get('status', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()

    # Base query
    query = Threat.query

    # Apply Search Keywords (IOC value, threat type, source, description)
    if q:
        search_filter = f"%{q}%"
        query = query.filter(
            (Threat.ioc_value.like(search_filter)) |
            (Threat.threat_type.like(search_filter)) |
            (Threat.source.like(search_filter)) |
            (Threat.description.like(search_filter))
        )

    # Apply Category Filters
    if threat_type:
        query = query.filter(Threat.threat_type == threat_type)
    if severity:
        query = query.filter(Threat.severity == severity)
    if status:
        query = query.filter(Threat.status == status)

    # Apply Date Range Filters
    if start_date:
        try:
            dt_start = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(Threat.created_at >= dt_start)
        except ValueError:
            flash("Invalid start date format.", "warning")
    if end_date:
        try:
            dt_end = datetime.strptime(f"{end_date} 23:59:59", '%Y-%m-%d %H:%M:%S')
            query = query.filter(Threat.created_at <= dt_end)
        except ValueError:
            flash("Invalid end date format.", "warning")

    # Execute query, order by newest first
    threats = query.order_by(Threat.created_at.desc()).all()

    return render_template(
        'threats/list.html',
        threats=threats,
        threat_types=Threat.THREAT_TYPES,
        severities=Threat.SEVERITIES,
        statuses=Threat.STATUSES,
        search_query=q,
        selected_type=threat_type,
        selected_severity=severity,
        selected_status=status,
        start_date=start_date,
        end_date=end_date
    )

@threats_bp.route('/new', methods=['GET', 'POST'])
@login_required
@role_required('Admin', 'Analyst')
def new_threat() -> str | Response:
    """Record a new indicator of compromise (IOC)."""
    if request.method == 'POST':
        threat_type = request.form.get('threat_type', '').strip()
        ioc_type = request.form.get('ioc_type', '').strip()
        ioc_value = request.form.get('ioc_value', '').strip()
        severity = request.form.get('severity', '').strip()
        source = request.form.get('source', '').strip()
        status = request.form.get('status', '').strip()
        description = request.form.get('description', '').strip()
        
        try:
            confidence_score = int(request.form.get('confidence_score', '0'))
        except ValueError:
            confidence_score = -1

        # Validation
        errors = []
        if not threat_type or threat_type not in Threat.THREAT_TYPES:
            errors.append("Invalid threat type selected.")
        if not ioc_type:
            errors.append("IOC type is required.")
        if not ioc_value:
            errors.append("IOC value is required.")
        if not severity or severity not in Threat.SEVERITIES:
            errors.append("Invalid severity level selected.")
        if not source:
            errors.append("Intel source is required.")
        if not status or status not in Threat.STATUSES:
            errors.append("Invalid status selected.")
        if confidence_score < 0 or confidence_score > 100:
            errors.append("Confidence score must be an integer between 0 and 100.")

        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template(
                'threats/form.html',
                threat_types=Threat.THREAT_TYPES,
                severities=Threat.SEVERITIES,
                statuses=Threat.STATUSES
            )

        # Create model
        new_tr = Threat(
            threat_type=threat_type,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            severity=severity,
            source=source,
            status=status,
            confidence_score=confidence_score,
            description=description,
            created_by=current_user.id
        )

        try:
            db.session.add(new_tr)
            db.session.commit()
            
            from app.services.audit import AuditService
            AuditService.log('Threat Creation', f"Threat {new_tr.ioc_value}", after=f"Type={new_tr.threat_type}, Severity={new_tr.severity}")

            # VirusTotal Enrichment Trigger
            try:
                from app.services.virustotal import enrich_threat
                enrich_threat(new_tr)
            except Exception:
                current_app.logger.exception("Failed to run VirusTotal enrichment during threat creation")

            # AbuseIPDB Enrichment Trigger
            if new_tr.ioc_type == 'IP Address':
                try:
                    from app.services.abuseipdb import enrich_ip
                    enrich_ip(new_tr)
                except Exception:
                    current_app.logger.exception("Failed to run AbuseIPDB enrichment during threat creation")

            # Alert Generation Trigger
            try:
                from app.services.alert import AlertService
                AlertService.generate_alert(new_tr)
            except Exception:
                current_app.logger.exception("Failed to evaluate alert generation during threat creation")

            # Log threat creation activity
            try:
                from app.services.activity import log_activity
                log_activity(
                    message=f"Operator {current_user.username} recorded {new_tr.threat_type} IOC ({new_tr.ioc_value})",
                    icon="bi-shield-fill-plus",
                    badge_class="bg-primary-subtle text-primary"
                )
            except Exception:
                current_app.logger.exception("Failed to log activity for threat creation")

            flash("Threat indicator recorded successfully.", "success")
            return redirect(url_for('threats.list_threats'))
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Failed to save threat indicator")
            flash("An error occurred while saving the threat indicator.", "danger")

    return render_template(
        'threats/form.html',
        threat_types=Threat.THREAT_TYPES,
        severities=Threat.SEVERITIES,
        statuses=Threat.STATUSES
    )

@threats_bp.route('/<int:threat_id>', methods=['GET'])
@login_required
def view_threat(threat_id: int) -> str:
    """View details of a specific threat indicators."""
    threat = Threat.query.get_or_404(threat_id)
    from app.services.threat_summary import calculate_overall_risk, generate_summary, generate_recommendation
    overall_risk = calculate_overall_risk(threat)
    summary = generate_summary(threat)
    recommendations = generate_recommendation(threat)
    return render_template(
        'threats/view.html',
        threat=threat,
        overall_risk=overall_risk,
        summary=summary,
        recommendations=recommendations
    )

@threats_bp.route('/<int:threat_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('Admin', 'Analyst')
def edit_threat(threat_id: int) -> str | Response:
    """Edit existing threat intelligence record."""
    threat = Threat.query.get_or_404(threat_id)

    if request.method == 'POST':
        threat_type = request.form.get('threat_type', '').strip()
        ioc_type = request.form.get('ioc_type', '').strip()
        ioc_value = request.form.get('ioc_value', '').strip()
        severity = request.form.get('severity', '').strip()
        source = request.form.get('source', '').strip()
        status = request.form.get('status', '').strip()
        description = request.form.get('description', '').strip()

        try:
            confidence_score = int(request.form.get('confidence_score', '0'))
        except ValueError:
            confidence_score = -1

        # Validation
        errors = []
        if not threat_type or threat_type not in Threat.THREAT_TYPES:
            errors.append("Invalid threat type selected.")
        if not ioc_type:
            errors.append("IOC type is required.")
        if not ioc_value:
            errors.append("IOC value is required.")
        if not severity or severity not in Threat.SEVERITIES:
            errors.append("Invalid severity level selected.")
        if not source:
            errors.append("Intel source is required.")
        if not status or status not in Threat.STATUSES:
            errors.append("Invalid status selected.")
        if confidence_score < 0 or confidence_score > 100:
            errors.append("Confidence score must be an integer between 0 and 100.")

        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template(
                'threats/form.html',
                threat=threat,
                threat_types=Threat.THREAT_TYPES,
                severities=Threat.SEVERITIES,
                statuses=Threat.STATUSES
            )

        # Update values
        threat.threat_type = threat_type
        threat.ioc_type = ioc_type
        threat.ioc_value = ioc_value
        threat.severity = severity
        threat.source = source
        threat.status = status
        threat.confidence_score = confidence_score
        threat.description = description
        threat.updated_at = datetime.utcnow()

        try:
            db.session.commit()
            
            from app.services.audit import AuditService
            AuditService.log('Threat Update', f"Threat {threat.ioc_value}", after=f"Type={threat.threat_type}, Severity={threat.severity}")

            # VirusTotal Enrichment Trigger
            try:
                from app.services.virustotal import enrich_threat
                enrich_threat(threat)
            except Exception:
                current_app.logger.exception("Failed to run VirusTotal enrichment during threat update")

            # AbuseIPDB Enrichment Trigger
            if threat.ioc_type == 'IP Address':
                try:
                    from app.services.abuseipdb import enrich_ip
                    enrich_ip(threat)
                except Exception:
                    current_app.logger.exception("Failed to run AbuseIPDB enrichment during threat update")

            # Alert Generation Trigger
            try:
                from app.services.alert import AlertService
                AlertService.generate_alert(threat)
            except Exception:
                current_app.logger.exception("Failed to evaluate alert generation during threat update")

            # Log threat update activity
            try:
                from app.services.activity import log_activity
                log_activity(
                    message=f"Operator {current_user.username} updated {threat.threat_type} IOC ({threat.ioc_value})",
                    icon="bi-shield-fill-exclamation",
                    badge_class="bg-info-subtle text-info"
                )
            except Exception:
                current_app.logger.exception("Failed to log activity for threat update")

            flash("Threat indicator updated successfully.", "success")
            return redirect(url_for('threats.view_threat', threat_id=threat.id))
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Failed to update threat indicator")
            flash("An error occurred while updating the threat indicator.", "danger")

    return render_template(
        'threats/form.html',
        threat=threat,
        threat_types=Threat.THREAT_TYPES,
        severities=Threat.SEVERITIES,
        statuses=Threat.STATUSES
    )

@threats_bp.route('/<int:threat_id>/delete', methods=['POST'])
@login_required
@role_required('Admin')
def delete_threat(threat_id: int) -> Response:
    """Delete a threat indicator. Restricted to Admin."""
    threat = Threat.query.get_or_404(threat_id)
    try:
        db.session.delete(threat)
        db.session.commit()
        
        from app.services.audit import AuditService
        AuditService.log('Threat Deletion', f"Threat {threat.ioc_value}", status='Success')

        flash("Threat indicator deleted successfully.", "success")
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to delete threat indicator")
        flash("An error occurred while deleting the threat indicator.", "danger")
        
    return redirect(url_for('threats.list_threats'))


