from datetime import datetime, timedelta
from flask import render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from sqlalchemy import or_
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.blueprints.incidents import incidents_bp
from app.utils import role_required
from app.models.incident import Incident
from app.models.threat import Threat
from app.models.user import User
from app.services.incident import create_incident, update_incident
from app.services.threat_summary import calculate_overall_risk, generate_summary, generate_recommendation

@incidents_bp.route('/')
@login_required
def list_incidents():
    """List security incidents with filtering, search, pagination, and sorting."""
    # Query parameters
    q = request.args.get('q', '').strip()
    severity = request.args.get('severity', '').strip()
    status = request.args.get('status', '').strip()
    assigned_to = request.args.get('assigned_to', '').strip()
    threat_type = request.args.get('threat_type', '').strip()
    ioc_type = request.args.get('ioc_type', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    
    # Sorting
    sort_by = request.args.get('sort_by', 'created_at_desc').strip()
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # Start query with eager loading to prevent N+1 queries
    query = Incident.query.options(
        joinedload(Incident.threat),
        joinedload(Incident.assignee),
        joinedload(Incident.creator)
    ).join(Incident.threat)

    # Search filter
    if q:
        query = query.filter(or_(
            Incident.title.ilike(f"%{q}%"),
            Incident.incident_number.ilike(f"%{q}%"),
            Threat.ioc_value.ilike(f"%{q}%")
        ))

    # Filters
    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)
    if assigned_to:
        query = query.filter(Incident.assigned_to == int(assigned_to))
    if threat_type:
        query = query.filter(Threat.threat_type == threat_type)
    if ioc_type:
        query = query.filter(Threat.ioc_type == ioc_type)
        
    if start_date:
        try:
            start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(Incident.created_at >= start_dt)
        except ValueError:
            pass
            
    if end_date:
        try:
            end_dt = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Incident.created_at < end_dt)
        except ValueError:
            pass

    # Apply sorting
    if sort_by == 'created_at_asc':
        query = query.order_by(Incident.created_at.asc())
    elif sort_by == 'severity_desc':
        # Severity ordering: Critical, High, Medium, Low
        query = query.order_by(
            db.case(
                (Incident.severity == 'Critical', 1),
                (Incident.severity == 'High', 2),
                (Incident.severity == 'Medium', 3),
                (Incident.severity == 'Low', 4),
                else_=5
            ).asc(),
            Incident.created_at.desc()
        )
    else:  # Default to created_at_desc
        query = query.order_by(Incident.created_at.desc())

    # Execute paginated query
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    incidents = pagination.items

    # Available filters list for form
    users = User.query.filter(User._role.in_(['Admin', 'Analyst'])).all()

    return render_template(
        'incidents/list.html',
        incidents=incidents,
        pagination=pagination,
        search_query=q,
        selected_severity=severity,
        selected_status=status,
        selected_analyst=assigned_to,
        selected_threat_type=threat_type,
        selected_ioc_type=ioc_type,
        start_date=start_date,
        end_date=end_date,
        sort_by=sort_by,
        severities=Incident.SEVERITIES,
        statuses=Incident.STATUSES,
        users=users,
        threat_types=Threat.THREAT_TYPES
    )

@incidents_bp.route('/new', defaults={'threat_id': None}, methods=['GET', 'POST'])
@incidents_bp.route('/new/<int:threat_id>', methods=['GET', 'POST'])
@login_required
@role_required('Admin', 'Analyst')
def new_incident(threat_id: int | None):
    """Create a new incident linked to a threat."""
    threat = None
    overall_risk = None
    summary = ""
    recommendations = []
    
    if threat_id:
        # Prevent duplicate Incident creation: redirect if one already exists
        existing_incident = Incident.query.filter_by(threat_id=threat_id).first()
        if existing_incident:
            flash("An Incident already exists for this Threat.", "warning")
            return redirect(url_for('incidents.view_incident', incident_id=existing_incident.id))

        threat = Threat.query.get_or_404(threat_id)
        # Calculate AI Risk / Heuristics info
        overall_risk = calculate_overall_risk(threat)
        summary = generate_summary(threat)
        recommendations = generate_recommendation(threat)

    if request.method == 'POST':
        # Retrieve form parameters
        if not threat_id:
            threat_id = int(request.form.get('threat_id'))
            threat = Threat.query.get_or_404(threat_id)

        # Prevent duplicate Incident creation on submission
        existing_incident = Incident.query.filter_by(threat_id=threat_id).first()
        if existing_incident:
            flash("An Incident already exists for this Threat.", "warning")
            return redirect(url_for('incidents.view_incident', incident_id=existing_incident.id))
            
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        severity = request.form.get('severity', '').strip()
        status = request.form.get('status', '').strip()
        
        assigned_to_val = request.form.get('assigned_to')
        assigned_to = int(assigned_to_val) if assigned_to_val and assigned_to_val.strip() else None
        
        resolution_notes = request.form.get('resolution_notes', '').strip()

        try:
            incident = create_incident(
                threat_id=threat_id,
                title=title,
                description=description,
                severity=severity,
                status=status,
                assigned_to=assigned_to,
                creator_id=current_user.id,
                resolution_notes=resolution_notes
            )
            flash('Incident Created Successfully', 'success')
            return redirect(url_for('incidents.view_incident', incident_id=incident.id))
        except ValueError as e:
            flash(str(e), 'danger')

    # For GET, render creation page
    users = User.query.filter(User._role.in_(['Admin', 'Analyst'])).all()
    
    # If no threat_id supplied, fetch all threats that can be linked
    available_threats = []
    if not threat_id:
        available_threats = Threat.query.order_by(Threat.created_at.desc()).all()

    from app.services.incident import generate_incident_number
    next_incident_number = generate_incident_number()

    return render_template(
        'incidents/new.html',
        threat=threat,
        overall_risk=overall_risk,
        summary=summary,
        recommendations=recommendations,
        users=users,
        statuses=Incident.STATUSES,
        severities=Incident.SEVERITIES,
        available_threats=available_threats,
        next_incident_number=next_incident_number
    )

@incidents_bp.route('/<int:incident_id>')
@login_required
def view_incident(incident_id: int):
    """View security incident details, linked threat details, and enrichment reports."""
    incident = Incident.query.get_or_404(incident_id)
    threat = incident.threat

    # Calculate AI Heuristics / summary information from linked threat
    overall_risk = calculate_overall_risk(threat)
    summary = generate_summary(threat)
    recommendations = generate_recommendation(threat)

    # Generate AI Assistant Remediation & Incident Guidance
    from app.services.ai_incident_assistant import AIIncidentAssistant
    ai_assistance = AIIncidentAssistant.generate_assistance(incident)

    return render_template(
        'incidents/detail.html',
        incident=incident,
        threat=threat,
        overall_risk=overall_risk,
        summary=summary,
        recommendations=recommendations,
        vt=threat.vt_enrichment,
        abuse=threat.abuseipdb_enrichment,
        ai_assistance=ai_assistance
    )

@incidents_bp.route('/<int:incident_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('Admin', 'Analyst')
def edit_incident(incident_id: int):
    """Edit security incident details based on role-based restrictions."""
    incident = Incident.query.get_or_404(incident_id)
    threat = incident.threat
    
    users = User.query.filter(User._role.in_(['Admin', 'Analyst'])).all()

    if request.method == 'POST':
        # Retrieve form parameters based on role
        if current_user.role == 'Admin':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            severity = request.form.get('severity', '').strip()
            assigned_to_val = request.form.get('assigned_to')
            assigned_to = int(assigned_to_val) if assigned_to_val and assigned_to_val.strip() else None
        else:
            # Analyst role - these are read-only and preserved
            title = incident.title
            description = incident.description
            severity = incident.severity
            assigned_to = incident.assigned_to

        status = request.form.get('status', '').strip()
        resolution_notes = request.form.get('resolution_notes', '').strip()

        old_status = incident.status
        old_assigned_to = incident.assigned_to

        try:
            update_incident(
                incident=incident,
                title=title,
                description=description,
                severity=severity,
                status=status,
                assigned_to=assigned_to,
                resolution_notes=resolution_notes,
                updater=current_user
            )

            # Determine appropriate notification to flash
            if old_status != incident.status:
                if incident.status == 'Resolved':
                    flash('Incident Resolved Successfully', 'success')
                elif incident.status == 'Closed':
                    flash('Incident Closed Successfully', 'success')
                else:
                    flash('Incident Updated Successfully', 'success')
            elif old_assigned_to != incident.assigned_to:
                flash('Incident Assigned Successfully', 'success')
            else:
                flash('Incident Updated Successfully', 'success')

            return redirect(url_for('incidents.view_incident', incident_id=incident.id))
        except (ValueError, PermissionError) as e:
            flash(str(e), 'danger')

    return render_template(
        'incidents/edit.html',
        incident=incident,
        threat=threat,
        users=users,
        statuses=Incident.STATUSES,
        severities=Incident.SEVERITIES
    )

@incidents_bp.route('/<int:incident_id>/delete', methods=['POST'])
@login_required
@role_required('Admin')
def delete_incident(incident_id: int):
    """Delete a security incident (Admin only)."""
    try:
        from app.services.incident import delete_incident as delete_service
        delete_service(incident_id, current_user)
        flash('Incident Deleted Successfully', 'success')
    except PermissionError as e:
        flash(str(e), 'danger')
    return redirect(url_for('incidents.list_incidents'))
