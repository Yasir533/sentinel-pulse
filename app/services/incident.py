from datetime import datetime
from app.extensions import db
from app.models.incident import Incident
from app.models.threat import Threat
from app.models.user import User
from app.services.activity import log_activity

def generate_incident_number() -> str:
    """
    Generate an auto-incrementing incident number in format: INC-YYYY-XXXX.
    Ensures uniqueness.
    """
    year = datetime.utcnow().year
    prefix = f"INC-{year}-"
    # Find the maximum sequence number for the current year
    max_incident = db.session.query(Incident).filter(Incident.incident_number.like(f"{prefix}%")).order_by(Incident.incident_number.desc()).first()
    if max_incident:
        try:
            last_seq = int(max_incident.incident_number.split('-')[-1])
            next_seq = last_seq + 1
        except ValueError:
            next_seq = 1
    else:
        next_seq = 1
    return f"{prefix}{next_seq:04d}"

def create_incident(
    threat_id: int,
    title: str,
    description: str,
    severity: str,
    status: str,
    assigned_to: int | None,
    creator_id: int,
    resolution_notes: str | None = None
) -> Incident:
    """
    Service function to create an Incident.
    Validates input fields, generates incident number, sets resolution timestamp if applicable,
    and logs activities.
    """
    # Validation
    if not title or not title.strip():
        raise ValueError("Title is required.")
    if severity not in Incident.SEVERITIES:
        raise ValueError("Invalid severity level.")
    if status not in Incident.STATUSES:
        raise ValueError("Invalid status level.")
    
    threat = db.session.get(Threat, threat_id)
    if not threat:
        raise ValueError("Invalid threat linked to incident.")

    creator = db.session.get(User, creator_id)
    if not creator:
        raise ValueError("Invalid creator user.")

    assignee = None
    if assigned_to:
        assignee = db.session.get(User, assigned_to)
        if not assignee:
            raise ValueError("Assigned Analyst user not found.")

    incident_number = generate_incident_number()
    if Incident.query.filter_by(incident_number=incident_number).first():
        raise ValueError("Incident number must be unique.")

    resolved_at = None
    if status in ['Resolved', 'Closed']:
        resolved_at = datetime.utcnow()

    incident = Incident(
        incident_number=incident_number,
        threat_id=threat_id,
        title=title.strip(),
        description=description.strip() if description else None,
        severity=severity,
        status=status,
        assigned_to=assigned_to,
        created_by=creator_id,
        resolved_at=resolved_at,
        resolution_notes=resolution_notes.strip() if resolution_notes else None
    )

    db.session.add(incident)
    db.session.commit()

    try:
        from app.services.audit import AuditService
        AuditService.log(
            action='Incident Creation',
            entity=f"Incident {incident.incident_number}",
            after=f"Title={incident.title}, Severity={incident.severity}",
            status='Success',
            username=creator.username,
            role=creator.role
        )
        if assignee:
            AuditService.log(
                action='Incident Assignment',
                entity=f"Incident {incident.incident_number}",
                after=f"AssignedTo={assignee.username}",
                status='Success',
                username=creator.username,
                role=creator.role
            )
    except Exception:
        pass

    # Trigger notifications
    try:
        from app.services.notification import NotificationService
        NotificationService.create_notification_for_incident(incident)
        if incident.assigned_to:
            NotificationService.create_notification_for_incident_assignment(incident)
    except Exception:
        pass

    # Audit Trail Logging
    # 1. Incident Created
    log_activity(
        message=f"Incident {incident_number} created for threat {threat.ioc_value} by {creator.username}",
        icon="bi-file-earmark-medical-fill",
        badge_class="bg-info-subtle text-info"
    )
    
    # 2. Assignment Changed if assigned
    if assignee:
        log_activity(
            message=f"Incident {incident_number} assigned to {assignee.username} by {creator.username}",
            icon="bi-person-plus-fill",
            badge_class="bg-warning-subtle text-warning"
        )

    return incident

def update_incident(
    incident: Incident,
    title: str,
    description: str,
    severity: str,
    status: str,
    assigned_to: int | None,
    resolution_notes: str | None,
    updater: User
) -> Incident:
    """
    Service function to update an Incident with RBAC safety checks.
    Only modifies fields permitted by role.
    """
    old_status = incident.status
    old_assignee_id = incident.assigned_to
    
    # Enforce workflow transition: Only allow closing if current status is Resolved
    if status == 'Closed' and old_status != 'Resolved':
        raise ValueError("Incident can only be closed if it is resolved.")
    
    changes = []
    
    # Check roles and update fields
    if updater.role == 'Admin':
        # Admin can update everything
        if not title or not title.strip():
            raise ValueError("Title is required.")
        if severity not in Incident.SEVERITIES:
            raise ValueError("Invalid severity level.")
        if status not in Incident.STATUSES:
            raise ValueError("Invalid status level.")

        if title.strip() != incident.title:
            changes.append("Title updated")
        if (description or '').strip() != (incident.description or ''):
            changes.append("Description updated")
        if severity != incident.severity:
            changes.append(f"Severity escalated to {severity}" if severity in ['High', 'Critical'] else f"Severity changed to {severity}")

        incident.title = title.strip()
        incident.description = description.strip() if description else None
        incident.severity = severity
        incident.status = status
        incident.assigned_to = assigned_to
        incident.resolution_notes = resolution_notes.strip() if resolution_notes else None

    elif updater.role == 'Analyst':
        # Analyst can only update status and resolution notes
        if status not in Incident.STATUSES:
            raise ValueError("Invalid status level.")
        
        incident.status = status
        incident.resolution_notes = resolution_notes.strip() if resolution_notes else None

    else:
        # Viewer or guest - cannot edit
        raise PermissionError("Access denied. You do not have the required permissions to modify incidents.")

    # Status transition resolution date check
    if incident.status in ['Resolved', 'Closed']:
        if not incident.resolved_at:
            incident.resolved_at = datetime.utcnow()
    else:
        incident.resolved_at = None

    db.session.commit()

    try:
        from app.services.audit import AuditService
        # 1. Status Change log
        if old_status != incident.status:
            AuditService.log(
                action='Incident Resolution' if incident.status in ['Resolved', 'Closed'] else 'Incident Update',
                entity=f"Incident {incident.incident_number}",
                before=old_status,
                after=incident.status,
                status='Success',
                username=updater.username,
                role=updater.role
            )
        # 2. Assignment Change log
        if old_assignee_id != incident.assigned_to:
            new_assignee = db.session.get(User, incident.assigned_to) if incident.assigned_to else None
            new_assignee_name = new_assignee.username if new_assignee else "Unassigned"
            AuditService.log(
                action='Incident Assignment',
                entity=f"Incident {incident.incident_number}",
                before=str(old_assignee_id),
                after=new_assignee_name,
                status='Success',
                username=updater.username,
                role=updater.role
            )
    except Exception:
        pass

    # Trigger notifications for updates
    try:
        from app.services.notification import NotificationService
        if old_status != incident.status:
            if incident.status == 'Resolved':
                NotificationService.create_notification_for_incident_resolution(incident)
            elif incident.status == 'Closed':
                NotificationService.create_notification_for_incident_closure(incident)
            else:
                NotificationService.create_notification_for_incident_update(incident, f"Status updated from '{old_status}' to '{incident.status}'.")
        elif changes:
            NotificationService.create_notification_for_incident_update(incident, ", ".join(changes))
            
        if old_assignee_id != incident.assigned_to and incident.assigned_to is not None:
            NotificationService.create_notification_for_incident_assignment(incident)
    except Exception:
        pass

    # Audit Trail Logs
    log_activity(
        message=f"Incident {incident.incident_number} updated by {updater.username}",
        icon="bi-pencil-square",
        badge_class="bg-primary-subtle text-primary"
    )

    # Status Changed or Closed logs
    if old_status != incident.status:
        log_activity(
            message=f"Incident {incident.incident_number} status changed to {incident.status} by {updater.username}",
            icon="bi-activity",
            badge_class="bg-info-subtle text-info"
        )
        if incident.status == 'Resolved':
            log_activity(
                message=f"Incident {incident.incident_number} resolved by {updater.username}",
                icon="bi-check-circle-fill",
                badge_class="bg-success-subtle text-success"
            )
        elif incident.status == 'Closed':
            log_activity(
                message=f"Incident {incident.incident_number} closed by {updater.username}",
                icon="bi-folder-check",
                badge_class="bg-success-subtle text-success"
            )

    # Assignment Changed logs
    if old_assignee_id != incident.assigned_to:
        new_assignee = db.session.get(User, incident.assigned_to) if incident.assigned_to else None
        new_assignee_name = new_assignee.username if new_assignee else "Unassigned"
        log_activity(
            message=f"Incident {incident.incident_number} assigned to {new_assignee_name} by {updater.username}",
            icon="bi-person-gear",
            badge_class="bg-warning-subtle text-warning"
        )

    return incident

def delete_incident(incident_id: int, deleter: User):
    """
    Admin only delete function.
    """
    if deleter.role != 'Admin':
        raise PermissionError("Access denied. Only administrators can delete incidents.")

    incident = Incident.query.get_or_404(incident_id)
    incident_number = incident.incident_number

    db.session.delete(incident)
    db.session.commit()

    try:
        from app.services.audit import AuditService
        AuditService.log('Incident Deletion', f"Incident {incident_number}", status='Success', username=deleter.username, role=deleter.role)
    except Exception:
        pass

    log_activity(
        message=f"Incident {incident_number} deleted by Administrator {deleter.username}",
        icon="bi-trash-fill",
        badge_class="bg-danger-subtle text-danger"
    )
