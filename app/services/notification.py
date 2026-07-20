from datetime import datetime
from app.extensions import db
from app.models.notification import Notification
from app.models.user import User

class NotificationService:
    @staticmethod
    def generate_next_notification_number() -> str:
        """
        Generate an auto-incrementing notification number: NTF-YYYY-XXXX.
        """
        year = datetime.utcnow().year
        prefix = f"NTF-{year}-"
        max_notif = db.session.query(Notification).filter(Notification.notification_number.like(f"{prefix}%")).order_by(Notification.notification_number.desc()).first()
        if max_notif:
            try:
                last_seq = int(max_notif.notification_number.split('-')[-1])
                next_seq = last_seq + 1
            except ValueError:
                next_seq = 1
        else:
            next_seq = 1
        return f"{prefix}{next_seq:04d}"

    @classmethod
    def create_notification(
        cls,
        user_id: int,
        title: str,
        message: str,
        type: str,
        priority: str,
        related_alert_id: int | None = None,
        related_incident_id: int | None = None
    ) -> Notification:
        """
        Create a notification for a specific user and commit to database.
        """
        curr_id = "None"
        curr_name = "Anonymous"
        curr_role = "None"
        try:
            from flask_login import current_user
            if current_user and current_user.is_authenticated:
                curr_id = current_user.id
                curr_name = current_user.username
                curr_role = current_user.role
        except Exception:
            pass

        from flask import current_app
        current_app.logger.info(
            f"Creating notification NTF. User: {curr_name} (ID: {curr_id}, Role: {curr_role}), Recipient User ID: {user_id}"
        )

        notification_number = cls.generate_next_notification_number()
        notif = Notification(
            notification_number=notification_number,
            title=title,
            message=message,
            type=type,
            priority=priority,
            user_id=user_id,
            related_alert_id=related_alert_id,
            related_incident_id=related_incident_id,
            status='Unread'
        )
        db.session.add(notif)
        db.session.commit()

        # Publish Real-time SSE Event (targeted strictly to recipient user ID for object-level privacy)
        try:
            from app.services.realtime_event_service import RealtimeEventService
            RealtimeEventService.publish('notification.created', notif.to_dict(), target_user_id=user_id)
        except Exception as e:
            if current_app:
                current_app.logger.warning(f"Failed to publish notification.created SSE event: {e}")

        return notif

    @classmethod
    def broadcast_notification(
        cls,
        title: str,
        message: str,
        type: str,
        priority: str,
        related_alert_id: int | None = None,
        related_incident_id: int | None = None,
        related_incident=None,
        target_user_id: int | None = None
    ) -> list[Notification]:
        """
        Broadcast a notification to all eligible users based on role-based access rules.
        """
        created_notifications = []
        users = User.query.all()

        # Find the starting sequence number for the current year
        year = datetime.utcnow().year
        prefix = f"NTF-{year}-"
        max_notif = db.session.query(Notification).filter(Notification.notification_number.like(f"{prefix}%")).order_by(Notification.notification_number.desc()).first()
        if max_notif:
            try:
                last_seq = int(max_notif.notification_number.split('-')[-1])
                next_seq = last_seq + 1
            except ValueError:
                next_seq = 1
        else:
            next_seq = 1

        recipient_ids = []
        for user in users:
            is_eligible = False
            user_role = user.role.strip().capitalize()

            # Rule 1: High/Critical Alert Created -> Every Admin, Every Analyst
            if type == 'Alert':
                if user_role in ['Admin', 'Analyst']:
                    is_eligible = True

            # Incident-related events
            elif type == 'Incident':
                is_assigned_only_event = "assigned" in title.lower() or "assigned" in message.lower()
                
                if is_assigned_only_event:
                    # Rule 3: Incident Assigned -> Assigned Analyst only (no Admins)
                    if related_incident and related_incident.assigned_to == user.id:
                        is_eligible = True
                else:
                    # Rule 2: Incident Created / Rule 4: Incident Resolved / Close / Update
                    # -> Every Admin + Assigned Analyst
                    if user_role == 'Admin':
                        is_eligible = True
                    elif related_incident and related_incident.assigned_to == user.id:
                        is_eligible = True

            # Rule 5, 6: Role Changed or Account Activated/Deactivated -> Affected User + Every Admin
            elif type == 'System':
                if user_role == 'Admin':
                    is_eligible = True
                elif target_user_id == user.id:
                    is_eligible = True

            # Threat Events -> All users (informational)
            elif type == 'Threat':
                is_eligible = True

            if is_eligible:
                recipient_ids.append(user.id)

        curr_id = "None"
        curr_name = "Anonymous"
        curr_role = "None"
        try:
            from flask_login import current_user
            if current_user and current_user.is_authenticated:
                curr_id = current_user.id
                curr_name = current_user.username
                curr_role = current_user.role
        except Exception:
            pass

        from flask import current_app
        current_app.logger.info(
            f"Broadcasting notification. User: {curr_name} (ID: {curr_id}, Role: {curr_role}), Recipient User IDs: {recipient_ids}"
        )

        for r_id in recipient_ids:
            notification_number = f"{prefix}{next_seq:04d}"
            next_seq += 1
            
            notif = Notification(
                notification_number=notification_number,
                title=title,
                message=message,
                type=type,
                priority=priority,
                user_id=r_id,
                related_alert_id=related_alert_id,
                related_incident_id=related_incident_id,
                status='Unread'
            )
            db.session.add(notif)
            created_notifications.append(notif)

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

        return created_notifications

    @classmethod
    def mark_as_read(cls, notification_id: int, user_id: int) -> bool:
        """
        Mark a notification as read for a specific user.
        """
        notif = Notification.query.filter_by(id=notification_id, user_id=user_id).first()
        if notif and notif.status == 'Unread':
            notif.status = 'Read'
            notif.read_at = datetime.utcnow()
            db.session.commit()
            return True
        return False

    @classmethod
    def mark_all_as_read(cls, user_id: int) -> int:
        """
        Mark all unread notifications as read for a user.
        """
        unread_notifs = Notification.query.filter_by(user_id=user_id, status='Unread').all()
        now = datetime.utcnow()
        for notif in unread_notifs:
            notif.status = 'Read'
            notif.read_at = now
        db.session.commit()
        return len(unread_notifs)

    @classmethod
    def get_unread_count(cls, user_id: int) -> int:
        """
        Get the count of unread notifications for a user.
        """
        return Notification.query.filter_by(user_id=user_id, status='Unread').count()

    @classmethod
    def get_recent_notifications(cls, user_id: int, limit: int = 5) -> list[Notification]:
        """
        Get recent notifications for a user (newest first).
        """
        return Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).limit(limit).all()

    # Automatic Event Creation Hooks
    @classmethod
    def create_notification_for_alert(cls, alert) -> list[Notification]:
        """
        Create a notification whenever a new HIGH or CRITICAL Alert is generated.
        """
        if alert.severity in ['High', 'Critical']:
            title = f"New Alert: {alert.alert_number}"
            message = alert.message or f"Telemetry indicates high risk security anomaly."
            return cls.broadcast_notification(
                title=title,
                message=message,
                type='Alert',
                priority=alert.severity,
                related_alert_id=alert.id
            )
        return []

    @classmethod
    def create_notification_for_incident(cls, incident) -> list[Notification]:
        """
        Create a notification whenever a new Incident is created.
        """
        title = f"New Incident Escalated: {incident.incident_number}"
        message = f"Incident '{incident.title}' was created and linked to threat indicator."
        return cls.broadcast_notification(
            title=title,
            message=message,
            type='Incident',
            priority=incident.severity,
            related_incident_id=incident.id,
            related_incident=incident
        )

    @classmethod
    def create_notification_for_incident_resolution(cls, incident) -> list[Notification]:
        """
        Create a notification when an Incident is resolved.
        """
        title = f"Incident Resolved: {incident.incident_number}"
        message = f"Incident '{incident.title}' has been successfully resolved."
        return cls.broadcast_notification(
            title=title,
            message=message,
            type='Incident',
            priority=incident.severity,
            related_incident_id=incident.id,
            related_incident=incident
        )

    @classmethod
    def create_notification_for_incident_assignment(cls, incident) -> list[Notification]:
        """
        Create a notification when a user is assigned to an Incident.
        """
        if incident.assignee:
            title = f"Incident Assigned: {incident.incident_number}"
            message = f"You have been assigned to Incident '{incident.title}'."
            # Also broadcasts to Admins (via logic) and the assignee Analyst
            return cls.broadcast_notification(
                title=title,
                message=message,
                type='Incident',
                priority=incident.severity,
                related_incident_id=incident.id,
                related_incident=incident
            )
        return []

    @classmethod
    def create_notification_for_role_change(cls, user, old_role: str, new_role: str) -> list[Notification]:
        """
        Create a notification when an Admin changes a user's role.
        """
        title = f"Security Role Changed"
        message = f"Your operator security role has been changed from '{old_role}' to '{new_role}'."
        return cls.broadcast_notification(
            title=title,
            message=message,
            type='System',
            priority='High',
            target_user_id=user.id
        )

    @classmethod
    def create_notification_for_incident_closure(cls, incident) -> list[Notification]:
        """
        Create a notification when an Incident is closed.
        """
        title = f"Incident Closed: {incident.incident_number}"
        message = f"Incident '{incident.title}' has been successfully closed."
        return cls.broadcast_notification(
            title=title,
            message=message,
            type='Incident',
            priority=incident.severity,
            related_incident_id=incident.id,
            related_incident=incident
        )

    @classmethod
    def create_notification_for_incident_update(cls, incident, details: str) -> list[Notification]:
        """
        Create a notification when an Incident is updated.
        """
        title = f"Incident Updated: {incident.incident_number}"
        message = f"Incident '{incident.title}' has been updated: {details}"
        return cls.broadcast_notification(
            title=title,
            message=message,
            type='Incident',
            priority=incident.severity,
            related_incident_id=incident.id,
            related_incident=incident
        )

    @classmethod
    def create_notification_for_account_status(cls, user, active: bool) -> list[Notification]:
        """
        Create a notification when an operator's active status changes.
        """
        status_str = "activated" if active else "deactivated"
        title = f"Security Account {status_str.capitalize()}"
        message = f"Your operator account has been {status_str}."
        return cls.broadcast_notification(
            title=title,
            message=message,
            type='System',
            priority='High',
            target_user_id=user.id
        )
