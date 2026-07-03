from flask import request, has_request_context
from flask_login import current_user
from app.extensions import db
from app.models.audit_log import AuditLog

class AuditService:
    @staticmethod
    def log(action: str, entity: str, before: str = None, after: str = None, status: str = 'Success', username: str = None, role: str = None) -> AuditLog:
        """
        Create a SOC compliance audit log record.
        Automatically grabs IP and current operator context if available.
        """
        ip_addr = '127.0.0.1'
        if has_request_context():
            ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
            if ',' in ip_addr:
                ip_addr = ip_addr.split(',')[0].strip()

        # Resolve operator username & role
        if not username:
            if current_user and current_user.is_authenticated:
                username = current_user.username
                role = current_user.role
            else:
                username = 'System/Anonymous'
                role = 'None'
        
        if not role:
            role = 'None'

        log_entry = AuditLog(
            username=username,
            role=role,
            ip_address=ip_addr,
            action=action,
            entity=entity,
            before_state=before,
            after_state=after,
            status=status
        )
        
        try:
            db.session.add(log_entry)
            db.session.commit()
        except Exception:
            db.session.rollback()
            # If database commit fails, still allow workflow execution to continue
            
        return log_entry
