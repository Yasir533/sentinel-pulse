from datetime import datetime
from app.extensions import db
from app.models.activity_log import ActivityLog

def log_activity(message: str, icon: str = 'bi-info-circle', badge_class: str = 'bg-secondary-subtle text-muted') -> ActivityLog:
    """
    Log an activity message with timestamp and styles to the database.
    """
    entry = ActivityLog(
        message=message,
        icon=icon,
        badge_class=badge_class,
        timestamp=datetime.utcnow()
    )
    db.session.add(entry)
    db.session.commit()
    return entry
