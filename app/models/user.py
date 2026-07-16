from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db
from sqlalchemy.ext.hybrid import hybrid_property

class User(db.Model, UserMixin):
    """
    Database model representing platform users.
    Inherits UserMixin to provide integration with Flask-Login.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    _role = db.Column('role', db.String(20), nullable=False, default='Viewer')

    @hybrid_property
    def role(self) -> str:
        """Get the trimmed and capitalized user role."""
        return self._role.strip().capitalize() if self._role else 'Viewer'

    @role.setter
    def role(self, value: str) -> None:
        """Set the user role, trimming any leading/trailing whitespace and capitalizing."""
        self._role = value.strip().capitalize() if value else 'Viewer'

    @role.expression
    def role(cls):
        """Database expression for the role hybrid property."""
        return cls._role

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)

    def __init__(self, **kwargs):
        role_val = kwargs.pop('role', 'Viewer')
        super().__init__(**kwargs)
        self.role = role_val

    def set_password(self, password: str) -> None:
        """Hash and set the user's password using Werkzeug."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify the user's password against the hashed value."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f'<User {self.username} ({self.role})>'
