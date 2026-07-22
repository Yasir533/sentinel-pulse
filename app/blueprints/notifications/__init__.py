from flask import Blueprint

notifications_bp = Blueprint('notifications', __name__)

from app.blueprints.notifications import routes as routes  # noqa: E402
