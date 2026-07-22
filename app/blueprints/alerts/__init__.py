from flask import Blueprint

alerts_bp = Blueprint('alerts', __name__)

from app.blueprints.alerts import routes as routes  # noqa: E402
