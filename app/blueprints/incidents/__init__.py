from flask import Blueprint

incidents_bp = Blueprint('incidents', __name__)

from app.blueprints.incidents import routes as routes  # noqa: E402
