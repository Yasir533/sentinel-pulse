from flask import Blueprint

api_bp = Blueprint('api', __name__)

from app.blueprints.api import routes as routes  # noqa: E402
