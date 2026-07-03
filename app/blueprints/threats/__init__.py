from flask import Blueprint

threats_bp = Blueprint('threats', __name__)

from app.blueprints.threats import routes
