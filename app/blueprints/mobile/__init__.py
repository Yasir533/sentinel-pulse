from flask import Blueprint

mobile_bp = Blueprint('mobile', __name__, template_folder='templates')

from app.blueprints.mobile import routes
