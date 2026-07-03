from flask import jsonify
from app.blueprints.api import api_bp

@api_bp.route('/status', methods=['GET'])
def get_status():
    """Placeholder API route to fetch system status."""
    return jsonify({
        "status": "healthy",
        "service": "Sentinel Pulse API",
        "version": "Version 2.0 RC-2"
    }), 200

@api_bp.route('/threats', methods=['GET'])
def get_threats():
    """Placeholder API route to fetch threat intelligence data."""
    return jsonify({
        "message": "Threat data API placeholder",
        "data": []
    }), 200
