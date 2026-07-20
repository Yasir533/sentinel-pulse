import json
import queue
from datetime import datetime
from flask import Response, jsonify, stream_with_context
from flask_login import login_required, current_user
from app.blueprints.api import api_bp
from app.models.threat import Threat
from app.services.realtime_event_service import RealtimeEventService

@api_bp.route('/status', methods=['GET'])
def get_status():
    """API route to fetch system status."""
    return jsonify({
        "status": "healthy",
        "service": "Sentinel Pulse API",
        "version": "Version 2.0 RC-2"
    }), 200

@api_bp.route('/threats', methods=['GET'])
def get_threats():
    """API route to fetch threat intelligence data."""
    threats = Threat.query.order_by(Threat.created_at.desc()).limit(50).all()
    return jsonify({
        "status": "success",
        "data": [t.to_dict() for t in threats]
    }), 200

@api_bp.route('/events/stream')
@login_required
def event_stream():
    """
    Authenticated Server-Sent Events (SSE) stream endpoint for real-time security events,
    threat alerts, and dashboard updates. Uses same-origin Flask-Login session authentication.
    """
    user_id = current_user.id
    role = current_user.role

    def generate():
        listener = RealtimeEventService.register_listener(user_id, role)
        try:
            # Connection announcement
            conn_payload = {
                'event_type': 'connection',
                'status': 'connected',
                'user_id': user_id,
                'role': role,
                'timestamp': datetime.utcnow().isoformat() + "Z"
            }
            yield f"data: {json.dumps(conn_payload)}\n\n"

            while True:
                try:
                    # Wait up to 15 seconds for a published event
                    event_obj = listener['queue'].get(timeout=15)
                    yield f"data: {json.dumps(event_obj)}\n\n"
                except queue.Empty:
                    # Send periodic heartbeat to keep connection alive
                    heartbeat = {
                        'event_type': 'heartbeat',
                        'timestamp': datetime.utcnow().isoformat() + "Z"
                    }
                    yield f"data: {json.dumps(heartbeat)}\n\n"
        finally:
            RealtimeEventService.unregister_listener(listener)

    return Response(stream_with_context(generate()), mimetype='text/event-stream')
