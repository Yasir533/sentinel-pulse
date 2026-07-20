import json
import time
from datetime import datetime
from flask import Response, jsonify, stream_with_context
from app.blueprints.api import api_bp
from app.models.alert import Alert
from app.models.threat import Threat

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
def event_stream():
    """
    Server-Sent Events (SSE) stream endpoint for real-time security events,
    threat alerts, and dashboard updates.
    """
    def generate():
        last_check = datetime.utcnow()
        yield f"data: {json.dumps({'type': 'connection', 'status': 'connected', 'timestamp': last_check.isoformat()})}\n\n"
        
        # Send initial pulse
        while True:
            time.sleep(5)
            now = datetime.utcnow()
            
            # Check for new critical alerts since last check
            recent_alerts = Alert.query.filter(Alert.created_at >= last_check).all()
            if recent_alerts:
                for alert in recent_alerts:
                    event_payload = {
                        'type': 'security_alert',
                        'alert_number': alert.alert_number,
                        'severity': alert.severity,
                        'message': alert.message,
                        'created_at': alert.created_at.isoformat()
                    }
                    yield f"data: {json.dumps(event_payload)}\n\n"
            
            # Send heartbeat event
            heartbeat = {
                'type': 'heartbeat',
                'timestamp': now.isoformat()
            }
            yield f"data: {json.dumps(heartbeat)}\n\n"
            last_check = now

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

