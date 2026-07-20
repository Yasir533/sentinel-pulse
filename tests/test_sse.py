import pytest
from app.models.user import User
from app.extensions import db
from app.services.realtime_event_service import RealtimeEventService

def test_sse_anonymous_access_rejected(client):
    """Test 1: Unauthenticated anonymous access to SSE stream is rejected with 302 redirect."""
    response = client.get('/api/events/stream')
    assert response.status_code == 302

def test_sse_authenticated_access(client, app):
    """Test 2: Authenticated user can connect to SSE stream with text/event-stream content type."""
    with app.app_context():
        user = User(username='sse_user', email='sse_user@sentinelpulse.local', role='Admin')
        user.set_password('Password123!')
        db.session.add(user)
        db.session.commit()

    login_res = client.post('/auth/login', data={
        'username_or_email': 'sse_user',
        'password': 'Password123!'
    }, follow_redirects=True)
    assert login_res.status_code == 200

    response = client.get('/api/events/stream')
    assert response.status_code == 200
    assert response.mimetype == 'text/event-stream'

def test_realtime_event_publisher_rbac_filtering(app):
    """Test 3 & 4: Admin receives Admin events, Analyst receives Analyst events, Viewer receives read-only events."""
    with app.app_context():
        admin_listener = RealtimeEventService.register_listener(user_id=1, role='Admin')
        analyst_listener = RealtimeEventService.register_listener(user_id=2, role='Analyst')
        viewer_listener = RealtimeEventService.register_listener(user_id=3, role='Viewer')

        try:
            # 1. Admin-only event (system.health_warning)
            delivered = RealtimeEventService.publish('system.health_warning', {'msg': 'CPU High'}, target_role='Admin')
            assert delivered >= 1
            assert not admin_listener['queue'].empty()
            assert analyst_listener['queue'].empty()
            assert viewer_listener['queue'].empty()

            # Drain queue
            admin_listener['queue'].get_nowait()

            # 2. Analyst role event (incident.created)
            RealtimeEventService.publish('incident.created', {'incident_id': 101}, target_role='Analyst')
            assert not admin_listener['queue'].empty()
            assert not analyst_listener['queue'].empty()
            assert viewer_listener['queue'].empty()
        finally:
            RealtimeEventService.unregister_listener(admin_listener)
            RealtimeEventService.unregister_listener(analyst_listener)
            RealtimeEventService.unregister_listener(viewer_listener)

def test_object_level_user_targeting_isolation(app):
    """Test 5 & 6: User-targeted and Analyst-targeted isolation (Analyst A vs Analyst B)."""
    with app.app_context():
        analyst_a_listener = RealtimeEventService.register_listener(user_id=101, role='Analyst')
        analyst_b_listener = RealtimeEventService.register_listener(user_id=102, role='Analyst')

        try:
            # Publish event targeted specifically to Analyst A (user_id=101)
            RealtimeEventService.publish(
                event_type='incident.assigned',
                payload={'incident_number': 'INC-2026-0001', 'assigned_to': 101},
                target_user_id=101
            )

            assert not analyst_a_listener['queue'].empty()
            assert analyst_b_listener['queue'].empty()

            evt = analyst_a_listener['queue'].get_nowait()
            assert evt['payload']['assigned_to'] == 101
        finally:
            RealtimeEventService.unregister_listener(analyst_a_listener)
            RealtimeEventService.unregister_listener(analyst_b_listener)

def test_sse_payload_secret_sanitization(app):
    """Test 7-10: SSE payloads strip sensitive credential fields (passwords, tokens, api keys)."""
    with app.app_context():
        listener = RealtimeEventService.register_listener(user_id=50, role='Admin')
        try:
            dirty_payload = {
                'incident_id': 505,
                'status': 'Investigating',
                'password': 'SuperSecretPassword!',
                'api_key': 'vt_api_key_secret_12345',
                'jwt_secret': 'shhhh_secret'
            }
            RealtimeEventService.publish('incident.updated', dirty_payload, target_role='Admin')
            
            assert not listener['queue'].empty()
            evt = listener['queue'].get_nowait()
            payload = evt['payload']

            # Assert safe metadata is kept
            assert payload['incident_id'] == 505
            assert payload['status'] == 'Investigating'

            # Assert secrets are stripped
            assert 'password' not in payload
            assert 'api_key' not in payload
            assert 'jwt_secret' not in payload
        finally:
            RealtimeEventService.unregister_listener(listener)
