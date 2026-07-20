import pytest
from app.models.user import User
from app.extensions import db
from app.services.realtime_event_service import RealtimeEventService

def test_sse_anonymous_access_rejected(client):
    """Test that unauthenticated anonymous access to SSE stream is rejected with 302 redirect."""
    response = client.get('/api/events/stream')
    assert response.status_code == 302

def test_sse_authenticated_access(client, app):
    """Test that authenticated users can connect to SSE stream with text/event-stream content type."""
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
    """Test that RealtimeEventService delivers events based on subscriber roles."""
    with app.app_context():
        # Register Admin & Viewer listeners
        admin_listener = RealtimeEventService.register_listener(user_id=1, role='Admin')
        viewer_listener = RealtimeEventService.register_listener(user_id=2, role='Viewer')

        try:
            # 1. Publish Admin-only event
            delivered = RealtimeEventService.publish('system.health_warning', {'msg': 'CPU High'}, target_role='Admin')
            assert delivered >= 1
            assert not admin_listener['queue'].empty()
            assert viewer_listener['queue'].empty()

            # Drain queue
            admin_listener['queue'].get_nowait()

            # 2. Publish general alert
            RealtimeEventService.publish('alert.created', {'alert_number': 'ALT-2026-0001'})
            assert not admin_listener['queue'].empty()
        finally:
            RealtimeEventService.unregister_listener(admin_listener)
            RealtimeEventService.unregister_listener(viewer_listener)

def test_object_level_user_targeting_isolation(app):
    """Test object-level security: Analyst A receives targeted events while Analyst B does not."""
    with app.app_context():
        analyst_a_listener = RealtimeEventService.register_listener(user_id=101, role='Analyst')
        analyst_b_listener = RealtimeEventService.register_listener(user_id=102, role='Analyst')

        try:
            # Publish event targeted specifically to Analyst A (user_id=101)
            RealtimeEventService.publish(
                event_type='notification.created',
                payload={'notification_number': 'NTF-2026-0001', 'title': 'Assigned Task'},
                target_user_id=101
            )

            assert not analyst_a_listener['queue'].empty()
            assert analyst_b_listener['queue'].empty()

            evt = analyst_a_listener['queue'].get_nowait()
            assert evt['payload']['title'] == 'Assigned Task'
        finally:
            RealtimeEventService.unregister_listener(analyst_a_listener)
            RealtimeEventService.unregister_listener(analyst_b_listener)
