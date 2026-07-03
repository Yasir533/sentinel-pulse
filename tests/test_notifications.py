import pytest
from datetime import datetime
from app.models.user import User
from app.models.threat import Threat
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.notification import Notification
from app.extensions import db
from app.services.notification import NotificationService
from app.services.incident import create_incident, update_incident
from app.services.alert import AlertService

@pytest.fixture
def seed_users(app):
    """Seed three users with different roles (Admin, Analyst, Viewer)."""
    with app.app_context():
        admin = User(username='admin_op', email='admin@sentinelpulse.local', role='Admin')
        admin.set_password('AdminPassword123')
        
        analyst = User(username='analyst_op', email='analyst@sentinelpulse.local', role='Analyst')
        analyst.set_password('AnalystPassword123')
        
        viewer = User(username='viewer_op', email='viewer@sentinelpulse.local', role='Viewer')
        viewer.set_password('ViewerPassword123')
        
        db.session.add_all([admin, analyst, viewer])
        db.session.commit()
        
        return {
            'admin': admin.id,
            'analyst': analyst.id,
            'viewer': viewer.id
        }

def test_notification_creation_and_fields(app, seed_users):
    """Test manual notification creation and helper properties."""
    with app.app_context():
        notif = NotificationService.create_notification(
            user_id=seed_users['analyst'],
            title="Manual Intel Notice",
            message="Reputation feed updated",
            type="Threat",
            priority="Medium"
        )
        assert notif is not None
        assert notif.notification_number.startswith("NTF-2026-")
        assert notif.status == 'Unread'
        assert notif.read_at is None
        assert notif.relative_time == 'just now'
        assert notif.color_class == 'info'
        assert notif.icon_class == 'bi-virus'
        assert notif.link_url == '/notifications/'

def test_broadcaster_role_rules(app, seed_users):
    """Test broadcasting notifications to role-based subsets of users."""
    with app.app_context():
        # 1. Alert Notification: Should broadcast to Admin and Analyst
        NotificationService.broadcast_notification(
            title="Alert Notice",
            message="New alert triggered",
            type="Alert",
            priority="High"
        )
        # Admin and Analyst should each have 1 notification; Viewer should have 0
        assert Notification.query.filter_by(user_id=seed_users['admin']).count() == 1
        assert Notification.query.filter_by(user_id=seed_users['analyst']).count() == 1
        assert Notification.query.filter_by(user_id=seed_users['viewer']).count() == 0

        # Reset notifications
        Notification.query.delete()
        db.session.commit()

        # 2. Threat Notification: All roles should receive it (informational read-only)
        NotificationService.broadcast_notification(
            title="Threat Feed",
            message="IOC update",
            type="Threat",
            priority="Low"
        )
        assert Notification.query.filter_by(user_id=seed_users['admin']).count() == 1
        assert Notification.query.filter_by(user_id=seed_users['analyst']).count() == 1
        assert Notification.query.filter_by(user_id=seed_users['viewer']).count() == 1

def test_notification_unread_count_and_recent(app, seed_users):
    """Test unread counters and recent notification query limits."""
    with app.app_context():
        # Create 6 notifications for Analyst
        for i in range(6):
            NotificationService.create_notification(
                user_id=seed_users['analyst'],
                title=f"Notification {i}",
                message="Details",
                type="System",
                priority="Low"
            )
        
        assert NotificationService.get_unread_count(seed_users['analyst']) == 6
        recent = NotificationService.get_recent_notifications(seed_users['analyst'], limit=5)
        assert len(recent) == 5
        # Order should be newest first (Notification 5 first)
        assert recent[0].title == "Notification 5"

def test_mark_read_and_mark_all_read(client, app, seed_users):
    """Test routes to mark individual and all notifications as read."""
    with app.app_context():
        n1 = NotificationService.create_notification(seed_users['analyst'], "Notif 1", "Msg 1", "System", "Low")
        n2 = NotificationService.create_notification(seed_users['analyst'], "Notif 2", "Msg 2", "System", "Low")
        n1_id = n1.id
        n2_id = n2.id

    # Login as Analyst
    client.post('/auth/login', data={'username_or_email': 'analyst_op', 'password': 'AnalystPassword123'})

    # Mark n1 as read
    response = client.post(f'/notifications/mark-read/{n1_id}', follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        assert db.session.get(Notification, n1_id).status == 'Read'
        assert db.session.get(Notification, n2_id).status == 'Unread'

    # Mark all as read
    response = client.post('/notifications/mark-all-read', follow_redirects=True)
    assert response.status_code == 200
    assert b"Marked 1 notifications as read" in response.data
    with app.app_context():
        assert db.session.get(Notification, n2_id).status == 'Read'

def test_notifications_filter_and_search(client, app, seed_users):
    """Test keyword searching and priority/status filtering in list route."""
    with app.app_context():
        NotificationService.create_notification(seed_users['analyst'], "Special Alert Name", "Crucial Message", "Alert", "Critical")
        NotificationService.create_notification(seed_users['analyst'], "Standard Log Update", "Quiet update", "System", "Low")

    # Login as Analyst
    client.post('/auth/login', data={'username_or_email': 'analyst_op', 'password': 'AnalystPassword123'})

    # 1. Search keyword
    response = client.get('/notifications/?q=Special')
    assert b'Special Alert Name' in response.data
    assert b'Standard Log Update' not in response.data

    # 2. Filter priority
    response = client.get('/notifications/?priority=Critical')
    assert b'Special Alert Name' in response.data
    assert b'Standard Log Update' not in response.data

    # 3. Filter type
    response = client.get('/notifications/?type=System')
    assert b'Standard Log Update' in response.data
    assert b'Special Alert Name' not in response.data

def test_automatic_notification_alerts(app, seed_users):
    """Test generating notifications automatically when High/Critical Alerts are created."""
    with app.app_context():
        threat = Threat(threat_type='Malware', ioc_type='SHA256', ioc_value='hash_high', source='Test', created_by=seed_users['analyst'])
        db.session.add(threat)
        db.session.commit()

        # Generate a Critical alert using AlertService rules
        alert = Alert(alert_number='ALT-2026-0099', threat_id=threat.id, severity='Critical', status='New', message="Automatic notice check")
        db.session.add(alert)
        db.session.commit()

        # Trigger notification generator hook
        NotificationService.create_notification_for_alert(alert)

        # Admin and Analyst should have notifications generated
        n_admin = Notification.query.filter_by(user_id=seed_users['admin'], related_alert_id=alert.id).first()
        n_analyst = Notification.query.filter_by(user_id=seed_users['analyst'], related_alert_id=alert.id).first()
        
        assert n_admin is not None
        assert n_admin.title == f"New Alert: {alert.alert_number}"
        assert n_analyst is not None

def test_automatic_notification_incidents(app, seed_users):
    """Test automatic notifications for Incident escalations, assignments, and resolutions."""
    with app.app_context():
        threat = Threat(threat_type='Malware', ioc_type='SHA256', ioc_value='inc_hash', source='Test', created_by=seed_users['analyst'])
        db.session.add(threat)
        db.session.commit()
        threat_id = threat.id

        # 1. Create incident -> triggers create notification & assignee notification
        incident = create_incident(
            threat_id=threat_id,
            title="Breach Threat Intel",
            description="Testing breach response",
            severity="High",
            status="Open",
            assigned_to=seed_users['analyst'],
            creator_id=seed_users['admin']
        )
        
        # Verify incident creation notification is broadcast
        notif_creation = Notification.query.filter_by(user_id=seed_users['admin'], related_incident_id=incident.id, type='Incident').first()
        assert notif_creation is not None
        assert "escalated" in notif_creation.title.lower() or "created" in notif_creation.message.lower()

        # Verify assignee notification is broadcast
        notifs_analyst = Notification.query.filter_by(user_id=seed_users['analyst'], related_incident_id=incident.id, type='Incident').all()
        assert len(notifs_analyst) >= 1
        assert any("assigned" in n.title.lower() or "assigned" in n.message.lower() for n in notifs_analyst)

        # Reset notification DB
        Notification.query.delete()
        db.session.commit()

        # 2. Resolve incident -> triggers resolved notification
        updater = db.session.get(User, seed_users['admin'])
        update_incident(
            incident=incident,
            title="Breach Threat Intel",
            description="Testing breach response",
            severity="High",
            status="Resolved",
            assigned_to=seed_users['analyst'],
            resolution_notes="Closed successfully",
            updater=updater
        )
        
        notif_resolved = Notification.query.filter_by(user_id=seed_users['admin'], related_incident_id=incident.id).first()
        assert notif_resolved is not None
        assert "resolved" in notif_resolved.title.lower() or "resolved" in notif_resolved.message.lower()

def test_automatic_notification_role_change(client, app, seed_users):
    """Test generating notifications automatically when user role is updated."""
    # Login as Admin
    client.post('/auth/login', data={'username_or_email': 'admin_op', 'password': 'AdminPassword123'})

    # Change Analyst's role to Viewer
    response = client.post(f'/admin/users/{seed_users["analyst"]}/edit', data={
        'role': 'Viewer',
        'status': 'Active'
    }, follow_redirects=True)
    assert response.status_code == 200

    # Analyst should have a System notification for role change
    with app.app_context():
        notif = Notification.query.filter_by(user_id=seed_users['analyst'], type='System').first()
        assert notif is not None
        assert "role" in notif.title.lower() or "role" in notif.message.lower()

def test_bell_dropdown_and_poll_api(client, app, seed_users):
    """Test API polling returns recent unread counts and rendered HTML segments."""
    with app.app_context():
        NotificationService.create_notification(seed_users['analyst'], "Update 1", "Body 1", "Alert", "High")
        NotificationService.create_notification(seed_users['analyst'], "Update 2", "Body 2", "Incident", "Critical")

    # Login as Analyst
    client.post('/auth/login', data={'username_or_email': 'analyst_op', 'password': 'AnalystPassword123'})

    # Call poll API
    response = client.get('/notifications/api/poll')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['unread_count'] == 2
    assert 'dropdown_html' in json_data
    assert 'widget_html' in json_data
    assert 'Update 1' in json_data['dropdown_html']
    assert 'Update 2' in json_data['dropdown_html']

def test_dashboard_widgets_contain_data(client, app, seed_users):
    """Test that dashboards show appropriate recent notifications widgets."""
    with app.app_context():
        NotificationService.create_notification(seed_users['admin'], "Admin notice", "Secret log", "System", "High")
        NotificationService.create_notification(seed_users['analyst'], "Analyst case notice", "Docket assigned", "Incident", "Medium")
        NotificationService.create_notification(seed_users['viewer'], "Viewer update", "Threat feed news", "Threat", "Low")

    # 1. Admin dashboard widget
    client.post('/auth/login', data={'username_or_email': 'admin_op', 'password': 'AdminPassword123'})
    response = client.get('/admin/dashboard')
    assert b'Recent Notifications' in response.data
    assert b'Admin notice' in response.data
    client.get('/auth/logout')

    # 2. Analyst dashboard widget
    client.post('/auth/login', data={'username_or_email': 'analyst_op', 'password': 'AnalystPassword123'})
    response = client.get('/analyst/dashboard')
    assert b'My Notifications' in response.data
    assert b'Analyst case notice' in response.data
    client.get('/auth/logout')

    # 3. Viewer dashboard widget
    client.post('/auth/login', data={'username_or_email': 'viewer_op', 'password': 'ViewerPassword123'})
    response = client.get('/viewer/dashboard')
    assert b'Security Updates' in response.data
    assert b'Viewer update' in response.data

def test_additional_stabilization_notifications(client, app, seed_users):
    """Test generating notifications automatically for incident closures, updates, and account status changes."""
    # 1. Test account status changes (activation/deactivation)
    # Login as Admin
    client.post('/auth/login', data={'username_or_email': 'admin_op', 'password': 'AdminPassword123'})

    # Deactivate Analyst
    response = client.post(f'/admin/users/{seed_users["analyst"]}/edit', data={
        'role': 'Analyst',
        'status': 'Inactive'
    }, follow_redirects=True)
    assert response.status_code == 200

    # Analyst should have a System notification for account status change
    with app.app_context():
        notif = Notification.query.filter_by(user_id=seed_users['analyst'], type='System').order_by(Notification.created_at.desc()).first()
        assert notif is not None
        assert "deactivated" in notif.message.lower()

    # 2. Test incident general updates and closure
    with app.app_context():
        threat = Threat(threat_type='Intrusion', ioc_type='IP Address', ioc_value='1.2.3.4', source='Test', created_by=seed_users['admin'])
        db.session.add(threat)
        db.session.commit()
        threat_id = threat.id
        
        # Create incident
        incident = create_incident(
            threat_id=threat_id,
            title="General Incident Test",
            description="Testing updates and close",
            severity="Medium",
            status="Open",
            assigned_to=seed_users['admin'],
            creator_id=seed_users['admin']
        )
        
        # Clean notifications generated during create
        Notification.query.delete()
        db.session.commit()
        
        # Update incident status to In Progress (not Resolved/Closed)
        updater = db.session.get(User, seed_users['admin'])
        update_incident(
            incident=incident,
            title="General Incident Test",
            description="Testing updates and close",
            severity="Medium",
            status="In Progress",
            assigned_to=seed_users['admin'],
            resolution_notes=None,
            updater=updater
        )
        
        notif_update = Notification.query.filter_by(user_id=seed_users['admin'], related_incident_id=incident.id).first()
        assert notif_update is not None
        assert "status updated" in notif_update.message.lower()
        
        # Clean notifications
        Notification.query.delete()
        db.session.commit()
        
        # Resolve incident first
        update_incident(
            incident=incident,
            title="General Incident Test",
            description="Testing updates and close",
            severity="Medium",
            status="Resolved",
            assigned_to=seed_users['admin'],
            resolution_notes="Resolved",
            updater=updater
        )
        
        # Clean notifications
        Notification.query.delete()
        db.session.commit()
        
        # Close incident (generates Closure notification)
        update_incident(
            incident=incident,
            title="General Incident Test",
            description="Testing updates and close",
            severity="Medium",
            status="Closed",
            assigned_to=seed_users['admin'],
            resolution_notes="Closed",
            updater=updater
        )
        
        notif_close = Notification.query.filter_by(user_id=seed_users['admin'], related_incident_id=incident.id).first()
        assert notif_close is not None
        assert "closed" in notif_close.title.lower() or "closed" in notif_close.message.lower()
