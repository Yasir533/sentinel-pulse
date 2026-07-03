import pytest
from app.models.user import User
from app.models.activity_log import ActivityLog
from app.extensions import db

@pytest.fixture
def seed_users(app):
    """Seed four users with different roles (two Admins, one Analyst, one Viewer)."""
    with app.app_context():
        admin = User(username='admin_op', email='admin@sentinelpulse.local', role='Admin')
        admin.set_password('AdminPassword123')
        
        admin2 = User(username='admin_op2', email='admin2@sentinelpulse.local', role='Admin')
        admin2.set_password('AdminPassword123')
        
        analyst = User(username='analyst_op', email='analyst@sentinelpulse.local', role='Analyst')
        analyst.set_password('AnalystPassword123')
        
        viewer = User(username='viewer_op', email='viewer@sentinelpulse.local', role='Viewer')
        viewer.set_password('ViewerPassword123')
        
        db.session.add_all([admin, admin2, analyst, viewer])
        db.session.commit()
        
        return {
            'admin': admin.id,
            'admin2': admin2.id,
            'analyst': analyst.id,
            'viewer': viewer.id
        }

def test_admin_access_user_management(client, app, seed_users):
    """Test that Admin can access the users page, but Viewer and Analyst cannot."""
    # 1. Analyst cannot access
    client.post('/auth/login', data={
        'username_or_email': 'analyst_op',
        'password': 'AnalystPassword123'
    })
    response = client.get('/admin/users')
    assert response.status_code == 403
    client.get('/auth/logout')

    # 2. Viewer cannot access
    client.post('/auth/login', data={
        'username_or_email': 'viewer_op',
        'password': 'ViewerPassword123'
    })
    response = client.get('/admin/users')
    assert response.status_code == 403
    client.get('/auth/logout')

    # 3. Admin can access
    client.post('/auth/login', data={
        'username_or_email': 'admin_op',
        'password': 'AdminPassword123'
    })
    response = client.get('/admin/users')
    assert response.status_code == 200
    assert b"Operator Registry" in response.data

def test_edit_user_role_and_status(client, app, seed_users):
    """Test standard valid user role and status update by Admin."""
    client.post('/auth/login', data={
        'username_or_email': 'admin_op',
        'password': 'AdminPassword123'
    })

    # Update viewer to Analyst and deactivate
    response = client.post(f'/admin/users/{seed_users["viewer"]}/edit', data={
        'role': 'Analyst',
        'status': 'Inactive'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"User role updated successfully." in response.data
    assert b"Account deactivated successfully." in response.data

    with app.app_context():
        target_user = db.session.get(User, seed_users['viewer'])
        assert target_user.role == 'Analyst'
        assert target_user.is_active is False

        # Verify audit log entry
        log_entry = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).first()
        assert log_entry is not None
        assert "Admin admin_op changed viewer_op's role Viewer -> Analyst" in log_entry.message

def test_prevent_self_role_modification(client, app, seed_users):
    """Test that Admin cannot change their own role."""
    client.post('/auth/login', data={
        'username_or_email': 'admin_op',
        'password': 'AdminPassword123'
    })

    response = client.post(f'/admin/users/{seed_users["admin"]}/edit', data={
        'role': 'Viewer',
        'status': 'Active'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"You cannot change your own role." in response.data

    with app.app_context():
        admin_user = db.session.get(User, seed_users['admin'])
        assert admin_user.role == 'Admin'

def test_prevent_last_admin_role_change_and_deactivation(client, app, seed_users):
    """Test that the last remaining Admin's role cannot be removed and they cannot be deactivated."""
    # Delete the second admin so admin_op becomes the last admin
    with app.app_context():
        db.session.delete(db.session.get(User, seed_users['admin2']))
        db.session.commit()

    client.post('/auth/login', data={
        'username_or_email': 'admin_op',
        'password': 'AdminPassword123'
    })

    # Attempt to change role of last admin
    response = client.post(f'/admin/users/{seed_users["admin"]}/edit', data={
        'role': 'Analyst',
        'status': 'Active'
    }, follow_redirects=True)
    assert b"Cannot remove the Admin role from the last remaining Administrator." in response.data

    # Attempt to deactivate last admin
    response = client.post(f'/admin/users/{seed_users["admin"]}/edit', data={
        'role': 'Admin',
        'status': 'Inactive'
    }, follow_redirects=True)
    assert b"Cannot deactivate the last remaining Administrator." in response.data

    with app.app_context():
        admin_user = db.session.get(User, seed_users['admin'])
        assert admin_user.role == 'Admin'
        assert admin_user.is_active is True

def test_validate_role_and_status_values(client, app, seed_users):
    """Test server side validation of input parameters."""
    client.post('/auth/login', data={
        'username_or_email': 'admin_op',
        'password': 'AdminPassword123'
    })

    # Invalid role
    response = client.post(f'/admin/users/{seed_users["viewer"]}/edit', data={
        'role': 'SuperAdmin',
        'status': 'Active'
    }, follow_redirects=True)
    assert b"Invalid role value." in response.data

    # Invalid status
    response = client.post(f'/admin/users/{seed_users["viewer"]}/edit', data={
        'role': 'Viewer',
        'status': 'Suspended'
    }, follow_redirects=True)
    assert b"Invalid status value." in response.data
