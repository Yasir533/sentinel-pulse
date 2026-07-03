import pytest
from app.models.user import User
from app.extensions import db

def test_register_user(client, app):
    """Test standard valid user registration."""
    response = client.post('/auth/register', data={
        'username': 'test_user',
        'email': 'test_user@sentinelpulse.local',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Registration successful!" in response.data
    
    with app.app_context():
        user = User.query.filter_by(username='test_user').first()
        assert user is not None
        assert user.email == 'test_user@sentinelpulse.local'
        assert user.role == 'Viewer'
        assert user.check_password('Password123!') is True
        assert user.check_password('WrongPassword') is False

def test_register_validations(client, app):
    """Test registration validations like password match, length, duplicates."""
    # 1. Password mismatch
    response = client.post('/auth/register', data={
        'username': 'mismatch',
        'email': 'mismatch@sentinelpulse.local',
        'password': 'Password123!',
        'confirm_password': 'Password1234'
    }, follow_redirects=True)
    assert b"Passwords do not match." in response.data

    # 2. Password too short
    response = client.post('/auth/register', data={
        'username': 'short',
        'email': 'short@sentinelpulse.local',
        'password': 'Short',
        'confirm_password': 'Short'
    }, follow_redirects=True)
    assert b"Password must be at least 8 characters long." in response.data

    # 3. Duplicate checks
    # Seed user first
    with app.app_context():
        user = User(username='existing_user', email='existing@sentinelpulse.local')
        user.set_password('Password123!')
        db.session.add(user)
        db.session.commit()

    # Try duplicate username
    response = client.post('/auth/register', data={
        'username': 'existing_user',
        'email': 'different@sentinelpulse.local',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    }, follow_redirects=True)
    assert b"Username is already taken." in response.data

    # Try duplicate email
    response = client.post('/auth/register', data={
        'username': 'different_user',
        'email': 'existing@sentinelpulse.local',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    }, follow_redirects=True)
    assert b"Email address is already registered." in response.data

def test_login_and_logout(client, app):
    """Test login with username or email, remember me, and logout."""
    with app.app_context():
        user = User(username='login_user', email='login_user@sentinelpulse.local')
        user.set_password('SecretPassword123')
        db.session.add(user)
        db.session.commit()

    # 1. Invalid login
    response = client.post('/auth/login', data={
        'username_or_email': 'login_user',
        'password': 'WrongPassword'
    }, follow_redirects=True)
    assert b"Invalid username/email or password." in response.data

    # 2. Valid login via username
    response = client.post('/auth/login', data={
        'username_or_email': 'login_user',
        'password': 'SecretPassword123'
    }, follow_redirects=True)
    assert b"Welcome back, login_user!" in response.data
    assert b"Monitoring Dashboard" in response.data  # Updated dashboard heading

    # 3. Logout
    response = client.get('/auth/logout', follow_redirects=True)
    assert b"You have been logged out successfully." in response.data
    assert b"Access Sentinel Console" in response.data # Login page text

    # 4. Valid login via email
    response = client.post('/auth/login', data={
        'username_or_email': 'login_user@sentinelpulse.local',
        'password': 'SecretPassword123'
    }, follow_redirects=True)
    assert b"Welcome back, login_user!" in response.data

def test_role_protection(client, app):
    """Test role restriction decorator (@role_required)."""
    # Create two users: Admin and Viewer
    with app.app_context():
        admin = User(username='admin_op', email='admin@sentinelpulse.local', role='Admin')
        admin.set_password('AdminPassword123')
        viewer = User(username='viewer_op', email='viewer@sentinelpulse.local', role='Viewer')
        viewer.set_password('ViewerPassword123')
        db.session.add_all([admin, viewer])
        db.session.commit()

    # Try accessing admin-only without login -> redirected to login
    response = client.get('/auth/admin-only')
    assert response.status_code == 302

    # Login as Viewer
    client.post('/auth/login', data={
        'username_or_email': 'viewer_op',
        'password': 'ViewerPassword123'
    })
    
    # Try accessing admin-only as Viewer -> 403 Forbidden
    response = client.get('/auth/admin-only')
    assert response.status_code == 403
    assert b"Access Level Insufficient" in response.data

    # Logout Viewer
    client.get('/auth/logout')

    # Login as Admin
    client.post('/auth/login', data={
        'username_or_email': 'admin_op',
        'password': 'AdminPassword123'
    })
    
    # Try accessing admin-only as Admin -> 200 OK
    response = client.get('/auth/admin-only')
    assert response.status_code == 200
    assert b"Admin Access Granted" in response.data

def test_user_role_whitespace_stripping(client, app):
    """Verify that roles containing leading or trailing whitespace are stripped on load/set,
    and that the decorators handle them correctly.
    """
    with app.app_context():
        # Create a user with leading/trailing spaces in their role
        dirty_user = User(
            username='dirty_admin',
            email='dirty_admin@sentinelpulse.local',
            role='   Admin  '
        )
        dirty_user.set_password('DirtyPassword123')
        db.session.add(dirty_user)
        db.session.commit()

        # The role should be retrieved as clean 'Admin'
        assert dirty_user.role == 'Admin'
        assert dirty_user._role == 'Admin'

    # Authenticate as the newly created user
    client.post('/auth/login', data={
        'username_or_email': 'dirty_admin',
        'password': 'DirtyPassword123'
    })

    # Access the admin-only route; it should allow access because whitespace is stripped
    response = client.get('/auth/admin-only')
    assert response.status_code == 200
    assert b"Admin Access Granted" in response.data
