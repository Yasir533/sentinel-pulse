import pytest
from app.models.user import User
from app.extensions import db

@pytest.fixture
def seed_user(app):
    """Seed a test user and return credentials."""
    with app.app_context():
        user = User(username='test_analyst', email='analyst@sentinelpulse.local', role='Analyst')
        user.set_password('SecurePassword123')
        db.session.add(user)
        db.session.commit()
        return user.id

def test_api_threats_unauthorized(client):
    """Test that public threats API rejects requests without a valid API Key."""
    response = client.get('/api/threats')
    assert response.status_code == 401
    json_data = response.get_json()
    assert json_data['status'] == 'error'
    assert 'Unauthorized' in json_data['message']

def test_api_threats_authorized_header(client, app):
    """Test that public threats API accepts valid X-API-Key header."""
    response = client.get('/api/threats', headers={'X-API-Key': 'sentinel_pulse_api_key_2026'})
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['status'] == 'success'
    assert 'data' in json_data

def test_api_threats_authorized_bearer(client):
    """Test that public threats API accepts valid Bearer token."""
    response = client.get('/api/threats', headers={'Authorization': 'Bearer sentinel_pulse_api_key_2026'})
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['status'] == 'success'

def test_api_threats_authorized_query_param(client):
    """Test that public threats API accepts valid API key query parameter."""
    response = client.get('/api/threats?api_key=sentinel_pulse_api_key_2026')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['status'] == 'success'

def test_device_separation_mobile_redirect(client, seed_user):
    """Test that a mobile User-Agent is blocked from desktop routes and redirected to mobile dashboard."""
    # Login the user
    client.post('/auth/login', data={
        'username_or_email': 'test_analyst',
        'password': 'SecurePassword123'
    })
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) Mobile/15E148',
        'X-Enforce-Device-Mode': 'True'
    }
    
    # Try accessing desktop dashboard root
    response = client.get('/', headers=headers)
    assert response.status_code == 302
    assert '/mobile/dashboard' in response.headers['Location']

def test_device_separation_desktop_redirect(client, seed_user):
    """Test that a desktop User-Agent is blocked from mobile routes and redirected to desktop dashboard."""
    # Login the user
    client.post('/auth/login', data={
        'username_or_email': 'test_analyst',
        'password': 'SecurePassword123'
    })
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/114.0.0.0',
        'X-Enforce-Device-Mode': 'True'
    }
    
    # Try accessing mobile dashboard
    response = client.get('/mobile/dashboard', headers=headers)
    assert response.status_code == 302
    assert '/dashboard' in response.headers['Location'] or response.headers['Location'].endswith('/')
