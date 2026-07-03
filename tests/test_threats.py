from datetime import datetime, timedelta
import pytest
from app.models.user import User
from app.models.threat import Threat
from app.extensions import db

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

def test_threat_creation_and_validation(client, app, seed_users):
    """Test successful threat creation and server-side validation rules."""
    # Authenticate as Analyst
    client.post('/auth/login', data={
        'username_or_email': 'analyst_op',
        'password': 'AnalystPassword123'
    })

    # 1. Successful threat creation
    response = client.post('/threats/new', data={
        'threat_type': 'Malware',
        'ioc_type': 'SHA256',
        'ioc_value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'severity': 'Critical',
        'source': 'Internal Sandbox',
        'status': 'New',
        'confidence_score': '95',
        'description': 'Zero-day payload'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Threat indicator recorded successfully." in response.data

    with app.app_context():
        threat = Threat.query.filter_by(ioc_value='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855').first()
        assert threat is not None
        assert threat.threat_type == 'Malware'
        assert threat.severity == 'Critical'
        assert threat.confidence_score == 95
        assert threat.creator.username == 'analyst_op'

    # 2. Validation: invalid confidence score
    response = client.post('/threats/new', data={
        'threat_type': 'Malware',
        'ioc_type': 'IP Address',
        'ioc_value': '1.1.1.1',
        'severity': 'Medium',
        'source': 'AlienVault',
        'status': 'New',
        'confidence_score': '150',  # Invalid
        'description': 'Test confidence score validation'
    }, follow_redirects=True)
    
    assert b"Confidence score must be an integer between 0 and 100." in response.data

    # 3. Validation: missing required fields
    response = client.post('/threats/new', data={
        'threat_type': '',  # Invalid
        'ioc_type': 'IP Address',
        'ioc_value': '',  # Invalid
        'severity': 'Medium',
        'source': 'AlienVault',
        'status': 'New',
        'confidence_score': '50',
        'description': 'Test missing fields'
    }, follow_redirects=True)
    
    assert b"Invalid threat type selected." in response.data
    assert b"IOC value is required." in response.data

def test_threat_view_and_editing(client, app, seed_users):
    """Test viewing threat dossier details and editing existing entries."""
    # Seed a threat indicator in DB
    with app.app_context():
        admin_user = db.session.get(User, seed_users['admin'])
        threat = Threat(
            threat_type='Phishing',
            ioc_type='Domain',
            ioc_value='secure-bank-login.xyz',
            severity='High',
            source='Spam Trap',
            status='New',
            confidence_score=75,
            description='Active phishing campaign targeting credentials.',
            created_by=admin_user.id
        )
        db.session.add(threat)
        db.session.commit()
        threat_id = threat.id

    # Authenticate as Analyst
    client.post('/auth/login', data={
        'username_or_email': 'analyst_op',
        'password': 'AnalystPassword123'
    })

    # 1. View Threat Dossier
    response = client.get(f'/threats/{threat_id}')
    assert response.status_code == 200
    assert b"secure-bank-login.xyz" in response.data
    assert b"Spam Trap" in response.data
    assert b"Active phishing campaign" in response.data

    # 2. Edit Threat Dossier (successful update)
    response = client.post(f'/threats/{threat_id}/edit', data={
        'threat_type': 'Phishing',
        'ioc_type': 'Domain',
        'ioc_value': 'secure-bank-login-updated.xyz',  # Modified
        'severity': 'Critical',                          # Modified
        'source': 'Spam Trap',
        'status': 'Investigating',                       # Modified
        'confidence_score': '85',                        # Modified
        'description': 'Updated description detail.'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Threat indicator updated successfully." in response.data
    assert b"secure-bank-login-updated.xyz" in response.data

    with app.app_context():
        updated_threat = db.session.get(Threat, threat_id)
        assert updated_threat.ioc_value == 'secure-bank-login-updated.xyz'
        assert updated_threat.severity == 'Critical'
        assert updated_threat.status == 'Investigating'
        assert updated_threat.confidence_score == 85

def test_threat_deletion_roles(client, app, seed_users):
    """Verify that only Admins can delete threats, while Analysts and Viewers are blocked."""
    # Seed a threat indicator in DB
    with app.app_context():
        admin_user = db.session.get(User, seed_users['admin'])
        threat = Threat(
            threat_type='Intrusion',
            ioc_type='IP Address',
            ioc_value='103.20.14.88',
            severity='Medium',
            source='Firewall Logs',
            status='New',
            confidence_score=60,
            created_by=admin_user.id
        )
        db.session.add(threat)
        db.session.commit()
        threat_id = threat.id

    # 1. Test deletion as Viewer -> Blocked
    client.post('/auth/login', data={
        'username_or_email': 'viewer_op',
        'password': 'ViewerPassword123'
    })
    response = client.post(f'/threats/{threat_id}/delete')
    assert response.status_code == 403
    client.get('/auth/logout')

    # 2. Test deletion as Analyst -> Blocked
    client.post('/auth/login', data={
        'username_or_email': 'analyst_op',
        'password': 'AnalystPassword123'
    })
    response = client.post(f'/threats/{threat_id}/delete')
    assert response.status_code == 403
    client.get('/auth/logout')

    # 3. Test deletion as Admin -> Success
    client.post('/auth/login', data={
        'username_or_email': 'admin_op',
        'password': 'AdminPassword123'
    })
    response = client.post(f'/threats/{threat_id}/delete', follow_redirects=True)
    assert response.status_code == 200
    assert b"Threat indicator deleted successfully." in response.data

    with app.app_context():
        deleted_threat = db.session.get(Threat, threat_id)
        assert deleted_threat is None

def test_search_and_filters(client, app, seed_users):
    """Test advanced query search, category filters, and date constraints."""
    with app.app_context():
        uid = seed_users['admin']
        t1 = Threat(threat_type='Malware', ioc_type='URL', ioc_value='http://badurl1.com/exe', severity='Critical', status='New', source='OSINT Feed A', created_by=uid, created_at=datetime.utcnow() - timedelta(days=5))
        t2 = Threat(threat_type='Phishing', ioc_type='Domain', ioc_value='goodurl2.com', severity='Low', status='Resolved', source='OSINT Feed B', created_by=uid, created_at=datetime.utcnow() - timedelta(days=2))
        t3 = Threat(threat_type='Ransomware', ioc_type='IP Address', ioc_value='8.8.8.8', severity='High', status='New', source='OSINT Feed A', created_by=uid, created_at=datetime.utcnow())
        db.session.add_all([t1, t2, t3])
        db.session.commit()

    # Authenticate
    client.post('/auth/login', data={
        'username_or_email': 'viewer_op',
        'password': 'ViewerPassword123'
    })

    # 1. Search by Keyword (IOC Value matches)
    response = client.get('/threats/?q=badurl1.com')
    assert b'http://badurl1.com/exe' in response.data
    assert b'goodurl2.com' not in response.data

    # 2. Filter by Severity
    response = client.get('/threats/?severity=High')
    assert b'8.8.8.8' in response.data
    assert b'http://badurl1.com/exe' not in response.data

    # 3. Filter by Status
    response = client.get('/threats/?status=Resolved')
    assert b'goodurl2.com' in response.data
    assert b'8.8.8.8' not in response.data

    # 4. Filter by Date Range (e.g. from 6 days ago to 3 days ago)
    start = (datetime.utcnow() - timedelta(days=6)).strftime('%Y-%m-%d')
    end = (datetime.utcnow() - timedelta(days=3)).strftime('%Y-%m-%d')
    response = client.get(f'/threats/?start_date={start}&end_date={end}')
    assert b'http://badurl1.com/exe' in response.data
    assert b'goodurl2.com' not in response.data
    assert b'8.8.8.8' not in response.data
