import pytest
from unittest.mock import patch, MagicMock
from app.models.user import User
from app.models.threat import Threat, AbuseIPDBEnrichment
from app.services.abuseipdb import get_abuseipdb_api_key, lookup_ip, enrich_ip
from app.extensions import db

@pytest.fixture
def seed_user(app):
    """Seed a test user with Analyst role for authentication."""
    with app.app_context():
        user = User(username='test_analyst', email='analyst@sentinelpulse.local', role='Analyst')
        user.set_password('AnalystPassword123')
        db.session.add(user)
        db.session.commit()
        return user.id

def test_get_abuseipdb_api_key(app):
    """Test retrieving API key from configuration."""
    with app.app_context():
        app.config['ABUSEIPDB_API_KEY'] = 'testkey_abuseipdb'
        assert get_abuseipdb_api_key() == 'testkey_abuseipdb'

@patch('requests.get')
def test_lookup_ip_valid(mock_get, app):
    """Test lookup routing and parameters for a valid public IP."""
    with app.app_context():
        app.config['ABUSEIPDB_API_KEY'] = 'dummykey'

        # Set up a successful mock response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "8.8.8.8",
                "isPublic": True,
                "abuseConfidenceScore": 5,
                "countryCode": "US",
                "countryName": "United States",
                "isp": "Google LLC",
                "domain": "google.com",
                "usageType": "Data Center",
                "totalReports": 12,
                "lastReportedAt": "2026-06-30T10:00:00+00:00"
            }
        }
        mock_get.return_value = mock_resp

        res = lookup_ip("8.8.8.8")
        mock_get.assert_called_with(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": "dummykey", "Accept": "application/json"},
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90},
            timeout=10
        )
        assert res["data"]["ipAddress"] == "8.8.8.8"
        assert res["data"]["abuseConfidenceScore"] == 5

def test_lookup_ip_invalid(app):
    """Test lookup raises ValueError for invalid IP address format."""
    with app.app_context():
        app.config['ABUSEIPDB_API_KEY'] = 'dummykey'
        with pytest.raises(ValueError) as excinfo:
            lookup_ip("not-a-valid-ip")
        assert "Invalid IP address format." in str(excinfo.value)

def test_lookup_ip_private(app):
    """Test lookup raises ValueError for private IP addresses to protect API quota."""
    with app.app_context():
        app.config['ABUSEIPDB_API_KEY'] = 'dummykey'
        with pytest.raises(ValueError) as excinfo:
            lookup_ip("192.168.1.1")
        assert "Private IP addresses cannot be checked." in str(excinfo.value)

@patch('requests.get')
def test_lookup_ip_rate_limit(mock_get, app):
    """Test rate limiting error mapping (HTTP 429)."""
    with app.app_context():
        app.config['ABUSEIPDB_API_KEY'] = 'dummykey'
        
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        with pytest.raises(ConnectionRefusedError) as excinfo:
            lookup_ip("8.8.8.8")
        assert "rate limit exceeded" in str(excinfo.value).lower()

def test_lookup_ip_missing_key(app):
    """Test that lookup raises error if API key is not configured."""
    with app.app_context():
        app.config['ABUSEIPDB_API_KEY'] = ''
        with pytest.raises(ValueError) as excinfo:
            lookup_ip("8.8.8.8")
        assert "API Key is not configured." in str(excinfo.value)

@patch('requests.get')
def test_enrich_ip_persistence(mock_get, app, seed_user):
    """Test successful IP enrichment saving to SQLite database."""
    with app.app_context():
        app.config['ABUSEIPDB_API_KEY'] = 'validkey'
        
        # Mock successful API response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "8.8.8.8",
                "isPublic": True,
                "abuseConfidenceScore": 15,
                "countryCode": "US",
                "countryName": "United States",
                "isp": "Google LLC",
                "domain": "google.com",
                "usageType": "Data Center",
                "totalReports": 3,
                "lastReportedAt": "2026-06-30T12:00:00Z"
            }
        }
        mock_get.return_value = mock_resp

        threat = Threat(
            threat_type='Malicious IP',
            ioc_type='IP Address',
            ioc_value='8.8.8.8',
            severity='High',
            source='Unit Test',
            created_by=seed_user
        )
        db.session.add(threat)
        db.session.commit()

        enrichment = enrich_ip(threat)
        assert enrichment is not None
        assert enrichment.status == 'success'
        assert enrichment.abuse_confidence_score == 15
        assert enrichment.country_code == 'US'
        assert enrichment.country_name == 'United States'
        assert enrichment.isp == 'Google LLC'
        assert enrichment.domain == 'google.com'
        assert enrichment.usage_type == 'Data Center'
        assert enrichment.total_reports == 3
        assert enrichment.error_message is None

        # Verify relation
        retrieved_threat = db.session.get(Threat, threat.id)
        assert retrieved_threat.abuseipdb_enrichment is not None
        assert retrieved_threat.abuseipdb_enrichment.abuse_confidence_score == 15

def test_details_rendering_success(client, app, seed_user):
    """Test threat details page renders AbuseIPDB card with success status."""
    # Authenticate user
    client.post('/auth/login', data={
        'username_or_email': 'test_analyst',
        'password': 'AnalystPassword123'
    })

    with app.app_context():
        threat = Threat(
            threat_type='Malicious IP',
            ioc_type='IP Address',
            ioc_value='8.8.8.8',
            severity='High',
            source='Unit Test Web',
            created_by=seed_user
        )
        db.session.add(threat)
        db.session.commit()

        enrichment = AbuseIPDBEnrichment(
            threat_id=threat.id,
            status='success',
            abuse_confidence_score=45,
            country_code='US',
            country_name='United States',
            isp='Google LLC',
            domain='google.com',
            usage_type='Data Center',
            total_reports=8,
            error_message=None
        )
        db.session.add(enrichment)
        db.session.commit()
        threat_id = threat.id

    response = client.get(f'/threats/{threat_id}')
    assert response.status_code == 200
    assert b"AbuseIPDB Intelligence" in response.data
    assert b"45%" in response.data
    assert b"United States" in response.data
    assert b"Google LLC" in response.data
    assert b"8 reports" in response.data
    assert b"Medium Risk" in response.data
    assert b"Further investigation recommended" in response.data

def test_details_rendering_failed(client, app, seed_user):
    """Test threat details page renders AbuseIPDB card with failed status."""
    # Authenticate user
    client.post('/auth/login', data={
        'username_or_email': 'test_analyst',
        'password': 'AnalystPassword123'
    })

    with app.app_context():
        threat = Threat(
            threat_type='Malicious IP',
            ioc_type='IP Address',
            ioc_value='127.0.0.1',
            severity='Medium',
            source='Unit Test Web Error',
            created_by=seed_user
        )
        db.session.add(threat)
        db.session.commit()

        enrichment = AbuseIPDBEnrichment(
            threat_id=threat.id,
            status='failed',
            error_message='Private IP addresses cannot be checked.'
        )
        db.session.add(enrichment)
        db.session.commit()
        threat_id = threat.id

    response = client.get(f'/threats/{threat_id}')
    assert response.status_code == 200
    assert b"AbuseIPDB Intelligence" in response.data
    assert b"Analysis Enrichment Failed" in response.data
    assert b"Private IP addresses cannot be checked." in response.data

def test_calculate_abuse_risk():
    """Test calculate_abuse_risk returns correct mappings for all score tiers."""
    from app.services.abuseipdb import calculate_abuse_risk
    
    # 1. Low Risk (0-20)
    low_res = calculate_abuse_risk(15)
    assert low_res["label"] == "Low Risk"
    assert low_res["badge"] == "success"
    assert "monitoring" in low_res["recommendation"]
    
    # 2. Medium Risk (21-60)
    med_res = calculate_abuse_risk(45)
    assert med_res["label"] == "Medium Risk"
    assert med_res["badge"] == "warning"
    assert "Further investigation" in med_res["recommendation"]
    
    # 3. High Risk (61-100)
    high_res = calculate_abuse_risk(85)
    assert high_res["label"] == "High Risk"
    assert high_res["badge"] == "danger"
    assert "blocking this IP" in high_res["recommendation"]
