from unittest.mock import patch, MagicMock
from app.models.threat import Threat
from app.services.virustotal import get_virustotal_api_key, lookup_ioc_on_vt, enrich_threat
from app.extensions import db

def test_get_virustotal_api_key(app):
    """Test retrieving API key from configuration."""
    with app.app_context():
        app.config['VIRUSTOTAL_API_KEY'] = 'testkey123'
        assert get_virustotal_api_key() == 'testkey123'

@patch('requests.get')
def test_lookup_ioc_on_vt_types(mock_get, app):
    """Test lookup routing and encoding for various IOC types."""
    with app.app_context():
        app.config['VIRUSTOTAL_API_KEY'] = 'dummykey'

        # Set up a successful mock response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"id": "1.1.1.1"}}
        mock_get.return_value = mock_resp

        # 1. Test IP Lookup
        res = lookup_ioc_on_vt("IP Address", "1.1.1.1")
        mock_get.assert_called_with(
            "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1",
            headers={"x-apikey": "dummykey", "accept": "application/json"},
            timeout=10
        )
        assert res == {"data": {"id": "1.1.1.1"}}

        # 2. Test Domain Lookup
        lookup_ioc_on_vt("Domain", "example.com")
        mock_get.assert_called_with(
            "https://www.virustotal.com/api/v3/domains/example.com",
            headers={"x-apikey": "dummykey", "accept": "application/json"},
            timeout=10
        )

        # 3. Test URL Lookup (URL-safe base64 unpadded)
        lookup_ioc_on_vt("URL", "http://example.com/test")
        # Base64 of 'http://example.com/test' is 'aHR0cDovL2V4YW1wbGUuY29tL3Rlc3Q=' -> 'aHR0cDovL2V4YW1wbGUuY29tL3Rlc3Q' (stripped '=')
        mock_get.assert_called_with(
            "https://www.virustotal.com/api/v3/urls/aHR0cDovL2V4YW1wbGUuY29tL3Rlc3Q",
            headers={"x-apikey": "dummykey", "accept": "application/json"},
            timeout=10
        )

        # 4. Test Hash Lookup
        lookup_ioc_on_vt("SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        mock_get.assert_called_with(
            "https://www.virustotal.com/api/v3/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            headers={"x-apikey": "dummykey", "accept": "application/json"},
            timeout=10
        )

def test_enrich_threat_no_key(app):
    """Test threat enrichment fails gracefully when API key is missing."""
    with app.app_context():
        app.config['VIRUSTOTAL_API_KEY'] = ''
        threat = Threat(
            threat_type='Malware',
            ioc_type='IP Address',
            ioc_value='8.8.8.8',
            severity='Medium',
            source='Unit Test',
            created_by=1
        )
        db.session.add(threat)
        db.session.commit()

        # Run enrichment
        enrichment = enrich_threat(threat)
        assert enrichment is not None
        assert enrichment.status == 'failed'
        assert "API Key is not configured" in enrichment.error_message

@patch('requests.get')
def test_enrich_threat_success(mock_get, app):
    """Test successful threat enrichment saving to SQLite database."""
    with app.app_context():
        app.config['VIRUSTOTAL_API_KEY'] = 'validkey'
        
        # Mock responses
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 1,
                        "harmless": 60,
                        "undetected": 2
                    },
                    "reputation": 12
                }
            }
        }
        mock_get.return_value = mock_resp

        threat = Threat(
            threat_type='Phishing',
            ioc_type='Domain',
            ioc_value='phish-example.com',
            severity='High',
            source='Unit Test',
            created_by=1
        )
        db.session.add(threat)
        db.session.commit()

        enrichment = enrich_threat(threat)
        assert enrichment is not None
        assert enrichment.status == 'success'
        assert enrichment.malicious_count == 5
        assert enrichment.suspicious_count == 1
        assert enrichment.harmless_count == 60
        assert enrichment.undetected_count == 2
        assert enrichment.reputation == 12
        assert enrichment.error_message is None

        # Verify details are accessible on Threat model relationship
        retrieved_threat = db.session.get(Threat, threat.id)
        assert retrieved_threat.vt_enrichment is not None
        assert retrieved_threat.vt_enrichment.malicious_count == 5
