import pytest
import io
from app.models.user import User
from app.models.threat import Threat
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.report import Report
from app.extensions import db
from app.services.report import ReportService

@pytest.fixture
def seed_roles(app):
    """Seed three users with different roles (Admin, Analyst, Viewer)."""
    with app.app_context():
        admin = User(username='admin_rep', email='admin_rep@sentinelpulse.local', role='Admin')
        admin.set_password('AdminPassword123')
        
        analyst = User(username='analyst_rep', email='analyst_rep@sentinelpulse.local', role='Analyst')
        analyst.set_password('AnalystPassword123')
        
        viewer = User(username='viewer_rep', email='viewer_rep@sentinelpulse.local', role='Viewer')
        viewer.set_password('ViewerPassword123')
        
        db.session.add_all([admin, analyst, viewer])
        db.session.commit()
        
        return {
            'admin': admin.id,
            'analyst': analyst.id,
            'viewer': viewer.id
        }

def test_report_service_generation(app, seed_roles):
    """Verify that the ReportService generates all 6 report types successfully."""
    with app.app_context():
        # Seed some dummy metrics data to query
        threat = Threat(threat_type='Malware', ioc_type='MD5', ioc_value='11111111111111111111111111111111', severity='High', source='Test', created_by=seed_roles['admin'])
        db.session.add(threat)
        db.session.commit()
        
        alert = Alert(alert_number='ALT-2026-9999', threat_id=threat.id, severity='High', status='New', message="Test Alert")
        db.session.add(alert)
        db.session.commit()

        report_types = [
            'Executive Security Report',
            'Threat Intelligence Report',
            'Incident Summary Report',
            'Alert Summary Report',
            'IOC Report',
            'Analyst Activity Report'
        ]

        for r_type in report_types:
            report = ReportService.generate_report(r_type, seed_roles['admin'])
            assert report is not None
            assert report.report_number.startswith("RPT-2026-")
            assert report.title != ""
            assert report.report_type == r_type
            assert report.payload['stats']['threats']['total'] == 1
            assert report.payload['stats']['alerts']['total'] == 1

def test_report_exports(app, seed_roles):
    """Verify PDF, Excel, and CSV binary and text exports."""
    with app.app_context():
        report = ReportService.generate_report('Executive Security Report', seed_roles['admin'])
        
        # 1. PDF
        pdf_bytes = ReportService.generate_pdf(report)
        assert len(pdf_bytes) > 0
        assert pdf_bytes.startswith(b'%PDF')  # PDF signature
        
        # 2. Excel
        excel_bytes = ReportService.generate_excel(report)
        assert len(excel_bytes) > 0
        assert excel_bytes.startswith(b'PK\x03\x04')  # Zip signature for OpenXML XLSX
        
        # 3. CSV
        csv_str = ReportService.generate_csv(report)
        assert len(csv_str) > 0
        assert "Sentinel Pulse Security Report" in csv_str
        assert report.report_number in csv_str

def test_reports_routing_rbac(client, app, seed_roles):
    """Verify Role-Based Access Control restrictions for all endpoints."""
    # 1. ADMIN USER -> FULL ACCESS
    # Login as Admin
    client.post('/auth/login', data={'username_or_email': 'admin_rep', 'password': 'AdminPassword123'})
    
    # View Reports Page
    response = client.get('/reports/')
    assert response.status_code == 200
    assert b'SOC Reports' in response.data
    assert b'Generate Report' in response.data  # Button is visible
    
    # Generate Report via POST
    response = client.post('/reports/generate', data={'report_type': 'Executive Security Report'}, follow_redirects=True)
    assert response.status_code == 200
    assert b'Report' in response.data
    assert b'successfully generated' in response.data
    
    with app.app_context():
        report = Report.query.filter_by(report_type='Executive Security Report').first()
        assert report is not None
        report_id = report.id
        
    # Preview Report
    response = client.get(f'/reports/preview/{report_id}')
    assert response.status_code == 200
    assert b'Report Details' in response.data
    
    # Download PDF
    response = client.get(f'/reports/download/{report_id}/pdf')
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/pdf'
    
    # Download XLSX
    response = client.get(f'/reports/download/{report_id}/xlsx')
    assert response.status_code == 200
    assert 'spreadsheet' in response.headers['Content-Type']
    
    # Download CSV
    response = client.get(f'/reports/download/{report_id}/csv')
    assert response.status_code == 200
    assert 'text/csv' in response.headers['Content-Type']
    
    client.get('/auth/logout')

    # 2. ANALYST USER -> READ ONLY OPERATIONS
    # Login as Analyst
    client.post('/auth/login', data={'username_or_email': 'analyst_rep', 'password': 'AnalystPassword123'})
    
    # View Reports Page
    response = client.get('/reports/')
    assert response.status_code == 200
    assert b'SOC Reports' in response.data
    assert b'Generate Report' not in response.data  # Button is hidden
    
    # Attempt to Generate -> Access Denied / 403 Forbidden
    response = client.post('/reports/generate', data={'report_type': 'Executive Security Report'})
    assert response.status_code == 403
    
    # Can preview existing report
    response = client.get(f'/reports/preview/{report_id}')
    assert response.status_code == 200
    
    # Can download existing report
    response = client.get(f'/reports/download/{report_id}/pdf')
    assert response.status_code == 200
    
    client.get('/auth/logout')

    # 3. VIEWER USER -> NO ACCESS AT ALL
    # Login as Viewer
    client.post('/auth/login', data={'username_or_email': 'viewer_rep', 'password': 'ViewerPassword123'})
    
    # View reports list -> 403 Forbidden
    response = client.get('/reports/')
    assert response.status_code == 403
    
    # Attempt to preview -> 403 Forbidden
    response = client.get(f'/reports/preview/{report_id}')
    assert response.status_code == 403
    
    client.get('/auth/logout')
