import pytest
from app.models.user import User
from app.models.threat import Threat
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.audit_log import AuditLog
from app.models.report_schedule import ReportSchedule
from app.extensions import db
from app.services.scorecard import ScorecardService
from app.services.audit import AuditService
from app.services.export import ExportService
from app.services.report import ReportService

@pytest.fixture
def seed_data(app):
    """Seed base roles and threat elements for testing."""
    with app.app_context():
        admin = User(username='admin_ent', email='admin_ent@sentinelpulse.local', role='Admin')
        admin.set_password('AdminPassword123')
        
        analyst = User(username='analyst_ent', email='analyst_ent@sentinelpulse.local', role='Analyst')
        analyst.set_password('AnalystPassword123')
        
        db.session.add_all([admin, analyst])
        db.session.commit()
        
        threat = Threat(
            threat_type='Malware', 
            ioc_type='IP Address', 
            ioc_value='192.168.10.25', 
            severity='High', 
            source='Test Feed', 
            created_by=admin.id
        )
        db.session.add(threat)
        db.session.commit()
        
        alert = Alert(
            alert_number='ALT-2026-0001', 
            threat_id=threat.id, 
            severity='High', 
            status='New', 
            message="Test High Risk Alert"
        )
        db.session.add(alert)
        db.session.commit()
        
        return {
            'admin_id': admin.id,
            'analyst_id': analyst.id,
            'threat_id': threat.id,
            'alert_id': alert.id
        }

def test_scorecard_service(app, seed_data):
    """Verify security health scorecard computations."""
    with app.app_context():
        # Score calculation with 1 high alert (10 deduction points)
        scorecard = ScorecardService.get_security_score()
        assert scorecard['score'] < 100
        assert scorecard['rating'] in ['Excellent', 'Good', 'Fair', 'Critical']

def test_audit_service_logging(app, seed_data):
    """Verify audit trails logging functionality."""
    with app.app_context():
        # Log a generic compliance event
        AuditService.log(
            action='Settings Changes',
            entity='System Config',
            before='exposure_threshold=90',
            after='exposure_threshold=80',
            status='Success',
            username='admin_ent',
            role='Admin',
            ip_address='127.0.0.1'
        )
        
        log = AuditLog.query.filter_by(action='Settings Changes').first()
        assert log is not None
        assert log.username == 'admin_ent'
        assert log.before_state == 'exposure_threshold=90'
        assert log.after_state == 'exposure_threshold=80'

def test_export_service(app, seed_data):
    """Verify ExportService compiles tabular data to PDF, Excel, and CSV bytes."""
    with app.app_context():
        # 1. Export CSV
        csv_data = ExportService.export_to_csv('threats', {})
        assert csv_data is not None
        assert b"192.168.10.25" in csv_data

        # 2. Export Excel
        xlsx_data = ExportService.export_to_xlsx('alerts', {})
        assert xlsx_data is not None
        assert len(xlsx_data) > 0

        # 3. Export PDF
        pdf_data = ExportService.export_to_pdf('incidents', {})
        assert pdf_data is not None
        assert len(pdf_data) > 0

def test_all_12_report_types(app, seed_data):
    """Verify ReportService successfully generates all 12 operational security report types."""
    with app.app_context():
        report_types = [
            'Executive Security Report',
            'Threat Intelligence Report',
            'Incident Summary Report',
            'Alert Summary Report',
            'Notification Report',
            'Analyst Activity Report',
            'User Activity Report',
            'Audit Report',
            'IOC Report',
            'Monthly SOC Report',
            'Weekly SOC Report',
            'Daily SOC Report'
        ]
        
        for r_type in report_types:
            report = ReportService.generate_report(r_type, seed_data['admin_id'])
            assert report is not None
            assert report.report_type == r_type
            assert report.report_number.startswith("RPT-")

def test_report_schedules_endpoints(client, app, seed_data):
    """Verify ReportSchedule model registration and scheduling endpoints flow."""
    # Authenticate as Admin
    with client.session_transaction() as sess:
        sess['_user_id'] = str(seed_data['admin_id'])
        sess['_fresh'] = True

    # 1. Create a schedule
    response = client.post('/reports/schedules/new', data={
        'report_type': 'Weekly SOC Report',
        'frequency': 'Weekly',
        'email_recipient': 'security-team@sentinelpulse.local'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    with app.app_context():
        sched = ReportSchedule.query.filter_by(report_type='Weekly SOC Report').first()
        assert sched is not None
        assert sched.frequency == 'Weekly'
        assert sched.email_recipient == 'security-team@sentinelpulse.local'
        sched_id = sched.id

    # 2. Delete schedule
    response_del = client.post(f'/reports/schedules/{sched_id}/delete', follow_redirects=True)
    assert response_del.status_code == 200
    with app.app_context():
        sched_del = db.session.get(ReportSchedule, sched_id)
        assert sched_del is None

def test_settings_save_endpoint(client, app, seed_data):
    """Verify Settings update route records changes and triggers audit log creation."""
    # Authenticate as Admin
    with client.session_transaction() as sess:
        sess['_user_id'] = str(seed_data['admin_id'])
        sess['_fresh'] = True

    # Post settings configuration adjustments
    response = client.post('/admin/settings/save', data={
        'confidence_threshold': '70',
        'retention_days': '45',
        'email_notifications': 'true'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    # Assert audit log is recorded
    with app.app_context():
        log = AuditLog.query.filter_by(action='Settings Changes').first()
        assert log is not None
        assert 'confidence_threshold' in log.after_state

def test_global_search_endpoint(client, app, seed_data):
    """Verify Global search engine queries all matching items correctly."""
    # Authenticate as Admin
    with client.session_transaction() as sess:
        sess['_user_id'] = str(seed_data['admin_id'])
        sess['_fresh'] = True

    # Search query matching "192.168.10.25"
    response = client.get('/search?q=192.168.10.25')
    assert response.status_code == 200
    assert b"192.168.10.25" in response.data
