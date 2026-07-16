import io
from flask import render_template, request, redirect, url_for, flash, send_file, Response, current_app
from flask_login import login_required, current_user
from app.extensions import db
from app.models.report import Report
from app.blueprints.reports import reports_bp
from app.services.report import ReportService
from app.utils import role_required

@reports_bp.route('/')
@login_required
@role_required('Admin', 'Analyst')
def list_reports() -> str:
    """Renders active system reports with pagination."""
    page = request.args.get('page', 1, type=int)
    
    # Enforce standard pagination matching Phase 6.4 stabilization
    pagination = Report.query.order_by(Report.created_at.desc()).paginate(page=page, per_page=10, error_out=False)
    reports = pagination.items
    
    from app.models.report_schedule import ReportSchedule
    schedules = ReportSchedule.query.order_by(ReportSchedule.created_at.desc()).all()
    
    return render_template(
        'reports/list.html',
        reports=reports,
        pagination=pagination,
        schedules=schedules
    )

@reports_bp.route('/generate', methods=['POST'])
@login_required
@role_required('Admin') # Only administrators can generate new reports
def generate_report() -> Response:
    """Generates a new security report dynamically."""
    report_type = request.form.get('report_type', '').strip()
    
    valid_types = [
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
        'Daily SOC Report',
        'Threat Report',
        'Incident Report',
        'Mobile Security Report',
        'AI Analysis Report',
        'Executive Summary'
    ]
    
    if not report_type or report_type not in valid_types:
        flash("Invalid report type selected.", "danger")
        return redirect(url_for('reports.list_reports'))
        
    try:
        report = ReportService.generate_report(report_type, current_user.id)
        
        from app.services.audit import AuditService
        AuditService.log('Report Generation', f"Report {report.report_number}", after=report.title, status='Success')
        
        flash(f"Report '{report.title}' successfully generated (ID: {report.report_number}).", "success")
    except Exception as e:
        current_app.logger.exception("Failed to generate report")
        flash(f"Failed to generate report: {str(e)}", "danger")
        
    return redirect(url_for('reports.list_reports'))

@reports_bp.route('/preview/<int:report_id>')
@login_required
@role_required('Admin', 'Analyst')
def preview_report(report_id: int) -> str | Response:
    """Renders an HTML preview of the report payload."""
    report = db.session.get(Report, report_id)
    if not report:
        flash("Report not found.", "warning")
        return redirect(url_for('reports.list_reports'))
        
    return render_template('reports/preview.html', report=report)

@reports_bp.route('/download/<int:report_id>/pdf')
@login_required
@role_required('Admin', 'Analyst')
def download_pdf(report_id: int) -> Response:
    """Exports and downloads the report in PDF format."""
    report = db.session.get(Report, report_id)
    if not report:
        flash("Report not found.", "warning")
        return redirect(url_for('reports.list_reports'))
        
    try:
        pdf_bytes = ReportService.generate_pdf(report)
        from app.services.audit import AuditService
        AuditService.log('Report Download', f"Report {report.report_number}", after="Format=PDF", status='Success')
        return send_file(
            send_file_io_bytes(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"{report.report_number}.pdf"
        )
    except Exception as e:
        current_app.logger.exception("Failed to export PDF")
        flash(f"Failed to export PDF: {str(e)}", "danger")
        return redirect(url_for('reports.list_reports'))

@reports_bp.route('/download/<int:report_id>/xlsx')
@login_required
@role_required('Admin', 'Analyst')
def download_excel(report_id: int) -> Response:
    """Exports and downloads the report in Excel format."""
    report = db.session.get(Report, report_id)
    if not report:
        flash("Report not found.", "warning")
        return redirect(url_for('reports.list_reports'))
        
    try:
        xlsx_bytes = ReportService.generate_excel(report)
        from app.services.audit import AuditService
        AuditService.log('Report Download', f"Report {report.report_number}", after="Format=Excel", status='Success')
        return send_file(
            send_file_io_bytes(xlsx_bytes),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f"{report.report_number}.xlsx"
        )
    except Exception as e:
        current_app.logger.exception("Failed to export Excel")
        flash(f"Failed to export Excel: {str(e)}", "danger")
        return redirect(url_for('reports.list_reports'))

@reports_bp.route('/download/<int:report_id>/csv')
@login_required
@role_required('Admin', 'Analyst')
def download_csv(report_id: int) -> Response:
    """Exports and downloads the report in CSV format."""
    report = db.session.get(Report, report_id)
    if not report:
        flash("Report not found.", "warning")
        return redirect(url_for('reports.list_reports'))
        
    try:
        csv_str = ReportService.generate_csv(report)
        from app.services.audit import AuditService
        AuditService.log('Report Download', f"Report {report.report_number}", after="Format=CSV", status='Success')
        # Return standard response
        return Response(
            csv_str,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment;filename={report.report_number}.csv'}
        )
    except Exception as e:
        current_app.logger.exception("Failed to export CSV")
        flash(f"Failed to export CSV: {str(e)}", "danger")
        return redirect(url_for('reports.list_reports'))

@reports_bp.route('/schedules/new', methods=['POST'])
@login_required
@role_required('Admin')
def new_schedule() -> Response:
    """Creates a new automated report schedule."""
    report_type = request.form.get('report_type', '').strip()
    frequency = request.form.get('frequency', '').strip()
    email_recipient = request.form.get('email_recipient', '').strip()

    if not report_type or not frequency or not email_recipient:
        flash("All fields are required to create a schedule.", "danger")
        return redirect(url_for('reports.list_reports'))

    from app.models.report_schedule import ReportSchedule
    schedule = ReportSchedule(
        report_type=report_type,
        frequency=frequency,
        email_recipient=email_recipient,
        created_by_id=current_user.id
    )
    
    try:
        db.session.add(schedule)
        db.session.commit()
        from app.services.audit import AuditService
        AuditService.log('Report Schedule Created', f"Schedule {report_type} ({frequency})", after=f"Recipient={email_recipient}", status='Success')
        flash(f"Successfully scheduled {report_type} ({frequency}) for {email_recipient}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to create schedule: {str(e)}", "danger")

    return redirect(url_for('reports.list_reports'))

@reports_bp.route('/schedules/<int:schedule_id>/delete', methods=['POST'])
@login_required
@role_required('Admin')
def delete_schedule(schedule_id: int) -> Response:
    """Removes a report schedule."""
    from app.models.report_schedule import ReportSchedule
    schedule = db.session.get(ReportSchedule, schedule_id)
    if not schedule:
        flash("Schedule not found.", "warning")
        return redirect(url_for('reports.list_reports'))

    try:
        db.session.delete(schedule)
        db.session.commit()
        from app.services.audit import AuditService
        AuditService.log('Report Schedule Deleted', f"Schedule {schedule.report_type} ({schedule.frequency})", status='Success')
        flash("Report schedule removed successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to delete schedule: {str(e)}", "danger")

    return redirect(url_for('reports.list_reports'))

def send_file_io_bytes(data_bytes: bytes) -> io.BytesIO:
    return io.BytesIO(data_bytes)

@reports_bp.route('/<int:report_id>/delete', methods=['POST'])
@login_required
@role_required('Admin')
def delete_report(report_id: int) -> Response:
    """Admin-only endpoint to delete a generated report."""
    report = db.session.get(Report, report_id)
    if not report:
        flash("Report not found.", "warning")
        return redirect(url_for('reports.list_reports'))
        
    try:
        db.session.delete(report)
        db.session.commit()
        
        from app.services.audit import AuditService
        AuditService.log('Report Deletion', f"Report {report.report_number}", status='Success')
        
        flash("Report deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to delete report: {str(e)}", "danger")
        
    return redirect(url_for('reports.list_reports'))
