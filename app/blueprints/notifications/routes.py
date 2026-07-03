from datetime import datetime
from flask import render_template, request, redirect, url_for, flash, jsonify, Response
from flask_login import login_required, current_user
from app.extensions import db
from app.models.notification import Notification
from app.services.notification import NotificationService
from app.blueprints.notifications import notifications_bp

@notifications_bp.route('/')
@login_required
def list_notifications() -> str:
    """List notifications with advanced search and filters."""
    q = request.args.get('q', '').strip()
    priority = request.args.get('priority', '').strip()
    status = request.args.get('status', '').strip()
    type_filter = request.args.get('type', '').strip()
    date_filter = request.args.get('date', '').strip()
    page = request.args.get('page', 1, type=int)

    query = Notification.query.filter_by(user_id=current_user.id)

    # Search keyword
    if q:
        query = query.filter(
            (Notification.title.like(f"%{q}%")) |
            (Notification.message.like(f"%{q}%")) |
            (Notification.notification_number.like(f"%{q}%"))
        )

    # Filter priority
    if priority:
        query = query.filter_by(priority=priority)

    # Filter status
    if status:
        query = query.filter_by(status=status)

    # Filter type
    if type_filter:
        query = query.filter_by(type=type_filter)

    # Filter date (YYYY-MM-DD)
    if date_filter:
        try:
            dt_start = datetime.strptime(date_filter, '%Y-%m-%d')
            dt_end = datetime.strptime(f"{date_filter} 23:59:59", '%Y-%m-%d %H:%M:%S')
            query = query.filter(Notification.created_at >= dt_start, Notification.created_at <= dt_end)
        except ValueError:
            flash("Invalid date format.", "warning")

    pagination = query.order_by(Notification.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
    notifications = pagination.items
    unread_count = NotificationService.get_unread_count(current_user.id)

    return render_template(
        'notifications/list.html',
        notifications=notifications,
        pagination=pagination,
        unread_count=unread_count,
        search_query=q,
        selected_priority=priority,
        selected_status=status,
        selected_type=type_filter,
        selected_date=date_filter
    )

@notifications_bp.route('/mark-read/<int:notification_id>', methods=['POST'])
@login_required
def mark_read(notification_id: int) -> Response:
    """Mark a specific notification as read."""
    NotificationService.mark_as_read(notification_id, current_user.id)
    from app.services.audit import AuditService
    AuditService.log('Notification Read', f"Notification {notification_id}", status='Success')
    return redirect(request.referrer or url_for('notifications.list_notifications'))

@notifications_bp.route('/mark-all-read', methods=['POST'])
@login_required
def mark_all_read() -> Response:
    """Mark all unread notifications as read."""
    count = NotificationService.mark_all_as_read(current_user.id)
    from app.services.audit import AuditService
    AuditService.log('Notification Read', "All notifications", after=f"Count={count}", status='Success')
    flash(f"Marked {count} notifications as read.", "success")
    return redirect(request.referrer or url_for('notifications.list_notifications'))

@notifications_bp.route('/delete/<int:notification_id>', methods=['POST'])
@login_required
def delete_notification(notification_id: int) -> Response:
    """Delete a notification."""
    notif = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first_or_404()
    db.session.delete(notif)
    db.session.commit()
    flash("Notification deleted successfully.", "success")
    return redirect(request.referrer or url_for('notifications.list_notifications'))

@notifications_bp.route('/api/poll')
@login_required
def poll_notifications():
    """Lightweight AJAX polling endpoint returning JSON metadata and pre-rendered templates."""
    unread_count = NotificationService.get_unread_count(current_user.id)
    recent_notifications = NotificationService.get_recent_notifications(current_user.id, limit=5)
    
    dropdown_html = render_template('notifications/dropdown_items.html', notifications=recent_notifications)
    widget_html = render_template('notifications/widget_items.html', recent_notifications=recent_notifications)
    
    return jsonify({
        'unread_count': unread_count,
        'dropdown_html': dropdown_html,
        'widget_html': widget_html
    })
