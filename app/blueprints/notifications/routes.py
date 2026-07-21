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
    
    latest_notif = None
    if recent_notifications:
        latest = recent_notifications[0]
        if latest.status == 'Unread':
            latest_notif = {
                'id': latest.id,
                'title': latest.title,
                'message': latest.message,
                'priority': latest.priority
            }

    return jsonify({
        'unread_count': unread_count,
        'dropdown_html': dropdown_html,
        'widget_html': widget_html,
        'latest_notification': latest_notif
    })

@notifications_bp.route('/new', methods=['GET', 'POST'])
@login_required
def create_notification() -> str | Response:
    """Trigger/dispatch a new notification manually (restricted to Admin/Analyst)."""
    # Enforce role restriction
    if current_user.role not in ['Admin', 'Analyst']:
        abort(403)
        
    if request.method == 'POST':
        user_id_val = request.form.get('user_id')
        title = request.form.get('title', '').strip()
        message = request.form.get('message', '').strip()
        priority = request.form.get('priority', 'Medium').strip()
        category = request.form.get('category', 'System Announcement').strip()
        
        if not user_id_val or not title or not message:
            flash("User, title and message are required.", "danger")
            return redirect(url_for('notifications.list_notifications'))
            
        try:
            user_id = int(user_id_val)
            notif = NotificationService.create_notification(
                user_id=user_id,
                title=title,
                message=message,
                priority=priority,
                category=category
            )
            
            from app.services.audit import AuditService
            AuditService.log('Notification Dispatch', f"Notification {notif.id}", after=f"Recipient User={user_id}, Title={title}", status='Success')
            
            flash("Notification dispatched successfully.", "success")
            return redirect(url_for('notifications.list_notifications'))
        except Exception as e:
            flash(f"Failed to dispatch notification: {str(e)}", "danger")
            
    # For GET, fetch users to target
    from app.models.user import User
    users = User.query.order_by(User.username.asc()).all()
    return render_template('notifications/new.html', users=users)
