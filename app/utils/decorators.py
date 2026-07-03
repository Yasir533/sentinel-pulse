from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):

            print("=" * 60)
            print("Authenticated :", current_user.is_authenticated)
            print("Username      :", current_user.username)
            print("Role          :", repr(current_user.role))
            print("Allowed Roles :", roles)
            print("Comparison    :", current_user.role in roles)
            print("=" * 60)

            if not current_user.is_authenticated:
                flash("Authentication required.", "warning")
                return redirect(url_for("auth.login"))

            # Normalize roles list and check if current_user.role (stripped and capitalized) is in it
            clean_roles = [r.strip().capitalize() for r in roles]
            user_role = current_user.role.strip().capitalize() if current_user.role else ""
            if user_role not in clean_roles:
                flash("Access denied. You do not have the required role.", "danger")
                abort(403)

            return f(*args, **kwargs)

        return decorated_function
    return decorator