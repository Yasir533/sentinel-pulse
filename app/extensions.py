from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_mail import Mail
from celery import Celery

# Database extension
db = SQLAlchemy()

# Migration extension
migrate = Migrate()

# Authentication & Session management extensions
login_manager = LoginManager()
jwt = JWTManager()

# Cross-Origin Resource Sharing extension
cors = CORS()

# Mail dispatcher extension
mail = Mail()

# Celery placeholder initialization
# To complete initialization in application factory, call make_celery(app)
celery = Celery()

def make_celery(app):
    """
    Integrate Celery with the Flask Application context.
    Configures Celery broker and backend from Flask configuration.
    """
    celery.conf.update(
        broker_url=app.config['CELERY_BROKER_URL'],
        result_backend=app.config['CELERY_RESULT_BACKEND'],
        timezone='UTC'
    )
    
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
                
    celery.Task = ContextTask
    return celery
