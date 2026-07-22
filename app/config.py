import os
import secrets
from datetime import timedelta

# Resolve base directory of the application
BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

class BaseConfig:
    """Base Configuration holding settings common to all environments."""
    # Security Keys
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or secrets.token_hex(32)
    
    # Session / Token Expirations
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # SQLAlchemy
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Database default (SQLite in instance folder)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'sentinel_pulse.db')}"
    # Ensure relative SQLite URIs resolve to absolute path within instance folder
    db_url = os.environ.get('DATABASE_URL')
    if db_url and db_url.startswith('sqlite:///'):
        path_part = db_url.replace('sqlite:///', '')
        if not os.path.isabs(path_part):
            SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.abspath(os.path.join(BASE_DIR, path_part))}"

    # VirusTotal Integration Configuration
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

    # AbuseIPDB Integration Configuration
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')


    # Mail Server Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'sentinel-pulse@yourdomain.com')

    # Celery Configuration
    CELERY_BROKER_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # CORS Configuration
    CORS_RESOURCES = {r"/api/*": {"origins": "*"}}

    # Sentinel API Key for Public Endpoint Protection
    SENTINEL_API_KEY = os.environ.get('SENTINEL_API_KEY', 'sentinel_pulse_api_key_2026')


class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    DEBUG = True
    ENV = 'development'


class TestingConfig(BaseConfig):
    """Testing configuration."""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    JWT_COOKIE_CSRF_PROTECT = False


class ProductionConfig(BaseConfig):
    """Production configuration."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    
    # Restrict CORS origins in production
    CORS_RESOURCES = {
        r"/api/*": {
            "origins": [
                o.strip() for o in os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',') if o.strip()
            ]
        }
    }
    
    # Ensure production environment has actual environment variables set
    @classmethod
    def init_app(cls, app):
        if not os.environ.get('SECRET_KEY'):
            raise RuntimeError("CRITICAL CONFIGURATION ERROR: SECRET_KEY environment variable is not set for Production.")
        if not os.environ.get('JWT_SECRET_KEY'):
            raise RuntimeError("CRITICAL CONFIGURATION ERROR: JWT_SECRET_KEY environment variable is not set for Production.")
            
        # Ensure database is PostgreSQL in production
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if not db_uri or not db_uri.startswith(('postgresql://', 'postgresql+psycopg2://')):
            raise RuntimeError(
                "CRITICAL CONFIGURATION ERROR: PostgreSQL database is required in Production. "
                "The DATABASE_URL environment variable must be set to a valid PostgreSQL URI starting with "
                "'postgresql://' or 'postgresql+psycopg2://'."
            )



# Map configurations by environment string
config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
