import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

from app import create_app
from app.extensions import db

# Instantiate Flask application using Application Factory
app = create_app()
print("VT Config =", app.config.get("VIRUSTOTAL_API_KEY"))

print("Database URI:", app.config["SQLALCHEMY_DATABASE_URI"])

if __name__ == '__main__':
    # Determine host and port
    host = os.environ.get('FLASK_RUN_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_RUN_PORT', 5000))
    debug = app.config.get('DEBUG', True)

    print(f" * Starting Sentinel Pulse Platform in {os.environ.get('FLASK_ENV', 'development')} mode...")
    app.run(host=host, port=port, debug=debug)
