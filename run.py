import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Auto-re-execute in virtual environment if running with system python
if sys.prefix == sys.base_prefix:
    venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'venv', 'Scripts', 'python.exe')
    if os.path.exists(venv_python):
        os.execv(venv_python, [venv_python] + sys.argv)

from app import create_app
from app.extensions import db

# Instantiate Flask application using Application Factory
app = create_app()
print("VT Config =", app.config.get("VIRUSTOTAL_API_KEY"))

print("Database URI:", app.config["SQLALCHEMY_DATABASE_URI"])

if __name__ == '__main__':
    import socket

    def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
        finally:
            s.close()

    # Determine host and port
    host = os.environ.get('FLASK_RUN_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_RUN_PORT', 5000))
    debug = app.config.get('DEBUG', True)
    lan_ip = get_local_ip()

    print("=" * 55)
    print("  Sentinel Pulse Platform")
    print("=" * 55)
    print(f"  Laptop : http://127.0.0.1:{port}")
    print(f"  Phone  : http://{lan_ip}:{port}  (same Wi-Fi)")
    print("=" * 55)
    print(f"  Mode   : {os.environ.get('FLASK_ENV', 'development')}")
    print("=" * 55)

    app.run(host=host, port=port, debug=debug)

