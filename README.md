# SENTINEL PULSE
### Unified AI Threat Intelligence and Incident Observability Platform (Phase 1 Foundation)

Sentinel Pulse is a modern, modular, production-grade cybersecurity application platform designed to consolidate telemetry analysis, AI-driven threat predictive models, and security incident response tracking.

This repository contains the **Phase 1 Foundation** layout built on Clean Architecture and the Flask Application Factory Pattern.

---

## Technology Stack

- **Backend core**: Python 3.12+, Flask 3.0
- **Database Layer**: SQLAlchemy, Flask-Migrate (Alembic support)
- **Security & Auth**: Flask-Login, Flask-JWT-Extended, Flask-CORS
- **Asynchronous Processing**: Celery (Redis integration skeleton)
- **Frontend Assets**: HTML5, CSS3, JS, Bootstrap 5 (Stylized Cyber Theme), Bootstrap Icons
- **Testing**: Pytest

---

## Directory Structure & Architecture

```text
sentinel-pulse/
├── app/                      # Main application codebase
│   ├── __init__.py           # Application Factory constructor (create_app())
│   ├── extensions.py         # Shared extension registries (db, login_manager, jwt, cors, celery, etc.)
│   ├── config.py             # Multi-environment settings (Dev, Testing, Production)
│   ├── models/               # SQLAlchemy schema definitions
│   ├── routes/               # Global standard routing interfaces
│   ├── services/             # Core business logic / decoupled execution services
│   ├── ai/                   # AI/ML intelligence pipelines & heuristics models
│   ├── utils/                # Helper tools, formatting, decorators
│   ├── templates/            # HTML views structure
│   │     ├── layouts/        # Parent blueprints wrappers (base.html)
│   │     ├── auth/           # Login, registration, credential recovery pages
│   │     ├── dashboard/      # Incident consoles, charts, feeds
│   │     └── errors/         # Customized user alerts (404, 500)
│   ├── static/               # CSS styles, vanilla JS files, UI components assets
│   └── blueprints/           # Decoupled domain modules (Blueprints)
│         ├── auth/           # Authentication endpoints & credentials logic
│         ├── dashboard/      # Telemetry feed dashboards views
│         ├── threats/        # Threat intel registries
│         ├── incidents/      # Incident observer tracking
│         ├── alerts/         # Acknowledgment alert routing
│         ├── reports/        # PDF/CSV threat summary generators
│         └── api/            # JSON services for platform connectors
├── migrations/               # Alembic database migrations
├── instance/                 # Secure SQLite/Local environment db location
├── tests/                    # Automation testing specs & conftest setup
├── requirements.txt          # Decoupled packages dependencies file
├── .env.example              # Platform environment settings blueprint
├── .gitignore                # Production ignore patterns (e.g. databases, credential logs, caches)
├── run.py                    # Entry point runner supporting dotenv and application factory context
└── README.md                 # Project outline & installation instructions
```

### Why we use this layout:
- **Clean Architecture & Separation of Concerns**: Isolating `models`, `services`, and `blueprints` prevents logic leakages. Blueprints process requests, services execute business logic, models handle database transactions, and the AI package is fully sandboxed.
- **Flask Application Factory Pattern**: Avoids global imports that create circular dependencies. It supports spinning up different application configurations (development, testing, production) dynamically.
- **Scalable Extensions**: Extensions are initialized globally inside `extensions.py` but bound dynamically to app instances in `create_app()`, which is standard practice for production Flask applications.

---

## Installation & Setup

### 1. Clone & Navigate to Project Directory
Ensure you are in the project folder root:
```bash
cd sentinel-pulse
```

### 2. Create and Activate a Python Virtual Environment
On Windows (PowerShell / Command Prompt):
```powershell
python -m venv venv
venv\Scripts\activate
```
On macOS / Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Package Dependencies
Install the required packages:
```bash
pip install -r requirements.txt
```

### 4. Create the Configuration Environment File
Copy the example environment template into a local active `.env` file:
```bash
copy .env.example .env
```
*(Open `.env` to update `SECRET_KEY`, database paths, and Redis URLs as needed).*

---

## Running the Application

### 1. Run in Development Mode
Execute the app runner:
```bash
python run.py
```
By default, the platform will spin up locally at `http://127.0.0.1:5000/`.

### 2. Run Automated Verification Tests
Run the automation suite to verify configuration loading and endpoints bindings:
```bash
pytest
```
All environment checks, db mappings, and mock endpoint responses will execute under the testing context.
