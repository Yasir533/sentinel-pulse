import time
import uuid
import queue
import threading
from datetime import datetime
from typing import Dict, List, Optional
from flask import current_app

class RealtimeEventService:
    """
    Central thread-safe Real-Time Event Publisher & SSE Broker.
    Manages active SSE client subscriber queues and broadcasts role-filtered security events.
    """
    _listeners: List[Dict] = []
    _lock = threading.Lock()

    @classmethod
    def register_listener(cls, user_id: int, role: str) -> Dict:
        """
        Register a new SSE client listener queue.
        """
        listener = {
            'id': uuid.uuid4().hex,
            'user_id': user_id,
            'role': role.strip().capitalize() if role else 'Viewer',
            'queue': queue.Queue(maxsize=50) # Bounded queue prevents memory leaks
        }
        with cls._lock:
            cls._listeners.append(listener)
        return listener

    @classmethod
    def unregister_listener(cls, listener: Dict) -> None:
        """
        Unregister and clean up an SSE client listener queue.
        """
        with cls._lock:
            if listener in cls._listeners:
                cls._listeners.remove(listener)

    @staticmethod
    def _sanitize_and_minimize_payload(payload: dict) -> dict:
        """
        Sanitize and minimize SSE event payloads to prevent secret or long payload leakage.
        Strips sensitive credential keys and truncates long text payloads.
        """
        if not isinstance(payload, dict):
            return {}

        SENSITIVE_KEYS = {
            'password', 'password_hash', 'secret_key', 'jwt_secret',
            'api_key', 'token', 'secret', 'access_token', 'refresh_token',
            'session_id', 'cookie'
        }

        minimized = {}
        for k, v in payload.items():
            if k.lower() in SENSITIVE_KEYS:
                continue
            if isinstance(v, str) and len(v) > 200:
                minimized[k] = v[:200] + '...'
            else:
                minimized[k] = v
        return minimized

    @classmethod
    def publish(
        cls,
        event_type: str,
        payload: dict,
        target_role: Optional[str] = None,
        target_user_id: Optional[int] = None
    ) -> int:
        """
        Publish a structured security event to authorized SSE listener queues.
        Returns the count of client queues that received the event.
        """
        clean_payload = cls._sanitize_and_minimize_payload(payload)
        event_obj = {
            'event_id': f"evt_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}",
            'event_type': event_type,
            'timestamp': datetime.utcnow().isoformat() + "Z",
            'payload': clean_payload
        }

        delivered_count = 0
        with cls._lock:
            active_listeners = list(cls._listeners)

        for listener in active_listeners:
            # 1. Target User ID filtering
            if target_user_id is not None and listener['user_id'] != target_user_id:
                continue

            # 2. Role-based event filtering (RBAC)
            listener_role = listener['role']
            if target_role:
                req_role = target_role.strip().capitalize()
                if req_role == 'Admin' and listener_role != 'Admin':
                    continue
                elif req_role == 'Analyst' and listener_role not in ['Admin', 'Analyst']:
                    continue
            else:
                # Default role safety: Admin receives all events; Analyst receives non-Admin events; Viewer receives Viewer events
                if event_type in ['system.health_warning', 'audit.log_created'] and listener_role != 'Admin':
                    continue

            try:
                listener['queue'].put_nowait(event_obj)
                delivered_count += 1
            except queue.Full:
                # Queue full, skip to prevent blocking application workers
                pass

        return delivered_count

    @classmethod
    def get_listener_count(cls) -> int:
        """Return count of active connected SSE clients."""
        with cls._lock:
            return len(cls._listeners)
