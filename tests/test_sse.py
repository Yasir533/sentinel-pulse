import pytest

def test_sse_event_stream_init(client):
    """Test initializing Server-Sent Events stream endpoint."""
    response = client.get('/api/events/stream')
    assert response.status_code == 200
    assert response.mimetype == 'text/event-stream'
