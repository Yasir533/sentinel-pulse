def test_config(app):
    """Test that the application is running in testing mode."""
    assert app.config['TESTING'] is True

def test_dashboard(client):
    """Test that the dashboard page redirects guest users to login."""
    response = client.get('/dashboard')
    assert response.status_code == 302
    assert '/auth/login' in response.headers['Location']

def test_api_status(client):
    """Test that the api status endpoint returns json status information."""
    response = client.get('/api/status')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['status'] == 'healthy'
    assert 'Sentinel Pulse API' in json_data['service']

def test_404_error(client):
    """Test that a non-existent page triggers custom 404 handler."""
    response = client.get('/non-existent-endpoint-route')
    assert response.status_code == 404
    assert b"Resource Coordinates Not Found" in response.data
