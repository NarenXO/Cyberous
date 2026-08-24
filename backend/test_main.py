import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_check():
    """Test the health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_login_success():
    """Test successful login"""
    response = client.post("/api/login", json={
        "username": "naren",
        "password": "password123",
        "cyberous_enabled": False
    })
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert data["username"] == "naren"
    assert "trust_score" in data

def test_login_invalid_credentials():
    """Test login with invalid credentials"""
    response = client.post("/api/login", json={
        "username": "naren",
        "password": "wrongpassword",
        "cyberous_enabled": False
    })
    assert response.status_code == 401

def test_login_with_behavioral_biometrics():
    """Test login with behavioral biometrics enabled"""
    response = client.post("/api/login", json={
        "username": "naren",
        "password": "password123",
        "cyberous_enabled": True,
        "behavior_data": {
            "avg_keystroke_interval": 125,
            "avg_hold_duration": 85,
            "avg_mouse_velocity": 2.5,
            "ip_address": "127.0.0.1",
            "location": "Local Baseline",
            "device_type": "Desktop"
        }
    })
    assert response.status_code == 200
    data = response.json()
    assert "trust_score" in data
    assert data["trust_score"] > 50
    assert "agents" in data
    assert len(data["agents"]) == 5
    # Check new agent schema fields
    for agent in data["agents"]:
        assert "name" in agent
        assert "score" in agent
        assert "status" in agent
        assert "insight" in agent
        assert "latency_ms" in agent

def test_login_with_untrusted_location():
    """Test login with untrusted location"""
    response = client.post("/api/login", json={
        "username": "naren",
        "password": "password123",
        "cyberous_enabled": True,
        "behavior_data": {
            "avg_keystroke_interval": 125,
            "avg_hold_duration": 85,
            "avg_mouse_velocity": 2.5,
            "ip_address": "192.168.1.1",
            "location": "Unknown",
            "device_type": "Desktop"
        }
    })
    assert response.status_code == 200
    data = response.json()
    assert "trust_score" in data

def test_login_with_attack_simulation():
    """Test login with attack simulation - should freeze account"""
    response = client.post("/api/login", json={
        "username": "naren",
        "password": "password123",
        "cyberous_enabled": True,
        "behavior_data": {
            "avg_keystroke_interval": 25,
            "avg_hold_duration": 15,
            "avg_mouse_velocity": 2.5,
            "ip_address": "192.168.1.1",
            "location": "Unknown",
            "device_type": "Desktop",
            "is_attack_simulation": True
        }
    })
    assert response.status_code == 403
    data = response.json()
    assert "detail" in data
    assert "automated attack detection" in data["detail"].lower()

def test_reset_endpoint():
    """Test the reset endpoint"""
    response = client.post("/api/reset")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == True
    assert "Demo state reset successfully" in data["message"]
