import pytest
from fastapi.testclient import TestClient
from backend.main import app
import os

# Set dummy key so app doesn't crash on boot if environment missing
os.environ["SKIP_DB"] = "1"

client = TestClient(app)

def test_health_check():
    response = client.get("/api/v1/analyze/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "model": "text-classifier-v2",
        "version": "2.0.0"
    }

def test_datasets_list():
    response = client.get("/api/v1/datasets/")
    assert response.status_code == 200
    data = response.json()
    assert "datasets" in data
    assert len(data["datasets"]) >= 1
    # Check that our new scam datasets are properly mounted
    dataset_ids = [d["id"] for d in data["datasets"]]
    # Since we use dynamic IDs from filename parsing:
    assert any("spam" in d for d in dataset_ids) or any("job" in d for d in dataset_ids)

def test_text_analysis():
    payload = {
        "text": "URGENT: Your account has been compromised. Please reset your password immediately."
    }
    response = client.post("/api/v1/analyze/text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "is_fraud" in data
    assert "risk_score" in data
    assert data["risk_score"] >= 0
    # Our mocked text classifier should trigger on 'urgent'
    assert data["detected_signals"]["urgency"] is True

def test_empty_text_analysis():
    payload = {"text": "   "}
    response = client.post("/api/v1/analyze/text", json=payload)
    # The Pydantic model throws a 422 Unprocessable Entity
    assert response.status_code == 422
