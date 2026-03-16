import json
import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def client():
    with patch("app.load_k8s_client"), \
         patch("app.K8S_AVAILABLE", True), \
         patch("app.v1", MagicMock()):
        import app as application
        application.app.config["TESTING"] = True

        # Reset rate limiter between every test
        application._rate_limit.clear()

        with application.app.test_client() as c:
            yield c


def alert(rule="Terminal shell in container",
          priority="Critical",
          pod="attacker",
          ns="default"):
    return {
        "rule": rule,
        "priority": priority,
        "output_fields": {
            "k8s.pod.name": pod,
            "k8s.ns.name": ns
        }
    }


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_critical_alert_actioned(client):
    with patch("app.respond") as mock_respond:
        r = client.post("/",
                        data=json.dumps(alert()),
                        content_type="application/json")
        assert r.status_code == 200
        assert r.get_json()["status"] == "actioned"
        mock_respond.assert_called_once()


def test_warning_alert_actioned(client):
    with patch("app.respond") as mock_respond:
        r = client.post("/",
                        data=json.dumps(alert(priority="Warning")),
                        content_type="application/json")
        assert r.status_code == 200
        assert r.get_json()["status"] == "actioned"
        mock_respond.assert_called_once()


def test_no_pod_metadata_ignored(client):
    payload = {"rule": "Terminal shell in container",
               "priority": "Critical", "output_fields": {}}
    r = client.post("/",
                    data=json.dumps(payload),
                    content_type="application/json")
    assert r.status_code == 200
    assert r.get_json()["reason"] == "no pod metadata"


def test_non_security_rule_ignored(client):
    r = client.post("/",
                    data=json.dumps(
                        alert(rule="Some unrelated Falco rule")),
                    content_type="application/json")
    assert r.status_code == 200
    assert r.get_json()["reason"] == "not a security rule"


def test_rate_limiting(client):
    with patch("app.respond"):
        # First request — should be actioned
        r1 = client.post("/",
                         data=json.dumps(alert()),
                         content_type="application/json")
        assert r1.get_json()["status"] == "actioned"

        # Immediate second request same pod — should be rate limited
        r2 = client.post("/",
                         data=json.dumps(alert()),
                         content_type="application/json")
        assert r2.get_json()["status"] == "rate_limited"