from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from sentinelx import api


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv(
        "NEON_AUTH_BASE_URL",
        "https://ep-curly-dust-aonytmmj.neonauth.c-2.ap-southeast-1.aws.neon.tech/sentinelx/auth",
    )
    return TestClient(api.app)


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("patch", "/incidents/demo-incident/status?status=resolved", {}),
        (
            "post",
            "/incidents/demo-incident/notes",
            {"json": {"body": "Investigating the alert"}},
        ),
    ],
)
def test_analyst_mutations_reject_missing_bearer_token(client, method, path, kwargs):
    response = getattr(client, method)(path, **kwargs)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_analyst_mutations_reject_invalid_bearer_token(client, monkeypatch):
    class NoKeys:
        def get_signing_key_from_jwt(self, token):
            raise jwt.InvalidTokenError("unknown signing key")

    monkeypatch.setattr(api, "_jwks_client", lambda: NoKeys())
    response = client.post(
        "/incidents/demo-incident/notes",
        headers={"Authorization": "Bearer not-a-jwt"},
        json={"body": "Investigating the alert"},
    )
    assert response.status_code == 401


def test_require_analyst_accepts_valid_issuer_subject_and_expiry(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = "https://ep-curly-dust-aonytmmj.neonauth.c-2.ap-southeast-1.aws.neon.tech"
    monkeypatch.setenv("NEON_AUTH_BASE_URL", issuer + "/sentinelx/auth")

    class TestKeys:
        def get_signing_key_from_jwt(self, token):
            return SimpleNamespace(key=private_key.public_key())

    monkeypatch.setattr(api, "_jwks_client", lambda: TestKeys())
    token = jwt.encode(
        {"iss": issuer, "sub": "test-analyst", "exp": 4102444800},
        private_key,
        algorithm="RS256",
    )

    claims = api.require_analyst("Bearer " + token)
    assert claims["sub"] == "test-analyst"
    assert claims["iss"] == issuer
