"""DNS rebinding cannot read local results or mutate history; pages cannot be framed."""

from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from tool.web.app import create_app


@pytest.mark.parametrize(
    "host",
    [
        "attacker.example",
        "127.0.0.1.attacker.example",
        "192.168.1.4",
        "0.0.0.0",  # noqa: S104 - rejected Host input, no server is bound
        "localhost.attacker.example",
        "user@127.0.0.1",
        "127.0.0.1/path",
        "127.0.0.1?x",
        "127.0.0.1#x",
        "127.0.0.1:99999",
        "127.0.0.1:0",
        "",
        "[::1%eth0]",
        " localhost",
        "127.0.0.1\\evil",
    ],
)
@pytest.mark.parametrize("path", ["/", "/history", "/map.json", "/report", "/static/netmap.css"])
def test_rebinding_host_cannot_read_any_surface(host, path):
    load = Mock(return_value=None)
    client = TestClient(create_app(load), base_url="http://127.0.0.1")
    response = client.get(path, headers={"host": host, "x-forwarded-host": "127.0.0.1"})
    assert response.status_code == 403
    load.assert_not_called()
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["content-security-policy"] == "frame-ancestors 'none'"


def test_rebinding_same_origin_delete_cannot_reach_history():
    history = Mock()
    client = TestClient(create_app(lambda: None, history=history), base_url="http://127.0.0.1")
    response = client.post(
        "/history/delete",
        data={"confirm": "yes"},
        headers={"host": "evil.example", "origin": "http://evil.example"},
    )
    assert response.status_code == 403
    history.delete_all.assert_not_called()


@pytest.mark.parametrize("host", ["localhost", "localhost:8000", "127.0.0.1:8000", "[::1]:8000"])
@pytest.mark.parametrize("path,status", [("/", 200), ("/map.json", 200), ("/missing", 404)])
def test_supported_local_hosts_and_frame_headers(host, path, status):
    client = TestClient(create_app(lambda: None), base_url="http://127.0.0.1")
    response = client.get(path, headers={"host": host})
    assert response.status_code == status
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["content-security-policy"] == "frame-ancestors 'none'"


def test_duplicate_host_is_rejected():
    client = TestClient(create_app(lambda: None), base_url="http://127.0.0.1")
    response = client.get("/", headers=[("host", "127.0.0.1"), ("host", "evil.example")])
    assert response.status_code == 403
