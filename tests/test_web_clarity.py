"""Finding identity and the recommended action precede the scan control."""

from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from tool.content.ui import UI
from tool.engine import analyze_file
from tool.web.app import create_app


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_codes_port_hint_and_action_before_check_again(lang):
    scan = analyze_file(
        Path(__file__).parent / "fixtures/validation/V2_smart_home.xml", salt=b"test"
    ).to_dict()
    runner = Mock()
    runner.state.return_value = None
    app = create_app(lambda: scan, scan_runner=runner)

    async def with_peer(scope, receive, send):
        if scope["type"] == "http":
            scope = {**scope, "client": ("127.0.0.1", 12345)}
        await app(scope, receive, send)

    client = TestClient(with_peer, base_url="http://127.0.0.1")
    html = client.get("/", params={"lang": lang}).text
    assert html.index(UI["do_first"][lang]) < html.index('action="/scan"')
    assert UI["port_hint"][lang] in html
    # The catalog codes sit with each device's fix steps, on /devices since #273.
    html = client.get("/devices", params={"lang": lang}).text
    for finding in scan["findings"]:
        assert f'<code>{finding["code"]}</code>' in html
    risks = client.get("/risks", params={"lang": lang}).text
    assert UI["port_hint"][lang] in risks
    assert "<code>OUTDATED_SERVICE</code>" in risks
    runner.start_scan.assert_not_called()
