"""Outdated program/version evidence is local, translated and escaped."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tool.engine.result import analyze_file
from tool.web.app import create_app


@pytest.mark.parametrize(
    "lang,label", [("en", "What the scan saw"), ("ro", "Ce a observat verificarea")]
)
@pytest.mark.parametrize("product", ["Old server", None, '<script>alert("x")</script>'])
def test_outdated_finding_shows_escaped_product_version_or_service(lang, label, product):
    scan = analyze_file(
        Path(__file__).parent / "fixtures/validation/V4_legacy.xml", salt=b"test"
    ).to_dict()
    finding = next(f for f in scan["findings"] if f["code"] == "OUTDATED_SERVICE")
    finding["evidence"].update(product=product, service_name="ftp", version="2.3.4")
    html = (
        TestClient(create_app(lambda: scan), base_url="http://127.0.0.1")
        .get("/", params={"lang": lang})
        .text
    )
    assert label in html
    assert "2.3.4" in html
    if product is None:
        assert "ftp 2.3.4" in html
    elif product.startswith("<"):
        assert product not in html
        assert "&lt;script&gt;" in html
    else:
        assert product + " 2.3.4" in html
