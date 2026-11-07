"""FastAPI app for `tool serve` (FR-11). Runs unprivileged and never calls nmap.

Where the scan comes from is injected (`load_result`), so the app is tested against the
contract fixtures today and wired to history (#21) later without changing the views.
"""

import json
from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from tool.ai.explain import Explainer
from tool.config import DISPLAY_NAME
from tool.content import LANGS
from tool.content.ui import LANG_NAMES, UI
from tool.web.view import home_view

TEMPLATES_DIR = Path(__file__).parent / "templates"
MAX_RESULT_BYTES = 5 * 1024 * 1024

ResultLoader = Callable[[], dict | None]


def load_json_file(path: Path) -> dict | None:
    """Read one ScanResult JSON. Anything unreadable shows the empty state, never a crash."""
    try:
        if path.stat().st_size > MAX_RESULT_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def create_app(load_result: ResultLoader, explainer: Explainer | None = None) -> FastAPI:
    """`explainer` is the optional AI layer. It is used only when the user turns AI on."""
    app = FastAPI(title=DISPLAY_NAME, docs_url=None, redoc_url=None, openapi_url=None)
    # Jinja2Templates turns autoescape on for .html files: RAW scan fields and AI text
    # are escaped.
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request, lang: str | None = None, ai: str | None = None) -> HTMLResponse:
        # Opt-in: only an explicit ai=1 turns it on (MASTERPLAN §5.4).
        view = home_view(load_result(), lang, explainer, ai_on=ai == "1")
        return templates.TemplateResponse(
            request,
            "home.html",
            {
                "view": view,
                "ai_param": "1" if view.ai_on else "0",
                "ui": {key: value[view.lang] for key, value in UI.items()},
                "langs": [(code, LANG_NAMES[code]) for code in LANGS],
                "display_name": DISPLAY_NAME,
            },
        )

    return app
