"""FastAPI app for `tool serve` (FR-11). Runs unprivileged and never calls nmap.

Where the scan comes from is injected (`load_result`), so the app is tested against the
contract fixtures today and wired to history (#21) later without changing the views.
"""

import json
from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from tool.ai.explain import Explainer
from tool.config import DISPLAY_NAME
from tool.content import LANGS
from tool.content.ui import LANG_NAMES, UI
from tool.web.view import HomeView, home_view

TEMPLATES_DIR = Path(__file__).parent / "templates"
MAX_RESULT_BYTES = 5 * 1024 * 1024
MAX_FORM_BYTES = 4096  # the question form: lang, ai and a question of at most 300 chars

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


async def read_form(request: Request) -> dict[str, str] | None:
    """A small urlencoded form, or None if it is too large. Hostile input: capped, decoded
    leniently, and only the first value of each field is kept."""
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_FORM_BYTES:
            return None
    fields = parse_qs(body.decode("utf-8", errors="replace"), max_num_fields=10)
    return {key: values[0] for key, values in fields.items() if values}


def create_app(load_result: ResultLoader, explainer: Explainer | None = None) -> FastAPI:
    """`explainer` is the optional AI layer. It is used only when the user turns AI on."""
    app = FastAPI(title=DISPLAY_NAME, docs_url=None, redoc_url=None, openapi_url=None)
    # Jinja2Templates turns autoescape on for .html files: RAW scan fields and AI text
    # are escaped.
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    def render(request: Request, view: HomeView) -> HTMLResponse:
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

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request, lang: str | None = None, ai: str | None = None) -> HTMLResponse:
        # Opt-in: only an explicit ai=1 turns it on (MASTERPLAN §5.4).
        return render(request, home_view(load_result(), lang, explainer, ai_on=ai == "1"))

    @app.post("/ask", response_class=HTMLResponse)
    async def ask(request: Request) -> HTMLResponse:
        # POST, so a link or a page reload never sends a question to the AI by itself.
        form = await read_form(request)
        if form is None:
            return PlainTextResponse("Request too large", status_code=413)
        # The AI call blocks for up to the timeout, so it runs off the event loop.
        view = await run_in_threadpool(
            home_view,
            load_result(),
            form.get("lang"),
            explainer,
            ai_on=form.get("ai") == "1",
            question=form.get("q", ""),
        )
        return render(request, view)

    return app
