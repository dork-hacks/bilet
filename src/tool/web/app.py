"""FastAPI app for `tool serve` (FR-11). Runs unprivileged and never calls nmap.

Where the scan comes from is injected (`load_result`), so the app is tested against the
contract fixtures today and wired to history (#21) later without changing the views.
"""

import json
from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from tool.ai.explain import Explainer
from tool.config import DISPLAY_NAME
from tool.content import LANGS
from tool.content.ui import LANG_NAMES, UI
from tool.history import History
from tool.web.history_view import HistoryView, history_view
from tool.web.view import HomeView, home_view, pick_lang

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


def same_origin(request: Request) -> bool:
    """False for a form posted from another website (a drive-by "delete my history").

    Browsers send `Origin` (and `Sec-Fetch-Site`) with a form POST. A request that has
    neither, such as one from curl or the test client, is not a browser cross-site post.
    """
    if request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
        return False
    origin = request.headers.get("origin")
    if origin is None:
        return True
    host = request.headers.get("host", "")
    return origin in (f"http://{host}", f"https://{host}")


def create_app(
    load_result: ResultLoader,
    explainer: Explainer | None = None,
    history: History | None = None,
) -> FastAPI:
    """`explainer` is the optional AI layer. It is used only when the user turns AI on.
    `history` is the local scan history (#21) behind the history screen; None turns it off.
    """
    app = FastAPI(title=DISPLAY_NAME, docs_url=None, redoc_url=None, openapi_url=None)
    # Jinja2Templates turns autoescape on for .html files: RAW scan fields and AI text
    # are escaped.
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    def context(lang: str) -> dict:
        return {
            "ui": {key: value[lang] for key, value in UI.items()},
            "langs": [(code, LANG_NAMES[code]) for code in LANGS],
            "display_name": DISPLAY_NAME,
        }

    def render(request: Request, view: HomeView) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "home.html",
            {"view": view, "ai_param": "1" if view.ai_on else "0", **context(view.lang)},
        )

    def render_history(request: Request, view: HistoryView, status: int = 200) -> HTMLResponse:
        return templates.TemplateResponse(
            request, "history.html", {"view": view, **context(view.lang)}, status_code=status
        )

    @app.get("/history", response_class=HTMLResponse)
    def history_page(
        request: Request,
        lang: str | None = None,
        old: str | None = None,
        new: str | None = None,
        done: str | None = None,
    ) -> HTMLResponse:
        message = "deleted_done" if done == "1" else None
        return render_history(request, history_view(history, lang, old, new, message))

    @app.post("/history/delete", response_class=HTMLResponse)
    async def delete_history(request: Request) -> Response:
        # POST only, with a confirm step, so a link or a reload never deletes anything.
        form = await read_form(request)
        if form is None:
            return PlainTextResponse("Request too large", status_code=413)
        lang = pick_lang(form.get("lang"))
        if not same_origin(request):
            return PlainTextResponse("Forbidden", status_code=403)
        if history is None:
            return render_history(request, history_view(None, lang))
        if form.get("confirm") != "yes":
            return render_history(request, history_view(history, lang, confirm_delete=True))
        await run_in_threadpool(history.delete_all)
        return RedirectResponse(f"/history?lang={lang}&done=1", status_code=303)

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
