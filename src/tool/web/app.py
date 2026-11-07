"""FastAPI app for `tool serve` (FR-11). Runs unprivileged and never calls nmap.

Where the scan comes from is injected (`load_result`, from `serve --result`). Without one,
the home screen shows the newest readable scan in the local history (#87), with its change
alerts (#78).
"""

import json
import re
import secrets
import sqlite3
import tempfile
from collections.abc import Callable
from email.parser import BytesParser
from email.policy import HTTP
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
from tool.engine.parser import EMPTY_FILE, MAX_FILE_BYTES, NOT_XML, TOO_LARGE
from tool.engine.result import analyze_file, error_result
from tool.history import Alert, History, HistoryError
from tool.web.history_view import HistoryView, history_view
from tool.web.risks_view import risks_view
from tool.web.view import HomeView, home_view, pick_lang

TEMPLATES_DIR = Path(__file__).parent / "templates"
MAX_RESULT_BYTES = 5 * 1024 * 1024
MAX_FORM_BYTES = 4096  # the question form: lang, ai and a question of at most 300 chars
# "Open a scan file" (#92): the parser's own file limit plus room for the multipart framing.
MAX_UPLOAD_BYTES = MAX_FILE_BYTES + 64 * 1024
MAX_NAME_CHARS = 100
UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

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


def latest_from_history(history: History | None) -> dict | None:
    """The newest readable scan in the history, or None (#87).

    Read on every request, so a scan saved while the server runs shows up on the next page
    load. A corrupt or missing database shows the empty state, never a 500.
    """
    return latest_with_alerts(history)[0]


def latest_with_alerts(history: History | None) -> tuple[dict | None, list[Alert]]:
    """The newest readable scan in the history and its change alerts (#87, #78).

    A history error leaves the alerts out (and the scan too, if it can't be read): the home
    screen never breaks because of the history.
    """
    if history is None:
        return None, []
    try:
        readable = [s for s in history.scans() if s.status == "ok"]
        if not readable:
            return None, []
        data = history.result(readable[-1].id)
    except (HistoryError, sqlite3.Error, OSError, ValueError):
        return None, []
    if not isinstance(data, dict):
        return None, []
    try:
        alerts = history.alerts_for(readable[-1].id)
    except (HistoryError, sqlite3.Error, OSError, ValueError, KeyError, TypeError):
        alerts = []
    return data, alerts


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


class UploadError(Exception):
    """An upload refused before analysis. `code` is a parser error code (FILE_ERRORS)."""

    def __init__(self, code: str, status: int):
        super().__init__(code)
        self.code = code
        self.status = status


def safe_name(name: str) -> str:
    """The uploaded file name, made safe to use as a temp file name and to show (escaped).

    Hostile input: only the last path part is kept, odd characters become "_", leading dots
    go (no hidden or ".." names) and the length is capped.
    """
    base = name.replace(chr(92), "/").rsplit("/", 1)[-1]
    base = UNSAFE_NAME.sub("_", base).strip("._")[:MAX_NAME_CHARS]
    return base or "scan.xml"


async def read_upload(request: Request) -> tuple[dict[str, str], str, bytes]:
    """One multipart form with a `file` field, plus the small `lang` and `ai` fields.

    Read with a hard cap of MAX_UPLOAD_BYTES (the rest is never read into memory) and parsed
    with the standard library, so no extra dependency is needed. Raises UploadError.
    """
    ctype = request.headers.get("content-type", "")
    if not ctype.lower().startswith("multipart/form-data") or "boundary=" not in ctype.lower():
        raise UploadError(NOT_XML, 400)
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_UPLOAD_BYTES:
        raise UploadError(TOO_LARGE, 413)
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_UPLOAD_BYTES:
            raise UploadError(TOO_LARGE, 413)
    head = b"Content-Type: " + ctype.encode("latin-1", errors="replace") + b"\r\n\r\n"
    message = BytesParser(policy=HTTP).parsebytes(head + bytes(body))
    if not message.is_multipart():
        raise UploadError(NOT_XML, 400)
    fields: dict[str, str] = {}
    name, data = "", None
    for part in message.iter_parts():
        field = part.get_param("name", header="content-disposition")
        payload = part.get_payload(decode=True) or b""
        if field == "file" and data is None:
            name, data = part.get_filename() or "", payload
        elif field in ("lang", "ai") and field not in fields:
            fields[field] = payload[:16].decode("utf-8", errors="replace")
    if data is None:
        raise UploadError(EMPTY_FILE, 400)
    return fields, name, data


def analyze_upload(name: str, data: bytes) -> dict:
    """Analyse an uploaded file with the same code as `tool analyze`, never a second rule set.

    The bytes go to a private temp folder that is deleted right after, never to the repo or
    the history. A fresh random salt keeps the user's own salt file out of it: device keys
    only matter for the history, and an opened file is never saved there.
    """
    with tempfile.TemporaryDirectory(prefix="tool-open-") as folder:
        path = Path(folder) / safe_name(name)
        path.write_bytes(data)
        return analyze_file(path, salt=secrets.token_hex(32).encode()).to_dict()


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
    The home screen shows `load_result()` when it has a scan (`serve --result`), otherwise
    the newest readable scan in the history (#87).
    """
    app = FastAPI(title=DISPLAY_NAME, docs_url=None, redoc_url=None, openapi_url=None)

    def current_result() -> tuple[dict | None, list[Alert]]:
        # Alerts belong to a scan in the history, so a `--result` file shows none.
        result = load_result()
        return (result, []) if result is not None else latest_with_alerts(history)

    # Jinja2Templates turns autoescape on for .html files: RAW scan fields and AI text
    # are escaped.
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    def context(lang: str) -> dict:
        return {
            "ui": {key: value[lang] for key, value in UI.items()},
            "langs": [(code, LANG_NAMES[code]) for code in LANGS],
            "display_name": DISPLAY_NAME,
        }

    def render(
        request: Request, view: HomeView, opened: bool = False, status: int = 200
    ) -> HTMLResponse:
        # `opened`: the page shows a file the user just opened (#92), not the latest scan.
        return templates.TemplateResponse(
            request,
            "home.html",
            {
                "view": view,
                "ai_param": "1" if view.ai_on else "0",
                "opened": opened,
                **context(view.lang),
            },
            status_code=status,
        )

    def render_history(request: Request, view: HistoryView, status: int = 200) -> HTMLResponse:
        return templates.TemplateResponse(
            request, "history.html", {"view": view, **context(view.lang)}, status_code=status
        )

    @app.get("/risks", response_class=HTMLResponse)
    def risks_page(request: Request, lang: str | None = None) -> HTMLResponse:
        # Reads only the catalog texts, never a scan, so it works with no history (#83).
        view = risks_view(lang)
        return templates.TemplateResponse(
            request, "risks.html", {"view": view, **context(view.lang)}
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
        result, alerts = current_result()
        view = home_view(result, lang, explainer, ai_on=ai == "1", alerts=alerts)
        return render(request, view)

    @app.post("/open", response_class=HTMLResponse)
    async def open_file(request: Request) -> HTMLResponse:
        # Live checks 2 and 5 (MASTERPLAN §8): any file, even a broken one, gives a page.
        if not same_origin(request):
            return PlainTextResponse("Forbidden", status_code=403)
        try:
            fields, name, data = await read_upload(request)
        except UploadError as exc:
            # The form's lang field may be unreadable here, so the language comes from the
            # form's action URL. No file name: the upload never got that far.
            result = error_result("", exc.code).to_dict()
            view = home_view(result, request.query_params.get("lang"))
            return render(request, view, opened=True, status=exc.status)
        result = await run_in_threadpool(analyze_upload, name, data)
        # AI stays opt-in, as on the home screen. No change alerts: the opened file isn't in
        # the history, so there is nothing to compare it with.
        lang = fields.get("lang") or request.query_params.get("lang")
        view = await run_in_threadpool(
            home_view, result, lang, explainer, ai_on=fields.get("ai") == "1"
        )
        return render(request, view, opened=True)

    @app.post("/ask", response_class=HTMLResponse)
    async def ask(request: Request) -> HTMLResponse:
        # POST, so a link or a page reload never sends a question to the AI by itself.
        form = await read_form(request)
        if form is None:
            return PlainTextResponse("Request too large", status_code=413)
        # The AI call blocks for up to the timeout, so it runs off the event loop.
        result, alerts = current_result()
        view = await run_in_threadpool(
            home_view,
            result,
            form.get("lang"),
            explainer,
            ai_on=form.get("ai") == "1",
            question=form.get("q", ""),
            alerts=alerts,
        )
        return render(request, view)

    return app
