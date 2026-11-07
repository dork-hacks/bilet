"""Single place for the product name and runtime settings.

The product name is not decided yet (MASTERPLAN.md). Change DISPLAY_NAME here
and nowhere else. All settings come from environment variables (NFR-01).
"""

import os
from pathlib import Path

DISPLAY_NAME = "the tool"


def data_dir() -> Path:
    """Local folder for history, the device-key salt and other private data (NFR-02)."""
    return Path(os.environ.get("TOOL_DATA_DIR", "data")).expanduser()
