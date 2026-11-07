"""Single place for the product name and runtime settings.

The product name is bilet (MASTERPLAN.md). Change DISPLAY_NAME here and nowhere
else. All settings come from environment variables (NFR-01).
"""

import os
from pathlib import Path

DISPLAY_NAME = "bilet"


def data_dir() -> Path:
    """Local folder for history, the device-key salt and other private data (NFR-02)."""
    # `or`, not a get() default: an empty TOOL_DATA_DIR= (as in .env.example) means "unset",
    # not "the current directory", which isn't git-ignored.
    return Path(os.environ.get("TOOL_DATA_DIR") or "data").expanduser()
