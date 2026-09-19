"""Reproducibly export the FastAPI contract for frontend type generation."""

import json
import sys
from pathlib import Path

from firewall_manager.main import app


def main() -> None:
    """Write canonical, stable JSON to the requested path."""
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m firewall_manager.export_openapi OUTPUT")
    target = Path(sys.argv[1])
    target.write_text(json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
