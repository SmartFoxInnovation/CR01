"""Public engineering receipts; no private identities or traffic state."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from . import __version__

from ._paths import default_project_root

ROOT = default_project_root()


def source_hashes(paths):
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(paths)}


def write_report(path, report, paths=()):
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    result = dict(report)
    result.update(product_version=__version__, generated_at=datetime.now(timezone.utc).isoformat(),
                  source_sha256=source_hashes(paths))
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result
