"""Locate checkout assets; an installed wheel may use an explicit/cwd project root."""
from pathlib import Path


def default_project_root():
    candidate = Path(__file__).resolve().parents[3]
    if (candidate / "pyproject.toml").is_file() and (candidate / "src/python/cr01_sc").is_dir():
        return candidate
    return Path.cwd().resolve()
