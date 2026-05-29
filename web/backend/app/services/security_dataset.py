"""Runtime loaders for VulnAssess Pro security datasets."""
from functools import lru_cache
import json
import os
from typing import Any, Dict

DATASET_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "datasets",
)


def _load_json(filename: str) -> Dict[str, Any]:
    path = os.path.join(DATASET_DIR, filename)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def load_security_headers() -> Dict[str, Any]:
    return _load_json("security_headers.json")


@lru_cache(maxsize=1)
def load_recommendations() -> Dict[str, Any]:
    return _load_json("recommendations.json")
