from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any


def _set_if_present(section: dict[str, Any], key: str, env_name: str) -> None:
    env_value = os.getenv(env_name)
    if env_value:
        section[key] = env_value


def load_runtime_config(config_path: str = "config.json") -> dict[str, Any]:
    path = Path(config_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    config = deepcopy(data)

    icann = config.setdefault("icann", {})
    discovery = config.setdefault("domain_discovery", {})

    _set_if_present(icann, "api_key", "ICANN_API_KEY")
    _set_if_present(discovery, "virustotal_key", "VT_API_KEY")
    _set_if_present(discovery, "securitytrails_key", "SECURITYTRAILS_API_KEY")
    _set_if_present(discovery, "urlscan_key", "URLSCAN_API_KEY")

    return config
