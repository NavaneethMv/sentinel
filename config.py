"""Config loader (the soft/heuristic tier).

`config.yaml` lists common secret-y variable names and common output sinks.
These are heuristics — they seed the name-set fallback inside the analyzer
but do NOT override the IR. A hardcoded literal `api_key = "abc"` stays a
`Constant` and is treated as safe.

See ARCHITECTURE.md §3.1 (two-tier rule model).
"""

from dataclasses import dataclass

import yaml


@dataclass
class Config:
    secrets: set[str]
    sinks: set[str]


def load_config() -> Config:
    with open("config.yaml") as f:
        data = yaml.safe_load(f)
    return Config(
        secrets=set(data.get("secrets", [])),
        sinks=set(data.get("sinks", [])),
    )
