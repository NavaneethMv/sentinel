from dataclasses import dataclass
import yaml


@dataclass
class Config:
    secrets: set[str]
    sinks: set[str]


def load_config() -> Config:
    with open("config.yaml", "r") as f:
        data = yaml.safe_load(f)
    return Config(
        secrets=set(data.get("secrets", [])),
        sinks=set(data.get("sinks", [])),
    )
