from dataclasses import dataclass


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    recommendation: str