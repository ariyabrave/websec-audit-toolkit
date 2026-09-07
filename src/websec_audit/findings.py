from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    """
    Represents a single security finding.
    """

    finding_id: str
    title: str
    severity: str
    description: str
    evidence: str
    recommendation: str