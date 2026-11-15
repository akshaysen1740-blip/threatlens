from dataclasses import asdict, dataclass

SEVERITY_WEIGHTS = {"info": 0, "low": 10, "medium": 20, "high": 35, "critical": 50}


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str  # info | low | medium | high | critical
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)
