
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Evidence:
    test_id: str
    detector: str                  
    request_method: str
    request_url: str
    request_headers: dict
    request_body: dict | None
    response_status: int
    response_body: dict | None
    finding_confirmed: bool
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class EvidenceStore:
    
    def __init__(self, output_path: str):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._counter = 0

    def record(
        self,
        detector: str,
        request_method: str,
        request_url: str,
        request_headers: dict,
        request_body: dict | None,
        response_status: int,
        response_body: dict | None,
        finding_confirmed: bool,
    ) -> Evidence:
       
        self._counter += 1
        test_id = f"{detector}-{self._counter:05d}"

        safe_headers = self._redact_sensitive_headers(request_headers)

        evidence = Evidence(
            test_id=test_id,
            detector=detector,
            request_method=request_method,
            request_url=request_url,
            request_headers=safe_headers,
            request_body=request_body,
            response_status=response_status,
            response_body=response_body,
            finding_confirmed=finding_confirmed,
        )

        with self.output_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(evidence), ensure_ascii=False) + "\n")

        return evidence

    def _redact_sensitive_headers(self, headers: dict) -> dict:
        """Masque les tokens dans les headers avant tout export/stockage."""
        redacted = dict(headers)
        if "Authorization" in redacted:
            value = redacted["Authorization"]
            redacted["Authorization"] = value[:15] + "...REDACTED"
        return redacted