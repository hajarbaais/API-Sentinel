
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OwaspCategory(str, Enum):
    BOLA = "API1:2023 - Broken Object Level Authorization"
    BROKEN_AUTH = "API2:2023 - Broken Authentication"
    BOPLA = "API3:2023 - Broken Object Property Level Authorization"
    RESOURCE_CONSUMPTION = "API4:2023 - Unrestricted Resource Consumption"
    BFLA = "API5:2023 - Broken Function Level Authorization"
    SSRF = "API7:2023 - Server Side Request Forgery"
    SECURITY_MISCONFIGURATION = "API8:2023 - Security Misconfiguration"


@dataclass
class Finding:
   
    detector: str
    owasp_category: OwaspCategory
    severity: Severity
    confidence: float
    title: str
    description: str
    affected_endpoint: str
    evidence_test_id: str
    victim_role: str
    attacker_role: str
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )