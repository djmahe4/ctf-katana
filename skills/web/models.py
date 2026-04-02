from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

class WebCategory(str, Enum):
    INJECTION = "injection"
    AUTH = "auth"
    ACCESS = "access"
    DATA_EXPOSURE = "data_exposure"
    MISCONFIG = "misconfig"
    XSS = "xss"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"
    CSRF = "csrf"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    JWT = "jwt"
    LOGIC = "logic"
    CACHE_POISONING = "cache_poisoning"
    WEBSOCKET = "websocket"
    GRAPHQL = "graphql"
    DISCOVERY = "discovery"

class WebSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class WebFinding(BaseModel):
    vulnerability_id: str
    category: WebCategory
    description: str
    severity: WebSeverity
    payload: Optional[str] = None
    evidence: Optional[str] = None
    url: Optional[str] = None
    request: Optional[Dict[str, Any]] = None
    response: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)

class WebRunResult(BaseModel):
    category: WebCategory
    target: str
    findings: List[WebFinding] = Field(default_factory=list)
    artifacts: List[str] = Field(default_factory=list)
    summary: str = ""
    statistics: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)
