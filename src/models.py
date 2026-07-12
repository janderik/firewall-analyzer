from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class Action(Enum):
    ALLOW = 'allow'
    DENY = 'deny'
    DROP = 'drop'
    REJECT = 'reject'
    LOG = 'log'

class Protocol(Enum):
    TCP = 'tcp'
    UDP = 'udp'
    ICMP = 'icmp'
    ANY = 'any'

class Severity(Enum):
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'

@dataclass
class FirewallRule:
    chain: str = ''
    action: Action = Action.DENY
    protocol: Protocol = Protocol.ANY
    source: str = '0.0.0.0/0'
    destination: str = '0.0.0.0/0'
    source_port: Optional[str] = None
    destination_port: Optional[str] = None
    line_number: int = 0
    raw: str = ''
    comment: str = ''
    flags: list = field(default_factory=list)

@dataclass
class Finding:
    rule_line: int
    severity: Severity
    title: str
    description: str
    recommendation: str = ''
    category: str = ''
    cwe_id: str = ''

@dataclass
class AnalysisResult:
    total_rules: int = 0
    allow_rules: int = 0
    deny_rules: int = 0
    findings: list = field(default_factory=list)
    rules: list = field(default_factory=list)
