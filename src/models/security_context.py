from dataclasses import dataclass
from typing import List, Dict, Set

@dataclass
class SecurityContext:
    """Tracks security-relevant context for code analysis"""
    trust_boundaries: Set[str]
    sensitive_data: Set[str]
    authentication_points: Set[str]
    authorization_checks: Dict[str, List[str]] 