from dataclasses import dataclass
from typing import List, Dict, Pattern
import re

@dataclass
class SecurityPattern:
    name: str
    pattern: Pattern
    severity: str
    description: str
    mitigation: str

class SecurityPatternMatcher:
    def __init__(self):
        self.patterns: List[SecurityPattern] = self._load_patterns()
        
    def _load_patterns(self) -> List[SecurityPattern]:
        return [
            SecurityPattern(
                name="Hardcoded Credentials",
                pattern=re.compile(r'password\s*=\s*["\'].*["\']'),
                severity="HIGH",
                description="Hardcoded credentials detected",
                mitigation="Use environment variables or secure vaults"
            ),
            # Add more patterns
        ]
    
    def analyze_code(self, code: str) -> List[Dict]:
        findings = []
        for pattern in self.patterns:
            matches = pattern.pattern.finditer(code)
            for match in matches:
                findings.append({
                    'pattern': pattern.name,
                    'severity': pattern.severity,
                    'line': code.count('\n', 0, match.start()) + 1,
                    'mitigation': pattern.mitigation
                })
        return findings 