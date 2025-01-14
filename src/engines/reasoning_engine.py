from typing import List, Dict
from ..security_agent import SecurityAgent

class ReasoningEngine:
    """Applies security reasoning to findings"""
    
    def __init__(self, agent: SecurityAgent):
        self.agent = agent
        
    def analyze_attack_vectors(self) -> List[Dict]:
        """Generate potential attack vectors based on findings"""
        vectors = []
        findings = self.agent._generate_findings()
        
        for finding in findings:
            if finding['type'] == 'trust_boundary_violation':
                vectors.append(self._analyze_data_exposure(finding))
            elif finding['type'] == 'missing_authentication':
                vectors.append(self._analyze_auth_bypass(finding))
        
        return vectors

    # ... (rest of the original ReasoningEngine methods) 