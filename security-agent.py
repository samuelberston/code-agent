import ast
from dataclasses import dataclass
from typing import List, Dict, Set
import networkx as nx

@dataclass
class SecurityContext:
    """Tracks security-relevant context for code analysis"""
    trust_boundaries: Set[str]
    sensitive_data: Set[str]
    authentication_points: Set[str]
    authorization_checks: Dict[str, List[str]]

class SecurityAgent:
    def __init__(self):
        self.context = SecurityContext(
            trust_boundaries=set(),
            sensitive_data=set(),
            authentication_points=set(),
            authorization_checks={}
        )
        self.call_graph = nx.DiGraph()
        
    def analyze_codebase(self, source_files: List[str]):
        """Analyze codebase for potential vulnerabilities"""
        for file in source_files:
            self._analyze_file(file)
        return self._generate_findings()
    
    def _analyze_file(self, file_path: str):
        """Analyze a single source file"""
        with open(file_path) as f:
            tree = ast.parse(f.read(), filename=file_path)
            
        # Build call graph
        self._build_call_graph(tree)
        
        # Identify security boundaries
        self._identify_trust_boundaries(tree)
        
        # Track data flow
        self._track_data_flow(tree)
        
        # Check for common vulnerability patterns
        self._check_vulnerability_patterns(tree)
    
    def _identify_trust_boundaries(self, tree: ast.AST):
        """Identify trust boundaries in the code"""
        class TrustBoundaryVisitor(ast.NodeVisitor):
            def __init__(self):
                self.boundaries = set()
                
            def visit_FunctionDef(self, node):
                # Identify API endpoints and external interfaces
                decorators = [d.id for d in node.decorator_list 
                            if isinstance(d, ast.Name)]
                
                if any(d in ['route', 'endpoint', 'api'] for d in decorators):
                    self.boundaries.add(node.name)
                    
                self.generic_visit(node)
        
        visitor = TrustBoundaryVisitor()
        visitor.visit(tree)
        self.context.trust_boundaries.update(visitor.boundaries)
    
    def _track_data_flow(self, tree: ast.AST):
        """Track flow of data through the application"""
        class DataFlowVisitor(ast.NodeVisitor):
            def __init__(self):
                self.sensitive_data = set()
                
            def visit_Assign(self, node):
                # Look for assignments involving sensitive data patterns
                if isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Name):
                        if node.value.func.id in ['get_password', 'decrypt', 'load_key']:
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    self.sensitive_data.add(target.id)
                
                self.generic_visit(node)
        
        visitor = DataFlowVisitor()
        visitor.visit(tree)
        self.context.sensitive_data.update(visitor.sensitive_data)
    
    def _check_vulnerability_patterns(self, tree: ast.AST):
        """Check for common vulnerability patterns"""
        class VulnerabilityVisitor(ast.NodeVisitor):
            def __init__(self):
                self.findings = []
                
            def visit_Call(self, node):
                # Check for dangerous function calls
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec', 'os.system']:
                        self.findings.append({
                            'type': 'dangerous_function',
                            'function': node.func.id,
                            'line': node.lineno
                        })
                
                self.generic_visit(node)
                
            def visit_BinOp(self, node):
                # Check for potential SQL injection
                if isinstance(node.op, ast.Add):
                    if isinstance(node.left, ast.Str) and 'SELECT' in node.left.s:
                        self.findings.append({
                            'type': 'sql_injection',
                            'line': node.lineno
                        })
                
                self.generic_visit(node)
        
        visitor = VulnerabilityVisitor()
        visitor.visit(tree)
        return visitor.findings
    
    def _generate_findings(self) -> List[Dict]:
        """Generate security findings based on analysis"""
        findings = []
        
        # Analyze trust boundary violations
        for data in self.context.sensitive_data:
            paths = self._find_paths_to_boundaries(data)
            if paths:
                findings.append({
                    'type': 'trust_boundary_violation',
                    'sensitive_data': data,
                    'exposure_paths': paths
                })
        
        # Analyze authentication bypass risks
        for boundary in self.context.trust_boundaries:
            if not self._has_auth_check(boundary):
                findings.append({
                    'type': 'missing_authentication',
                    'boundary': boundary
                })
        
        return findings
    
    def _find_paths_to_boundaries(self, data_point: str) -> List[str]:
        """Find paths from sensitive data to trust boundaries"""
        paths = []
        for boundary in self.context.trust_boundaries:
            if nx.has_path(self.call_graph, data_point, boundary):
                paths.append(nx.shortest_path(self.call_graph, data_point, boundary))
        return paths
    
    def _has_auth_check(self, function: str) -> bool:
        """Check if a function has proper authentication"""
        if function not in self.context.authorization_checks:
            return False
        return bool(self.context.authorization_checks[function])

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
    
    def _analyze_data_exposure(self, finding: Dict) -> Dict:
        """Analyze potential data exposure vectors"""
        return {
            'type': 'attack_vector',
            'category': 'data_exposure',
            'target': finding['sensitive_data'],
            'path': finding['exposure_paths'],
            'risk': self._assess_risk(finding),
            'mitigation': self._suggest_mitigation(finding)
        }
    
    def _analyze_auth_bypass(self, finding: Dict) -> Dict:
        """Analyze potential authentication bypass vectors"""
        return {
            'type': 'attack_vector',
            'category': 'auth_bypass',
            'target': finding['boundary'],
            'risk': 'high',
            'mitigation': 'Implement authentication middleware'
        }
    
    def _assess_risk(self, finding: Dict) -> str:
        """Assess risk level of a finding"""
        if finding['type'] == 'trust_boundary_violation':
            if len(finding['exposure_paths']) > 1:
                return 'high'
            return 'medium'
        return 'low'
    
    def _suggest_mitigation(self, finding: Dict) -> str:
        """Suggest mitigation strategies"""
        if finding['type'] == 'trust_boundary_violation':
            return 'Implement data encryption and access controls'
        return 'Review security controls'
