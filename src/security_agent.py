import ast
from typing import List, Dict
import networkx as nx
from .models.security_context import SecurityContext
from .visitors.trust_boundary_visitor import TrustBoundaryVisitor
from .visitors.data_flow_visitor import DataFlowVisitor
from .visitors.vulnerability_visitor import VulnerabilityVisitor
from .analyzers.call_graph_analyzer import CallGraphAnalyzer
from .analyzers.input_validation_analyzer import InputValidationAnalyzer
from .patterns.security_pattern_matcher import SecurityPatternMatcher
from .analyzers.data_flow_analyzer import DataFlowAnalyzer
from .analyzers.config_analyzer import ConfigAnalyzer
from .analyzers.dependency_analyzer import DependencyAnalyzer
from pathlib import Path

class SecurityAgent:
    def __init__(self):
        self.context = SecurityContext(
            trust_boundaries=set(),
            sensitive_data=set(),
            authentication_points=set(),
            authorization_checks={}
        )
        self.call_graph = nx.DiGraph()
        
    def analyze_codebase(self, source_files: List[str], config_file: Path = None):
        """Analyze codebase for potential vulnerabilities"""
        # Analyze source files
        for file in source_files:
            self._analyze_file(file)
        
        # Analyze configuration if provided
        if config_file:
            config_analyzer = ConfigAnalyzer(self.context)
            config_analyzer.analyze_config_file(config_file)
        
        # Analyze dependencies if requirements.txt exists
        req_file = Path('requirements.txt')
        if req_file.exists():
            dep_analyzer = DependencyAnalyzer(self.context)
            dep_analyzer.analyze_dependencies(req_file)
        
        return self._generate_findings()
    
    def _analyze_file(self, file_path: str):
        """Analyze a single source file"""
        with open(file_path) as f:
            code = f.read()
            tree = ast.parse(code, filename=file_path)
            
        # Initialize analyzers
        analyzers = [
            CallGraphAnalyzer(self.context),
            InputValidationAnalyzer(self.context),
            DataFlowAnalyzer(self.context)
        ]
        
        # Run all analyzers
        for analyzer in analyzers:
            analyzer.analyze(tree)
        
        # Run pattern matching
        pattern_matcher = SecurityPatternMatcher()
        findings = pattern_matcher.analyze_code(code)
        
        # Update context with findings
        self.context.pattern_findings.extend(findings)

    # ... (rest of the original SecurityAgent methods) 