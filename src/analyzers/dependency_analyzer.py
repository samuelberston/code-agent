from .base_analyzer import BaseAnalyzer
import ast
from pathlib import Path
import pkg_resources
import requests
from typing import Dict, List, Set

class DependencyAnalyzer(BaseAnalyzer):
    def __init__(self, context):
        super().__init__(context)
        self.vulnerability_db_url = "https://api.example.com/vulnerabilities"  # Replace with actual vulnerability DB
        self.known_vulnerabilities = self._fetch_vulnerability_data()
        
    def analyze_dependencies(self, requirements_path: Path) -> List[Dict]:
        findings = []
        dependencies = self._parse_requirements(requirements_path)
        
        for package, version in dependencies.items():
            vulns = self._check_vulnerabilities(package, version)
            if vulns:
                findings.extend(vulns)
                
        self.context.dependency_findings = findings
        return findings
    
    def _parse_requirements(self, path: Path) -> Dict[str, str]:
        """Parse requirements.txt file"""
        dependencies = {}
        if not path.exists():
            return dependencies
            
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        req = pkg_resources.Requirement.parse(line)
                        dependencies[req.name] = str(req.specifier)
                    except:
                        continue
        return dependencies
    
    def _fetch_vulnerability_data(self) -> Dict:
        """Fetch known vulnerabilities from security database"""
        try:
            response = requests.get(self.vulnerability_db_url)
            return response.json()
        except:
            return {}  # Fallback to empty DB if fetch fails
    
    def _check_vulnerabilities(self, package: str, version: str) -> List[Dict]:
        """Check if a package version has known vulnerabilities"""
        findings = []
        if package in self.known_vulnerabilities:
            vulns = self.known_vulnerabilities[package]
            for vuln in vulns:
                if self._version_affected(version, vuln['affected_versions']):
                    findings.append({
                        'type': 'dependency_vulnerability',
                        'package': package,
                        'version': version,
                        'vulnerability_id': vuln['id'],
                        'severity': vuln['severity'],
                        'description': vuln['description'],
                        'fix_version': vuln['fixed_version']
                    })
        return findings
    
    def _version_affected(self, current: str, affected_range: str) -> bool:
        """Check if current version falls within affected range"""
        # Implement version comparison logic
        # This is a simplified check that should be replaced with proper version parsing
        return current in affected_range 