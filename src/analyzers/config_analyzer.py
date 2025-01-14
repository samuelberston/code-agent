from .base_analyzer import BaseAnalyzer
import ast
import yaml
import json
from pathlib import Path
from typing import Dict, Any, List

class ConfigAnalyzer(BaseAnalyzer):
    def __init__(self, context):
        super().__init__(context)
        self.security_checks = {
            'debug': {'safe_value': False, 'severity': 'HIGH'},
            'ssl_verify': {'safe_value': True, 'severity': 'HIGH'},
            'secret_key': {'min_length': 32, 'severity': 'MEDIUM'},
            'allowed_hosts': {'required': True, 'severity': 'HIGH'}
        }
        
    def analyze_config_file(self, config_path: Path) -> List[Dict]:
        findings = []
        config = self._load_config(config_path)
        
        for key, check in self.security_checks.items():
            if key in config:
                finding = self._check_config_value(key, config[key], check)
                if finding:
                    findings.append(finding)
                    
        self.context.config_findings = findings
        return findings
    
    def _load_config(self, path: Path) -> Dict[str, Any]:
        """Load configuration from various file formats"""
        if path.suffix == '.yaml' or path.suffix == '.yml':
            with open(path) as f:
                return yaml.safe_load(f)
        elif path.suffix == '.json':
            with open(path) as f:
                return json.load(f)
        raise ValueError(f"Unsupported config format: {path.suffix}")
    
    def _check_config_value(self, key: str, value: Any, check: Dict) -> Dict:
        """Check if a configuration value meets security requirements"""
        if 'safe_value' in check and value != check['safe_value']:
            return {
                'type': 'config_issue',
                'key': key,
                'current_value': value,
                'recommended_value': check['safe_value'],
                'severity': check['severity']
            }
        elif 'min_length' in check and len(str(value)) < check['min_length']:
            return {
                'type': 'config_issue',
                'key': key,
                'issue': f'Length should be at least {check["min_length"]} characters',
                'severity': check['severity']
            }
        return None 