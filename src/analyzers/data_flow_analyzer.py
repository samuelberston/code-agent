from .base_analyzer import BaseAnalyzer
import ast
from typing import Set, Dict, List

class DataFlowAnalyzer(BaseAnalyzer):
    def __init__(self, context):
        super().__init__(context)
        self.taint_sources = {
            'request.form': 'USER_INPUT',
            'request.args': 'USER_INPUT',
            'request.json': 'USER_INPUT',
            'input': 'USER_INPUT',
            'file.read': 'FILE_INPUT'
        }
        self.sinks = {
            'execute': 'SQL',
            'eval': 'CODE_EXECUTION',
            'render_template': 'XSS',
            'send_file': 'FILE_OPERATION'
        }
        
    def analyze(self, tree: ast.AST) -> None:
        taint_tracker = TaintTracker(self.taint_sources, self.sinks)
        taint_tracker.visit(tree)
        self.context.taint_flows = taint_tracker.flows

class TaintTracker(ast.NodeVisitor):
    def __init__(self, sources: Dict[str, str], sinks: Dict[str, str]):
        self.sources = sources
        self.sinks = sinks
        self.flows: List[Dict] = []
        self.tainted_vars: Dict[str, str] = {}
        
    def visit_Assign(self, node):
        # Track tainted assignments
        if isinstance(node.value, ast.Call):
            source_type = self._check_source(node.value)
            if source_type:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars[target.id] = source_type
        self.generic_visit(node)
        
    def visit_Call(self, node):
        # Check for tainted data flowing into sinks
        if isinstance(node.func, ast.Name) and node.func.id in self.sinks:
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                    self.flows.append({
                        'type': 'taint_flow',
                        'source_type': self.tainted_vars[arg.id],
                        'sink_type': self.sinks[node.func.id],
                        'line': node.lineno
                    })
        self.generic_visit(node)
        
    def _check_source(self, node) -> str:
        """Check if a node represents a taint source"""
        if isinstance(node.func, ast.Attribute):
            source = f"{node.func.value.id}.{node.func.attr}"
            return self.sources.get(source)
        elif isinstance(node.func, ast.Name):
            return self.sources.get(node.func.id)
        return None 