import ast

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