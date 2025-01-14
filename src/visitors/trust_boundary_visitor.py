import ast

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