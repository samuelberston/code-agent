from .base_analyzer import BaseAnalyzer
import ast
import networkx as nx

class CallGraphAnalyzer(BaseAnalyzer):
    def analyze(self, tree: ast.AST) -> None:
        class CallGraphBuilder(ast.NodeVisitor):
            def __init__(self):
                self.graph = nx.DiGraph()
                self.current_function = None
                
            def visit_FunctionDef(self, node):
                previous = self.current_function
                self.current_function = node.name
                self.generic_visit(node)
                self.current_function = previous
                
            def visit_Call(self, node):
                if self.current_function and isinstance(node.func, ast.Name):
                    self.graph.add_edge(self.current_function, node.func.id)
                self.generic_visit(node)
                
        builder = CallGraphBuilder()
        builder.visit(tree)
        self.context.call_graph = builder.graph 